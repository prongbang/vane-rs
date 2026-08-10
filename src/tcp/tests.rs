use std::sync::Arc;

use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls::RootCertStore;
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::CertificateDer;

use super::*;
use crate::{VaneClientConfig, certificate_pin_values, sha256_pin};

fn client_with(config: VaneClientConfig) -> VaneClient {
    VaneClient::new(config).unwrap()
}

type TlsStream = rustls::StreamOwned<rustls::ServerConnection, std::net::TcpStream>;

/// A localhost TLS listener with a per-run CA, so a test can drive the real
/// TCP transport against a hand-written HTTP response. Returns the port and
/// the CA DER the caller must install in `TEST_ROOT`.
fn local_tls_server<F>(alpn: &[u8], handle: F) -> (u16, CertificateDer<'static>)
where
    F: Fn(TlsStream) + Send + Sync + 'static,
{
    use rustls::pki_types::PrivateKeyDer;
    use rustls::{ServerConfig, ServerConnection};

    let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let ca_der = ca.der().clone();
    let issuer = Issuer::new(ca_params, ca_key);

    let leaf_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
    let leaf_der = leaf.der().clone();
    let leaf_pkcs8 = PrivateKeyDer::try_from(leaf_key.serialize_der()).unwrap();

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server_config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![leaf_der], leaf_pkcs8)
        .unwrap();
    server_config.alpn_protocols = vec![alpn.to_vec()];
    let server_config = Arc::new(server_config);

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = Arc::new(handle);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let config = server_config.clone();
            let handle = handle.clone();
            std::thread::spawn(move || {
                stream.set_nodelay(true).ok();
                let Ok(conn) = ServerConnection::new(config) else {
                    return;
                };
                handle(rustls::StreamOwned::new(conn, stream));
            });
        }
    });
    (port, ca_der)
}

/// Answers each request with a raw response picked by path, so a test can
/// script the exact bytes on the wire — including a repeated `Set-Cookie` and
/// an `HTTP/1.0` status line, neither of which reqwest can be asked to fake.
fn raw_http_server(
    routes: &'static [(&'static str, &'static str)],
) -> (u16, CertificateDer<'static>) {
    local_tls_server(b"http/1.1", move |mut tls| {
        let mut buf = [0u8; 8192];
        let mut pending = Vec::new();
        loop {
            match std::io::Read::read(&mut tls, &mut buf) {
                Ok(0) | Err(_) => return,
                Ok(read) => pending.extend_from_slice(&buf[..read]),
            }
            while let Some(end) = pending
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|position| position + 4)
            {
                let head = String::from_utf8_lossy(&pending[..end]).into_owned();
                pending.drain(..end);
                let path = head.split_whitespace().nth(1).unwrap_or("/");
                let response = routes
                    .iter()
                    .find(|(route, _)| *route == path)
                    .map(|(_, response)| *response)
                    .unwrap_or("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
                if std::io::Write::write_all(&mut tls, response.as_bytes()).is_err() {
                    return;
                }
                std::io::Write::flush(&mut tls).ok();
            }
        }
    })
}

/// Installs `ca` as the process-wide trust anchor for the duration of the
/// returned guard, serialized against every other test that builds a TCP
/// client.
fn with_test_root(ca: CertificateDer<'static>) -> impl Drop {
    // Held, not read: dropping the guard is the whole point.
    struct Guard(#[allow(dead_code)] std::sync::MutexGuard<'static, ()>);
    impl Drop for Guard {
        fn drop(&mut self) {
            *super::TEST_ROOT.lock().unwrap() = None;
        }
    }
    let guard = Guard(crate::tcp_test_lock());
    *super::TEST_ROOT.lock().unwrap() = Some(ca);
    guard
}

/// A CA plus a leaf it signed, so the pin logic can be reached through a chain
/// that real path validation actually accepts.
struct Chain {
    verifier: Arc<WebPkiServerVerifier>,
    leaf: CertificateDer<'static>,
}

fn test_chain(host: &str) -> Chain {
    let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();

    let issuer = Issuer::new(ca_params, ca_key);

    let leaf_params = CertificateParams::new(vec![host.to_string()]).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();

    let mut roots = RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    Chain {
        verifier: WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .unwrap(),
        leaf: leaf.der().clone(),
    }
}

fn verify(chain: &Chain, host: &str, pins: HashMap<String, Vec<String>>) -> Result<(), String> {
    let verifier = PinnedServerCertVerifier {
        inner: chain.verifier.clone(),
        certificate_pins: pins,
    };
    verifier
        .verify_server_cert(
            &chain.leaf,
            &[],
            &ServerName::try_from(host.to_string()).unwrap(),
            &[],
            UnixTime::now(),
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[test]
fn pinned_verifier_accepts_a_valid_chain_and_enforces_pins() {
    let host = "api.example.com";
    let chain = test_chain(host);
    let matching = certificate_pin_values(&chain.leaf);

    // No pins: standard path validation alone decides.
    assert!(verify(&chain, host, HashMap::new()).is_ok());

    // Matching pin on top of a valid chain.
    assert!(
        verify(
            &chain,
            host,
            HashMap::from([(host.to_string(), matching.clone())])
        )
        .is_ok()
    );

    // Backup pin present alongside a non-matching one still matches.
    let mut with_backup =
        vec!["sha256-cert/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string()];
    with_backup.extend(matching);
    assert!(
        verify(
            &chain,
            host,
            HashMap::from([(host.to_string(), with_backup)])
        )
        .is_ok()
    );

    // Wrong pin on a chain that is otherwise perfectly valid must fail closed.
    let err = verify(
        &chain,
        host,
        HashMap::from([(
            host.to_string(),
            vec![sha256_pin("sha256-cert", b"some other certificate")],
        )]),
    )
    .unwrap_err();
    assert!(err.contains("Certificate pin mismatch"), "got {err}");

    // Pins are host-scoped: a pin for a different host does not apply here.
    assert!(
        verify(
            &chain,
            host,
            HashMap::from([(
                "other.example.com".to_string(),
                vec![sha256_pin("sha256-cert", b"some other certificate")],
            )])
        )
        .is_ok()
    );
}

#[test]
fn pinned_verifier_rejects_a_chain_that_does_not_validate() {
    // A leaf from a different CA: the pin never gets a chance to matter.
    let chain = test_chain("api.example.com");
    let other = test_chain("api.example.com");
    let verifier = PinnedServerCertVerifier {
        inner: chain.verifier.clone(),
        certificate_pins: HashMap::new(),
    };

    assert!(
        verifier
            .verify_server_cert(
                &other.leaf,
                &[],
                &ServerName::try_from("api.example.com").unwrap(),
                &[],
                UnixTime::now(),
            )
            .is_err()
    );
}

#[test]
fn pin_lookup_host_matches_url_host_spelling() {
    // Url::host_str keeps IPv6 brackets; a mismatch here would look up a
    // pinned host under a name with no pins and silently allow it.
    assert_eq!(
        Url::parse("https://[::1]:8443/x").unwrap().host_str(),
        Some("[::1]")
    );
    assert_eq!(
        pin_lookup_host(&ServerName::try_from("::1").unwrap()).as_deref(),
        Some("[::1]")
    );
    assert_eq!(
        pin_lookup_host(&ServerName::try_from("127.0.0.1").unwrap()).as_deref(),
        Some("127.0.0.1")
    );
    assert_eq!(
        Url::parse("https://API.Example.COM/x").unwrap().host_str(),
        Some("api.example.com")
    );
    assert_eq!(
        pin_lookup_host(&ServerName::try_from("API.Example.COM").unwrap()).as_deref(),
        Some("api.example.com")
    );
}

#[test]
fn tls_config_offers_alpn_per_protocol_mode() {
    // reqwest leaves a preconfigured config's ALPN alone, so without these
    // HTTP/2 is never negotiated at all.
    let alpn = |mode| {
        tls_config(&mode, HashMap::new())
            .unwrap()
            .alpn_protocols
            .clone()
    };
    assert_eq!(
        alpn(VaneProtocolMode::Http1Only),
        vec![b"http/1.1".to_vec()]
    );
    assert_eq!(alpn(VaneProtocolMode::Http2Only), vec![b"h2".to_vec()]);
    assert_eq!(
        alpn(VaneProtocolMode::Http2ThenHttp1),
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    );
    assert_eq!(
        alpn(VaneProtocolMode::Http3ThenHttp2ThenHttp1),
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    );
}

#[test]
fn client_build_plumbs_dns_overrides_pool_and_proxy() {
    let ok = client_with(VaneClientConfig {
        dns_overrides: HashMap::from([("api.example.com".to_string(), "203.0.113.10".to_string())]),
        proxy_url: Some("https://proxy.example.com:8080".to_string()),
        proxy_authorization: Some("Basic dXNlcjpwYXNz".to_string()),
        ..VaneClientConfig::default()
    });
    assert!(build_client(&ok, HashMap::new()).is_ok());

    let pooled_off = client_with(VaneClientConfig {
        connection_pool_enabled: false,
        ..VaneClientConfig::default()
    });
    assert!(build_client(&pooled_off, HashMap::new()).is_ok());

    let bad_dns = client_with(VaneClientConfig {
        dns_overrides: HashMap::from([("api.example.com".to_string(), "not-an-ip".to_string())]),
        ..VaneClientConfig::default()
    });
    let err = build_client(&bad_dns, HashMap::new())
        .unwrap_err()
        .to_string();
    assert!(err.contains("Invalid DNS override"), "got {err}");
}

#[test]
fn shared_client_is_cached_and_reset_when_pins_change() {
    let client = client_with(VaneClientConfig::default());
    assert!(client.tcp_client.lock().unwrap().is_none());

    shared_client(&client).unwrap();
    assert!(client.tcp_client.lock().unwrap().is_some());

    // The verifier holds a pin snapshot, so changing pins must drop it.
    client
        .set_certificate_pins(
            "api.example.com".to_string(),
            vec!["sha256/example".to_string()],
        )
        .unwrap();
    assert!(client.tcp_client.lock().unwrap().is_none());
}

#[test]
fn concurrent_client_build_never_caches_stale_pins() {
    // The build reads the pins it caches into the verifier. If a pin change can
    // interleave between that read and the insert, the cached client keeps the
    // old (empty) pin set forever and the host is silently unpinned.
    for _ in 0..40 {
        let client = Arc::new(client_with(VaneClientConfig::default()));
        let builder = {
            let client = client.clone();
            std::thread::spawn(move || {
                for _ in 0..20 {
                    let _ = shared_client(&client);
                }
            })
        };
        client
            .set_certificate_pins(
                "api.example.com".to_string(),
                vec!["sha256/example".to_string()],
            )
            .unwrap();
        builder.join().unwrap();

        // Whatever client is cached now must have been built with the pins that
        // are currently configured.
        let cached_is_pinned = client.tcp_client.lock().unwrap().is_some();
        if cached_is_pinned {
            assert!(
                !client
                    .certificate_pins_snapshot()
                    .unwrap()
                    .get("api.example.com")
                    .unwrap()
                    .is_empty(),
                "a cached client exists while the configured pins are gone"
            );
        }
    }
}

/// Drives the shipped `redirect_target` with a synthesized response rather
/// than a copy of its logic, so the test cannot pass while the code diverges.
fn target(
    status: u16,
    location: &str,
    current: &Url,
    pins: &HashMap<String, Vec<String>>,
) -> Option<Url> {
    let mut raw = http::Response::builder().status(status);
    if !location.is_empty() {
        raw = raw.header("location", location);
    }
    let response = reqwest::blocking::Response::from(raw.body(Vec::new()).unwrap());
    let mut request = crate::test_request(&current.to_string());
    request.follow_redirects = true;
    match redirect_target(&response, current, &request, 0, pins) {
        RedirectDecision::Follow(url) => Some(url),
        // The reasons are asserted in the shared gate's own tests; here only
        // "did the TCP adapter hand back a hop" matters.
        RedirectDecision::Stop | RedirectDecision::Refused(_) => None,
    }
}

#[test]
fn redirects_stop_on_downgrade_and_on_leaving_a_pinned_host() {
    let pinned = HashMap::from([(
        "api.example.com".to_string(),
        vec!["sha256/example".to_string()],
    )]);
    let from = Url::parse("https://api.example.com/login").unwrap();
    let unpinned = HashMap::new();

    // Same host, still https: fine.
    assert_eq!(
        target(302, "/home", &from, &pinned).map(|u| u.to_string()),
        Some("https://api.example.com/home".to_string())
    );
    // Downgrade to cleartext: never.
    assert_eq!(
        target(302, "http://api.example.com/home", &from, &pinned),
        None
    );
    // Leaving a pinned host: the pin does not cover the next hop.
    assert_eq!(
        target(302, "https://cdn.example.net/home", &from, &pinned),
        None
    );
    // Unpinned origin may cross hosts.
    assert_eq!(
        target(302, "https://cdn.example.net/home", &from, &unpinned).map(|u| u.to_string()),
        Some("https://cdn.example.net/home".to_string())
    );
    // Hosts vane's parser and reqwest's could spell differently must not
    // resolve at all, or every gate below would judge a host we never dial.
    for hostile in [
        "https://attacker.test\\.api.example.com/y",
        "https://attacker.test\t.api.example.com/y",
        "https://attacker%2etest/y",
        "https://evil@other.example/",
    ] {
        assert_eq!(
            target(302, hostile, &from, &unpinned),
            None,
            "{hostile} must not resolve"
        );
    }
    // A 200 is not a redirect; an absent or empty Location is not one either.
    assert_eq!(target(200, "/home", &from, &unpinned), None);
    assert_eq!(target(302, "", &from, &unpinned), None);
    // The SSO return-to shape resolves as a relative path rather than being
    // mistaken for an absolute URL.
    assert_eq!(
        target(
            302,
            "/login?return_to=https://app.example.com/home",
            &from,
            &unpinned
        )
        .map(|u| u.to_string()),
        Some("https://api.example.com/login?return_to=https://app.example.com/home".to_string())
    );
}

#[test]
fn cross_origin_hop_drops_caller_headers() {
    let client = client_with(VaneClientConfig {
        default_headers: HashMap::from([("X-Api-Key".to_string(), "secret".to_string())]),
        ..VaneClientConfig::default()
    });
    let mut request = crate::test_request("https://api.example.com/x");
    request
        .headers
        .insert("Accept".to_string(), "application/json".to_string());

    let same = build_headers(
        &client,
        &request,
        &Url::parse("https://api.example.com/x").unwrap(),
        ("api.example.com", 443),
        None,
        false,
    )
    .unwrap();
    assert_eq!(same.get("x-api-key").unwrap(), "secret");

    let crossed = build_headers(
        &client,
        &request,
        &Url::parse("https://evil.example/x").unwrap(),
        ("api.example.com", 443),
        None,
        false,
    )
    .unwrap();
    assert!(
        crossed.get("x-api-key").is_none(),
        "caller credentials must not follow a redirect to another host"
    );
    // Benign headers still ride along.
    assert_eq!(crossed.get("accept").unwrap(), "application/json");
}

#[test]
fn tcp_rejects_plaintext_urls() {
    let client = client_with(VaneClientConfig {
        protocol_mode: VaneProtocolMode::Http1Only,
        ..VaneClientConfig::default()
    });
    let err = client
        .execute(crate::test_request("http://api.example.com/x"))
        .unwrap_err()
        .to_string();
    assert!(err.contains("only supports https://"), "got {err}");
}

/// Regression test for the hyper connection-pool checkout race.
///
/// A keep-alive peer can close a pooled connection at the moment hyper hands it
/// to us. By then the request is committed to that connection, so hyper-util's
/// own retry cannot cover it (that path needs `take_message`, and ours arrives
/// as `SendRequest`) and the write surfaces as a transport error. The HTTP/3
/// path has always retried this shape; the TCP path did not.
///
/// The server below closes an idle connection without `close_notify` — the
/// abrupt shape, which only selects the error string. Making rustls tolerate
/// EOF would rename this bug and mask genuine truncation, so the fix is the
/// retry, and this test is what proves it is still there.
mod pool_checkout_race {
    use super::*;
    use std::io::Write;
    use std::time::Duration;

    // The window is narrow and sits where the client's pool checkout coincides
    // with the server's close, so the delay tracks the idle timeout rather than
    // exceeding it: measured here, delay == idle fails ~20-27% of requests
    // without the retry, while delay = idle + 5ms fails 0% because hyper has
    // already reaped the dead connection by then.
    const SERVER_IDLE_MS: u64 = 60;
    /// Offsets around the server's close, in milliseconds. The window is only a
    /// few milliseconds wide and its exact position moves with machine speed,
    /// so the run sweeps across it instead of betting on one delay.
    const DELAY_OFFSETS_MS: [i64; 4] = [-2, -1, 0, 1];
    const ROUNDS: usize = 14;

    fn serve(mut tls: TlsStream) {
        let mut buf = [0u8; 8192];
        let mut pending = Vec::new();
        loop {
            tls.sock
                .set_read_timeout(Some(Duration::from_millis(SERVER_IDLE_MS)))
                .ok();
            match std::io::Read::read(&mut tls, &mut buf) {
                Ok(0) => return,
                Ok(read) => pending.extend_from_slice(&buf[..read]),
                // Idle past the keep-alive window: bare TCP FIN, no
                // close_notify. This is what a real server does to us.
                Err(_) => return,
            }
            while let Some(end) = pending
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .map(|p| p + 4)
            {
                pending.drain(..end);
                let response =
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok";
                if tls.write_all(response).is_err() {
                    return;
                }
                tls.flush().ok();
            }
        }
    }

    #[test]
    fn a_stale_pooled_connection_is_retried_rather_than_failing_the_request() {
        let (port, ca) = local_tls_server(b"http/1.1", serve);
        // Serialized against the other tests that build a TCP client, since the
        // trust anchor and the client cache are process-wide.
        let _guard = with_test_root(ca);

        let client = client_with(VaneClientConfig {
            base_url: Some(format!("https://localhost:{port}")),
            protocol_mode: VaneProtocolMode::Http1Only,
            timeout_seconds: Some(10),
            ..VaneClientConfig::default()
        });

        let mut failures = Vec::new();
        let mut attempts = 0usize;
        for round in 0..ROUNDS {
            for offset in DELAY_OFFSETS_MS {
                if attempts > 0 {
                    let delay = (SERVER_IDLE_MS as i64 + offset).max(1) as u64;
                    std::thread::sleep(Duration::from_millis(delay));
                }
                attempts += 1;
                match client.execute(crate::test_request("/")) {
                    Ok(response) => assert_eq!(response.status_code, 200),
                    Err(err) => failures.push(format!("round {round} offset {offset}ms: {err}")),
                }
            }
        }

        assert!(
            failures.is_empty(),
            "{} of {attempts} requests failed on a stale pooled connection: {failures:?}",
            failures.len()
        );
    }
}

/// The response metadata the transports must agree on: the raw `Set-Cookie`
/// values, kept out of the header map, and the protocol read off the wire.
///
/// These drive the shipped `VaneClient::execute`, not a reimplementation of
/// the header loop, so the wire bytes are the only input.
mod response_metadata {
    use super::*;
    use crate::VaneHttpVersion;

    const TWO_COOKIES: &str = concat!(
        "HTTP/1.1 200 OK\r\n",
        "Content-Length: 2\r\n",
        "Set-Cookie: a=1; Path=/\r\n",
        "Set-Cookie: b=2; Path=/\r\n",
        "Connection: close\r\n",
        "\r\nok"
    );

    fn get(port: u16, cookies_enabled: bool) -> crate::VaneResponse {
        client_with(VaneClientConfig {
            base_url: Some(format!("https://localhost:{port}")),
            protocol_mode: VaneProtocolMode::Http1Only,
            timeout_seconds: Some(10),
            cookies_enabled,
            ..VaneClientConfig::default()
        })
        .execute(crate::test_request("/"))
        .unwrap()
    }

    #[test]
    fn repeated_set_cookie_is_surfaced_whether_or_not_the_jar_is_on() {
        let (port, ca) = raw_http_server(&[("/", TWO_COOKIES)]);
        let _guard = with_test_root(ca);

        // With the jar off, `read_body`'s skip used to be unconditional while
        // the per-hop harvest was gated, so `Set-Cookie` vanished entirely.
        for cookies_enabled in [true, false] {
            let response = get(port, cookies_enabled);
            assert_eq!(
                response.set_cookie,
                vec!["a=1; Path=/".to_string(), "b=2; Path=/".to_string()],
                "cookies_enabled={cookies_enabled}"
            );
            assert!(
                !response.headers.contains_key("set-cookie"),
                "set-cookie must never collapse into the header map"
            );
            assert_eq!(response.http_version, Some(VaneHttpVersion::Http11));
        }
    }

    /// The TCP half of the join rule pinned by
    /// `repeated_h3_headers_comma_join_across_header_blocks` in the crate
    /// tests: the same repeated wire shape must yield the same `", "`-joined
    /// map entry here, or which headers a caller sees depends on whether UDP
    /// happened to work. Hyper lowercases the mixed-case spelling; hyper also
    /// rejects differing repeated `Content-Length` values outright, so that
    /// edge is pinned on the H3 merge, which this response cannot reach.
    #[test]
    fn repeated_headers_comma_join_identically_on_both_transports() {
        // A 200, so the repeated `Location` reaches the shared merge instead
        // of the redirect machinery.
        const REPEATS: &str = concat!(
            "HTTP/1.1 200 OK\r\n",
            "Content-Length: 2\r\n",
            "X-Multi: a\r\n",
            "X-Multi: b\r\n",
            "Location: https://first.example/\r\n",
            "Location: https://second.example/\r\n",
            "Set-Cookie: a=1; Path=/\r\n",
            "Set-Cookie: b=2; Path=/\r\n",
            "Connection: close\r\n",
            "\r\nok"
        );
        let (port, ca) = raw_http_server(&[("/", REPEATS)]);
        let _guard = with_test_root(ca);

        let response = get(port, true);
        assert_eq!(
            response.headers.get("x-multi").map(String::as_str),
            Some("a, b")
        );
        // `location` is the join's exception on both transports: first
        // occurrence whole, repeats dropped — the value `redirect_target`'s
        // `HeaderMap::get` would act on, now also the one the caller sees.
        assert_eq!(
            response.headers.get("location").map(String::as_str),
            Some("https://first.example/")
        );
        assert_eq!(
            response.set_cookie,
            vec!["a=1; Path=/".to_string(), "b=2; Path=/".to_string()]
        );
        assert!(!response.headers.contains_key("set-cookie"));
    }

    #[test]
    fn a_redirect_surfaces_only_the_final_hop_but_the_jar_still_sees_both() {
        let (port, ca) = raw_http_server(&[
            (
                "/",
                concat!(
                    "HTTP/1.1 302 Found\r\n",
                    "Location: /done\r\n",
                    "Content-Length: 0\r\n",
                    "Set-Cookie: hop=1; Path=/\r\n",
                    "\r\n"
                ),
            ),
            (
                "/done",
                concat!(
                    "HTTP/1.1 200 OK\r\n",
                    "Content-Length: 2\r\n",
                    "Set-Cookie: final=2; Path=/\r\n",
                    "Connection: close\r\n",
                    "\r\nok"
                ),
            ),
        ]);
        let _guard = with_test_root(ca);

        let client = client_with(VaneClientConfig {
            base_url: Some(format!("https://localhost:{port}")),
            protocol_mode: VaneProtocolMode::Http1Only,
            timeout_seconds: Some(10),
            cookies_enabled: true,
            ..VaneClientConfig::default()
        });
        let response = client.execute(crate::test_request("/")).unwrap();

        assert_eq!(response.set_cookie, vec!["final=2; Path=/".to_string()]);
        // Surfacing the final hop must not have disturbed the per-hop harvest.
        let jar = client
            .cookie_header(&Url::parse(&format!("https://localhost:{port}/")).unwrap())
            .unwrap();
        assert!(
            jar.contains("hop=1"),
            "jar lost the intermediate hop: {jar}"
        );
        assert!(jar.contains("final=2"), "jar lost the final hop: {jar}");
    }

    /// The version has to come off the status line, not from the mode the
    /// caller asked for — this server answers an `Http1Only` request with
    /// `HTTP/1.0`, which a hardcoded `Http11` would report wrongly.
    #[test]
    fn the_http_version_is_read_off_the_status_line() {
        let (port, ca) = raw_http_server(&[(
            "/",
            "HTTP/1.0 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        )]);
        let _guard = with_test_root(ca);

        let response = get(port, true);
        assert_eq!(response.status_code, 200);
        assert_eq!(response.http_version, Some(VaneHttpVersion::Http10));
    }
}
