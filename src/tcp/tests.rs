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
    redirect_target(&response, current, &request, 0, pins)
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
