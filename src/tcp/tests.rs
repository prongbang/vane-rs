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

/// Upload (request-body) streaming over the TCP backend: wire framing,
/// writer backpressure, and the permitting half of the H3→TCP fallback
/// decision (nothing consumed yet). The refusing half — consumed bytes — is
/// `h3_offline::tests::streamed_upload_mid_body_transport_failure_does_not_fall_back`.
mod upload {
    use std::io::{Read as _, Write as _};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::Duration;

    use std::collections::HashMap;

    use super::{CertificateDer, TlsStream, local_tls_server, with_test_root};
    use crate::h3_offline::{TEST_HOST, body_pattern, sha256_hex, test_pki};
    use crate::{
        VaneClientConfig, VaneError, VaneHttpVersion, VaneProtocolMode, create_body_stream,
        finish_body_stream, free_body_stream, test_request, write_body_stream_chunk,
    };

    /// Reads up to the end of the request head; returns it plus any body
    /// bytes that arrived in the same reads.
    fn read_head(tls: &mut TlsStream) -> (String, Vec<u8>) {
        let mut buf = [0u8; 8192];
        let mut pending = Vec::new();
        loop {
            if let Some(end) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&pending[..end]).into_owned();
                let rest = pending[end + 4..].to_vec();
                return (head, rest);
            }
            match tls.read(&mut buf) {
                Ok(0) | Err(_) => return (String::new(), Vec::new()),
                Ok(n) => pending.extend_from_slice(&buf[..n]),
            }
        }
    }

    fn header_value(head: &str, name: &str) -> Option<String> {
        head.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim()
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_string())
        })
    }

    fn read_exact_body(tls: &mut TlsStream, mut pending: Vec<u8>, len: usize) -> Vec<u8> {
        let mut buf = [0u8; 8192];
        while pending.len() < len {
            match tls.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => pending.extend_from_slice(&buf[..n]),
            }
        }
        pending.truncate(len);
        pending
    }

    /// Minimal `Transfer-Encoding: chunked` decoder — enough for hyper's own
    /// output, which is all it ever reads.
    fn read_chunked_body(tls: &mut TlsStream, mut pending: Vec<u8>) -> Vec<u8> {
        let mut buf = [0u8; 8192];
        let mut body = Vec::new();
        let mut offset = 0;
        loop {
            let line_end = loop {
                if let Some(pos) = pending[offset..].windows(2).position(|w| w == b"\r\n") {
                    break offset + pos;
                }
                match tls.read(&mut buf) {
                    Ok(0) | Err(_) => return body,
                    Ok(n) => pending.extend_from_slice(&buf[..n]),
                }
            };
            let size_text = String::from_utf8_lossy(&pending[offset..line_end]).into_owned();
            let Ok(size) = usize::from_str_radix(size_text.trim(), 16) else {
                return body;
            };
            if size == 0 {
                return body;
            }
            let chunk_start = line_end + 2;
            while pending.len() < chunk_start + size + 2 {
                match tls.read(&mut buf) {
                    Ok(0) | Err(_) => return body,
                    Ok(n) => pending.extend_from_slice(&buf[..n]),
                }
            }
            body.extend_from_slice(&pending[chunk_start..chunk_start + size]);
            offset = chunk_start + size + 2;
        }
    }

    /// Answers with the received body's digest plus which framing carried it,
    /// so a test asserts what went over the wire, not what Vane meant to send.
    fn respond_with_digest(tls: &mut TlsStream, framing: &str, body: &[u8]) {
        let payload = format!(
            "{{\"len\": {}, \"sha256\": \"{}\", \"framing\": \"{framing}\"}}",
            body.len(),
            sha256_hex(body)
        );
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        );
        tls.write_all(response.as_bytes()).ok();
        tls.flush().ok();
    }

    fn upload_handler(mut tls: TlsStream) {
        let (head, rest) = read_head(&mut tls);
        if let Some(len) = header_value(&head, "content-length") {
            let body = read_exact_body(&mut tls, rest, len.parse().unwrap_or(0));
            respond_with_digest(&mut tls, "sized", &body);
        } else if header_value(&head, "transfer-encoding").as_deref() == Some("chunked") {
            let body = read_chunked_body(&mut tls, rest);
            respond_with_digest(&mut tls, "chunked", &body);
        } else {
            respond_with_digest(&mut tls, "missing", &[]);
        }
    }

    fn spawn_writer(
        id: u64,
        body: Vec<u8>,
        chunk: usize,
    ) -> std::thread::JoinHandle<Result<(), VaneError>> {
        std::thread::spawn(move || {
            for part in body.chunks(chunk) {
                write_body_stream_chunk(id, part.to_vec())?;
            }
            finish_body_stream(id)
        })
    }

    /// The Content-Length answer on the wire: a declared length arrives as
    /// `Content-Length` with the exact bytes; an undeclared one arrives as
    /// `Transfer-Encoding: chunked` and reassembles byte-identical.
    #[test]
    fn streamed_upload_sends_content_length_when_declared_and_chunked_otherwise() {
        let (port, ca, _leaf) = local_tls_server(b"http/1.1", upload_handler);
        let _root = with_test_root(ca);
        let client = super::client_with(VaneClientConfig {
            protocol_mode: VaneProtocolMode::Http1Only,
            connection_pool_enabled: false,
            timeout_seconds: Some(20),
            ..VaneClientConfig::default()
        });
        // Larger than the stream buffer, so the reqwest pump and the writer
        // really interleave.
        let body = body_pattern(700 * 1024);
        let expected_sha = sha256_hex(&body);

        let id = create_body_stream(Some(body.len() as u64));
        let writer = spawn_writer(id, body.clone(), 64 * 1024);
        let mut sized = test_request(&format!("https://localhost:{port}/upload"));
        sized.method = "PUT".to_string();
        sized.body_stream_id = Some(id);
        let response = client.execute(sized).unwrap();
        writer.join().unwrap().unwrap();
        assert!(response.is_success);
        let text = String::from_utf8_lossy(&response.body).into_owned();
        assert!(text.contains("\"framing\": \"sized\""), "{text}");
        assert!(text.contains(&expected_sha), "{text}");
        free_body_stream(id);

        let id = create_body_stream(None);
        let writer = spawn_writer(id, body, 64 * 1024);
        let mut chunked = test_request(&format!("https://localhost:{port}/upload"));
        chunked.method = "PUT".to_string();
        chunked.body_stream_id = Some(id);
        let response = client.execute(chunked).unwrap();
        writer.join().unwrap().unwrap();
        assert!(response.is_success);
        let text = String::from_utf8_lossy(&response.body).into_owned();
        assert!(text.contains("\"framing\": \"chunked\""), "{text}");
        assert!(text.contains(&expected_sha), "{text}");
        free_body_stream(id);
    }

    /// Backpressure through the reqwest bridge: while the server reads
    /// nothing, the writer must park — hyper stops pulling the reader once
    /// the send buffers fill, which stops the queue draining — and the body
    /// is far too large for the kernel's loopback buffers to swallow.
    #[test]
    fn streamed_upload_backpressure_parks_the_writer_until_the_server_reads() {
        const TOTAL: usize = 24 * 1024 * 1024;
        let hold = Arc::new(AtomicBool::new(true));
        let (port, ca, _leaf) = local_tls_server(b"http/1.1", {
            let hold = Arc::clone(&hold);
            move |mut tls| {
                let (head, rest) = read_head(&mut tls);
                let len: usize = header_value(&head, "content-length")
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(0);
                while hold.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(10));
                }
                let body = read_exact_body(&mut tls, rest, len);
                respond_with_digest(&mut tls, "sized", &body);
            }
        });
        let _root = with_test_root(ca);
        let client = Arc::new(super::client_with(VaneClientConfig {
            protocol_mode: VaneProtocolMode::Http1Only,
            connection_pool_enabled: false,
            timeout_seconds: Some(30),
            ..VaneClientConfig::default()
        }));
        let body = body_pattern(TOTAL);
        let expected_sha = sha256_hex(&body);
        let id = create_body_stream(Some(TOTAL as u64));

        let written = Arc::new(AtomicU64::new(0));
        let writer = std::thread::spawn({
            let written = Arc::clone(&written);
            move || -> Result<(), VaneError> {
                for part in body.chunks(256 * 1024) {
                    write_body_stream_chunk(id, part.to_vec())?;
                    written.fetch_add(part.len() as u64, Ordering::Relaxed);
                }
                finish_body_stream(id)
            }
        });
        let exec = std::thread::spawn({
            let client = Arc::clone(&client);
            let url = format!("https://localhost:{port}/upload");
            move || {
                let mut request = test_request(&url);
                request.method = "PUT".to_string();
                request.body_stream_id = Some(id);
                client.execute(request)
            }
        });

        // Parked: the counter stops moving with most of the body unwritten —
        // socket buffers are finite and nothing else drains the pipe.
        let mut last = u64::MAX;
        let mut stable = 0;
        while stable < 3 {
            std::thread::sleep(Duration::from_millis(150));
            let now = written.load(Ordering::Relaxed);
            if now == last {
                stable += 1;
            } else {
                stable = 0;
                last = now;
            }
        }
        let parked_at = written.load(Ordering::Relaxed);
        assert!(
            parked_at < TOTAL as u64,
            "no backpressure: the writer pushed 24 MiB while the server read nothing"
        );

        hold.store(false, Ordering::Relaxed);
        let response = exec.join().unwrap().unwrap();
        writer.join().unwrap().unwrap();
        assert!(response.is_success);
        assert!(String::from_utf8_lossy(&response.body).contains(&expected_sha));
        assert_eq!(written.load(Ordering::Relaxed), TOTAL as u64);
        free_body_stream(id);
    }

    /// A TCP twin of the offline HTTP/3 host: serves `h3.test` over TLS on a
    /// TCP port using the same per-process PKI, so the H3→TCP fallback can be
    /// exercised for one origin with one trust anchor.
    fn h3_test_tls_server<F>(handle: F) -> u16
    where
        F: Fn(TlsStream) + Send + Sync + 'static,
    {
        use rustls::pki_types::PrivateKeyDer;
        use rustls::{ServerConfig, ServerConnection};

        let pki = test_pki();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(pki.leaf_der.clone())],
                PrivateKeyDer::try_from(pki.leaf_key_der.clone()).unwrap(),
            )
            .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let config = Arc::new(config);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = Arc::new(handle);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let config = config.clone();
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
        port
    }

    /// The fallback decision, permitting half: nothing listens on UDP, so the
    /// HTTP/3 attempt dies at connect with zero streamed bytes consumed — and
    /// the TCP fallback takes over the intact stream from byte 0 and
    /// completes the upload. (PUT, so the method gate is not what permits it;
    /// the consumed-bytes gate is the decision under test.)
    #[test]
    fn streamed_upload_falls_back_to_tcp_while_nothing_was_consumed() {
        let port = h3_test_tls_server(upload_handler);
        let _root = with_test_root(CertificateDer::from(test_pki().ca_der.clone()));
        let client = super::client_with(VaneClientConfig {
            protocol_mode: VaneProtocolMode::Http3ThenHttp2ThenHttp1,
            dns_overrides: HashMap::from([(TEST_HOST.to_string(), "127.0.0.1".to_string())]),
            connection_pool_enabled: false,
            // Bounds the H3 attempt even where the refused UDP port is not
            // reported via ICMP and the handshake has to time out instead.
            timeout_seconds: Some(3),
            ..VaneClientConfig::default()
        });
        let body = body_pattern(300 * 1024);
        let expected_sha = sha256_hex(&body);
        let id = create_body_stream(Some(body.len() as u64));
        let writer = spawn_writer(id, body, 64 * 1024);

        let mut request = test_request(&format!("https://{TEST_HOST}:{port}/upload"));
        request.method = "PUT".to_string();
        request.body_stream_id = Some(id);
        let response = client.execute(request).unwrap();
        writer.join().unwrap().unwrap();

        assert!(response.is_success);
        assert_eq!(
            response.http_version,
            Some(VaneHttpVersion::Http11),
            "the response must have come over the TCP fallback"
        );
        let text = String::from_utf8_lossy(&response.body).into_owned();
        assert!(text.contains("\"framing\": \"sized\""), "{text}");
        assert!(text.contains(&expected_sha), "{text}");
        free_body_stream(id);
    }
}

type TlsStream = rustls::StreamOwned<rustls::ServerConnection, std::net::TcpStream>;

/// A localhost TLS listener with a per-run CA, so a test can drive the real
/// TCP transport against a hand-written HTTP response. Returns the port, the
/// CA DER the caller must install in `TEST_ROOT`, and the leaf DER so a test
/// can compute a pin that matches what the server presents.
fn local_tls_server<F>(
    alpn: &[u8],
    handle: F,
) -> (u16, CertificateDer<'static>, CertificateDer<'static>)
where
    F: Fn(TlsStream) + Send + Sync + 'static,
{
    local_tls_server_with_versions(rustls::DEFAULT_VERSIONS, alpn, handle)
}

/// [`local_tls_server`] with the server's TLS versions pinned, so a test can
/// stand up e.g. a TLS 1.2-only peer for the `tls_min_version` knob.
fn local_tls_server_with_versions<F>(
    versions: &[&'static rustls::SupportedProtocolVersion],
    alpn: &[u8],
    handle: F,
) -> (u16, CertificateDer<'static>, CertificateDer<'static>)
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
    let leaf_for_pins = leaf_der.clone();
    let leaf_pkcs8 = PrivateKeyDer::try_from(leaf_key.serialize_der()).unwrap();

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server_config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
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
    (port, ca_der, leaf_for_pins)
}

/// Answers each request with a raw response picked by path, so a test can
/// script the exact bytes on the wire — including a repeated `Set-Cookie` and
/// an `HTTP/1.0` status line, neither of which reqwest can be asked to fake.
fn raw_http_server(
    routes: &'static [(&'static str, &'static str)],
) -> (u16, CertificateDer<'static>) {
    let (port, ca, _leaf) = local_tls_server(b"http/1.1", raw_http_handler(routes));
    (port, ca)
}

/// The scripted-response handler [`raw_http_server`] runs, split out so a
/// test can pair it with [`local_tls_server_with_versions`].
fn raw_http_handler(
    routes: &'static [(&'static str, &'static str)],
) -> impl Fn(TlsStream) + Send + Sync + 'static {
    move |mut tls| {
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
    }
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
        tls_config(&mode, HashMap::new(), None, None)
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
    match redirect_target(&response, current, &request, 0, 10, pins) {
        RedirectDecision::Follow(url) => Some(url),
        // The reasons are asserted in the shared gate's own tests; here only
        // "did the TCP adapter hand back a hop" matters.
        RedirectDecision::Stop | RedirectDecision::Refused(_) => None,
    }
}

/// TCP twin of `h3_offline::tests::redirect_chain_honours_the_configured_hop_cap`:
/// the same 3-hop chain, refused at `max_redirects = 2`, followed at 3 —
/// pinning that both transports share one cap decision.
#[test]
fn redirect_chain_honours_the_configured_hop_cap() {
    let (port, ca) = raw_http_server(&[
        (
            "/a",
            "HTTP/1.1 302 Found\r\nLocation: /b\r\nContent-Length: 0\r\n\r\n",
        ),
        (
            "/b",
            "HTTP/1.1 302 Found\r\nLocation: /c\r\nContent-Length: 0\r\n\r\n",
        ),
        (
            "/c",
            "HTTP/1.1 302 Found\r\nLocation: /d\r\nContent-Length: 0\r\n\r\n",
        ),
        (
            "/d",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        ),
    ]);
    let _guard = with_test_root(ca);
    let client = |max_redirects: u32| {
        client_with(VaneClientConfig {
            base_url: Some(format!("https://localhost:{port}")),
            protocol_mode: VaneProtocolMode::Http1Only,
            timeout_seconds: Some(10),
            max_redirects,
            ..VaneClientConfig::default()
        })
    };

    let refused = client(2).execute(crate::test_request("/a")).unwrap();
    assert_eq!(refused.status_code, 302);
    assert_eq!(
        crate::first_header_value(&refused.headers, REDIRECT_REFUSED_HEADER),
        Some(crate::REDIRECT_REFUSED_HOP_CAP)
    );

    let followed = client(3).execute(crate::test_request("/a")).unwrap();
    assert!(followed.is_success);
    assert!(
        followed.url.ends_with("/d"),
        "redirect chain should end on /d, got {}",
        followed.url
    );
}

/// The one real TLS-version enforcement site: `tls_min_version = tls13` on
/// the TCP path refuses a TLS 1.2-only server that the default posture
/// accepts. (HTTP/3 has no enforcement to test — QUIC is TLS 1.3-always, and
/// the incompatible combination is refused at construction.)
#[test]
fn tls_min_13_refuses_a_tls12_only_server() {
    static ROUTES: &[(&str, &str)] = &[(
        "/",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    )];
    let (port, ca, _leaf) = local_tls_server_with_versions(
        &[&rustls::version::TLS12],
        b"http/1.1",
        raw_http_handler(ROUTES),
    );
    let _guard = with_test_root(ca);
    let client = |tls_min_version: Option<VaneTlsVersion>| {
        client_with(VaneClientConfig {
            base_url: Some(format!("https://localhost:{port}")),
            protocol_mode: VaneProtocolMode::Http1Only,
            timeout_seconds: Some(10),
            tls_min_version,
            ..VaneClientConfig::default()
        })
    };

    // Control half: the server itself is reachable under the default
    // posture (TLS 1.2 + 1.3), so the refusal below is the knob's doing.
    let response = client(None).execute(crate::test_request("/")).unwrap();
    assert!(response.is_success);

    // With the floor raised to 1.3 the handshake has no common version and
    // the request fails before any HTTP happens.
    let err = client(Some(VaneTlsVersion::Tls13))
        .execute(crate::test_request("/"))
        .unwrap_err();
    assert!(
        !matches!(err, VaneError::InvalidRequest(_)),
        "expected a handshake failure, not a config rejection: {err}"
    );
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
        let (port, ca, _leaf) = local_tls_server(b"http/1.1", serve);
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
            let cookies: Vec<&str> = response
                .headers
                .iter()
                .filter(|header| header.name == "set-cookie")
                .map(|header| header.value.as_str())
                .collect();
            assert_eq!(
                cookies,
                vec!["a=1; Path=/", "b=2; Path=/"],
                "cookies_enabled={cookies_enabled}"
            );
            assert_eq!(response.http_version, Some(VaneHttpVersion::Http11));
        }
    }

    /// The TCP half of the list rule pinned by
    /// `repeated_h3_headers_are_preserved_in_order_across_header_blocks` in
    /// the crate tests: the same repeated wire shape must yield the same
    /// ordered, duplicate-preserving list here, or which headers a caller
    /// sees depends on whether UDP happened to work. Hyper lowercases the
    /// mixed-case spelling; hyper also rejects differing repeated
    /// `Content-Length` values outright, so that edge is pinned on the H3
    /// merge, which this response cannot reach.
    #[test]
    fn repeated_headers_are_preserved_identically_on_both_transports() {
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
        let multi: Vec<&str> = response
            .headers
            .iter()
            .filter(|header| header.name == "x-multi")
            .map(|header| header.value.as_str())
            .collect();
        assert_eq!(multi, vec!["a", "b"], "duplicates must survive, in order");
        let cookies: Vec<&str> = response
            .headers
            .iter()
            .filter(|header| header.name == "set-cookie")
            .map(|header| header.value.as_str())
            .collect();
        assert_eq!(cookies, vec!["a=1; Path=/", "b=2; Path=/"]);
        // Both `location` occurrences stay in the list as data; the first is
        // the value `redirect_target`'s `HeaderMap::get` would act on.
        assert_eq!(
            crate::first_header_value(&response.headers, "location"),
            Some("https://first.example/")
        );
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

        let cookies: Vec<&str> = response
            .headers
            .iter()
            .filter(|header| header.name == "set-cookie")
            .map(|header| header.value.as_str())
            .collect();
        assert_eq!(cookies, vec!["final=2; Path=/"]);
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

    /// The TCP half of `h3_offline`'s `remote_ip_is_the_socket_peer`: the
    /// field reports the peer reqwest actually connected to, captured before
    /// `read_body` moves the response. Through a CONNECT proxy this would be
    /// the proxy — the only address `remote_addr()` can report.
    #[test]
    fn remote_ip_is_the_socket_peer() {
        let (port, ca) = raw_http_server(&[("/", TWO_COOKIES)]);
        let _guard = with_test_root(ca);

        let response = get(port, false);
        assert_eq!(response.remote_ip.as_deref(), Some("127.0.0.1"));
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

/// `VaneClient::warmup` on the TCP transport: client construction, the TLS
/// probe, and the best-effort failure contract.
mod warmup {
    use super::*;

    const OK: &str = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

    /// End to end over the real transport: warmup builds and caches the
    /// client, handshakes against a live listener without sending a request,
    /// repeats cheaply, and leaves the client fully usable.
    #[test]
    fn warmup_builds_the_client_probes_the_target_and_repeats() {
        let (port, ca) = raw_http_server(&[("/", OK)]);
        let _guard = with_test_root(ca);

        let client = client_with(VaneClientConfig {
            base_url: Some(format!("https://localhost:{port}")),
            protocol_mode: VaneProtocolMode::Http1Only,
            timeout_seconds: Some(10),
            // The probe resolves one address; the resolver may prefer ::1
            // while the test server listens on 127.0.0.1 only. Same pinning
            // the h3_offline tests use.
            dns_overrides: HashMap::from([("localhost".to_string(), "127.0.0.1".to_string())]),
            ..VaneClientConfig::default()
        });

        assert!(client.tcp_client.lock().unwrap().is_none());
        client
            .warmup_inner(None)
            .expect("warmup against a live local server");
        assert!(
            client.tcp_client.lock().unwrap().is_some(),
            "warmup should have built and cached the TCP client"
        );
        // Idempotent: the second call reuses the cached client and stays Ok.
        client.warmup_inner(None).expect("repeat warmup");

        // The warmed client serves a real request.
        let response = client.execute(crate::test_request("/")).unwrap();
        assert_eq!(response.status_code, 200);
    }

    /// No URL and no baseUrl: construction still happens — that is most of
    /// the win — and nothing is dialed.
    #[test]
    fn warmup_without_a_target_only_builds_the_client() {
        // Never contacted; exists so a per-run CA is installed and the client
        // build stays hermetic under TEST_ROOT.
        let (_port, ca) = raw_http_server(&[]);
        let _guard = with_test_root(ca);

        let client = client_with(VaneClientConfig {
            protocol_mode: VaneProtocolMode::Http2Only,
            ..VaneClientConfig::default()
        });

        client.warmup_inner(None).expect("construction-only warmup");
        assert!(client.tcp_client.lock().unwrap().is_some());
    }

    /// A dead target fails the probe but must leave the built client cached;
    /// the public wrapper swallows the failure entirely, because the first
    /// real request reports the same problem with a better message.
    #[test]
    fn a_failed_probe_reports_but_keeps_the_built_client() {
        let (_port, ca) = raw_http_server(&[]);
        let _guard = with_test_root(ca);

        // Accepts and immediately hangs up, so the TLS handshake can never
        // complete.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let dead_port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                drop(stream);
            }
        });

        let client = client_with(VaneClientConfig {
            base_url: Some(format!("https://localhost:{dead_port}")),
            protocol_mode: VaneProtocolMode::Http1Only,
            timeout_seconds: Some(5),
            // Pin the probe onto the dropping listener rather than whatever
            // the resolver prefers for localhost.
            dns_overrides: HashMap::from([("localhost".to_string(), "127.0.0.1".to_string())]),
            ..VaneClientConfig::default()
        });

        let err = client.warmup_inner(None).unwrap_err();
        assert!(
            matches!(
                err,
                VaneError::Tls(_) | VaneError::Transport(_) | VaneError::ConnectTimeout(_)
            ),
            "{err:?}"
        );
        assert!(
            client.tcp_client.lock().unwrap().is_some(),
            "construction must survive a failed probe"
        );
        // The public API swallows exactly this class of failure.
        client.warmup(None);
    }
}

/// The never-resume-pinned-hosts rule on the TCP transport, mirroring the
/// HTTP/3 gate (`may_resume_tls_session`): a resumed TLS handshake carries no
/// Certificate message — rustls restores the chain cached when the ticket was
/// stored and never calls `verify_server_cert` — so the only connection shape
/// on which `PinnedServerCertVerifier` runs at all is a full handshake.
///
/// The server records each connection's `HandshakeKind`; `Full` is the
/// observable proof the verifier ran (a full handshake cannot complete
/// without it), `Resumed` the proof it was skipped.
mod resumption {
    use super::*;
    use rustls::HandshakeKind;

    const OK_CLOSE: &str = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

    type Kinds = Arc<std::sync::Mutex<Vec<Option<HandshakeKind>>>>;

    /// [`local_tls_server`] with each connection's handshake kind recorded.
    /// Records land in handshake order: the handshake is driven to completion
    /// before serving, and these tests issue requests strictly sequentially.
    fn recording_server() -> (u16, CertificateDer<'static>, CertificateDer<'static>, Kinds) {
        let kinds: Kinds = Arc::default();
        let record = kinds.clone();
        let (port, ca, leaf) = local_tls_server(b"http/1.1", move |mut tls| {
            while tls.conn.is_handshaking() {
                if tls.conn.complete_io(&mut tls.sock).is_err() {
                    return;
                }
            }
            record.lock().unwrap().push(tls.conn.handshake_kind());
            // One scripted response, `Connection: close`, so every request
            // below costs exactly one handshake. A warmup probe never sends a
            // request; its close_notify lands here as EOF.
            let mut buf = [0u8; 8192];
            let mut pending = Vec::new();
            loop {
                match std::io::Read::read(&mut tls, &mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(read) => pending.extend_from_slice(&buf[..read]),
                }
                if pending.windows(4).any(|window| window == b"\r\n\r\n") {
                    std::io::Write::write_all(&mut tls, OK_CLOSE.as_bytes()).ok();
                    std::io::Write::flush(&mut tls).ok();
                    return;
                }
            }
        });
        (port, ca, leaf, kinds)
    }

    /// Pool off, so every request handshakes rather than reusing a pooled
    /// connection; the server's `Connection: close` makes the peer agree.
    fn fresh_handshake_client(
        port: u16,
        certificate_pins: HashMap<String, Vec<String>>,
    ) -> VaneClient {
        client_with(VaneClientConfig {
            base_url: Some(format!("https://localhost:{port}")),
            protocol_mode: VaneProtocolMode::Http1Only,
            timeout_seconds: Some(10),
            connection_pool_enabled: false,
            // Same pinning as the warmup tests: the resolver may prefer ::1
            // while the server listens on 127.0.0.1 only.
            dns_overrides: HashMap::from([("localhost".to_string(), "127.0.0.1".to_string())]),
            certificate_pins,
            ..VaneClientConfig::default()
        })
    }

    fn recorded(kinds: &Kinds) -> Vec<Option<HandshakeKind>> {
        kinds.lock().unwrap().clone()
    }

    #[test]
    fn a_pinned_host_never_resumes_while_an_unpinned_host_does() {
        let (port, ca, leaf, kinds) = recording_server();
        let _guard = with_test_root(ca);

        // Unpinned: the second connection must keep resuming — the gate is
        // per-host, not client-wide.
        let unpinned = fresh_handshake_client(port, HashMap::new());
        unpinned.execute(crate::test_request("/")).unwrap();
        unpinned.execute(crate::test_request("/")).unwrap();
        assert_eq!(
            recorded(&kinds),
            vec![Some(HandshakeKind::Full), Some(HandshakeKind::Resumed)],
            "an unpinned host stopped resuming — the pinned-host gate overshot"
        );

        // Pinned, with a pin that MATCHES the presented leaf so every full
        // handshake succeeds: each connection must be a full handshake, since
        // a resumed one would never consult the verifier the pin lives in.
        let pinned = fresh_handshake_client(
            port,
            HashMap::from([("localhost".to_string(), certificate_pin_values(&leaf))]),
        );
        pinned.execute(crate::test_request("/")).unwrap();
        pinned.execute(crate::test_request("/")).unwrap();
        assert_eq!(
            recorded(&kinds)[2..],
            [Some(HandshakeKind::Full), Some(HandshakeKind::Full)],
            "a pinned host resumed a TLS session, so its pin was never checked"
        );
    }

    #[test]
    fn pins_added_after_tickets_exist_invalidate_them() {
        let (port, ca, leaf, kinds) = recording_server();
        let _guard = with_test_root(ca);

        // Unpinned first contact banks the server's session tickets.
        let client = fresh_handshake_client(port, HashMap::new());
        client.execute(crate::test_request("/")).unwrap();

        // Pinning the host must strand those tickets: they were stored under
        // the old trust context, and resuming from one would skip the
        // certificate exchange the new pin needs to be checked against.
        client
            .set_certificate_pins("localhost".to_string(), certificate_pin_values(&leaf))
            .unwrap();
        client.execute(crate::test_request("/")).unwrap();
        assert_eq!(
            recorded(&kinds),
            vec![Some(HandshakeKind::Full), Some(HandshakeKind::Full)],
            "a ticket banked before the host was pinned was resumed after"
        );
    }

    #[test]
    fn warmup_primes_resumption_for_unpinned_hosts_only() {
        let (port, ca, leaf, kinds) = recording_server();
        let _guard = with_test_root(ca);

        // Unpinned: the probe's session is exactly what the first real
        // request resumes — warmup's banked value, kept working.
        let unpinned = fresh_handshake_client(port, HashMap::new());
        unpinned.warmup_inner(None).unwrap();
        unpinned.execute(crate::test_request("/")).unwrap();
        assert_eq!(
            recorded(&kinds),
            vec![Some(HandshakeKind::Full), Some(HandshakeKind::Resumed)],
            "warmup no longer primes resumption for an unpinned host"
        );

        // Pinned: the probe still runs — warm verifier, warm DNS, and an
        // early pin check — but must not bank a resumable session.
        let pinned = fresh_handshake_client(
            port,
            HashMap::from([("localhost".to_string(), certificate_pin_values(&leaf))]),
        );
        pinned.warmup_inner(None).unwrap();
        pinned.execute(crate::test_request("/")).unwrap();
        assert_eq!(
            recorded(&kinds)[2..],
            [Some(HandshakeKind::Full), Some(HandshakeKind::Full)],
            "warmup primed a resumable TLS session for a pinned host"
        );
    }
}

mod streaming {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::{local_tls_server, raw_http_server, with_test_root};
    use crate::{VaneClientConfig, VaneError, VaneHttpVersion, VaneProtocolMode};

    fn streaming_client(port: u16) -> Arc<crate::VaneClient> {
        Arc::new(
            crate::VaneClient::new(VaneClientConfig {
                base_url: Some(format!("https://localhost:{port}")),
                protocol_mode: VaneProtocolMode::Http1Only,
                timeout_seconds: Some(10),
                ..VaneClientConfig::default()
            })
            .unwrap(),
        )
    }

    /// Reads one request head off the TLS stream; the response is the
    /// handler's business. Good for one request per connection.
    fn read_request_head(tls: &mut super::TlsStream) {
        let mut buf = [0u8; 4096];
        let mut pending = Vec::new();
        loop {
            match std::io::Read::read(tls, &mut buf) {
                Ok(0) | Err(_) => return,
                Ok(read) => pending.extend_from_slice(&buf[..read]),
            }
            if pending.windows(4).any(|window| window == b"\r\n\r\n") {
                return;
            }
        }
    }

    /// The load-bearing streaming property: a chunk is delivered as soon as
    /// the server sends it, not when the body completes. The server holds the
    /// second half back for 500 ms, so the first pull can only ever contain
    /// the first half — unless the client buffered the whole body, which is
    /// exactly the bug this pins against.
    #[test]
    fn first_chunk_arrives_before_the_body_is_complete() {
        let (port, ca, _leaf) = local_tls_server(b"http/1.1", |mut tls| {
            read_request_head(&mut tls);
            let head = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n";
            std::io::Write::write_all(&mut tls, head.as_bytes()).ok();
            std::io::Write::write_all(&mut tls, b"part1").ok();
            std::io::Write::flush(&mut tls).ok();
            std::thread::sleep(std::time::Duration::from_millis(500));
            std::io::Write::write_all(&mut tls, b"part2").ok();
            std::io::Write::flush(&mut tls).ok();
        });
        let _guard = with_test_root(ca);
        let client = streaming_client(port);

        let stream = Arc::clone(&client)
            .execute_streaming(crate::test_request("/"))
            .unwrap();
        let head = stream.head();
        assert!(head.is_success);
        assert!(head.body.is_empty());
        assert_eq!(head.http_version, Some(VaneHttpVersion::Http11));

        let first = stream.read_chunk().unwrap().unwrap();
        assert_eq!(
            first.as_slice(),
            b"part1",
            "the first pull must not wait for (or contain) the held-back half"
        );
        let mut rest = Vec::new();
        while let Some(chunk) = stream.read_chunk().unwrap() {
            rest.extend_from_slice(&chunk);
        }
        assert_eq!(rest.as_slice(), b"part2");
    }

    /// The load-bearing FFI rule from the streaming design: a blocked
    /// `vane_ffi_stream_read` must never hold the stream-registry lock.
    /// Stream A's second read is parked on a server that holds its body
    /// open; while it is provably parked, a second stream's entire
    /// create-read-close lifecycle must complete. If the parked read held
    /// the map lock, stream B would hang behind it and the 5-second
    /// receive below would fail.
    #[test]
    fn ffi_blocked_read_does_not_hold_the_stream_registry() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        let release = Arc::new(AtomicBool::new(false));
        let release_for_server = Arc::clone(&release);
        let connections = Arc::new(AtomicUsize::new(0));
        // Connection 1 is stream A: half a body, then hold until released.
        // Every later connection is stream B: a small complete body.
        let (port, ca, _leaf) = local_tls_server(b"http/1.1", move |mut tls| {
            read_request_head(&mut tls);
            if connections.fetch_add(1, Ordering::SeqCst) == 0 {
                let head = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n";
                std::io::Write::write_all(&mut tls, head.as_bytes()).ok();
                std::io::Write::write_all(&mut tls, b"part1").ok();
                std::io::Write::flush(&mut tls).ok();
                while !release_for_server.load(Ordering::SeqCst) {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                std::io::Write::write_all(&mut tls, b"part2").ok();
                std::io::Write::flush(&mut tls).ok();
            } else {
                let head = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\ndone!";
                std::io::Write::write_all(&mut tls, head.as_bytes()).ok();
                std::io::Write::flush(&mut tls).ok();
            }
        });
        let _guard = with_test_root(ca);
        let client = streaming_client(port);
        let client_handle =
            crate::FFI_NEXT_HANDLE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        crate::FFI_CLIENTS
            .lock()
            .unwrap()
            .insert(client_handle, Arc::clone(&client));

        // Stream A up and half-read, so its next read parks.
        let request_a = crate::test_ffi_request("/");
        let mut stream_a = 0u64;
        let head_a = crate::vane_ffi_execute_streaming(
            client_handle,
            &request_a,
            std::ptr::null(),
            0,
            &mut stream_a,
        );
        unsafe {
            assert_eq!((*head_a).error.len, 0);
            crate::vane_ffi_response_free(head_a);
        }
        let first = crate::vane_ffi_stream_read(stream_a);
        assert!(!first.eof && first.error.len == 0);
        assert_eq!(
            unsafe { std::slice::from_raw_parts(first.body.data, first.body.len) },
            b"part1"
        );
        crate::vane_ffi_buffer_free(first.body);
        crate::vane_ffi_buffer_free(first.error);

        let parked = std::thread::spawn(move || {
            let chunk = crate::vane_ffi_stream_read(stream_a);
            let body = if chunk.body.data.is_null() {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(chunk.body.data, chunk.body.len) }.to_vec()
            };
            let failed = chunk.error.len > 0;
            crate::vane_ffi_buffer_free(chunk.body);
            crate::vane_ffi_buffer_free(chunk.error);
            (body, chunk.eof, failed)
        });
        // Give the parked read time to enter the blocking pull. Best-effort:
        // if it has not parked yet, the test still passes but proves less.
        std::thread::sleep(std::time::Duration::from_millis(200));

        // Stream B's whole lifecycle, off-thread so a registry deadlock
        // fails the receive below instead of hanging the test forever.
        let (done_tx, done_rx) = std::sync::mpsc::channel::<Vec<u8>>();
        std::thread::spawn(move || {
            let request_b = crate::test_ffi_request("/");
            let mut stream_b = 0u64;
            let head_b = crate::vane_ffi_execute_streaming(
                client_handle,
                &request_b,
                std::ptr::null(),
                0,
                &mut stream_b,
            );
            unsafe {
                assert_eq!((*head_b).error.len, 0);
                crate::vane_ffi_response_free(head_b);
            }
            let mut body = Vec::new();
            loop {
                let chunk = crate::vane_ffi_stream_read(stream_b);
                assert_eq!(chunk.error.len, 0);
                if chunk.eof {
                    crate::vane_ffi_buffer_free(chunk.body);
                    crate::vane_ffi_buffer_free(chunk.error);
                    break;
                }
                body.extend_from_slice(unsafe {
                    std::slice::from_raw_parts(chunk.body.data, chunk.body.len)
                });
                crate::vane_ffi_buffer_free(chunk.body);
                crate::vane_ffi_buffer_free(chunk.error);
            }
            crate::vane_ffi_stream_close(stream_b);
            done_tx.send(body).ok();
        });
        let body_b = done_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect(
                "stream B's create/read/close must complete while stream A's read is parked — \
                 a blocked vane_ffi_stream_read is holding the registry lock",
            );
        assert_eq!(body_b.as_slice(), b"done!");

        // Let stream A finish and drain cleanly.
        release.store(true, std::sync::atomic::Ordering::SeqCst);
        let (part2, eof, failed) = parked.join().unwrap();
        assert!(!eof && !failed);
        assert_eq!(part2.as_slice(), b"part2");
        let end = crate::vane_ffi_stream_read(stream_a);
        assert!(end.eof);
        crate::vane_ffi_buffer_free(end.body);
        crate::vane_ffi_buffer_free(end.error);
        crate::vane_ffi_stream_close(stream_a);
        crate::vane_ffi_client_close(client_handle);
    }

    #[test]
    fn cancel_mid_stream_is_terminal() {
        let (port, ca, _leaf) = local_tls_server(b"http/1.1", |mut tls| {
            read_request_head(&mut tls);
            let head = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n";
            std::io::Write::write_all(&mut tls, head.as_bytes()).ok();
            std::io::Write::write_all(&mut tls, b"part1").ok();
            std::io::Write::flush(&mut tls).ok();
            // Hold the connection open so the body never completes.
            std::thread::sleep(std::time::Duration::from_secs(5));
        });
        let _guard = with_test_root(ca);
        let client = streaming_client(port);
        let cancel_id = crate::cancel_token_create();
        let mut request = crate::test_request("/");
        request.cancel_token_id = Some(cancel_id);

        let stream = Arc::clone(&client).execute_streaming(request).unwrap();
        assert_eq!(stream.read_chunk().unwrap().unwrap().as_slice(), b"part1");
        crate::cancel_token_cancel(cancel_id);
        assert!(matches!(stream.read_chunk(), Err(VaneError::Cancelled(_))));
        // Terminal: replays, never resurrects.
        assert!(matches!(stream.read_chunk(), Err(VaneError::Cancelled(_))));
        crate::cancel_token_free(cancel_id);
    }

    #[test]
    fn body_limit_applies_to_streamed_bodies() {
        let (port, ca, _leaf) = local_tls_server(b"http/1.1", |mut tls| {
            read_request_head(&mut tls);
            let body = vec![b'x'; 128 * 1024];
            let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
            std::io::Write::write_all(&mut tls, head.as_bytes()).ok();
            std::io::Write::write_all(&mut tls, &body).ok();
            std::io::Write::flush(&mut tls).ok();
        });
        let _guard = with_test_root(ca);
        let client = Arc::new(
            crate::VaneClient::new(VaneClientConfig {
                base_url: Some(format!("https://localhost:{port}")),
                protocol_mode: VaneProtocolMode::Http1Only,
                timeout_seconds: Some(10),
                max_response_body_bytes: 1024,
                ..VaneClientConfig::default()
            })
            .unwrap(),
        );

        let stream = Arc::clone(&client)
            .execute_streaming(crate::test_request("/"))
            .unwrap();
        let err = loop {
            match stream.read_chunk() {
                Ok(Some(_)) => {}
                Ok(None) => panic!("stream ended under the limit"),
                Err(err) => break err,
            }
        };
        assert!(matches!(err, VaneError::BodyLimitExceeded(_)), "{err}");
    }

    #[test]
    fn redirect_chain_streams_the_final_hop() {
        let (port, ca) = raw_http_server(&[
            (
                "/hop",
                "HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\n\r\n",
            ),
            ("/final", "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone"),
        ]);
        let _guard = with_test_root(ca);
        let client = streaming_client(port);

        let stream = Arc::clone(&client)
            .execute_streaming(crate::test_request("/hop"))
            .unwrap();
        let head = stream.head();
        assert_eq!(head.status_code, 200);
        assert!(head.url.ends_with("/final"), "got {}", head.url);
        let mut body = Vec::new();
        while let Some(chunk) = stream.read_chunk().unwrap() {
            body.extend_from_slice(&chunk);
        }
        assert_eq!(body.as_slice(), b"done");
    }

    /// A drained stream's connection goes back to hyper's pool; the follow-up
    /// buffered request must ride it instead of dialing a second one.
    #[test]
    fn drained_stream_connection_is_reused() {
        static CONNECTIONS: AtomicUsize = AtomicUsize::new(0);
        const OK: &str = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let (port, ca, _leaf) = local_tls_server(b"http/1.1", |mut tls| {
            CONNECTIONS.fetch_add(1, Ordering::SeqCst);
            // Keep-alive loop: serve every request on this connection.
            let mut buf = [0u8; 4096];
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
                    pending.drain(..end);
                    if std::io::Write::write_all(&mut tls, OK.as_bytes()).is_err() {
                        return;
                    }
                    std::io::Write::flush(&mut tls).ok();
                }
            }
        });
        let _guard = with_test_root(ca);
        let client = streaming_client(port);

        let stream = Arc::clone(&client)
            .execute_streaming(crate::test_request("/"))
            .unwrap();
        let mut body = Vec::new();
        while let Some(chunk) = stream.read_chunk().unwrap() {
            body.extend_from_slice(&chunk);
        }
        assert_eq!(body.as_slice(), b"ok");

        let followup = client.execute(crate::test_request("/")).unwrap();
        assert!(followup.is_success);
        assert_eq!(
            CONNECTIONS.load(Ordering::SeqCst),
            1,
            "the buffered follow-up must reuse the drained stream's connection"
        );
    }
}
