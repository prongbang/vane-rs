//! In-process quiche HTTP/3 server, so tests can drive the real H3 transport
//! without `VANE_TEST_BASE_URL` or a network. Exists above all to prove TLS
//! session resumption end to end: it terminates real QUIC+TLS, issues
//! NewSessionTickets, and records per connection whether the handshake was a
//! resumption (`SSL_session_reused` via `quiche::Connection::is_resumed`).
//!
//! The client trusts the per-process test CA through the `#[cfg(test)]` seam
//! in `create_quiche_config` — the H3 twin of the TCP path's `TEST_ROOT`.
//! That seam is additive (platform roots and `verify_peer(true)` stay in
//! force) and compiled out of every non-test build.
//!
//! ponytail: a focused test server, not a framework — connections are keyed
//! by peer address (no CID routing, no migration; the client disables it), no
//! Retry, no version negotiation (the client is this same quiche build), and
//! responses are buffered whole. Grow those only if a test actually needs it.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use quiche::h3::NameValue;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};

/// Hostname every test server answers as; tests point it at 127.0.0.1 through
/// `dns_overrides`, so resolution never leaves the process's control.
pub(crate) const TEST_HOST: &str = "h3.test";

/// One CA and one leaf per test process, shared by every server instance.
/// Sharing one PKI keeps the trust seam a set-once `OnceLock` — tests never
/// swap anchors, so they need no serializing lock and can run in parallel.
pub(crate) struct TestPki {
    ca_pem_path: PathBuf,
    cert_pem_path: PathBuf,
    key_pem_path: PathBuf,
    /// Leaf DER, so tests can compute the pin the server actually presents.
    pub(crate) leaf_der: Vec<u8>,
}

static TEST_PKI: OnceLock<TestPki> = OnceLock::new();

/// The extra trust anchor `create_quiche_config`'s test-only seam loads.
/// `None` until a test starts a server, so suites that never touch the
/// offline server keep a byte-identical trust path.
pub(crate) fn test_ca_pem_path() -> Option<&'static str> {
    TEST_PKI.get().and_then(|pki| pki.ca_pem_path.to_str())
}

pub(crate) fn test_pki() -> &'static TestPki {
    TEST_PKI.get_or_init(|| {
        let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
        // rcgen's default gives CA and leaf the identical subject DN, and
        // BoringSSL then treats the leaf (subject == issuer) as self-signed
        // and never builds the chain — webpki on the TCP path tolerates it,
        // X509 verification does not. Distinct CNs keep BoringSSL honest.
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "vane offline test CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let ca_pem = ca.pem();
        let issuer = Issuer::new(ca_params, ca_key);

        let mut leaf_params = CertificateParams::new(vec![TEST_HOST.to_string()]).unwrap();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, TEST_HOST);
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();

        // quiche only loads trust anchors and keys from files. One tiny
        // pid-named trio in the OS temp dir, never deleted: the path must
        // outlive every quiche config built in this process.
        let dir = std::env::temp_dir();
        let pid = std::process::id();
        let write = |name: &str, contents: &str| -> PathBuf {
            let path = dir.join(format!("vane-h3-offline-{pid}-{name}"));
            std::fs::write(&path, contents).unwrap();
            path
        };
        TestPki {
            ca_pem_path: write("ca.pem", &ca_pem),
            cert_pem_path: write("cert.pem", &leaf.pem()),
            key_pem_path: write("key.pem", &leaf_key.serialize_pem()),
            leaf_der: leaf.der().to_vec(),
        }
    })
}

/// A localhost HTTP/3 origin on an ephemeral port, served from one background
/// thread until dropped. `handshakes` records, in accept order, whether each
/// connection's TLS handshake resumed a previous session.
pub(crate) struct TestH3Server {
    port: u16,
    handshakes: Arc<Mutex<Vec<bool>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl TestH3Server {
    pub(crate) fn start() -> Self {
        let pki = test_pki();
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        // The tick that bounds every loop below: recv wakes at least this
        // often to fire QUIC timers and check the stop flag.
        socket
            .set_read_timeout(Some(Duration::from_millis(5)))
            .unwrap();
        let port = socket.local_addr().unwrap().port();

        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        config
            .load_cert_chain_from_pem_file(pki.cert_pem_path.to_str().unwrap())
            .unwrap();
        config
            .load_priv_key_from_pem_file(pki.key_pem_path.to_str().unwrap())
            .unwrap();
        config
            .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
            .unwrap();
        config.set_max_idle_timeout(10_000);
        config.set_max_recv_udp_payload_size(MAX_SERVER_DATAGRAM);
        config.set_max_send_udp_payload_size(MAX_SERVER_DATAGRAM);
        config.enable_dgram(true, 16, 16);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_stream_data_uni(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);

        let handshakes = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = std::thread::spawn({
            let handshakes = Arc::clone(&handshakes);
            let stop = Arc::clone(&stop);
            move || serve(&socket, config, &handshakes, &stop)
        });
        Self {
            port,
            handshakes,
            stop,
            thread: Some(thread),
        }
    }

    pub(crate) fn url(&self, path: &str) -> String {
        format!("https://{TEST_HOST}:{}{path}", self.port)
    }

    /// Snapshot of the per-connection resumption log, in accept order.
    pub(crate) fn handshakes(&self) -> Vec<bool> {
        self.handshakes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Drop for TestH3Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            thread.join().ok();
        }
    }
}

const MAX_SERVER_DATAGRAM: usize = 1350;

struct ServerConn {
    conn: quiche::Connection,
    h3: Option<quiche::h3::Connection>,
    requests: HashMap<u64, PendingRequest>,
    /// Response bodies still being written, keyed by stream id: a body larger
    /// than the stream's flow-control window cannot leave in one pass, which
    /// is exactly what the client's streaming tests need to exist.
    pending_bodies: HashMap<u64, PendingBody>,
}

struct PendingBody {
    body: Vec<u8>,
    offset: usize,
}

#[derive(Default)]
struct PendingRequest {
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn serve(
    socket: &UdpSocket,
    mut config: quiche::Config,
    handshakes: &Mutex<Vec<bool>>,
    stop: &AtomicBool,
) {
    let local_addr = socket.local_addr().unwrap();
    let h3_config = quiche::h3::Config::new().unwrap();
    let mut conns: HashMap<SocketAddr, ServerConn> = HashMap::new();
    let mut buf = [0u8; 65_535];
    let mut out = [0u8; MAX_SERVER_DATAGRAM];

    while !stop.load(Ordering::Relaxed) {
        match socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                let pkt = &mut buf[..len];
                let server_conn = match conns.entry(from) {
                    Entry::Occupied(entry) => entry.into_mut(),
                    Entry::Vacant(entry) => {
                        let Some(scid) = accepted_scid(pkt) else {
                            continue;
                        };
                        let scid = quiche::ConnectionId::from_ref(&scid);
                        let Ok(conn) = quiche::accept(&scid, None, local_addr, from, &mut config)
                        else {
                            continue;
                        };
                        entry.insert(ServerConn {
                            conn,
                            h3: None,
                            requests: HashMap::new(),
                            pending_bodies: HashMap::new(),
                        })
                    }
                };
                server_conn
                    .conn
                    .recv(
                        pkt,
                        quiche::RecvInfo {
                            to: local_addr,
                            from,
                        },
                    )
                    .ok();
            }
            // WouldBlock/TimedOut is the 5 ms tick; anything else means the
            // socket died and the thread should exit rather than spin.
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => break,
        }

        for (peer, server_conn) in conns.iter_mut() {
            if server_conn.conn.timeout().is_some_and(|t| t.is_zero()) {
                server_conn.conn.on_timeout();
            }
            if server_conn.conn.is_established() && server_conn.h3.is_none() {
                handshakes
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(server_conn.conn.is_resumed());
                // A failure here poisons only this connection; the client's
                // request deadline turns it into a loud test failure.
                server_conn.h3 =
                    quiche::h3::Connection::with_transport(&mut server_conn.conn, &h3_config).ok();
            }
            if let Some(h3) = server_conn.h3.as_mut() {
                poll_h3(
                    h3,
                    &mut server_conn.conn,
                    &mut server_conn.requests,
                    &mut server_conn.pending_bodies,
                );
                drain_pending_bodies(h3, &mut server_conn.conn, &mut server_conn.pending_bodies);
            }
            loop {
                match server_conn.conn.send(&mut out) {
                    Ok((written, _info)) => {
                        socket.send_to(&out[..written], *peer).ok();
                    }
                    Err(quiche::Error::Done) => break,
                    Err(_) => break,
                }
            }
        }
        conns.retain(|_, server_conn| !server_conn.conn.is_closed());
    }
}

/// The DCID a fresh Initial packet was sent to, which becomes our SCID —
/// mirroring quiche's server example, minus retry. `None` for anything that
/// is not an acceptable first packet.
fn accepted_scid(pkt: &mut [u8]) -> Option<Vec<u8>> {
    let hdr = quiche::Header::from_slice(pkt, quiche::MAX_CONN_ID_LEN).ok()?;
    if hdr.ty != quiche::Type::Initial || !quiche::version_is_supported(hdr.version) {
        return None;
    }
    Some(hdr.dcid.as_ref().to_vec())
}

fn poll_h3(
    h3: &mut quiche::h3::Connection,
    conn: &mut quiche::Connection,
    requests: &mut HashMap<u64, PendingRequest>,
    pending_bodies: &mut HashMap<u64, PendingBody>,
) {
    loop {
        match h3.poll(conn) {
            Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                let mut request = PendingRequest::default();
                for header in &list {
                    let name = String::from_utf8_lossy(header.name()).into_owned();
                    let value = String::from_utf8_lossy(header.value()).into_owned();
                    if name == ":path" {
                        request.path = value.clone();
                    }
                    request.headers.push((name, value));
                }
                requests.insert(stream_id, request);
            }
            Ok((stream_id, quiche::h3::Event::Data)) => {
                let mut chunk = [0u8; 4096];
                while let Ok(read) = h3.recv_body(conn, stream_id, &mut chunk) {
                    if let Some(request) = requests.get_mut(&stream_id) {
                        request.body.extend_from_slice(&chunk[..read]);
                    }
                }
            }
            Ok((stream_id, quiche::h3::Event::Finished)) => {
                if let Some(request) = requests.remove(&stream_id) {
                    respond(h3, conn, stream_id, &request, pending_bodies);
                }
            }
            Ok(_) => {}
            Err(quiche::h3::Error::Done) => break,
            Err(_) => break,
        }
    }
}

fn respond(
    h3: &mut quiche::h3::Connection,
    conn: &mut quiche::Connection,
    stream_id: u64,
    request: &PendingRequest,
    pending_bodies: &mut HashMap<u64, PendingBody>,
) {
    let (status, extra_headers, body) = route(request);
    let content_length = body.len().to_string();
    let mut headers = vec![
        quiche::h3::Header::new(b":status", status.as_bytes()),
        quiche::h3::Header::new(b"content-length", content_length.as_bytes()),
    ];
    for (name, value) in &extra_headers {
        headers.push(quiche::h3::Header::new(name.as_bytes(), value.as_bytes()));
    }
    if h3
        .send_response(conn, stream_id, &headers, body.is_empty())
        .is_err()
    {
        return;
    }
    let mut pending = PendingBody { body, offset: 0 };
    if push_pending_body(h3, conn, stream_id, &mut pending) && pending.offset < pending.body.len() {
        // Flow control stalled the write; the serve loop keeps draining it as
        // the client's window updates arrive. This is what lets the server
        // carry a body larger than one stream window — the shape the client's
        // streaming path exists for.
        pending_bodies.insert(stream_id, pending);
    }
}

/// Writes as much of `pending` as quiche will take. `false` means the stream
/// died and the body should be dropped.
fn push_pending_body(
    h3: &mut quiche::h3::Connection,
    conn: &mut quiche::Connection,
    stream_id: u64,
    pending: &mut PendingBody,
) -> bool {
    while pending.offset < pending.body.len() {
        // fin=true throughout: quiche only puts the FIN on the wire once the
        // final byte is accepted, so repeating it on each remainder is the
        // established idiom.
        match h3.send_body(conn, stream_id, &pending.body[pending.offset..], true) {
            Ok(0) | Err(quiche::h3::Error::Done) => return true,
            Ok(written) => pending.offset += written,
            Err(_) => return false,
        }
    }
    true
}

fn drain_pending_bodies(
    h3: &mut quiche::h3::Connection,
    conn: &mut quiche::Connection,
    pending_bodies: &mut HashMap<u64, PendingBody>,
) {
    pending_bodies.retain(|stream_id, pending| {
        push_pending_body(h3, conn, *stream_id, pending) && pending.offset < pending.body.len()
    });
}

/// httpbin-shaped routing, just deep enough for the offline twins of the live
/// tests: echo endpoints, the cookie set/read pair, and a redirect chain.
fn route(request: &PendingRequest) -> (String, Vec<(String, String)>, Vec<u8>) {
    let (path, query) = match request.path.split_once('?') {
        Some((path, query)) => (path, query),
        None => (request.path.as_str(), ""),
    };

    if path == "/get" || path == "/post" {
        return ("200".to_string(), Vec::new(), echo_body(request, query));
    }
    if let Some(pair) = path.strip_prefix("/cookies/set/") {
        let (name, value) = pair.split_once('/').unwrap_or((pair, ""));
        return (
            "302".to_string(),
            vec![
                ("location".to_string(), "/cookies".to_string()),
                ("set-cookie".to_string(), format!("{name}={value}; Path=/")),
            ],
            Vec::new(),
        );
    }
    if path == "/cookies" {
        let cookies = request
            .headers
            .iter()
            .filter(|(name, _)| name == "cookie")
            .flat_map(|(_, value)| value.split("; "))
            .filter_map(|pair| pair.split_once('='))
            .map(|(name, value)| format!("\"{name}\": \"{value}\""))
            .collect::<Vec<_>>()
            .join(", ");
        return (
            "200".to_string(),
            Vec::new(),
            format!("{{\"cookies\": {{{cookies}}}}}").into_bytes(),
        );
    }
    if let Some(count) = path.strip_prefix("/redirect/") {
        let remaining: u32 = count.parse().unwrap_or(1);
        let target = if remaining <= 1 {
            "/get".to_string()
        } else {
            format!("/redirect/{}", remaining - 1)
        };
        return (
            "302".to_string(),
            vec![("location".to_string(), target)],
            Vec::new(),
        );
    }
    if let Some(len) = path.strip_prefix("/bytes/") {
        let len: usize = len.parse().unwrap_or(0);
        return ("200".to_string(), Vec::new(), body_pattern(len));
    }
    // A redirect to cleartext, which the shared gate refuses (downgrade).
    if path == "/redirect-http" {
        return (
            "302".to_string(),
            vec![("location".to_string(), format!("http://{TEST_HOST}/get"))],
            Vec::new(),
        );
    }
    ("404".to_string(), Vec::new(), Vec::new())
}

/// Deterministic non-repeating-ish byte pattern, so a reassembled streamed
/// body can be checked for both length and content.
pub(crate) fn body_pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// Loose JSON echo in httpbin's shape — tests assert with `contains`, so the
/// exact framing only has to be stable, not parseable.
fn echo_body(request: &PendingRequest, query: &str) -> Vec<u8> {
    let headers = request
        .headers
        .iter()
        .filter(|(name, _)| !name.starts_with(':'))
        .map(|(name, value)| format!("\"{name}\": \"{value}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let data = String::from_utf8_lossy(&request.body);
    format!("{{\"args\": \"{query}\", \"headers\": {{{headers}}}, \"data\": \"{data}\"}}")
        .into_bytes()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{TEST_HOST, TestH3Server, test_pki};
    use crate::{VaneClient, VaneClientConfig, sha256_pin, test_request};

    fn offline_client(config: VaneClientConfig) -> VaneClient {
        VaneClient::new(VaneClientConfig {
            dns_overrides: HashMap::from([(TEST_HOST.to_string(), "127.0.0.1".to_string())]),
            timeout_seconds: Some(10),
            ..config
        })
        .unwrap()
    }

    /// The batch-2 flagship, finally end to end: the second connection to a
    /// non-pinned origin must reuse the NewSessionTicket the server issued on
    /// the first, not run a full handshake.
    #[test]
    fn second_connection_resumes_tls_session() {
        let server = TestH3Server::start();
        // Pooling off: each request must dial (and handshake) its own
        // connection, otherwise the second request never reaches TLS.
        let client = offline_client(VaneClientConfig {
            connection_pool_enabled: false,
            ..VaneClientConfig::default()
        });

        let first = client.execute(test_request(&server.url("/get"))).unwrap();
        assert!(first.is_success);
        assert_eq!(
            client.tls_sessions.lock().unwrap().len(),
            1,
            "client should have captured the server's NewSessionTicket after the first response"
        );

        let second = client.execute(test_request(&server.url("/get"))).unwrap();
        assert!(second.is_success);
        assert_eq!(
            server.handshakes(),
            vec![false, true],
            "second handshake should have resumed the first connection's TLS session"
        );
    }

    /// `warmup()` in an HTTP/3-capable mode dials ahead of time: exactly one
    /// connection lands in the pool, a repeat warmup is a no-op while it is
    /// live, and the first real request rides it instead of handshaking.
    #[test]
    fn warmup_pre_connects_the_pool_and_the_first_request_reuses_it() {
        let server = TestH3Server::start();
        // Default config is Http3Only with pooling on.
        let client = offline_client(VaneClientConfig::default());
        let url = server.url("/get");

        client
            .warmup_inner(Some(url.as_str()))
            .expect("warmup against the in-process server");
        assert_eq!(client.pool.lock().unwrap().len(), 1);
        // Http3Only must never touch the TCP machinery.
        #[cfg(feature = "tcp-fallback")]
        assert!(client.tcp_client.lock().unwrap().is_none());

        // Idempotent: a live pooled connection short-circuits the redial.
        client
            .warmup_inner(Some(url.as_str()))
            .expect("repeat warmup");
        assert_eq!(client.pool.lock().unwrap().len(), 1);

        let response = client.execute(test_request(&url)).unwrap();
        assert!(response.is_success);
        // Asserted only after the round trip: the server registers a
        // handshake asynchronously, and the request forces it to have
        // processed the warmup connection — which must be the request's too.
        assert_eq!(
            server.handshakes().len(),
            1,
            "the request should have ridden the pre-connected pooled connection"
        );
    }

    /// The batch-2 security rule: a resumed handshake restores the cached
    /// peer chain instead of proving the current one, so a pinned host must
    /// always full-handshake — no ticket stored, none offered.
    #[test]
    fn pinned_host_never_resumes() {
        let server = TestH3Server::start();
        // The whole-cert pin works in every feature set, and it must match:
        // the rule under test is "pinned hosts skip resumption", not "pin
        // mismatches fail" — both requests have to succeed.
        let pin = sha256_pin("sha256-cert", &test_pki().leaf_der);
        let client = offline_client(VaneClientConfig {
            connection_pool_enabled: false,
            certificate_pins: HashMap::from([(TEST_HOST.to_string(), vec![pin])]),
            ..VaneClientConfig::default()
        });

        assert!(
            client
                .execute(test_request(&server.url("/get")))
                .unwrap()
                .is_success
        );
        assert!(
            client
                .execute(test_request(&server.url("/get")))
                .unwrap()
                .is_success
        );

        assert_eq!(
            server.handshakes(),
            vec![false, false],
            "a pinned host must never resume a TLS session"
        );
        assert!(
            client.tls_sessions.lock().unwrap().is_empty(),
            "no ticket may be stored for a pinned host"
        );
    }

    /// Offline twin of the live `/get`+`/post` echo test.
    #[test]
    fn get_and_post_echo() {
        let server = TestH3Server::start();
        let client = offline_client(VaneClientConfig::default());

        let mut get = test_request(&server.url("/get"));
        get.headers
            .insert("X-Vane-Trace".to_string(), "trace-offline".to_string());
        get.query_params
            .insert("vane_query".to_string(), "query-offline".to_string());
        let response = client.execute(get).unwrap();
        assert!(response.is_success);
        let body = String::from_utf8_lossy(&response.body).into_owned();
        assert!(
            body.contains("trace-offline"),
            "headers echo missing: {body}"
        );
        assert!(body.contains("query-offline"), "query echo missing: {body}");

        let mut post = test_request(&server.url("/post"));
        post.method = "POST".to_string();
        post.body = Some(b"offline-h3-body".to_vec());
        let response = client.execute(post).unwrap();
        assert!(response.is_success);
        let body = String::from_utf8_lossy(&response.body).into_owned();
        assert!(
            body.contains("offline-h3-body"),
            "body echo missing: {body}"
        );
    }

    /// Multi-hop redirect chain on the wire — previously only reachable
    /// against live pie.dev.
    #[test]
    fn multi_hop_redirect_lands_on_final_target() {
        let server = TestH3Server::start();
        let client = offline_client(VaneClientConfig::default());

        let response = client
            .execute(test_request(&server.url("/redirect/3")))
            .unwrap();
        assert!(response.is_success);
        assert!(
            response.url.ends_with("/get"),
            "redirect chain should end on /get, got {}",
            response.url
        );
    }

    /// Offline twin of the live cookie test: a `Set-Cookie` on a 302 hop is
    /// stored and replayed on the follow-up request.
    #[test]
    fn cookie_set_on_redirect_is_sent_back() {
        let server = TestH3Server::start();
        let client = offline_client(VaneClientConfig {
            cookies_enabled: true,
            ..VaneClientConfig::default()
        });

        let response = client
            .execute(test_request(&server.url("/cookies/set/vane/offline")))
            .unwrap();
        assert!(response.is_success);
        let body = String::from_utf8_lossy(&response.body).into_owned();
        assert!(
            body.contains("\"vane\": \"offline\""),
            "cookie jar round-trip missing: {body}"
        );
    }

    // ---------- Streaming ----------

    use std::sync::Arc;

    use super::body_pattern;
    use crate::VaneError;

    /// Larger than the 1 MiB stream flow-control window, so the body cannot
    /// possibly arrive in one pass: the server is forced to wait for the
    /// client's window updates, which only flow while the caller pulls.
    const STREAM_BODY_LEN: usize = 3 * 1024 * 1024;

    fn stream_request(server: &TestH3Server) -> crate::VaneRequest {
        test_request(&server.url(&format!("/bytes/{STREAM_BODY_LEN}")))
    }

    #[test]
    fn streaming_get_delivers_incremental_chunks_and_pools_the_drained_connection() {
        let server = TestH3Server::start();
        let client = Arc::new(offline_client(VaneClientConfig::default()));
        let progress_id = crate::create_progress();
        let mut request = stream_request(&server);
        request.progress_id = Some(progress_id);

        let stream = Arc::clone(&client).execute_streaming(request).unwrap();
        let head = stream.head();
        assert!(head.is_success);
        assert_eq!(head.status_code, 200);
        assert!(head.body.is_empty(), "the stream head carries no body");
        assert_eq!(
            head.headers.get("content-length").map(String::as_str),
            Some(STREAM_BODY_LEN.to_string().as_str())
        );

        let mut body = Vec::new();
        let mut chunks = 0usize;
        while let Some(chunk) = stream.read_chunk().unwrap() {
            assert!(!chunk.is_empty(), "read_chunk never returns empty chunks");
            chunks += 1;
            body.extend_from_slice(&chunk);
        }
        assert_eq!(body.len(), STREAM_BODY_LEN);
        assert!(
            body == body_pattern(STREAM_BODY_LEN),
            "body content differs"
        );
        assert!(
            chunks > 1,
            "3 MiB against a 1 MiB flow window cannot arrive as one chunk"
        );
        // EOF after EOF stays EOF.
        assert!(stream.read_chunk().unwrap().is_none());

        // The drained connection went back to the pool, and the follow-up
        // request rides it instead of handshaking.
        assert_eq!(client.pool.lock().unwrap().len(), 1);
        let followup = client.execute(test_request(&server.url("/get"))).unwrap();
        assert!(followup.is_success);
        assert_eq!(
            server.handshakes().len(),
            1,
            "the follow-up request must reuse the streamed request's connection"
        );

        let progress = crate::progress_snapshot_by_id(progress_id);
        assert!(progress.done, "progress latches done at end of stream");
        assert_eq!(progress.download_received, STREAM_BODY_LEN as u64);
        assert_eq!(progress.download_total, STREAM_BODY_LEN as u64);
        crate::free_progress(progress_id);
    }

    #[test]
    fn streaming_redirect_chain_streams_the_final_hop() {
        let server = TestH3Server::start();
        let client = Arc::new(offline_client(VaneClientConfig::default()));

        let stream = Arc::clone(&client)
            .execute_streaming(test_request(&server.url("/redirect/2")))
            .unwrap();
        let head = stream.head();
        assert!(head.is_success);
        assert!(
            head.url.ends_with("/get"),
            "redirect chain should end on /get, got {}",
            head.url
        );

        let mut body = Vec::new();
        while let Some(chunk) = stream.read_chunk().unwrap() {
            body.extend_from_slice(&chunk);
        }
        let body = String::from_utf8_lossy(&body).into_owned();
        assert!(body.contains("args"), "final hop body missing: {body}");
    }

    /// A refused redirect (cleartext downgrade here) is handed back as the
    /// stream itself: the 3xx head with the refusal marker, and its (empty)
    /// body drained through the same pull API.
    #[test]
    fn streaming_refused_redirect_hands_back_the_marked_3xx() {
        let server = TestH3Server::start();
        let client = Arc::new(offline_client(VaneClientConfig::default()));

        let stream = Arc::clone(&client)
            .execute_streaming(test_request(&server.url("/redirect-http")))
            .unwrap();
        let head = stream.head();
        assert_eq!(head.status_code, 302);
        assert_eq!(
            head.headers
                .get(crate::REDIRECT_REFUSED_HEADER)
                .map(String::as_str),
            Some(crate::REDIRECT_REFUSED_DOWNGRADE)
        );
        assert!(stream.read_chunk().unwrap().is_none());
    }

    #[test]
    fn streaming_cancel_aborts_mid_body_and_discards_the_connection() {
        let server = TestH3Server::start();
        let client = Arc::new(offline_client(VaneClientConfig::default()));
        let cancel_id = crate::create_cancel_token();
        let mut request = stream_request(&server);
        request.cancel_token_id = Some(cancel_id);

        let stream = Arc::clone(&client).execute_streaming(request).unwrap();
        assert!(
            stream.read_chunk().unwrap().is_some(),
            "first chunk arrives before the cancel"
        );
        crate::cancel_by_id(cancel_id);
        assert!(matches!(stream.read_chunk(), Err(VaneError::Cancelled(_))));
        // Terminal: the same error replays, and the connection was discarded
        // rather than pooled with an unread body.
        assert!(matches!(stream.read_chunk(), Err(VaneError::Cancelled(_))));
        assert!(client.pool.lock().unwrap().is_empty());
        crate::free_cancel_token(cancel_id);
    }

    /// The response body limit applies to streamed bodies cumulatively —
    /// streaming must not become the bypass route for a configured bound.
    #[test]
    fn streaming_enforces_the_response_body_limit() {
        let server = TestH3Server::start();
        let client = Arc::new(offline_client(VaneClientConfig {
            max_response_body_bytes: 64 * 1024,
            ..VaneClientConfig::default()
        }));

        // The limit can trip while reaching the headers (body bytes arriving
        // in the same pass) or on a later pull; either way it must be a
        // `BodyLimitExceeded` and the connection must not be pooled.
        let err = match Arc::clone(&client).execute_streaming(stream_request(&server)) {
            Err(err) => err,
            Ok(stream) => loop {
                match stream.read_chunk() {
                    Ok(Some(_)) => {}
                    Ok(None) => panic!("stream ended under the limit"),
                    Err(err) => break err,
                }
            },
        };
        assert!(matches!(err, VaneError::BodyLimitExceeded(_)), "{err}");
        assert!(client.pool.lock().unwrap().is_empty());
    }

    #[test]
    fn streaming_close_without_draining_discards_the_connection() {
        let server = TestH3Server::start();
        let client = Arc::new(offline_client(VaneClientConfig::default()));

        let stream = Arc::clone(&client)
            .execute_streaming(stream_request(&server))
            .unwrap();
        assert!(stream.read_chunk().unwrap().is_some());
        stream.close();
        assert!(
            client.pool.lock().unwrap().is_empty(),
            "an undrained stream must never pool its connection"
        );
        // Reading after close is a clean EOF, not an error.
        assert!(stream.read_chunk().unwrap().is_none());

        // The next request has to dial a fresh connection (a resumed TLS
        // handshake still counts: the ticket was banked at headers-time).
        assert!(
            client
                .execute(test_request(&server.url("/get")))
                .unwrap()
                .is_success
        );
        assert_eq!(
            server.handshakes().len(),
            2,
            "a closed stream's connection must not be reused"
        );
    }

    /// Dropping an undrained stream without `close()` — the FFI-handle-freed
    /// path — must clean up exactly like `close()`.
    #[test]
    fn streaming_drop_without_close_discards_the_connection() {
        let server = TestH3Server::start();
        let client = Arc::new(offline_client(VaneClientConfig::default()));

        {
            let stream = Arc::clone(&client)
                .execute_streaming(stream_request(&server))
                .unwrap();
            assert!(stream.read_chunk().unwrap().is_some());
        }
        assert!(client.pool.lock().unwrap().is_empty());
    }
}
