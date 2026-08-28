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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use quiche::h3::NameValue;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use sha2::{Digest, Sha256};

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
    /// CA DER, so a TCP test server can present this same PKI through
    /// `tcp::TEST_ROOT` — the H3→TCP fallback tests serve both transports
    /// for one host and need one trust anchor covering both.
    #[cfg(feature = "tcp-fallback")]
    pub(crate) ca_der: Vec<u8>,
    /// Leaf key DER (PKCS#8), for the same TCP twin server.
    #[cfg(feature = "tcp-fallback")]
    pub(crate) leaf_key_der: Vec<u8>,
}

impl TestPki {
    /// The CA as PEM text, for tests that feed it through
    /// `custom_root_certificates` instead of relying on the seam.
    pub(crate) fn ca_pem(&self) -> String {
        std::fs::read_to_string(&self.ca_pem_path).unwrap()
    }
}

static TEST_PKI: OnceLock<TestPki> = OnceLock::new();

/// Counter so each [`fresh_pki`] call writes distinct server files.
static FRESH_PKI_SEQ: AtomicU64 = AtomicU64::new(0);

/// A second, independent PKI for `TEST_HOST`, trusted by NOTHING — not the
/// platform store and not the `#[cfg(test)]` seam (which only ever loads
/// `TEST_PKI`'s CA). Handing `ca_pem` to `custom_root_certificates` is
/// therefore the only way a client can trust a server presenting this PKI —
/// exactly what the custom-roots tests must prove. The files exist for the
/// test *server's* quiche config, which loads from paths; the client under
/// test consumes the PEM from memory.
pub(crate) struct FreshPki {
    pub(crate) ca_pem: String,
    cert_pem_path: PathBuf,
    key_pem_path: PathBuf,
}

pub(crate) fn fresh_pki() -> FreshPki {
    let seq = FRESH_PKI_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
    // Distinct CNs for the same BoringSSL reason as `test_pki`.
    ca_params
        .distinguished_name
        .push(DnType::CommonName, format!("vane fresh test CA {seq}"));
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

    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let write = |name: &str, contents: &str| -> PathBuf {
        let path = dir.join(format!("vane-h3-fresh-{pid}-{seq}-{name}"));
        std::fs::write(&path, contents).unwrap();
        path
    };
    FreshPki {
        ca_pem,
        cert_pem_path: write("cert.pem", &leaf.pem()),
        key_pem_path: write("key.pem", &leaf_key.serialize_pem()),
    }
}

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
            #[cfg(feature = "tcp-fallback")]
            ca_der: ca.der().to_vec(),
            #[cfg(feature = "tcp-fallback")]
            leaf_key_der: leaf_key.serialize_der(),
        }
    })
}

/// One request the server finished receiving, for upload assertions: which
/// attempt/hop arrived, what framing it declared, and what bytes it carried
/// (as a digest, so multi-megabyte bodies don't sit in the log).
#[derive(Clone)]
pub(crate) struct SeenRequest {
    pub(crate) method: String,
    pub(crate) path: String,
    /// The request's `content-length` header, verbatim, if it sent one.
    pub(crate) content_length: Option<String>,
    pub(crate) body_len: usize,
    pub(crate) body_sha256: String,
}

/// Knobs for the upload tests. `Default` is the plain server every existing
/// test uses.
#[derive(Default)]
pub(crate) struct ServerTuning {
    /// Overrides the connection and per-stream flow-control windows. Small
    /// values cap how far a client upload can run ahead of the server's
    /// reads, which is what makes writer backpressure observable.
    pub(crate) flow_window: Option<u64>,
    /// While true, the serve loop still ACKs packets but never polls HTTP/3 —
    /// so received stream data is never consumed, no window credit is ever
    /// granted, and an uploading client stalls against `flow_window`.
    pub(crate) hold_h3: Option<Arc<AtomicBool>>,
    /// Serve from this PKI instead of the process-wide [`test_pki`], so the
    /// client can only trust the server through `custom_root_certificates`.
    pub(crate) pki: Option<FreshPki>,
}

/// A localhost HTTP/3 origin on an ephemeral port, served from one background
/// thread until dropped. `handshakes` records, in accept order, whether each
/// connection's TLS handshake resumed a previous session.
pub(crate) struct TestH3Server {
    port: u16,
    handshakes: Arc<Mutex<Vec<bool>>>,
    requests: Arc<Mutex<Vec<SeenRequest>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl TestH3Server {
    pub(crate) fn start() -> Self {
        Self::start_tuned(ServerTuning::default())
    }

    pub(crate) fn start_tuned(tuning: ServerTuning) -> Self {
        let (cert_pem_path, key_pem_path) = match &tuning.pki {
            Some(pki) => (pki.cert_pem_path.clone(), pki.key_pem_path.clone()),
            None => {
                let pki = test_pki();
                (pki.cert_pem_path.clone(), pki.key_pem_path.clone())
            }
        };
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        // The tick that bounds every loop below: recv wakes at least this
        // often to fire QUIC timers and check the stop flag.
        socket
            .set_read_timeout(Some(Duration::from_millis(5)))
            .unwrap();
        let port = socket.local_addr().unwrap().port();

        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        config
            .load_cert_chain_from_pem_file(cert_pem_path.to_str().unwrap())
            .unwrap();
        config
            .load_priv_key_from_pem_file(key_pem_path.to_str().unwrap())
            .unwrap();
        config
            .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
            .unwrap();
        config.set_max_idle_timeout(10_000);
        config.set_max_recv_udp_payload_size(MAX_SERVER_DATAGRAM);
        config.set_max_send_udp_payload_size(MAX_SERVER_DATAGRAM);
        config.enable_dgram(true, 16, 16);
        let flow_window = tuning.flow_window;
        config.set_initial_max_data(flow_window.unwrap_or(10_000_000));
        config.set_initial_max_stream_data_bidi_local(flow_window.unwrap_or(1_000_000));
        config.set_initial_max_stream_data_bidi_remote(flow_window.unwrap_or(1_000_000));
        config.set_initial_max_stream_data_uni(flow_window.unwrap_or(1_000_000));
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);

        let handshakes = Arc::new(Mutex::new(Vec::new()));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let hold_h3 = tuning.hold_h3;
        let thread = std::thread::spawn({
            let handshakes = Arc::clone(&handshakes);
            let requests = Arc::clone(&requests);
            let stop = Arc::clone(&stop);
            move || {
                serve(
                    &socket,
                    config,
                    &handshakes,
                    &requests,
                    hold_h3.as_deref(),
                    &stop,
                )
            }
        });
        Self {
            port,
            handshakes,
            requests,
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

    /// Snapshot of every fully-received request, in arrival order. The retry
    /// and redirect decision tests count and inspect entries here: what the
    /// server actually saw is the ground truth for "was it replayed".
    pub(crate) fn requests(&self) -> Vec<SeenRequest> {
        self.requests
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
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn serve(
    socket: &UdpSocket,
    mut config: quiche::Config,
    handshakes: &Mutex<Vec<bool>>,
    requests_log: &Mutex<Vec<SeenRequest>>,
    hold_h3: Option<&AtomicBool>,
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
            // While held, packets are still received and ACKed above but no
            // HTTP/3 event is consumed: stream data stays in quiche's buffers
            // and no flow-control credit is granted, so an uploading client
            // runs out of window and its writer blocks. Releasing the flag
            // drains everything normally.
            let held = hold_h3.is_some_and(|hold| hold.load(Ordering::Relaxed));
            if let Some(h3) = server_conn.h3.as_mut()
                && !held
            {
                poll_h3(
                    h3,
                    &mut server_conn.conn,
                    &mut server_conn.requests,
                    &mut server_conn.pending_bodies,
                    requests_log,
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
    requests_log: &Mutex<Vec<SeenRequest>>,
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
                    if name == ":method" {
                        request.method = value.clone();
                    }
                    request.headers.push((name, value));
                }
                requests.insert(stream_id, request);
            }
            Ok((stream_id, quiche::h3::Event::Data)) => {
                // The consumed-bytes fallback discriminator: once any body
                // byte for this path has arrived, kill the whole connection
                // abruptly. The client is left with a transport error and a
                // partially-consumed body stream — the exact state in which
                // the TCP fallback must NOT run.
                if requests
                    .get(&stream_id)
                    .is_some_and(|request| request.path == "/upload-die")
                {
                    conn.close(false, 0x2, b"mid-upload abort").ok();
                    return;
                }
                let mut chunk = [0u8; 4096];
                while let Ok(read) = h3.recv_body(conn, stream_id, &mut chunk) {
                    if let Some(request) = requests.get_mut(&stream_id) {
                        request.body.extend_from_slice(&chunk[..read]);
                    }
                }
            }
            Ok((stream_id, quiche::h3::Event::Finished)) => {
                if let Some(request) = requests.remove(&stream_id) {
                    respond(h3, conn, stream_id, &request, pending_bodies, requests_log);
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
    requests_log: &Mutex<Vec<SeenRequest>>,
) {
    requests_log
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(SeenRequest {
            method: request.method.clone(),
            path: request.path.clone(),
            content_length: request
                .headers
                .iter()
                .find(|(name, _)| name == "content-length")
                .map(|(_, value)| value.clone()),
            body_len: request.body.len(),
            body_sha256: sha256_hex(&request.body),
        });
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
    // Upload sink: answers with the received body's length and digest (so a
    // multi-megabyte body is verified without echoing it) and mirrors the
    // request's own framing back for the content-length assertions.
    if path == "/upload" {
        let framing = request
            .headers
            .iter()
            .find(|(name, _)| name == "content-length")
            .map(|(_, value)| value.clone())
            .unwrap_or_else(|| "none".to_string());
        return (
            "200".to_string(),
            vec![("x-request-content-length".to_string(), framing)],
            format!(
                "{{\"len\": {}, \"sha256\": \"{}\"}}",
                request.body.len(),
                sha256_hex(&request.body)
            )
            .into_bytes(),
        );
    }
    // Same-origin 307: preserves method and body, so a buffered upload
    // follows it and a streamed one must refuse it.
    if path == "/upload-307" {
        return (
            "307".to_string(),
            vec![("location".to_string(), "/upload".to_string())],
            Vec::new(),
        );
    }
    // 303: rewrites to a bodyless GET, which even a streamed upload follows.
    if path == "/upload-303" {
        return (
            "303".to_string(),
            vec![("location".to_string(), "/get".to_string())],
            Vec::new(),
        );
    }
    // Always-5xx endpoint for the retry-decision tests.
    if let Some(code) = path.strip_prefix("/status/") {
        return (code.to_string(), Vec::new(), Vec::new());
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
            vec![
                ("location".to_string(), target),
                // A hostile peer spoofing Vane's own refusal marker; the
                // client must drop it (`ResponseState::push_header`) or it
                // would win every first-wins lookup over the real one.
                (
                    crate::REDIRECT_REFUSED_HEADER.to_string(),
                    "peer-spoofed".to_string(),
                ),
            ],
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
            vec![
                ("location".to_string(), format!("http://{TEST_HOST}/get")),
                // Spoof attempt, as on `/redirect/` above.
                (
                    crate::REDIRECT_REFUSED_HEADER.to_string(),
                    "peer-spoofed".to_string(),
                ),
            ],
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

/// Hex SHA-256, shared by the request log and the tests asserting against it.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
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

    use super::{ServerTuning, TEST_HOST, TestH3Server, fresh_pki, test_pki};
    use crate::{
        REDIRECT_REFUSED_HEADER, REDIRECT_REFUSED_HOP_CAP, VaneClient, VaneClientConfig,
        first_header_value, sha256_pin, test_request,
    };

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

    /// The batch-3 flagship, HTTP/3 twin: the fresh CA reaches the client
    /// only through `custom_root_certificates` — the production ctx-builder
    /// path — never the `#[cfg(test)]` seam, which has never seen this CA.
    /// Extend-only semantics, both directions: unknown CA fails without the
    /// knob, validates with it.
    #[test]
    fn custom_root_extends_platform_trust() {
        let pki = fresh_pki();
        let ca_pem = pki.ca_pem.clone();
        let server = TestH3Server::start_tuned(ServerTuning {
            pki: Some(pki),
            ..ServerTuning::default()
        });

        // Control: nothing trusts this CA, so the handshake must fail.
        let untrusting = offline_client(VaneClientConfig::default());
        assert!(
            untrusting
                .execute(test_request(&server.url("/get")))
                .is_err(),
            "a fresh CA must not validate without the knob"
        );

        let trusting = offline_client(VaneClientConfig {
            custom_root_certificates: vec![ca_pem],
            ..VaneClientConfig::default()
        });
        let response = trusting.execute(test_request(&server.url("/get"))).unwrap();
        assert!(response.is_success);
    }

    /// The OR is a union, not "anything goes": with a custom root configured,
    /// a chain anchored in a third, unknown CA must still fail.
    #[test]
    fn custom_roots_do_not_widen_trust() {
        let server_pki = fresh_pki();
        let stranger = fresh_pki();
        let server = TestH3Server::start_tuned(ServerTuning {
            pki: Some(server_pki),
            ..ServerTuning::default()
        });

        let client = offline_client(VaneClientConfig {
            custom_root_certificates: vec![stranger.ca_pem.clone()],
            ..VaneClientConfig::default()
        });
        assert!(
            client.execute(test_request(&server.url("/get"))).is_err(),
            "a stranger CA in the knob must not admit an unrelated chain"
        );
    }

    /// Extend, never replace: with a (stranger) custom root active — so the
    /// ctx-builder path is in force — roots loaded through the
    /// post-construction quiche call (`load_platform_roots` and the test
    /// seam share it) must still be honored. Trust for this server comes
    /// only from the seam; the knob may add trust, never subtract it.
    #[test]
    fn custom_roots_do_not_replace_existing_trust() {
        let server = TestH3Server::start();
        let stranger = fresh_pki();
        let client = offline_client(VaneClientConfig {
            custom_root_certificates: vec![stranger.ca_pem.clone()],
            ..VaneClientConfig::default()
        });

        let response = client.execute(test_request(&server.url("/get"))).unwrap();
        assert!(response.is_success);
    }

    /// Pins run post-handshake regardless of which root anchored the chain:
    /// a custom root that makes the chain validate must not make a wrong pin
    /// pass.
    #[test]
    fn custom_roots_do_not_bypass_pins() {
        let pki = fresh_pki();
        let ca_pem = pki.ca_pem.clone();
        let server = TestH3Server::start_tuned(ServerTuning {
            pki: Some(pki),
            ..ServerTuning::default()
        });

        let wrong_pin = sha256_pin("sha256-cert", b"not the certificate the server presents");
        let client = offline_client(VaneClientConfig {
            custom_root_certificates: vec![ca_pem],
            certificate_pins: HashMap::from([(TEST_HOST.to_string(), vec![wrong_pin])]),
            ..VaneClientConfig::default()
        });
        let err = client
            .execute(test_request(&server.url("/get")))
            .unwrap_err();
        assert!(
            matches!(err, crate::VaneError::Tls(_)),
            "expected the pin failure, got {err}"
        );
    }

    /// The builder-path twin of `second_connection_resumes_tls_session`:
    /// custom roots switch config construction to
    /// `with_boring_ssl_ctx_builder`, and quiche's `from_boring` must keep
    /// the session callback installed. Security-critical seam: a resumed
    /// handshake skips certificate verification, so resumption behavior must
    /// be identical on both construction paths (the pinned-host gate is
    /// covered by `pinned_host_never_resumes`, which is path-independent).
    #[test]
    fn custom_roots_preserve_tls_session_resumption() {
        let server = TestH3Server::start();
        let client = offline_client(VaneClientConfig {
            connection_pool_enabled: false,
            custom_root_certificates: vec![test_pki().ca_pem()],
            ..VaneClientConfig::default()
        });

        let first = client.execute(test_request(&server.url("/get"))).unwrap();
        assert!(first.is_success);
        assert_eq!(
            client.tls_sessions.lock().unwrap().len(),
            1,
            "the ctx-builder path should still capture NewSessionTickets"
        );

        let second = client.execute(test_request(&server.url("/get"))).unwrap();
        assert!(second.is_success);
        assert_eq!(
            server.handshakes(),
            vec![false, true],
            "the ctx-builder path should still resume the TLS session"
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

    /// `remote_ip` on the wire: the H3 response reports the socket peer of
    /// the connection that served it — the resolved origin, which the
    /// override map pins to 127.0.0.1 here. The TCP twin is
    /// `tcp::tests::response_metadata::remote_ip_is_the_socket_peer`; the
    /// MASQUE arm (`outer.peer_addr`) is pinned by
    /// `masque_remote_ip_is_the_outer_socket_peer` at the selection point.
    #[test]
    fn remote_ip_is_the_socket_peer() {
        let server = TestH3Server::start();
        let client = offline_client(VaneClientConfig::default());

        let response = client.execute(test_request(&server.url("/get"))).unwrap();
        assert!(response.is_success);
        assert_eq!(response.remote_ip.as_deref(), Some("127.0.0.1"));

        // The streaming head carries the same peer.
        let stream = std::sync::Arc::new(offline_client(VaneClientConfig::default()))
            .execute_streaming(test_request(&server.url("/get")))
            .unwrap();
        assert_eq!(stream.head().remote_ip.as_deref(), Some("127.0.0.1"));
        while stream.read_chunk().unwrap().is_some() {}
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

    /// The `max_redirects` knob on the wire: the same 3-hop chain is a
    /// hop-cap refusal one hop short of the cap it needs and a success at
    /// exactly that cap. The TCP twin is
    /// `tcp::tests::redirect_chain_honours_the_configured_hop_cap`.
    #[test]
    fn redirect_chain_honours_the_configured_hop_cap() {
        let server = TestH3Server::start();

        let refused = offline_client(VaneClientConfig {
            max_redirects: 2,
            ..VaneClientConfig::default()
        })
        .execute(test_request(&server.url("/redirect/3")))
        .unwrap();
        assert_eq!(refused.status_code, 302);
        assert_eq!(
            first_header_value(&refused.headers, REDIRECT_REFUSED_HEADER),
            Some(REDIRECT_REFUSED_HOP_CAP)
        );
        // The server spoofs the marker on every 302 (see `route`); only
        // Vane's own may survive, or the peer's would win first-wins.
        assert_eq!(
            refused
                .headers
                .iter()
                .filter(|h| h.name == REDIRECT_REFUSED_HEADER)
                .count(),
            1,
            "the peer-spoofed marker must be dropped"
        );

        let followed = offline_client(VaneClientConfig {
            max_redirects: 3,
            ..VaneClientConfig::default()
        })
        .execute(test_request(&server.url("/redirect/3")))
        .unwrap();
        assert!(followed.is_success);
        assert!(
            followed.url.ends_with("/get"),
            "redirect chain should end on /get, got {}",
            followed.url
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
            first_header_value(&head.headers, "content-length"),
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

    /// The UniFFI-facing wrapper (`execute_streaming_request` returning
    /// `Arc<VaneResponseStream>`, plus `close_stream`, the export-safe name
    /// for `close`) delegates to the same stream the core test above proves.
    #[test]
    fn streaming_uniffi_export_surface_delegates_to_the_core_stream() {
        let server = TestH3Server::start();
        let client = Arc::new(offline_client(VaneClientConfig::default()));

        let stream = Arc::clone(&client)
            .execute_streaming_request(stream_request(&server))
            .unwrap();
        assert!(stream.head().is_success);
        assert!(stream.read_chunk().unwrap().is_some());

        // close_stream is close: idempotent, and reads after it report EOF.
        stream.close_stream();
        stream.close_stream();
        assert!(stream.read_chunk().unwrap().is_none());
        assert_eq!(
            client.pool.lock().unwrap().len(),
            0,
            "an abandoned stream must discard its connection, never pool it"
        );
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
            crate::first_header_value(&head.headers, crate::REDIRECT_REFUSED_HEADER),
            Some(crate::REDIRECT_REFUSED_DOWNGRADE)
        );
        // `/redirect-http` spoofs the marker too; the streaming path must
        // drop the peer's copy just like the buffered one.
        assert_eq!(
            head.headers
                .iter()
                .filter(|h| h.name == crate::REDIRECT_REFUSED_HEADER)
                .count(),
            1,
            "the peer-spoofed marker must be dropped"
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

    // ---------- Upload (request-body) streaming ----------

    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::Duration;

    use super::sha256_hex;
    use crate::{
        VaneRequest, create_body_stream, finish_body_stream, free_body_stream,
        write_body_stream_chunk,
    };

    /// One MiB: larger than `BODY_STREAM_BUFFER_BYTES`, so a passing
    /// round-trip proves the writer and the drive loop really interleave
    /// rather than the queue swallowing the whole body up front.
    const UPLOAD_BODY_LEN: usize = 1024 * 1024;

    fn upload_request(server: &TestH3Server, path: &str, method: &str, id: u64) -> VaneRequest {
        let mut request = test_request(&server.url(path));
        request.method = method.to_string();
        request.body_stream_id = Some(id);
        request
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

    /// Declared length: `content-length` goes on the wire, the body arrives
    /// byte-exact, progress publishes sent == total, and the connection pools
    /// exactly like a buffered upload's.
    #[test]
    fn streamed_upload_round_trips_with_content_length_and_pools_the_connection() {
        let server = TestH3Server::start();
        let client = offline_client(VaneClientConfig::default());
        let body = body_pattern(UPLOAD_BODY_LEN);
        let expected_sha = sha256_hex(&body);
        let id = create_body_stream(Some(UPLOAD_BODY_LEN as u64));
        let progress_id = crate::create_progress();
        let writer = spawn_writer(id, body, 64 * 1024);

        let mut request = upload_request(&server, "/upload", "POST", id);
        request.progress_id = Some(progress_id);
        let response = client.execute(request).unwrap();
        writer.join().unwrap().unwrap();

        assert!(response.is_success);
        let text = String::from_utf8_lossy(&response.body).into_owned();
        assert!(text.contains(&expected_sha), "body digest mismatch: {text}");
        assert_eq!(
            crate::first_header_value(&response.headers, "x-request-content-length"),
            Some(UPLOAD_BODY_LEN.to_string().as_str()),
            "a declared length must go on the wire as content-length"
        );
        let seen = server.requests();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].body_len, UPLOAD_BODY_LEN);
        assert_eq!(seen[0].body_sha256, expected_sha);

        let progress = crate::progress_snapshot_by_id(progress_id);
        assert!(progress.done);
        assert_eq!(progress.upload_sent, UPLOAD_BODY_LEN as u64);
        assert_eq!(progress.upload_total, UPLOAD_BODY_LEN as u64);

        // Pool invariant: a cleanly-completed streamed upload pools its
        // connection and the follow-up request rides it.
        assert_eq!(client.pool.lock().unwrap().len(), 1);
        assert!(
            client
                .execute(test_request(&server.url("/get")))
                .unwrap()
                .is_success
        );
        assert_eq!(server.handshakes().len(), 1);
        crate::free_progress(progress_id);
        free_body_stream(id);
    }

    /// Unknown length: no `content-length` anywhere, plain DATA + FIN, body
    /// still byte-exact.
    #[test]
    fn streamed_upload_of_unknown_length_sends_no_content_length() {
        let server = TestH3Server::start();
        let client = offline_client(VaneClientConfig::default());
        let body = body_pattern(UPLOAD_BODY_LEN);
        let expected_sha = sha256_hex(&body);
        let id = create_body_stream(None);
        let writer = spawn_writer(id, body, 64 * 1024);

        let response = client
            .execute(upload_request(&server, "/upload", "POST", id))
            .unwrap();
        writer.join().unwrap().unwrap();

        assert!(response.is_success);
        assert_eq!(
            crate::first_header_value(&response.headers, "x-request-content-length"),
            Some("none"),
            "an undeclared length must not invent a content-length"
        );
        let seen = server.requests();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].content_length, None);
        assert_eq!(seen[0].body_len, UPLOAD_BODY_LEN);
        assert_eq!(seen[0].body_sha256, expected_sha);
        free_body_stream(id);
    }

    /// The retry decision: a streamed body runs exactly one attempt, whatever
    /// the retry config says. The buffered control first proves the config
    /// really does retry against this endpoint — without it a broken
    /// discriminator would pass vacuously.
    #[test]
    fn streamed_upload_is_attempted_exactly_once_despite_retry_config() {
        let server = TestH3Server::start();
        let client = offline_client(VaneClientConfig {
            retry_max_attempts: 3,
            retry_unsafe_methods: true,
            retry_initial_delay_millis: 1,
            retry_max_delay_millis: 1,
            ..VaneClientConfig::default()
        });

        let mut buffered = test_request(&server.url("/status/500"));
        buffered.method = "POST".to_string();
        buffered.body = Some(b"retry-me".to_vec());
        let response = client.execute(buffered).unwrap();
        assert_eq!(response.status_code, 500);
        assert_eq!(
            server.requests().len(),
            3,
            "control: a buffered POST must burn every configured attempt"
        );

        let id = create_body_stream(None);
        write_body_stream_chunk(id, b"stream-once".to_vec()).unwrap();
        finish_body_stream(id).unwrap();
        let response = client
            .execute(upload_request(&server, "/status/500", "POST", id))
            .unwrap();
        assert_eq!(response.status_code, 500);
        assert_eq!(
            server.requests().len(),
            4,
            "a streamed body is attempted exactly once, 5xx or not"
        );
        free_body_stream(id);
    }

    /// The redirect decision, half one: a same-origin 307 — which a buffered
    /// body follows by replaying itself (the control) — is handed back
    /// refused for a streamed body, marked `streamed-body`.
    #[test]
    fn streamed_upload_refuses_the_same_origin_307_a_buffered_body_follows() {
        let server = TestH3Server::start();
        let client = offline_client(VaneClientConfig::default());

        let mut buffered = test_request(&server.url("/upload-307"));
        buffered.method = "PUT".to_string();
        buffered.body = Some(b"replayable".to_vec());
        let response = client.execute(buffered).unwrap();
        assert!(response.is_success);
        assert!(response.url.ends_with("/upload"));
        {
            let seen = server.requests();
            assert_eq!(seen.len(), 2, "control: the buffered 307 must be followed");
            assert_eq!(seen[1].path, "/upload");
            assert_eq!(seen[1].body_len, "replayable".len());
        }

        let id = create_body_stream(None);
        write_body_stream_chunk(id, b"one-shot".to_vec()).unwrap();
        finish_body_stream(id).unwrap();
        let response = client
            .execute(upload_request(&server, "/upload-307", "PUT", id))
            .unwrap();
        assert_eq!(response.status_code, 307);
        assert_eq!(
            crate::first_header_value(&response.headers, crate::REDIRECT_REFUSED_HEADER),
            Some(crate::REDIRECT_REFUSED_STREAMED_BODY)
        );
        let seen = server.requests();
        assert_eq!(seen.len(), 3, "the streamed 307 must not be followed");
        assert_eq!(seen[2].path, "/upload-307");
        free_body_stream(id);
    }

    /// The redirect decision, half two: a 303 rewrites to a bodyless GET, so
    /// even a streamed upload follows it — nothing needs replaying.
    #[test]
    fn streamed_upload_follows_a_303_as_a_bodyless_get() {
        let server = TestH3Server::start();
        let client = offline_client(VaneClientConfig::default());

        let id = create_body_stream(None);
        write_body_stream_chunk(id, b"posted-then-redirected".to_vec()).unwrap();
        finish_body_stream(id).unwrap();
        let response = client
            .execute(upload_request(&server, "/upload-303", "POST", id))
            .unwrap();
        assert!(response.is_success);
        assert!(response.url.ends_with("/get"));
        let seen = server.requests();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].method, "POST");
        assert_eq!(seen[0].body_len, "posted-then-redirected".len());
        assert_eq!(seen[1].method, "GET");
        assert_eq!(seen[1].body_len, 0, "the 303 hop must carry no body");
        free_body_stream(id);
    }

    /// Backpressure: with the server's flow-control window pinned small and
    /// its HTTP/3 reads held, the writer must park inside
    /// `write_body_stream_chunk` after roughly window + stream buffer bytes —
    /// nowhere near the full body — and complete only once the server reads.
    #[test]
    fn streamed_upload_backpressure_parks_the_writer_against_the_flow_window() {
        const WINDOW: u64 = 64 * 1024;
        let hold = Arc::new(AtomicBool::new(true));
        let server = TestH3Server::start_tuned(ServerTuning {
            flow_window: Some(WINDOW),
            hold_h3: Some(Arc::clone(&hold)),
            ..ServerTuning::default()
        });
        let client = Arc::new(offline_client(VaneClientConfig::default()));
        let body = body_pattern(UPLOAD_BODY_LEN);
        let expected_sha = sha256_hex(&body);
        let id = create_body_stream(Some(UPLOAD_BODY_LEN as u64));

        let written = Arc::new(AtomicU64::new(0));
        let writer = std::thread::spawn({
            let written = Arc::clone(&written);
            move || -> Result<(), VaneError> {
                for part in body.chunks(32 * 1024) {
                    write_body_stream_chunk(id, part.to_vec())?;
                    written.fetch_add(part.len() as u64, Ordering::Relaxed);
                }
                finish_body_stream(id)
            }
        });
        let request = upload_request(&server, "/upload", "POST", id);
        let exec = std::thread::spawn({
            let client = Arc::clone(&client);
            move || client.execute(request)
        });

        // The writer has parked once its counter stops moving: everything the
        // flow window plus the stream buffer can absorb has been absorbed.
        let mut last = u64::MAX;
        let mut stable = 0;
        while stable < 3 {
            std::thread::sleep(Duration::from_millis(100));
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
            parked_at < UPLOAD_BODY_LEN as u64,
            "no backpressure: the writer pushed the whole body while the server read nothing"
        );
        assert!(
            parked_at <= WINDOW + crate::BODY_STREAM_BUFFER_BYTES as u64 + 2 * 32 * 1024,
            "writer ran further ahead than the window + buffer allow: {parked_at}"
        );

        hold.store(false, Ordering::Relaxed);
        let response = exec.join().unwrap().unwrap();
        writer.join().unwrap().unwrap();
        assert!(response.is_success);
        assert!(String::from_utf8_lossy(&response.body).contains(&expected_sha));
        assert_eq!(written.load(Ordering::Relaxed), UPLOAD_BODY_LEN as u64);
        free_body_stream(id);
    }

    /// The fallback decision, refusing half: the server kills the connection
    /// after body bytes were consumed, and the TCP fallback must NOT run —
    /// PUT is a retryable method and the failure is a transport failure, so
    /// the consumed-bytes gate is the only thing standing in the way. (Its
    /// permitting half, consumed == 0, lives in `tcp::tests::upload`.)
    #[cfg(feature = "tcp-fallback")]
    #[test]
    fn streamed_upload_mid_body_transport_failure_does_not_fall_back() {
        let server = TestH3Server::start();
        let client = offline_client(VaneClientConfig {
            protocol_mode: crate::VaneProtocolMode::Http3ThenHttp2ThenHttp1,
            ..VaneClientConfig::default()
        });
        let id = create_body_stream(None);
        let writer = std::thread::spawn(move || {
            for _ in 0..64 {
                if write_body_stream_chunk(id, vec![7u8; 16 * 1024]).is_err() {
                    // The abort reached the writer — expected once the
                    // connection died mid-upload.
                    return;
                }
            }
            finish_body_stream(id).ok();
        });

        let err = client
            .execute(upload_request(&server, "/upload-die", "PUT", id))
            .unwrap_err();
        writer.join().unwrap();
        assert!(
            matches!(err, VaneError::Transport(_) | VaneError::Timeout(_)),
            "{err}"
        );
        assert!(
            !err.to_string().contains("TCP fallback also failed"),
            "the TCP fallback ran despite consumed streamed bytes: {err}"
        );
        assert!(
            client.pool.lock().unwrap().is_empty(),
            "a connection that died mid-upload must not pool"
        );
        free_body_stream(id);
    }

    /// Freeing the id mid-flight is the abort path: the request fails
    /// `Cancelled`, exactly like freeing a half-read response stream.
    #[test]
    fn streamed_upload_freed_mid_flight_cancels_the_request() {
        let server = TestH3Server::start();
        let client = offline_client(VaneClientConfig::default());
        let id = create_body_stream(None);
        write_body_stream_chunk(id, vec![1u8; 8 * 1024]).unwrap();
        let free = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            free_body_stream(id);
        });
        let err = client
            .execute(upload_request(&server, "/upload", "POST", id))
            .unwrap_err();
        free.join().unwrap();
        assert!(matches!(err, VaneError::Cancelled(_)), "{err}");
    }

    /// A writer that never calls `finish()` cannot hang the request forever:
    /// the shared deadline fires, and the writer-side handle then reports the
    /// request's end instead of blocking.
    #[test]
    fn streamed_upload_whose_writer_never_finishes_times_out() {
        let server = TestH3Server::start();
        let client = offline_client(VaneClientConfig::default());
        let id = create_body_stream(None);
        write_body_stream_chunk(id, b"stuck".to_vec()).unwrap();
        let mut request = upload_request(&server, "/upload", "POST", id);
        request.timeout_seconds = Some(1);
        let err = client.execute(request).unwrap_err();
        assert!(matches!(err, VaneError::Timeout(_)), "{err}");
        assert!(
            matches!(
                write_body_stream_chunk(id, b"late".to_vec()),
                Err(VaneError::Cancelled(_))
            ),
            "a write after the request died must report it, not park"
        );
        free_body_stream(id);
    }

    /// `max_request_body_bytes` binds a stream of unknown length at the exact
    /// configured byte: the request fails `BodyLimitExceeded` and the writer
    /// gets the same error instead of blocking forever.
    #[test]
    fn streamed_upload_enforces_the_request_body_limit_incrementally() {
        let server = TestH3Server::start();
        let client = offline_client(VaneClientConfig {
            max_request_body_bytes: 64 * 1024,
            ..VaneClientConfig::default()
        });
        let id = create_body_stream(None);
        let writer = std::thread::spawn(move || {
            loop {
                if let Err(err) = write_body_stream_chunk(id, vec![9u8; 32 * 1024]) {
                    return err;
                }
            }
        });
        let err = client
            .execute(upload_request(&server, "/upload", "POST", id))
            .unwrap_err();
        assert!(matches!(err, VaneError::BodyLimitExceeded(_)), "{err}");
        let writer_err = writer.join().unwrap();
        assert!(
            matches!(writer_err, VaneError::BodyLimitExceeded(_)),
            "{writer_err}"
        );
        free_body_stream(id);
    }

    /// A body short of its declared length must never FIN cleanly: `finish`
    /// refuses, the request fails, and the server sees no completed request.
    #[test]
    fn streamed_upload_short_of_its_declared_length_fails_the_request() {
        let server = TestH3Server::start();
        let client = offline_client(VaneClientConfig::default());
        let id = create_body_stream(Some(10));
        write_body_stream_chunk(id, b"four".to_vec()).unwrap();
        assert!(matches!(
            finish_body_stream(id),
            Err(VaneError::InvalidRequest(_))
        ));
        let err = client
            .execute(upload_request(&server, "/upload", "POST", id))
            .unwrap_err();
        assert!(matches!(err, VaneError::InvalidRequest(_)), "{err}");
        assert!(
            server.requests().is_empty(),
            "a short body must never reach the server as a finished request"
        );
        free_body_stream(id);
    }

    /// Upload streaming composes with response streaming: the request body is
    /// caller-pushed, and the response comes back through the pull API.
    #[test]
    fn execute_streaming_accepts_a_streamed_upload() {
        let server = TestH3Server::start();
        let client = Arc::new(offline_client(VaneClientConfig::default()));
        let body = body_pattern(512 * 1024);
        let expected_sha = sha256_hex(&body);
        let id = create_body_stream(Some(body.len() as u64));
        let writer = spawn_writer(id, body, 64 * 1024);

        let stream = Arc::clone(&client)
            .execute_streaming(upload_request(&server, "/upload", "POST", id))
            .unwrap();
        writer.join().unwrap().unwrap();
        assert!(stream.head().is_success);
        let mut received = Vec::new();
        while let Some(chunk) = stream.read_chunk().unwrap() {
            received.extend_from_slice(&chunk);
        }
        assert!(String::from_utf8_lossy(&received).contains(&expected_sha));
        free_body_stream(id);
    }

    /// The whole C ABI stream lifecycle against the in-process server, byte
    /// for byte: head through `VaneFfiResponse` with an empty body buffer,
    /// the chunk pull loop, the EOF latch, and close freeing the registry
    /// entry — after which a read reports EOF, not an error. This is the
    /// only test that exercises the exact structs and ownership rules the
    /// Dart pump builds on.
    #[test]
    fn ffi_streaming_round_trips_the_c_abi() {
        let server = TestH3Server::start();
        let client = Arc::new(offline_client(VaneClientConfig::default()));
        let handle = crate::FFI_NEXT_HANDLE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        crate::FFI_CLIENTS
            .lock()
            .unwrap()
            .insert(handle, Arc::clone(&client));

        let url = server.url(&format!("/bytes/{STREAM_BODY_LEN}"));
        let request = crate::test_ffi_request(&url);
        let mut stream_id = 0u64;
        let response = crate::vane_ffi_execute_streaming(
            handle,
            &request,
            std::ptr::null(),
            0,
            &mut stream_id,
        );
        unsafe {
            assert_eq!((*response).error.len, 0, "the head must not be an error");
            assert_eq!((*response).status_code, 200);
            assert_eq!((*response).body.len, 0, "the stream head carries no body");
            crate::vane_ffi_response_free(response);
        }
        assert_ne!(stream_id, 0, "success must hand out a stream handle");

        let mut body = Vec::new();
        let mut chunks = 0usize;
        loop {
            let chunk = crate::vane_ffi_stream_read(stream_id);
            assert_eq!(chunk.error.len, 0, "no chunk may carry an error");
            if chunk.eof {
                crate::vane_ffi_buffer_free(chunk.body);
                crate::vane_ffi_buffer_free(chunk.error);
                break;
            }
            assert!(!chunk.body.data.is_null() && chunk.body.len > 0);
            body.extend_from_slice(unsafe {
                std::slice::from_raw_parts(chunk.body.data, chunk.body.len)
            });
            chunks += 1;
            crate::vane_ffi_buffer_free(chunk.body);
            crate::vane_ffi_buffer_free(chunk.error);
        }
        assert_eq!(body.len(), STREAM_BODY_LEN);
        assert!(
            body == body_pattern(STREAM_BODY_LEN),
            "body content differs"
        );
        assert!(chunks > 1, "3 MiB cannot arrive as one chunk");

        // EOF latches through the ABI.
        let again = crate::vane_ffi_stream_read(stream_id);
        assert!(again.eof);
        crate::vane_ffi_buffer_free(again.body);
        crate::vane_ffi_buffer_free(again.error);

        crate::vane_ffi_stream_close(stream_id);
        assert!(
            !crate::FFI_STREAMS.lock().unwrap().contains_key(&stream_id),
            "close must free the registry entry"
        );
        let after_close = crate::vane_ffi_stream_read(stream_id);
        assert!(after_close.eof, "read after close is EOF, not an error");
        crate::vane_ffi_buffer_free(after_close.body);
        crate::vane_ffi_buffer_free(after_close.error);

        crate::vane_ffi_client_close(handle);
    }

    /// The caller-supplied DNS resolver on the H3 transport: the chain is
    /// consulted (risk f2's H3 half) and drain-on-set holds (risk f4).
    mod dns_resolver {
        use std::collections::HashMap;
        use std::sync::Arc;

        use super::super::{TEST_HOST, TestH3Server};
        use crate::tests::RecordingResolver;
        use crate::{VaneClient, VaneClientConfig, VaneDnsResolver, test_request};

        #[test]
        fn the_dns_resolver_steers_the_h3_transport() {
            let server = TestH3Server::start();
            // No dns_overrides: TEST_HOST resolves nowhere on the system, so
            // success is itself proof the resolver was the source.
            let client = VaneClient::new(VaneClientConfig {
                timeout_seconds: Some(10),
                ..VaneClientConfig::default()
            })
            .unwrap();
            let recording = RecordingResolver::answering(&["127.0.0.1"]);
            client.set_dns_resolver(Some(recording.clone() as Arc<dyn VaneDnsResolver>));

            let response = client.execute(test_request(&server.url("/get"))).unwrap();

            assert!(response.is_success);
            assert_eq!(recording.calls(), vec![TEST_HOST.to_string()]);
        }

        #[test]
        fn set_dns_resolver_drains_the_h3_pool() {
            let server = TestH3Server::start();
            // Pooling ON (the default): without the drain, the second request
            // would ride the pooled connection and resolver B never runs.
            let client = VaneClient::new(VaneClientConfig {
                dns_overrides: HashMap::new(),
                timeout_seconds: Some(10),
                ..VaneClientConfig::default()
            })
            .unwrap();
            let first = RecordingResolver::answering(&["127.0.0.1"]);
            client.set_dns_resolver(Some(first.clone() as Arc<dyn VaneDnsResolver>));
            assert!(
                client
                    .execute(test_request(&server.url("/get")))
                    .unwrap()
                    .is_success
            );
            assert_eq!(first.calls().len(), 1);

            let second = RecordingResolver::answering(&["127.0.0.1"]);
            client.set_dns_resolver(Some(second.clone() as Arc<dyn VaneDnsResolver>));
            assert!(
                client
                    .execute(test_request(&server.url("/get")))
                    .unwrap()
                    .is_success
            );

            assert_eq!(
                second.calls(),
                vec![TEST_HOST.to_string()],
                "the new resolver must be consulted — a pooled connection was not reused"
            );
            assert_eq!(
                server.handshakes().len(),
                2,
                "the drain forces a fresh connection"
            );
        }

        #[test]
        fn a_pooled_h3_request_never_consults_the_resolver() {
            let server = TestH3Server::start();
            // Pooling ON (the default): the second request must ride the
            // pooled connection, and a pooled request has no dial — so it
            // has nothing to resolve.
            let client = VaneClient::new(VaneClientConfig {
                timeout_seconds: Some(10),
                ..VaneClientConfig::default()
            })
            .unwrap();
            let recording = RecordingResolver::answering(&["127.0.0.1"]);
            client.set_dns_resolver(Some(recording.clone() as Arc<dyn VaneDnsResolver>));

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
                server.handshakes().len(),
                1,
                "the second request must reuse the pool"
            );
            assert_eq!(
                recording.calls(),
                vec![TEST_HOST.to_string()],
                "resolution belongs to the dial, not the request"
            );
        }
    }
}
