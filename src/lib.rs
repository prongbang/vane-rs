uniffi::setup_scaffolding!();

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use quiche::h3::NameValue;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use url::Url;

const MAX_DATAGRAM_SIZE: usize = 1350;
const MAX_RESPONSE_BODY_BYTES: usize = 64 * 1024 * 1024;

// ---------- Models ----------
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct VaneRequest {
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub query_params: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
    pub timeout_seconds: Option<u64>,
    pub follow_redirects: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct VaneResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub is_success: bool,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct VaneClientConfig {
    pub base_url: Option<String>,
    pub default_headers: HashMap<String, String>,
    pub timeout_seconds: Option<u64>,
    pub follow_redirects: bool,
    pub user_agent: Option<String>,
}

impl Default for VaneClientConfig {
    fn default() -> Self {
        Self {
            base_url: None,
            default_headers: HashMap::new(),
            timeout_seconds: Some(30),
            follow_redirects: true,
            user_agent: Some("Vane/0.1.0".to_string()),
        }
    }
}

// ---------- Error ----------
#[derive(Debug, Clone, Error, uniffi::Error)]
pub enum VaneError {
    #[error("{0}")]
    Generic(String),
}

impl From<quiche::Error> for VaneError {
    fn from(err: quiche::Error) -> Self {
        VaneError::Generic(format!("QUIC error: {err:?}"))
    }
}

impl From<quiche::h3::Error> for VaneError {
    fn from(err: quiche::h3::Error) -> Self {
        VaneError::Generic(format!("HTTP/3 error: {err:?}"))
    }
}

impl From<io::Error> for VaneError {
    fn from(err: io::Error) -> Self {
        VaneError::Generic(format!("I/O error: {err}"))
    }
}

// ---------- Client ----------
#[derive(uniffi::Object)]
pub struct VaneClient {
    config: VaneClientConfig,
}

impl VaneClient {
    pub fn new(config: VaneClientConfig) -> Result<Self, VaneError> {
        Ok(Self { config })
    }

    pub fn execute(&self, request: VaneRequest) -> Result<VaneResponse, VaneError> {
        let url = self.build_url(&request)?;
        self.execute_http3(request, url)
    }

    fn build_url(&self, request: &VaneRequest) -> Result<Url, VaneError> {
        let url = &request.url;
        if let Some(base) = &self.config.base_url {
            let base_url = Url::parse(base)
                .map_err(|e| VaneError::Generic(format!("Invalid base URL: {e}")))?;
            let mut url = base_url
                .join(url)
                .map_err(|e| VaneError::Generic(format!("Failed to join URL: {e}")))?;
            append_query_params(&mut url, &request.query_params);
            Ok(url)
        } else {
            let mut url =
                Url::parse(url).map_err(|e| VaneError::Generic(format!("Invalid URL: {e}")))?;
            append_query_params(&mut url, &request.query_params);
            Ok(url)
        }
    }

    fn execute_http3(&self, request: VaneRequest, url: Url) -> Result<VaneResponse, VaneError> {
        if url.scheme() != "https" {
            return Err(VaneError::Generic(
                "quiche backend only supports https:// URLs over HTTP/3".to_string(),
            ));
        }

        let host = url
            .host_str()
            .ok_or_else(|| VaneError::Generic("URL is missing host".to_string()))?;
        let peer_addr = resolve_peer_addr(host, url.port_or_known_default().unwrap_or(443))?;
        let bind_addr = match peer_addr {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        };

        let socket = UdpSocket::bind(bind_addr)?;
        socket.connect(peer_addr)?;
        let local_addr = socket.local_addr()?;
        let timeout = Duration::from_secs(
            request
                .timeout_seconds
                .or(self.config.timeout_seconds)
                .unwrap_or(30),
        );
        socket.set_read_timeout(Some(Duration::from_millis(10)))?;
        socket.set_write_timeout(Some(timeout))?;

        let mut quic_config = create_quiche_config(timeout)?;
        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        getrandom::fill(&mut scid).map_err(|e| {
            VaneError::Generic(format!("Failed to generate QUIC connection ID: {e}"))
        })?;
        let scid = quiche::ConnectionId::from_ref(&scid);
        let mut conn = quiche::connect(Some(host), &scid, local_addr, peer_addr, &mut quic_config)?;
        let h3_config = quiche::h3::Config::new()?;

        flush_quic_packets(&socket, &mut conn)?;

        let headers = build_h3_headers(&url, &request, &self.config)?;
        let mut h3_conn = None;
        let mut request_stream_id = None;
        let mut body_offset = 0usize;
        let request_body = request.body.unwrap_or_default();
        let deadline = Instant::now() + timeout;
        let mut response_status = 0u16;
        let mut response_headers = HashMap::new();
        let mut response_body = Vec::new();
        let mut finished = false;

        while Instant::now() < deadline {
            read_quic_packets(&socket, &mut conn, local_addr)?;

            if conn.is_established() && h3_conn.is_none() {
                h3_conn = Some(quiche::h3::Connection::with_transport(
                    &mut conn, &h3_config,
                )?);
            }

            if let Some(http3) = &mut h3_conn {
                if request_stream_id.is_none() {
                    let fin = request_body.is_empty();
                    request_stream_id = Some(http3.send_request(&mut conn, &headers, fin)?);
                }

                if let Some(stream_id) = request_stream_id {
                    while body_offset < request_body.len() {
                        match http3.send_body(
                            &mut conn,
                            stream_id,
                            &request_body[body_offset..],
                            true,
                        ) {
                            Ok(written) => body_offset += written,
                            Err(quiche::h3::Error::Done) => break,
                            Err(e) => return Err(e.into()),
                        }
                    }
                }

                process_h3_events(
                    http3,
                    &mut conn,
                    &mut response_status,
                    &mut response_headers,
                    &mut response_body,
                    &mut finished,
                )?;

                if finished {
                    conn.close(true, 0x00, b"done").ok();
                    flush_quic_packets(&socket, &mut conn)?;
                    break;
                }
            }

            flush_quic_packets(&socket, &mut conn)?;

            if conn.is_closed() && !finished {
                return Err(VaneError::Generic(
                    "QUIC connection closed before response completed".to_string(),
                ));
            }
        }

        if !finished {
            return Err(VaneError::Generic("HTTP/3 request timed out".to_string()));
        }

        Ok(VaneResponse {
            status_code: response_status,
            headers: response_headers,
            body: response_body,
            is_success: (200..=299).contains(&response_status),
            url: url.to_string(),
        })
    }

    fn make_request(
        &self,
        method: &str,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> Result<VaneResponse, VaneError> {
        self.execute(VaneRequest {
            url: url.to_string(),
            method: method.to_string(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
            body,
            timeout_seconds: None,
            follow_redirects: self.config.follow_redirects,
        })
    }
}

fn create_quiche_config(timeout: Duration) -> Result<quiche::Config, VaneError> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .map_err(|e| VaneError::Generic(format!("Failed to configure HTTP/3 ALPN: {e:?}")))?;
    config.verify_peer(true);
    load_platform_roots(&mut config)?;
    config.set_max_idle_timeout(timeout.as_millis().try_into().unwrap_or(u64::MAX));
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);
    Ok(config)
}

fn load_platform_roots(config: &mut quiche::Config) -> Result<(), VaneError> {
    let cert_files = [
        "/etc/ssl/cert.pem",
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
    ];
    for path in cert_files {
        if std::path::Path::new(path).exists() {
            config.load_verify_locations_from_file(path)?;
            return Ok(());
        }
    }

    let cert_dirs = ["/etc/ssl/certs", "/system/etc/security/cacerts"];
    for path in cert_dirs {
        if std::path::Path::new(path).exists() {
            config.load_verify_locations_from_directory(path)?;
            return Ok(());
        }
    }

    Err(VaneError::Generic(
        "No platform CA bundle found for quiche certificate verification".to_string(),
    ))
}

fn append_query_params(url: &mut Url, query_params: &HashMap<String, String>) {
    if query_params.is_empty() {
        return;
    }

    let mut pairs = url.query_pairs_mut();
    for (key, value) in query_params {
        pairs.append_pair(key, value);
    }
}

fn resolve_peer_addr(host: &str, port: u16) -> Result<SocketAddr, VaneError> {
    (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| VaneError::Generic(format!("Failed to resolve {host}:{port}")))
}

fn build_h3_headers(
    url: &Url,
    request: &VaneRequest,
    config: &VaneClientConfig,
) -> Result<Vec<quiche::h3::Header>, VaneError> {
    let method = request.method.to_ascii_uppercase();
    let host = url
        .host_str()
        .ok_or_else(|| VaneError::Generic("URL is missing host".to_string()))?;
    let authority = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    let mut path = url.path().to_string();
    if path.is_empty() {
        path.push('/');
    }
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }

    let mut headers = vec![
        quiche::h3::Header::new(b":method", method.as_bytes()),
        quiche::h3::Header::new(b":scheme", url.scheme().as_bytes()),
        quiche::h3::Header::new(b":authority", authority.as_bytes()),
        quiche::h3::Header::new(b":path", path.as_bytes()),
    ];

    let user_agent = config.user_agent.as_deref().unwrap_or("Vane/0.1.0");
    headers.push(quiche::h3::Header::new(
        b"user-agent",
        user_agent.as_bytes(),
    ));

    for (key, value) in &config.default_headers {
        push_regular_header(&mut headers, key, value)?;
    }
    for (key, value) in &request.headers {
        push_regular_header(&mut headers, key, value)?;
    }

    Ok(headers)
}

fn push_regular_header(
    headers: &mut Vec<quiche::h3::Header>,
    key: &str,
    value: &str,
) -> Result<(), VaneError> {
    if key.starts_with(':') {
        return Err(VaneError::Generic(format!(
            "HTTP/3 pseudo-header cannot be set by callers: {key}"
        )));
    }
    headers.push(quiche::h3::Header::new(
        key.to_ascii_lowercase().as_bytes(),
        value.as_bytes(),
    ));
    Ok(())
}

fn read_quic_packets(
    socket: &UdpSocket,
    conn: &mut quiche::Connection,
    local_addr: SocketAddr,
) -> Result<(), VaneError> {
    let timeout = conn.timeout().unwrap_or(Duration::from_millis(10));
    socket.set_read_timeout(Some(timeout.min(Duration::from_millis(50))))?;

    let mut buf = [0; 65535];
    loop {
        match socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                let recv_info = quiche::RecvInfo {
                    from,
                    to: local_addr,
                };
                match conn.recv(&mut buf[..len], recv_info) {
                    Ok(_) => {}
                    Err(quiche::Error::Done) => break,
                    Err(e) => return Err(e.into()),
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                if conn.timeout().is_some_and(|t| t.is_zero()) {
                    conn.on_timeout();
                }
                break;
            }
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}

fn flush_quic_packets(socket: &UdpSocket, conn: &mut quiche::Connection) -> Result<(), VaneError> {
    let mut out = [0; MAX_DATAGRAM_SIZE];
    loop {
        match conn.send(&mut out) {
            Ok((written, send_info)) => {
                socket.send_to(&out[..written], send_info.to)?;
            }
            Err(quiche::Error::Done) => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

fn process_h3_events(
    http3: &mut quiche::h3::Connection,
    conn: &mut quiche::Connection,
    response_status: &mut u16,
    response_headers: &mut HashMap<String, String>,
    response_body: &mut Vec<u8>,
    finished: &mut bool,
) -> Result<(), VaneError> {
    let mut buf = [0; 16 * 1024];

    loop {
        match http3.poll(conn) {
            Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                for header in list {
                    let name = String::from_utf8_lossy(header.name()).to_string();
                    let value = String::from_utf8_lossy(header.value()).to_string();
                    if name == ":status" {
                        *response_status = value.parse::<u16>().unwrap_or_default();
                    } else {
                        response_headers.insert(name, value);
                    }
                }
                let _ = stream_id;
            }
            Ok((stream_id, quiche::h3::Event::Data)) => loop {
                match http3.recv_body(conn, stream_id, &mut buf) {
                    Ok(read) => {
                        if response_body.len() + read > MAX_RESPONSE_BODY_BYTES {
                            return Err(VaneError::Generic(format!(
                                "HTTP/3 response body exceeded {} bytes",
                                MAX_RESPONSE_BODY_BYTES
                            )));
                        }
                        response_body.extend_from_slice(&buf[..read]);
                    }
                    Err(quiche::h3::Error::Done) => break,
                    Err(e) => return Err(e.into()),
                }
            },
            Ok((_stream_id, quiche::h3::Event::Finished)) => {
                *finished = true;
                break;
            }
            Ok((_stream_id, quiche::h3::Event::Reset(e))) => {
                return Err(VaneError::Generic(format!("HTTP/3 stream reset: {e:?}")));
            }
            Ok((_id, quiche::h3::Event::GoAway)) => {
                return Err(VaneError::Generic("HTTP/3 GOAWAY received".to_string()));
            }
            Ok((_id, quiche::h3::Event::PriorityUpdate)) => {}
            Err(quiche::h3::Error::Done) => break,
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}

// ---------- UniFFI Exports ----------
#[uniffi::export]
pub fn create_default_config() -> VaneClientConfig {
    VaneClientConfig::default()
}

#[uniffi::export]
pub fn create_vane_client(config: VaneClientConfig) -> Result<Arc<VaneClient>, VaneError> {
    Ok(Arc::new(VaneClient::new(config)?))
}

#[uniffi::export]
impl VaneClient {
    pub fn execute_request(&self, request: VaneRequest) -> Result<VaneResponse, VaneError> {
        self.execute(request)
    }

    pub fn get_request(&self, url: String) -> Result<VaneResponse, VaneError> {
        self.make_request("GET", &url, None)
    }

    pub fn post_request(
        &self,
        url: String,
        body: Option<Vec<u8>>,
    ) -> Result<VaneResponse, VaneError> {
        self.make_request("POST", &url, body)
    }

    pub fn put_request(
        &self,
        url: String,
        body: Option<Vec<u8>>,
    ) -> Result<VaneResponse, VaneError> {
        self.make_request("PUT", &url, body)
    }

    pub fn delete_request(&self, url: String) -> Result<VaneResponse, VaneError> {
        self.make_request("DELETE", &url, None)
    }

    pub fn patch_request(
        &self,
        url: String,
        body: Option<Vec<u8>>,
    ) -> Result<VaneResponse, VaneError> {
        self.make_request("PATCH", &url, body)
    }
}

// ---------- Helpers ----------
#[uniffi::export]
pub fn parse_json_response(resp: &VaneResponse) -> Result<String, VaneError> {
    let parsed: Value = serde_json::from_slice(&resp.body)
        .map_err(|e| VaneError::Generic(format!("Parse JSON failed: {e}")))?;
    serde_json::to_string_pretty(&parsed)
        .map_err(|e| VaneError::Generic(format!("Serialize JSON failed: {e}")))
}

#[uniffi::export]
pub fn response_body_utf8(resp: &VaneResponse) -> Result<String, VaneError> {
    String::from_utf8(resp.body.clone())
        .map_err(|e| VaneError::Generic(format!("Invalid UTF-8 in response body: {e}")))
}
