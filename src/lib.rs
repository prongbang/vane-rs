uniffi::setup_scaffolding!();

use std::collections::HashMap;
use std::fs::{self, File};
use std::io;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
#[cfg(feature = "spki-pinning")]
use boring::x509::X509;
use quiche::h3::NameValue;
use sha2::{Digest, Sha256};
use thiserror::Error;

const MAX_DATAGRAM_SIZE: usize = 1350;
const DEFAULT_MAX_REQUEST_BODY_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_MAX_RESPONSE_BODY_BYTES: u64 = 64 * 1024 * 1024;

static CANCEL_TOKENS: LazyLock<Mutex<HashMap<u64, Arc<AtomicBool>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static NEXT_CANCEL_TOKEN_ID: AtomicU64 = AtomicU64::new(1);
static PROGRESS_STATES: LazyLock<Mutex<HashMap<u64, VaneProgressState>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static NEXT_PROGRESS_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Default)]
struct VaneProgressState {
    upload_sent: u64,
    upload_total: u64,
    download_received: u64,
    download_total: u64,
    done: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Url {
    scheme: String,
    host: String,
    port: Option<u16>,
    path: String,
    query: Option<String>,
}

impl Url {
    fn parse(input: &str) -> Result<Self, String> {
        let (scheme, rest) = input
            .split_once("://")
            .ok_or_else(|| "URL must include http:// or https:// scheme".to_string())?;
        if scheme != "http" && scheme != "https" {
            return Err(format!("unsupported URL scheme {scheme}"));
        }

        let rest = rest
            .split_once('#')
            .map(|(before_fragment, _)| before_fragment)
            .unwrap_or(rest);
        let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        if authority.is_empty() {
            return Err("URL is missing host".to_string());
        }

        let (host, port) = parse_authority(authority)?;
        let path_and_query = &rest[authority_end..];
        let (path, query) = split_path_and_query(path_and_query);

        Ok(Self {
            scheme: scheme.to_string(),
            host,
            port,
            path,
            query,
        })
    }

    fn join(&self, input: &str) -> Result<Self, String> {
        if input.contains("://") {
            return Self::parse(input);
        }

        if let Some(rest) = input.strip_prefix("//") {
            return Self::parse(&format!("{}://{rest}", self.scheme));
        }

        let input = input
            .split_once('#')
            .map(|(before_fragment, _)| before_fragment)
            .unwrap_or(input);
        let (path, query) = split_path_and_query(input);
        let joined_path = if input.starts_with('?') {
            self.path.clone()
        } else if path.starts_with('/') {
            path
        } else {
            join_relative_path(&self.path, &path)
        };

        Ok(Self {
            scheme: self.scheme.clone(),
            host: self.host.clone(),
            port: self.port,
            path: normalize_path(&joined_path),
            query,
        })
    }

    fn scheme(&self) -> &str {
        &self.scheme
    }

    fn host_str(&self) -> Option<&str> {
        Some(&self.host)
    }

    fn port(&self) -> Option<u16> {
        self.port
    }

    fn port_or_known_default(&self) -> Option<u16> {
        self.port.or(match self.scheme.as_str() {
            "http" => Some(80),
            "https" => Some(443),
            _ => None,
        })
    }

    fn path(&self) -> &str {
        &self.path
    }

    fn query(&self) -> Option<&str> {
        self.query.as_deref()
    }

    fn append_query_pair(&mut self, key: &str, value: &str) {
        let pair = format!(
            "{}={}",
            percent_encode_query(key),
            percent_encode_query(value)
        );
        match &mut self.query {
            Some(query) if !query.is_empty() => {
                query.push('&');
                query.push_str(&pair);
            }
            Some(query) => query.push_str(&pair),
            None => self.query = Some(pair),
        }
    }
}

impl std::fmt::Display for Url {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://{}", self.scheme, self.host)?;
        if let Some(port) = self.port {
            write!(f, ":{port}")?;
        }
        write!(f, "{}", self.path)?;
        if let Some(query) = &self.query {
            write!(f, "?{query}")?;
        }
        Ok(())
    }
}

fn parse_authority(authority: &str) -> Result<(String, Option<u16>), String> {
    if authority.contains('@') {
        return Err("userinfo in URLs is not supported".to_string());
    }

    if let Some(rest) = authority.strip_prefix('[') {
        let (host, after_host) = rest
            .split_once(']')
            .ok_or_else(|| "IPv6 host is missing closing bracket".to_string())?;
        let port = if let Some(port) = after_host.strip_prefix(':') {
            Some(parse_port(port)?)
        } else if after_host.is_empty() {
            None
        } else {
            return Err("invalid IPv6 authority".to_string());
        };
        return Ok((format!("[{host}]"), port));
    }

    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            (host, Some(parse_port(port)?))
        }
        Some((_, "")) => {
            return Err("URL port is empty".to_string());
        }
        _ => (authority, None),
    };

    if host.is_empty() {
        return Err("URL is missing host".to_string());
    }
    if !host.is_ascii() {
        return Err("non-ASCII hosts are not supported; use punycode".to_string());
    }

    Ok((host.to_ascii_lowercase(), port))
}

fn parse_port(port: &str) -> Result<u16, String> {
    port.parse::<u16>()
        .map_err(|e| format!("invalid URL port {port}: {e}"))
}

fn split_path_and_query(input: &str) -> (String, Option<String>) {
    if input.is_empty() {
        return ("/".to_string(), None);
    }

    let (path, query) = input
        .split_once('?')
        .map(|(path, query)| (path, Some(query.to_string())))
        .unwrap_or((input, None));
    let path = if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    };

    (path, query)
}

fn join_relative_path(base_path: &str, relative_path: &str) -> String {
    if relative_path.is_empty() {
        return base_path.to_string();
    }

    let base_dir = base_path
        .rsplit_once('/')
        .map(|(dir, _)| {
            if dir.is_empty() {
                "/".to_string()
            } else {
                format!("{dir}/")
            }
        })
        .unwrap_or_else(|| "/".to_string());

    format!("{base_dir}{relative_path}")
}

fn normalize_path(path: &str) -> String {
    let mut segments = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            _ => segments.push(segment),
        }
    }

    format!("/{}", segments.join("/"))
}

fn percent_encode_query(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char)
            }
            b' ' => encoded.push('+'),
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

// ---------- Models ----------
#[derive(Debug, Clone, uniffi::Record)]
pub struct VaneRequest {
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub query_params: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
    pub body_file_path: Option<String>,
    pub response_body_path: Option<String>,
    pub cancel_token_id: Option<u64>,
    pub progress_id: Option<u64>,
    pub timeout_seconds: Option<u64>,
    pub follow_redirects: bool,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct VaneResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub body_file_path: Option<String>,
    pub is_success: bool,
    pub url: String,
}

#[derive(Debug, Clone, Default, uniffi::Record)]
pub struct VaneProgressSnapshot {
    pub upload_sent: u64,
    pub upload_total: u64,
    pub download_received: u64,
    pub download_total: u64,
    pub done: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum VaneProtocolMode {
    /// Kept for source compatibility; this build uses HTTP/3 only.
    Http3ThenHttp2ThenHttp1,
    Http3Only,
    /// Kept for source compatibility; HTTP/2 and HTTP/1.1 are unsupported.
    Http2ThenHttp1,
    Http2Only,
    Http1Only,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct VaneClientConfig {
    pub base_url: Option<String>,
    pub default_headers: HashMap<String, String>,
    pub dns_overrides: HashMap<String, String>,
    pub certificate_pins: HashMap<String, Vec<String>>,
    pub cookies_enabled: bool,
    pub cookie_persistence_path: Option<String>,
    pub connection_pool_enabled: bool,
    pub max_idle_connections: u64,
    pub connection_idle_timeout_seconds: u64,
    pub retry_max_attempts: u64,
    pub retry_initial_delay_millis: u64,
    pub retry_max_delay_millis: u64,
    pub retry_unsafe_methods: bool,
    pub max_request_body_bytes: u64,
    pub max_response_body_bytes: u64,
    pub timeout_seconds: Option<u64>,
    pub follow_redirects: bool,
    pub user_agent: Option<String>,
    pub protocol_mode: VaneProtocolMode,
    pub proxy_url: Option<String>,
    pub proxy_authorization: Option<String>,
}

impl Default for VaneClientConfig {
    fn default() -> Self {
        Self {
            base_url: None,
            default_headers: HashMap::new(),
            dns_overrides: HashMap::new(),
            certificate_pins: HashMap::new(),
            cookies_enabled: false,
            cookie_persistence_path: None,
            connection_pool_enabled: false,
            max_idle_connections: 4,
            connection_idle_timeout_seconds: 30,
            retry_max_attempts: 1,
            retry_initial_delay_millis: 100,
            retry_max_delay_millis: 1_000,
            retry_unsafe_methods: false,
            max_request_body_bytes: DEFAULT_MAX_REQUEST_BODY_BYTES,
            max_response_body_bytes: DEFAULT_MAX_RESPONSE_BODY_BYTES,
            timeout_seconds: Some(30),
            follow_redirects: true,
            user_agent: Some("Vane/0.1.0".to_string()),
            protocol_mode: VaneProtocolMode::Http3Only,
            proxy_url: None,
            proxy_authorization: None,
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

fn unsupported_tcp_backend_error() -> VaneError {
    VaneError::Generic(
        "This Vane build supports HTTP/3 only; HTTP/1.1 and HTTP/2 fallback were removed"
            .to_string(),
    )
}

// ---------- Client ----------
#[derive(uniffi::Object)]
pub struct VaneClient {
    config: VaneClientConfig,
    pool: Mutex<Vec<PooledHttp3Connection>>,
    cookie_jar: Mutex<Vec<StoredCookie>>,
    certificate_pins: Mutex<HashMap<String, Vec<String>>>,
}

impl VaneClient {
    pub fn new(config: VaneClientConfig) -> Result<Self, VaneError> {
        let cookie_jar = if config.cookies_enabled {
            load_cookie_jar(config.cookie_persistence_path.as_deref())?
        } else {
            Vec::new()
        };
        let certificate_pins = config.certificate_pins.clone();
        Ok(Self {
            config,
            pool: Mutex::new(Vec::new()),
            cookie_jar: Mutex::new(cookie_jar),
            certificate_pins: Mutex::new(certificate_pins),
        })
    }

    pub fn execute(&self, request: VaneRequest) -> Result<VaneResponse, VaneError> {
        let url = self.build_url(&request)?;
        match self.config.protocol_mode {
            VaneProtocolMode::Http3ThenHttp2ThenHttp1 | VaneProtocolMode::Http3Only => {
                self.execute_with_retry(&request, &url)
            }
            VaneProtocolMode::Http2ThenHttp1
            | VaneProtocolMode::Http2Only
            | VaneProtocolMode::Http1Only => Err(unsupported_tcp_backend_error()),
        }
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

    fn execute_with_retry(
        &self,
        request: &VaneRequest,
        url: &Url,
    ) -> Result<VaneResponse, VaneError> {
        let max_attempts = self.config.retry_max_attempts.max(1);
        let mut attempt = 1u64;
        let mut last_error = None;

        while attempt <= max_attempts {
            match self.execute_http3_once(request, url) {
                Ok(response) => {
                    if should_retry_response(
                        &request.method,
                        response.status_code,
                        attempt,
                        &self.config,
                    ) {
                        sleep_before_retry(attempt, &self.config);
                        attempt += 1;
                        continue;
                    }

                    return Ok(response);
                }
                Err(err) => {
                    if !should_retry_error(&request.method, attempt, &self.config) {
                        return Err(err);
                    }

                    last_error = Some(err);
                    sleep_before_retry(attempt, &self.config);
                    attempt += 1;
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            VaneError::Generic("Request retry attempts were exhausted".to_string())
        }))
    }

    fn execute_http3_once(
        &self,
        request: &VaneRequest,
        url: &Url,
    ) -> Result<VaneResponse, VaneError> {
        if url.scheme() != "https" {
            return Err(VaneError::Generic(
                "quiche backend only supports https:// URLs over HTTP/3".to_string(),
            ));
        }
        let host = url
            .host_str()
            .ok_or_else(|| VaneError::Generic("URL is missing host".to_string()))?;
        if let Some(proxy_url) = self.config.proxy_url.as_deref() {
            MasqueProxyConfig::parse(proxy_url)?;
        }
        let peer_addr = resolve_peer_addr(
            host,
            url.port_or_known_default().unwrap_or(443),
            &self.config.dns_overrides,
        )?;
        let timeout = Duration::from_secs(
            request
                .timeout_seconds
                .or(self.config.timeout_seconds)
                .unwrap_or(30),
        );
        let cookie_header = if self.config.cookies_enabled {
            Some(self.cookie_header(url)?)
        } else {
            None
        };
        let headers = build_h3_headers(url, request, &self.config, cookie_header.as_deref())?;
        let request_body = load_request_body(request)?;
        validate_request_body_limit(&request_body, self.config.max_request_body_bytes)?;
        progress_init(request.progress_id, request_body.len() as u64);
        let certificate_pins = self.certificate_pins_snapshot()?;
        let pool_key = PoolKey::new(url, &self.config, &certificate_pins);
        let mut transport = match if self.config.connection_pool_enabled {
            self.take_pooled_connection(&pool_key, timeout)?
        } else {
            None
        } {
            Some(connection) => connection,
            None => self
                .connect_http3(
                    host,
                    peer_addr,
                    timeout,
                    pool_key.clone(),
                    &certificate_pins,
                )
                .inspect_err(|_| {
                    self.drop_closed_connections();
                })?,
        };

        let result = perform_http3_request(
            &mut transport,
            H3RequestOptions {
                headers: &headers,
                request_body: &request_body,
                timeout,
                url,
                max_response_body_bytes: self.config.max_response_body_bytes,
                response_body_path: request.response_body_path.as_deref(),
                cancel_token_id: request.cancel_token_id,
                progress_id: request.progress_id,
            },
        );
        match result {
            Ok(response) => {
                if self.config.cookies_enabled {
                    self.store_response_cookies(url, &response.set_cookie_headers)?;
                }
                progress_done(request.progress_id);

                let public_response = response.into_public_response();
                if self.config.connection_pool_enabled && !transport.conn.is_closed() {
                    self.return_pooled_connection(transport)?;
                } else {
                    transport.conn.close(true, 0x00, b"done").ok();
                    transport.flush_packets().ok();
                }

                Ok(public_response)
            }
            Err(err) => {
                progress_done(request.progress_id);
                transport.conn.close(true, 0x01, b"request failed").ok();
                transport.flush_packets().ok();
                Err(err)
            }
        }
    }

    fn connect_http3(
        &self,
        host: &str,
        peer_addr: SocketAddr,
        timeout: Duration,
        key: PoolKey,
        certificate_pins: &HashMap<String, Vec<String>>,
    ) -> Result<PooledHttp3Connection, VaneError> {
        if let Some(proxy_url) = self.config.proxy_url.as_deref() {
            return self.connect_http3_via_masque(
                host,
                peer_addr,
                proxy_url,
                timeout,
                key,
                certificate_pins,
            );
        }

        let direct = connect_quic_h3(host, peer_addr, timeout, certificate_pins)?;
        Ok(PooledHttp3Connection {
            key,
            io: Http3Io::Direct {
                socket: direct.socket,
            },
            local_addr: direct.local_addr,
            peer_addr: direct.peer_addr,
            conn: direct.conn,
            http3: direct.http3,
            last_used: Instant::now(),
        })
    }

    fn connect_http3_via_masque(
        &self,
        host: &str,
        peer_addr: SocketAddr,
        proxy_url: &str,
        timeout: Duration,
        key: PoolKey,
        certificate_pins: &HashMap<String, Vec<String>>,
    ) -> Result<PooledHttp3Connection, VaneError> {
        let proxy = MasqueProxyConfig::parse(proxy_url)?;
        let proxy_addr = resolve_peer_addr(&proxy.host, proxy.port, &self.config.dns_overrides)?;
        let mut outer = connect_quic_h3(&proxy.host, proxy_addr, timeout, certificate_pins)?;
        let stream_id = establish_connect_udp_tunnel(
            &mut outer,
            &proxy,
            host,
            peer_addr.port(),
            self.config.proxy_authorization.as_deref(),
            timeout,
        )?;

        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        getrandom::fill(&mut scid).map_err(|e| {
            VaneError::Generic(format!("Failed to generate QUIC connection ID: {e}"))
        })?;
        let scid = quiche::ConnectionId::from_ref(&scid);
        let mut quic_config = create_quiche_config(timeout)?;
        let mut conn = quiche::connect(
            Some(host),
            &scid,
            outer.local_addr,
            peer_addr,
            &mut quic_config,
        )
        .map_err(|e| VaneError::Generic(format!("Failed to create QUIC client: {e}")))?;
        let h3_config = quiche::h3::Config::new()
            .map_err(|e| VaneError::Generic(format!("Failed to create HTTP/3 config: {e}")))?;
        let mut io = Http3Io::Masque(Box::new(MasqueTunnel {
            socket: outer.socket,
            local_addr: outer.local_addr,
            peer_addr: outer.peer_addr,
            conn: outer.conn,
            http3: outer.http3,
            stream_id,
            flow_id: stream_id / 4,
        }));

        flush_quic_packets_via(&mut io, &mut conn)?;
        let deadline = Instant::now() + timeout;

        while Instant::now() < deadline {
            read_quic_packets_via(&mut io, &mut conn, outer.local_addr, peer_addr)?;

            if conn.is_established() {
                verify_certificate_pins(host, conn.peer_cert(), certificate_pins)?;
                let http3 = quiche::h3::Connection::with_transport(&mut conn, &h3_config)?;
                return Ok(PooledHttp3Connection {
                    key,
                    io,
                    local_addr: outer.local_addr,
                    peer_addr,
                    conn,
                    http3,
                    last_used: Instant::now(),
                });
            }

            flush_quic_packets_via(&mut io, &mut conn)?;

            if conn.is_closed() {
                return Err(VaneError::Generic(
                    "QUIC connection closed before handshake completed".to_string(),
                ));
            }
        }

        Err(VaneError::Generic("HTTP/3 handshake timed out".to_string()))
    }

    fn take_pooled_connection(
        &self,
        key: &PoolKey,
        timeout: Duration,
    ) -> Result<Option<PooledHttp3Connection>, VaneError> {
        let mut pool = self
            .pool
            .lock()
            .map_err(|_| VaneError::Generic("Connection pool lock was poisoned".to_string()))?;
        let idle_timeout = Duration::from_secs(self.config.connection_idle_timeout_seconds);
        let now = Instant::now();
        pool.retain(|conn| {
            !conn.conn.is_closed() && now.duration_since(conn.last_used) <= idle_timeout
        });

        let Some(index) = pool.iter().position(|conn| &conn.key == key) else {
            return Ok(None);
        };

        let conn = pool.swap_remove(index);
        conn.set_write_timeout(timeout)?;
        Ok(Some(conn))
    }

    fn return_pooled_connection(
        &self,
        mut connection: PooledHttp3Connection,
    ) -> Result<(), VaneError> {
        let mut pool = self
            .pool
            .lock()
            .map_err(|_| VaneError::Generic("Connection pool lock was poisoned".to_string()))?;
        let max_idle = self.config.max_idle_connections as usize;
        if max_idle == 0 {
            connection.conn.close(true, 0x00, b"pool disabled").ok();
            connection.flush_packets().ok();
            return Ok(());
        }

        connection.last_used = Instant::now();
        pool.push(connection);

        while pool.len() > max_idle {
            if let Some(removed) = pool.first_mut() {
                removed.conn.close(true, 0x00, b"pool full").ok();
                removed.flush_packets().ok();
            }
            pool.remove(0);
        }

        Ok(())
    }

    fn drop_closed_connections(&self) {
        if let Ok(mut pool) = self.pool.lock() {
            pool.retain(|conn| !conn.conn.is_closed());
        }
    }

    fn clear_connection_pool(&self) -> Result<(), VaneError> {
        let mut pool = self
            .pool
            .lock()
            .map_err(|_| VaneError::Generic("Connection pool lock was poisoned".to_string()))?;
        for conn in pool.iter_mut() {
            conn.conn
                .close(true, 0x00, b"certificate pins changed")
                .ok();
            conn.flush_packets().ok();
        }
        pool.clear();
        Ok(())
    }

    fn certificate_pins_snapshot(&self) -> Result<HashMap<String, Vec<String>>, VaneError> {
        self.certificate_pins
            .lock()
            .map(|pins| pins.clone())
            .map_err(|_| VaneError::Generic("Certificate pin lock was poisoned".to_string()))
    }

    fn set_certificate_pins_internal(
        &self,
        host: String,
        pins: Vec<String>,
    ) -> Result<(), VaneError> {
        validate_certificate_pin_host(&host)?;
        validate_certificate_pins(&pins)?;
        {
            let mut configured = self
                .certificate_pins
                .lock()
                .map_err(|_| VaneError::Generic("Certificate pin lock was poisoned".to_string()))?;
            if pins.is_empty() {
                configured.remove(&host);
            } else {
                configured.insert(host, pins);
            }
        }
        self.clear_connection_pool()
    }

    fn add_certificate_pin_internal(&self, host: String, pin: String) -> Result<(), VaneError> {
        self.set_certificate_pins_internal(host.clone(), {
            let mut pins = self
                .certificate_pins
                .lock()
                .map_err(|_| VaneError::Generic("Certificate pin lock was poisoned".to_string()))?
                .get(&host)
                .cloned()
                .unwrap_or_default();
            pins.push(pin);
            pins
        })
    }

    fn cookie_header(&self, url: &Url) -> Result<String, VaneError> {
        let mut jar = self
            .cookie_jar
            .lock()
            .map_err(|_| VaneError::Generic("Cookie jar lock was poisoned".to_string()))?;
        let now = now_epoch_seconds();
        jar.retain(|cookie| !cookie.is_expired(now));

        Ok(jar
            .iter()
            .filter(|cookie| cookie.matches(url, now))
            .map(|cookie| format!("{}={}", cookie.name, cookie.value))
            .collect::<Vec<_>>()
            .join("; "))
    }

    fn store_response_cookies(
        &self,
        url: &Url,
        set_cookie_headers: &[String],
    ) -> Result<(), VaneError> {
        if set_cookie_headers.is_empty() {
            return Ok(());
        }

        let mut jar = self
            .cookie_jar
            .lock()
            .map_err(|_| VaneError::Generic("Cookie jar lock was poisoned".to_string()))?;
        for header in set_cookie_headers {
            if let Some(cookie) = StoredCookie::parse(url, header) {
                jar.retain(|existing| !existing.same_key(&cookie));
                if !cookie.is_expired(now_epoch_seconds()) {
                    jar.push(cookie);
                }
            }
        }
        persist_cookie_jar(self.config.cookie_persistence_path.as_deref(), &jar)?;

        Ok(())
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
            body_file_path: None,
            response_body_path: None,
            cancel_token_id: None,
            progress_id: None,
            timeout_seconds: None,
            follow_redirects: self.config.follow_redirects,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PoolKey {
    scheme: String,
    host: String,
    port: u16,
    protocol_mode: VaneProtocolMode,
    dns_override: Option<String>,
    proxy_url: Option<String>,
    proxy_authorization: Option<String>,
    certificate_pins: Vec<String>,
}

impl PoolKey {
    fn new(
        url: &Url,
        config: &VaneClientConfig,
        certificate_pin_map: &HashMap<String, Vec<String>>,
    ) -> Self {
        let host = url.host_str().unwrap_or_default().to_string();
        let mut certificate_pins = certificate_pin_map.get(&host).cloned().unwrap_or_default();
        certificate_pins.sort();

        Self {
            scheme: url.scheme().to_string(),
            host: host.clone(),
            port: url.port_or_known_default().unwrap_or(443),
            protocol_mode: config.protocol_mode.clone(),
            dns_override: config.dns_overrides.get(&host).cloned(),
            proxy_url: config.proxy_url.clone(),
            proxy_authorization: config.proxy_authorization.clone(),
            certificate_pins,
        }
    }
}

struct PooledHttp3Connection {
    key: PoolKey,
    io: Http3Io,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    conn: quiche::Connection,
    http3: quiche::h3::Connection,
    last_used: Instant,
}

impl PooledHttp3Connection {
    fn set_write_timeout(&self, timeout: Duration) -> Result<(), VaneError> {
        self.io.set_write_timeout(timeout)
    }

    fn read_packets(&mut self) -> Result<(), VaneError> {
        read_quic_packets_via(
            &mut self.io,
            &mut self.conn,
            self.local_addr,
            self.peer_addr,
        )
    }

    fn flush_packets(&mut self) -> Result<(), VaneError> {
        flush_quic_packets_via(&mut self.io, &mut self.conn)
    }
}

struct DirectHttp3Connection {
    socket: UdpSocket,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    conn: quiche::Connection,
    http3: quiche::h3::Connection,
}

enum Http3Io {
    Direct { socket: UdpSocket },
    Masque(Box<MasqueTunnel>),
}

impl Http3Io {
    fn set_write_timeout(&self, timeout: Duration) -> Result<(), VaneError> {
        match self {
            Self::Direct { socket } => socket
                .set_write_timeout(Some(timeout))
                .map_err(|e| VaneError::Generic(format!("Failed to set UDP write timeout: {e}"))),
            Self::Masque(tunnel) => tunnel.socket.set_write_timeout(Some(timeout)).map_err(|e| {
                VaneError::Generic(format!("Failed to set proxy UDP write timeout: {e}"))
            }),
        }
    }
}

struct MasqueTunnel {
    socket: UdpSocket,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    conn: quiche::Connection,
    http3: quiche::h3::Connection,
    stream_id: u64,
    flow_id: u64,
}

impl MasqueTunnel {
    fn send_origin_packet(&mut self, packet: &[u8]) -> Result<(), VaneError> {
        let datagram = encode_h3_datagram(self.flow_id, 0, packet)?;
        self.conn.dgram_send(&datagram)?;
        flush_quic_packets(&self.socket, &mut self.conn)
    }

    fn read_origin_packets(
        &mut self,
        origin_conn: &mut quiche::Connection,
        origin_local_addr: SocketAddr,
        origin_peer_addr: SocketAddr,
    ) -> Result<(), VaneError> {
        read_quic_packets(
            &self.socket,
            &mut self.conn,
            self.local_addr,
            self.peer_addr,
        )?;
        process_masque_control_events(&mut self.http3, &mut self.conn, self.stream_id)?;

        let mut buf = [0; MAX_DATAGRAM_SIZE];
        loop {
            match self.conn.dgram_recv(&mut buf) {
                Ok(len) => {
                    let Some((flow_id, context_id, payload_offset)) =
                        decode_h3_datagram(&buf[..len])?
                    else {
                        continue;
                    };
                    if flow_id != self.flow_id || context_id != 0 {
                        continue;
                    }
                    let recv_info = quiche::RecvInfo {
                        from: origin_peer_addr,
                        to: origin_local_addr,
                    };
                    match origin_conn.recv(&mut buf[payload_offset..len], recv_info) {
                        Ok(_) | Err(quiche::Error::Done) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
                Err(quiche::Error::Done) => break,
                Err(e) => return Err(e.into()),
            }
        }

        Ok(())
    }
}

struct Http3ResponseParts {
    status_code: u16,
    headers: HashMap<String, String>,
    set_cookie_headers: Vec<String>,
    body: Vec<u8>,
    body_file_path: Option<String>,
    url: String,
}

impl Http3ResponseParts {
    fn into_public_response(self) -> VaneResponse {
        VaneResponse {
            status_code: self.status_code,
            headers: self.headers,
            body: self.body,
            body_file_path: self.body_file_path,
            is_success: (200..=299).contains(&self.status_code),
            url: self.url,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredCookie {
    name: String,
    value: String,
    domain: String,
    host_only: bool,
    path: String,
    secure: bool,
    expires_at_epoch_seconds: Option<u64>,
}

impl StoredCookie {
    fn parse(url: &Url, set_cookie: &str) -> Option<Self> {
        let origin_host = url.host_str()?.to_ascii_lowercase();
        let mut parts = set_cookie.split(';').map(str::trim);
        let name_value = parts.next()?;
        let (name, value) = name_value.split_once('=')?;
        let name = name.trim();
        if name.is_empty() {
            return None;
        }

        let mut cookie = Self {
            name: name.to_string(),
            value: value.trim().to_string(),
            domain: origin_host.clone(),
            host_only: true,
            path: default_cookie_path(url),
            secure: false,
            expires_at_epoch_seconds: None,
        };

        for attr in parts {
            let (key, value) = attr.split_once('=').unwrap_or((attr, ""));
            match key.trim().to_ascii_lowercase().as_str() {
                "domain" => {
                    let domain = value.trim().trim_start_matches('.').to_ascii_lowercase();
                    if domain.is_empty() || !domain_matches(&origin_host, &domain) {
                        return None;
                    }
                    cookie.domain = domain;
                    cookie.host_only = false;
                }
                "path" => {
                    let path = value.trim();
                    if path.starts_with('/') {
                        cookie.path = path.to_string();
                    }
                }
                "secure" => cookie.secure = true,
                "max-age" => {
                    if let Ok(seconds) = value.trim().parse::<i64>() {
                        cookie.expires_at_epoch_seconds = if seconds <= 0 {
                            Some(now_epoch_seconds())
                        } else {
                            Some(now_epoch_seconds().saturating_add(seconds as u64))
                        };
                    }
                }
                _ => {}
            }
        }

        Some(cookie)
    }

    fn matches(&self, url: &Url, now: u64) -> bool {
        let Some(host) = url.host_str().map(str::to_ascii_lowercase) else {
            return false;
        };
        if self.is_expired(now) {
            return false;
        }
        if self.secure && url.scheme() != "https" {
            return false;
        }
        if self.host_only {
            if host != self.domain {
                return false;
            }
        } else if !domain_matches(&host, &self.domain) {
            return false;
        }

        path_matches(url.path(), &self.path)
    }

    fn same_key(&self, other: &Self) -> bool {
        self.name == other.name && self.domain == other.domain && self.path == other.path
    }

    fn is_expired(&self, now: u64) -> bool {
        self.expires_at_epoch_seconds
            .is_some_and(|expires_at| now >= expires_at)
    }
}

fn now_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn load_cookie_jar(path: Option<&str>) -> Result<Vec<StoredCookie>, VaneError> {
    let Some(path) = path.filter(|path| !path.is_empty()) else {
        return Ok(Vec::new());
    };
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(VaneError::Generic(format!(
                "Failed to read cookie persistence file {path}: {err}"
            )));
        }
    };
    let now = now_epoch_seconds();
    Ok(content
        .lines()
        .filter_map(parse_persisted_cookie)
        .filter(|cookie| !cookie.is_expired(now))
        .collect())
}

fn persist_cookie_jar(path: Option<&str>, jar: &[StoredCookie]) -> Result<(), VaneError> {
    let Some(path) = path.filter(|path| !path.is_empty()) else {
        return Ok(());
    };
    let now = now_epoch_seconds();
    let mut content = String::new();
    for cookie in jar.iter().filter(|cookie| !cookie.is_expired(now)) {
        content.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            BASE64.encode(cookie.name.as_bytes()),
            BASE64.encode(cookie.value.as_bytes()),
            BASE64.encode(cookie.domain.as_bytes()),
            u8::from(cookie.host_only),
            BASE64.encode(cookie.path.as_bytes()),
            u8::from(cookie.secure),
            cookie
                .expires_at_epoch_seconds
                .map(|value| value.to_string())
                .unwrap_or_default()
        ));
    }
    if let Some(parent) = std::path::Path::new(path).parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|err| {
            VaneError::Generic(format!("Failed to create cookie directory: {err}"))
        })?;
    }
    fs::write(path, content).map_err(|err| {
        VaneError::Generic(format!(
            "Failed to write cookie persistence file {path}: {err}"
        ))
    })
}

fn parse_persisted_cookie(line: &str) -> Option<StoredCookie> {
    let mut parts = line.split('\t');
    Some(StoredCookie {
        name: decode_cookie_field(parts.next()?)?,
        value: decode_cookie_field(parts.next()?)?,
        domain: decode_cookie_field(parts.next()?)?,
        host_only: parts.next()? == "1",
        path: decode_cookie_field(parts.next()?)?,
        secure: parts.next()? == "1",
        expires_at_epoch_seconds: match parts.next().unwrap_or_default() {
            "" => None,
            value => value.parse::<u64>().ok(),
        },
    })
}

fn decode_cookie_field(value: &str) -> Option<String> {
    String::from_utf8(BASE64.decode(value).ok()?).ok()
}

struct MasqueProxyConfig {
    host: String,
    port: u16,
    authority: String,
}

impl MasqueProxyConfig {
    fn parse(proxy_url: &str) -> Result<Self, VaneError> {
        let url = Url::parse(proxy_url)
            .map_err(|e| VaneError::Generic(format!("Invalid proxyUrl {proxy_url}: {e}")))?;
        if url.scheme() != "https" {
            return Err(VaneError::Generic(
                "HTTP/3 proxyUrl must use https:// for MASQUE/CONNECT-UDP".to_string(),
            ));
        }
        let host = url
            .host_str()
            .ok_or_else(|| VaneError::Generic("proxyUrl is missing host".to_string()))?
            .to_string();
        let port = url.port_or_known_default().unwrap_or(443);
        let authority = match url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.clone(),
        };
        Ok(Self {
            host,
            port,
            authority,
        })
    }
}

fn connect_quic_h3(
    host: &str,
    peer_addr: SocketAddr,
    timeout: Duration,
    certificate_pins: &HashMap<String, Vec<String>>,
) -> Result<DirectHttp3Connection, VaneError> {
    let bind_addr = match peer_addr {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };

    let socket = UdpSocket::bind(bind_addr)
        .map_err(|e| VaneError::Generic(format!("Failed to bind UDP socket: {e}")))?;
    socket.connect(peer_addr).map_err(|e| {
        VaneError::Generic(format!("Failed to connect UDP socket to {peer_addr}: {e}"))
    })?;
    let local_addr = socket
        .local_addr()
        .map_err(|e| VaneError::Generic(format!("Failed to read UDP local address: {e}")))?;
    socket
        .set_read_timeout(Some(Duration::from_millis(10)))
        .map_err(|e| VaneError::Generic(format!("Failed to set UDP read timeout: {e}")))?;
    socket
        .set_write_timeout(Some(timeout))
        .map_err(|e| VaneError::Generic(format!("Failed to set UDP write timeout: {e}")))?;

    let mut quic_config = create_quiche_config(timeout)?;
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    getrandom::fill(&mut scid)
        .map_err(|e| VaneError::Generic(format!("Failed to generate QUIC connection ID: {e}")))?;
    let scid = quiche::ConnectionId::from_ref(&scid);
    let mut conn = quiche::connect(Some(host), &scid, local_addr, peer_addr, &mut quic_config)
        .map_err(|e| VaneError::Generic(format!("Failed to create QUIC client: {e}")))?;
    let mut h3_config = quiche::h3::Config::new()
        .map_err(|e| VaneError::Generic(format!("Failed to create HTTP/3 config: {e}")))?;
    h3_config.enable_extended_connect(true);

    flush_quic_packets(&socket, &mut conn)?;
    let deadline = Instant::now() + timeout;

    while Instant::now() < deadline {
        read_quic_packets(&socket, &mut conn, local_addr, peer_addr)?;

        if conn.is_established() {
            verify_certificate_pins(host, conn.peer_cert(), certificate_pins)?;
            let http3 = quiche::h3::Connection::with_transport(&mut conn, &h3_config)?;
            return Ok(DirectHttp3Connection {
                socket,
                local_addr,
                peer_addr,
                conn,
                http3,
            });
        }

        flush_quic_packets(&socket, &mut conn)?;

        if conn.is_closed() {
            return Err(VaneError::Generic(
                "QUIC connection closed before handshake completed".to_string(),
            ));
        }
    }

    Err(VaneError::Generic("HTTP/3 handshake timed out".to_string()))
}

fn establish_connect_udp_tunnel(
    transport: &mut DirectHttp3Connection,
    proxy: &MasqueProxyConfig,
    target_host: &str,
    target_port: u16,
    proxy_authorization: Option<&str>,
    timeout: Duration,
) -> Result<u64, VaneError> {
    let target_path = format!(
        "/.well-known/masque/udp/{}/{}/",
        masque_path_component(target_host),
        target_port
    );
    let mut headers = vec![
        quiche::h3::Header::new(b":method", b"CONNECT"),
        quiche::h3::Header::new(b":protocol", b"connect-udp"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", proxy.authority.as_bytes()),
        quiche::h3::Header::new(b":path", target_path.as_bytes()),
    ];
    if let Some(value) = proxy_authorization.filter(|value| !value.is_empty()) {
        headers.push(quiche::h3::Header::new(
            b"proxy-authorization",
            value.as_bytes(),
        ));
    }

    let stream_id = transport
        .http3
        .send_request(&mut transport.conn, &headers, true)?;
    flush_quic_packets(&transport.socket, &mut transport.conn)?;

    let deadline = Instant::now() + timeout;
    let mut tunnel_accepted = false;
    while Instant::now() < deadline {
        read_quic_packets(
            &transport.socket,
            &mut transport.conn,
            transport.local_addr,
            transport.peer_addr,
        )?;
        process_connect_udp_events(
            &mut transport.http3,
            &mut transport.conn,
            stream_id,
            &mut tunnel_accepted,
        )?;

        if tunnel_accepted {
            if !transport.http3.extended_connect_enabled_by_peer() {
                return Err(VaneError::Generic(
                    "MASQUE proxy did not advertise Extended CONNECT support".to_string(),
                ));
            }
            if !transport.http3.dgram_enabled_by_peer(&transport.conn) {
                return Err(VaneError::Generic(
                    "MASQUE proxy did not advertise HTTP/3 DATAGRAM support".to_string(),
                ));
            }
            return Ok(stream_id);
        }

        flush_quic_packets(&transport.socket, &mut transport.conn)?;

        if transport.conn.is_closed() {
            return Err(VaneError::Generic(
                "MASQUE proxy connection closed before CONNECT-UDP completed".to_string(),
            ));
        }
    }

    Err(VaneError::Generic(
        "MASQUE CONNECT-UDP establishment timed out".to_string(),
    ))
}

fn process_connect_udp_events(
    http3: &mut quiche::h3::Connection,
    conn: &mut quiche::Connection,
    tunnel_stream_id: u64,
    tunnel_accepted: &mut bool,
) -> Result<(), VaneError> {
    loop {
        match http3.poll(conn) {
            Ok((stream_id, quiche::h3::Event::Headers { list, .. }))
                if stream_id == tunnel_stream_id =>
            {
                let mut status = None;
                for header in list {
                    if header.name() == b":status" {
                        status = Some(String::from_utf8_lossy(header.value()).to_string());
                    }
                }
                let Some(status) = status else {
                    return Err(VaneError::Generic(
                        "MASQUE proxy CONNECT-UDP response is missing :status".to_string(),
                    ));
                };
                if status.starts_with('2') {
                    *tunnel_accepted = true;
                } else {
                    return Err(VaneError::Generic(format!(
                        "MASQUE proxy rejected CONNECT-UDP with status {status}"
                    )));
                }
            }
            Ok((stream_id, quiche::h3::Event::Data)) => {
                let mut buf = [0; 4096];
                loop {
                    match http3.recv_body(conn, stream_id, &mut buf) {
                        Ok(_) => {}
                        Err(quiche::h3::Error::Done) => break,
                        Err(e) => return Err(e.into()),
                    }
                }
            }
            Ok((stream_id, quiche::h3::Event::Finished))
                if stream_id == tunnel_stream_id && !*tunnel_accepted =>
            {
                return Err(VaneError::Generic(
                    "MASQUE proxy closed CONNECT-UDP before accepting it".to_string(),
                ));
            }
            Ok((stream_id, quiche::h3::Event::Reset(e))) if stream_id == tunnel_stream_id => {
                return Err(VaneError::Generic(format!(
                    "MASQUE proxy reset CONNECT-UDP stream: {e:?}"
                )));
            }
            Ok((_stream_id, quiche::h3::Event::Headers { .. }))
            | Ok((_stream_id, quiche::h3::Event::Finished))
            | Ok((_stream_id, quiche::h3::Event::Reset(_)))
            | Ok((_stream_id, quiche::h3::Event::PriorityUpdate)) => {}
            Ok((_id, quiche::h3::Event::GoAway)) => {
                return Err(VaneError::Generic(
                    "MASQUE proxy sent HTTP/3 GOAWAY".to_string(),
                ));
            }
            Err(quiche::h3::Error::Done) => break,
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}

fn process_masque_control_events(
    http3: &mut quiche::h3::Connection,
    conn: &mut quiche::Connection,
    tunnel_stream_id: u64,
) -> Result<(), VaneError> {
    let mut accepted = true;
    process_connect_udp_events(http3, conn, tunnel_stream_id, &mut accepted)
}

fn read_quic_packets_via(
    io: &mut Http3Io,
    conn: &mut quiche::Connection,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
) -> Result<(), VaneError> {
    match io {
        Http3Io::Direct { socket } => read_quic_packets(socket, conn, local_addr, peer_addr),
        Http3Io::Masque(tunnel) => tunnel.read_origin_packets(conn, local_addr, peer_addr),
    }
}

fn flush_quic_packets_via(
    io: &mut Http3Io,
    conn: &mut quiche::Connection,
) -> Result<(), VaneError> {
    let mut out = [0; MAX_DATAGRAM_SIZE];
    loop {
        match conn.send(&mut out) {
            Ok((written, send_info)) => {
                let _ = send_info;
                match io {
                    Http3Io::Direct { socket } => {
                        socket.send(&out[..written]).map_err(|e| {
                            VaneError::Generic(format!("Failed to send UDP packet: {e}"))
                        })?;
                    }
                    Http3Io::Masque(tunnel) => {
                        tunnel.send_origin_packet(&out[..written])?;
                    }
                }
            }
            Err(quiche::Error::Done) => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

fn encode_h3_datagram(flow_id: u64, context_id: u64, payload: &[u8]) -> Result<Vec<u8>, VaneError> {
    let mut out = Vec::with_capacity(varint_len(flow_id) + varint_len(context_id) + payload.len());
    put_varint(flow_id, &mut out)?;
    put_varint(context_id, &mut out)?;
    out.extend_from_slice(payload);
    Ok(out)
}

fn decode_h3_datagram(buf: &[u8]) -> Result<Option<(u64, u64, usize)>, VaneError> {
    let Some((flow_id, offset)) = get_varint(buf, 0)? else {
        return Ok(None);
    };
    let Some((context_id, offset)) = get_varint(buf, offset)? else {
        return Ok(None);
    };
    Ok(Some((flow_id, context_id, offset)))
}

fn varint_len(value: u64) -> usize {
    match value {
        0..=0x3f => 1,
        0x40..=0x3fff => 2,
        0x4000..=0x3fff_ffff => 4,
        _ => 8,
    }
}

fn put_varint(value: u64, out: &mut Vec<u8>) -> Result<(), VaneError> {
    match value {
        0..=0x3f => out.push(value as u8),
        0x40..=0x3fff => {
            out.push(((value >> 8) as u8) | 0x40);
            out.push(value as u8);
        }
        0x4000..=0x3fff_ffff => {
            out.push(((value >> 24) as u8) | 0x80);
            out.push((value >> 16) as u8);
            out.push((value >> 8) as u8);
            out.push(value as u8);
        }
        0x4000_0000..=0x3fff_ffff_ffff_ffff => {
            out.push(((value >> 56) as u8) | 0xc0);
            out.push((value >> 48) as u8);
            out.push((value >> 40) as u8);
            out.push((value >> 32) as u8);
            out.push((value >> 24) as u8);
            out.push((value >> 16) as u8);
            out.push((value >> 8) as u8);
            out.push(value as u8);
        }
        _ => {
            return Err(VaneError::Generic(format!(
                "HTTP/3 datagram varint is too large: {value}"
            )));
        }
    }
    Ok(())
}

fn get_varint(buf: &[u8], offset: usize) -> Result<Option<(u64, usize)>, VaneError> {
    let Some(first) = buf.get(offset).copied() else {
        return Ok(None);
    };
    let len = match first >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    if buf.len() < offset + len {
        return Ok(None);
    }
    let mut value = (first & 0x3f) as u64;
    for byte in &buf[offset + 1..offset + len] {
        value = (value << 8) | u64::from(*byte);
    }
    Ok(Some((value, offset + len)))
}

fn masque_path_component(value: &str) -> String {
    let mut out = String::new();
    for byte in value.as_bytes() {
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(*byte as char)
            }
            byte => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

struct H3RequestOptions<'a> {
    headers: &'a [quiche::h3::Header],
    request_body: &'a [u8],
    timeout: Duration,
    url: &'a Url,
    max_response_body_bytes: u64,
    response_body_path: Option<&'a str>,
    cancel_token_id: Option<u64>,
    progress_id: Option<u64>,
}

fn perform_http3_request(
    transport: &mut PooledHttp3Connection,
    options: H3RequestOptions<'_>,
) -> Result<Http3ResponseParts, VaneError> {
    let mut request_stream_id = None;
    let mut body_offset = 0usize;
    let deadline = Instant::now() + options.timeout;
    let mut response =
        H3ResponseState::new(options.max_response_body_bytes, options.response_body_path)?;

    while Instant::now() < deadline {
        check_cancelled(options.cancel_token_id)?;
        transport.read_packets()?;

        if request_stream_id.is_none() {
            let fin = options.request_body.is_empty();
            request_stream_id = Some(transport.http3.send_request(
                &mut transport.conn,
                options.headers,
                fin,
            )?);
        }

        if let Some(stream_id) = request_stream_id {
            while body_offset < options.request_body.len() {
                match transport.http3.send_body(
                    &mut transport.conn,
                    stream_id,
                    &options.request_body[body_offset..],
                    true,
                ) {
                    Ok(written) => {
                        body_offset += written;
                        progress_upload(
                            options.progress_id,
                            body_offset as u64,
                            options.request_body.len() as u64,
                        );
                    }
                    Err(quiche::h3::Error::Done) => break,
                    Err(e) => return Err(e.into()),
                }
            }
        }

        process_h3_events(
            &mut transport.http3,
            &mut transport.conn,
            &mut response,
            options.cancel_token_id,
            options.progress_id,
        )?;

        if response.finished {
            transport.flush_packets()?;
            break;
        }

        transport.flush_packets()?;

        if transport.conn.is_closed() && !response.finished {
            return Err(VaneError::Generic(
                "QUIC connection closed before response completed".to_string(),
            ));
        }
    }

    if !response.finished {
        return Err(VaneError::Generic("HTTP/3 request timed out".to_string()));
    }

    Ok(Http3ResponseParts {
        status_code: response.status_code,
        headers: response.headers,
        set_cookie_headers: response.set_cookie_headers,
        body: response.body,
        body_file_path: response.body_file_path,
        url: options.url.to_string(),
    })
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
    config.enable_dgram(true, 1024, 1024);
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
            config.load_verify_locations_from_file(path).map_err(|e| {
                VaneError::Generic(format!("Failed to load CA bundle from {path}: {e}"))
            })?;
            return Ok(());
        }
    }

    let cert_dirs = ["/etc/ssl/certs", "/system/etc/security/cacerts"];
    for path in cert_dirs {
        if std::path::Path::new(path).exists() {
            config
                .load_verify_locations_from_directory(path)
                .map_err(|e| {
                    VaneError::Generic(format!("Failed to load CA directory from {path}: {e}"))
                })?;
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

    for (key, value) in query_params {
        url.append_query_pair(key, value);
    }
}

fn resolve_peer_addr(
    host: &str,
    port: u16,
    dns_overrides: &HashMap<String, String>,
) -> Result<SocketAddr, VaneError> {
    if let Some(override_addr) = dns_overrides.get(host) {
        let ip = override_addr.parse::<IpAddr>().map_err(|e| {
            VaneError::Generic(format!(
                "Invalid DNS override for {host}: expected IP address, got {override_addr}: {e}"
            ))
        })?;
        return Ok(SocketAddr::new(ip, port));
    }

    (host, port)
        .to_socket_addrs()
        .map_err(|e| VaneError::Generic(format!("Failed to resolve {host}:{port}: {e}")))?
        .next()
        .ok_or_else(|| VaneError::Generic(format!("Failed to resolve {host}:{port}")))
}

fn verify_certificate_pins(
    host: &str,
    peer_cert_der: Option<&[u8]>,
    certificate_pins: &HashMap<String, Vec<String>>,
) -> Result<(), VaneError> {
    let Some(pins) = certificate_pins.get(host) else {
        return Ok(());
    };

    if pins.is_empty() {
        return Ok(());
    }

    let cert_der = peer_cert_der.ok_or_else(|| {
        VaneError::Generic(format!(
            "Certificate pinning configured for {host}, but peer certificate was unavailable"
        ))
    })?;

    let presented_pins = certificate_pin_values(cert_der);
    if pins.iter().any(|configured| {
        presented_pins
            .iter()
            .any(|presented| presented == configured)
    }) {
        return Ok(());
    }

    Err(VaneError::Generic(format!(
        "Certificate pin mismatch for {host}"
    )))
}

fn validate_certificate_pin_host(host: &str) -> Result<(), VaneError> {
    if host.is_empty() {
        return Err(VaneError::Generic(
            "Certificate pin host must not be empty".to_string(),
        ));
    }
    if host.contains("://") || host.contains('/') {
        return Err(VaneError::Generic(
            "Certificate pin host must be a hostname without scheme or path".to_string(),
        ));
    }
    if !host.is_ascii() {
        return Err(VaneError::Generic(
            "Certificate pin host must be ASCII; use punycode for IDN hosts".to_string(),
        ));
    }
    Ok(())
}

fn validate_certificate_pins(pins: &[String]) -> Result<(), VaneError> {
    for pin in pins {
        if !(pin.starts_with("sha256/") || pin.starts_with("sha256-cert/")) {
            return Err(VaneError::Generic(format!(
                "Unsupported certificate pin format: {pin}"
            )));
        }
    }
    Ok(())
}

fn certificate_pin_values(cert_der: &[u8]) -> Vec<String> {
    let cert_sha256 = sha256_pin("sha256-cert", cert_der);
    #[cfg(not(feature = "spki-pinning"))]
    {
        vec![cert_sha256]
    }

    #[cfg(feature = "spki-pinning")]
    {
        let spki_sha256 = spki_sha256_pin(cert_der);

        match spki_sha256 {
            Ok(pin) => vec![pin, cert_sha256],
            Err(_) => vec![cert_sha256],
        }
    }
}

#[cfg(feature = "spki-pinning")]
fn spki_sha256_pin(cert_der: &[u8]) -> Result<String, VaneError> {
    let cert = X509::from_der(cert_der)
        .map_err(|e| VaneError::Generic(format!("Failed to parse peer certificate: {e}")))?;
    let public_key = cert
        .public_key()
        .map_err(|e| VaneError::Generic(format!("Failed to read peer public key: {e}")))?;
    let spki_der = public_key
        .public_key_to_der()
        .map_err(|e| VaneError::Generic(format!("Failed to encode peer public key SPKI: {e}")))?;

    Ok(sha256_pin("sha256", &spki_der))
}

fn sha256_pin(prefix: &str, bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("{prefix}/{}", BASE64.encode(digest))
}

fn default_cookie_path(url: &Url) -> String {
    let path = url.path();
    if path.is_empty() || !path.starts_with('/') {
        return "/".to_string();
    }
    let Some(last_slash) = path.rfind('/') else {
        return "/".to_string();
    };
    if last_slash == 0 {
        "/".to_string()
    } else {
        path[..last_slash].to_string()
    }
}

fn domain_matches(host: &str, domain: &str) -> bool {
    host == domain
        || host
            .strip_suffix(domain)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn path_matches(request_path: &str, cookie_path: &str) -> bool {
    if request_path == cookie_path {
        return true;
    }
    if !request_path.starts_with(cookie_path) {
        return false;
    }
    cookie_path.ends_with('/')
        || request_path
            .as_bytes()
            .get(cookie_path.len())
            .is_some_and(|b| *b == b'/')
}

fn validate_request_body_limit(body: &[u8], max_request_body_bytes: u64) -> Result<(), VaneError> {
    if body.len() as u64 > max_request_body_bytes {
        return Err(VaneError::Generic(format!(
            "HTTP/3 request body exceeded {max_request_body_bytes} bytes"
        )));
    }

    Ok(())
}

fn load_request_body(request: &VaneRequest) -> Result<Vec<u8>, VaneError> {
    if let Some(path) = &request.body_file_path
        && !path.is_empty()
    {
        let mut file = File::open(path).map_err(|e| {
            VaneError::Generic(format!("Failed to open request body file {path}: {e}"))
        })?;
        let mut body = Vec::new();
        file.read_to_end(&mut body).map_err(|e| {
            VaneError::Generic(format!("Failed to read request body file {path}: {e}"))
        })?;
        return Ok(body);
    }
    Ok(request.body.clone().unwrap_or_default())
}

fn validate_response_body_limit(
    current_len: usize,
    read_len: usize,
    max_response_body_bytes: u64,
) -> Result<(), VaneError> {
    if current_len as u64 + read_len as u64 > max_response_body_bytes {
        return Err(VaneError::Generic(format!(
            "HTTP/3 response body exceeded {max_response_body_bytes} bytes"
        )));
    }

    Ok(())
}

fn check_cancelled(cancel_token_id: Option<u64>) -> Result<(), VaneError> {
    let Some(id) = cancel_token_id else {
        return Ok(());
    };
    let cancelled = CANCEL_TOKENS
        .lock()
        .ok()
        .and_then(|tokens| tokens.get(&id).cloned())
        .is_some_and(|token| token.load(Ordering::Relaxed));
    if cancelled {
        Err(VaneError::Generic("Vane request was cancelled".to_string()))
    } else {
        Ok(())
    }
}

fn progress_init(progress_id: Option<u64>, upload_total: u64) {
    let Some(id) = progress_id else {
        return;
    };
    if let Ok(mut states) = PROGRESS_STATES.lock() {
        states.insert(
            id,
            VaneProgressState {
                upload_total,
                ..VaneProgressState::default()
            },
        );
    }
}

fn progress_upload(progress_id: Option<u64>, sent: u64, total: u64) {
    let Some(id) = progress_id else {
        return;
    };
    if let Ok(mut states) = PROGRESS_STATES.lock() {
        let state = states.entry(id).or_default();
        state.upload_sent = sent;
        state.upload_total = total;
    }
}

fn progress_download(progress_id: Option<u64>, received: u64, total: u64) {
    let Some(id) = progress_id else {
        return;
    };
    if let Ok(mut states) = PROGRESS_STATES.lock() {
        let state = states.entry(id).or_default();
        state.download_received = received;
        state.download_total = total;
    }
}

fn progress_done(progress_id: Option<u64>) {
    let Some(id) = progress_id else {
        return;
    };
    if let Ok(mut states) = PROGRESS_STATES.lock() {
        states.entry(id).or_default().done = true;
    }
}

fn progress_create() -> u64 {
    let id = NEXT_PROGRESS_ID.fetch_add(1, Ordering::Relaxed);
    if let Ok(mut states) = PROGRESS_STATES.lock() {
        states.insert(id, VaneProgressState::default());
    }
    id
}

fn progress_snapshot(id: u64) -> VaneProgressSnapshot {
    let state = PROGRESS_STATES
        .lock()
        .ok()
        .and_then(|states| states.get(&id).cloned())
        .unwrap_or_default();
    VaneProgressSnapshot {
        upload_sent: state.upload_sent,
        upload_total: state.upload_total,
        download_received: state.download_received,
        download_total: state.download_total,
        done: state.done,
    }
}

fn progress_free(id: u64) {
    if let Ok(mut states) = PROGRESS_STATES.lock() {
        states.remove(&id);
    }
}

fn should_retry_response(
    method: &str,
    status_code: u16,
    attempt: u64,
    config: &VaneClientConfig,
) -> bool {
    attempt < config.retry_max_attempts.max(1)
        && is_retryable_method(method, config.retry_unsafe_methods)
        && matches!(status_code, 408 | 425 | 429 | 500 | 502 | 503 | 504)
}

fn should_retry_error(method: &str, attempt: u64, config: &VaneClientConfig) -> bool {
    attempt < config.retry_max_attempts.max(1)
        && is_retryable_method(method, config.retry_unsafe_methods)
}

fn is_retryable_method(method: &str, retry_unsafe_methods: bool) -> bool {
    match method.to_ascii_uppercase().as_str() {
        "GET" | "HEAD" | "OPTIONS" | "PUT" | "DELETE" => true,
        "POST" | "PATCH" => retry_unsafe_methods,
        _ => false,
    }
}

fn retry_delay(attempt: u64, config: &VaneClientConfig) -> Duration {
    let initial = config.retry_initial_delay_millis;
    let max = config.retry_max_delay_millis.max(initial);
    let multiplier_shift = attempt.saturating_sub(1).min(20);
    let multiplier = 1u64 << multiplier_shift;
    let delay_millis = initial.saturating_mul(multiplier).min(max);
    Duration::from_millis(delay_millis)
}

fn sleep_before_retry(attempt: u64, config: &VaneClientConfig) {
    let delay = retry_delay(attempt, config);
    if !delay.is_zero() {
        thread::sleep(delay);
    }
}

fn build_h3_headers(
    url: &Url,
    request: &VaneRequest,
    config: &VaneClientConfig,
    cookie_header: Option<&str>,
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
    if let Some(cookie_header) = cookie_header.filter(|header| !header.is_empty()) {
        push_regular_header(&mut headers, "cookie", cookie_header)?;
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
    peer_addr: SocketAddr,
) -> Result<(), VaneError> {
    let timeout = conn.timeout().unwrap_or(Duration::from_millis(10));
    socket
        .set_read_timeout(Some(timeout.min(Duration::from_millis(50))))
        .map_err(|e| VaneError::Generic(format!("Failed to set UDP read timeout: {e}")))?;

    let mut buf = [0; 65535];
    loop {
        match socket.recv(&mut buf) {
            Ok(len) => {
                let recv_info = quiche::RecvInfo {
                    from: peer_addr,
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
            Err(e) => {
                return Err(VaneError::Generic(format!(
                    "Failed to receive UDP packet: {e}"
                )));
            }
        }
    }

    Ok(())
}

fn flush_quic_packets(socket: &UdpSocket, conn: &mut quiche::Connection) -> Result<(), VaneError> {
    let mut out = [0; MAX_DATAGRAM_SIZE];
    loop {
        match conn.send(&mut out) {
            Ok((written, send_info)) => {
                let _ = send_info;
                socket
                    .send(&out[..written])
                    .map_err(|e| VaneError::Generic(format!("Failed to send UDP packet: {e}")))?;
            }
            Err(quiche::Error::Done) => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

struct H3ResponseState {
    status_code: u16,
    headers: HashMap<String, String>,
    set_cookie_headers: Vec<String>,
    body: Vec<u8>,
    body_file_path: Option<String>,
    body_file: Option<File>,
    finished: bool,
    max_body_bytes: u64,
    body_len: usize,
}

impl H3ResponseState {
    fn new(max_body_bytes: u64, body_file_path: Option<&str>) -> Result<Self, VaneError> {
        let body_file = match body_file_path {
            Some(path) if !path.is_empty() => Some(File::create(path).map_err(|e| {
                VaneError::Generic(format!("Failed to create response body file {path}: {e}"))
            })?),
            _ => None,
        };
        Ok(Self {
            status_code: 0,
            headers: HashMap::new(),
            set_cookie_headers: Vec::new(),
            body: Vec::new(),
            body_file_path: body_file_path
                .filter(|path| !path.is_empty())
                .map(ToString::to_string),
            body_file,
            finished: false,
            max_body_bytes,
            body_len: 0,
        })
    }

    fn push_body(&mut self, bytes: &[u8]) -> Result<(), VaneError> {
        validate_response_body_limit(self.body_len, bytes.len(), self.max_body_bytes)?;
        self.body_len += bytes.len();
        if let Some(file) = &mut self.body_file {
            file.write_all(bytes)
                .map_err(|e| VaneError::Generic(format!("Failed to write response body: {e}")))?;
        } else {
            self.body.extend_from_slice(bytes);
        }
        Ok(())
    }
}

fn process_h3_events(
    http3: &mut quiche::h3::Connection,
    conn: &mut quiche::Connection,
    response: &mut H3ResponseState,
    cancel_token_id: Option<u64>,
    progress_id: Option<u64>,
) -> Result<(), VaneError> {
    let mut buf = [0; 16 * 1024];

    loop {
        match http3.poll(conn) {
            Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                for header in list {
                    let name = String::from_utf8_lossy(header.name()).to_string();
                    let value = String::from_utf8_lossy(header.value()).to_string();
                    if name == ":status" {
                        response.status_code = value.parse::<u16>().unwrap_or_default();
                    } else if name.eq_ignore_ascii_case("set-cookie") {
                        response.set_cookie_headers.push(value);
                    } else {
                        response.headers.insert(name, value);
                    }
                }
                let _ = stream_id;
            }
            Ok((stream_id, quiche::h3::Event::Data)) => loop {
                check_cancelled(cancel_token_id)?;
                match http3.recv_body(conn, stream_id, &mut buf) {
                    Ok(read) => {
                        response.push_body(&buf[..read])?;
                        progress_download(progress_id, response.body_len as u64, 0);
                    }
                    Err(quiche::h3::Error::Done) => break,
                    Err(e) => return Err(e.into()),
                }
            },
            Ok((_stream_id, quiche::h3::Event::Finished)) => {
                response.finished = true;
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
pub fn create_progress() -> u64 {
    progress_create()
}

#[uniffi::export]
pub fn progress_snapshot_by_id(id: u64) -> VaneProgressSnapshot {
    progress_snapshot(id)
}

#[uniffi::export]
pub fn free_progress(id: u64) {
    progress_free(id);
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

    pub fn set_certificate_pins(&self, host: String, pins: Vec<String>) -> Result<(), VaneError> {
        self.set_certificate_pins_internal(host, pins)
    }

    pub fn add_certificate_pin(&self, host: String, pin: String) -> Result<(), VaneError> {
        self.add_certificate_pin_internal(host, pin)
    }

    pub fn clear_certificate_pins(&self, host: String) -> Result<(), VaneError> {
        self.set_certificate_pins_internal(host, Vec::new())
    }
}

// ---------- Helpers ----------
#[uniffi::export]
pub fn response_body_utf8(resp: &VaneResponse) -> Result<String, VaneError> {
    String::from_utf8(resp.body.clone())
        .map_err(|e| VaneError::Generic(format!("Invalid UTF-8 in response body: {e}")))
}

// ---------- Stable C ABI for Dart FFI ----------
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VaneFfiString {
    pub data: *const u8,
    pub len: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct VaneFfiStringPair {
    pub key: VaneFfiString,
    pub value: VaneFfiString,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct VaneFfiStringList {
    pub values: *const VaneFfiString,
    pub len: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct VaneFfiStringListPair {
    pub key: VaneFfiString,
    pub values: VaneFfiStringList,
}

#[repr(C)]
pub struct VaneFfiClientConfig {
    pub base_url: VaneFfiString,
    pub default_headers: *const VaneFfiStringPair,
    pub default_headers_len: usize,
    pub dns_overrides: *const VaneFfiStringPair,
    pub dns_overrides_len: usize,
    pub certificate_pins: *const VaneFfiStringListPair,
    pub certificate_pins_len: usize,
    pub cookies_enabled: bool,
    pub cookie_persistence_path: VaneFfiString,
    pub connection_pool_enabled: bool,
    pub max_idle_connections: u64,
    pub connection_idle_timeout_seconds: u64,
    pub retry_max_attempts: u64,
    pub retry_initial_delay_millis: u64,
    pub retry_max_delay_millis: u64,
    pub retry_unsafe_methods: bool,
    pub max_request_body_bytes: u64,
    pub max_response_body_bytes: u64,
    pub timeout_seconds: i64,
    pub follow_redirects: bool,
    pub user_agent: VaneFfiString,
    pub protocol_mode: u8,
    pub proxy_url: VaneFfiString,
    pub proxy_authorization: VaneFfiString,
}

#[repr(C)]
pub struct VaneFfiRequest {
    pub url: VaneFfiString,
    pub method: VaneFfiString,
    pub headers: *const VaneFfiStringPair,
    pub headers_len: usize,
    pub query_params: *const VaneFfiStringPair,
    pub query_params_len: usize,
    pub body_file_path: VaneFfiString,
    pub response_body_path: VaneFfiString,
    pub cancel_token_id: u64,
    pub progress_id: u64,
    pub timeout_seconds: i64,
    pub follow_redirects: bool,
}

#[repr(C)]
pub struct VaneFfiBuffer {
    pub data: *mut u8,
    pub len: usize,
    pub cap: usize,
}

#[repr(C)]
pub struct VaneFfiHeader {
    pub key: VaneFfiBuffer,
    pub value: VaneFfiBuffer,
}

#[repr(C)]
pub struct VaneFfiHeaderArray {
    pub data: *mut VaneFfiHeader,
    pub len: usize,
    pub cap: usize,
}

#[repr(C)]
pub struct VaneFfiResponse {
    pub status_code: u16,
    pub is_success: bool,
    pub headers: VaneFfiHeaderArray,
    pub body: VaneFfiBuffer,
    pub body_file_path: VaneFfiBuffer,
    pub url: VaneFfiBuffer,
    pub error: VaneFfiBuffer,
}

#[repr(C)]
pub struct VaneFfiProgress {
    pub upload_sent: u64,
    pub upload_total: u64,
    pub download_received: u64,
    pub download_total: u64,
    pub done: bool,
}

static FFI_CLIENTS: LazyLock<Mutex<HashMap<u64, Arc<VaneClient>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static FFI_NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

#[unsafe(no_mangle)]
pub extern "C" fn vane_ffi_client_create(
    config: *const VaneFfiClientConfig,
    out_error: *mut VaneFfiBuffer,
) -> u64 {
    ffi_clear_error(out_error);
    match std::panic::catch_unwind(|| ffi_create_client(config)) {
        Ok(Ok(handle)) => handle,
        Ok(Err(error)) => {
            ffi_set_error(out_error, error);
            0
        }
        Err(_) => {
            ffi_set_error(
                out_error,
                "Rust panic while creating Vane client".to_string(),
            );
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn vane_ffi_client_close(handle: u64) {
    if handle == 0 {
        return;
    }
    if let Ok(mut clients) = FFI_CLIENTS.lock() {
        clients.remove(&handle);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn vane_ffi_client_set_certificate_pins(
    handle: u64,
    host: VaneFfiString,
    pins: VaneFfiStringList,
    out_error: *mut VaneFfiBuffer,
) -> bool {
    ffi_clear_error(out_error);
    match std::panic::catch_unwind(|| ffi_set_certificate_pins(handle, host, pins)) {
        Ok(Ok(())) => true,
        Ok(Err(error)) => {
            ffi_set_error(out_error, error);
            false
        }
        Err(_) => {
            ffi_set_error(
                out_error,
                "Rust panic while setting certificate pins".to_string(),
            );
            false
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn vane_ffi_cancel_token_create() -> u64 {
    let id = NEXT_CANCEL_TOKEN_ID.fetch_add(1, Ordering::Relaxed);
    if let Ok(mut tokens) = CANCEL_TOKENS.lock() {
        tokens.insert(id, Arc::new(AtomicBool::new(false)));
    }
    id
}

#[unsafe(no_mangle)]
pub extern "C" fn vane_ffi_cancel_token_cancel(id: u64) {
    if let Ok(tokens) = CANCEL_TOKENS.lock()
        && let Some(token) = tokens.get(&id)
    {
        token.store(true, Ordering::Relaxed);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn vane_ffi_cancel_token_free(id: u64) {
    if let Ok(mut tokens) = CANCEL_TOKENS.lock() {
        tokens.remove(&id);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn vane_ffi_progress_create() -> u64 {
    progress_create()
}

#[unsafe(no_mangle)]
pub extern "C" fn vane_ffi_progress_snapshot(id: u64) -> VaneFfiProgress {
    let state = progress_snapshot(id);
    VaneFfiProgress {
        upload_sent: state.upload_sent,
        upload_total: state.upload_total,
        download_received: state.download_received,
        download_total: state.download_total,
        done: state.done,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn vane_ffi_progress_free(id: u64) {
    progress_free(id);
}

#[unsafe(no_mangle)]
pub extern "C" fn vane_ffi_execute(
    handle: u64,
    request: *const VaneFfiRequest,
    body_data: *const u8,
    body_len: usize,
) -> *mut VaneFfiResponse {
    let result = std::panic::catch_unwind(|| ffi_execute(handle, request, body_data, body_len));
    let response = match result {
        Ok(Ok(response)) => ffi_response_from_vane(response),
        Ok(Err(error)) => ffi_error_response(error),
        Err(_) => ffi_error_response("Rust panic while executing Vane request".to_string()),
    };
    Box::into_raw(Box::new(response))
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `response` must be a pointer previously returned by `vane_ffi_execute`.
/// It must be passed to this function at most once.
pub unsafe extern "C" fn vane_ffi_response_free(response: *mut VaneFfiResponse) {
    if response.is_null() {
        return;
    }
    unsafe {
        let response = Box::from_raw(response);
        ffi_header_array_free(response.headers);
        ffi_buffer_free(response.body);
        ffi_buffer_free(response.body_file_path);
        ffi_buffer_free(response.url);
        ffi_buffer_free(response.error);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn vane_ffi_buffer_free(buffer: VaneFfiBuffer) {
    ffi_buffer_free(buffer);
}

fn ffi_create_client(config: *const VaneFfiClientConfig) -> Result<u64, String> {
    let config = ffi_config(config)?;
    let client = Arc::new(VaneClient::new(config).map_err(|error| error.to_string())?);
    let handle = FFI_NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    FFI_CLIENTS
        .lock()
        .map_err(|_| "Vane FFI client registry lock was poisoned".to_string())?
        .insert(handle, client);
    Ok(handle)
}

fn ffi_execute(
    handle: u64,
    request: *const VaneFfiRequest,
    body_data: *const u8,
    body_len: usize,
) -> Result<VaneResponse, String> {
    let client = {
        let clients = FFI_CLIENTS
            .lock()
            .map_err(|_| "Vane FFI client registry lock was poisoned".to_string())?;
        clients
            .get(&handle)
            .cloned()
            .ok_or_else(|| format!("No Vane client exists for handle {handle}"))?
    };
    let mut request = ffi_request(request)?;
    if body_len > 0 {
        request.body = Some(ffi_bytes(body_data, body_len)?.to_vec());
    } else {
        request.body = None;
    }
    client.execute(request).map_err(|error| error.to_string())
}

fn ffi_set_certificate_pins(
    handle: u64,
    host: VaneFfiString,
    pins: VaneFfiStringList,
) -> Result<(), String> {
    let client = {
        let clients = FFI_CLIENTS
            .lock()
            .map_err(|_| "Vane FFI client registry lock was poisoned".to_string())?;
        clients
            .get(&handle)
            .cloned()
            .ok_or_else(|| format!("No Vane client exists for handle {handle}"))?
    };
    let host = ffi_required_string(host, "certificate_pin_host")?;
    let pins = ffi_string_list(pins, "certificate_pins")?;
    client
        .set_certificate_pins(host, pins)
        .map_err(|error| error.to_string())
}

fn ffi_response_from_vane(response: VaneResponse) -> VaneFfiResponse {
    VaneFfiResponse {
        status_code: response.status_code,
        is_success: response.is_success,
        headers: ffi_header_array_from_map(response.headers),
        body: ffi_buffer_from_vec(response.body),
        body_file_path: ffi_buffer_from_vec(
            response.body_file_path.unwrap_or_default().into_bytes(),
        ),
        url: ffi_buffer_from_vec(response.url.into_bytes()),
        error: ffi_buffer_from_vec(Vec::new()),
    }
}

fn ffi_error_response(error: String) -> VaneFfiResponse {
    VaneFfiResponse {
        status_code: 0,
        is_success: false,
        headers: ffi_header_array_empty(),
        body: ffi_buffer_from_vec(Vec::new()),
        body_file_path: ffi_buffer_from_vec(Vec::new()),
        url: ffi_buffer_from_vec(Vec::new()),
        error: ffi_buffer_from_vec(error.into_bytes()),
    }
}

fn ffi_config(config: *const VaneFfiClientConfig) -> Result<VaneClientConfig, String> {
    if config.is_null() {
        return Ok(VaneClientConfig::default());
    }
    let config = unsafe { &*config };
    Ok(VaneClientConfig {
        base_url: ffi_optional_string(config.base_url, "base_url")?,
        default_headers: ffi_string_pair_map(
            config.default_headers,
            config.default_headers_len,
            "default_headers",
        )?,
        dns_overrides: ffi_string_pair_map(
            config.dns_overrides,
            config.dns_overrides_len,
            "dns_overrides",
        )?,
        certificate_pins: ffi_string_list_pair_map(
            config.certificate_pins,
            config.certificate_pins_len,
            "certificate_pins",
        )?,
        cookies_enabled: config.cookies_enabled,
        cookie_persistence_path: ffi_optional_string(
            config.cookie_persistence_path,
            "cookie_persistence_path",
        )?,
        connection_pool_enabled: config.connection_pool_enabled,
        max_idle_connections: config.max_idle_connections,
        connection_idle_timeout_seconds: config.connection_idle_timeout_seconds,
        retry_max_attempts: config.retry_max_attempts,
        retry_initial_delay_millis: config.retry_initial_delay_millis,
        retry_max_delay_millis: config.retry_max_delay_millis,
        retry_unsafe_methods: config.retry_unsafe_methods,
        max_request_body_bytes: config.max_request_body_bytes,
        max_response_body_bytes: config.max_response_body_bytes,
        timeout_seconds: ffi_optional_u64(config.timeout_seconds, "timeout_seconds")?,
        follow_redirects: config.follow_redirects,
        user_agent: ffi_optional_string(config.user_agent, "user_agent")?,
        protocol_mode: ffi_protocol_mode(config.protocol_mode)?,
        proxy_url: ffi_optional_string(config.proxy_url, "proxy_url")?,
        proxy_authorization: ffi_optional_string(
            config.proxy_authorization,
            "proxy_authorization",
        )?,
    })
}

fn ffi_request(request: *const VaneFfiRequest) -> Result<VaneRequest, String> {
    if request.is_null() {
        return Err("Vane FFI request pointer is null".to_string());
    }
    let request = unsafe { &*request };
    Ok(VaneRequest {
        url: ffi_required_string(request.url, "url")?,
        method: ffi_required_string(request.method, "method")?,
        headers: ffi_string_pair_map(request.headers, request.headers_len, "headers")?,
        query_params: ffi_string_pair_map(
            request.query_params,
            request.query_params_len,
            "query_params",
        )?,
        body: None,
        body_file_path: ffi_optional_string(request.body_file_path, "body_file_path")?,
        response_body_path: ffi_optional_string(request.response_body_path, "response_body_path")?,
        cancel_token_id: (request.cancel_token_id != 0).then_some(request.cancel_token_id),
        progress_id: (request.progress_id != 0).then_some(request.progress_id),
        timeout_seconds: ffi_optional_u64(request.timeout_seconds, "timeout_seconds")?,
        follow_redirects: request.follow_redirects,
    })
}

fn ffi_protocol_mode(value: u8) -> Result<VaneProtocolMode, String> {
    match value {
        0 => Ok(VaneProtocolMode::Http3ThenHttp2ThenHttp1),
        1 => Ok(VaneProtocolMode::Http3Only),
        2 => Ok(VaneProtocolMode::Http2ThenHttp1),
        3 => Ok(VaneProtocolMode::Http2Only),
        4 => Ok(VaneProtocolMode::Http1Only),
        _ => Err(format!("Invalid Vane protocol mode: {value}")),
    }
}

fn ffi_optional_u64(value: i64, field: &str) -> Result<Option<u64>, String> {
    if value < 0 {
        return Ok(None);
    }
    u64::try_from(value)
        .map(Some)
        .map_err(|_| format!("{field} is too large"))
}

fn ffi_required_string(input: VaneFfiString, field: &str) -> Result<String, String> {
    let value = ffi_string(input, field)?;
    if value.is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    Ok(value.to_string())
}

fn ffi_optional_string(input: VaneFfiString, field: &str) -> Result<Option<String>, String> {
    let value = ffi_string(input, field)?;
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value.to_string()))
    }
}

fn ffi_string(input: VaneFfiString, field: &str) -> Result<&str, String> {
    let bytes = ffi_bytes(input.data, input.len)?;
    std::str::from_utf8(bytes).map_err(|error| format!("Invalid UTF-8 in {field}: {error}"))
}

fn ffi_string_pair_map(
    pairs: *const VaneFfiStringPair,
    len: usize,
    field: &str,
) -> Result<HashMap<String, String>, String> {
    if len == 0 {
        return Ok(HashMap::new());
    }
    if pairs.is_null() {
        return Err(format!("{field} pointer is null"));
    }
    let pairs = unsafe { std::slice::from_raw_parts(pairs, len) };
    let mut map = HashMap::with_capacity(len);
    for pair in pairs {
        map.insert(
            ffi_string(pair.key, field)?.to_string(),
            ffi_string(pair.value, field)?.to_string(),
        );
    }
    Ok(map)
}

fn ffi_string_list_pair_map(
    pairs: *const VaneFfiStringListPair,
    len: usize,
    field: &str,
) -> Result<HashMap<String, Vec<String>>, String> {
    if len == 0 {
        return Ok(HashMap::new());
    }
    if pairs.is_null() {
        return Err(format!("{field} pointer is null"));
    }
    let pairs = unsafe { std::slice::from_raw_parts(pairs, len) };
    let mut map = HashMap::with_capacity(len);
    for pair in pairs {
        map.insert(
            ffi_string(pair.key, field)?.to_string(),
            ffi_string_list(pair.values, field)?,
        );
    }
    Ok(map)
}

fn ffi_string_list(list: VaneFfiStringList, field: &str) -> Result<Vec<String>, String> {
    if list.len == 0 {
        return Ok(Vec::new());
    }
    if list.values.is_null() {
        return Err(format!("{field} list pointer is null"));
    }
    let values = unsafe { std::slice::from_raw_parts(list.values, list.len) };
    values
        .iter()
        .map(|value| ffi_string(*value, field).map(ToString::to_string))
        .collect()
}

fn ffi_header_array_empty() -> VaneFfiHeaderArray {
    VaneFfiHeaderArray {
        data: ptr::null_mut(),
        len: 0,
        cap: 0,
    }
}

fn ffi_header_array_from_map(headers: HashMap<String, String>) -> VaneFfiHeaderArray {
    let mut headers: Vec<VaneFfiHeader> = headers
        .into_iter()
        .map(|(key, value)| VaneFfiHeader {
            key: ffi_buffer_from_vec(key.into_bytes()),
            value: ffi_buffer_from_vec(value.into_bytes()),
        })
        .collect();
    if headers.is_empty() {
        return ffi_header_array_empty();
    }
    let array = VaneFfiHeaderArray {
        data: headers.as_mut_ptr(),
        len: headers.len(),
        cap: headers.capacity(),
    };
    std::mem::forget(headers);
    array
}

fn ffi_header_array_free(headers: VaneFfiHeaderArray) {
    if headers.data.is_null() || headers.cap == 0 {
        return;
    }
    unsafe {
        let headers = Vec::from_raw_parts(headers.data, headers.len, headers.cap);
        for header in headers {
            ffi_buffer_free(header.key);
            ffi_buffer_free(header.value);
        }
    }
}

fn ffi_buffer_from_vec(mut bytes: Vec<u8>) -> VaneFfiBuffer {
    if bytes.is_empty() {
        return VaneFfiBuffer {
            data: ptr::null_mut(),
            len: 0,
            cap: 0,
        };
    }
    let buffer = VaneFfiBuffer {
        data: bytes.as_mut_ptr(),
        len: bytes.len(),
        cap: bytes.capacity(),
    };
    std::mem::forget(bytes);
    buffer
}

fn ffi_buffer_free(buffer: VaneFfiBuffer) {
    if buffer.data.is_null() || buffer.cap == 0 {
        return;
    }
    unsafe {
        drop(Vec::from_raw_parts(buffer.data, buffer.len, buffer.cap));
    }
}

fn ffi_clear_error(out_error: *mut VaneFfiBuffer) {
    if !out_error.is_null() {
        unsafe {
            *out_error = VaneFfiBuffer {
                data: ptr::null_mut(),
                len: 0,
                cap: 0,
            };
        }
    }
}

fn ffi_set_error(out_error: *mut VaneFfiBuffer, error: String) {
    if !out_error.is_null() {
        unsafe {
            *out_error = ffi_buffer_from_vec(error.into_bytes());
        }
    }
}

fn ffi_bytes<'a>(data: *const u8, len: usize) -> Result<&'a [u8], String> {
    if len == 0 {
        return Ok(&[]);
    }
    if data.is_null() {
        return Err("FFI data pointer is null".to_string());
    }
    Ok(unsafe { std::slice::from_raw_parts(data, len) })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(url: &str) -> VaneRequest {
        VaneRequest {
            url: url.to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
            body: None,
            body_file_path: None,
            response_body_path: None,
            cancel_token_id: None,
            progress_id: None,
            timeout_seconds: None,
            follow_redirects: true,
        }
    }

    fn live_https_base_url() -> Option<String> {
        let Ok(base_url) = std::env::var("VANE_TEST_BASE_URL") else {
            eprintln!("Skipping Vane live HTTP/3 test. Set VANE_TEST_BASE_URL.");
            return None;
        };
        if !base_url.starts_with("https://") {
            eprintln!("Skipping Vane live HTTP/3 test. VANE_TEST_BASE_URL must use https://.");
            return None;
        }

        Some(base_url.trim_end_matches('/').to_string())
    }

    fn assert_response_body_contains(response: &VaneResponse, expected: &str) {
        let body = String::from_utf8_lossy(&response.body);
        assert!(
            body.contains(expected),
            "expected response body to contain {expected:?}, got {body}"
        );
    }

    #[test]
    fn default_config_uses_http3_only() {
        let config = VaneClientConfig::default();

        assert_eq!(config.protocol_mode, VaneProtocolMode::Http3Only);
        assert_eq!(config.timeout_seconds, Some(30));
        assert!(!config.cookies_enabled);
        assert!(!config.connection_pool_enabled);
        assert_eq!(config.max_idle_connections, 4);
        assert_eq!(config.connection_idle_timeout_seconds, 30);
        assert_eq!(config.retry_max_attempts, 1);
        assert_eq!(config.retry_initial_delay_millis, 100);
        assert_eq!(config.retry_max_delay_millis, 1_000);
        assert!(!config.retry_unsafe_methods);
        assert_eq!(
            config.max_request_body_bytes,
            DEFAULT_MAX_REQUEST_BODY_BYTES
        );
        assert_eq!(
            config.max_response_body_bytes,
            DEFAULT_MAX_RESPONSE_BODY_BYTES
        );
    }

    #[test]
    fn http3_only_http_scheme_fails_before_network_io() {
        let client = VaneClient::new(VaneClientConfig {
            protocol_mode: VaneProtocolMode::Http3Only,
            ..VaneClientConfig::default()
        })
        .unwrap();

        let err = client.execute(request("http://example.com")).unwrap_err();

        assert!(err.to_string().contains("https:// URLs over HTTP/3"));
    }

    #[test]
    fn live_http3_only_get_when_base_url_is_set() {
        let Some(base_url) = live_https_base_url() else {
            return;
        };

        let client = VaneClient::new(VaneClientConfig {
            base_url: Some(base_url),
            protocol_mode: VaneProtocolMode::Http3Only,
            timeout_seconds: Some(30),
            ..VaneClientConfig::default()
        })
        .unwrap();

        let response = client
            .get_request("/get".to_string())
            .expect("HTTP/3-only GET should succeed");

        assert!(response.is_success);
    }

    #[test]
    fn live_http3_methods_headers_query_and_body_when_base_url_is_set() {
        let Some(base_url) = live_https_base_url() else {
            return;
        };

        let client = VaneClient::new(VaneClientConfig {
            base_url: Some(base_url),
            default_headers: HashMap::from([(
                "X-Vane-Default".to_string(),
                "default-live".to_string(),
            )]),
            protocol_mode: VaneProtocolMode::Http3Only,
            timeout_seconds: Some(30),
            ..VaneClientConfig::default()
        })
        .unwrap();

        let mut get = request("/get");
        get.headers
            .insert("X-Vane-Trace".to_string(), "trace-live".to_string());
        get.query_params
            .insert("vane_query".to_string(), "query-live".to_string());
        let response = client.execute(get).expect("HTTP/3 GET should succeed");
        assert!(response.is_success);
        assert_response_body_contains(&response, "trace-live");
        assert_response_body_contains(&response, "query-live");

        for (method, path) in [
            ("POST", "/post"),
            ("PUT", "/put"),
            ("PATCH", "/patch"),
            ("DELETE", "/delete"),
        ] {
            let mut req = request(path);
            req.method = method.to_string();
            req.headers
                .insert("Content-Type".to_string(), "application/json".to_string());
            req.body = Some(format!(r#"{{"method":"{method}","source":"vane-live"}}"#).into());

            let response = client
                .execute(req)
                .unwrap_or_else(|err| panic!("HTTP/3 {method} should succeed: {err}"));

            assert!(
                response.is_success,
                "{method} response should be successful"
            );
            assert_response_body_contains(&response, "vane-live");
        }
    }

    #[test]
    fn live_http3_cookies_when_base_url_is_set() {
        let Some(base_url) = live_https_base_url() else {
            return;
        };

        let client = VaneClient::new(VaneClientConfig {
            base_url: Some(base_url),
            cookies_enabled: true,
            protocol_mode: VaneProtocolMode::Http3Only,
            timeout_seconds: Some(30),
            ..VaneClientConfig::default()
        })
        .unwrap();

        let set_cookie = client
            .get_request("/cookies/set/vane_cookie/live".to_string())
            .expect("HTTP/3 cookie set should succeed");
        assert!(set_cookie.is_success);

        let cookies = client
            .get_request("/cookies".to_string())
            .expect("HTTP/3 cookie read should succeed");
        assert!(cookies.is_success);
        assert_response_body_contains(&cookies, "vane_cookie");
        assert_response_body_contains(&cookies, "live");
    }

    #[test]
    fn live_http3_certificate_pin_when_env_pin_is_set() {
        let Some(base_url) = live_https_base_url() else {
            return;
        };
        let Ok(pin) = std::env::var("VANE_TEST_CERT_PIN") else {
            eprintln!("Skipping Vane live certificate pin test. Set VANE_TEST_CERT_PIN.");
            return;
        };

        let host = Url::parse(&base_url).unwrap().host;
        let client = VaneClient::new(VaneClientConfig {
            base_url: Some(base_url),
            certificate_pins: HashMap::from([(host, vec![pin])]),
            protocol_mode: VaneProtocolMode::Http3Only,
            timeout_seconds: Some(30),
            ..VaneClientConfig::default()
        })
        .unwrap();

        let response = client
            .get_request("/get".to_string())
            .expect("HTTP/3 pinned GET should succeed");

        assert!(response.is_success);
    }

    #[test]
    fn http3_backend_requires_https_proxy_for_masque() {
        let client = VaneClient::new(VaneClientConfig {
            protocol_mode: VaneProtocolMode::Http3Only,
            proxy_url: Some("http://proxy.example.com:8080".to_string()),
            ..VaneClientConfig::default()
        })
        .unwrap();

        let err = client
            .execute(request("https://api.example.com/users"))
            .unwrap_err();

        assert!(err.to_string().contains("proxyUrl must use https://"));
        assert!(err.to_string().contains("MASQUE/CONNECT-UDP"));
    }

    #[test]
    fn masque_proxy_config_parses_https_authority() {
        let proxy = MasqueProxyConfig::parse("https://proxy.example.com:8443").unwrap();

        assert_eq!(proxy.host, "proxy.example.com");
        assert_eq!(proxy.port, 8443);
        assert_eq!(proxy.authority, "proxy.example.com:8443");
    }

    #[test]
    fn h3_datagram_roundtrips_flow_context_and_payload() {
        let encoded = encode_h3_datagram(64, 0, b"packet").unwrap();
        let decoded = decode_h3_datagram(&encoded).unwrap().unwrap();

        assert_eq!(decoded.0, 64);
        assert_eq!(decoded.1, 0);
        assert_eq!(&encoded[decoded.2..], b"packet");
    }

    #[test]
    fn masque_path_component_percent_encodes_ipv6_colons() {
        assert_eq!(masque_path_component("2001:db8::1"), "2001%3Adb8%3A%3A1");
    }

    #[test]
    fn tcp_modes_report_that_fallback_was_removed() {
        let client = VaneClient::new(VaneClientConfig {
            protocol_mode: VaneProtocolMode::Http2ThenHttp1,
            ..VaneClientConfig::default()
        })
        .unwrap();

        let err = client
            .execute(request("https://api.example.com/users"))
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("HTTP/3 only; HTTP/1.1 and HTTP/2 fallback were removed")
        );
    }

    #[test]
    fn query_params_are_appended_to_absolute_urls() {
        let client = VaneClient::new(VaneClientConfig::default()).unwrap();
        let mut req = request("https://example.com/users?existing=1");
        req.query_params.insert("page".to_string(), "2".to_string());

        let url = client.build_url(&req).unwrap();

        assert_eq!(
            url.to_string(),
            "https://example.com/users?existing=1&page=2"
        );
    }

    #[test]
    fn base_url_joins_relative_paths_and_query_params() {
        let config = VaneClientConfig {
            base_url: Some("https://api.example.com/v1/".to_string()),
            ..VaneClientConfig::default()
        };
        let client = VaneClient::new(config).unwrap();
        let mut req = request("users");
        req.query_params
            .insert("limit".to_string(), "10".to_string());

        let url = client.build_url(&req).unwrap();

        assert_eq!(url.to_string(), "https://api.example.com/v1/users?limit=10");
    }

    #[test]
    fn dns_override_resolves_to_configured_ip() {
        let mut overrides = HashMap::new();
        overrides.insert("api.example.com".to_string(), "203.0.113.10".to_string());

        let addr = resolve_peer_addr("api.example.com", 443, &overrides).unwrap();

        assert_eq!(addr, SocketAddr::from(([203, 0, 113, 10], 443)));
    }

    #[test]
    fn dns_override_rejects_non_ip_values() {
        let mut overrides = HashMap::new();
        overrides.insert("api.example.com".to_string(), "not-an-ip".to_string());

        let err = resolve_peer_addr("api.example.com", 443, &overrides).unwrap_err();

        assert!(err.to_string().contains("Invalid DNS override"));
    }

    #[test]
    fn certificate_pin_values_include_cert_der_sha256_pin() {
        let cert_der = b"fake certificate bytes";

        let values = certificate_pin_values(cert_der);

        assert!(values.contains(&sha256_pin("sha256-cert", cert_der)));
    }

    #[test]
    fn certificate_pinning_accepts_matching_cert_der_pin() {
        let host = "api.example.com";
        let cert_der = b"fake certificate bytes";
        let certificate_pins =
            HashMap::from([(host.to_string(), vec![sha256_pin("sha256-cert", cert_der)])]);

        let result = verify_certificate_pins(host, Some(cert_der), &certificate_pins);

        assert!(result.is_ok());
    }

    #[test]
    fn certificate_pinning_accepts_backup_pin() {
        let host = "api.example.com";
        let cert_der = b"fake certificate bytes";
        let certificate_pins = HashMap::from([(
            host.to_string(),
            vec![
                "sha256-cert/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
                sha256_pin("sha256-cert", cert_der),
            ],
        )]);

        let result = verify_certificate_pins(host, Some(cert_der), &certificate_pins);

        assert!(result.is_ok());
    }

    #[test]
    fn certificate_pinning_rejects_mismatch() {
        let host = "api.example.com";
        let certificate_pins = HashMap::from([(
            host.to_string(),
            vec!["sha256-cert/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string()],
        )]);

        let err = verify_certificate_pins(host, Some(b"different certificate"), &certificate_pins)
            .unwrap_err();

        assert!(err.to_string().contains("Certificate pin mismatch"));
    }

    #[test]
    fn certificate_pinning_requires_peer_cert_when_configured() {
        let host = "api.example.com";
        let certificate_pins =
            HashMap::from([(host.to_string(), vec!["sha256/example".to_string()])]);

        let err = verify_certificate_pins(host, None, &certificate_pins).unwrap_err();

        assert!(err.to_string().contains("peer certificate was unavailable"));
    }

    #[test]
    fn dynamic_certificate_pins_can_be_updated_and_cleared() {
        let host = "api.example.com".to_string();
        let client = VaneClient::new(VaneClientConfig::default()).unwrap();

        client
            .set_certificate_pins(host.clone(), vec!["sha256/example".to_string()])
            .unwrap();
        assert_eq!(
            client
                .certificate_pins_snapshot()
                .unwrap()
                .get(&host)
                .cloned(),
            Some(vec!["sha256/example".to_string()])
        );

        client
            .add_certificate_pin(host.clone(), "sha256-cert/example".to_string())
            .unwrap();
        assert_eq!(
            client
                .certificate_pins_snapshot()
                .unwrap()
                .get(&host)
                .cloned(),
            Some(vec![
                "sha256/example".to_string(),
                "sha256-cert/example".to_string()
            ])
        );

        client.clear_certificate_pins(host.clone()).unwrap();
        assert!(
            !client
                .certificate_pins_snapshot()
                .unwrap()
                .contains_key(&host)
        );
    }

    #[test]
    fn pseudo_headers_are_rejected() {
        let mut headers = Vec::new();

        let err = push_regular_header(&mut headers, ":authority", "example.com").unwrap_err();

        assert!(err.to_string().contains("pseudo-header"));
    }

    #[test]
    fn h3_headers_include_defaults_and_request_overrides() {
        let mut config = VaneClientConfig::default();
        config
            .default_headers
            .insert("Authorization".to_string(), "Bearer default".to_string());
        let mut req = request("https://example.com/items");
        req.headers
            .insert("X-Trace-ID".to_string(), "abc123".to_string());

        let url = Url::parse("https://example.com/items").unwrap();
        let headers = build_h3_headers(&url, &req, &config, None).unwrap();
        let pairs: Vec<(String, String)> = headers
            .iter()
            .map(|h| {
                (
                    String::from_utf8_lossy(h.name()).to_string(),
                    String::from_utf8_lossy(h.value()).to_string(),
                )
            })
            .collect();

        assert!(pairs.contains(&(":method".to_string(), "GET".to_string())));
        assert!(pairs.contains(&(":scheme".to_string(), "https".to_string())));
        assert!(pairs.contains(&(":authority".to_string(), "example.com".to_string())));
        assert!(pairs.contains(&(":path".to_string(), "/items".to_string())));
        assert!(pairs.contains(&("authorization".to_string(), "Bearer default".to_string())));
        assert!(pairs.contains(&("x-trace-id".to_string(), "abc123".to_string())));
    }

    #[test]
    fn h3_headers_include_cookie_jar_header_when_present() {
        let config = VaneClientConfig::default();
        let req = request("https://example.com/items");
        let url = Url::parse("https://example.com/items").unwrap();

        let headers =
            build_h3_headers(&url, &req, &config, Some("session=abc; theme=dark")).unwrap();
        let pairs: Vec<(String, String)> = headers
            .iter()
            .map(|h| {
                (
                    String::from_utf8_lossy(h.name()).to_string(),
                    String::from_utf8_lossy(h.value()).to_string(),
                )
            })
            .collect();

        assert!(pairs.contains(&("cookie".to_string(), "session=abc; theme=dark".to_string())));
    }

    #[test]
    fn request_body_limit_rejects_oversized_body() {
        let err = validate_request_body_limit(b"abcd", 3).unwrap_err();

        assert!(err.to_string().contains("request body exceeded 3 bytes"));
        assert!(validate_request_body_limit(b"abc", 3).is_ok());
    }

    #[test]
    fn response_body_limit_rejects_oversized_body() {
        let err = validate_response_body_limit(3, 2, 4).unwrap_err();

        assert!(err.to_string().contains("response body exceeded 4 bytes"));
        assert!(validate_response_body_limit(3, 1, 4).is_ok());
    }

    #[test]
    fn cookie_parser_respects_domain_path_secure_and_delete() {
        let url = Url::parse("https://api.example.com/v1/login").unwrap();
        let cookie = StoredCookie::parse(
            &url,
            "session=abc; Domain=.example.com; Path=/v1; Secure; HttpOnly; SameSite=Lax",
        )
        .unwrap();

        assert!(!cookie.host_only);
        assert_eq!(cookie.domain, "example.com");
        assert_eq!(cookie.path, "/v1");
        assert!(cookie.secure);
        assert!(cookie.matches(
            &Url::parse("https://api.example.com/v1/users").unwrap(),
            now_epoch_seconds()
        ));
        assert!(!cookie.matches(
            &Url::parse("http://api.example.com/v1/users").unwrap(),
            now_epoch_seconds()
        ));
        assert!(!cookie.matches(
            &Url::parse("https://api.example.com/v2/users").unwrap(),
            now_epoch_seconds()
        ));

        let delete = StoredCookie::parse(&url, "session=deleted; Path=/v1; Max-Age=0").unwrap();
        assert!(delete.is_expired(now_epoch_seconds()));
    }

    #[test]
    fn cookie_jar_scopes_cookies_by_host_and_path() {
        let client = VaneClient::new(VaneClientConfig {
            cookies_enabled: true,
            ..VaneClientConfig::default()
        })
        .unwrap();
        let login_url = Url::parse("https://api.example.com/v1/login").unwrap();
        client
            .store_response_cookies(
                &login_url,
                &[
                    "session=abc; Path=/v1; Secure".to_string(),
                    "global=xyz; Domain=example.com; Path=/".to_string(),
                ],
            )
            .unwrap();

        let same_path = Url::parse("https://api.example.com/v1/users").unwrap();
        let other_path = Url::parse("https://api.example.com/v2/users").unwrap();
        let other_host = Url::parse("https://other.test/v1/users").unwrap();

        assert_eq!(
            client.cookie_header(&same_path).unwrap(),
            "session=abc; global=xyz"
        );
        assert_eq!(client.cookie_header(&other_path).unwrap(), "global=xyz");
        assert_eq!(client.cookie_header(&other_host).unwrap(), "");
    }

    #[test]
    fn cookie_jar_persists_to_disk_when_path_is_configured() {
        let path = std::env::temp_dir().join(format!("vane-cookies-{}.txt", now_epoch_seconds()));
        let path = path.to_string_lossy().to_string();
        let url = Url::parse("https://api.example.com/v1/users").unwrap();
        let client = VaneClient::new(VaneClientConfig {
            cookies_enabled: true,
            cookie_persistence_path: Some(path.clone()),
            ..VaneClientConfig::default()
        })
        .unwrap();

        client
            .store_response_cookies(&url, &["session=abc; Path=/v1; Max-Age=60".to_string()])
            .unwrap();
        let loaded = load_cookie_jar(Some(&path)).unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "session");
        assert_eq!(loaded[0].value, "abc");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn cancel_tokens_and_progress_state_are_tracked_by_id() {
        let cancel_id = vane_ffi_cancel_token_create();
        assert!(check_cancelled(Some(cancel_id)).is_ok());
        vane_ffi_cancel_token_cancel(cancel_id);
        assert!(check_cancelled(Some(cancel_id)).is_err());
        vane_ffi_cancel_token_free(cancel_id);

        let progress_id = vane_ffi_progress_create();
        progress_init(Some(progress_id), 10);
        progress_upload(Some(progress_id), 4, 10);
        progress_download(Some(progress_id), 8, 0);
        progress_done(Some(progress_id));
        let progress = vane_ffi_progress_snapshot(progress_id);
        assert_eq!(progress.upload_sent, 4);
        assert_eq!(progress.upload_total, 10);
        assert_eq!(progress.download_received, 8);
        assert!(progress.done);
        vane_ffi_progress_free(progress_id);
    }

    #[test]
    fn retry_is_disabled_by_default() {
        let config = VaneClientConfig::default();

        assert!(!should_retry_response("GET", 503, 1, &config));
        assert!(!should_retry_error("GET", 1, &config));
    }

    #[test]
    fn retry_allows_idempotent_methods_when_configured() {
        let config = VaneClientConfig {
            retry_max_attempts: 3,
            ..VaneClientConfig::default()
        };

        assert!(should_retry_response("GET", 503, 1, &config));
        assert!(should_retry_response("PUT", 429, 2, &config));
        assert!(!should_retry_response("GET", 200, 1, &config));
        assert!(!should_retry_response("GET", 503, 3, &config));
    }

    #[test]
    fn retry_blocks_unsafe_methods_unless_opted_in() {
        let default_config = VaneClientConfig {
            retry_max_attempts: 3,
            ..VaneClientConfig::default()
        };
        let unsafe_config = VaneClientConfig {
            retry_max_attempts: 3,
            retry_unsafe_methods: true,
            ..VaneClientConfig::default()
        };

        assert!(!should_retry_error("POST", 1, &default_config));
        assert!(!should_retry_response("PATCH", 503, 1, &default_config));
        assert!(should_retry_error("POST", 1, &unsafe_config));
        assert!(should_retry_response("PATCH", 503, 1, &unsafe_config));
    }

    #[test]
    fn retry_delay_uses_exponential_backoff_with_cap() {
        let config = VaneClientConfig {
            retry_initial_delay_millis: 25,
            retry_max_delay_millis: 60,
            ..VaneClientConfig::default()
        };

        assert_eq!(retry_delay(1, &config), Duration::from_millis(25));
        assert_eq!(retry_delay(2, &config), Duration::from_millis(50));
        assert_eq!(retry_delay(3, &config), Duration::from_millis(60));
    }

    #[test]
    fn pool_key_includes_dns_override_and_certificate_pins() {
        let url = Url::parse("https://api.example.com/v1").unwrap();
        let mut base = VaneClientConfig::default();
        base.certificate_pins.insert(
            "api.example.com".to_string(),
            vec!["sha256/b".to_string(), "sha256/a".to_string()],
        );

        let mut dns_config = base.clone();
        dns_config
            .dns_overrides
            .insert("api.example.com".to_string(), "203.0.113.10".to_string());

        let base_key = PoolKey::new(&url, &base, &base.certificate_pins);
        let dns_key = PoolKey::new(&url, &dns_config, &dns_config.certificate_pins);

        assert_ne!(base_key, dns_key);
        assert_eq!(
            base_key.certificate_pins,
            vec!["sha256/a".to_string(), "sha256/b".to_string()]
        );
    }
}
