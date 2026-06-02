uniffi::setup_scaffolding!();

use std::collections::HashMap;
#[cfg(feature = "http12")]
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
#[cfg(feature = "http12")]
use std::pin::Pin;
#[cfg(feature = "http12")]
use std::sync::Once;
use std::sync::{Arc, Mutex};
#[cfg(feature = "http12")]
use std::task::{Context, Poll};
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
#[cfg(feature = "spki-pinning")]
use boring::x509::X509;
#[cfg(feature = "http12")]
use bytes::Bytes;
#[cfg(feature = "http12")]
use http_body_util::{BodyExt, Full};
#[cfg(feature = "http12")]
use hyper::body::Incoming;
#[cfg(feature = "http12")]
use hyper::header::{
    COOKIE, HOST, HeaderMap, HeaderName, HeaderValue, LOCATION, PROXY_AUTHORIZATION, SET_COOKIE,
    USER_AGENT,
};
#[cfg(feature = "http12")]
use hyper::{Method, Request, StatusCode, Uri};
#[cfg(feature = "http12")]
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
#[cfg(feature = "http12")]
use hyper_util::client::legacy::Client as HyperClient;
#[cfg(feature = "http12")]
use hyper_util::client::legacy::connect::dns::Name;
#[cfg(feature = "http12")]
use hyper_util::client::legacy::connect::{Connected, Connection, HttpConnector};
#[cfg(feature = "http12")]
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use quiche::h3::NameValue;
#[cfg(feature = "http12")]
use rustls_pki_types::ServerName;
use sha2::{Digest, Sha256};
use thiserror::Error;
#[cfg(feature = "http12")]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
#[cfg(feature = "http12")]
use tokio::runtime::Runtime;
#[cfg(feature = "http12")]
use tokio_rustls::{TlsConnector, client::TlsStream};
#[cfg(feature = "http12")]
use tower_service::Service;

const MAX_DATAGRAM_SIZE: usize = 1350;
const DEFAULT_MAX_REQUEST_BODY_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_MAX_RESPONSE_BODY_BYTES: u64 = 64 * 1024 * 1024;

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
    pub timeout_seconds: Option<u64>,
    pub follow_redirects: bool,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct VaneResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub is_success: bool,
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum VaneProtocolMode {
    /// Try HTTP/3 first, then fall back to HTTP/2 or HTTP/1.1 over TCP/TLS.
    Http3ThenHttp2ThenHttp1,
    Http3Only,
    /// Use hyper over TCP/TLS with ALPN for HTTP/2 or HTTP/1.1.
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
            protocol_mode: VaneProtocolMode::Http3ThenHttp2ThenHttp1,
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

// ---------- Client ----------
#[derive(uniffi::Object)]
pub struct VaneClient {
    config: VaneClientConfig,
    pool: Mutex<Vec<PooledHttp3Connection>>,
    cookie_jar: Mutex<Vec<StoredCookie>>,
    #[cfg(feature = "http12")]
    runtime: Runtime,
    #[cfg(feature = "http12")]
    tcp_client: TcpClient,
}

impl VaneClient {
    pub fn new(config: VaneClientConfig) -> Result<Self, VaneError> {
        #[cfg(feature = "http12")]
        let runtime = Runtime::new()
            .map_err(|e| VaneError::Generic(format!("Failed to create HTTP runtime: {e}")))?;
        #[cfg(feature = "http12")]
        let tcp_client = build_tcp_client(&config)?;

        Ok(Self {
            config,
            pool: Mutex::new(Vec::new()),
            cookie_jar: Mutex::new(Vec::new()),
            #[cfg(feature = "http12")]
            runtime,
            #[cfg(feature = "http12")]
            tcp_client,
        })
    }

    pub fn execute(&self, request: VaneRequest) -> Result<VaneResponse, VaneError> {
        let url = self.build_url(&request)?;
        match self.config.protocol_mode {
            VaneProtocolMode::Http3ThenHttp2ThenHttp1 => {
                match self.execute_with_retry(&request, &url, TransportBackend::Http3) {
                    Ok(response) => Ok(response),
                    Err(http3_error) => self
                        .execute_with_retry(&request, &url, TransportBackend::Tcp)
                        .map_err(|tcp_error| {
                            VaneError::Generic(format!(
                                "HTTP/3 failed ({http3_error}); HTTP/2 or HTTP/1.1 fallback failed ({tcp_error})"
                            ))
                        }),
                }
            }
            VaneProtocolMode::Http3Only => {
                self.execute_with_retry(&request, &url, TransportBackend::Http3)
            }
            VaneProtocolMode::Http2ThenHttp1
            | VaneProtocolMode::Http2Only
            | VaneProtocolMode::Http1Only => {
                self.execute_with_retry(&request, &url, TransportBackend::Tcp)
            }
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
        backend: TransportBackend,
    ) -> Result<VaneResponse, VaneError> {
        let max_attempts = self.config.retry_max_attempts.max(1);
        let mut attempt = 1u64;
        let mut last_error = None;

        while attempt <= max_attempts {
            match match backend {
                TransportBackend::Http3 => self.execute_http3_once(request, url),
                TransportBackend::Tcp => self.execute_tcp_once(request, url),
            } {
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

    fn execute_tcp_once(
        &self,
        request: &VaneRequest,
        url: &Url,
    ) -> Result<VaneResponse, VaneError> {
        #[cfg(not(feature = "http12"))]
        {
            let _ = request;
            let _ = url;
            Err(VaneError::Generic(
                "This Vane build was compiled without HTTP/1.1 and HTTP/2 support".to_string(),
            ))
        }

        #[cfg(feature = "http12")]
        {
            if url.scheme() != "https" && url.scheme() != "http" {
                return Err(VaneError::Generic(
                    "HTTP/1.1/2 backend only supports http:// or https:// URLs".to_string(),
                ));
            }

            let host = url
                .host_str()
                .ok_or_else(|| VaneError::Generic("URL is missing host".to_string()))?;
            if self
                .config
                .certificate_pins
                .get(host)
                .is_some_and(|pins| !pins.is_empty())
            {
                return Err(VaneError::Generic(format!(
                    "Certificate pinning for {host} is only supported by the HTTP/3 backend"
                )));
            }

            let request_body = request.body.clone().unwrap_or_default();
            validate_request_body_limit(&request_body, self.config.max_request_body_bytes)?;

            let timeout = Duration::from_secs(
                request
                    .timeout_seconds
                    .or(self.config.timeout_seconds)
                    .unwrap_or(30),
            );
            let method = Method::from_bytes(request.method.as_bytes()).map_err(|e| {
                VaneError::Generic(format!("Invalid HTTP method {}: {e}", request.method))
            })?;

            let result = self.runtime.block_on(async {
                tokio::time::timeout(
                    timeout,
                    self.execute_hyper_request_with_redirects(
                        method,
                        url.clone(),
                        request,
                        request_body,
                    ),
                )
                .await
                .map_err(|_| VaneError::Generic("HTTP/1.1/2 request timed out".to_string()))?
            })?;

            if self.config.cookies_enabled {
                self.store_response_cookies(&result.cookie_url, &result.set_cookie_headers)?;
            }

            Ok(VaneResponse {
                status_code: result.status_code,
                headers: result.headers,
                body: result.body,
                is_success: (200..=299).contains(&result.status_code),
                url: result.url,
            })
        }
    }

    #[cfg(feature = "http12")]
    async fn execute_hyper_request_with_redirects(
        &self,
        mut method: Method,
        mut url: Url,
        request: &VaneRequest,
        mut request_body: Vec<u8>,
    ) -> Result<TcpResponseParts, VaneError> {
        let max_redirects = if request.follow_redirects { 10 } else { 0 };
        for redirect_count in 0..=max_redirects {
            let response = self
                .send_hyper_request(method.clone(), &url, request, request_body.clone())
                .await?;
            if !request.follow_redirects || !is_redirect_status(response.status_code) {
                return Ok(response);
            }

            let Some(location) = response.redirect_location.clone() else {
                return Ok(response);
            };
            if redirect_count == max_redirects {
                return Err(VaneError::Generic(
                    "HTTP/1.1/2 redirect limit exceeded".to_string(),
                ));
            }

            url = url
                .join(&location)
                .map_err(|e| VaneError::Generic(format!("Invalid redirect location: {e}")))?;
            if response.status_code == StatusCode::SEE_OTHER.as_u16() {
                method = Method::GET;
                request_body.clear();
            }
        }

        Err(VaneError::Generic(
            "HTTP/1.1/2 redirect handling failed".to_string(),
        ))
    }

    #[cfg(feature = "http12")]
    async fn send_hyper_request(
        &self,
        method: Method,
        url: &Url,
        request: &VaneRequest,
        request_body: Vec<u8>,
    ) -> Result<TcpResponseParts, VaneError> {
        let mut headers = build_tcp_headers(url, request, &self.config)?;
        if self.config.cookies_enabled {
            let cookie_header = self.cookie_header(url)?;
            if !cookie_header.is_empty() {
                headers.insert(
                    COOKIE,
                    HeaderValue::from_str(&cookie_header).map_err(|e| {
                        VaneError::Generic(format!("Invalid cookie header generated by jar: {e}"))
                    })?,
                );
            }
        }

        let uri = url
            .to_string()
            .parse::<Uri>()
            .map_err(|e| VaneError::Generic(format!("Invalid HTTP URI: {e}")))?;
        let hyper_request = Request::builder()
            .method(method)
            .uri(uri)
            .body(Full::from(Bytes::from(request_body)))
            .map_err(|e| VaneError::Generic(format!("Failed to build HTTP request: {e}")))?;
        let (mut parts, body) = hyper_request.into_parts();
        parts.headers = headers;
        let hyper_request = Request::from_parts(parts, body);

        let response = self
            .tcp_client
            .request(hyper_request)
            .await
            .map_err(|e| VaneError::Generic(format!("HTTP/1.1/2 error: {e}")))?;
        collect_hyper_response(response, url, self.config.max_response_body_bytes).await
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
        if self.config.proxy_url.is_some() {
            return Err(VaneError::Generic(
                "HTTP/3 proxying is not supported yet; QUIC proxying requires MASQUE/CONNECT-UDP. Use the HTTP/1.1/2 TCP fallback backend with http://, https://, socks5://, or socks5h:// proxies.".to_string(),
            ));
        }

        let host = url
            .host_str()
            .ok_or_else(|| VaneError::Generic("URL is missing host".to_string()))?;
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
        let request_body = request.body.clone().unwrap_or_default();
        validate_request_body_limit(&request_body, self.config.max_request_body_bytes)?;
        let pool_key = PoolKey::new(url, &self.config);
        let mut transport = match if self.config.connection_pool_enabled {
            self.take_pooled_connection(&pool_key, timeout)?
        } else {
            None
        } {
            Some(connection) => connection,
            None => self
                .connect_http3(host, peer_addr, timeout, pool_key.clone())
                .inspect_err(|_| {
                    self.drop_closed_connections();
                })?,
        };

        let result = perform_http3_request(
            &mut transport,
            &headers,
            &request_body,
            timeout,
            url,
            self.config.max_response_body_bytes,
        );
        match result {
            Ok(response) => {
                if self.config.cookies_enabled {
                    self.store_response_cookies(url, &response.set_cookie_headers)?;
                }

                let public_response = response.into_public_response();
                if self.config.connection_pool_enabled && !transport.conn.is_closed() {
                    self.return_pooled_connection(transport)?;
                } else {
                    transport.conn.close(true, 0x00, b"done").ok();
                    flush_quic_packets(&transport.socket, &mut transport.conn).ok();
                }

                Ok(public_response)
            }
            Err(err) => {
                transport.conn.close(true, 0x01, b"request failed").ok();
                flush_quic_packets(&transport.socket, &mut transport.conn).ok();
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
    ) -> Result<PooledHttp3Connection, VaneError> {
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
        getrandom::fill(&mut scid).map_err(|e| {
            VaneError::Generic(format!("Failed to generate QUIC connection ID: {e}"))
        })?;
        let scid = quiche::ConnectionId::from_ref(&scid);
        let mut conn = quiche::connect(Some(host), &scid, local_addr, peer_addr, &mut quic_config)
            .map_err(|e| VaneError::Generic(format!("Failed to create QUIC client: {e}")))?;
        let h3_config = quiche::h3::Config::new()
            .map_err(|e| VaneError::Generic(format!("Failed to create HTTP/3 config: {e}")))?;

        flush_quic_packets(&socket, &mut conn)?;
        let deadline = Instant::now() + timeout;

        while Instant::now() < deadline {
            read_quic_packets(&socket, &mut conn, local_addr, peer_addr)?;

            if conn.is_established() {
                verify_certificate_pins(host, conn.peer_cert(), &self.config)?;
                let http3 = quiche::h3::Connection::with_transport(&mut conn, &h3_config)?;
                return Ok(PooledHttp3Connection {
                    key,
                    socket,
                    local_addr,
                    peer_addr,
                    conn,
                    http3,
                    last_used: Instant::now(),
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
        conn.socket.set_write_timeout(Some(timeout)).map_err(|e| {
            VaneError::Generic(format!("Failed to set pooled UDP write timeout: {e}"))
        })?;
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
            flush_quic_packets(&connection.socket, &mut connection.conn).ok();
            return Ok(());
        }

        connection.last_used = Instant::now();
        pool.push(connection);

        while pool.len() > max_idle {
            if let Some(removed) = pool.first_mut() {
                removed.conn.close(true, 0x00, b"pool full").ok();
                flush_quic_packets(&removed.socket, &mut removed.conn).ok();
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

    fn cookie_header(&self, url: &Url) -> Result<String, VaneError> {
        let mut jar = self
            .cookie_jar
            .lock()
            .map_err(|_| VaneError::Generic("Cookie jar lock was poisoned".to_string()))?;
        let now = Instant::now();
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
                if !cookie.is_expired(Instant::now()) {
                    jar.push(cookie);
                }
            }
        }

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
    certificate_pins: Vec<String>,
}

impl PoolKey {
    fn new(url: &Url, config: &VaneClientConfig) -> Self {
        let host = url.host_str().unwrap_or_default().to_string();
        let mut certificate_pins = config
            .certificate_pins
            .get(&host)
            .cloned()
            .unwrap_or_default();
        certificate_pins.sort();

        Self {
            scheme: url.scheme().to_string(),
            host: host.clone(),
            port: url.port_or_known_default().unwrap_or(443),
            protocol_mode: config.protocol_mode.clone(),
            dns_override: config.dns_overrides.get(&host).cloned(),
            certificate_pins,
        }
    }
}

struct PooledHttp3Connection {
    key: PoolKey,
    socket: UdpSocket,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    conn: quiche::Connection,
    http3: quiche::h3::Connection,
    last_used: Instant,
}

#[cfg(feature = "http12")]
type TcpRequestBody = Full<Bytes>;
#[cfg(feature = "http12")]
type TcpConnector = HttpsConnector<ProxyConnector>;
#[cfg(feature = "http12")]
type TcpClient = HyperClient<TcpConnector, TcpRequestBody>;
#[cfg(feature = "http12")]
type ProxyTlsStream = TlsStream<tokio::net::TcpStream>;
#[cfg(feature = "http12")]
type DnsFuture =
    Pin<Box<dyn Future<Output = Result<std::vec::IntoIter<SocketAddr>, io::Error>> + Send>>;

#[cfg(feature = "http12")]
static RUSTLS_PROVIDER_INIT: Once = Once::new();

#[cfg(feature = "http12")]
#[derive(Clone)]
struct StaticDnsResolver {
    overrides: Arc<HashMap<String, IpAddr>>,
}

#[cfg(feature = "http12")]
impl StaticDnsResolver {
    fn new(dns_overrides: &HashMap<String, String>) -> Result<Self, VaneError> {
        let overrides = dns_overrides
            .iter()
            .map(|(host, ip)| {
                ip.parse::<IpAddr>()
                    .map(|ip| (host.clone(), ip))
                    .map_err(|e| {
                        VaneError::Generic(format!(
                            "Invalid DNS override for {host}: expected IP address, got {ip}: {e}"
                        ))
                    })
            })
            .collect::<Result<HashMap<_, _>, _>>()?;

        Ok(Self {
            overrides: Arc::new(overrides),
        })
    }
}

#[cfg(feature = "http12")]
impl Service<Name> for StaticDnsResolver {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = io::Error;
    type Future = DnsFuture;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let _ = cx;
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: Name) -> Self::Future {
        if let Some(ip) = self.overrides.get(name.as_str()).copied() {
            return Box::pin(async move { Ok(vec![SocketAddr::new(ip, 0)].into_iter()) });
        }

        let host = name.as_str().to_string();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                (host.as_str(), 0)
                    .to_socket_addrs()
                    .map(|addrs| addrs.collect::<Vec<_>>().into_iter())
            })
            .await
            .map_err(|e| io::Error::other(format!("DNS resolver task failed: {e}")))?
        })
    }
}

#[cfg(feature = "http12")]
#[derive(Clone)]
struct ProxyConnector {
    http: HttpConnector<StaticDnsResolver>,
    proxy: Option<HttpProxyConfig>,
}

#[cfg(feature = "http12")]
#[derive(Clone, Debug)]
struct HttpProxyConfig {
    host: String,
    port: u16,
    scheme: ProxyScheme,
    authorization: Option<String>,
    socks_username: Option<String>,
    socks_password: Option<String>,
}

#[cfg(feature = "http12")]
#[derive(Clone, Debug, PartialEq, Eq)]
enum ProxyScheme {
    Http,
    Https,
    Socks5 { remote_dns: bool },
}

#[cfg(feature = "http12")]
enum ProxyIo {
    Plain {
        stream: tokio::net::TcpStream,
        proxied: bool,
    },
    Tls(Box<ProxyTlsStream>),
}

#[cfg(feature = "http12")]
impl Connection for ProxyIo {
    fn connected(&self) -> Connected {
        match self {
            Self::Plain { proxied, .. } => Connected::new().proxy(*proxied),
            Self::Tls(_) => Connected::new().proxy(true),
        }
    }
}

#[cfg(feature = "http12")]
impl AsyncRead for ProxyIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain { stream, .. } => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
        }
    }
}

#[cfg(feature = "http12")]
impl AsyncWrite for ProxyIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain { stream, .. } => Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain { stream, .. } => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain { stream, .. } => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }
}

#[cfg(feature = "http12")]
impl ProxyConnector {
    fn new(
        http: HttpConnector<StaticDnsResolver>,
        config: &VaneClientConfig,
    ) -> Result<Self, VaneError> {
        Ok(Self {
            http,
            proxy: parse_http_proxy_config(config)?,
        })
    }
}

#[cfg(feature = "http12")]
impl Service<Uri> for ProxyConnector {
    type Response = TokioIo<ProxyIo>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.http
            .poll_ready(cx)
            .map_err(|e| io::Error::other(format!("HTTP connector is not ready: {e}")))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let mut http = self.http.clone();
        let proxy = self.proxy.clone();

        Box::pin(async move {
            let Some(proxy) = proxy else {
                let stream = http
                    .call(dst)
                    .await
                    .map_err(|e| io::Error::other(format!("Failed to connect: {e}")))?
                    .into_inner();
                return Ok(TokioIo::new(ProxyIo::Plain {
                    stream,
                    proxied: false,
                }));
            };

            match dst.scheme_str() {
                Some("http") => connect_via_proxy(&mut http, &proxy, &dst, false).await,
                Some("https") => connect_via_proxy(&mut http, &proxy, &dst, true).await,
                Some(scheme) => Err(io::Error::other(format!(
                    "Proxy connector does not support {scheme} URLs"
                ))),
                None => Err(io::Error::other("Proxy connector requires a URL scheme")),
            }
        })
    }
}

#[derive(Debug, Clone, Copy)]
enum TransportBackend {
    Http3,
    Tcp,
}

struct Http3ResponseParts {
    status_code: u16,
    headers: HashMap<String, String>,
    set_cookie_headers: Vec<String>,
    body: Vec<u8>,
    url: String,
}

#[cfg(feature = "http12")]
struct TcpResponseParts {
    status_code: u16,
    headers: HashMap<String, String>,
    set_cookie_headers: Vec<String>,
    redirect_location: Option<String>,
    body: Vec<u8>,
    url: String,
    cookie_url: Url,
}

impl Http3ResponseParts {
    fn into_public_response(self) -> VaneResponse {
        VaneResponse {
            status_code: self.status_code,
            headers: self.headers,
            body: self.body,
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
    expires_at: Option<Instant>,
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
            expires_at: None,
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
                        cookie.expires_at = if seconds <= 0 {
                            Some(Instant::now())
                        } else {
                            Some(Instant::now() + Duration::from_secs(seconds as u64))
                        };
                    }
                }
                _ => {}
            }
        }

        Some(cookie)
    }

    fn matches(&self, url: &Url, now: Instant) -> bool {
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

    fn is_expired(&self, now: Instant) -> bool {
        self.expires_at.is_some_and(|expires_at| now >= expires_at)
    }
}

fn perform_http3_request(
    transport: &mut PooledHttp3Connection,
    headers: &[quiche::h3::Header],
    request_body: &[u8],
    timeout: Duration,
    url: &Url,
    max_response_body_bytes: u64,
) -> Result<Http3ResponseParts, VaneError> {
    let mut request_stream_id = None;
    let mut body_offset = 0usize;
    let deadline = Instant::now() + timeout;
    let mut response = H3ResponseState::new(max_response_body_bytes);

    while Instant::now() < deadline {
        read_quic_packets(
            &transport.socket,
            &mut transport.conn,
            transport.local_addr,
            transport.peer_addr,
        )?;

        if request_stream_id.is_none() {
            let fin = request_body.is_empty();
            request_stream_id = Some(transport.http3.send_request(
                &mut transport.conn,
                headers,
                fin,
            )?);
        }

        if let Some(stream_id) = request_stream_id {
            while body_offset < request_body.len() {
                match transport.http3.send_body(
                    &mut transport.conn,
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

        process_h3_events(&mut transport.http3, &mut transport.conn, &mut response)?;

        if response.finished {
            flush_quic_packets(&transport.socket, &mut transport.conn)?;
            break;
        }

        flush_quic_packets(&transport.socket, &mut transport.conn)?;

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
        url: url.to_string(),
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

#[cfg(feature = "http12")]
fn parse_http_proxy_config(
    config: &VaneClientConfig,
) -> Result<Option<HttpProxyConfig>, VaneError> {
    let Some(proxy_url) = config.proxy_url.as_deref() else {
        return Ok(None);
    };
    parse_proxy_url(proxy_url, config.proxy_authorization.clone()).map(Some)
}

#[cfg(feature = "http12")]
fn parse_proxy_url(
    proxy_url: &str,
    authorization: Option<String>,
) -> Result<HttpProxyConfig, VaneError> {
    let (scheme, rest) = proxy_url
        .split_once("://")
        .ok_or_else(|| VaneError::Generic("Proxy URL must include a scheme".to_string()))?;
    let scheme = match scheme {
        "http" => ProxyScheme::Http,
        "https" => ProxyScheme::Https,
        "socks5" => ProxyScheme::Socks5 { remote_dns: false },
        "socks5h" => ProxyScheme::Socks5 { remote_dns: true },
        other => {
            return Err(VaneError::Generic(format!(
                "Unsupported proxy URL scheme {other}; use http://, https://, socks5://, or socks5h://"
            )));
        }
    };
    let before_path = rest
        .split_once(['/', '?', '#'])
        .map(|(authority, _)| authority)
        .unwrap_or(rest);
    if before_path.is_empty() {
        return Err(VaneError::Generic("Proxy URL is missing host".to_string()));
    }

    let (userinfo, authority) = before_path
        .rsplit_once('@')
        .map(|(userinfo, authority)| (Some(userinfo), authority))
        .unwrap_or((None, before_path));
    let (host, port) = parse_authority(authority)
        .map_err(|e| VaneError::Generic(format!("Invalid proxy URL: {e}")))?;
    let port = port.unwrap_or(match scheme {
        ProxyScheme::Http => 80,
        ProxyScheme::Https => 443,
        ProxyScheme::Socks5 { .. } => 1080,
    });
    let (socks_username, socks_password) = match (&scheme, userinfo) {
        (ProxyScheme::Socks5 { .. }, Some(userinfo)) => {
            let (username, password) = userinfo.split_once(':').unwrap_or((userinfo, ""));
            if username.len() > 255 || password.len() > 255 {
                return Err(VaneError::Generic(
                    "SOCKS5 proxy username and password must be 255 bytes or fewer".to_string(),
                ));
            }
            (Some(username.to_string()), Some(password.to_string()))
        }
        (_, Some(_)) => {
            return Err(VaneError::Generic(
                "Proxy URL userinfo is only supported for SOCKS5 proxies; use proxyAuthorization for HTTP/HTTPS proxies".to_string(),
            ));
        }
        (_, None) => (None, None),
    };

    Ok(HttpProxyConfig {
        host,
        port,
        scheme,
        authorization,
        socks_username,
        socks_password,
    })
}

#[cfg(feature = "http12")]
fn proxy_uri(proxy: &HttpProxyConfig) -> Result<Uri, io::Error> {
    format!("http://{}:{}", proxy.host, proxy.port)
        .parse::<Uri>()
        .map_err(|e| io::Error::other(format!("Invalid proxy URI: {e}")))
}

#[cfg(feature = "http12")]
async fn connect_proxy_tcp(
    http: &mut HttpConnector<StaticDnsResolver>,
    proxy: &HttpProxyConfig,
) -> Result<tokio::net::TcpStream, io::Error> {
    Ok(http
        .call(proxy_uri(proxy)?)
        .await
        .map_err(|e| io::Error::other(format!("Failed to connect to proxy: {e}")))?
        .into_inner())
}

#[cfg(feature = "http12")]
async fn connect_via_proxy(
    http: &mut HttpConnector<StaticDnsResolver>,
    proxy: &HttpProxyConfig,
    dst: &Uri,
    requires_tunnel: bool,
) -> Result<TokioIo<ProxyIo>, io::Error> {
    match &proxy.scheme {
        ProxyScheme::Http => {
            let stream = connect_proxy_tcp(http, proxy).await?;
            let mut stream = ProxyIo::Plain {
                stream,
                proxied: true,
            };
            if requires_tunnel {
                let authority = proxy_connect_authority(dst)?;
                send_proxy_connect(&mut stream, &authority, proxy.authorization.as_deref()).await?;
            }
            Ok(TokioIo::new(stream))
        }
        ProxyScheme::Https => {
            let stream = connect_proxy_tcp(http, proxy).await?;
            let tls_stream = connect_https_proxy_tls(stream, &proxy.host).await?;
            let mut stream = ProxyIo::Tls(Box::new(tls_stream));
            if requires_tunnel {
                let authority = proxy_connect_authority(dst)?;
                send_proxy_connect(&mut stream, &authority, proxy.authorization.as_deref()).await?;
            }
            Ok(TokioIo::new(stream))
        }
        ProxyScheme::Socks5 { remote_dns } => {
            let mut stream = connect_proxy_tcp(http, proxy).await?;
            let (host, port) = proxy_target_host_port(dst)?;
            send_socks5_connect(&mut stream, &host, port, *remote_dns, proxy).await?;
            Ok(TokioIo::new(ProxyIo::Plain {
                stream,
                proxied: true,
            }))
        }
    }
}

#[cfg(feature = "http12")]
async fn connect_https_proxy_tls(
    stream: tokio::net::TcpStream,
    proxy_host: &str,
) -> Result<ProxyTlsStream, io::Error> {
    ensure_rustls_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name = ServerName::try_from(proxy_host.trim_matches(['[', ']']).to_string())
        .map_err(|e| io::Error::other(format!("Invalid HTTPS proxy server name: {e}")))?;
    TlsConnector::from(Arc::new(tls_config))
        .connect(server_name, stream)
        .await
        .map_err(|e| io::Error::other(format!("HTTPS proxy TLS handshake failed: {e}")))
}

#[cfg(feature = "http12")]
fn ensure_rustls_crypto_provider() {
    RUSTLS_PROVIDER_INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[cfg(feature = "http12")]
fn proxy_target_host_port(dst: &Uri) -> Result<(String, u16), io::Error> {
    let host = dst
        .host()
        .ok_or_else(|| io::Error::other("Proxy target is missing host"))?;
    let default_port = match dst.scheme_str() {
        Some("http") => 80,
        Some("https") => 443,
        _ => return Err(io::Error::other("Proxy target has unsupported scheme")),
    };
    Ok((host.to_string(), dst.port_u16().unwrap_or(default_port)))
}

#[cfg(feature = "http12")]
fn proxy_connect_authority(dst: &Uri) -> Result<String, io::Error> {
    let host = dst
        .host()
        .ok_or_else(|| io::Error::other("CONNECT target is missing host"))?;
    let port = dst.port_u16().unwrap_or(443);
    Ok(format!("{host}:{port}"))
}

#[cfg(feature = "http12")]
async fn send_proxy_connect<S>(
    stream: &mut S,
    authority: &str,
    authorization: Option<&str>,
) -> Result<(), io::Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut request =
        format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: Vane/0.1.0\r\n");
    if let Some(authorization) = authorization {
        request.push_str("Proxy-Authorization: ");
        request.push_str(authorization);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");

    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let mut response = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    while response.len() < 8192 {
        let read = stream.read(&mut byte).await?;
        if read == 0 {
            return Err(io::Error::other(
                "Proxy closed connection before CONNECT response completed",
            ));
        }
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    if !response.ends_with(b"\r\n\r\n") {
        return Err(io::Error::other(
            "Proxy CONNECT response header was too large",
        ));
    }

    let response_text = String::from_utf8_lossy(&response);
    let status_line = response_text
        .lines()
        .next()
        .ok_or_else(|| io::Error::other("Proxy CONNECT response was empty"))?;
    if !status_line.contains(" 200 ") {
        return Err(io::Error::other(format!(
            "Proxy CONNECT failed: {status_line}"
        )));
    }

    Ok(())
}

#[cfg(feature = "http12")]
async fn send_socks5_connect(
    stream: &mut tokio::net::TcpStream,
    host: &str,
    port: u16,
    remote_dns: bool,
    proxy: &HttpProxyConfig,
) -> Result<(), io::Error> {
    let use_auth = proxy.socks_username.is_some();
    let methods: &[u8] = if use_auth { &[0x00, 0x02] } else { &[0x00] };
    let mut greeting = Vec::with_capacity(2 + methods.len());
    greeting.push(0x05);
    greeting.push(methods.len() as u8);
    greeting.extend_from_slice(methods);
    stream.write_all(&greeting).await?;
    stream.flush().await?;

    let mut selected = [0u8; 2];
    stream.read_exact(&mut selected).await?;
    if selected[0] != 0x05 {
        return Err(io::Error::other("SOCKS5 proxy returned invalid version"));
    }
    match selected[1] {
        0x00 => {}
        0x02 => send_socks5_username_password(stream, proxy).await?,
        0xff => {
            return Err(io::Error::other(
                "SOCKS5 proxy did not accept any offered authentication method",
            ));
        }
        method => {
            return Err(io::Error::other(format!(
                "SOCKS5 proxy selected unsupported authentication method 0x{method:02x}"
            )));
        }
    }

    let mut request = vec![0x05, 0x01, 0x00];
    write_socks5_address(&mut request, host, port, remote_dns)?;
    stream.write_all(&request).await?;
    stream.flush().await?;

    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != 0x05 {
        return Err(io::Error::other(
            "SOCKS5 proxy returned invalid CONNECT response version",
        ));
    }
    if header[1] != 0x00 {
        return Err(io::Error::other(format!(
            "SOCKS5 CONNECT failed with status 0x{:02x}",
            header[1]
        )));
    }
    read_socks5_bound_address(stream, header[3]).await?;
    Ok(())
}

#[cfg(feature = "http12")]
async fn send_socks5_username_password(
    stream: &mut tokio::net::TcpStream,
    proxy: &HttpProxyConfig,
) -> Result<(), io::Error> {
    let username = proxy.socks_username.as_deref().unwrap_or("");
    let password = proxy.socks_password.as_deref().unwrap_or("");
    let mut request = Vec::with_capacity(3 + username.len() + password.len());
    request.push(0x01);
    request.push(username.len() as u8);
    request.extend_from_slice(username.as_bytes());
    request.push(password.len() as u8);
    request.extend_from_slice(password.as_bytes());
    stream.write_all(&request).await?;
    stream.flush().await?;

    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await?;
    if response != [0x01, 0x00] {
        return Err(io::Error::other(
            "SOCKS5 username/password authentication failed",
        ));
    }
    Ok(())
}

#[cfg(feature = "http12")]
fn write_socks5_address(
    request: &mut Vec<u8>,
    host: &str,
    port: u16,
    remote_dns: bool,
) -> Result<(), io::Error> {
    let host = host.trim_matches(['[', ']']);
    if !remote_dns && let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(ip) => {
                request.push(0x01);
                request.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                request.push(0x04);
                request.extend_from_slice(&ip.octets());
            }
        }
        request.extend_from_slice(&port.to_be_bytes());
        return Ok(());
    }

    if host.len() > 255 {
        return Err(io::Error::other(
            "SOCKS5 domain targets must be 255 bytes or fewer",
        ));
    }
    request.push(0x03);
    request.push(host.len() as u8);
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    Ok(())
}

#[cfg(feature = "http12")]
async fn read_socks5_bound_address(
    stream: &mut tokio::net::TcpStream,
    atyp: u8,
) -> Result<(), io::Error> {
    match atyp {
        0x01 => {
            let mut buf = [0u8; 6];
            stream.read_exact(&mut buf).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut buf = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut buf).await?;
        }
        0x04 => {
            let mut buf = [0u8; 18];
            stream.read_exact(&mut buf).await?;
        }
        other => {
            return Err(io::Error::other(format!(
                "SOCKS5 proxy returned unsupported bound address type 0x{other:02x}"
            )));
        }
    }
    Ok(())
}

#[cfg(feature = "http12")]
fn build_tcp_client(config: &VaneClientConfig) -> Result<TcpClient, VaneError> {
    ensure_rustls_crypto_provider();
    let mut http = HttpConnector::new_with_resolver(StaticDnsResolver::new(&config.dns_overrides)?);
    http.enforce_http(false);
    http.set_connect_timeout(config.timeout_seconds.map(Duration::from_secs));
    http.set_keepalive(Some(Duration::from_secs(
        config.connection_idle_timeout_seconds,
    )));
    let proxy = ProxyConnector::new(http, config)?;

    let connector = match config.protocol_mode {
        VaneProtocolMode::Http1Only => HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .wrap_connector(proxy),
        VaneProtocolMode::Http2Only => HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http2()
            .wrap_connector(proxy),
        VaneProtocolMode::Http3Only
        | VaneProtocolMode::Http2ThenHttp1
        | VaneProtocolMode::Http3ThenHttp2ThenHttp1 => HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(proxy),
    };

    let mut builder = HyperClient::builder(TokioExecutor::new());
    builder.pool_timer(TokioTimer::new());
    builder.pool_idle_timeout(Duration::from_secs(config.connection_idle_timeout_seconds));
    builder.pool_max_idle_per_host(config.max_idle_connections as usize);
    if matches!(config.protocol_mode, VaneProtocolMode::Http2Only) {
        builder.http2_only(true);
    }

    Ok(builder.build(connector))
}

#[cfg(feature = "http12")]
fn build_tcp_headers(
    url: &Url,
    request: &VaneRequest,
    config: &VaneClientConfig,
) -> Result<HeaderMap, VaneError> {
    let mut headers = HeaderMap::new();
    let user_agent = config.user_agent.as_deref().unwrap_or("Vane/0.1.0");
    headers.insert(
        USER_AGENT,
        HeaderValue::from_str(user_agent)
            .map_err(|e| VaneError::Generic(format!("Invalid user-agent header: {e}")))?,
    );

    for (key, value) in &config.default_headers {
        insert_tcp_header(&mut headers, key, value)?;
    }
    for (key, value) in &request.headers {
        insert_tcp_header(&mut headers, key, value)?;
    }

    if let Some(host) = url.host_str() {
        let authority = match url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_string(),
        };
        headers.insert(
            HOST,
            HeaderValue::from_str(&authority)
                .map_err(|e| VaneError::Generic(format!("Invalid host header: {e}")))?,
        );
    }
    if url.scheme() == "http"
        && let Some(authorization) = config.proxy_authorization.as_deref()
    {
        headers.insert(
            PROXY_AUTHORIZATION,
            HeaderValue::from_str(authorization).map_err(|e| {
                VaneError::Generic(format!("Invalid proxy authorization header: {e}"))
            })?,
        );
    }

    Ok(headers)
}

#[cfg(feature = "http12")]
fn insert_tcp_header(headers: &mut HeaderMap, key: &str, value: &str) -> Result<(), VaneError> {
    if key.starts_with(':') {
        return Err(VaneError::Generic(format!(
            "HTTP pseudo-header cannot be set by callers: {key}"
        )));
    }

    let name = HeaderName::from_bytes(key.as_bytes())
        .map_err(|e| VaneError::Generic(format!("Invalid HTTP header name {key}: {e}")))?;
    let value = HeaderValue::from_str(value)
        .map_err(|e| VaneError::Generic(format!("Invalid HTTP header value for {key}: {e}")))?;
    headers.insert(name, value);
    Ok(())
}

#[cfg(feature = "http12")]
async fn collect_hyper_response(
    response: hyper::Response<Incoming>,
    url: &Url,
    max_response_body_bytes: u64,
) -> Result<TcpResponseParts, VaneError> {
    let final_url = url.to_string();
    let status_code = response.status().as_u16();
    let redirect_location = response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let mut headers = HashMap::new();
    let mut set_cookie_headers = Vec::new();
    for (name, value) in response.headers() {
        if name == SET_COOKIE {
            if let Ok(value) = value.to_str() {
                set_cookie_headers.push(value.to_string());
            }
        } else if let Ok(value) = value.to_str() {
            headers.insert(name.as_str().to_string(), value.to_string());
        }
    }

    let body = response
        .into_body()
        .collect()
        .await
        .map_err(|e| VaneError::Generic(format!("Failed to read HTTP/1.1/2 body: {e}")))?
        .to_bytes();
    validate_response_body_limit(0, body.len(), max_response_body_bytes)?;

    Ok(TcpResponseParts {
        status_code,
        headers,
        set_cookie_headers,
        redirect_location,
        body: body.to_vec(),
        url: final_url,
        cookie_url: url.clone(),
    })
}

#[cfg(feature = "http12")]
fn is_redirect_status(status_code: u16) -> bool {
    matches!(status_code, 301 | 302 | 303 | 307 | 308)
}

fn verify_certificate_pins(
    host: &str,
    peer_cert_der: Option<&[u8]>,
    config: &VaneClientConfig,
) -> Result<(), VaneError> {
    let Some(pins) = config.certificate_pins.get(host) else {
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
    finished: bool,
    max_body_bytes: u64,
}

impl H3ResponseState {
    fn new(max_body_bytes: u64) -> Self {
        Self {
            status_code: 0,
            headers: HashMap::new(),
            set_cookie_headers: Vec::new(),
            body: Vec::new(),
            finished: false,
            max_body_bytes,
        }
    }
}

fn process_h3_events(
    http3: &mut quiche::h3::Connection,
    conn: &mut quiche::Connection,
    response: &mut H3ResponseState,
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
                match http3.recv_body(conn, stream_id, &mut buf) {
                    Ok(read) => {
                        validate_response_body_limit(
                            response.body.len(),
                            read,
                            response.max_body_bytes,
                        )?;
                        response.body.extend_from_slice(&buf[..read]);
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
pub fn response_body_utf8(resp: &VaneResponse) -> Result<String, VaneError> {
    String::from_utf8(resp.body.clone())
        .map_err(|e| VaneError::Generic(format!("Invalid UTF-8 in response body: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "http12")]
    use std::io::{Read, Write};
    #[cfg(feature = "http12")]
    use std::net::TcpListener;
    #[cfg(feature = "http12")]
    use std::sync::mpsc;

    fn request(url: &str) -> VaneRequest {
        VaneRequest {
            url: url.to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
            body: None,
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

    #[cfg(feature = "http12")]
    fn live_proxy_config() -> Option<(String, Option<String>, String)> {
        let Ok(proxy_url) = std::env::var("VANE_TEST_PROXY_URL") else {
            eprintln!("Skipping Vane live proxy test. Set VANE_TEST_PROXY_URL.");
            return None;
        };
        let Some(base_url) = live_https_base_url() else {
            eprintln!("Skipping Vane live proxy test. VANE_TEST_BASE_URL is required.");
            return None;
        };
        let proxy_authorization = std::env::var("VANE_TEST_PROXY_AUTHORIZATION").ok();

        Some((proxy_url, proxy_authorization, base_url))
    }

    fn assert_response_body_contains(response: &VaneResponse, expected: &str) {
        let body = String::from_utf8_lossy(&response.body);
        assert!(
            body.contains(expected),
            "expected response body to contain {expected:?}, got {body}"
        );
    }

    #[cfg(feature = "http12")]
    fn spawn_single_request_proxy(response: &'static [u8]) -> (String, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();

        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while request.len() < 8192 {
                let read = stream.read(&mut byte).unwrap();
                if read == 0 {
                    break;
                }
                request.push(byte[0]);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            tx.send(String::from_utf8_lossy(&request).to_string())
                .unwrap();
            stream.write_all(response).unwrap();
            stream.flush().unwrap();
        });

        (format!("http://{addr}"), rx)
    }

    #[cfg(feature = "http12")]
    fn spawn_single_request_socks5_proxy(
        response: &'static [u8],
    ) -> (String, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();

        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            stream.write_all(&[0x05, 0x00]).unwrap();

            let mut header = [0u8; 4];
            stream.read_exact(&mut header).unwrap();
            assert_eq!(&header[..3], &[0x05, 0x01, 0x00]);
            let target = match header[3] {
                0x01 => {
                    let mut addr = [0u8; 4];
                    let mut port = [0u8; 2];
                    stream.read_exact(&mut addr).unwrap();
                    stream.read_exact(&mut port).unwrap();
                    format!(
                        "{}.{}.{}.{}:{}",
                        addr[0],
                        addr[1],
                        addr[2],
                        addr[3],
                        u16::from_be_bytes(port)
                    )
                }
                0x03 => {
                    let mut len = [0u8; 1];
                    stream.read_exact(&mut len).unwrap();
                    let mut host = vec![0u8; len[0] as usize];
                    let mut port = [0u8; 2];
                    stream.read_exact(&mut host).unwrap();
                    stream.read_exact(&mut port).unwrap();
                    format!(
                        "{}:{}",
                        String::from_utf8_lossy(&host),
                        u16::from_be_bytes(port)
                    )
                }
                other => panic!("unexpected SOCKS5 address type {other}"),
            };
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .unwrap();

            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while request.len() < 8192 {
                let read = stream.read(&mut byte).unwrap();
                if read == 0 {
                    break;
                }
                request.push(byte[0]);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            tx.send(format!("{target}\n{}", String::from_utf8_lossy(&request)))
                .unwrap();
            stream.write_all(response).unwrap();
            stream.flush().unwrap();
        });

        (format!("socks5h://{addr}"), rx)
    }

    #[test]
    fn default_config_uses_http3_with_tcp_fallback() {
        let config = VaneClientConfig::default();

        assert_eq!(
            config.protocol_mode,
            VaneProtocolMode::Http3ThenHttp2ThenHttp1
        );
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

    #[cfg(feature = "http12")]
    #[test]
    fn tcp_backend_rejects_certificate_pins_to_avoid_bypass() {
        let client = VaneClient::new(VaneClientConfig {
            protocol_mode: VaneProtocolMode::Http2ThenHttp1,
            certificate_pins: HashMap::from([(
                "api.example.com".to_string(),
                vec!["sha256/example".to_string()],
            )]),
            ..VaneClientConfig::default()
        })
        .unwrap();

        let err = client
            .execute(request("https://api.example.com/users"))
            .unwrap_err();

        assert!(err.to_string().contains("Certificate pinning"));
        assert!(err.to_string().contains("HTTP/3 backend"));
    }

    #[cfg(feature = "http12")]
    #[test]
    fn proxy_config_accepts_http_proxy_urls() {
        let proxy = parse_http_proxy_config(&VaneClientConfig {
            proxy_url: Some("http://proxy.example.com:8080".to_string()),
            proxy_authorization: Some("Basic dXNlcjpwYXNz".to_string()),
            ..VaneClientConfig::default()
        })
        .unwrap()
        .unwrap();

        assert_eq!(proxy.scheme, ProxyScheme::Http);
        assert_eq!(proxy.host, "proxy.example.com");
        assert_eq!(proxy.port, 8080);
        assert_eq!(proxy.authorization.as_deref(), Some("Basic dXNlcjpwYXNz"));
    }

    #[cfg(feature = "http12")]
    #[test]
    fn proxy_config_accepts_https_and_socks5_proxy_urls() {
        let https = parse_http_proxy_config(&VaneClientConfig {
            proxy_url: Some("https://secure-proxy.example.com".to_string()),
            proxy_authorization: Some("Bearer token".to_string()),
            ..VaneClientConfig::default()
        })
        .unwrap()
        .unwrap();
        let socks = parse_http_proxy_config(&VaneClientConfig {
            proxy_url: Some("socks5h://user:pass@socks.example.com:1081".to_string()),
            ..VaneClientConfig::default()
        })
        .unwrap()
        .unwrap();

        assert_eq!(https.scheme, ProxyScheme::Https);
        assert_eq!(https.host, "secure-proxy.example.com");
        assert_eq!(https.port, 443);
        assert_eq!(https.authorization.as_deref(), Some("Bearer token"));
        assert_eq!(socks.scheme, ProxyScheme::Socks5 { remote_dns: true });
        assert_eq!(socks.host, "socks.example.com");
        assert_eq!(socks.port, 1081);
        assert_eq!(socks.socks_username.as_deref(), Some("user"));
        assert_eq!(socks.socks_password.as_deref(), Some("pass"));
    }

    #[cfg(feature = "http12")]
    #[test]
    fn proxy_config_rejects_unsupported_proxy_urls() {
        let err = parse_http_proxy_config(&VaneClientConfig {
            proxy_url: Some("ftp://proxy.example.com:21".to_string()),
            ..VaneClientConfig::default()
        })
        .unwrap_err();

        assert!(err.to_string().contains("Unsupported proxy URL scheme"));
    }

    #[cfg(feature = "http12")]
    #[test]
    fn tcp_http_requests_are_forwarded_through_configured_proxy() {
        let (proxy_url, rx) = spawn_single_request_proxy(
            b"HTTP/1.1 207 Multi-Status\r\nContent-Length: 17\r\n\r\nproxied http body",
        );
        let client = VaneClient::new(VaneClientConfig {
            protocol_mode: VaneProtocolMode::Http1Only,
            proxy_url: Some(proxy_url),
            proxy_authorization: Some("Basic dXNlcjpwYXNz".to_string()),
            ..VaneClientConfig::default()
        })
        .unwrap();

        let response = client
            .execute(request("http://origin.example/proxy-path?x=1"))
            .unwrap();
        let proxied_request = rx.recv_timeout(Duration::from_secs(5)).unwrap();

        assert_eq!(response.status_code, 207);
        assert_eq!(String::from_utf8_lossy(&response.body), "proxied http body");
        assert!(
            proxied_request.starts_with("GET http://origin.example/proxy-path?x=1 HTTP/1.1"),
            "{proxied_request}"
        );
        assert!(proxied_request.contains("host: origin.example"));
        assert!(proxied_request.contains("proxy-authorization: Basic dXNlcjpwYXNz"));
    }

    #[cfg(feature = "http12")]
    #[test]
    fn tcp_https_requests_use_connect_with_proxy_authorization() {
        let (proxy_url, rx) =
            spawn_single_request_proxy(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
        let client = VaneClient::new(VaneClientConfig {
            protocol_mode: VaneProtocolMode::Http1Only,
            proxy_url: Some(proxy_url),
            proxy_authorization: Some("Bearer proxy-token".to_string()),
            ..VaneClientConfig::default()
        })
        .unwrap();

        let err = client
            .execute(request("https://secure.example/tunnel"))
            .unwrap_err();
        let connect_request = rx.recv_timeout(Duration::from_secs(5)).unwrap();

        assert!(err.to_string().contains("client error (Connect)"));
        assert!(connect_request.starts_with("CONNECT secure.example:443 HTTP/1.1"));
        assert!(connect_request.contains("Host: secure.example:443"));
        assert!(connect_request.contains("Proxy-Authorization: Bearer proxy-token"));
    }

    #[cfg(feature = "http12")]
    #[test]
    fn tcp_http_requests_can_use_socks5_proxy_tunnels() {
        let (proxy_url, rx) = spawn_single_request_socks5_proxy(
            b"HTTP/1.1 209 Content Returned\r\nContent-Length: 18\r\n\r\nproxied socks body",
        );
        let client = VaneClient::new(VaneClientConfig {
            protocol_mode: VaneProtocolMode::Http1Only,
            proxy_url: Some(proxy_url),
            ..VaneClientConfig::default()
        })
        .unwrap();

        let response = client
            .execute(request("http://origin.example/socks-path"))
            .unwrap();
        let observed = rx.recv_timeout(Duration::from_secs(5)).unwrap();

        assert_eq!(response.status_code, 209);
        assert_eq!(
            String::from_utf8_lossy(&response.body),
            "proxied socks body"
        );
        assert!(observed.starts_with("origin.example:80\n"));
        assert!(observed.contains("GET http://origin.example/socks-path HTTP/1.1"));
        assert!(observed.contains("host: origin.example"));
    }

    #[cfg(feature = "http12")]
    #[test]
    fn live_tcp_proxy_get_when_proxy_url_is_set() {
        let Some((proxy_url, proxy_authorization, base_url)) = live_proxy_config() else {
            return;
        };
        let client = VaneClient::new(VaneClientConfig {
            protocol_mode: VaneProtocolMode::Http2ThenHttp1,
            proxy_url: Some(proxy_url),
            proxy_authorization,
            timeout_seconds: Some(30),
            ..VaneClientConfig::default()
        })
        .unwrap();

        let response = client.execute(request(&base_url)).unwrap();

        assert!(
            (200..=399).contains(&response.status_code),
            "unexpected status from live proxy GET: {}",
            response.status_code
        );
    }

    #[cfg(feature = "http12")]
    #[test]
    fn http3_backend_rejects_proxy_configuration() {
        let client = VaneClient::new(VaneClientConfig {
            protocol_mode: VaneProtocolMode::Http3Only,
            proxy_url: Some("http://proxy.example.com:8080".to_string()),
            ..VaneClientConfig::default()
        })
        .unwrap();

        let err = client
            .execute(request("https://api.example.com/users"))
            .unwrap_err();

        assert!(err.to_string().contains("HTTP/3 proxying"));
        assert!(err.to_string().contains("MASQUE/CONNECT-UDP"));
    }

    #[cfg(not(feature = "http12"))]
    #[test]
    fn tcp_backend_reports_when_http12_feature_is_disabled() {
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
                .contains("without HTTP/1.1 and HTTP/2 support")
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
        let mut config = VaneClientConfig::default();
        config
            .certificate_pins
            .insert(host.to_string(), vec![sha256_pin("sha256-cert", cert_der)]);

        let result = verify_certificate_pins(host, Some(cert_der), &config);

        assert!(result.is_ok());
    }

    #[test]
    fn certificate_pinning_accepts_backup_pin() {
        let host = "api.example.com";
        let cert_der = b"fake certificate bytes";
        let mut config = VaneClientConfig::default();
        config.certificate_pins.insert(
            host.to_string(),
            vec![
                "sha256-cert/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
                sha256_pin("sha256-cert", cert_der),
            ],
        );

        let result = verify_certificate_pins(host, Some(cert_der), &config);

        assert!(result.is_ok());
    }

    #[test]
    fn certificate_pinning_rejects_mismatch() {
        let host = "api.example.com";
        let mut config = VaneClientConfig::default();
        config.certificate_pins.insert(
            host.to_string(),
            vec!["sha256-cert/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string()],
        );

        let err =
            verify_certificate_pins(host, Some(b"different certificate"), &config).unwrap_err();

        assert!(err.to_string().contains("Certificate pin mismatch"));
    }

    #[test]
    fn certificate_pinning_requires_peer_cert_when_configured() {
        let host = "api.example.com";
        let mut config = VaneClientConfig::default();
        config
            .certificate_pins
            .insert(host.to_string(), vec!["sha256/example".to_string()]);

        let err = verify_certificate_pins(host, None, &config).unwrap_err();

        assert!(err.to_string().contains("peer certificate was unavailable"));
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

    #[cfg(feature = "http12")]
    #[test]
    fn tcp_headers_include_defaults_and_request_overrides() {
        let mut config = VaneClientConfig::default();
        config
            .default_headers
            .insert("Authorization".to_string(), "Bearer default".to_string());
        let mut req = request("https://example.com/items");
        req.headers
            .insert("X-Trace-ID".to_string(), "abc123".to_string());
        let url = Url::parse("https://example.com/items").unwrap();

        let headers = build_tcp_headers(&url, &req, &config).unwrap();

        assert_eq!(
            headers.get(USER_AGENT).unwrap().to_str().unwrap(),
            "Vane/0.1.0"
        );
        assert_eq!(headers.get("authorization").unwrap(), "Bearer default");
        assert_eq!(headers.get("x-trace-id").unwrap(), "abc123");
        assert_eq!(headers.get(HOST).unwrap(), "example.com");
    }

    #[cfg(feature = "http12")]
    #[test]
    fn tcp_headers_include_proxy_authorization_for_plain_http_proxy_requests() {
        let config = VaneClientConfig {
            proxy_url: Some("http://proxy.example.com:8080".to_string()),
            proxy_authorization: Some("Basic dXNlcjpwYXNz".to_string()),
            ..VaneClientConfig::default()
        };
        let req = request("http://example.com/items");
        let url = Url::parse("http://example.com/items").unwrap();

        let headers = build_tcp_headers(&url, &req, &config).unwrap();

        assert_eq!(
            headers.get(PROXY_AUTHORIZATION).unwrap().to_str().unwrap(),
            "Basic dXNlcjpwYXNz"
        );
    }

    #[cfg(feature = "http12")]
    #[test]
    fn tcp_headers_do_not_send_proxy_authorization_to_https_origins() {
        let config = VaneClientConfig {
            proxy_url: Some("http://proxy.example.com:8080".to_string()),
            proxy_authorization: Some("Basic dXNlcjpwYXNz".to_string()),
            ..VaneClientConfig::default()
        };
        let req = request("https://example.com/items");
        let url = Url::parse("https://example.com/items").unwrap();

        let headers = build_tcp_headers(&url, &req, &config).unwrap();

        assert!(!headers.contains_key(PROXY_AUTHORIZATION));
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
            Instant::now()
        ));
        assert!(!cookie.matches(
            &Url::parse("http://api.example.com/v1/users").unwrap(),
            Instant::now()
        ));
        assert!(!cookie.matches(
            &Url::parse("https://api.example.com/v2/users").unwrap(),
            Instant::now()
        ));

        let delete = StoredCookie::parse(&url, "session=deleted; Path=/v1; Max-Age=0").unwrap();
        assert!(delete.is_expired(Instant::now()));
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

        let base_key = PoolKey::new(&url, &base);
        let dns_key = PoolKey::new(&url, &dns_config);

        assert_ne!(base_key, dns_key);
        assert_eq!(
            base_key.certificate_pins,
            vec!["sha256/a".to_string(), "sha256/b".to_string()]
        );
    }
}
