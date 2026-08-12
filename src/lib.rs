uniffi::setup_scaffolding!();

#[cfg(feature = "tcp-fallback")]
mod tcp;

/// In-process HTTP/3 test server plus its offline tests; also owns the test
/// CA that `create_quiche_config`'s test-only seam trusts.
#[cfg(test)]
mod h3_offline;

use std::borrow::Cow;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fs::{self, File};
use std::io;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
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
/// Ceiling on the up-front body reservation made from `content-length`. Keeps a
/// bodiless (HEAD, 304) or lying response from allocating the full body limit.
const MAX_BODY_RESERVE_BYTES: u64 = 1 << 20;
/// One datagram plus headroom. We advertise `MAX_DATAGRAM_SIZE` as our max
/// receive payload and read with plain connected-socket `recv` (no GRO), so a
/// conforming peer can never hand us more than that in one call.
const UDP_RECV_BUFFER_BYTES: usize = 2 * MAX_DATAGRAM_SIZE;
const H3_BODY_BUFFER_BYTES: usize = 16 * 1024;
const MASQUE_CONTROL_BUFFER_BYTES: usize = 4096;
/// Used when the outer connection reports no datagram capacity; quiche's own
/// minimum outgoing UDP payload is 1200.
const MASQUE_INNER_FALLBACK_UDP_PAYLOAD: usize = 1200;
/// ponytail: naive bound — when the store is full it is cleared wholesale
/// rather than evicting the least-recently-used entry. A client talking to more
/// than this many origins just pays full handshakes. Swap in an LRU only if
/// that shows up in a profile.
const MAX_TLS_SESSIONS: usize = 8;
/// ponytail: same naive bound as the session store. The MASQUE inner payload is
/// measured per connection (it depends on the server's DCID length and crypto
/// overhead), so the key space is not a fixed pair of constants. Swap in an LRU
/// only if config rebuilds show up in a profile.
const MAX_QUIC_CONFIGS: usize = 8;
/// Flat ceiling on the cookie jar; see `store_response_cookies`.
const MAX_COOKIES: usize = 512;
/// Ceiling on the body of a 3xx that is still a candidate for following.
///
/// The TCP path never reads an intermediate body at all (reqwest drops it), so
/// without this a hostile origin answering ten 302s with a 64 MiB body each
/// would cost ~700 MiB of metered data over HTTP/3 and nothing over TCP. A
/// redirect stub does not need more than this; a 3xx that exceeds it fails the
/// request rather than being followed.
const MAX_INTERMEDIATE_BODY_BYTES: u64 = 64 * 1024;
/// Ceiling on one HTTP/3 response header section, advertised to the peer as
/// `SETTINGS_MAX_FIELD_SECTION_SIZE` and enforced by quiche on receipt.
///
/// Without it the only bound is the 1 MiB stream flow-control window, which a
/// hostile peer can fill with header bytes that all land in the response map
/// before flow control stalls. 64 KiB is far above any legitimate header
/// block (servers commonly cap *request* header sections at 8-16 KiB) and
/// well under the flow window, so an oversized block is rejected cleanly
/// instead of being buffered.
const MAX_RESPONSE_HEADER_SECTION_BYTES: u64 = 64 * 1024;
/// Redirect hops allowed when `follow_redirects` is on. Shared by both
/// transports: the hop cap is a security bound, not a transport detail.
const MAX_REDIRECTS: usize = 10;
/// Caller-supplied headers allowed to survive a redirect to a different origin.
///
/// Everything else — API keys, bearer tokens, tenant ids — is dropped: reqwest
/// strips only a fixed list of well-known auth headers, so a custom
/// `X-Api-Key` would otherwise be handed straight to the redirect target.
const CROSS_ORIGIN_SAFE_HEADERS: [&str; 4] =
    ["accept", "accept-language", "content-type", "user-agent"];
/// Headers the transport owns. Hop-by-hop names are illegal on HTTP/3
/// (RFC 9114 4.2), and a caller-supplied framing header lets a request be
/// framed differently by us and by an intermediary.
const RESERVED_HEADERS: [&str; 9] = [
    "connection",
    "content-length",
    "host",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

static CANCEL_TOKENS: LazyLock<Mutex<HashMap<u64, Arc<AtomicBool>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static NEXT_CANCEL_TOKEN_ID: AtomicU64 = AtomicU64::new(1);
static PROGRESS_STATES: LazyLock<Mutex<HashMap<u64, Arc<VaneProgressState>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static NEXT_PROGRESS_ID: AtomicU64 = AtomicU64::new(1);

/// Shared progress counters for one request. The global map only resolves ids
/// to handles; the transfer loop writes the atomics directly so it never takes
/// a lock per chunk.
#[derive(Debug, Default)]
struct VaneProgressState {
    upload_sent: AtomicU64,
    upload_total: AtomicU64,
    download_received: AtomicU64,
    download_total: AtomicU64,
    done: AtomicBool,
}

impl VaneProgressState {
    fn reset(&self, upload_total: u64) {
        self.done.store(false, Ordering::Relaxed);
        self.upload_sent.store(0, Ordering::Relaxed);
        self.upload_total.store(upload_total, Ordering::Relaxed);
        self.download_received.store(0, Ordering::Relaxed);
        self.download_total.store(0, Ordering::Relaxed);
    }
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
        // Schemes are case-insensitive; "HTTPS://host/" is legal.
        let scheme = scheme.to_ascii_lowercase();
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
            scheme,
            host,
            port,
            path,
            query,
        })
    }

    fn join(&self, input: &str) -> Result<Self, String> {
        // Absoluteness is decided by a scheme before the first path/query
        // separator, not by "://" appearing anywhere: a relative target like
        // `/login?return_to=https://app.example.com/` is the single most common
        // SSO shape and must not be mistaken for an absolute URL.
        if has_url_scheme(input) {
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

/// True when `input` starts with a URL scheme, i.e. a `:` that comes before any
/// `/`, `?` or `#` and is preceded only by scheme characters.
fn has_url_scheme(input: &str) -> bool {
    let Some(colon) = input.find([':', '/', '?', '#']) else {
        return false;
    };
    if input.as_bytes()[colon] != b':' || colon == 0 {
        return false;
    }
    input[..colon]
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
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
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err("bracketed host must be an IPv6 address".to_string());
        }
        // Hex case is meaningless in an IPv6 literal, and every host-keyed
        // security lookup stores lowercase (`set_certificate_pins_internal`
        // lowercases on write; cookies lowercase on compare) — a case-preserved
        // "[2001:DB8::A]" would silently miss a pin registered for the same
        // address and connect unpinned.
        return Ok((format!("[{host}]").to_ascii_lowercase(), port));
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
    // Every security decision downstream — certificate pins, cross-origin
    // header stripping, cookie scoping — keys off this host, but the bytes we
    // hand to a transport get re-parsed by that transport's own URL parser.
    // Anything the two parsers could spell differently (backslash, tab,
    // percent-escape, control characters) would let those decisions be made
    // about a host we never actually connect to, so only the characters that
    // are unambiguously part of a hostname are allowed through.
    let host = host.to_ascii_lowercase();
    if !host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        return Err(format!("URL host contains unsupported characters: {host}"));
    }

    Ok((host, port))
}

fn parse_port(port: &str) -> Result<u16, String> {
    // `u16::from_str` accepts a leading '+'. The non-bracketed authority path
    // screens for digits before calling, but the IPv6 path does not, so the
    // digit rule lives here: a port is all ASCII digits or it is not a port —
    // anything looser is a spelling another URL parser may read differently.
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("invalid URL port {port}: not a decimal number"));
    }
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
    /// One entry per header name, keyed lowercase. A name the server repeated
    /// carries its values comma-joined in wire order (`"a, b"`, RFC 9110
    /// §5.2) — identically on both transports. Two exceptions: `set-cookie`
    /// (see [`Self::set_cookie`]) and `location`, which is single-valued by
    /// RFC 9110 §10.2.2 and keeps its first occurrence — the one the redirect
    /// gate acts on — rather than joining into a non-URL.
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub body_file_path: Option<String>,
    pub is_success: bool,
    pub url: String,
    /// Raw `Set-Cookie` values from the final response, in wire order.
    ///
    /// Unfiltered: a cookie the jar refused (a `Domain` that is a public
    /// suffix, or an IP literal) still appears here, because this reports what
    /// the server sent. Never folded into `headers` — a `HashMap` cannot hold
    /// repeats and RFC 6265 forbids comma-joining `Set-Cookie` (an `Expires`
    /// value contains a comma, so the join is unsplittable).
    ///
    /// Redirects: the final response only. Intermediate hops still reach the
    /// cookie jar as before.
    #[uniffi(default = [])]
    pub set_cookie: Vec<String>,
    /// Protocol that served the final response. `None` when no exchange
    /// completed, or when the transport could not say.
    #[uniffi(default = None)]
    pub http_version: Option<VaneHttpVersion>,
}

/// Protocol a response was actually served over, as opposed to the
/// [`VaneProtocolMode`] the request asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum VaneHttpVersion {
    Http10,
    Http11,
    Http2,
    Http3,
}

impl VaneHttpVersion {
    /// Wire code for `VaneFfiResponse::http_version`. 0 means "not known" and
    /// is written by `ffi_error_response`. Append only, never renumber: a
    /// shipped Dart build decodes these by value.
    fn ffi_code(self) -> u8 {
        match self {
            VaneHttpVersion::Http10 => 1,
            VaneHttpVersion::Http11 => 2,
            VaneHttpVersion::Http2 => 3,
            VaneHttpVersion::Http3 => 4,
        }
    }
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
    /// HTTP/3 first, falling back to HTTP/2 or HTTP/1.1 over TCP when the
    /// HTTP/3 transport fails. Needs the `tcp-fallback` build feature.
    Http3ThenHttp2ThenHttp1,
    Http3Only,
    /// TCP with ALPN negotiating HTTP/2 or HTTP/1.1. Needs `tcp-fallback`.
    Http2ThenHttp1,
    /// TCP with HTTP/2 prior knowledge. Needs `tcp-fallback`.
    Http2Only,
    /// TCP restricted to HTTP/1.1. Needs `tcp-fallback`.
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
            connection_pool_enabled: true,
            max_idle_connections: 4,
            // Under a real server's: measured keep-alive close at ~28.9 s on
            // github.com, and servers do not advertise `Keep-Alive: timeout=N`
            // in practice. Sitting above the peer's timeout is the worst place
            // to be — every pooled checkout races the peer's close.
            connection_idle_timeout_seconds: 25,
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
/// The variant is the machine-readable kind; every one carries the same
/// human-readable message the caller has always seen, so `Display` output and
/// catch-all handling are unchanged. `Generic` means "not classified", not
/// "internal" — new call sites may land there and callers must treat it as
/// unknown rather than as any particular failure.
///
/// No variant carries structured detail beyond the message: a `Tls` mismatch
/// deliberately exposes no host or pin field, so error handling cannot become a
/// pin oracle.
#[derive(Debug, Clone, Error, uniffi::Error)]
pub enum VaneError {
    #[error("{0}")]
    Generic(String),
    /// The caller's request or configuration is wrong — URL, scheme, method,
    /// header, body file, pin or proxy setting. Fails identically on every
    /// transport.
    #[error("{0}")]
    InvalidRequest(String),
    /// The request's cancel token was set.
    #[error("{0}")]
    Cancelled(String),
    /// The connection could not be established within the deadline. Nothing
    /// reached the peer, so the request is safe to replay.
    #[error("{0}")]
    ConnectTimeout(String),
    /// The deadline expired with the connection already up.
    #[error("{0}")]
    Timeout(String),
    /// Network or protocol failure: DNS, socket, QUIC, HTTP/3 framing, proxy.
    #[error("{0}")]
    Transport(String),
    /// Certificate verification failed, including a pin mismatch.
    #[error("{0}")]
    Tls(String),
    /// A request or response body exceeded the configured limit.
    #[error("{0}")]
    BodyLimitExceeded(String),
    /// The requested protocol is not available in this build.
    #[error("{0}")]
    ProtocolUnsupported(String),
}

impl VaneError {
    /// Whether another transport could plausibly do better. A request or config
    /// error fails the same way over TCP, a pin mismatch fails the same way by
    /// design, and a cancelled request must stay cancelled. `Generic` is
    /// included because it means "unclassified": excluding it would silently
    /// drop the fallback for every call site not yet classified.
    fn is_transport_failure(&self) -> bool {
        matches!(
            self,
            VaneError::Generic(_)
                | VaneError::ConnectTimeout(_)
                | VaneError::Timeout(_)
                | VaneError::Transport(_)
        )
    }

    /// The attempt provably never put the request on the wire, so replaying it
    /// on another transport is safe even for a non-idempotent method.
    ///
    /// ponytail: only the handshake deadline qualifies. A handshake that failed
    /// for another reason ("QUIC connection closed before handshake completed")
    /// also sent nothing, but classifying that needs a `Connect` variant no
    /// caller would branch on. Add it if POST-over-blocked-UDP shows up as
    /// something other than a timeout.
    fn never_left_the_client(&self) -> bool {
        matches!(self, VaneError::ConnectTimeout(_))
    }

    /// Same kind, different message. Used where two failures are reported as
    /// one so the surviving kind is the one the caller can act on.
    fn with_message(self, message: String) -> Self {
        match self {
            VaneError::Generic(_) => VaneError::Generic(message),
            VaneError::InvalidRequest(_) => VaneError::InvalidRequest(message),
            VaneError::Cancelled(_) => VaneError::Cancelled(message),
            VaneError::ConnectTimeout(_) => VaneError::ConnectTimeout(message),
            VaneError::Timeout(_) => VaneError::Timeout(message),
            VaneError::Transport(_) => VaneError::Transport(message),
            VaneError::Tls(_) => VaneError::Tls(message),
            VaneError::BodyLimitExceeded(_) => VaneError::BodyLimitExceeded(message),
            VaneError::ProtocolUnsupported(_) => VaneError::ProtocolUnsupported(message),
        }
    }

    /// Stable numeric kind for the C ABI. These values are part of that ABI:
    /// append only, never renumber. 0 doubles as "no error" on a successful
    /// response, which is unambiguous because callers only read the kind when
    /// the error buffer is non-empty.
    fn ffi_kind(&self) -> u32 {
        match self {
            VaneError::Generic(_) => 0,
            VaneError::InvalidRequest(_) => 1,
            VaneError::Cancelled(_) => 2,
            VaneError::ConnectTimeout(_) => 3,
            VaneError::Timeout(_) => 4,
            VaneError::Transport(_) => 5,
            VaneError::Tls(_) => 6,
            VaneError::BodyLimitExceeded(_) => 7,
            VaneError::ProtocolUnsupported(_) => 8,
        }
    }
}

impl From<quiche::Error> for VaneError {
    fn from(err: quiche::Error) -> Self {
        VaneError::Transport(format!("QUIC error: {err:?}"))
    }
}

impl From<quiche::h3::Error> for VaneError {
    fn from(err: quiche::h3::Error) -> Self {
        VaneError::Transport(format!("HTTP/3 error: {err:?}"))
    }
}

impl From<io::Error> for VaneError {
    fn from(err: io::Error) -> Self {
        VaneError::Transport(format!("I/O error: {err}"))
    }
}

#[cfg(not(feature = "tcp-fallback"))]
fn unsupported_tcp_backend_error() -> VaneError {
    VaneError::ProtocolUnsupported(
        "This Vane build supports HTTP/3 only; HTTP/1.1 and HTTP/2 fallback were removed"
            .to_string(),
    )
}

/// Cached `quiche::Config`s keyed by `(max-idle-timeout millis, max send UDP
/// payload)` — the only per-connection settings on them. Building one re-reads
/// the platform CA bundle, which is a whole directory scan on Android. Bounded
/// in practice by the handful of distinct timeouts an application uses, times
/// the two payload sizes (direct/outer vs MASQUE inner).
type QuicConfigCache = Mutex<HashMap<(u64, usize), quiche::Config>>;

/// Serialized TLS session tickets for TLS 1.3 resumption. Ticket reuse only —
/// 0-RTT/early data is never enabled (replay risk).
type TlsSessionStore = Mutex<HashMap<TlsSessionKey, Vec<u8>>>;

/// What a stored ticket is scoped to.
///
/// A resumed TLS 1.3 handshake performs no certificate verification, so a
/// ticket must never be offered to anything but the exact peer that minted it.
/// Host alone is not that peer: a different port can be a different terminator,
/// and the proxy hop and the origin are different trust contexts even when they
/// share a hostname.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TlsSessionKey {
    host: String,
    port: u16,
    proxy_hop: bool,
}

impl TlsSessionKey {
    fn origin(host: &str, port: u16) -> Self {
        Self {
            host: host.to_string(),
            port,
            proxy_hop: false,
        }
    }

    fn proxy(host: &str, port: u16) -> Self {
        Self {
            host: host.to_string(),
            port,
            proxy_hop: true,
        }
    }
}

// ---------- Client ----------
#[derive(uniffi::Object)]
pub struct VaneClient {
    config: VaneClientConfig,
    pool: Mutex<Vec<PooledHttp3Connection>>,
    cookie_jar: Mutex<Vec<StoredCookie>>,
    certificate_pins: Mutex<HashMap<String, Vec<String>>>,
    quic_config: QuicConfigCache,
    tls_sessions: TlsSessionStore,
    /// Built on first TCP use so HTTP/3-only applications never spin up a tokio
    /// runtime, and cleared whenever the pins it was built with change.
    #[cfg(feature = "tcp-fallback")]
    tcp_client: Mutex<Option<tcp::SharedTcpClient>>,
}

impl VaneClient {
    pub fn new(config: VaneClientConfig) -> Result<Self, VaneError> {
        // One rule for both transports, checked once at construction: which
        // transport ends up carrying a request depends on network conditions,
        // so the proxy posture must not.
        if let Some(proxy_url) = config.proxy_url.as_deref() {
            let proxy = Url::parse(proxy_url).map_err(|e| {
                VaneError::InvalidRequest(format!(
                    "Invalid proxyUrl {}: {e}",
                    redact_url_userinfo(proxy_url)
                ))
            })?;
            if proxy.scheme() != "https" {
                return Err(VaneError::InvalidRequest(
                    "proxyUrl must use https://: a plaintext proxy exposes the CONNECT target \
                     and proxyAuthorization on the local network"
                        .to_string(),
                ));
            }
        }
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
            quic_config: Mutex::new(HashMap::new()),
            tls_sessions: Mutex::new(HashMap::new()),
            #[cfg(feature = "tcp-fallback")]
            tcp_client: Mutex::new(None),
        })
    }

    pub fn execute(&self, request: VaneRequest) -> Result<VaneResponse, VaneError> {
        let url = self.build_url(&request)?;
        self.reject_unsupported_protocol_mode()?;
        // Loaded once for every attempt on every transport: neither a retry nor
        // a fallback may re-read the body file (it can change underneath us) or
        // re-copy an in-memory body.
        let request_body = load_request_body(&request, self.config.max_request_body_bytes)?;
        validate_request_body_limit(
            request_body.len() as u64,
            self.config.max_request_body_bytes,
        )?;
        let body = request_body.as_ref();

        let result = self.dispatch(&request, &url, body);
        // Marked done once, when the caller-visible request ends. Doing it per
        // transport attempt would flip `done` true between the HTTP/3 failure
        // and the TCP fallback, and a poller that latched it would stop early.
        progress_done(progress_handle(request.progress_id).as_deref());
        result
    }

    /// Like [`Self::execute`], but returns as soon as the final response's
    /// headers are in, leaving the body to be pulled incrementally from the
    /// returned [`VaneResponseStream`].
    ///
    /// Everything up to the headers behaves exactly like `execute`: the same
    /// redirect chain (intermediate 3xx bodies are drained internally), the
    /// same retry policy and HTTP/3-to-TCP fallback (both apply only until
    /// headers are delivered — a stream, once returned, is never silently
    /// replayed), the same cookie and pin handling, and the shared deadline
    /// for reaching the headers. The response body limit still applies,
    /// cumulatively across chunks. `response_body_path` is refused: the
    /// stream replaces the file escape hatch.
    ///
    /// Takes `self: Arc<Self>` because the stream keeps the client alive to
    /// return its connection to the pool when the body is drained.
    pub fn execute_streaming(
        self: Arc<Self>,
        request: VaneRequest,
    ) -> Result<VaneResponseStream, VaneError> {
        let result = Self::execute_streaming_inner(&self, &request);
        if result.is_err() {
            // Parity with `execute`: a request that failed before its stream
            // existed is over. A live stream instead latches `done` when it
            // terminates — that is when the transfer actually ends.
            progress_done(progress_handle(request.progress_id).as_deref());
        }
        result
    }

    fn execute_streaming_inner(
        this: &Arc<Self>,
        request: &VaneRequest,
    ) -> Result<VaneResponseStream, VaneError> {
        if request
            .response_body_path
            .as_deref()
            .is_some_and(|path| !path.is_empty())
        {
            return Err(VaneError::InvalidRequest(
                "responseBodyPath cannot be combined with a streaming request; \
                 read the stream instead"
                    .to_string(),
            ));
        }
        let url = this.build_url(request)?;
        this.reject_unsupported_protocol_mode()?;
        let request_body = load_request_body(request, this.config.max_request_body_bytes)?;
        validate_request_body_limit(
            request_body.len() as u64,
            this.config.max_request_body_bytes,
        )?;
        let body = request_body.as_ref();

        this.dispatch_via(
            request,
            || Self::execute_http3_streaming(this, request, &url, body),
            || this.execute_tcp_streaming(request, &url, body),
        )
    }

    /// Without the TCP backend the TCP-only modes cannot work; fail before
    /// touching the request body file.
    fn reject_unsupported_protocol_mode(&self) -> Result<(), VaneError> {
        #[cfg(not(feature = "tcp-fallback"))]
        if matches!(
            self.config.protocol_mode,
            VaneProtocolMode::Http2ThenHttp1
                | VaneProtocolMode::Http2Only
                | VaneProtocolMode::Http1Only
        ) {
            return Err(unsupported_tcp_backend_error());
        }
        Ok(())
    }

    fn dispatch(
        &self,
        request: &VaneRequest,
        url: &Url,
        body: &[u8],
    ) -> Result<VaneResponse, VaneError> {
        self.dispatch_via(
            request,
            || self.execute_http3(request, url, body),
            || self.execute_tcp(request, url, body),
        )
    }

    /// The protocol-mode routing and HTTP/3-to-TCP fallback rules, shared by
    /// the buffered and streaming entry points so the two can never disagree
    /// about when a fallback is safe. The closures run one full transport
    /// attempt each (retry policy included).
    fn dispatch_via<R>(
        &self,
        request: &VaneRequest,
        http3: impl Fn() -> Result<R, VaneError>,
        tcp: impl Fn() -> Result<R, VaneError>,
    ) -> Result<R, VaneError> {
        match self.config.protocol_mode {
            VaneProtocolMode::Http3Only => http3(),
            VaneProtocolMode::Http3ThenHttp2ThenHttp1 => {
                let http3 = http3();
                // Only a transport failure falls through: an HTTP status is a
                // successful exchange, and a cancelled request must stay
                // cancelled rather than being replayed over TCP.
                //
                // ponytail: sequential, so a dead HTTP/3 path costs up to two
                // timeouts. Happy-eyeballs-style racing is the upgrade path.
                match http3 {
                    Ok(response) => Ok(response),
                    Err(err) if !self.tcp_fallback_enabled() => Err(err),
                    // A body over the limit, a missing body file or a pin
                    // mismatch fails exactly the same way over TCP, so trying
                    // costs a second full timeout and changes nothing.
                    Err(err) if !err.is_transport_failure() => Err(err),
                    // A method the retry policy refuses to replay must not be
                    // replayed by the fallback either. HTTP/3 can fail *after*
                    // the server accepted the request — connection lost
                    // mid-response — so re-sending a POST here would create the
                    // resource a second time. A handshake that never completed
                    // put nothing on the wire, which is the case that matters:
                    // on a UDP-blocked network that is how every request fails.
                    Err(err)
                        if !err.never_left_the_client()
                            && !is_retryable_method(
                                &request.method,
                                self.config.retry_unsafe_methods,
                            ) =>
                    {
                        Err(err)
                    }
                    Err(err) => {
                        if check_cancelled(cancel_token(request.cancel_token_id).as_deref())
                            .is_err()
                        {
                            return Err(err);
                        }
                        tcp().map_err(|tcp_err| {
                            // Both transports failed: reporting only one of
                            // them sends whoever debugs this down the wrong
                            // path. The kind kept is the TCP one — that is the
                            // attempt the caller's request actually died on.
                            let message = format!(
                                "HTTP/3 transport failed ({err}); TCP fallback also failed \
                                 ({tcp_err})"
                            );
                            tcp_err.with_message(message)
                        })
                    }
                }
            }
            VaneProtocolMode::Http2ThenHttp1
            | VaneProtocolMode::Http2Only
            | VaneProtocolMode::Http1Only => tcp(),
        }
    }

    fn execute_http3(
        &self,
        request: &VaneRequest,
        url: &Url,
        body: &[u8],
    ) -> Result<VaneResponse, VaneError> {
        self.execute_with_retry(request, || self.follow_http3_redirects(request, url, body))
    }

    /// One attempt: the redirect chain. Each hop is a full HTTP/3 request
    /// (`execute_http3_once`, which owns the stale-pooled-connection retry), so
    /// the retry policy, the redirect chain and the connection-reuse retry stay
    /// three separate loops.
    ///
    /// Mirrors `tcp::follow_and_read`, including every rule in it.
    fn follow_http3_redirects(
        &self,
        request: &VaneRequest,
        url: &Url,
        request_body: &[u8],
    ) -> Result<VaneResponse, VaneError> {
        let timeout = Duration::from_secs(
            request
                .timeout_seconds
                .or(self.config.timeout_seconds)
                .unwrap_or(30),
        );
        let cancel_token = cancel_token(request.cancel_token_id);
        // Once per attempt, not per hop: resetting the counters mid-chain would
        // walk a progress bar backwards. `execute` marks the request done once
        // the whole dispatch resolves.
        let progress = progress_init(request.progress_id, request_body.len() as u64);
        // Snapshotted once so a concurrent `set_certificate_pins` cannot change
        // what the hop gate allows halfway down a chain.
        let certificate_pins = self.certificate_pins_snapshot()?;

        RedirectChain {
            request,
            certificate_pins: &certificate_pins,
            cancel_token: cancel_token.as_deref(),
            progress: progress.as_deref(),
            timeouts: HopTimeouts {
                // One deadline for the whole chain, shared by every stage of
                // every hop. Applying the timeout per hop would let a hostile
                // server hold a caller thread for hop-cap times the requested
                // timeout, and the retry loop multiplies that again.
                deadline: Instant::now() + timeout,
                idle: timeout,
            },
        }
        .run(url, request_body, |hop| {
            self.execute_http3_once(
                request,
                hop,
                &certificate_pins,
                cancel_token.as_deref(),
                progress.as_deref(),
            )
        })
    }

    /// Streaming twin of [`Self::execute_http3`]: the same retry policy over
    /// streaming attempts. A retried attempt's stream is dropped, which tears
    /// its connection down; nothing of its body was ever handed out.
    fn execute_http3_streaming(
        this: &Arc<Self>,
        request: &VaneRequest,
        url: &Url,
        body: &[u8],
    ) -> Result<VaneResponseStream, VaneError> {
        this.execute_with_retry(request, || {
            Self::follow_http3_redirects_streaming(this, request, url, body)
        })
    }

    /// Streaming twin of [`Self::follow_http3_redirects`]: the identical chain
    /// (same [`RedirectChain`], same deadline, same refusal rules) over
    /// streaming hops. Only the hop the gate declares final becomes the public
    /// stream; every intermediate is drained and dropped inside the chain.
    fn follow_http3_redirects_streaming(
        this: &Arc<Self>,
        request: &VaneRequest,
        url: &Url,
        request_body: &[u8],
    ) -> Result<VaneResponseStream, VaneError> {
        let timeout = Duration::from_secs(
            request
                .timeout_seconds
                .or(this.config.timeout_seconds)
                .unwrap_or(30),
        );
        let cancel_token = cancel_token(request.cancel_token_id);
        let progress = progress_init(request.progress_id, request_body.len() as u64);
        let certificate_pins = this.certificate_pins_snapshot()?;

        let hop_result = RedirectChain {
            request,
            certificate_pins: &certificate_pins,
            cancel_token: cancel_token.as_deref(),
            progress: progress.as_deref(),
            timeouts: HopTimeouts {
                // One deadline bounds the whole chain up to the final
                // headers, exactly as it bounds the buffered chain. The body
                // is then paced by the caller: each pull gets the configured
                // timeout as its inactivity budget instead.
                deadline: Instant::now() + timeout,
                idle: timeout,
            },
        }
        .run(url, request_body, |hop| {
            this.execute_http3_hop(
                request,
                hop,
                &certificate_pins,
                cancel_token.as_deref(),
                progress.as_deref(),
                H3HopMode::Streaming { client: this },
            )?
            .expect_stream()
        })?;
        Ok(hop_result.into_stream(cancel_token, progress))
    }

    #[cfg(feature = "tcp-fallback")]
    fn tcp_fallback_enabled(&self) -> bool {
        true
    }

    #[cfg(not(feature = "tcp-fallback"))]
    fn tcp_fallback_enabled(&self) -> bool {
        false
    }

    #[cfg(feature = "tcp-fallback")]
    fn execute_tcp(
        &self,
        request: &VaneRequest,
        url: &Url,
        body: &[u8],
    ) -> Result<VaneResponse, VaneError> {
        self.execute_with_retry(request, || tcp::execute_tcp_once(self, request, url, body))
    }

    #[cfg(not(feature = "tcp-fallback"))]
    fn execute_tcp(
        &self,
        _request: &VaneRequest,
        _url: &Url,
        _body: &[u8],
    ) -> Result<VaneResponse, VaneError> {
        Err(unsupported_tcp_backend_error())
    }

    #[cfg(feature = "tcp-fallback")]
    fn execute_tcp_streaming(
        &self,
        request: &VaneRequest,
        url: &Url,
        body: &[u8],
    ) -> Result<VaneResponseStream, VaneError> {
        self.execute_with_retry(request, || {
            tcp::execute_tcp_streaming_once(self, request, url, body)
        })
    }

    #[cfg(not(feature = "tcp-fallback"))]
    fn execute_tcp_streaming(
        &self,
        _request: &VaneRequest,
        _url: &Url,
        _body: &[u8],
    ) -> Result<VaneResponseStream, VaneError> {
        Err(unsupported_tcp_backend_error())
    }

    /// The fallible core behind [`Self::warmup`], split out so tests (and a
    /// Rust caller who wants to know) can see what actually happened.
    ///
    /// Warms exactly the transports the configured [`VaneProtocolMode`] can
    /// use, so `Http3Only` never touches the TCP machinery (no tokio runtime,
    /// no platform verifier) and a TCP-only mode never dials QUIC. Repeat
    /// calls are cheap: the TCP client build is cached, and the HTTP/3
    /// pre-connect is skipped while a live pooled connection exists.
    fn warmup_inner(&self, url: Option<&str>) -> Result<(), VaneError> {
        let target = match url.or(self.config.base_url.as_deref()) {
            Some(raw) => {
                let parsed = Url::parse(raw)
                    .map_err(|e| VaneError::InvalidRequest(format!("Invalid warmup URL: {e}")))?;
                // The same rule every transport enforces; failing here beats a
                // probe that dials a cleartext port.
                if parsed.scheme() != "https" {
                    return Err(VaneError::InvalidRequest(
                        "Vane only supports https:// URLs".to_string(),
                    ));
                }
                Some(parsed)
            }
            // No URL and no baseUrl: nothing to connect to, but construction
            // (the TCP arm below) is still worth paying for.
            None => None,
        };

        match self.config.protocol_mode {
            VaneProtocolMode::Http3Only => match &target {
                Some(url) => self.warmup_http3(url),
                None => Ok(()),
            },
            VaneProtocolMode::Http3ThenHttp2ThenHttp1 => {
                let h3 = match &target {
                    Some(url) => self.warmup_http3(url),
                    None => Ok(()),
                };
                // TCP is this mode's fallback: warming it moves the ~1 s
                // construction cost off the worst possible moment — right
                // after an HTTP/3 transport failure. Both arms always run;
                // the first failure is the one reported.
                h3.and(self.warmup_tcp(target.as_ref(), false))
            }
            VaneProtocolMode::Http2ThenHttp1
            | VaneProtocolMode::Http2Only
            | VaneProtocolMode::Http1Only => self.warmup_tcp(target.as_ref(), true),
        }
    }

    #[cfg(feature = "tcp-fallback")]
    fn warmup_tcp(&self, url: Option<&Url>, _tcp_required: bool) -> Result<(), VaneError> {
        tcp::warmup(self, url)
    }

    /// Without the backend, a TCP-only mode gets the same refusal `execute`
    /// gives it — warmup must not look like it worked — while the fallback
    /// mode is HTTP/3-only in practice and has nothing to warm.
    #[cfg(not(feature = "tcp-fallback"))]
    fn warmup_tcp(&self, _url: Option<&Url>, tcp_required: bool) -> Result<(), VaneError> {
        if tcp_required {
            Err(unsupported_tcp_backend_error())
        } else {
            Ok(())
        }
    }

    /// Establishes one HTTP/3 connection — QUIC + TLS handshake and the H3
    /// preamble, no HTTP request — and parks it in the pool for the first
    /// real request to reuse. Goes through [`Self::connect_http3`], so DNS
    /// overrides, certificate pins, TLS session resumption and a MASQUE proxy
    /// all behave exactly as they would for a request.
    fn warmup_http3(&self, url: &Url) -> Result<(), VaneError> {
        // Nowhere to keep the connection: dialing one just to close it again
        // would be pure startup cost.
        if !self.config.connection_pool_enabled || self.config.max_idle_connections == 0 {
            return Ok(());
        }
        let host = url
            .host_str()
            .ok_or_else(|| VaneError::InvalidRequest("URL is missing host".to_string()))?;
        let certificate_pins = self.certificate_pins_snapshot()?;
        let key = PoolKey::new(url, &self.config, &certificate_pins);
        {
            let pool = self
                .pool
                .lock()
                .map_err(|_| VaneError::Generic("Connection pool lock was poisoned".to_string()))?;
            // ponytail: two racing warmups can still both dial and pool two
            // connections; max_idle_connections caps the damage and the spare
            // idles out. A build-in-flight flag if that ever matters.
            if pool
                .iter()
                .any(|conn| conn.key == key && !conn.conn.is_closed())
            {
                return Ok(());
            }
        }
        let peer_addr = resolve_peer_addr(
            host,
            url.port_or_known_default().unwrap_or(443),
            &self.config.dns_overrides,
        )?;
        let timeout = Duration::from_secs(self.config.timeout_seconds.unwrap_or(30));
        let timeouts = HopTimeouts {
            deadline: Instant::now() + timeout,
            idle: timeout,
        };
        let connection = self.connect_http3(host, peer_addr, timeouts, key, &certificate_pins)?;
        self.return_pooled_connection(connection)
    }

    fn build_url(&self, request: &VaneRequest) -> Result<Url, VaneError> {
        let url = &request.url;
        if let Some(base) = &self.config.base_url {
            let base_url = Url::parse(base)
                .map_err(|e| VaneError::InvalidRequest(format!("Invalid base URL: {e}")))?;
            let mut url = base_url
                .join(url)
                .map_err(|e| VaneError::InvalidRequest(format!("Failed to join URL: {e}")))?;
            append_query_params(&mut url, &request.query_params);
            Ok(url)
        } else {
            let mut url = Url::parse(url)
                .map_err(|e| VaneError::InvalidRequest(format!("Invalid URL: {e}")))?;
            append_query_params(&mut url, &request.query_params);
            Ok(url)
        }
    }

    /// Runs one transport's attempt closure under the shared retry policy.
    /// Generic over the delivery mode: a streaming attempt whose status the
    /// policy retries is simply dropped — nothing of its body was handed out,
    /// and dropping a live stream tears its connection down.
    fn execute_with_retry<R: RedirectHopResponse>(
        &self,
        request: &VaneRequest,
        attempt_once: impl Fn() -> Result<R, VaneError>,
    ) -> Result<R, VaneError> {
        let max_attempts = self.config.retry_max_attempts.max(1);
        let mut attempt = 1u64;
        let mut last_error = None;

        while attempt <= max_attempts {
            match attempt_once() {
                Ok(response) => {
                    if should_retry_response(
                        &request.method,
                        response.status_code(),
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

    /// One buffered hop; see [`Self::execute_http3_hop`].
    fn execute_http3_once(
        &self,
        request: &VaneRequest,
        hop: &Http3Hop<'_>,
        certificate_pins: &HashMap<String, Vec<String>>,
        cancel_token: Option<&AtomicBool>,
        progress: Option<&VaneProgressState>,
    ) -> Result<(VaneResponse, u64), VaneError> {
        let parts = self
            .execute_http3_hop(
                request,
                hop,
                certificate_pins,
                cancel_token,
                progress,
                H3HopMode::Buffered,
            )?
            .expect_response()?;
        let body_len = parts.body_len;
        Ok((parts.into_public_response(), body_len))
    }

    /// One hop. Everything here is keyed off `hop.url`, so a redirect to another
    /// host gets its own pool key, its own TLS session key and its own resolved
    /// address without any of them having to know a chain is in progress.
    ///
    /// `mode` picks the delivery: [`H3HopMode::Buffered`] reads the whole body
    /// before returning (the historical behavior), [`H3HopMode::Streaming`]
    /// stops at the response headers and hands the live transport out — except
    /// for a followable 3xx, whose body is an intermediate the caller never
    /// asked for and is drained buffered exactly as before.
    fn execute_http3_hop(
        &self,
        request: &VaneRequest,
        hop: &Http3Hop<'_>,
        certificate_pins: &HashMap<String, Vec<String>>,
        cancel_token: Option<&AtomicBool>,
        progress: Option<&VaneProgressState>,
        mode: H3HopMode<'_>,
    ) -> Result<H3HopOutcome, VaneError> {
        let url = hop.url;
        let request_body = hop.body;
        if url.scheme() != "https" {
            return Err(VaneError::InvalidRequest(
                "quiche backend only supports https:// URLs over HTTP/3".to_string(),
            ));
        }
        let host = url
            .host_str()
            .ok_or_else(|| VaneError::InvalidRequest("URL is missing host".to_string()))?;
        if let Some(proxy_url) = self.config.proxy_url.as_deref() {
            MasqueProxyConfig::parse(proxy_url)?;
        }
        let peer_addr = resolve_peer_addr(
            host,
            url.port_or_known_default().unwrap_or(443),
            &self.config.dns_overrides,
        )?;
        let cookie_header = if self.config.cookies_enabled {
            // Re-derived per hop: cookies are scoped by host and path, so the
            // header built for the first URL is wrong for a redirect target.
            Some(self.cookie_header(url)?)
        } else {
            None
        };
        let headers = build_h3_headers(
            url,
            request,
            &self.config,
            hop.method,
            hop.origin,
            cookie_header.as_deref(),
            hop.body_dropped,
        )?;
        let pool_key = PoolKey::new(url, &self.config, certificate_pins);
        let mut allow_pooled = self.config.connection_pool_enabled;

        loop {
            // Re-derived each time round: the stale-connection retry below runs
            // a second full connect and request, and must not get a fresh
            // budget for them.
            let remaining = hop.timeouts.remaining("request")?;
            let pooled = if allow_pooled {
                self.take_pooled_connection(&pool_key, remaining)?
            } else {
                None
            };
            let reused = pooled.is_some();
            let mut transport = match pooled {
                Some(connection) => connection,
                None => self
                    .connect_http3(
                        host,
                        peer_addr,
                        hop.timeouts,
                        pool_key.clone(),
                        certificate_pins,
                    )
                    .inspect_err(|_| {
                        self.drop_closed_connections();
                    })?,
            };

            let mut response_started = false;
            let options = H3RequestOptions {
                headers: &headers,
                request_body,
                deadline: hop.timeouts.deadline,
                url,
                max_response_body_bytes: self.config.max_response_body_bytes,
                response_body_path: request.response_body_path.as_deref(),
                cancel_token,
                progress,
                report_upload: hop.report_upload,
                redirect_possible: hop.redirect_possible,
            };
            let result = (|| {
                let mut exchange = begin_h3_exchange(&mut transport, &options)?;
                let until = match mode {
                    H3HopMode::Buffered => H3DriveUntil::ResponseFinished,
                    H3HopMode::Streaming { .. } => H3DriveUntil::HeadersComplete,
                };
                drive_h3_exchange(
                    &mut transport,
                    &options,
                    &mut exchange,
                    &mut response_started,
                    until,
                )?;
                // A followable 3xx's body is an intermediate: drain it under
                // the intermediate cap so the connection stays clean, exactly
                // as the buffered path always has.
                if exchange.response.is_intermediate_redirect() && !exchange.response.finished {
                    drive_h3_exchange(
                        &mut transport,
                        &options,
                        &mut exchange,
                        &mut response_started,
                        H3DriveUntil::ResponseFinished,
                    )?;
                }
                Ok(exchange)
            })();
            match result {
                Ok(mut exchange) => {
                    if self.config.cookies_enabled {
                        self.store_response_cookies(url, &exchange.response.set_cookie_headers)?;
                    }
                    // The server's NewSessionTicket normally lands after the
                    // handshake loop already returned, so this is the point
                    // where a resumable ticket actually exists. For a live
                    // stream this is also the last guaranteed look at the
                    // connection state before the caller paces it; a ticket
                    // that arrives mid-body is not banked.
                    store_tls_session(
                        &self.tls_sessions,
                        &transport.conn,
                        &TlsSessionKey::origin(host, peer_addr.port()),
                        certificate_pins,
                    );

                    return match mode {
                        H3HopMode::Buffered => {
                            self.park_or_close_h3(transport)?;
                            Ok(H3HopOutcome::Response(Http3ResponseParts {
                                body_len: exchange.response.body_len as u64,
                                status_code: exchange.response.status_code,
                                headers: exchange.response.headers,
                                set_cookie_headers: exchange.response.set_cookie_headers,
                                body: exchange.response.body,
                                body_file_path: exchange.response.body_file_path,
                                url: url.to_string(),
                            }))
                        }
                        H3HopMode::Streaming { client } => {
                            let downloaded = exchange.response.body_len as u64;
                            let head = streaming_head(
                                &mut exchange.response,
                                url,
                                Some(VaneHttpVersion::Http3),
                            );
                            let source = if exchange.response.finished {
                                // Whole body already read: an intermediate 3xx
                                // always, and any final response small enough
                                // to arrive with its headers. Nothing keeps
                                // the transport, so it can be parked now.
                                self.park_or_close_h3(transport)?;
                                StreamingBodySource::Buffered(std::mem::take(
                                    &mut exchange.response.body,
                                ))
                            } else {
                                // The caller's body is copied only when the
                                // server answered before the upload finished,
                                // so the continuation can keep sending without
                                // walking the upload counters backwards.
                                let request_body = if exchange.body_offset >= request_body.len() {
                                    Vec::new()
                                } else {
                                    request_body.to_vec()
                                };
                                let body_offset = exchange.body_offset.min(request_body.len());
                                StreamingBodySource::H3(Box::new(H3BodyStream {
                                    client: Arc::clone(client),
                                    transport: Some(transport),
                                    state: exchange.response,
                                    stream_id: exchange.stream_id,
                                    request_body,
                                    body_offset,
                                    report_upload: hop.report_upload,
                                    idle: hop.timeouts.idle,
                                }))
                            };
                            Ok(H3HopOutcome::Stream {
                                hop: StreamingHopResult { head, source },
                                downloaded,
                            })
                        }
                    };
                }
                Err(err) => {
                    transport.conn.close(true, 0x01, b"request failed").ok();
                    transport.flush_packets().ok();

                    // A pooled connection that died silently (NAT rebind, server
                    // idle timeout shorter than ours, GOAWAY) only fails once we
                    // try to use it. No response byte arrived, so the request was
                    // never processed and retrying once on a fresh connection is
                    // safe even for non-idempotent methods. `allow_pooled` is
                    // cleared first, so this can happen at most once. A cancelled
                    // request must not pay for another handshake to fail again.
                    if reused && !response_started && check_cancelled(cancel_token).is_ok() {
                        allow_pooled = false;
                        continue;
                    }

                    return Err(err);
                }
            }
        }
    }

    /// Returns a connection whose response was fully read to the pool, or
    /// closes it when pooling is off. Shared by the buffered hop and the
    /// streaming completion so the two can never disagree on reusability.
    fn park_or_close_h3(&self, mut transport: PooledHttp3Connection) -> Result<(), VaneError> {
        if self.config.connection_pool_enabled && !transport.conn.is_closed() {
            self.return_pooled_connection(transport)
        } else {
            transport.conn.close(true, 0x00, b"done").ok();
            transport.flush_packets().ok();
            Ok(())
        }
    }

    fn connect_http3(
        &self,
        host: &str,
        peer_addr: SocketAddr,
        timeouts: HopTimeouts,
        key: PoolKey,
        certificate_pins: &HashMap<String, Vec<String>>,
    ) -> Result<PooledHttp3Connection, VaneError> {
        if let Some(proxy_url) = self.config.proxy_url.as_deref() {
            return self.connect_http3_via_masque(
                host,
                peer_addr,
                proxy_url,
                timeouts,
                key,
                certificate_pins,
            );
        }

        let direct = connect_quic_h3(
            host,
            peer_addr,
            timeouts,
            certificate_pins,
            &self.quic_config,
            &self.tls_sessions,
            &TlsSessionKey::origin(host, peer_addr.port()),
        )?;
        Ok(PooledHttp3Connection {
            key,
            io: Http3Io::Direct {
                socket: direct.socket,
                last_read_timeout: None,
                recv_buf: vec![0; UDP_RECV_BUFFER_BYTES],
            },
            local_addr: direct.local_addr,
            peer_addr: direct.peer_addr,
            conn: direct.conn,
            http3: direct.http3,
            last_used: Instant::now(),
            send_buf: vec![0; MAX_DATAGRAM_SIZE],
            body_buf: vec![0; H3_BODY_BUFFER_BYTES],
        })
    }

    fn connect_http3_via_masque(
        &self,
        host: &str,
        peer_addr: SocketAddr,
        proxy_url: &str,
        timeouts: HopTimeouts,
        key: PoolKey,
        certificate_pins: &HashMap<String, Vec<String>>,
    ) -> Result<PooledHttp3Connection, VaneError> {
        let proxy = MasqueProxyConfig::parse(proxy_url)?;
        let proxy_addr = resolve_peer_addr(&proxy.host, proxy.port, &self.config.dns_overrides)?;
        let mut outer = connect_quic_h3(
            &proxy.host,
            proxy_addr,
            timeouts,
            certificate_pins,
            &self.quic_config,
            &self.tls_sessions,
            &TlsSessionKey::proxy(&proxy.host, proxy.port),
        )?;
        let stream_id = establish_connect_udp_tunnel(
            &mut outer,
            &proxy,
            host,
            peer_addr.port(),
            self.config.proxy_authorization.as_deref(),
            timeouts.remaining("proxy tunnel setup")?,
        )?;
        // The proxy's ticket usually only arrives during tunnel establishment,
        // after `connect_quic_h3` already returned.
        store_tls_session(
            &self.tls_sessions,
            &outer.conn,
            &TlsSessionKey::proxy(&proxy.host, proxy.port),
            certificate_pins,
        );

        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        getrandom::fill(&mut scid).map_err(|e| {
            VaneError::Generic(format!("Failed to generate QUIC connection ID: {e}"))
        })?;
        let scid = quiche::ConnectionId::from_ref(&scid);
        let mut conn = quic_connect(
            &self.quic_config,
            host,
            &scid,
            outer.local_addr,
            peer_addr,
            timeouts.idle,
            masque_inner_udp_payload(&outer.conn, stream_id / 4),
        )?;
        resume_tls_session(
            &self.tls_sessions,
            &mut conn,
            &TlsSessionKey::origin(host, peer_addr.port()),
            certificate_pins,
        );
        let h3_config = create_h3_config()?;
        let mut io = Http3Io::Masque(Box::new(MasqueTunnel {
            socket: outer.socket,
            local_addr: outer.local_addr,
            peer_addr: outer.peer_addr,
            conn: outer.conn,
            http3: outer.http3,
            stream_id,
            flow_id: stream_id / 4,
            last_read_timeout: None,
            recv_buf: vec![0; UDP_RECV_BUFFER_BYTES],
            send_buf: vec![0; MAX_DATAGRAM_SIZE],
            dgram_buf: vec![0; MAX_DATAGRAM_SIZE],
            control_buf: vec![0; MASQUE_CONTROL_BUFFER_BYTES],
        }));

        let mut send_buf = vec![0; MAX_DATAGRAM_SIZE];
        flush_quic_packets_via(&mut io, &mut send_buf, &mut conn)?;
        let deadline = timeouts.deadline;

        while Instant::now() < deadline {
            read_quic_packets_via(&mut io, &mut conn, outer.local_addr, peer_addr)?;

            if conn.is_established() {
                verify_certificate_pins(host, conn.peer_cert(), certificate_pins)?;
                store_tls_session(
                    &self.tls_sessions,
                    &conn,
                    &TlsSessionKey::origin(host, peer_addr.port()),
                    certificate_pins,
                );
                let http3 = quiche::h3::Connection::with_transport(&mut conn, &h3_config)?;
                return Ok(PooledHttp3Connection {
                    key,
                    io,
                    local_addr: outer.local_addr,
                    peer_addr,
                    conn,
                    http3,
                    last_used: Instant::now(),
                    send_buf,
                    body_buf: vec![0; H3_BODY_BUFFER_BYTES],
                });
            }

            flush_quic_packets_via(&mut io, &mut send_buf, &mut conn)?;

            if conn.is_closed() {
                return Err(VaneError::Transport(
                    "QUIC connection closed before handshake completed".to_string(),
                ));
            }
        }

        Err(VaneError::ConnectTimeout(
            "HTTP/3 handshake timed out".to_string(),
        ))
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
        // Every lookup lowercases, so storing "API.Example.com" verbatim would
        // create a pin that can never match — a silently unpinned host.
        let host = host.to_ascii_lowercase();
        // Stored tickets for this host were minted under the old trust context,
        // and a resumed handshake would skip the certificate exchange the new
        // pins need to be checked against. Drops every port and hop role for
        // the host, since pins are configured per host.
        self.tls_sessions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|key, _| key.host != host);
        {
            // The TCP client's TLS verifier holds a snapshot of the pins, so it
            // has to be rebuilt rather than reused with a stale pin set. The
            // guard is held across the pins write, and the lock order here
            // (tcp_client -> certificate_pins) matches `shared_client`: without
            // that, a build racing this invalidation could publish a client
            // carrying the pre-change pins and never be rebuilt, silently
            // dropping to platform-verification-only for the process lifetime.
            #[cfg(feature = "tcp-fallback")]
            let mut tcp_client = self
                .tcp_client
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            #[cfg(feature = "tcp-fallback")]
            tcp_client.take();

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
                    // ponytail: oldest-first eviction at a flat cap, not
                    // per-domain quotas as RFC 6265 5.3 suggests. A redirect
                    // chain can plant one cookie per hop, so the jar needs
                    // *some* bound; refine if a real workload needs it.
                    if jar.len() >= MAX_COOKIES {
                        jar.remove(0);
                    }
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

/// The two clocks one hop runs on.
#[derive(Debug, Clone, Copy)]
struct HopTimeouts {
    /// The whole request's deadline, shared by every hop and every stage inside
    /// a hop. An `Instant`, not a `Duration`: a duration gets re-anchored to
    /// `Instant::now()` by each stage that receives it, so handshake, tunnel
    /// setup and request would each get a full budget and a hostile peer could
    /// hold a caller for several multiples of the requested timeout.
    deadline: Instant,
    /// The caller's configured timeout, which becomes the connection's QUIC idle
    /// timeout. Deliberately not `remaining`: the quiche config cache is keyed on
    /// it, so a value that shrinks per hop would rebuild the config — reloading
    /// the platform roots — and evict the cache on every hop. It is also a
    /// property of the connection, which outlives the request in the pool.
    idle: Duration,
}

impl HopTimeouts {
    /// Time left before the shared deadline, or `Err(Timeout)` once it is gone.
    /// Every stage that arms a socket or starts a loop asks for this rather than
    /// carrying a budget of its own.
    fn remaining(&self, what: &str) -> Result<Duration, VaneError> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(VaneError::Timeout(format!("HTTP/3 {what} timed out")));
        }
        Ok(remaining)
    }
}

/// What the redirect chain and the retry policy need to know about one hop's
/// response — implemented by the buffered [`VaneResponse`], by the streaming
/// hop result, and by [`VaneResponseStream`], so the chain, the retry loop and
/// the transport-fallback logic stay single-sourced instead of forking per
/// delivery mode.
trait RedirectHopResponse {
    fn status_code(&self) -> u16;
    /// The `location` header value the shared gate acts on. `merge_header`
    /// keeps `location` first-wins (a repeat never joins), so this is the
    /// first occurrence's whole value on every implementation.
    fn location(&self) -> Option<&str>;
    /// Marks a 3xx that Vane refused to follow, so a caller cannot mistake it
    /// for "the server simply sent a redirect" and re-follow the `Location` by
    /// hand — which would defeat the pin or the downgrade rule that stopped it.
    fn mark_refused(&mut self, reason: &'static str);
}

impl RedirectHopResponse for VaneResponse {
    fn status_code(&self) -> u16 {
        self.status_code
    }

    fn location(&self) -> Option<&str> {
        header_value(&self.headers, "location")
    }

    fn mark_refused(&mut self, reason: &'static str) {
        self.headers
            .insert(REDIRECT_REFUSED_HEADER.to_string(), reason.to_string());
    }
}

/// Everything a redirect chain needs that does not change between hops.
///
/// Split from the hop executor so the loop — hop counting, the method and body
/// rewrites, the shared deadline, the refusal reporting and the replay-safety
/// downgrade — is drivable with a stub and therefore testable without a
/// network. Every finding that reached production in this loop was in the part
/// only a live server could reach.
struct RedirectChain<'a> {
    request: &'a VaneRequest,
    certificate_pins: &'a HashMap<String, Vec<String>>,
    cancel_token: Option<&'a AtomicBool>,
    progress: Option<&'a VaneProgressState>,
    timeouts: HopTimeouts,
}

impl RedirectChain<'_> {
    /// `hop` performs one request and reports how many body bytes it read (the
    /// body itself may have gone to a file, so the response cannot be asked).
    fn run<R: RedirectHopResponse>(
        &self,
        url: &Url,
        request_body: &[u8],
        mut hop: impl FnMut(&Http3Hop<'_>) -> Result<(R, u64), VaneError>,
    ) -> Result<R, VaneError> {
        let origin = (
            url.host_str().unwrap_or_default().to_string(),
            origin_port(url),
        );
        let mut current = url.clone();
        let mut method = self.request.method.clone();
        let mut body = request_body;
        let mut body_dropped = false;
        let mut hops = 0usize;

        loop {
            check_cancelled(self.cancel_token)?;
            self.timeouts.remaining("request")?;

            let (response, downloaded) = hop(&Http3Hop {
                url: &current,
                method: &method,
                body,
                body_dropped,
                origin: (&origin.0, origin.1),
                timeouts: self.timeouts,
                // The caller's body is uploaded once, on the first hop.
                // Reporting a replayed body's bytes from zero again would walk
                // the upload counter backwards.
                report_upload: hops == 0,
                redirect_possible: self.request.follow_redirects && hops < MAX_REDIRECTS,
            })
            .map_err(|err| withdraw_replay_safety(err, hops))?;

            // The trait's `location` is the first occurrence's whole value —
            // the same thing the TCP path's `HeaderMap::get` feeds the shared
            // gate. No splitting here: a lone malformed value goes to the
            // gate verbatim and both transports agree on its fate.
            let next = match next_redirect_url(
                response.status_code(),
                response.location(),
                &current,
                self.request,
                hops,
                self.certificate_pins,
            ) {
                RedirectDecision::Stop => return Ok(self.finish(response, downloaded)),
                RedirectDecision::Refused(reason) => {
                    let mut response = response;
                    response.mark_refused(reason);
                    return Ok(self.finish(response, downloaded));
                }
                RedirectDecision::Follow(next) => next,
            };

            let cross_origin = (next.host_str().unwrap_or_default(), origin_port(&next))
                != (
                    current.host_str().unwrap_or_default(),
                    origin_port(&current),
                );
            match redirect_rewrite(
                response.status_code(),
                &method,
                !body.is_empty(),
                cross_origin,
            ) {
                RedirectRewrite::Refuse => {
                    let mut response = response;
                    response.mark_refused(REDIRECT_REFUSED_CROSS_ORIGIN_BODY);
                    return Ok(self.finish(response, downloaded));
                }
                RedirectRewrite::ToGet => {
                    method = "GET".to_string();
                    body = &[];
                    body_dropped = true;
                }
                RedirectRewrite::Keep => {}
            }
            current = next;
            hops += 1;
        }
    }

    /// Publishes the download figure for the hop that turned out to be the
    /// final one. Streaming progress is suppressed while a 3xx could still be
    /// followed, so a 3xx the gate then refuses would otherwise be handed to
    /// the caller having reported nothing at all before `done` latches. For a
    /// live streaming hop `downloaded` is only the prefix read so far; the
    /// per-chunk reporting then keeps counting from it.
    fn finish<R>(&self, response: R, downloaded: u64) -> R {
        progress_download(self.progress, downloaded, downloaded);
        response
    }
}

/// Withdraws the "this attempt provably never left the client" claim once a hop
/// has been answered.
///
/// `ConnectTimeout` is only produced by a handshake deadline, which `dispatch`
/// reads as "nothing was sent, so the TCP fallback may replay it even for a
/// non-idempotent method". That is true of hop 0 and false of every hop after
/// it: hop 0's request was delivered and answered, so replaying the chain from
/// the start would submit it twice. `Timeout` is still a transport failure, so
/// an idempotent request still falls back.
fn withdraw_replay_safety(err: VaneError, hops: usize) -> VaneError {
    match err {
        VaneError::ConnectTimeout(message) if hops > 0 => VaneError::Timeout(message),
        err => err,
    }
}

/// One hop of an HTTP/3 request: everything a redirect chain changes between
/// hops. A request that never redirects is simply a chain of one.
struct Http3Hop<'a> {
    url: &'a Url,
    /// Uppercased; a 303 rewrites it to GET.
    method: &'a str,
    body: &'a [u8],
    /// Set once a rewrite dropped the body, so a caller `content-type` goes too.
    body_dropped: bool,
    /// Host and port the caller addressed. Caller headers are cut to
    /// [`CROSS_ORIGIN_SAFE_HEADERS`] once this hop leaves it.
    origin: (&'a str, u16),
    timeouts: HopTimeouts,
    /// False after the first hop: the caller's body is uploaded once.
    report_upload: bool,
    /// True while a 3xx from this hop could still be followed, which makes its
    /// body an intermediate the caller never asked for.
    redirect_possible: bool,
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
    /// Drive-loop scratch, allocated once per connection instead of being
    /// zeroed on every iteration. Heap-backed so moving the connection in and
    /// out of the pool stays a pointer move.
    send_buf: Vec<u8>,
    body_buf: Vec<u8>,
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
        flush_quic_packets_via(&mut self.io, &mut self.send_buf, &mut self.conn)
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
    Direct {
        socket: UdpSocket,
        /// Last value armed on the socket, so an unchanged read deadline does
        /// not cost a `setsockopt` on every read.
        last_read_timeout: Option<Duration>,
        recv_buf: Vec<u8>,
    },
    Masque(Box<MasqueTunnel>),
}

impl Http3Io {
    fn set_write_timeout(&self, timeout: Duration) -> Result<(), VaneError> {
        match self {
            Self::Direct { socket, .. } => socket
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
    last_read_timeout: Option<Duration>,
    /// Same hoist as `PooledHttp3Connection`: the tunnel drives its own socket
    /// once per outer packet, so these must not be per-call stack buffers.
    recv_buf: Vec<u8>,
    send_buf: Vec<u8>,
    dgram_buf: Vec<u8>,
    control_buf: Vec<u8>,
}

impl MasqueTunnel {
    fn send_origin_packet(&mut self, packet: &[u8]) -> Result<(), VaneError> {
        let datagram = encode_h3_datagram(self.flow_id, 0, packet)?;
        self.conn.dgram_send(&datagram)?;
        flush_quic_packets(&self.socket, &mut self.send_buf, &mut self.conn)
    }

    fn read_origin_packets(
        &mut self,
        origin_conn: &mut quiche::Connection,
        origin_local_addr: SocketAddr,
        origin_peer_addr: SocketAddr,
    ) -> Result<(), VaneError> {
        read_quic_packets(
            &self.socket,
            &mut self.last_read_timeout,
            &mut self.recv_buf,
            &mut self.conn,
            self.local_addr,
            self.peer_addr,
        )?;
        process_masque_control_events(
            &mut self.http3,
            &mut self.conn,
            &mut self.control_buf,
            self.stream_id,
        )?;

        let buf = &mut self.dgram_buf;
        loop {
            match self.conn.dgram_recv(&mut buf[..]) {
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
    /// Bytes read for this response, whether they went to memory or to the
    /// caller's file. The public response cannot be asked once a file was used.
    body_len: u64,
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
            set_cookie: self.set_cookie_headers,
            // `create_quiche_config` offers only `h3::APPLICATION_PROTOCOL`,
            // and the MASQUE path uses the same h3-only config on both hops,
            // so an `Http3ResponseParts` cannot have been served over anything
            // else.
            http_version: Some(VaneHttpVersion::Http3),
        }
    }
}

// ---------- Streaming response delivery ----------

/// How an HTTP/3 hop delivers its body; see [`VaneClient::execute_http3_hop`].
#[derive(Clone, Copy)]
enum H3HopMode<'a> {
    Buffered,
    Streaming { client: &'a Arc<VaneClient> },
}

/// What [`VaneClient::execute_http3_hop`] produced. The variant is dictated by
/// the [`H3HopMode`], so the `expect_*` accessors can only miss on a Vane bug.
enum H3HopOutcome {
    Response(Http3ResponseParts),
    Stream {
        hop: StreamingHopResult,
        /// Body bytes read while producing the hop: the whole body for a
        /// drained intermediate, only the prefix for a live stream.
        downloaded: u64,
    },
}

impl H3HopOutcome {
    fn expect_response(self) -> Result<Http3ResponseParts, VaneError> {
        match self {
            H3HopOutcome::Response(parts) => Ok(parts),
            H3HopOutcome::Stream { .. } => Err(VaneError::Generic(
                "Buffered HTTP/3 hop produced a stream".to_string(),
            )),
        }
    }

    fn expect_stream(self) -> Result<(StreamingHopResult, u64), VaneError> {
        match self {
            H3HopOutcome::Stream { hop, downloaded } => Ok((hop, downloaded)),
            H3HopOutcome::Response(_) => Err(VaneError::Generic(
                "Streaming HTTP/3 hop produced a buffered response".to_string(),
            )),
        }
    }
}

/// One streaming hop's result: the response head plus the body source that
/// will serve it. The redirect chain drives this through
/// [`RedirectHopResponse`]; only the hop that turns out to be final is wrapped
/// into the public [`VaneResponseStream`]. An intermediate hop the chain
/// follows is simply dropped, which is free: an intermediate is always a
/// drained [`StreamingBodySource::Buffered`], never a live transport.
struct StreamingHopResult {
    /// `body` is empty by contract; the stream delivers it.
    head: VaneResponse,
    source: StreamingBodySource,
}

impl StreamingHopResult {
    fn into_stream(
        self,
        cancel: Option<Arc<AtomicBool>>,
        progress: Option<Arc<VaneProgressState>>,
    ) -> VaneResponseStream {
        VaneResponseStream {
            head: self.head,
            body: Mutex::new(StreamingBody {
                source: self.source,
                terminal: None,
                cancel,
                progress,
            }),
        }
    }
}

impl RedirectHopResponse for StreamingHopResult {
    fn status_code(&self) -> u16 {
        self.head.status_code
    }

    fn location(&self) -> Option<&str> {
        header_value(&self.head.headers, "location")
    }

    fn mark_refused(&mut self, reason: &'static str) {
        self.head.mark_refused(reason);
    }
}

/// Builds the caller-visible head off a response whose headers are complete,
/// leaving the body (and the body counters) behind for the stream. Trailers a
/// live stream receives later merge into the drained state and are discarded:
/// the head was already handed out.
fn streaming_head(
    state: &mut ResponseState,
    url: &Url,
    http_version: Option<VaneHttpVersion>,
) -> VaneResponse {
    VaneResponse {
        status_code: state.status_code,
        headers: std::mem::take(&mut state.headers),
        body: Vec::new(),
        body_file_path: None,
        is_success: (200..=299).contains(&state.status_code),
        url: url.to_string(),
        set_cookie: std::mem::take(&mut state.set_cookie_headers),
        http_version,
    }
}

/// An HTTP response whose headers have arrived and whose body is read
/// incrementally by the caller.
///
/// Pull-based on purpose: the core never reads ahead of the caller, so a slow
/// consumer stalls the peer through QUIC flow control / the TCP receive
/// window instead of buffering without bound. `read_chunk` blocks until body
/// bytes arrive, the body ends (`None`), or the stream fails — a transport
/// error after the headers were delivered surfaces here, not as a failed
/// request. Abandoning the stream (`close`, or dropping it) discards the
/// underlying connection; only a stream read to its end returns the
/// connection to the pool.
pub struct VaneResponseStream {
    head: VaneResponse,
    body: Mutex<StreamingBody>,
}

impl VaneResponseStream {
    /// The response head: status, headers, final URL, cookies, protocol.
    /// `body` is empty by contract — the stream itself delivers it.
    pub fn head(&self) -> VaneResponse {
        self.head.clone()
    }

    /// Blocks until the next body chunk arrives and returns it; `Ok(None)`
    /// once the body is complete. Chunk boundaries carry no meaning.
    ///
    /// A pull that sees no data for roughly the request's timeout fails with
    /// [`VaneError::Timeout`]. After any error the stream is dead: the
    /// connection has been discarded and every later pull repeats the same
    /// error. After `close`, pulls return `Ok(None)`.
    pub fn read_chunk(&self) -> Result<Option<Vec<u8>>, VaneError> {
        let mut body = self
            .body
            .lock()
            .map_err(|_| VaneError::Generic("Response stream lock was poisoned".to_string()))?;
        if let Some(terminal) = &body.terminal {
            return match terminal {
                StreamTerminal::Eof | StreamTerminal::Closed => Ok(None),
                StreamTerminal::Failed(err) => Err(err.clone()),
            };
        }
        let cancel = body.cancel.clone();
        let progress = body.progress.clone();
        if let Err(err) = check_cancelled(cancel.as_deref()) {
            return Err(body.fail(err));
        }
        match body.source.next(cancel.as_deref(), progress.as_deref()) {
            Ok(BodyStep::Chunk(chunk)) => Ok(Some(chunk)),
            Ok(BodyStep::Eof) => {
                progress_done(body.progress.as_deref());
                body.terminal = Some(StreamTerminal::Eof);
                Ok(None)
            }
            Err(err) => Err(body.fail(err)),
        }
    }

    /// Releases the stream without draining it. Idempotent. The connection is
    /// discarded, never pooled: an undrained body would poison the next
    /// request on it. Reading after close returns `Ok(None)`.
    ///
    /// This runs on the caller's thread and takes the stream's lock, so it
    /// waits for an in-flight `read_chunk` to return; to interrupt a blocked
    /// read, cancel the request's `VaneCancelToken` first.
    pub fn close(&self) {
        if let Ok(mut body) = self.body.lock()
            && body.terminal.is_none()
        {
            body.source.abandon();
            progress_done(body.progress.as_deref());
            body.terminal = Some(StreamTerminal::Closed);
        }
    }
}

impl Drop for VaneResponseStream {
    fn drop(&mut self) {
        // A dropped-but-unfinished stream must not leak its connection or
        // leave a progress poller waiting forever. Poisoned lock: the panic
        // in flight already owns the teardown story.
        if let Ok(body) = self.body.get_mut()
            && body.terminal.is_none()
        {
            body.source.abandon();
            progress_done(body.progress.as_deref());
        }
    }
}

impl RedirectHopResponse for VaneResponseStream {
    fn status_code(&self) -> u16 {
        self.head.status_code
    }

    fn location(&self) -> Option<&str> {
        header_value(&self.head.headers, "location")
    }

    fn mark_refused(&mut self, reason: &'static str) {
        self.head.mark_refused(reason);
    }
}

struct StreamingBody {
    source: StreamingBodySource,
    /// Set once the stream ends, and replayed on every later pull.
    terminal: Option<StreamTerminal>,
    cancel: Option<Arc<AtomicBool>>,
    progress: Option<Arc<VaneProgressState>>,
}

impl StreamingBody {
    /// Tears the source down, latches the terminal state and hands the error
    /// back for returning. The clone is what later pulls replay.
    fn fail(&mut self, err: VaneError) -> VaneError {
        self.source.abandon();
        progress_done(self.progress.as_deref());
        self.terminal = Some(StreamTerminal::Failed(err.clone()));
        err
    }
}

enum StreamTerminal {
    Eof,
    Closed,
    Failed(VaneError),
}

enum BodyStep {
    Chunk(Vec<u8>),
    Eof,
}

enum StreamingBodySource {
    /// Body already fully in memory: a 3xx handed back to the caller
    /// (refused, hop-capped, or missing its Location), or a final response
    /// small enough to have arrived with its headers.
    Buffered(Vec<u8>),
    H3(Box<H3BodyStream>),
    #[cfg(feature = "tcp-fallback")]
    Tcp(Box<tcp::TcpBodyStream>),
}

impl StreamingBodySource {
    fn next(
        &mut self,
        cancel: Option<&AtomicBool>,
        progress: Option<&VaneProgressState>,
    ) -> Result<BodyStep, VaneError> {
        match self {
            StreamingBodySource::Buffered(body) => {
                if body.is_empty() {
                    Ok(BodyStep::Eof)
                } else {
                    Ok(BodyStep::Chunk(std::mem::take(body)))
                }
            }
            StreamingBodySource::H3(stream) => stream.next(cancel, progress),
            #[cfg(feature = "tcp-fallback")]
            StreamingBodySource::Tcp(stream) => stream.next(cancel, progress),
        }
    }

    /// Idempotent teardown for close, failure and drop.
    fn abandon(&mut self) {
        match self {
            StreamingBodySource::Buffered(body) => body.clear(),
            StreamingBodySource::H3(stream) => stream.abandon(),
            #[cfg(feature = "tcp-fallback")]
            StreamingBodySource::Tcp(stream) => stream.abandon(),
        }
    }
}

/// A live HTTP/3 response body: the checked-out connection plus everything the
/// drive loop needs to keep advancing it one pull at a time.
struct H3BodyStream {
    /// For returning the connection to the pool at end of body.
    client: Arc<VaneClient>,
    /// `None` once the connection was parked or discarded.
    transport: Option<PooledHttp3Connection>,
    /// Headers already stripped into the caller's head; carries the body
    /// accumulator, the cumulative limit counters and the finished flag.
    state: ResponseState,
    stream_id: Option<u64>,
    /// Unsent request-body tail; empty in the common fully-uploaded case.
    request_body: Vec<u8>,
    body_offset: usize,
    report_upload: bool,
    /// Per-pull inactivity budget: the request's configured timeout, the same
    /// value the connection's QUIC idle timeout was armed with.
    idle: Duration,
}

impl H3BodyStream {
    fn next(
        &mut self,
        cancel: Option<&AtomicBool>,
        progress: Option<&VaneProgressState>,
    ) -> Result<BodyStep, VaneError> {
        // Serve what the headers phase (or the previous pass) already read.
        if !self.state.body.is_empty() {
            return Ok(BodyStep::Chunk(std::mem::take(&mut self.state.body)));
        }
        if !self.state.finished {
            let Some(transport) = self.transport.as_mut() else {
                return Err(VaneError::Generic(
                    "Response stream connection is gone".to_string(),
                ));
            };
            let deadline = Instant::now() + self.idle;
            loop {
                check_cancelled(cancel)?;
                transport.read_packets()?;
                // A server may answer before consuming the whole request
                // body; keep feeding it so the exchange can finish.
                if let Some(stream_id) = self.stream_id
                    && self.body_offset < self.request_body.len()
                {
                    send_request_body(
                        transport,
                        stream_id,
                        &self.request_body,
                        &mut self.body_offset,
                        self.report_upload,
                        progress,
                    )?;
                }
                let mut response_started = true;
                process_h3_events(
                    &mut transport.http3,
                    &mut transport.conn,
                    &mut transport.body_buf,
                    &mut self.state,
                    cancel,
                    progress,
                    &mut response_started,
                )?;
                transport.flush_packets()?;

                if !self.state.body.is_empty() {
                    return Ok(BodyStep::Chunk(std::mem::take(&mut self.state.body)));
                }
                if self.state.finished {
                    break;
                }
                if transport.conn.is_closed() {
                    return Err(VaneError::Transport(
                        "QUIC connection closed before response completed".to_string(),
                    ));
                }
                if Instant::now() >= deadline {
                    return Err(VaneError::Timeout(
                        "HTTP/3 response body read timed out".to_string(),
                    ));
                }
            }
        }
        // Body complete: park the connection and publish the final figure so
        // a poller sees received == total even without a content-length.
        if let Some(transport) = self.transport.take() {
            self.client.park_or_close_h3(transport)?;
        }
        progress_download(
            progress,
            self.state.body_len as u64,
            self.state.body_len as u64,
        );
        Ok(BodyStep::Eof)
    }

    /// ponytail: an abandoned stream always closes its connection. QUIC could
    /// cancel just the stream (STOP_SENDING) and keep the connection, but
    /// making that reusable means draining the aborted stream's events
    /// without wedging the pool; one extra handshake after an abandon is the
    /// price until a real workload earns the upgrade.
    fn abandon(&mut self) {
        if let Some(mut transport) = self.transport.take() {
            transport.conn.close(true, 0x00, b"stream abandoned").ok();
            transport.flush_packets().ok();
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
                    if domain.is_empty()
                        || !domain_is_assignable(&origin_host, &domain)
                        || !domain_matches(&origin_host, &domain)
                    {
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
        content.push_str(&persisted_cookie_line(cookie));
        content.push('\n');
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

/// One cookie-jar line; `parse_persisted_cookie` is its inverse. The
/// `persisted_cookie_line_round_trips_exactly` property holds the pair
/// together: a drift on either side loses or widens a cookie's scope.
fn persisted_cookie_line(cookie: &StoredCookie) -> String {
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{}",
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
    )
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
        let url = Url::parse(proxy_url).map_err(|e| {
            VaneError::InvalidRequest(format!(
                "Invalid proxyUrl {}: {e}",
                redact_url_userinfo(proxy_url)
            ))
        })?;
        if url.scheme() != "https" {
            return Err(VaneError::InvalidRequest(
                "HTTP/3 proxyUrl must use https:// for MASQUE/CONNECT-UDP".to_string(),
            ));
        }
        let host = url
            .host_str()
            .ok_or_else(|| VaneError::InvalidRequest("proxyUrl is missing host".to_string()))?
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

/// Hands out a QUIC client connection built from the client's cached config,
/// rebuilding the config only when the effective idle timeout changes. The lock
/// is held across `quiche::connect` (cheap and non-blocking) and released well
/// before the handshake loop.
fn quic_connect(
    cache: &QuicConfigCache,
    server_name: &str,
    scid: &quiche::ConnectionId<'_>,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    timeout: Duration,
    max_send_udp_payload: usize,
) -> Result<quiche::Connection, VaneError> {
    let idle_timeout_millis = timeout.as_millis().try_into().unwrap_or(u64::MAX);
    // The cache holds no invariant a panicking thread could have broken, so a
    // poisoned lock must not brick every later request on this client.
    let mut cached = cache.lock().unwrap_or_else(PoisonError::into_inner);
    let key = (idle_timeout_millis, max_send_udp_payload);
    if cached.len() >= MAX_QUIC_CONFIGS && !cached.contains_key(&key) {
        cached.clear();
    }
    let config = match cached.entry(key) {
        Entry::Occupied(entry) => entry.into_mut(),
        Entry::Vacant(entry) => entry.insert(create_quiche_config(
            idle_timeout_millis,
            max_send_udp_payload,
        )?),
    };

    quiche::connect(Some(server_name), scid, local_addr, peer_addr, config)
        .map_err(|e| VaneError::Generic(format!("Failed to create QUIC client: {e}")))
}

/// Offers a cached ticket for TLS 1.3 resumption.
///
/// SECURITY: a resumed TLS 1.3 handshake does not re-run the certificate
/// exchange. BoringSSL restores the peer chain from the serialized
/// `SSL_SESSION`, so `peer_cert()` would hand our post-handshake pin check a
/// certificate cached from an earlier handshake rather than one the server just
/// proved it holds. Any host with pins configured therefore always does a full
/// handshake. Ticket reuse only — early data is never enabled.
fn resume_tls_session(
    store: &TlsSessionStore,
    conn: &mut quiche::Connection,
    key: &TlsSessionKey,
    certificate_pins: &HashMap<String, Vec<String>>,
) {
    if !may_resume_tls_session(&key.host, certificate_pins) {
        return;
    }
    let sessions = store.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(session) = sessions.get(key) {
        // A stale or rejected ticket just means a full handshake.
        conn.set_session(session).ok();
    }
}

/// The pinned-host gate described on [`resume_tls_session`]. The TCP
/// transport enforces the same rule through its rustls session store and
/// consults this in `warmup`, so both transports agree on what "pinned"
/// means for resumption.
fn may_resume_tls_session(host: &str, certificate_pins: &HashMap<String, Vec<String>>) -> bool {
    certificate_pins
        .get(host)
        .is_none_or(|pins| pins.is_empty())
}

/// Largest UDP payload the MASQUE inner connection may emit.
///
/// Every inner packet is varint-framed into an HTTP/3 DATAGRAM on the outer
/// connection, so a full-MTU inner packet plus framing overflows the outer
/// connection's datagram limit and is dropped — which only shows up as failures
/// at high throughput. Size the inner connection from the outer connection's
/// actual datagram capacity; quiche clamps the result up to its 1200-byte
/// floor, and there is nothing further we can do if the outer link is smaller
/// than that.
/// The result is clamped to quiche's own 1200-byte floor before it is returned,
/// because quiche clamps `set_max_send_udp_payload_size` up to that floor
/// anyway: without this, every smaller measurement would key a distinct but
/// byte-identical entry in the config cache.
fn masque_inner_udp_payload(outer: &quiche::Connection, flow_id: u64) -> usize {
    let framing = varint_len(flow_id) + varint_len(0);
    outer
        .dgram_max_writable_len()
        .map_or(MASQUE_INNER_FALLBACK_UDP_PAYLOAD, |max| {
            max.saturating_sub(framing).min(MAX_DATAGRAM_SIZE)
        })
        .max(MASQUE_INNER_FALLBACK_UDP_PAYLOAD)
}

fn store_tls_session(
    store: &TlsSessionStore,
    conn: &quiche::Connection,
    key: &TlsSessionKey,
    certificate_pins: &HashMap<String, Vec<String>>,
) {
    // A ticket resumption would always refuse is dead weight that counts toward
    // the bound and can evict a host that could actually have resumed.
    if !may_resume_tls_session(&key.host, certificate_pins) {
        return;
    }
    let Some(session) = conn.session() else {
        return;
    };
    let mut sessions = store.lock().unwrap_or_else(PoisonError::into_inner);
    if sessions
        .get(key)
        .is_some_and(|stored| stored.as_slice() == session)
    {
        return;
    }
    insert_tls_session(&mut sessions, key, session.to_vec());
}

fn insert_tls_session(
    sessions: &mut HashMap<TlsSessionKey, Vec<u8>>,
    key: &TlsSessionKey,
    session: Vec<u8>,
) {
    if sessions.len() >= MAX_TLS_SESSIONS && !sessions.contains_key(key) {
        sessions.clear();
    }
    sessions.insert(key.clone(), session);
}

/// Asks the kernel for a 1 MB receive buffer on a QUIC UDP socket —
/// best-effort, the same number Chromium's QUIC stack requests.
///
/// A pooled connection keeps the server's congestion window hot, so a whole
/// response flight arrives back-to-back; at ~2 KB of kernel skb accounting
/// per 1350-byte datagram, a ~110-packet flight (~126 KB of payload) costs
/// ~256 KB of socket buffer, which overflows Linux/Android's default
/// `rmem_default` (212–229 KB). Every overflowed packet is silently dropped
/// (`Udp: RcvbufErrors`) and costs the transfer a fast-retransmit RTT — or a
/// full probe timeout, tens of ms, when the tail of the flight is hit.
/// Measured on the Android emulator benchmark: one drop per request on
/// average, and every ≥50 ms body-transfer stall traced to it.
///
/// The kernel clamps the request to `rmem_max` on its own, and `SO_RCVBUF`
/// is a limit, not an allocation — an idle pooled connection costs nothing.
/// A socket that keeps its default buffer is still a working socket, so
/// failure (e.g. a platform rejecting the size) is deliberately ignored.
fn request_large_udp_recv_buffer(socket: &UdpSocket) {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd as _;
        let size: libc::c_int = 1024 * 1024;
        // SAFETY: setsockopt on an open, owned fd, with a valid c_int payload
        // and its exact size; the fd outlives the call.
        unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&raw const size).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
    #[cfg(not(unix))]
    let _ = socket;
}

/// `timeout` bounds the handshake; `idle_timeout` becomes the connection's QUIC
/// idle timeout and keys the config cache, so it must not shrink per redirect
/// hop.
fn connect_quic_h3(
    host: &str,
    peer_addr: SocketAddr,
    timeouts: HopTimeouts,
    certificate_pins: &HashMap<String, Vec<String>>,
    quic_config: &QuicConfigCache,
    tls_sessions: &TlsSessionStore,
    session_key: &TlsSessionKey,
) -> Result<DirectHttp3Connection, VaneError> {
    let bind_addr = match peer_addr {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };

    let socket = UdpSocket::bind(bind_addr)
        .map_err(|e| VaneError::Generic(format!("Failed to bind UDP socket: {e}")))?;
    request_large_udp_recv_buffer(&socket);
    socket.connect(peer_addr).map_err(|e| {
        VaneError::Generic(format!("Failed to connect UDP socket to {peer_addr}: {e}"))
    })?;
    let local_addr = socket
        .local_addr()
        .map_err(|e| VaneError::Generic(format!("Failed to read UDP local address: {e}")))?;
    let mut last_read_timeout = Some(Duration::from_millis(10));
    socket
        .set_read_timeout(last_read_timeout)
        .map_err(|e| VaneError::Generic(format!("Failed to set UDP read timeout: {e}")))?;
    socket
        .set_write_timeout(Some(timeouts.remaining("handshake")?))
        .map_err(|e| VaneError::Generic(format!("Failed to set UDP write timeout: {e}")))?;

    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    getrandom::fill(&mut scid)
        .map_err(|e| VaneError::Generic(format!("Failed to generate QUIC connection ID: {e}")))?;
    let scid = quiche::ConnectionId::from_ref(&scid);
    let mut conn = quic_connect(
        quic_config,
        host,
        &scid,
        local_addr,
        peer_addr,
        timeouts.idle,
        MAX_DATAGRAM_SIZE,
    )?;
    resume_tls_session(tls_sessions, &mut conn, session_key, certificate_pins);
    let mut h3_config = create_h3_config()?;
    h3_config.enable_extended_connect(true);

    let mut recv_buf = vec![0; UDP_RECV_BUFFER_BYTES];
    let mut send_buf = vec![0; MAX_DATAGRAM_SIZE];
    flush_quic_packets(&socket, &mut send_buf, &mut conn)?;
    let deadline = timeouts.deadline;

    while Instant::now() < deadline {
        read_quic_packets(
            &socket,
            &mut last_read_timeout,
            &mut recv_buf,
            &mut conn,
            local_addr,
            peer_addr,
        )?;

        if conn.is_established() {
            verify_certificate_pins(host, conn.peer_cert(), certificate_pins)?;
            store_tls_session(tls_sessions, &conn, session_key, certificate_pins);
            let http3 = quiche::h3::Connection::with_transport(&mut conn, &h3_config)?;
            return Ok(DirectHttp3Connection {
                socket,
                local_addr,
                peer_addr,
                conn,
                http3,
            });
        }

        flush_quic_packets(&socket, &mut send_buf, &mut conn)?;

        if conn.is_closed() {
            return Err(VaneError::Transport(
                "QUIC connection closed before handshake completed".to_string(),
            ));
        }
    }

    Err(VaneError::ConnectTimeout(
        "HTTP/3 handshake timed out".to_string(),
    ))
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
    let mut recv_buf = vec![0; UDP_RECV_BUFFER_BYTES];
    let mut send_buf = vec![0; MAX_DATAGRAM_SIZE];
    let mut control_buf = vec![0; MASQUE_CONTROL_BUFFER_BYTES];
    flush_quic_packets(&transport.socket, &mut send_buf, &mut transport.conn)?;

    let deadline = Instant::now() + timeout;
    let mut tunnel_accepted = false;
    let mut last_read_timeout = None;
    while Instant::now() < deadline {
        read_quic_packets(
            &transport.socket,
            &mut last_read_timeout,
            &mut recv_buf,
            &mut transport.conn,
            transport.local_addr,
            transport.peer_addr,
        )?;
        process_connect_udp_events(
            &mut transport.http3,
            &mut transport.conn,
            &mut control_buf,
            stream_id,
            &mut tunnel_accepted,
        )?;

        if tunnel_accepted {
            if !transport.http3.extended_connect_enabled_by_peer() {
                return Err(VaneError::Transport(
                    "MASQUE proxy did not advertise Extended CONNECT support".to_string(),
                ));
            }
            if !transport.http3.dgram_enabled_by_peer(&transport.conn) {
                return Err(VaneError::Transport(
                    "MASQUE proxy did not advertise HTTP/3 DATAGRAM support".to_string(),
                ));
            }
            return Ok(stream_id);
        }

        flush_quic_packets(&transport.socket, &mut send_buf, &mut transport.conn)?;

        if transport.conn.is_closed() {
            return Err(VaneError::Transport(
                "MASQUE proxy connection closed before CONNECT-UDP completed".to_string(),
            ));
        }
    }

    Err(VaneError::ConnectTimeout(
        "MASQUE CONNECT-UDP establishment timed out".to_string(),
    ))
}

fn process_connect_udp_events(
    http3: &mut quiche::h3::Connection,
    conn: &mut quiche::Connection,
    buf: &mut [u8],
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
                    return Err(VaneError::Transport(
                        "MASQUE proxy CONNECT-UDP response is missing :status".to_string(),
                    ));
                };
                if status.starts_with('2') {
                    *tunnel_accepted = true;
                } else {
                    return Err(VaneError::Transport(format!(
                        "MASQUE proxy rejected CONNECT-UDP with status {status}"
                    )));
                }
            }
            Ok((stream_id, quiche::h3::Event::Data)) => loop {
                match http3.recv_body(conn, stream_id, &mut buf[..]) {
                    Ok(_) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(e) => return Err(e.into()),
                }
            },
            Ok((stream_id, quiche::h3::Event::Finished))
                if stream_id == tunnel_stream_id && !*tunnel_accepted =>
            {
                return Err(VaneError::Transport(
                    "MASQUE proxy closed CONNECT-UDP before accepting it".to_string(),
                ));
            }
            Ok((stream_id, quiche::h3::Event::Reset(e))) if stream_id == tunnel_stream_id => {
                return Err(VaneError::Transport(format!(
                    "MASQUE proxy reset CONNECT-UDP stream: {e:?}"
                )));
            }
            Ok((_stream_id, quiche::h3::Event::Headers { .. }))
            | Ok((_stream_id, quiche::h3::Event::Finished))
            | Ok((_stream_id, quiche::h3::Event::Reset(_)))
            | Ok((_stream_id, quiche::h3::Event::PriorityUpdate)) => {}
            Ok((_id, quiche::h3::Event::GoAway)) => {
                return Err(VaneError::Transport(
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
    buf: &mut [u8],
    tunnel_stream_id: u64,
) -> Result<(), VaneError> {
    let mut accepted = true;
    process_connect_udp_events(http3, conn, buf, tunnel_stream_id, &mut accepted)
}

fn read_quic_packets_via(
    io: &mut Http3Io,
    conn: &mut quiche::Connection,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
) -> Result<(), VaneError> {
    match io {
        Http3Io::Direct {
            socket,
            last_read_timeout,
            recv_buf,
        } => read_quic_packets(
            socket,
            last_read_timeout,
            recv_buf,
            conn,
            local_addr,
            peer_addr,
        ),
        Http3Io::Masque(tunnel) => tunnel.read_origin_packets(conn, local_addr, peer_addr),
    }
}

fn flush_quic_packets_via(
    io: &mut Http3Io,
    out: &mut [u8],
    conn: &mut quiche::Connection,
) -> Result<(), VaneError> {
    loop {
        match conn.send(&mut out[..]) {
            Ok((written, send_info)) => {
                let _ = send_info;
                match io {
                    Http3Io::Direct { socket, .. } => {
                        socket.send(&out[..written]).map_err(|e| {
                            VaneError::Transport(format!("Failed to send UDP packet: {e}"))
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
    /// Shared with every other stage of the request; see [`HopTimeouts`].
    deadline: Instant,
    url: &'a Url,
    max_response_body_bytes: u64,
    response_body_path: Option<&'a str>,
    cancel_token: Option<&'a AtomicBool>,
    progress: Option<&'a VaneProgressState>,
    report_upload: bool,
    redirect_possible: bool,
}

/// In-flight request state that must survive across drive passes, so a
/// streaming caller can stop at the headers and keep driving the body later.
struct H3ExchangeState {
    response: ResponseState,
    /// `None` while quiche has asked us to retry `send_request`.
    stream_id: Option<u64>,
    body_offset: usize,
}

/// How far [`drive_h3_exchange`] runs before returning control.
#[derive(Clone, Copy, PartialEq, Eq)]
enum H3DriveUntil {
    /// The whole response, exactly the historical behavior.
    ResponseFinished,
    /// The final (non-1xx) header block. Body bytes that arrive in the same
    /// pass are kept in `response.body` for the caller to serve first.
    HeadersComplete,
}

/// Sends the request (headers plus whatever body quiche accepts up front) and
/// returns the exchange state the drive loop advances.
fn begin_h3_exchange(
    transport: &mut PooledHttp3Connection,
    options: &H3RequestOptions<'_>,
) -> Result<H3ExchangeState, VaneError> {
    let mut response =
        ResponseState::new(options.max_response_body_bytes, options.response_body_path)?;
    response.redirect_possible = options.redirect_possible;

    // Send before the first read: the read blocks for up to 50 ms, so reading
    // first delays the request by a full poll interval on every attempt. The
    // deadline is still checked first so an expired one sends nothing.
    if Instant::now() >= options.deadline {
        return Err(VaneError::Timeout(format!(
            "HTTP/3 request to {} timed out",
            redact_url_userinfo(&options.url.to_string())
        )));
    }
    check_cancelled(options.cancel_token)?;
    let mut exchange = H3ExchangeState {
        response,
        stream_id: send_h3_request(transport, options)?,
        body_offset: 0,
    };
    if let Some(stream_id) = exchange.stream_id {
        send_request_body(
            transport,
            stream_id,
            options.request_body,
            &mut exchange.body_offset,
            options.report_upload,
            options.progress,
        )?;
    }
    transport.flush_packets()?;
    Ok(exchange)
}

fn drive_h3_exchange(
    transport: &mut PooledHttp3Connection,
    options: &H3RequestOptions<'_>,
    exchange: &mut H3ExchangeState,
    response_started: &mut bool,
    until: H3DriveUntil,
) -> Result<(), VaneError> {
    let deadline = options.deadline;
    while Instant::now() < deadline {
        check_cancelled(options.cancel_token)?;
        transport.read_packets()?;

        // Re-issue a request quiche asked us to retry, now that the read above
        // may have delivered the peer's MAX_STREAMS credit.
        if exchange.stream_id.is_none() {
            exchange.stream_id = send_h3_request(transport, options)?;
        }
        if let Some(stream_id) = exchange.stream_id {
            send_request_body(
                transport,
                stream_id,
                options.request_body,
                &mut exchange.body_offset,
                options.report_upload,
                options.progress,
            )?;
        }

        process_h3_events(
            &mut transport.http3,
            &mut transport.conn,
            &mut transport.body_buf,
            &mut exchange.response,
            options.cancel_token,
            options.progress,
            response_started,
        )?;

        transport.flush_packets()?;

        if exchange.response.finished {
            return Ok(());
        }
        if until == H3DriveUntil::HeadersComplete && exchange.response.headers_complete {
            return Ok(());
        }

        if transport.conn.is_closed() {
            return Err(VaneError::Transport(
                "QUIC connection closed before response completed".to_string(),
            ));
        }
    }

    Err(VaneError::Timeout(format!(
        "HTTP/3 request to {} timed out",
        redact_url_userinfo(&options.url.to_string())
    )))
}

/// Returns `None` when quiche asked us to retry the whole call later. Both
/// `StreamBlocked` and `TransportError(StreamLimit)` roll the H3 stream state
/// back without consuming the stream id, and quiche documents that repeating
/// `send_request` with the same arguments is the required recovery once the
/// peer grants more stream credit. Every other error stays fatal.
fn send_h3_request(
    transport: &mut PooledHttp3Connection,
    options: &H3RequestOptions<'_>,
) -> Result<Option<u64>, VaneError> {
    match transport.http3.send_request(
        &mut transport.conn,
        options.headers,
        options.request_body.is_empty(),
    ) {
        Ok(stream_id) => Ok(Some(stream_id)),
        Err(
            quiche::h3::Error::StreamBlocked
            | quiche::h3::Error::TransportError(quiche::Error::StreamLimit),
        ) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn send_request_body(
    transport: &mut PooledHttp3Connection,
    stream_id: u64,
    request_body: &[u8],
    body_offset: &mut usize,
    report_upload: bool,
    progress: Option<&VaneProgressState>,
) -> Result<(), VaneError> {
    while *body_offset < request_body.len() {
        match transport.http3.send_body(
            &mut transport.conn,
            stream_id,
            &request_body[*body_offset..],
            true,
        ) {
            Ok(written) => {
                *body_offset += written;
                if report_upload {
                    progress_upload(progress, *body_offset as u64, request_body.len() as u64);
                }
            }
            Err(quiche::h3::Error::Done) => break,
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}

fn create_quiche_config(
    max_idle_timeout_millis: u64,
    max_send_udp_payload: usize,
) -> Result<quiche::Config, VaneError> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .map_err(|e| VaneError::Generic(format!("Failed to configure HTTP/3 ALPN: {e:?}")))?;
    config.verify_peer(true);
    load_platform_roots(&mut config)?;
    // Test-only twin of the TCP path's `TEST_ROOT`: trust the in-process
    // HTTP/3 test server's CA. Strictly additive — `verify_peer(true)` above
    // and the platform roots stay in force — and compiled out of every
    // non-test build, so no release configuration can reach it.
    #[cfg(test)]
    if let Some(test_ca) = crate::h3_offline::test_ca_pem_path() {
        config
            .load_verify_locations_from_file(test_ca)
            .map_err(|e| VaneError::Generic(format!("Failed to load test CA: {e}")))?;
    }
    config.set_max_idle_timeout(max_idle_timeout_millis);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(max_send_udp_payload);
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

/// Builds the per-connection HTTP/3 config. Shared by the direct and the
/// MASQUE-tunneled connection paths so neither can drift on the response
/// header cap; the direct path additionally enables Extended CONNECT on its
/// copy (needed only where a tunnel may be opened).
fn create_h3_config() -> Result<quiche::h3::Config, VaneError> {
    let mut config = quiche::h3::Config::new()
        .map_err(|e| VaneError::Generic(format!("Failed to create HTTP/3 config: {e}")))?;
    config.set_max_field_section_size(MAX_RESPONSE_HEADER_SECTION_BYTES);
    Ok(config)
}

/// Whether a CA directory holds anything BoringSSL could actually load.
///
/// `load_verify_locations_from_directory` only registers a lazy hash-based
/// lookup path — it succeeds for a directory that exists but is empty, and the
/// consequence surfaces much later as every HTTP/3 connection failing to build
/// a chain, with nothing pointing at the trust store. An existence check is
/// therefore not enough: a present but cert-less directory has to count as a
/// miss so the next candidate still gets its turn.
fn directory_has_certs(path: &str) -> bool {
    let Ok(entries) = std::fs::read_dir(path) else {
        // Covers "does not exist" too, so this subsumes the old exists() check.
        return false;
    };
    entries.flatten().any(|entry| {
        // ponytail: the bar is one regular file (or symlink, which is how
        // /etc/ssl/certs is built), not parsing each candidate — BoringSSL
        // still validates whatever it ends up loading. Tighten to the OpenSSL
        // `<8 hex>.<n>` hash-link shape if some platform ever ships a cert
        // directory full of unrelated files.
        entry
            .file_type()
            .is_ok_and(|kind| kind.is_file() || kind.is_symlink())
    })
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

    let cert_dirs = [
        // Android 14+ serves the trust store from the Conscrypt APEX; the
        // legacy path below is kept for older images, which is why this one
        // goes first rather than after it.
        "/apex/com.android.conscrypt/cacerts",
        "/etc/ssl/certs",
        "/system/etc/security/cacerts",
    ];
    for path in cert_dirs {
        if !directory_has_certs(path) {
            continue;
        }
        config
            .load_verify_locations_from_directory(path)
            .map_err(|e| {
                VaneError::Generic(format!("Failed to load CA directory from {path}: {e}"))
            })?;
        return Ok(());
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
            VaneError::InvalidRequest(format!(
                "Invalid DNS override for {host}: expected IP address, got {override_addr}: {e}"
            ))
        })?;
        return Ok(SocketAddr::new(ip, port));
    }

    (host, port)
        .to_socket_addrs()
        .map_err(|e| VaneError::Transport(format!("Failed to resolve {host}:{port}: {e}")))?
        .next()
        .ok_or_else(|| VaneError::Transport(format!("Failed to resolve {host}:{port}")))
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
        VaneError::Tls(format!(
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

    Err(VaneError::Tls(format!(
        "Certificate pin mismatch for {host}"
    )))
}

/// Replaces any `user:password@` in a URL before it reaches an error message.
/// Proxy URLs routinely carry credentials, and these errors surface to callers
/// and into application logs.
fn redact_url_userinfo(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    match rest.split_once('@') {
        Some((_, host)) => format!("{scheme}://***@{host}"),
        None => url.to_string(),
    }
}

fn validate_certificate_pin_host(host: &str) -> Result<(), VaneError> {
    if host.is_empty() {
        return Err(VaneError::InvalidRequest(
            "Certificate pin host must not be empty".to_string(),
        ));
    }
    if host.contains("://") || host.contains('/') {
        return Err(VaneError::InvalidRequest(
            "Certificate pin host must be a hostname without scheme or path".to_string(),
        ));
    }
    if !host.is_ascii() {
        return Err(VaneError::InvalidRequest(
            "Certificate pin host must be ASCII; use punycode for IDN hosts".to_string(),
        ));
    }
    // A pin keyed "host:443" could never match: every lookup uses the bare
    // host, so accepting it would silently leave the host unpinned.
    let bare = host.strip_prefix('[').and_then(|r| r.split_once(']'));
    if bare.map_or(host, |(_, after)| after).contains(':') {
        return Err(VaneError::InvalidRequest(
            "Certificate pin host must not include a port".to_string(),
        ));
    }
    Ok(())
}

fn validate_certificate_pins(pins: &[String]) -> Result<(), VaneError> {
    for pin in pins {
        if !(pin.starts_with("sha256/") || pin.starts_with("sha256-cert/")) {
            return Err(VaneError::InvalidRequest(format!(
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
        .map_err(|e| VaneError::Tls(format!("Failed to parse peer certificate: {e}")))?;
    let public_key = cert
        .public_key()
        .map_err(|e| VaneError::Tls(format!("Failed to read peer public key: {e}")))?;
    let spki_der = public_key
        .public_key_to_der()
        .map_err(|e| VaneError::Tls(format!("Failed to encode peer public key SPKI: {e}")))?;

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

/// RFC 6265 5.3 step 5: a `Domain` attribute that is itself a public suffix
/// must be ignored, or any host we talk to could set a cookie for every site
/// under `com` (or `co.uk`, or `github.io`) and shadow a real session cookie.
///
/// `domain_matches` alone says `evil.com` matches `com`, so this is the check
/// that stops it.
///
/// The two cheap rules below ship in every build. The `psl` feature (on by
/// default, dropped by the small profile) layers the full public suffix list on
/// top so multi-label suffixes like `co.uk` and `github.io` are refused too;
/// it does not replace them, since the list says nothing about IP literals.
/// Without `psl`, bare-TLD supercookies are still blocked and multi-label
/// public suffixes are not — see ARTIFACT_SIZES.md.
fn domain_is_assignable(host: &str, domain: &str) -> bool {
    // An IP literal has no domain hierarchy: "10.0.0.1" domain-matches "1".
    if host.starts_with('[') || host.parse::<IpAddr>().is_ok() {
        return false;
    }
    // A single-label Domain is a bare TLD.
    if !domain.contains('.') {
        return false;
    }

    #[cfg(feature = "psl")]
    if let Some(suffix) = psl::suffix_str(domain) {
        // The attribute must name something strictly narrower than the
        // registrable suffix it sits under.
        return domain.len() > suffix.len() && domain.ends_with(suffix);
    }

    true
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

/// Takes a length, not the bytes, so callers can refuse an oversized body
/// *before* materializing it — same error either way, so nothing downstream
/// can tell which check fired.
fn validate_request_body_limit(
    body_len: u64,
    max_request_body_bytes: u64,
) -> Result<(), VaneError> {
    if body_len > max_request_body_bytes {
        return Err(VaneError::BodyLimitExceeded(format!(
            "Request body exceeded {max_request_body_bytes} bytes"
        )));
    }

    Ok(())
}

fn load_request_body(
    request: &VaneRequest,
    max_request_body_bytes: u64,
) -> Result<Cow<'_, [u8]>, VaneError> {
    if let Some(path) = &request.body_file_path
        && !path.is_empty()
    {
        let mut file = File::open(path).map_err(|e| {
            VaneError::InvalidRequest(format!("Failed to open request body file {path}: {e}"))
        })?;
        // Sized before it is read: `read_to_end` on a multi-GB body file would
        // OOM a mobile app long before the post-load check could report the
        // limit cleanly. The caller re-checks the loaded length, which also
        // covers a file that grew between this stat and the read.
        let len = file
            .metadata()
            .map(|metadata| metadata.len())
            .map_err(|e| {
                VaneError::InvalidRequest(format!("Failed to read request body file {path}: {e}"))
            })?;
        validate_request_body_limit(len, max_request_body_bytes)?;
        let mut body = Vec::new();
        file.read_to_end(&mut body).map_err(|e| {
            VaneError::InvalidRequest(format!("Failed to read request body file {path}: {e}"))
        })?;
        return Ok(Cow::Owned(body));
    }
    Ok(Cow::Borrowed(request.body.as_deref().unwrap_or_default()))
}

fn validate_response_body_limit(
    current_len: usize,
    read_len: usize,
    max_response_body_bytes: u64,
) -> Result<(), VaneError> {
    if current_len as u64 + read_len as u64 > max_response_body_bytes {
        return Err(VaneError::BodyLimitExceeded(format!(
            "Response body exceeded {max_response_body_bytes} bytes"
        )));
    }

    Ok(())
}

/// Resolves a cancel token id to its handle once per request; the transfer loop
/// then only loads the atomic.
fn cancel_token(cancel_token_id: Option<u64>) -> Option<Arc<AtomicBool>> {
    let id = cancel_token_id?;
    CANCEL_TOKENS.lock().ok()?.get(&id).cloned()
}

fn check_cancelled(cancel_token: Option<&AtomicBool>) -> Result<(), VaneError> {
    if cancel_token.is_some_and(|token| token.load(Ordering::Relaxed)) {
        return Err(VaneError::Cancelled(
            "Vane request was cancelled".to_string(),
        ));
    }

    Ok(())
}

// Shared by the C ABI and UniFFI entry points. Cancel and free tolerate ids
// that were never created or already freed, and ids are never reused, so
// double-free and cancel-after-free are safe no-ops.
fn cancel_token_create() -> u64 {
    let id = NEXT_CANCEL_TOKEN_ID.fetch_add(1, Ordering::Relaxed);
    if let Ok(mut tokens) = CANCEL_TOKENS.lock() {
        tokens.insert(id, Arc::new(AtomicBool::new(false)));
    }
    id
}

fn cancel_token_cancel(id: u64) {
    if let Ok(tokens) = CANCEL_TOKENS.lock()
        && let Some(token) = tokens.get(&id)
    {
        token.store(true, Ordering::Relaxed);
    }
}

fn cancel_token_free(id: u64) {
    if let Ok(mut tokens) = CANCEL_TOKENS.lock() {
        tokens.remove(&id);
    }
}

fn progress_init(progress_id: Option<u64>, upload_total: u64) -> Option<Arc<VaneProgressState>> {
    let state = progress_handle(progress_id)?;
    state.reset(upload_total);
    Some(state)
}

/// Resolves a progress id to its handle. Lookup only, like `cancel_token`:
/// every binding creates ids through `progress_create` before use, and
/// `execute` resolves the id again at done-time — inserting there would
/// resurrect an id the caller already freed as a permanently leaked entry
/// (ids are never reused). A missing id is simply "no progress reporting".
fn progress_handle(progress_id: Option<u64>) -> Option<Arc<VaneProgressState>> {
    let id = progress_id?;
    PROGRESS_STATES.lock().ok()?.get(&id).cloned()
}

fn progress_upload(progress: Option<&VaneProgressState>, sent: u64, total: u64) {
    if let Some(state) = progress {
        state.upload_sent.store(sent, Ordering::Relaxed);
        state.upload_total.store(total, Ordering::Relaxed);
    }
}

fn progress_download(progress: Option<&VaneProgressState>, received: u64, total: u64) {
    if let Some(state) = progress {
        state.download_received.store(received, Ordering::Relaxed);
        state.download_total.store(total, Ordering::Relaxed);
    }
}

fn progress_done(progress: Option<&VaneProgressState>) {
    if let Some(state) = progress {
        // Release pairs with the Acquire load in `progress_snapshot`: a reader
        // that observes `done` must also observe the final counters, otherwise
        // a progress bar can latch "done" while still showing 99%.
        state.done.store(true, Ordering::Release);
    }
}

fn progress_create() -> u64 {
    let id = NEXT_PROGRESS_ID.fetch_add(1, Ordering::Relaxed);
    if let Ok(mut states) = PROGRESS_STATES.lock() {
        states.insert(id, Arc::default());
    }
    id
}

fn progress_snapshot(id: u64) -> VaneProgressSnapshot {
    let state = PROGRESS_STATES
        .lock()
        .ok()
        .and_then(|states| states.get(&id).cloned());
    let Some(state) = state else {
        return VaneProgressSnapshot::default();
    };
    // `done` is read first with Acquire so the counters read after it are at
    // least as new as the ones the writer published before setting it.
    let done = state.done.load(Ordering::Acquire);
    VaneProgressSnapshot {
        upload_sent: state.upload_sent.load(Ordering::Relaxed),
        upload_total: state.upload_total.load(Ordering::Relaxed),
        download_received: state.download_received.load(Ordering::Relaxed),
        download_total: state.download_total.load(Ordering::Relaxed),
        done,
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

/// Builds the header list for one hop. `origin` is the origin the caller
/// addressed; once a redirect has moved us to a different one, caller-supplied
/// headers are cut down to [`CROSS_ORIGIN_SAFE_HEADERS`]. `method` is passed in
/// rather than read off the request because a 303 rewrites it to GET.
fn build_h3_headers(
    url: &Url,
    request: &VaneRequest,
    config: &VaneClientConfig,
    method: &str,
    origin: (&str, u16),
    cookie_header: Option<&str>,
    body_dropped: bool,
) -> Result<Vec<quiche::h3::Header>, VaneError> {
    // Port is part of the origin: app.example.com and app.example.com:8443 are
    // different security origins on multi-tenant and dev/staging hosts.
    let same_origin = (url.host_str().unwrap_or_default(), origin_port(url)) == origin;
    let method = method.to_ascii_uppercase();
    let host = url
        .host_str()
        .ok_or_else(|| VaneError::InvalidRequest("URL is missing host".to_string()))?;
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

    for_each_regular_header(request, config, |key, value| {
        let lower = key.to_ascii_lowercase();
        if !same_origin && !header_survives_origin_change(&lower) {
            return Ok(());
        }
        // A 303 rewrite drops the body, so a caller content-type would describe
        // a payload that is no longer being sent.
        if body_dropped && lower == "content-type" {
            return Ok(());
        }
        headers.push(quiche::h3::Header::new(lower.as_bytes(), value.as_bytes()));
        Ok(())
    })?;

    // Only when the caller did not set one, so we never send two User-Agents.
    if !headers.iter().any(|header| header.name() == b"user-agent") {
        let user_agent = config.user_agent.as_deref().unwrap_or("Vane/0.1.0");
        headers.push(quiche::h3::Header::new(
            b"user-agent",
            user_agent.as_bytes(),
        ));
    }

    // Appended after the allowlist, which exists to govern *caller* headers: the
    // jar's cookies are already scoped to this hop's host and path, so running
    // them through the cross-origin filter would just discard them.
    if let Some(cookie_header) = cookie_header.filter(|header| !header.is_empty()) {
        headers.push(quiche::h3::Header::new(b"cookie", cookie_header.as_bytes()));
    }

    Ok(headers)
}

/// Walks the non-pseudo request headers in the order both transports must send
/// them: client defaults, then per-request overrides. The cookie jar's header is
/// appended by each transport afterwards, because it must not be filtered by the
/// cross-origin allowlist the way caller headers are.
///
/// Shared so the TCP backend cannot drift from the HTTP/3 backend on which
/// headers a request carries or which ones callers are allowed to set.
fn for_each_regular_header(
    request: &VaneRequest,
    config: &VaneClientConfig,
    mut push: impl FnMut(&str, &str) -> Result<(), VaneError>,
) -> Result<(), VaneError> {
    let mut push_checked = |key: &str, value: &str| -> Result<(), VaneError> {
        if key.starts_with(':') {
            return Err(VaneError::InvalidRequest(format!(
                "HTTP/3 pseudo-header cannot be set by callers: {key}"
            )));
        }
        // Connection-management and framing headers are the transport's to set.
        // hyper honours a caller `content-length` over the real body length,
        // which is a request-smuggling shape against intermediaries, and
        // RFC 9114 4.2 makes the hop-by-hop names illegal on HTTP/3 outright.
        if RESERVED_HEADERS
            .iter()
            .any(|reserved| key.eq_ignore_ascii_case(reserved))
        {
            return Err(VaneError::InvalidRequest(format!(
                "Header cannot be set by callers: {key}"
            )));
        }
        push(key, value)
    };

    for (key, value) in config.default_headers.iter().chain(&request.headers) {
        push_checked(key, value)?;
    }

    Ok(())
}

/// Whether a caller-supplied header may follow a redirect to a different
/// origin. Lowercase name in, so both transports ask the same question.
fn header_survives_origin_change(lowercase_name: &str) -> bool {
    CROSS_ORIGIN_SAFE_HEADERS.contains(&lowercase_name)
}

fn origin_port(url: &Url) -> u16 {
    url.port_or_known_default().unwrap_or(443)
}

/// Case-insensitive lookup over a response header map. HTTP/3 field names are
/// lowercase by protocol, but the response is peer-controlled and the redirect
/// gate must not be skippable by spelling `Location` differently.
fn header_value<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

/// Response header naming why Vane stopped following a redirect chain.
const REDIRECT_REFUSED_HEADER: &str = "vane-redirect-refused";
const REDIRECT_REFUSED_DOWNGRADE: &str = "downgrade";
const REDIRECT_REFUSED_PINNED_HOST: &str = "pinned-host";
const REDIRECT_REFUSED_HOP_CAP: &str = "hop-cap";
const REDIRECT_REFUSED_CROSS_ORIGIN_BODY: &str = "cross-origin-body";

/// What the redirect gate decided about one response.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RedirectDecision {
    Follow(Url),
    /// Not a redirect to follow: not a 3xx, no usable `Location`, or the caller
    /// opted out. The response is final and nothing was refused.
    Stop,
    /// A redirect Vane refused for the caller's safety; the reason is reported
    /// on the response.
    Refused(&'static str),
}

/// Decides whether a response is a redirect worth following, and to where.
///
/// Shared by both transports on purpose: a rule that lives on one of them is a
/// rule that decides what a URL does based on whether UDP happens to work.
fn next_redirect_url(
    status_code: u16,
    location: Option<&str>,
    current: &Url,
    request: &VaneRequest,
    hops: usize,
    certificate_pins: &HashMap<String, Vec<String>>,
) -> RedirectDecision {
    if !request.follow_redirects || !(300..400).contains(&status_code) {
        return RedirectDecision::Stop;
    }
    if hops >= MAX_REDIRECTS {
        return RedirectDecision::Refused(REDIRECT_REFUSED_HOP_CAP);
    }
    // An empty Location means "no redirect" rather than the site root.
    let Some(location) = location.filter(|value| !value.is_empty()) else {
        return RedirectDecision::Stop;
    };
    // Resolved with Vane's own parser, which is stricter than the one reqwest
    // uses (no userinfo, ASCII hosts only). An unparsable or unsupported target
    // stops the chain rather than being guessed at or attributed to `current`.
    let Ok(next) = current.join(location) else {
        return RedirectDecision::Stop;
    };
    // Never downgrade to cleartext. Refusing rather than erroring is deliberate:
    // an error here would make an http:// Location mean "3xx" over TCP and
    // "failed request" over HTTP/3, which is the transport divergence this
    // whole change exists to remove. HTTP/3 refuses plaintext regardless, so
    // nothing insecure can be reached either way.
    if next.scheme() != "https" {
        return RedirectDecision::Refused(REDIRECT_REFUSED_DOWNGRADE);
    }
    // A pin only constrains the hop it was checked on, so leaving a pinned host
    // means leaving the pin behind: stop instead. Host-scoped, like the pins
    // themselves — a port change on the same host stays covered.
    let current_host = current.host_str().unwrap_or_default();
    if next.host_str() != Some(current_host)
        && certificate_pins
            .get(current_host)
            .is_some_and(|pins| !pins.is_empty())
    {
        return RedirectDecision::Refused(REDIRECT_REFUSED_PINNED_HOST);
    }

    RedirectDecision::Follow(next)
}

/// What a redirect does to the method and body of the next hop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RedirectRewrite {
    /// Keep the method, replay the body.
    Keep,
    /// Bodyless GET; a caller `content-type` goes with the body.
    ToGet,
    /// Refuse the hop and hand the 3xx back to the caller.
    Refuse,
}

/// A hop that would replay a request body at a different origin is refused: the
/// credential is as often in the payload as in a header, and stripping headers
/// does not cover it.
///
/// The guard is on "a body still to send", not on the status: 307 and 308 keep
/// the body by definition, but so does a 301/302 on a GET, and nothing strips a
/// body from a GET (GraphQL-over-GET and Elasticsearch `_search` are the real
/// shapes). The rewriting statuses below drop the body first, so they never
/// reach this.
fn redirect_rewrite(
    status_code: u16,
    method: &str,
    has_body: bool,
    cross_origin: bool,
) -> RedirectRewrite {
    if has_body && cross_origin && !rewrites_to_get(status_code, method) {
        return RedirectRewrite::Refuse;
    }
    if rewrites_to_get(status_code, method) {
        return RedirectRewrite::ToGet;
    }
    RedirectRewrite::Keep
}

/// 303, and 301/302 on a non-idempotent method, become a bodyless GET.
fn rewrites_to_get(status_code: u16, method: &str) -> bool {
    status_code == 303 || (matches!(status_code, 301 | 302) && !method.eq_ignore_ascii_case("GET"))
}

/// Reads every UDP packet the peer has already delivered into `conn`.
///
/// The first `recv` blocks, bounded by the QUIC timer capped at 50 ms, so the
/// drive loop waits for the network without spinning and cancel/deadline
/// checks in the caller still run at least once per timer tick. Once a packet
/// arrives the socket flips to non-blocking and the rest of the burst drains
/// without waiting, so the caller flushes ACKs the moment the kernel buffer is
/// empty. The previous always-blocking loop slept out the full timer after
/// every burst with the ACKs still queued, which added ~min(timer, 50 ms) to
/// each response flight and stalled the peer's congestion window.
/// Blocking-recv timeout for `read_quic_packets`: the QUIC timer, defaulted
/// to 10 ms when quiche has none pending, capped at 50 ms so the caller's
/// cancel/deadline checks keep ticking. Floored at 1 ms because a pooled
/// connection checked out after its quiche timer already expired reports
/// `Duration::ZERO`, and `UdpSocket::set_read_timeout(Some(ZERO))` is an
/// error in std — the request would fail instead of just polling promptly
/// (the expired timer itself fires via `on_timeout` on the recv-timeout arm).
fn quic_read_timeout(conn_timeout: Option<Duration>) -> Duration {
    conn_timeout
        .unwrap_or(Duration::from_millis(10))
        .clamp(Duration::from_millis(1), Duration::from_millis(50))
}

fn read_quic_packets(
    socket: &UdpSocket,
    last_read_timeout: &mut Option<Duration>,
    buf: &mut [u8],
    conn: &mut quiche::Connection,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
) -> Result<(), VaneError> {
    let timeout = quic_read_timeout(conn.timeout());
    if *last_read_timeout != Some(timeout) {
        socket
            .set_read_timeout(Some(timeout))
            .map_err(|e| VaneError::Generic(format!("Failed to set UDP read timeout: {e}")))?;
        *last_read_timeout = Some(timeout);
    }

    // ponytail: two fcntl toggles per burst and one recv syscall per datagram;
    // a poll-based loop (mio) with recvmmsg/GRO batching would drop both, if
    // syscall count ever shows up in a profile.
    let mut draining = false;
    let result = loop {
        match socket.recv(&mut buf[..]) {
            Ok(len) => {
                if !draining {
                    draining = true;
                    if let Err(e) = socket.set_nonblocking(true) {
                        break Err(VaneError::Generic(format!(
                            "Failed to set UDP socket non-blocking: {e}"
                        )));
                    }
                }
                let recv_info = quiche::RecvInfo {
                    from: peer_addr,
                    to: local_addr,
                };
                match conn.recv(&mut buf[..len], recv_info) {
                    Ok(_) => {}
                    Err(quiche::Error::Done) => break Ok(()),
                    Err(e) => break Err(e.into()),
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
                break Ok(());
            }
            Err(e) => {
                break Err(VaneError::Transport(format!(
                    "Failed to receive UDP packet: {e}"
                )));
            }
        }
    };

    // Restore before propagating anything: a socket left non-blocking would
    // turn the next call's opening wait into a busy spin.
    if draining {
        let restored = socket.set_nonblocking(false);
        result?;
        restored.map_err(|e| {
            VaneError::Generic(format!("Failed to restore blocking UDP socket: {e}"))
        })?;
        return Ok(());
    }
    result
}

fn flush_quic_packets(
    socket: &UdpSocket,
    out: &mut [u8],
    conn: &mut quiche::Connection,
) -> Result<(), VaneError> {
    loop {
        match conn.send(&mut out[..]) {
            Ok((written, send_info)) => {
                let _ = send_info;
                socket
                    .send(&out[..written])
                    .map_err(|e| VaneError::Transport(format!("Failed to send UDP packet: {e}")))?;
            }
            Err(quiche::Error::Done) => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

struct ResponseState {
    status_code: u16,
    headers: HashMap<String, String>,
    set_cookie_headers: Vec<String>,
    body: Vec<u8>,
    body_file_path: Option<String>,
    body_file: Option<File>,
    finished: bool,
    /// Set once a final (non-1xx) HEADERS block has been folded in — the
    /// response header section is complete and the status/header map may be
    /// acted on. Trailers arrive later and still merge; they do not clear it.
    headers_complete: bool,
    max_body_bytes: u64,
    body_len: usize,
    download_total: u64,
    /// Set by the HTTP/3 path while a 3xx from this response could still be
    /// followed. Such a body is an intermediate the caller never asked for: its
    /// bytes must not reach the progress counters (the next hop would restart
    /// from zero and walk the bar backwards) and it is capped hard. It is still
    /// read and kept, because a hop the redirect gate then refuses is returned
    /// to the caller in full.
    redirect_possible: bool,
}

impl ResponseState {
    fn new(max_body_bytes: u64, body_file_path: Option<&str>) -> Result<Self, VaneError> {
        let body_file = match body_file_path {
            Some(path) if !path.is_empty() => Some(File::create(path).map_err(|e| {
                VaneError::InvalidRequest(format!(
                    "Failed to create response body file {path}: {e}"
                ))
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
            headers_complete: false,
            max_body_bytes,
            body_len: 0,
            download_total: 0,
            redirect_possible: false,
        })
    }

    /// True while this response is a 3xx that could still be followed, which
    /// makes its body an intermediate rather than the caller's download.
    fn is_intermediate_redirect(&self) -> bool {
        self.redirect_possible && (300..400).contains(&self.status_code)
    }

    /// The limit this body is held to. An intermediate redirect gets the small
    /// one; see [`MAX_INTERMEDIATE_BODY_BYTES`].
    fn effective_max_body_bytes(&self) -> u64 {
        if self.is_intermediate_redirect() {
            MAX_INTERMEDIATE_BODY_BYTES.min(self.max_body_bytes)
        } else {
            self.max_body_bytes
        }
    }

    /// Records the advertised body size for progress and pre-sizes the
    /// in-memory body. HEAD and 304 responses carry a `content-length` for an
    /// entity that never arrives, so the reservation is capped well below the
    /// configured response limit; unparsable values are ignored.
    fn on_content_length(&mut self, content_length: &str) {
        let Ok(len) = content_length.parse::<u64>() else {
            return;
        };
        self.download_total = len;
        if self.body_file.is_some() {
            return;
        }
        if let Ok(len) = usize::try_from(len.min(self.max_body_bytes).min(MAX_BODY_RESERVE_BYTES)) {
            self.body.reserve_exact(len);
        }
    }

    /// Folds one response header into the state, applying the rules both
    /// transports share, so the same response yields the same map whether UDP
    /// or the TCP fallback served it:
    ///
    /// - `set-cookie` goes to its own list and never enters the map: a
    ///   `HashMap` cannot hold its repeats and RFC 6265 forbids joining them
    ///   (an `Expires` value contains a comma).
    /// - `location` keeps its first occurrence whole and drops repeats: it is
    ///   single-valued (RFC 9110 §10.2.2), a joined `"a, b"` is not a URL,
    ///   and the TCP path's `HeaderMap::get` already hands the redirect gate
    ///   the first occurrence — so first-wins is what keeps the map, the gate
    ///   and both transports agreeing on the same value.
    /// - Any other repeated name is combined into one `", "`-joined field
    ///   value in wire order (RFC 9110 §5.2), the shape `package:http`-style
    ///   consumers split back apart.
    /// - `content-length` feeds the body-size hint from its first occurrence
    ///   only. A repeat is malformed (RFC 9110 §8.6); the map keeps the
    ///   joined evidence verbatim, but re-parsing later occurrences would let
    ///   a hostile repeat — or a trailer — move the reservation hint after
    ///   the first was already acted on.
    ///
    /// Callers pass lowercase names: reqwest's `HeaderName` already is, and
    /// the HTTP/3 block merge lowercases before calling.
    fn merge_header(&mut self, name: String, value: String) {
        if name == "set-cookie" {
            self.set_cookie_headers.push(value);
            return;
        }
        match self.headers.get_mut(&name) {
            Some(combined) => {
                if name == "location" {
                    return;
                }
                combined.push_str(", ");
                combined.push_str(&value);
            }
            None => {
                if name == "content-length" {
                    self.on_content_length(&value);
                }
                self.headers.insert(name, value);
            }
        }
    }

    fn push_body(&mut self, bytes: &[u8]) -> Result<(), VaneError> {
        validate_response_body_limit(self.body_len, bytes.len(), self.effective_max_body_bytes())
            // Says which limit was hit: "exceeded 65536 bytes" against a
            // configured 64 MiB reads as a bug in Vane otherwise.
            .map_err(|err| {
                if self.is_intermediate_redirect() {
                    VaneError::BodyLimitExceeded(format!(
                        "Redirect response body exceeded {MAX_INTERMEDIATE_BODY_BYTES} bytes"
                    ))
                } else {
                    err
                }
            })?;
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

/// Folds one HEADERS block into the response, discarding interim (1xx) ones.
///
/// quiche's h3 layer emits one `Event::Headers` per HEADERS frame and has no
/// notion of a final response, so without this an `103 Early Hints` block's
/// `set-cookie` values would be surfaced on the final response and its other
/// fields would be comma-joined into the real ones. hyper consumes 1xx
/// internally on the TCP path, so dropping them here is also what keeps the two
/// transports agreeing on what the server sent (RFC 9114 §4.1.2). A trailers
/// block (an `Event::Headers` with no `:status`) folds in as before; a trailer
/// name that repeats a header name joins like any other repeat.
fn merge_h3_header_block(response: &mut ResponseState, list: Vec<quiche::h3::Header>) {
    // `None` rather than 0: a trailers block is also an `Event::Headers` and
    // carries no `:status`, so treating "absent" as 0 would wipe the real
    // status code off the response.
    let mut status: Option<u16> = None;
    let mut fields = Vec::with_capacity(list.len());
    for header in list {
        // Lowercased before it is keyed: HTTP/3 field names are lowercase by
        // protocol, but the peer controls them, and `Location` plus `location`
        // as two map entries would make the redirect gate's lookup
        // nondeterministic. Lowercasing first means such a repeat comma-joins
        // into a single entry instead, exactly as the TCP path's `HeaderName`
        // normalization makes it do.
        let name = String::from_utf8_lossy(header.name()).to_ascii_lowercase();
        let value = String::from_utf8_lossy(header.value()).to_string();
        if name == ":status" {
            status = Some(value.parse::<u16>().unwrap_or_default());
        } else {
            fields.push((name, value));
        }
    }
    if let Some(status) = status {
        if (100..200).contains(&status) {
            return;
        }
        response.status_code = status;
        response.headers_complete = true;
    }
    for (name, value) in fields {
        response.merge_header(name, value);
    }
}

fn process_h3_events(
    http3: &mut quiche::h3::Connection,
    conn: &mut quiche::Connection,
    buf: &mut [u8],
    response: &mut ResponseState,
    cancel_token: Option<&AtomicBool>,
    progress: Option<&VaneProgressState>,
    response_started: &mut bool,
) -> Result<(), VaneError> {
    loop {
        match http3.poll(conn) {
            Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                *response_started = true;
                merge_h3_header_block(response, list);
                let _ = stream_id;
            }
            Ok((stream_id, quiche::h3::Event::Data)) => loop {
                *response_started = true;
                check_cancelled(cancel_token)?;
                match http3.recv_body(conn, stream_id, &mut buf[..]) {
                    Ok(read) => {
                        response.push_body(&buf[..read])?;
                        if !response.is_intermediate_redirect() {
                            progress_download(
                                progress,
                                response.body_len as u64,
                                response.download_total,
                            );
                        }
                    }
                    Err(quiche::h3::Error::Done) => break,
                    Err(e) => return Err(e.into()),
                }
            },
            Ok((_stream_id, quiche::h3::Event::Finished)) => {
                *response_started = true;
                response.finished = true;
                break;
            }
            Ok((_stream_id, quiche::h3::Event::Reset(e))) => {
                *response_started = true;
                return Err(VaneError::Transport(format!("HTTP/3 stream reset: {e:?}")));
            }
            Ok((_id, quiche::h3::Event::GoAway)) => {
                return Err(VaneError::Transport("HTTP/3 GOAWAY received".to_string()));
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
pub fn create_cancel_token() -> u64 {
    cancel_token_create()
}

#[uniffi::export]
pub fn cancel_by_id(id: u64) {
    cancel_token_cancel(id);
}

#[uniffi::export]
pub fn free_cancel_token(id: u64) {
    cancel_token_free(id);
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

    /// Pays the client's one-time setup and connection cost up front — call it
    /// once at app startup, from a background thread (it blocks, exactly like
    /// `execute_request`), so the first real request doesn't pay it.
    ///
    /// What gets warmed follows the configured protocol mode:
    /// - HTTP/3-capable modes establish one pooled QUIC+TLS connection to
    ///   `url` (or `base_url` when `url` is empty). No HTTP request is sent.
    /// - TCP-capable modes build and cache the TCP client (tokio runtime, TLS
    ///   config, platform trust verifier) and run one TLS handshake to the
    ///   target — on Android that first verification loads the system trust
    ///   store and is the bulk of the measured ~1 s first-request cost. Again
    ///   no HTTP request: the server sees a handshake and a clean close.
    /// - `Http3Only` never touches TCP machinery, so it stays as light as it
    ///   is today.
    ///
    /// With neither `url` nor `base_url` there is nothing to connect to;
    /// TCP-capable modes still do the construction, which is most of the win.
    ///
    /// Best effort by contract: failures are swallowed. Every error it could
    /// raise is either transient (no network yet — exactly the startup
    /// condition this exists for) or will be reported, with a better message,
    /// by the first real request. Idempotent and cheap on repeat calls; safe
    /// to call concurrently with requests from any thread.
    pub fn warmup(&self, url: Option<String>) {
        let _ = self.warmup_inner(url.as_deref());
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
    /// `VaneHttpVersion::ffi_code`; 0 when the protocol is not known. Offset 3
    /// — the one free padding byte after `is_success` — so the struct neither
    /// grows nor moves a field. There is no second free byte.
    pub http_version: u8,
    /// `VaneError::ffi_kind` for `error`; 0 when `error` is empty. Sits here
    /// rather than at the end because it fits the padding after `is_success`,
    /// so the struct does not grow.
    pub error_kind: u32,
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

/// Version of the raw C ABI (`vane_ffi_*` symbols and `VaneFfi*` structs).
///
/// Kotlin and Swift ride UniFFI's own checksum guard; the Dart bindings
/// mirror these structs by hand, and this is their equivalent:
/// `vane_flutter/lib/vane_flutter_ffi.dart` looks this symbol up when the
/// library opens and refuses to run on a mismatch, turning layout skew into a
/// clear error instead of misread fields and wild-pointer frees.
///
/// Bump it on ANY `VaneFfi*` struct layout change OR value-contract change
/// (a new `ffi_kind` / `ffi_code` enum code counts), and bump the expected
/// constant in `vane_flutter_ffi.dart` in the same change. A new exported
/// symbol the Dart side binds also counts: a library without it cannot serve
/// that package, and the version check is what turns that skew into a clear
/// error instead of a symbol-lookup failure.
///
/// v2: added `vane_ffi_client_warmup`.
#[unsafe(no_mangle)]
pub extern "C" fn vane_ffi_abi_version() -> u32 {
    2
}

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

/// Blocking, best-effort warm-up of the client behind `handle`; see
/// [`VaneClient::warmup`]. An empty `url` means "use the client's base_url".
///
/// No `out_error` on purpose: warmup swallows failures by contract, and an
/// unknown handle warms nothing, which is indistinguishable from — and as
/// harmless as — any other failed warmup.
#[unsafe(no_mangle)]
pub extern "C" fn vane_ffi_client_warmup(handle: u64, url: VaneFfiString) {
    let _ = std::panic::catch_unwind(|| {
        let Some(client) = FFI_CLIENTS
            .lock()
            .ok()
            .and_then(|clients| clients.get(&handle).cloned())
        else {
            return;
        };
        let Ok(url) = ffi_optional_string(url, "warmup_url") else {
            return;
        };
        client.warmup(url);
    });
}

#[unsafe(no_mangle)]
pub extern "C" fn vane_ffi_cancel_token_create() -> u64 {
    cancel_token_create()
}

#[unsafe(no_mangle)]
pub extern "C" fn vane_ffi_cancel_token_cancel(id: u64) {
    cancel_token_cancel(id);
}

#[unsafe(no_mangle)]
pub extern "C" fn vane_ffi_cancel_token_free(id: u64) {
    cancel_token_free(id);
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
        Err(_) => ffi_error_response(VaneError::Generic(
            "Rust panic while executing Vane request".to_string(),
        )),
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
) -> Result<VaneResponse, VaneError> {
    let client = {
        let clients = FFI_CLIENTS
            .lock()
            .map_err(|_| VaneError::Generic("Vane FFI client registry lock was poisoned".into()))?;
        clients.get(&handle).cloned().ok_or_else(|| {
            VaneError::InvalidRequest(format!("No Vane client exists for handle {handle}"))
        })?
    };
    // The decoding helpers report plain strings; nothing about a malformed
    // request struct is transport-related, so they all land on InvalidRequest.
    let mut request = ffi_request(request).map_err(VaneError::InvalidRequest)?;
    if body_len > 0 {
        // Refused before the copy below materializes the caller's buffer, or
        // an over-limit body costs its full size in memory just to be
        // rejected. `execute` re-checks the loaded body; same error there.
        validate_request_body_limit(body_len as u64, client.config.max_request_body_bytes)?;
        request.body = Some(
            ffi_bytes(body_data, body_len)
                .map_err(VaneError::InvalidRequest)?
                .to_vec(),
        );
    } else {
        request.body = None;
    }
    client.execute(request)
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
        http_version: response.http_version.map_or(0, VaneHttpVersion::ffi_code),
        error_kind: 0,
        headers: ffi_header_array_from(response.headers, response.set_cookie),
        body: ffi_buffer_from_vec(response.body),
        body_file_path: ffi_buffer_from_vec(
            response.body_file_path.unwrap_or_default().into_bytes(),
        ),
        url: ffi_buffer_from_vec(response.url.into_bytes()),
        error: ffi_buffer_from_vec(Vec::new()),
    }
}

fn ffi_error_response(error: VaneError) -> VaneFfiResponse {
    VaneFfiResponse {
        status_code: 0,
        is_success: false,
        http_version: 0,
        error_kind: error.ffi_kind(),
        headers: ffi_header_array_empty(),
        body: ffi_buffer_from_vec(Vec::new()),
        body_file_path: ffi_buffer_from_vec(Vec::new()),
        url: ffi_buffer_from_vec(Vec::new()),
        error: ffi_buffer_from_vec(error.to_string().into_bytes()),
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

/// The array has always been a `(key, value)` list rather than a map, so the
/// `Set-Cookie` values ride as repeated `("set-cookie", value)` entries instead
/// of a second `repr(C)` field. Consumers must not assume unique keys.
fn ffi_header_array_from(
    headers: HashMap<String, String>,
    set_cookie: Vec<String>,
) -> VaneFfiHeaderArray {
    let mut headers: Vec<VaneFfiHeader> = headers
        .into_iter()
        .map(|(key, value)| VaneFfiHeader {
            key: ffi_buffer_from_vec(key.into_bytes()),
            value: ffi_buffer_from_vec(value.into_bytes()),
        })
        .chain(set_cookie.into_iter().map(|value| VaneFfiHeader {
            key: ffi_buffer_from_vec(b"set-cookie".to_vec()),
            value: ffi_buffer_from_vec(value.into_bytes()),
        }))
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

/// Serializes tests that install a process-wide TLS trust anchor.
#[cfg(all(test, feature = "tcp-fallback"))]
pub(crate) fn tcp_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Shared by the unit tests in this file and in `tcp::tests`.
#[cfg(test)]
fn test_request(url: &str) -> VaneRequest {
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

#[cfg(test)]
mod proptests;

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
    fn quic_read_timeout_stays_in_settable_range() {
        // A pooled connection with an already-expired quiche timer reports
        // ZERO, which UdpSocket::set_read_timeout rejects — must floor to 1 ms.
        assert_eq!(
            quic_read_timeout(Some(Duration::ZERO)),
            Duration::from_millis(1)
        );
        assert_eq!(
            quic_read_timeout(Some(Duration::from_micros(200))),
            Duration::from_millis(1)
        );
        // No timer pending: the 10 ms default.
        assert_eq!(quic_read_timeout(None), Duration::from_millis(10));
        // In-range timers pass through; long timers cap at 50 ms.
        assert_eq!(
            quic_read_timeout(Some(Duration::from_millis(25))),
            Duration::from_millis(25)
        );
        assert_eq!(
            quic_read_timeout(Some(Duration::from_secs(3))),
            Duration::from_millis(50)
        );
    }

    /// The sockopt call ignores errors by design (a default-buffer socket
    /// still works), so a typo in level/optname would regress silently — this
    /// readback is the only thing that would catch it.
    #[cfg(unix)]
    #[test]
    fn quic_socket_receive_buffer_actually_grows() {
        use std::os::fd::AsRawFd as _;

        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let read_back = |socket: &UdpSocket| {
            let mut size: libc::c_int = 0;
            let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            // SAFETY: getsockopt on an open fd with a correctly-sized out slot.
            let rc = unsafe {
                libc::getsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    (&raw mut size).cast(),
                    &raw mut len,
                )
            };
            assert_eq!(rc, 0, "getsockopt(SO_RCVBUF) failed");
            size
        };

        let before = read_back(&socket);
        request_large_udp_recv_buffer(&socket);
        let after = read_back(&socket);

        // Exact values are platform policy (Linux doubles the request and
        // clamps to rmem_max; macOS reports the request verbatim), so assert
        // the floor that matters: comfortably above the ~110-packet response
        // flight that overflowed Linux/Android's ~213-229 KB default.
        assert!(
            after >= 262_144,
            "SO_RCVBUF after request: {after} (before: {before})"
        );
        assert!(after >= before, "SO_RCVBUF shrank: {before} -> {after}");
    }

    #[test]
    fn default_config_uses_http3_only() {
        let config = VaneClientConfig::default();

        assert_eq!(config.protocol_mode, VaneProtocolMode::Http3Only);
        assert_eq!(config.timeout_seconds, Some(30));
        assert!(!config.cookies_enabled);
        assert!(config.connection_pool_enabled);
        assert_eq!(config.max_idle_connections, 4);
        assert_eq!(config.connection_idle_timeout_seconds, 25);
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

        // Redirects are NOT followed here: `/cookies/set/...` answers 302 and
        // only the final response's `Set-Cookie` is surfaced, so following it
        // would land on `/cookies`, which sets nothing. The jar still harvests
        // every hop either way — the reads below prove it.
        let set_cookie = client
            .execute(VaneRequest {
                follow_redirects: false,
                ..test_request("/cookies/set/vane_cookie/live")
            })
            .expect("HTTP/3 cookie set should succeed");
        assert_eq!(set_cookie.status_code, 302);
        // The H3 half of what `tcp::tests::response_metadata` proves offline:
        // the values reach the caller as well as the jar, and never through
        // the header map.
        assert!(
            set_cookie
                .set_cookie
                .iter()
                .any(|value| value.contains("vane_cookie")),
            "set_cookie was {:?}",
            set_cookie.set_cookie
        );
        assert!(!set_cookie.headers.contains_key("set-cookie"));
        assert_eq!(set_cookie.http_version, Some(VaneHttpVersion::Http3));

        let cookies = client
            .get_request("/cookies".to_string())
            .expect("HTTP/3 cookie read should succeed");
        assert!(cookies.is_success);
        assert_response_body_contains(&cookies, "vane_cookie");
        assert_response_body_contains(&cookies, "live");
    }

    #[test]
    fn live_http3_follows_a_redirect_chain_when_base_url_is_set() {
        let Some(base_url) = live_https_base_url() else {
            return;
        };

        let client = VaneClient::new(VaneClientConfig {
            base_url: Some(base_url.clone()),
            protocol_mode: VaneProtocolMode::Http3Only,
            timeout_seconds: Some(30),
            ..VaneClientConfig::default()
        })
        .unwrap();

        // Three hops, and the reported URL is the last one, not the first.
        let followed = client
            .get_request("/redirect/3".to_string())
            .expect("HTTP/3 redirect chain should be followed");
        assert!(followed.is_success, "status {}", followed.status_code);
        assert_eq!(followed.url, format!("{base_url}/get"));

        // Opting out returns the 3xx itself — the same thing the TCP path does.
        let mut opted_out = request("/redirect/3");
        opted_out.follow_redirects = false;
        let opted_out = client
            .execute(opted_out)
            .expect("HTTP/3 GET should succeed");
        assert_eq!(opted_out.status_code, 302);
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
    fn plaintext_proxies_are_rejected_for_both_transports() {
        fn client_error(config: VaneClientConfig) -> String {
            match VaneClient::new(config) {
                Ok(_) => panic!("client construction should have failed"),
                Err(err) => err.to_string(),
            }
        }

        // Checked at construction so the posture cannot depend on which
        // transport ends up carrying the request.
        let err = client_error(VaneClientConfig {
            proxy_url: Some("http://proxy.example.com:8080".to_string()),
            ..VaneClientConfig::default()
        });

        assert!(err.contains("proxyUrl must use https://"), "got {err}");
        assert!(err.contains("proxyAuthorization"), "got {err}");

        // Credentials in a bad proxy URL must not reach the error string.
        let err = client_error(VaneClientConfig {
            proxy_url: Some("http://user:hunter2@proxy.example.com".to_string()),
            ..VaneClientConfig::default()
        });
        assert!(!err.contains("hunter2"), "proxy password leaked: {err}");

        assert!(
            VaneClient::new(VaneClientConfig {
                proxy_url: Some("https://proxy.example.com:443".to_string()),
                ..VaneClientConfig::default()
            })
            .is_ok()
        );
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

        // `masque_inner_udp_payload` budgets exactly this many framing bytes;
        // if the encoder's prefix ever grows, the inner MTU silently overflows
        // the outer connection's datagram limit.
        for flow_id in [0, 64, 16_384, 1_073_741_824] {
            assert_eq!(
                encode_h3_datagram(flow_id, 0, b"").unwrap().len(),
                varint_len(flow_id) + varint_len(0)
            );
        }
    }

    #[test]
    fn masque_path_component_percent_encodes_ipv6_colons() {
        assert_eq!(masque_path_component("2001:db8::1"), "2001%3Adb8%3A%3A1");
    }

    #[cfg(not(feature = "tcp-fallback"))]
    #[test]
    fn tcp_modes_report_that_fallback_is_unavailable() {
        for mode in [
            VaneProtocolMode::Http2ThenHttp1,
            VaneProtocolMode::Http2Only,
            VaneProtocolMode::Http1Only,
        ] {
            let client = VaneClient::new(VaneClientConfig {
                protocol_mode: mode,
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
    }

    /// Loopback port 1 refuses immediately, so this reaches the TCP backend and
    /// forces the client to actually build — TLS config, root store, pinned
    /// verifier and mode flags — without depending on the network.
    #[cfg(feature = "tcp-fallback")]
    fn assert_reaches_tcp_backend(mode: VaneProtocolMode) {
        let client = VaneClient::new(VaneClientConfig {
            protocol_mode: mode.clone(),
            timeout_seconds: Some(1),
            ..VaneClientConfig::default()
        })
        .unwrap();

        let err = client
            .execute(request("https://127.0.0.1:1/"))
            .unwrap_err()
            .to_string();

        assert!(
            !err.contains("fallback were removed"),
            "{mode:?} should dispatch to the TCP backend, got {err}"
        );
        assert!(
            err.contains("HTTP request failed"),
            "{mode:?} should fail at the TCP transport, got {err}"
        );
    }

    #[cfg(feature = "tcp-fallback")]
    #[test]
    fn tcp_only_modes_dispatch_to_the_tcp_backend() {
        assert_reaches_tcp_backend(VaneProtocolMode::Http2ThenHttp1);
        assert_reaches_tcp_backend(VaneProtocolMode::Http2Only);
        assert_reaches_tcp_backend(VaneProtocolMode::Http1Only);
    }

    #[cfg(feature = "tcp-fallback")]
    #[test]
    fn http3_then_tcp_mode_falls_back_after_the_http3_transport_fails() {
        // HTTP/3 cannot hand back a response here, so reaching a TCP transport
        // error proves the fallback engaged rather than surfacing the H3 error.
        assert_reaches_tcp_backend(VaneProtocolMode::Http3ThenHttp2ThenHttp1);

        let client = VaneClient::new(VaneClientConfig {
            protocol_mode: VaneProtocolMode::Http3ThenHttp2ThenHttp1,
            timeout_seconds: Some(1),
            ..VaneClientConfig::default()
        })
        .unwrap();
        let err = client
            .execute(request("https://127.0.0.1:1/"))
            .unwrap_err()
            .to_string();

        // When both transports fail the caller needs to see both.
        assert!(err.contains("HTTP/3 transport failed"), "got {err}");
        assert!(err.contains("TCP fallback also failed"), "got {err}");
    }

    /// Transport-level only: the endpoint just has to speak HTTPS over TCP, so
    /// this asserts a status, headers and a readable body — not any particular
    /// response shape.
    #[cfg(feature = "tcp-fallback")]
    fn assert_live_tcp_get(mode: VaneProtocolMode) {
        let Some(base_url) = live_https_base_url() else {
            return;
        };

        let client = VaneClient::new(VaneClientConfig {
            base_url: Some(base_url),
            protocol_mode: mode.clone(),
            timeout_seconds: Some(30),
            ..VaneClientConfig::default()
        })
        .unwrap();

        let response = client
            .get_request("/".to_string())
            .unwrap_or_else(|err| panic!("{mode:?} GET over TCP should succeed: {err}"));

        assert!(
            response.status_code >= 100,
            "{mode:?} should return a status line"
        );
        assert!(
            !response.headers.is_empty(),
            "{mode:?} should return response headers"
        );
    }

    #[cfg(feature = "tcp-fallback")]
    #[test]
    fn live_http1_only_get_over_tcp_when_base_url_is_set() {
        assert_live_tcp_get(VaneProtocolMode::Http1Only);
    }

    #[cfg(feature = "tcp-fallback")]
    #[test]
    fn live_http2_then_http1_get_over_tcp_when_base_url_is_set() {
        assert_live_tcp_get(VaneProtocolMode::Http2ThenHttp1);
    }

    #[cfg(feature = "tcp-fallback")]
    #[test]
    fn non_idempotent_methods_never_fall_back_to_tcp() {
        // HTTP/3 can fail after the server already accepted the request, so
        // replaying a POST over TCP would create the resource twice. The
        // fallback must honour the same rule the retry policy does.
        for (method, unsafe_methods, may_fall_back) in [
            ("POST", false, false),
            ("PATCH", false, false),
            ("POST", true, true),
            ("GET", false, true),
            ("PUT", false, true),
        ] {
            let client = VaneClient::new(VaneClientConfig {
                protocol_mode: VaneProtocolMode::Http3ThenHttp2ThenHttp1,
                retry_unsafe_methods: unsafe_methods,
                timeout_seconds: Some(1),
                ..VaneClientConfig::default()
            })
            .unwrap();
            let mut req = request("https://127.0.0.1:1/");
            req.method = method.to_string();

            let err = client.execute(req).unwrap_err().to_string();

            assert_eq!(
                err.contains("TCP fallback also failed"),
                may_fall_back,
                "{method} (retry_unsafe_methods={unsafe_methods}) fallback decision wrong: {err}"
            );
        }
    }

    /// The fallback rule reads two predicates off the error kind; both are
    /// safety-relevant, so pin the mapping rather than the six-line `match`
    /// that consumes it.
    #[test]
    fn error_kinds_drive_the_fallback_decision() {
        let msg = || "x".to_string();
        for (error, transport, never_sent) in [
            (VaneError::Generic(msg()), true, false),
            (VaneError::Transport(msg()), true, false),
            (VaneError::Timeout(msg()), true, false),
            (VaneError::ConnectTimeout(msg()), true, true),
            (VaneError::InvalidRequest(msg()), false, false),
            (VaneError::Cancelled(msg()), false, false),
            (VaneError::Tls(msg()), false, false),
            (VaneError::BodyLimitExceeded(msg()), false, false),
            (VaneError::ProtocolUnsupported(msg()), false, false),
        ] {
            assert_eq!(error.is_transport_failure(), transport, "{error:?}");
            assert_eq!(error.never_left_the_client(), never_sent, "{error:?}");
        }
    }

    /// `ffi_kind` values are baked into `VaneFfiResponse.error_kind` and
    /// mirrored by `VaneErrorKind` in Dart. Renumbering silently mislabels
    /// every error on that binding, so nail the wire values down.
    #[test]
    fn ffi_error_kind_codes_are_stable() {
        let msg = || "x".to_string();
        assert_eq!(VaneError::Generic(msg()).ffi_kind(), 0);
        assert_eq!(VaneError::InvalidRequest(msg()).ffi_kind(), 1);
        assert_eq!(VaneError::Cancelled(msg()).ffi_kind(), 2);
        assert_eq!(VaneError::ConnectTimeout(msg()).ffi_kind(), 3);
        assert_eq!(VaneError::Timeout(msg()).ffi_kind(), 4);
        assert_eq!(VaneError::Transport(msg()).ffi_kind(), 5);
        assert_eq!(VaneError::Tls(msg()).ffi_kind(), 6);
        assert_eq!(VaneError::BodyLimitExceeded(msg()).ffi_kind(), 7);
        assert_eq!(VaneError::ProtocolUnsupported(msg()).ffi_kind(), 8);
        // Fourth byte in, filling the padding after `is_success` on both 32-
        // and 64-bit, which is why the field cost no struct growth. Dart
        // derives the same offset from its own field order, so a field
        // inserted above this one silently desyncs the two.
        assert_eq!(std::mem::offset_of!(VaneFfiResponse, error_kind), 4);
        // The one remaining padding byte. `headers` is what proves the struct
        // did not grow, and unlike a `size_of` literal it holds on both
        // pointer widths.
        assert_eq!(std::mem::offset_of!(VaneFfiResponse, http_version), 3);
        assert_eq!(std::mem::offset_of!(VaneFfiResponse, headers), 8);

        assert_eq!(VaneHttpVersion::Http10.ffi_code(), 1);
        assert_eq!(VaneHttpVersion::Http11.ffi_code(), 2);
        assert_eq!(VaneHttpVersion::Http2.ffi_code(), 3);
        assert_eq!(VaneHttpVersion::Http3.ffi_code(), 4);
    }

    /// The C ABI has no `set_cookie` field: the values ride as repeated
    /// `("set-cookie", value)` entries in the header array, which a `HashMap`
    /// input could never produce.
    #[test]
    fn ffi_header_array_carries_repeated_set_cookie() {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "text/plain".to_string());
        let array = ffi_header_array_from(
            headers,
            vec!["a=1; Path=/".to_string(), "b=2; Path=/".to_string()],
        );
        assert_eq!(array.len, 3);
        let entries: Vec<(String, String)> = (0..array.len)
            .map(|index| unsafe {
                let header = &*array.data.add(index);
                (
                    String::from_utf8_lossy(std::slice::from_raw_parts(
                        header.key.data,
                        header.key.len,
                    ))
                    .into_owned(),
                    String::from_utf8_lossy(std::slice::from_raw_parts(
                        header.value.data,
                        header.value.len,
                    ))
                    .into_owned(),
                )
            })
            .collect();
        let cookies: Vec<&str> = entries
            .iter()
            .filter(|(key, _)| key == "set-cookie")
            .map(|(_, value)| value.as_str())
            .collect();
        assert_eq!(cookies, vec!["a=1; Path=/", "b=2; Path=/"]);
        ffi_header_array_free(array);
    }

    /// warmup is best-effort: bad input errors internally and is swallowed
    /// publicly, and a client with nothing to connect to warms nothing.
    #[test]
    fn warmup_swallows_failures_and_nops_without_a_target() {
        // Default config: Http3Only, no base_url.
        let client = VaneClient::new(VaneClientConfig::default()).unwrap();
        client.warmup_inner(None).expect("no target: nothing to do");
        assert!(client.pool.lock().unwrap().is_empty());
        #[cfg(feature = "tcp-fallback")]
        assert!(client.tcp_client.lock().unwrap().is_none());

        let err = client.warmup_inner(Some("not a url")).unwrap_err();
        assert!(matches!(err, VaneError::InvalidRequest(_)), "{err:?}");
        // The same https-only rule every transport enforces.
        let err = client
            .warmup_inner(Some("http://example.com/"))
            .unwrap_err();
        assert!(matches!(err, VaneError::InvalidRequest(_)), "{err:?}");

        // The public method swallows all of it.
        client.warmup(Some("not a url".to_string()));
        client.warmup(None);
    }

    /// Http3Only with the pool disabled has nowhere to park a connection, so
    /// warmup must return without dialing (the TEST-NET-1 address would hang)
    /// and without touching TCP machinery.
    #[test]
    fn warmup_http3_only_with_pool_disabled_is_a_complete_noop() {
        let client = VaneClient::new(VaneClientConfig {
            connection_pool_enabled: false,
            ..VaneClientConfig::default()
        })
        .unwrap();
        client
            .warmup_inner(Some("https://192.0.2.1/"))
            .expect("pool disabled: nothing to warm");
        assert!(client.pool.lock().unwrap().is_empty());
        #[cfg(feature = "tcp-fallback")]
        assert!(client.tcp_client.lock().unwrap().is_none());
    }

    /// The reason the kind exists at all: an `http://` URL is rejected by both
    /// transports, so before the kind landed this burned a whole TCP attempt
    /// (and a second timeout) to arrive at the same answer.
    #[cfg(feature = "tcp-fallback")]
    #[test]
    fn non_transport_failures_never_reach_the_fallback() {
        let client = VaneClient::new(VaneClientConfig {
            protocol_mode: VaneProtocolMode::Http3ThenHttp2ThenHttp1,
            ..VaneClientConfig::default()
        })
        .unwrap();

        let err = client.execute(request("http://example.com/")).unwrap_err();

        assert!(matches!(err, VaneError::InvalidRequest(_)), "{err:?}");
        assert!(
            !err.to_string().contains("TCP fallback"),
            "the TCP fallback should not have been tried: {err}"
        );
    }

    /// An HTTP status is a completed exchange. Falling back on one would send
    /// the request a second time over a different transport.
    #[cfg(feature = "tcp-fallback")]
    #[test]
    fn http3_non_2xx_responses_never_reach_the_fallback() {
        let Some(base_url) = live_https_base_url() else {
            return;
        };
        let client = VaneClient::new(VaneClientConfig {
            base_url: Some(base_url),
            protocol_mode: VaneProtocolMode::Http3ThenHttp2ThenHttp1,
            timeout_seconds: Some(30),
            ..VaneClientConfig::default()
        })
        .unwrap();

        let response = client
            .get_request("/vane-nonexistent-path-for-status-test".to_string())
            .expect("a non-2xx status is a successful exchange, not a transport failure");

        assert!(response.status_code >= 400, "expected an error status");
        assert!(!response.is_success);
    }

    #[cfg(not(feature = "tcp-fallback"))]
    #[test]
    fn http3_then_tcp_mode_returns_the_raw_http3_error_without_the_feature() {
        let client = VaneClient::new(VaneClientConfig {
            protocol_mode: VaneProtocolMode::Http3ThenHttp2ThenHttp1,
            timeout_seconds: Some(1),
            ..VaneClientConfig::default()
        })
        .unwrap();

        let err = client
            .execute(request("http://api.example.com/users"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("https:// URLs"), "got {err}");
        assert!(!err.contains("TCP fallback"), "got {err}");
    }

    /// warmup mirrors `execute`: a TCP-only mode without the backend reports
    /// the same refusal internally (and swallows it publicly) rather than
    /// pretending it warmed something.
    #[cfg(not(feature = "tcp-fallback"))]
    #[test]
    fn warmup_in_a_tcp_only_mode_reports_unsupported_without_the_feature() {
        let client = VaneClient::new(VaneClientConfig {
            protocol_mode: VaneProtocolMode::Http2Only,
            ..VaneClientConfig::default()
        })
        .unwrap();

        let err = client
            .warmup_inner(Some("https://api.example.com/"))
            .unwrap_err();
        assert!(matches!(err, VaneError::ProtocolUnsupported(_)), "{err:?}");
        client.warmup(None);
    }

    #[cfg(feature = "tcp-fallback")]
    #[test]
    fn http3_only_mode_never_falls_back_to_tcp() {
        let client = VaneClient::new(VaneClientConfig {
            protocol_mode: VaneProtocolMode::Http3Only,
            timeout_seconds: Some(1),
            ..VaneClientConfig::default()
        })
        .unwrap();

        let err = client
            .execute(request("https://127.0.0.1:1/"))
            .unwrap_err()
            .to_string();

        assert!(
            !err.contains("HTTP request failed"),
            "Http3Only must not reach the TCP backend, got {err}"
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
        // Both transports funnel through this, so one check covers both.
        let mut req = request("https://example.com/items");
        req.headers
            .insert(":authority".to_string(), "example.com".to_string());

        let err =
            for_each_regular_header(&req, &VaneClientConfig::default(), |_, _| Ok(())).unwrap_err();

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
        let headers = build_h3_headers(
            &url,
            &req,
            &config,
            "GET",
            ("example.com", 443),
            None,
            false,
        )
        .unwrap();
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

    /// Drives the shipped decision function rather than a copy of its logic, so
    /// the test cannot pass while the code diverges.
    fn redirect(
        status: u16,
        location: &str,
        from: &Url,
        hops: usize,
        pins: &HashMap<String, Vec<String>>,
    ) -> RedirectDecision {
        let request = request(&from.to_string());
        next_redirect_url(status, Some(location), from, &request, hops, pins)
    }

    fn followed(decision: RedirectDecision) -> Option<String> {
        match decision {
            RedirectDecision::Follow(url) => Some(url.to_string()),
            _ => None,
        }
    }

    #[test]
    fn h3_redirect_gate_refuses_downgrades_pinned_hops_and_bad_locations() {
        use RedirectDecision::{Refused, Stop};

        let from = Url::parse("https://api.example.com/login").unwrap();
        let unpinned = HashMap::new();
        let pinned = HashMap::from([(
            "api.example.com".to_string(),
            vec!["sha256/example".to_string()],
        )]);

        // Same host, still https: fine.
        assert_eq!(
            followed(redirect(302, "/home", &from, 0, &pinned)),
            Some("https://api.example.com/home".to_string())
        );
        // Downgrade to cleartext: never. Refused rather than errored, so both
        // transports return the same 3xx for the same URL.
        assert_eq!(
            redirect(302, "http://api.example.com/home", &from, 0, &pinned),
            Refused(REDIRECT_REFUSED_DOWNGRADE)
        );
        // Leaving a pinned host: the pin does not cover the next hop.
        assert_eq!(
            redirect(302, "https://cdn.example.net/home", &from, 0, &pinned),
            Refused(REDIRECT_REFUSED_PINNED_HOST)
        );
        // A port change on a pinned host stays covered by the pin.
        assert_eq!(
            followed(redirect(
                302,
                "https://api.example.com:8443/home",
                &from,
                0,
                &pinned
            )),
            Some("https://api.example.com:8443/home".to_string())
        );
        // Unpinned origin may cross hosts.
        assert_eq!(
            followed(redirect(
                302,
                "https://cdn.example.net/home",
                &from,
                0,
                &unpinned
            )),
            Some("https://cdn.example.net/home".to_string())
        );
        // A Location our parser rejects stops the chain; it is never attributed
        // to the URL we are on. The last one is rejected by the scheme gate
        // instead, which stops the chain just the same.
        for hostile in [
            "https://attacker.test\\.api.example.com/y",
            "https://attacker.test\t.api.example.com/y",
            "https://attacker%2etest/y",
            "https://evil@other.example/",
            "gopher://api.example.com/home",
            // A single value shaped like a comma-join (`merge_header` never
            // produces one for `location`): the `", "` lands in the
            // authority, which cannot parse. Whole-value on both transports,
            // so both stop here identically.
            "https://a.example, https://b.example",
        ] {
            assert_eq!(
                redirect(302, hostile, &from, 0, &unpinned),
                Stop,
                "{hostile} must not resolve"
            );
        }
        // The same malformed shape with a path keeps the `", "` out of the
        // authority, so it parses — to the FIRST URL's host, which is what
        // every security gate keys on; the junk stays in the path verbatim.
        // Both transports hand this gate the same whole value, so they agree.
        assert_eq!(
            followed(redirect(
                302,
                "https://a.example/x, https://b.example/",
                &from,
                0,
                &unpinned
            )),
            Some("https://a.example/x, https://b.example/".to_string())
        );
        // Hop cap, enforced on the last allowed hop and the one after it.
        assert!(matches!(
            redirect(302, "/home", &from, MAX_REDIRECTS - 1, &unpinned),
            RedirectDecision::Follow(_)
        ));
        assert_eq!(
            redirect(302, "/home", &from, MAX_REDIRECTS, &unpinned),
            Refused(REDIRECT_REFUSED_HOP_CAP)
        );
        // Not a redirect status, empty Location, no Location, opted out: all
        // plain stops, and none of them is reported as a refusal.
        assert_eq!(redirect(200, "/home", &from, 0, &unpinned), Stop);
        assert_eq!(redirect(302, "", &from, 0, &unpinned), Stop);
        assert_eq!(
            next_redirect_url(
                302,
                None,
                &from,
                &request("https://api.example.com/login"),
                0,
                &unpinned
            ),
            Stop
        );
        let mut no_follow = request("https://api.example.com/login");
        no_follow.follow_redirects = false;
        assert_eq!(
            next_redirect_url(302, Some("/home"), &from, &no_follow, 0, &unpinned),
            Stop
        );
    }

    /// Covers the whole H3 population path for both new response fields: an
    /// interim block must be discarded, and `into_public_response` is the only
    /// place the H3 transport fills `set_cookie`/`http_version` in. Neither had
    /// offline coverage — the redirect tests assert on the `h3_response` helper
    /// below, which writes the values itself, and the live test is env-gated.
    #[test]
    fn an_interim_h3_header_block_never_reaches_the_response() {
        fn header(name: &str, value: &str) -> quiche::h3::Header {
            quiche::h3::Header::new(name.as_bytes(), value.as_bytes())
        }

        let mut state = ResponseState::new(1024, None).unwrap();
        // 103 Early Hints, then the real response. A hostile or misconfigured
        // peer can put anything in the interim block.
        merge_h3_header_block(
            &mut state,
            vec![
                header(":status", "103"),
                header("set-cookie", "sid=A"),
                header("server", "early"),
            ],
        );
        merge_h3_header_block(
            &mut state,
            vec![
                header(":status", "200"),
                header("set-cookie", "sid=B"),
                header("server", "real"),
            ],
        );
        // A trailers block is an `Event::Headers` too, and carries no
        // `:status`. It must not be mistaken for an interim block, and must
        // not wipe the status code either.
        merge_h3_header_block(&mut state, vec![header("grpc-status", "0")]);

        let response = Http3ResponseParts {
            body_len: state.body_len as u64,
            status_code: state.status_code,
            headers: state.headers,
            set_cookie_headers: state.set_cookie_headers,
            body: state.body,
            body_file_path: state.body_file_path,
            url: "https://example.com/".to_string(),
        }
        .into_public_response();

        assert_eq!(response.status_code, 200);
        assert_eq!(
            response.headers.get("grpc-status").map(String::as_str),
            Some("0")
        );
        assert_eq!(response.set_cookie, vec!["sid=B".to_string()]);
        assert_eq!(
            response.headers.get("server").map(String::as_str),
            Some("real")
        );
        // The map must never carry the cookie: it cannot hold repeats.
        assert!(!response.headers.contains_key("set-cookie"));
        assert_eq!(response.http_version, Some(VaneHttpVersion::Http3));
    }

    /// Pins the join rule the two transports share: a repeated non-cookie
    /// header combines into one `", "`-joined value in wire order (RFC 9110
    /// §5.2), except `location`, which keeps its first occurrence whole.
    /// `repeated_headers_comma_join_identically_on_both_transports` in
    /// `tcp::tests` asserts the same shapes for the same wire on the
    /// TCP fallback — the whole point is that the map cannot depend on
    /// whether UDP happened to work.
    #[test]
    fn repeated_h3_headers_comma_join_across_header_blocks() {
        fn header(name: &str, value: &str) -> quiche::h3::Header {
            quiche::h3::Header::new(name.as_bytes(), value.as_bytes())
        }

        let mut state = ResponseState::new(1024, None).unwrap();
        // An interim block's fields must not leak into the join.
        merge_h3_header_block(
            &mut state,
            vec![header(":status", "103"), header("x-multi", "interim")],
        );
        merge_h3_header_block(
            &mut state,
            vec![
                header(":status", "200"),
                header("x-multi", "a"),
                // Peer-controlled spelling: joins into the lowercase entry
                // rather than forking a second one.
                header("X-Multi", "b"),
                header("x-trailer", "h"),
                header("set-cookie", "sid=1"),
                header("set-cookie", "sid=2"),
                header("content-length", "7"),
                header("content-length", "999"),
                header("location", "https://first.example/"),
                header("location", "https://second.example/"),
            ],
        );
        // A trailers block carries no `:status`; a repeat there joins too.
        merge_h3_header_block(&mut state, vec![header("x-trailer", "t")]);

        assert_eq!(
            state.headers.get("x-multi").map(String::as_str),
            Some("a, b")
        );
        assert_eq!(
            state.headers.get("x-trailer").map(String::as_str),
            Some("h, t")
        );
        // The map carries the malformed repeat verbatim, but the parsed size
        // hint keeps first-value semantics: a later occurrence must not move
        // a reservation the first already sized.
        assert_eq!(
            state.headers.get("content-length").map(String::as_str),
            Some("7, 999")
        );
        assert_eq!(state.download_total, 7);
        // `location` never joins: first occurrence whole, repeats dropped —
        // the value the redirect gate acts on, on both transports. A joined
        // `"a, b"` here would not be a URL at all.
        assert_eq!(
            state.headers.get("location").map(String::as_str),
            Some("https://first.example/")
        );
        assert_eq!(
            state.set_cookie_headers,
            vec!["sid=1".to_string(), "sid=2".to_string()]
        );
        assert!(!state.headers.contains_key("set-cookie"));
    }

    fn h3_response(status: u16, location: Option<&str>, body: &str) -> VaneResponse {
        let mut headers = HashMap::new();
        if let Some(location) = location {
            headers.insert("location".to_string(), location.to_string());
        }
        VaneResponse {
            status_code: status,
            headers,
            body: body.as_bytes().to_vec(),
            body_file_path: None,
            is_success: (200..=299).contains(&status),
            url: String::new(),
            set_cookie: Vec::new(),
            http_version: Some(VaneHttpVersion::Http3),
        }
    }

    /// What one hop was asked to send.
    #[derive(Debug, PartialEq, Eq)]
    struct SeenHop {
        url: String,
        method: String,
        has_body: bool,
        body_dropped: bool,
    }

    /// Drives the shipped chain loop with a stub hop executor. Hop counting,
    /// the method and body rewrites, the shared deadline, refusal reporting and
    /// the replay-safety downgrade are only reachable here without a live
    /// HTTP/3 server, and every one of them is a rule with teeth.
    fn run_chain(
        request: &VaneRequest,
        request_body: &[u8],
        certificate_pins: &HashMap<String, Vec<String>>,
        progress: Option<&VaneProgressState>,
        deadline: Instant,
        mut respond: impl FnMut(usize) -> Result<(VaneResponse, u64), VaneError>,
    ) -> (Result<VaneResponse, VaneError>, Vec<SeenHop>) {
        let mut seen = Vec::new();
        let url = Url::parse(&request.url).unwrap();
        let result = RedirectChain {
            request,
            certificate_pins,
            cancel_token: None,
            progress,
            timeouts: HopTimeouts {
                deadline,
                idle: Duration::from_secs(30),
            },
        }
        .run(&url, request_body, |hop| {
            seen.push(SeenHop {
                url: hop.url.to_string(),
                method: hop.method.to_string(),
                has_body: !hop.body.is_empty(),
                body_dropped: hop.body_dropped,
            });
            respond(seen.len() - 1)
        });
        (result, seen)
    }

    fn post_request(url: &str) -> VaneRequest {
        let mut request = request(url);
        request.method = "POST".to_string();
        request
    }

    fn in_30s() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    #[test]
    fn redirect_chain_rewrites_to_get_and_stops_at_the_hop_cap() {
        let request = post_request("https://api.example.com/a");
        let (result, seen) = run_chain(
            &request,
            b"secret=1",
            &HashMap::new(),
            None,
            in_30s(),
            |hop| {
                Ok((
                    h3_response(302, Some(&format!("/hop{}", hop + 1)), "moved"),
                    5,
                ))
            },
        );

        // The cap allows MAX_REDIRECTS hops, so MAX_REDIRECTS + 1 requests.
        assert_eq!(seen.len(), MAX_REDIRECTS + 1);
        let response = result.unwrap();
        assert_eq!(response.status_code, 302);
        assert_eq!(
            response.headers.get(REDIRECT_REFUSED_HEADER).map(|s| &**s),
            Some(REDIRECT_REFUSED_HOP_CAP)
        );

        // Hop 0 sends the caller's POST body; the 302 rewrites it to a bodyless
        // GET and every later hop stays that way.
        assert_eq!(
            seen[0],
            SeenHop {
                url: "https://api.example.com/a".to_string(),
                method: "POST".to_string(),
                has_body: true,
                body_dropped: false,
            }
        );
        assert_eq!(
            seen[1],
            SeenHop {
                url: "https://api.example.com/hop1".to_string(),
                method: "GET".to_string(),
                has_body: false,
                body_dropped: true,
            }
        );
        assert!(
            seen[2..]
                .iter()
                .all(|hop| hop.method == "GET" && !hop.has_body)
        );
    }

    #[test]
    fn redirect_chain_refuses_a_cross_origin_body_and_returns_the_response() {
        let progress = VaneProgressState::default();
        let paying = post_request("https://api.example.com/pay");
        let (result, seen) = run_chain(
            &paying,
            b"card=4111",
            &HashMap::new(),
            Some(&progress),
            in_30s(),
            |_| Ok((h3_response(307, Some("https://evil.test/pay"), "moved"), 9)),
        );

        // Refused before the second hop is ever dialed.
        assert_eq!(seen.len(), 1);
        let response = result.unwrap();
        assert_eq!(response.status_code, 307);
        assert_eq!(
            response.headers.get(REDIRECT_REFUSED_HEADER).map(|s| &**s),
            Some(REDIRECT_REFUSED_CROSS_ORIGIN_BODY)
        );
        // The refused response reaches the caller in full, and its bytes are
        // reported: streaming progress is suppressed while a 3xx might still be
        // followed, so without the final publish this would report zero.
        assert_eq!(response.body, b"moved");
        assert_eq!(progress.download_received.load(Ordering::Relaxed), 9);
        // `refused_redirect` and `finish` rebuild nothing, so the protocol the
        // hop reported must still be there.
        assert_eq!(response.http_version, Some(VaneHttpVersion::Http3));

        // A pinned host that a redirect tries to leave is refused the same way.
        let pins = HashMap::from([(
            "api.example.com".to_string(),
            vec!["sha256/example".to_string()],
        )]);
        let pinned_get = request("https://api.example.com/x");
        let (result, seen) = run_chain(&pinned_get, b"", &pins, None, in_30s(), |_| {
            Ok((
                h3_response(302, Some("https://cdn.example.net/x"), "moved"),
                5,
            ))
        });
        assert_eq!(seen.len(), 1);
        assert_eq!(
            result
                .unwrap()
                .headers
                .get(REDIRECT_REFUSED_HEADER)
                .map(|s| &**s),
            Some(REDIRECT_REFUSED_PINNED_HOST)
        );
    }

    #[test]
    fn redirect_chain_withdraws_replay_safety_after_the_first_hop() {
        // Hop 0's handshake never left the client, so the TCP fallback may
        // replay even a POST.
        let (result, _) = run_chain(
            &post_request("https://api.example.com/orders"),
            b"item=1",
            &HashMap::new(),
            None,
            in_30s(),
            |_| Err(VaneError::ConnectTimeout("handshake".to_string())),
        );
        let err = result.unwrap_err();
        assert!(matches!(err, VaneError::ConnectTimeout(_)));
        assert!(err.never_left_the_client());

        // Once hop 0 has been answered, the same handshake failure on hop 1 must
        // not claim that: the POST was delivered, and a fallback that replayed
        // the chain from the start would submit it twice.
        let (result, seen) = run_chain(
            &post_request("https://api.example.com/orders"),
            b"item=1",
            &HashMap::new(),
            None,
            in_30s(),
            |hop| match hop {
                0 => Ok((h3_response(303, Some("/orders/42"), ""), 0)),
                _ => Err(VaneError::ConnectTimeout("handshake".to_string())),
            },
        );
        assert_eq!(seen.len(), 2);
        let err = result.unwrap_err();
        assert!(
            matches!(err, VaneError::Timeout(_)),
            "expected the claim to be withdrawn, got {err:?}"
        );
        assert!(!err.never_left_the_client());
        // Still a transport failure, so an idempotent request keeps its fallback.
        assert!(err.is_transport_failure());
    }

    #[test]
    fn an_intermediate_redirect_body_is_capped_far_below_the_configured_limit() {
        let big = vec![0u8; MAX_INTERMEDIATE_BODY_BYTES as usize];

        // The TCP path never reads an intermediate body at all, so HTTP/3 must
        // not let a hostile 302 cost the caller the full body limit per hop.
        let mut intermediate = ResponseState::new(64 * 1024 * 1024, None).unwrap();
        intermediate.redirect_possible = true;
        intermediate.status_code = 302;
        assert!(intermediate.push_body(&big).is_ok());
        let err = intermediate.push_body(b"x").unwrap_err();
        assert!(
            err.to_string().contains("Redirect response body exceeded"),
            "{err}"
        );
        // Suppressed from progress too: the next hop restarts from zero.
        assert!(intermediate.is_intermediate_redirect());

        // A 3xx that can no longer be followed is the caller's own response and
        // gets the configured limit and the progress counters.
        let mut last = ResponseState::new(64 * 1024 * 1024, None).unwrap();
        last.status_code = 302;
        assert!(last.push_body(&big).is_ok());
        assert!(last.push_body(b"x").is_ok());
        assert!(!last.is_intermediate_redirect());
    }

    #[test]
    fn redirect_chain_honours_one_deadline_for_the_whole_chain() {
        let (result, seen) = run_chain(
            &request("https://api.example.com/a"),
            b"",
            &HashMap::new(),
            None,
            Instant::now() - Duration::from_secs(1),
            |_| panic!("no hop may be dialed after the deadline"),
        );

        assert!(seen.is_empty());
        assert!(matches!(result.unwrap_err(), VaneError::Timeout(_)));
    }

    #[test]
    fn redirect_rewrite_refuses_cross_origin_bodies_and_rewrites_to_get() {
        use RedirectRewrite::{Keep, Refuse, ToGet};

        // A body that would be replayed at a different origin is refused,
        // whatever status carries it: stripping headers does not protect the
        // payload, and a 301/302 on a GET keeps its body too (GraphQL-over-GET).
        assert_eq!(redirect_rewrite(307, "POST", true, true), Refuse);
        assert_eq!(redirect_rewrite(308, "POST", true, true), Refuse);
        assert_eq!(redirect_rewrite(302, "GET", true, true), Refuse);
        assert_eq!(redirect_rewrite(301, "GET", true, true), Refuse);
        // A rewrite to GET drops the body first, so it never replays one.
        assert_eq!(redirect_rewrite(303, "POST", true, true), ToGet);
        assert_eq!(redirect_rewrite(302, "POST", true, true), ToGet);
        // Same origin, or nothing to replay: the hop is safe.
        assert_eq!(redirect_rewrite(307, "POST", true, false), Keep);
        assert_eq!(redirect_rewrite(308, "POST", false, true), Keep);
        // 303 always becomes a GET; 301/302 do on a non-GET method.
        assert_eq!(redirect_rewrite(303, "POST", true, false), ToGet);
        assert_eq!(redirect_rewrite(303, "GET", false, false), ToGet);
        assert_eq!(redirect_rewrite(301, "POST", true, false), ToGet);
        assert_eq!(redirect_rewrite(302, "put", true, false), ToGet);
        assert_eq!(redirect_rewrite(302, "GET", false, false), Keep);
    }

    #[test]
    fn h3_cross_origin_hop_drops_caller_headers() {
        let config = VaneClientConfig {
            default_headers: HashMap::from([("X-Api-Key".to_string(), "secret".to_string())]),
            ..VaneClientConfig::default()
        };
        let mut req = request("https://api.example.com/x");
        req.headers
            .insert("Authorization".to_string(), "Bearer live".to_string());
        req.headers
            .insert("Accept".to_string(), "application/json".to_string());
        req.headers
            .insert("Content-Type".to_string(), "application/json".to_string());

        let names = |url: &str, body_dropped: bool| -> Vec<String> {
            let url = Url::parse(url).unwrap();
            build_h3_headers(
                &url,
                &req,
                &config,
                "GET",
                ("api.example.com", 443),
                Some("session=abc"),
                body_dropped,
            )
            .unwrap()
            .iter()
            .map(|h| String::from_utf8_lossy(h.name()).to_string())
            .collect()
        };

        let same = names("https://api.example.com/x", false);
        assert!(same.contains(&"authorization".to_string()));
        assert!(same.contains(&"x-api-key".to_string()));

        // Different host: only the safe list survives.
        let other_host = names("https://cdn.example.net/x", false);
        assert!(!other_host.contains(&"authorization".to_string()));
        assert!(!other_host.contains(&"x-api-key".to_string()));
        assert!(other_host.contains(&"accept".to_string()));
        // The jar's cookies are scoped to the hop's own host, so they are not
        // subject to the caller-header allowlist.
        assert!(other_host.contains(&"cookie".to_string()));

        // Same host, different port: still a different origin.
        let other_port = names("https://api.example.com:8443/x", false);
        assert!(!other_port.contains(&"authorization".to_string()));
        assert!(!other_port.contains(&"x-api-key".to_string()));

        // A rewrite to GET drops the body, so the content-type goes with it.
        let dropped = names("https://api.example.com/x", true);
        assert!(!dropped.contains(&"content-type".to_string()));
        assert!(names("https://api.example.com/x", false).contains(&"content-type".to_string()));
    }

    #[test]
    fn h3_headers_include_cookie_jar_header_when_present() {
        let config = VaneClientConfig::default();
        let req = request("https://example.com/items");
        let url = Url::parse("https://example.com/items").unwrap();

        let headers = build_h3_headers(
            &url,
            &req,
            &config,
            "GET",
            ("example.com", 443),
            Some("session=abc; theme=dark"),
            false,
        )
        .unwrap();
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
        let err = validate_request_body_limit(4, 3).unwrap_err();

        assert!(err.to_string().contains("Request body exceeded 3 bytes"));
        assert!(validate_request_body_limit(3, 3).is_ok());
    }

    #[test]
    fn body_file_over_the_limit_is_refused_before_it_is_read() {
        // `set_len` makes a sparse multi-GB file in O(1): if the limit were
        // checked after `read_to_end` instead of before, this test would try
        // to allocate 8 GB — the OOM this ordering exists to prevent.
        let path = std::env::temp_dir().join("vane_oversized_body_file_test");
        let file = File::create(&path).unwrap();
        file.set_len(8 * 1024 * 1024 * 1024).unwrap();

        let mut oversized = request("https://example.com/upload");
        oversized.body_file_path = Some(path.display().to_string());
        let err = load_request_body(&oversized, 1024).unwrap_err();
        let _ = fs::remove_file(&path);

        // The exact error the post-load check produces, so callers matching
        // on the kind or message cannot tell which check fired.
        assert!(matches!(err, VaneError::BodyLimitExceeded(_)));
        assert!(err.to_string().contains("Request body exceeded 1024 bytes"));
    }

    #[test]
    fn response_body_limit_rejects_oversized_body() {
        let err = validate_response_body_limit(3, 2, 4).unwrap_err();

        assert!(err.to_string().contains("Response body exceeded 4 bytes"));
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

    /// Ships in both profiles: `domain_matches("evil.com", "com")` is true, so
    /// without this any host could plant a cookie for every *.com site and
    /// shadow a real session cookie.
    #[test]
    fn cookie_domain_cannot_be_a_bare_tld_or_an_ip_literal() {
        let url = Url::parse("https://evil.com/x").unwrap();
        for domain in ["com", "net", "org", "io"] {
            assert!(
                StoredCookie::parse(&url, &format!("session=x; Domain={domain}")).is_none(),
                "Domain={domain} must be refused"
            );
        }

        // One label narrower than the suffix is legitimate.
        let ok = StoredCookie::parse(&url, "session=x; Domain=evil.com").unwrap();
        assert_eq!(ok.domain, "evil.com");
        assert!(!ok.host_only);

        // An IP literal has no domain hierarchy: "10.0.0.1" domain-matches "1".
        let ip = Url::parse("https://10.0.0.1/x").unwrap();
        assert!(StoredCookie::parse(&ip, "session=x; Domain=1").is_none());
        assert!(StoredCookie::parse(&ip, "session=x; Domain=0.0.1").is_none());
        assert!(StoredCookie::parse(&ip, "session=x; Domain=10.0.0.1").is_none());
        let ipv6 = Url::parse("https://[::1]/x").unwrap();
        assert!(StoredCookie::parse(&ipv6, "session=x; Domain=::1").is_none());
    }

    /// Only the full public suffix list can see that `co.uk` is a suffix; the
    /// dot rule cannot.
    #[cfg(feature = "psl")]
    #[test]
    fn cookie_domain_cannot_be_a_multi_label_public_suffix() {
        for (origin, domain) in [
            ("https://evil.co.uk/x", "co.uk"),
            ("https://evil.github.io/x", "github.io"),
            ("https://evil.com.au/x", "com.au"),
        ] {
            let url = Url::parse(origin).unwrap();
            assert!(
                StoredCookie::parse(&url, &format!("session=x; Domain={domain}")).is_none(),
                "Domain={domain} must be refused with the psl feature on"
            );
        }

        // A registrable name under a multi-label suffix is still assignable.
        let url = Url::parse("https://api.evil.co.uk/x").unwrap();
        let ok = StoredCookie::parse(&url, "session=x; Domain=evil.co.uk").unwrap();
        assert_eq!(ok.domain, "evil.co.uk");
    }

    /// Pins the small profile's actual posture so the gap is a tested fact
    /// rather than a claim in a document: bare TLDs and IP literals are still
    /// refused, multi-label public suffixes are not.
    #[cfg(not(feature = "psl"))]
    #[test]
    fn cookie_domain_without_psl_still_blocks_bare_tlds_but_not_multi_label_suffixes() {
        let url = Url::parse("https://evil.com/x").unwrap();
        assert!(StoredCookie::parse(&url, "session=x; Domain=com").is_none());

        let ip = Url::parse("https://10.0.0.1/x").unwrap();
        assert!(StoredCookie::parse(&ip, "session=x; Domain=1").is_none());

        // Known gap without the public suffix list.
        let couk = Url::parse("https://evil.co.uk/x").unwrap();
        assert!(StoredCookie::parse(&couk, "session=x; Domain=co.uk").is_some());
    }

    #[test]
    fn hosts_two_url_parsers_could_spell_differently_are_rejected() {
        // Every pin, cross-origin and cookie decision keys off our host, but the
        // transport re-parses the URL with its own parser. Anything the two
        // could read differently must not parse at all.
        for hostile in [
            "https://attacker.test\\.api.victim.com/y",
            "https://attacker.test\t.api.victim.com/y",
            "https://attacker%2etest/y",
            "https://attacker.test\u{7f}.victim.com/y",
            "https://[not-an-ipv6]/y",
        ] {
            assert!(
                Url::parse(hostile).is_err(),
                "{hostile} must be rejected outright"
            );
        }

        // Ordinary hosts, IPv6 literals and uppercase schemes still work.
        assert_eq!(
            Url::parse("HTTPS://API.Example.com/y").unwrap().to_string(),
            "https://api.example.com/y"
        );
        assert_eq!(
            Url::parse("https://[::1]:8443/y").unwrap().host_str(),
            Some("[::1]")
        );
        assert!(Url::parse("https://my-host_1.example.com/y").is_ok());
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
        let token = cancel_token(Some(cancel_id)).expect("cancel token should resolve by id");
        assert!(check_cancelled(Some(&token)).is_ok());
        vane_ffi_cancel_token_cancel(cancel_id);
        assert!(check_cancelled(Some(&token)).is_err());
        vane_ffi_cancel_token_free(cancel_id);

        // The handle the transfer loop writes and the id-keyed snapshot API must
        // observe the same atomics.
        let progress_id = vane_ffi_progress_create();
        let progress = progress_init(Some(progress_id), 10).expect("progress should resolve by id");
        progress_upload(Some(&progress), 4, 10);
        progress_download(Some(&progress), 8, 0);
        progress_done(Some(&progress));
        let snapshot = vane_ffi_progress_snapshot(progress_id);
        assert_eq!(snapshot.upload_sent, 4);
        assert_eq!(snapshot.upload_total, 10);
        assert_eq!(snapshot.download_received, 8);
        assert!(snapshot.done);
        vane_ffi_progress_free(progress_id);
        assert!(!vane_ffi_progress_snapshot(progress_id).done);
    }

    /// `execute` resolves the progress id again when the request ends. If the
    /// caller freed the id mid-request (worker death frees eagerly), that
    /// late resolve must find nothing — an insert there would resurrect the
    /// entry forever, because ids are never reused and nothing frees twice.
    #[test]
    fn a_freed_progress_id_is_not_resurrected_by_a_late_resolve() {
        let progress_id = vane_ffi_progress_create();
        vane_ffi_progress_free(progress_id);

        assert!(progress_handle(Some(progress_id)).is_none());
        // The done-time call `execute` makes, verbatim: a no-op, not a leak.
        progress_done(progress_handle(Some(progress_id)).as_deref());
        assert!(
            !PROGRESS_STATES.lock().unwrap().contains_key(&progress_id),
            "resolving a freed progress id must not re-insert it"
        );
    }

    /// The constant the Dart bindings check at load time; see
    /// `vane_ffi_abi_version`'s doc for when it must move. Pinned so a bump
    /// cannot land without the author reading that contract.
    #[test]
    fn c_abi_version_is_the_one_the_dart_bindings_expect() {
        assert_eq!(vane_ffi_abi_version(), 2);
    }

    #[test]
    fn uniffi_cancel_token_exports_share_the_ffi_registry() {
        // The UniFFI trio and the C ABI trio must hit the same registry:
        // create through UniFFI, observe through the request-path resolver.
        let id = create_cancel_token();
        let token = cancel_token(Some(id)).expect("cancel token should resolve by id");
        assert!(check_cancelled(Some(&token)).is_ok());
        cancel_by_id(id);
        assert!(check_cancelled(Some(&token)).is_err());
        free_cancel_token(id);
        assert!(cancel_token(Some(id)).is_none());
        // Double-free and cancel-after-free are safe no-ops; ids are never
        // reused, so a stale id can never reach a later token.
        free_cancel_token(id);
        cancel_by_id(id);
    }

    #[test]
    fn quiche_config_is_cached_per_idle_timeout_and_udp_payload() {
        let cache = QuicConfigCache::new(HashMap::new());
        let scid = quiche::ConnectionId::from_ref(&[7; quiche::MAX_CONN_ID_LEN]);
        let local = SocketAddr::from(([127, 0, 0, 1], 4433));
        let peer = SocketAddr::from(([127, 0, 0, 1], 443));
        let connect = |seconds, payload| {
            quic_connect(
                &cache,
                "example.com",
                &scid,
                local,
                peer,
                Duration::from_secs(seconds),
                payload,
            )
        };
        let cached_keys = || {
            let mut keys = cache.lock().unwrap().keys().copied().collect::<Vec<_>>();
            keys.sort_unstable();
            keys
        };

        // A second connect on the same cached config must still succeed: that is
        // the property the cache depends on.
        for _ in 0..2 {
            connect(30, MAX_DATAGRAM_SIZE).expect("connect should reuse the cached config");
        }
        assert_eq!(cached_keys(), vec![(30_000, MAX_DATAGRAM_SIZE)]);

        // Alternating timeouts keep both configs instead of thrashing one slot.
        connect(5, MAX_DATAGRAM_SIZE).unwrap();
        connect(30, MAX_DATAGRAM_SIZE).unwrap();
        assert_eq!(
            cached_keys(),
            vec![(5_000, MAX_DATAGRAM_SIZE), (30_000, MAX_DATAGRAM_SIZE)]
        );

        // The MASQUE inner connection's smaller payload is a separate entry, so
        // outer and inner configs coexist instead of evicting each other.
        connect(30, MASQUE_INNER_FALLBACK_UDP_PAYLOAD).unwrap();
        assert_eq!(
            cached_keys(),
            vec![
                (5_000, MAX_DATAGRAM_SIZE),
                (30_000, MASQUE_INNER_FALLBACK_UDP_PAYLOAD),
                (30_000, MAX_DATAGRAM_SIZE)
            ]
        );

        // The payload half of the key is measured per connection, so the map
        // must stay bounded rather than growing one CA-parse per new pair.
        for seconds in 0..(MAX_QUIC_CONFIGS as u64 + 2) {
            connect(seconds + 1, MAX_DATAGRAM_SIZE).unwrap();
        }
        assert!(cache.lock().unwrap().len() <= MAX_QUIC_CONFIGS);
    }

    #[test]
    fn pinned_hosts_never_resume_a_tls_session() {
        let pinned = HashMap::from([
            (
                "pinned.test".to_string(),
                vec!["sha256/example".to_string()],
            ),
            // An empty pin list is not pinning, so it must not block resumption.
            ("empty.test".to_string(), Vec::new()),
        ]);

        assert!(!may_resume_tls_session("pinned.test", &pinned));
        assert!(may_resume_tls_session("empty.test", &pinned));
        assert!(may_resume_tls_session("other.test", &pinned));
        assert!(may_resume_tls_session("any.test", &HashMap::new()));
    }

    #[test]
    fn tls_session_store_stays_bounded() {
        let mut sessions = HashMap::new();
        let first = TlsSessionKey::origin("host0.test", 443);
        for index in 0..MAX_TLS_SESSIONS {
            insert_tls_session(
                &mut sessions,
                &TlsSessionKey::origin(&format!("host{index}.test"), 443),
                vec![1],
            );
        }
        assert_eq!(sessions.len(), MAX_TLS_SESSIONS);

        // Refreshing a host already in the store must not trip the bound.
        insert_tls_session(&mut sessions, &first, vec![2]);
        assert_eq!(sessions.len(), MAX_TLS_SESSIONS);
        assert_eq!(sessions.get(&first), Some(&vec![2]));

        // ponytail: the bound clears wholesale rather than evicting an LRU
        // entry, so a new host past the cap resets the store to just itself.
        let new = TlsSessionKey::origin("new.test", 443);
        insert_tls_session(&mut sessions, &new, vec![3]);
        assert_eq!(sessions.len(), 1);
        assert!(sessions.contains_key(&new));
    }

    #[test]
    fn tls_session_keys_separate_port_and_proxy_hop() {
        // A resumed TLS 1.3 handshake verifies no certificate, so a ticket must
        // not carry across a port change or between the proxy hop and origin.
        let origin = TlsSessionKey::origin("api.example.com", 443);
        assert_ne!(origin, TlsSessionKey::origin("api.example.com", 8443));
        assert_ne!(origin, TlsSessionKey::proxy("api.example.com", 443));
        assert_ne!(origin, TlsSessionKey::origin("other.example.com", 443));
        assert_eq!(origin, TlsSessionKey::origin("api.example.com", 443));

        let mut sessions = HashMap::new();
        insert_tls_session(&mut sessions, &origin, vec![1]);
        insert_tls_session(
            &mut sessions,
            &TlsSessionKey::origin("api.example.com", 8443),
            vec![2],
        );
        insert_tls_session(
            &mut sessions,
            &TlsSessionKey::proxy("api.example.com", 443),
            vec![3],
        );
        assert_eq!(sessions.len(), 3);
        assert_eq!(sessions.get(&origin), Some(&vec![1]));
    }

    #[test]
    fn changing_certificate_pins_drops_the_stored_tls_session() {
        let client = VaneClient::new(VaneClientConfig::default()).unwrap();
        client
            .tls_sessions
            .lock()
            .unwrap()
            .insert(TlsSessionKey::origin("api.example.com", 443), vec![7]);

        client
            .set_certificate_pins(
                "api.example.com".to_string(),
                vec!["sha256/example".to_string()],
            )
            .unwrap();

        assert!(client.tls_sessions.lock().unwrap().is_empty());
    }

    #[test]
    fn content_length_sets_download_total_and_caps_the_reservation() {
        let mut response = ResponseState::new(64 * 1024 * 1024, None).unwrap();

        response.on_content_length("not-a-number");
        assert_eq!(response.body.capacity(), 0);
        assert_eq!(response.download_total, 0);

        response.on_content_length("64");
        assert!(response.body.capacity() >= 64);
        assert_eq!(response.download_total, 64);

        // A bodiless HEAD/304 response must not pre-allocate the whole limit.
        response.on_content_length("60000000");
        assert_eq!(response.download_total, 60_000_000);
        assert!(response.body.capacity() <= MAX_BODY_RESERVE_BYTES as usize);

        // The configured limit still wins when it is the smaller cap.
        let mut small = ResponseState::new(1_024, None).unwrap();
        small.on_content_length("999999999999");
        assert!(small.body.capacity() <= 1_024);
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
