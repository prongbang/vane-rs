//! TCP fallback backend: HTTP/1.1 and HTTP/2 over TLS 1.2/1.3.
//!
//! Gated behind the `tcp-fallback` feature so the HTTP/3-only artifact never
//! links reqwest, hyper, tokio or rustls. Everything user-visible — the cookie
//! jar, retry policy, body limits, progress, cancellation and certificate pins
//! — is the same machinery the HTTP/3 path uses, so the two transports are
//! interchangeable from the caller's side.

use std::collections::HashMap;
use std::io::{self, Read};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::AtomicBool;
#[cfg(target_os = "android")]
use std::sync::atomic::Ordering;
use std::sync::{Arc, PoisonError};
use std::time::{Duration, Instant};

use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::redirect;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};

use super::{
    H3_BODY_BUFFER_BYTES, REDIRECT_REFUSED_CROSS_ORIGIN_BODY, REDIRECT_REFUSED_HEADER,
    RedirectDecision, RedirectRewrite, ResponseState, Url, VaneClient, VaneError, VaneHttpVersion,
    VaneProgressState, VaneProtocolMode, VaneRequest, VaneResponse, cancel_token, check_cancelled,
    for_each_regular_header, header_survives_origin_change, next_redirect_url, origin_port,
    progress_download, progress_init, progress_upload, redact_url_userinfo, redirect_rewrite,
    verify_certificate_pins,
};

/// Wraps the platform's own certificate verifier and adds Vane's host-scoped
/// pins.
///
/// Platform verification runs first and is never replaced or weakened — a pin
/// is an additional constraint on top of it, never a substitute. The pin check
/// is literally the same `verify_certificate_pins` the HTTP/3 path calls, so
/// both transports accept and reject exactly the same certificates.
///
/// (`ClientConfig::dangerous()` is only how rustls spells "install a custom
/// verifier"; nothing here skips verification.)
#[derive(Debug)]
struct PinnedServerCertVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    certificate_pins: HashMap<String, Vec<String>>,
}

impl ServerCertVerifier for PinnedServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;

        if self.certificate_pins.is_empty() {
            return Ok(ServerCertVerified::assertion());
        }

        // Fail closed: a name shape we cannot spell cannot be matched against a
        // pin, and this client has pins configured.
        let host = pin_lookup_host(server_name).ok_or_else(|| {
            rustls::Error::General(
                "Unsupported TLS server name for certificate pinning".to_string(),
            )
        })?;

        verify_certificate_pins(&host, Some(end_entity.as_ref()), &self.certificate_pins)
            .map_err(|err| rustls::Error::General(err.to_string()))?;

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Spells a TLS server name the way [`Url::host_str`] does, so a pinned host is
/// looked up under the same key the caller configured it with. Getting this
/// wrong fails open — the lookup misses and an unpinned host is assumed.
fn pin_lookup_host(server_name: &ServerName<'_>) -> Option<String> {
    match server_name {
        ServerName::DnsName(name) => Some(name.as_ref().to_ascii_lowercase()),
        ServerName::IpAddress(ip) => Some(match IpAddr::from(*ip) {
            IpAddr::V4(address) => address.to_string(),
            IpAddr::V6(address) => format!("[{address}]"),
        }),
        _ => None,
    }
}

/// Sends the platform verifier's own `log` output to logcat, in debug builds.
///
/// `rustls-platform-verifier` explains why it rejected a certificate through
/// `log::warn!` — the verbatim message Android handed back, and the only place
/// the real reason appears, since the crate then discards it and returns a bare
/// `CertificateError`. With no logger installed the `log` crate drops those
/// records, which is what turns a one-line diagnosis into a decompiler session.
///
/// Debug builds only: release installs nothing, and `log`'s macros in the
/// dependency compile down to a level check against a filter left at `Off`.
///
/// Note that `make build_so` always passes `--release`, so no shipped artifact
/// carries this. To get the explanation out of a device, rebuild the library
/// without `--release` (`cargo ndk --target aarch64-linux-android build`), drop
/// the result into `jniLibs/arm64-v8a/`, and read `logcat` — the records arrive
/// tagged `rustls_platform_verifier::verification::android`.
#[cfg(all(target_os = "android", debug_assertions))]
mod logcat {
    use std::ffi::{CString, c_char, c_int};

    // liblog is a core system library, present on every device and in every NDK
    // sysroot; the `android_log-sys` crate exists to declare just this.
    #[link(name = "log")]
    unsafe extern "C" {
        fn __android_log_write(prio: c_int, tag: *const c_char, text: *const c_char) -> c_int;
    }

    struct Logcat;

    impl log::Log for Logcat {
        fn enabled(&self, _: &log::Metadata) -> bool {
            true
        }

        fn log(&self, record: &log::Record) {
            // android_LogPriority: VERBOSE=2 .. ERROR=6.
            let priority = match record.level() {
                log::Level::Error => 6,
                log::Level::Warn => 5,
                log::Level::Info => 4,
                log::Level::Debug => 3,
                log::Level::Trace => 2,
            };
            // An interior NUL means there is nothing useful to print anyway.
            let (Ok(tag), Ok(text)) = (
                CString::new(record.target()),
                CString::new(record.args().to_string()),
            ) else {
                return;
            };
            // SAFETY: both pointers are NUL-terminated and outlive the call.
            unsafe { __android_log_write(priority, tag.as_ptr(), text.as_ptr()) };
        }

        fn flush(&self) {}
    }

    static LOGGER: Logcat = Logcat;

    /// Idempotent: a second call just loses the race and leaves the first
    /// logger in place, so an app that installed its own keeps it.
    pub(super) fn install() {
        if log::set_logger(&LOGGER).is_ok() {
            log::set_max_level(log::LevelFilter::Warn);
        }
    }
}

/// Set once [`Java_com_inteniquetic_vanekotlin_VaneNative_initAndroid`] has
/// handed the platform verifier an app `Context`.
///
/// Android is the one platform where certificate verification needs setup
/// before it can run: the trust store is only reachable over JNI. Skipping it
/// does not merely fail the handshake — `rustls-platform-verifier` panics
/// inside its first verification, and the release profile is `panic = "abort"`,
/// so the whole app process dies. Hence a flag checked *before* a verifier is
/// ever built, rather than letting the failure happen where it would.
#[cfg(target_os = "android")]
static ANDROID_TRUST_READY: AtomicBool = AtomicBool::new(false);

/// One-time JNI handshake giving `rustls-platform-verifier` the app `Context`
/// it verifies certificates through. Idempotent, and only the first call
/// counts (the crate stores its handles in a `OnceCell`).
///
/// An exported native method rather than a `JNI_OnLoad` hook: `JNI_OnLoad` is
/// handed only a `JavaVM`, and there is no supported way to reach a `Context`
/// from one — `ActivityThread.currentApplication()` is hidden API — while
/// `init_with_env` needs the `Context` to reach the app class loader that owns
/// `org.rustls.platformverifier.CertificateVerifier`.
///
/// Returns false instead of throwing, because the caller is a `ContentProvider`
/// running during app startup: a failure here has to degrade to "TCP fallback
/// unavailable", never to a crash before the app's first frame.
#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_inteniquetic_vanekotlin_VaneNative_initAndroid<'local>(
    mut env: jni::EnvUnowned<'local>,
    _this: jni::objects::JObject<'local>,
    context: jni::objects::JObject<'local>,
) -> jni::sys::jboolean {
    env.with_env(|env| -> Result<jni::sys::jboolean, jni::errors::Error> {
        // Before the verifier can reject anything, so its explanation is not
        // lost. No-op in release.
        #[cfg(debug_assertions)]
        logcat::install();
        // A local ref is what this wants: it promotes the `Context` to a global
        // itself, along with the class loader it reads off it.
        rustls_platform_verifier::android::init_with_env(env, context)?;
        ANDROID_TRUST_READY.store(true, Ordering::Release);
        Ok(jni::sys::JNI_TRUE)
    })
    // Logs and returns 0 (`JNI_FALSE`) on error or panic; never throws, and
    // never unwinds into the JVM.
    .resolve::<jni::errors::LogErrorAndDefault>()
}

/// Refuses a TCP request that would otherwise reach an uninitialized verifier.
///
/// The message names the missing call on purpose: the alternative failure is a
/// process abort with no mention of Android setup anywhere in the trace, which
/// is a multi-hour diagnosis for a one-line fix.
#[cfg(target_os = "android")]
fn check_android_trust_ready() -> Result<(), VaneError> {
    if ANDROID_TRUST_READY.load(Ordering::Acquire) {
        return Ok(());
    }
    Err(VaneError::Generic(
        "Android platform trust store is not initialized, so the TCP transport \
         (HTTP/2 and HTTP/1.1) cannot verify certificates. Vane's AAR does this \
         automatically from its VaneInitProvider ContentProvider; if the merged \
         manifest dropped that provider, or libvane.so was loaded without it, \
         call Vane.initialize(context) once at startup. HTTP/3 does not need this."
            .to_string(),
    ))
}

fn tls_config(
    mode: &VaneProtocolMode,
    certificate_pins: HashMap<String, Vec<String>>,
) -> Result<ClientConfig, VaneError> {
    // Before `Verifier::new`, not after: this is the only place a platform
    // verifier is constructed, so every TCP request is covered by this one
    // guard regardless of which entry point it came in through.
    #[cfg(target_os = "android")]
    check_android_trust_ready()?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let inner = inner_verifier(&provider)?;

    // `with_safe_default_protocol_versions` is TLS 1.2 + 1.3.
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| VaneError::Tls(format!("Failed to configure TLS versions: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedServerCertVerifier {
            inner,
            certificate_pins,
        }))
        .with_no_client_auth();

    // reqwest only fills these in on its own TLS path; a preconfigured config
    // is passed through untouched, so without this nothing offers ALPN, HTTP/2
    // is never negotiated, and prior-knowledge h2 violates RFC 9113 3.4.
    config.alpn_protocols = match mode {
        VaneProtocolMode::Http1Only => vec![b"http/1.1".to_vec()],
        VaneProtocolMode::Http2Only => vec![b"h2".to_vec()],
        _ => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
    };

    Ok(config)
}

/// The platform's own verifier, which is what "trusted" has to mean on
/// SecTrust and Android.
#[cfg(not(test))]
fn inner_verifier(
    provider: &Arc<rustls::crypto::CryptoProvider>,
) -> Result<Arc<dyn ServerCertVerifier>, VaneError> {
    Ok(Arc::new(
        rustls_platform_verifier::Verifier::new(provider.clone())
            .map_err(|e| VaneError::Tls(format!("Failed to build TLS verifier: {e}")))?,
    ))
}

/// Test-only trust anchor. The suite runs against a local server whose CA is
/// generated per run and therefore can never be in the platform store; without
/// this the reuse-retry regression test could not reach vane's own code path.
#[cfg(test)]
pub(crate) static TEST_ROOT: std::sync::Mutex<Option<CertificateDer<'static>>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
fn inner_verifier(
    provider: &Arc<rustls::crypto::CryptoProvider>,
) -> Result<Arc<dyn ServerCertVerifier>, VaneError> {
    let root = TEST_ROOT
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    let Some(root) = root else {
        return Ok(Arc::new(
            rustls_platform_verifier::Verifier::new(provider.clone())
                .map_err(|e| VaneError::Tls(format!("Failed to build TLS verifier: {e}")))?,
        ));
    };
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(root)
        .map_err(|e| VaneError::Tls(format!("Invalid test root: {e}")))?;
    Ok(rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .build()
    .map_err(|e| VaneError::Tls(format!("Failed to build TLS verifier: {e}")))?)
}

fn build_client(
    client: &VaneClient,
    certificate_pins: HashMap<String, Vec<String>>,
) -> Result<Client, VaneError> {
    let config = &client.config;
    let mut builder = Client::builder()
        .use_preconfigured_tls(tls_config(&config.protocol_mode, certificate_pins)?)
        // Redirects are driven by hand in `follow_and_read`: reqwest's policy
        // cannot re-derive the cookie header per hop, cannot see intermediate
        // `Set-Cookie`, and cannot drop caller headers when the host changes.
        .redirect(redirect::Policy::none())
        // Plaintext is rejected before we reach here; this is the backstop.
        .https_only(true);

    builder = match config.protocol_mode {
        VaneProtocolMode::Http1Only => builder.http1_only(),
        VaneProtocolMode::Http2Only => builder.http2_prior_knowledge(),
        _ => builder,
    };

    builder = if config.connection_pool_enabled {
        builder
            .pool_max_idle_per_host(config.max_idle_connections as usize)
            .pool_idle_timeout(std::time::Duration::from_secs(
                config.connection_idle_timeout_seconds,
            ))
    } else {
        builder.pool_max_idle_per_host(0)
    };

    for (host, address) in &config.dns_overrides {
        let ip = address.parse::<IpAddr>().map_err(|e| {
            VaneError::InvalidRequest(format!(
                "Invalid DNS override for {host}: expected IP address, got {address}: {e}"
            ))
        })?;
        // Port 0 tells reqwest to take the port from the URL, matching how the
        // HTTP/3 path applies overrides.
        builder = builder.resolve(host, SocketAddr::new(ip, 0));
    }

    if let Some(proxy_url) = config.proxy_url.as_deref() {
        // Per-transport reading of one setting: MASQUE/CONNECT-UDP on HTTP/3,
        // HTTP CONNECT here.
        let mut proxy = reqwest::Proxy::all(proxy_url).map_err(|e| {
            VaneError::InvalidRequest(format!(
                "Invalid proxyUrl {}: {e}",
                redact_url_userinfo(proxy_url)
            ))
        })?;
        if let Some(authorization) = config
            .proxy_authorization
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            let value = HeaderValue::from_str(authorization).map_err(|_| {
                VaneError::InvalidRequest("Invalid proxyAuthorization header".to_string())
            })?;
            proxy = proxy.custom_http_auth(value);
        }
        builder = builder.proxy(proxy);
    } else {
        // reqwest otherwise picks up $HTTPS_PROXY and OS proxy settings. The
        // HTTP/3 path never does, so an unset proxyUrl has to mean "no proxy"
        // on both transports rather than "whatever the environment says".
        builder = builder.no_proxy();
    }

    builder
        .build()
        .map_err(|e| VaneError::Generic(format!("Failed to build TCP client: {e}")))
}

/// Returns the client's blocking reqwest client, building it on first use so
/// HTTP/3-only applications never pay for the tokio runtime.
fn shared_client(client: &VaneClient) -> Result<(Client, HashMap<String, Vec<String>>), VaneError> {
    // Lock order is tcp_client -> certificate_pins, matching
    // `set_certificate_pins_internal`. Snapshotting the pins first would let an
    // invalidation land between the read and the insert, permanently caching a
    // client whose verifier holds stale (usually empty) pins.
    let mut cached = client
        .tcp_client
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    // Read inside the same critical section, so the redirect gate and the TLS
    // verifier baked into the client can never disagree about the pin set.
    let certificate_pins = client.certificate_pins_snapshot()?;
    if let Some(existing) = cached.as_ref() {
        return Ok((existing.clone(), certificate_pins));
    }
    let built = build_client(client, certificate_pins.clone())?;
    Ok((cached.insert(built).clone(), certificate_pins))
}

/// Builds the header map for one hop. `origin` is the origin the caller
/// addressed; once a redirect has moved us to a different one, caller-supplied
/// headers are cut down to the shared cross-origin allowlist.
fn build_headers(
    client: &VaneClient,
    request: &VaneRequest,
    url: &Url,
    origin: (&str, u16),
    cookie_header: Option<&str>,
    body_dropped: bool,
) -> Result<HeaderMap, VaneError> {
    // Port is part of the origin: app.example.com and app.example.com:8443 are
    // different security origins on multi-tenant and dev/staging hosts.
    let same_origin = (url.host_str().unwrap_or_default(), origin_port(url)) == origin;
    let mut headers = HeaderMap::new();

    for_each_regular_header(request, &client.config, |key, value| {
        let lower = key.to_ascii_lowercase();
        if !same_origin && !header_survives_origin_change(&lower) {
            return Ok(());
        }
        // A 303 rewrite drops the body, so a caller content-type would describe
        // a payload that is no longer being sent.
        if body_dropped && lower == "content-type" {
            return Ok(());
        }
        let name = HeaderName::from_bytes(lower.as_bytes())
            .map_err(|e| VaneError::InvalidRequest(format!("Invalid header name {key}: {e}")))?;
        let value = HeaderValue::from_str(value)
            .map_err(|_| VaneError::InvalidRequest(format!("Invalid value for header {key}")))?;
        // Append rather than insert: the HTTP/3 path sends every occurrence,
        // and replacing would silently drop a caller's second value.
        headers.append(name, value);
        Ok(())
    })?;

    // Only set when the caller did not, so we never send two User-Agents.
    if !headers.contains_key(reqwest::header::USER_AGENT) {
        let user_agent = client.config.user_agent.as_deref().unwrap_or("Vane/0.1.0");
        headers.insert(
            reqwest::header::USER_AGENT,
            HeaderValue::from_str(user_agent)
                .map_err(|_| VaneError::InvalidRequest("Invalid userAgent".to_string()))?,
        );
    }

    // Inserted after the allowlist, which exists to govern *caller* headers:
    // the jar's cookies are already scoped to this hop's host and path, so
    // running them through the cross-origin filter would just discard them.
    if let Some(cookie_header) = cookie_header.filter(|header| !header.is_empty()) {
        headers.insert(
            reqwest::header::COOKIE,
            HeaderValue::from_str(cookie_header)
                .map_err(|_| VaneError::InvalidRequest("Invalid cookie header".to_string()))?,
        );
    }

    Ok(headers)
}

pub(crate) fn execute_tcp_once(
    client: &VaneClient,
    request: &VaneRequest,
    url: &Url,
    request_body: &[u8],
) -> Result<VaneResponse, VaneError> {
    // Same guard as the HTTP/3 path. Without it an `http://` URL is sent in the
    // clear with no TLS and therefore no pin check — and in the fallback mode
    // the HTTP/3 https-only rejection is exactly what would have routed us
    // here, turning a hard failure into a silent cleartext send.
    if url.scheme() != "https" {
        return Err(VaneError::InvalidRequest(
            "Vane only supports https:// URLs".to_string(),
        ));
    }

    let cancel_token = cancel_token(request.cancel_token_id);
    let progress = progress_init(request.progress_id, request_body.len() as u64);
    // `execute` marks the request done once the whole dispatch resolves, so a
    // poller never sees `done` flip while a fallback is still to come.
    follow_and_read(
        client,
        request,
        url,
        request_body,
        cancel_token.as_deref(),
        progress.as_deref(),
    )
}

fn follow_and_read(
    client: &VaneClient,
    request: &VaneRequest,
    url: &Url,
    request_body: &[u8],
    cancel_token: Option<&AtomicBool>,
    progress: Option<&VaneProgressState>,
) -> Result<VaneResponse, VaneError> {
    let origin = (
        url.host_str().unwrap_or_default().to_string(),
        origin_port(url),
    );
    let timeout = std::time::Duration::from_secs(
        request
            .timeout_seconds
            .or(client.config.timeout_seconds)
            .unwrap_or(30),
    );
    // One deadline for the whole chain. Applying the timeout per hop would let
    // a hostile server hold a caller thread for hop-cap times the requested
    // timeout, and the retry loop multiplies that again.
    let deadline = Instant::now() + timeout;
    let (http, certificate_pins) = shared_client(client)?;

    // Created before anything goes on the wire so a bad response_body_path
    // fails without having sent a request, matching the HTTP/3 path.
    let mut state = ResponseState::new(
        client.config.max_response_body_bytes,
        request.response_body_path.as_deref(),
    )?;

    let mut current = url.clone();
    let mut method = reqwest::Method::from_bytes(request.method.to_ascii_uppercase().as_bytes())
        .map_err(|_| {
            VaneError::InvalidRequest(format!("Invalid HTTP method {}", request.method))
        })?;
    let mut body = request_body;
    let mut body_dropped = false;
    let mut hops = 0usize;
    // Names why a redirect chain stopped, so a caller cannot mistake a refusal
    // for a plain 3xx and re-follow the Location by hand.
    let mut refused: Option<&'static str> = None;
    // Once per request, not per redirect hop: the race below is a property of
    // checking a connection out of the pool, so one retry covers the request.
    let mut allow_reuse_retry = true;

    let response = loop {
        check_cancelled(cancel_token)?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(VaneError::Timeout("HTTP request timed out".to_string()));
        }
        // Rebuilt rather than `try_clone`d for the retry below: cloning up
        // front would copy the request body on every single request to cover a
        // path that is almost never taken.
        let build = |remaining: Duration| -> Result<reqwest::blocking::RequestBuilder, VaneError> {
            let cookie_header = if client.config.cookies_enabled {
                // Re-derived per hop: cookies are scoped by host and path, so
                // the header built for the first URL is wrong for a redirect
                // target.
                Some(client.cookie_header(&current)?)
            } else {
                None
            };
            let mut builder = http
                .request(method.clone(), current.to_string())
                .headers(build_headers(
                    client,
                    request,
                    &current,
                    (&origin.0, origin.1),
                    cookie_header.as_deref(),
                    body_dropped,
                )?)
                .timeout(remaining);
            if !body.is_empty() {
                // reqwest owns the body; the HTTP/3 path can borrow, this
                // cannot.
                builder = builder.body(body.to_vec());
            }
            Ok(builder)
        };

        let response = match build(remaining)?.send() {
            Ok(response) => response,
            Err(error) => {
                // The same rule the HTTP/3 path applies to a pooled connection
                // that died silently. hyper can hand us a keep-alive
                // connection at the instant the peer closes it; by then the
                // request is already committed to that connection, so
                // hyper-util's own retry (which needs `take_message`) cannot
                // cover it and the write surfaces as a transport error.
                //
                // Nothing was read back, so the request was not processed and
                // one retry on a fresh connection is safe for any method.
                // Timeouts and connect failures are excluded because they are
                // genuine failures, not a stale checkout — `is_connect` is
                // checked directly since `classify_send_error` folds
                // connect-without-timeout into `Transport`.
                let stale_pooled_connection = allow_reuse_retry
                    && client.config.connection_pool_enabled
                    && !error.is_timeout()
                    && !error.is_connect()
                    && check_cancelled(cancel_token).is_ok();
                if !stale_pooled_connection {
                    return Err(classify_send_error(error));
                }
                allow_reuse_retry = false;
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(VaneError::Timeout("HTTP request timed out".to_string()));
                }
                build(remaining)?.send().map_err(classify_send_error)?
            }
        };
        // Belt and braces for the host we based every security decision on:
        // reqwest re-parses the URL with its own parser, so if the two ever
        // disagree about the host, fail closed instead of acting on ours.
        if response.url().host_str() != current.host_str() {
            return Err(VaneError::Generic(
                "URL host was interpreted differently by the HTTP client".to_string(),
            ));
        }
        // The caller's body is uploaded once, on the first hop; a later hop
        // whose body was dropped has nothing more to send. Reporting that
        // hop's (zero) length would walk the progress bar backwards, so the
        // cumulative figure stands.
        progress_upload(
            progress,
            request_body.len() as u64,
            request_body.len() as u64,
        );

        // Harvested per hop: only the final response reaches the body read, so
        // a `Set-Cookie` on a 302 would otherwise be dropped and the caller
        // would look silently logged out.
        if client.config.cookies_enabled {
            let set_cookies = collect_set_cookie(&response);
            if !set_cookies.is_empty() {
                client.store_response_cookies(&current, &set_cookies)?;
            }
        }

        let next = match redirect_target(&response, &current, request, hops, &certificate_pins) {
            RedirectDecision::Stop => break response,
            RedirectDecision::Refused(reason) => {
                refused = Some(reason);
                break response;
            }
            RedirectDecision::Follow(next) => next,
        };
        let cross_origin = (next.host_str().unwrap_or_default(), origin_port(&next))
            != (
                current.host_str().unwrap_or_default(),
                origin_port(&current),
            );
        match redirect_rewrite(
            response.status().as_u16(),
            method.as_str(),
            !body.is_empty(),
            cross_origin,
        ) {
            // The hop would replay the body at a different origin.
            RedirectRewrite::Refuse => {
                refused = Some(REDIRECT_REFUSED_CROSS_ORIGIN_BODY);
                break response;
            }
            RedirectRewrite::ToGet => {
                method = reqwest::Method::GET;
                body = &[];
                body_dropped = true;
            }
            RedirectRewrite::Keep => {}
        }
        current = next;
        hops += 1;
    };

    // Read off the final hop only — Vane runs `redirect::Policy::none()` and
    // does its own hops — and before `read_body` moves the response.
    let http_version = http_version_of(response.version());
    read_body(response, &mut state, cancel_token, progress)?;

    if let Some(reason) = refused {
        state
            .headers
            .insert(REDIRECT_REFUSED_HEADER.to_string(), reason.to_string());
    }

    let status_code = state.status_code;
    Ok(VaneResponse {
        status_code,
        headers: state.headers,
        body: state.body,
        body_file_path: state.body_file_path,
        is_success: (200..=299).contains(&status_code),
        url: current.to_string(),
        set_cookie: state.set_cookie_headers,
        http_version,
    })
}

/// reqwest hands back the version hyper read off the wire (h2 stamps
/// `HTTP_2`, the h1 parser stamps `HTTP_11`/`HTTP_10` from the status line),
/// so this is the negotiated protocol, not the requested one.
fn http_version_of(version: reqwest::Version) -> Option<VaneHttpVersion> {
    match version {
        reqwest::Version::HTTP_10 => Some(VaneHttpVersion::Http10),
        reqwest::Version::HTTP_11 => Some(VaneHttpVersion::Http11),
        reqwest::Version::HTTP_2 => Some(VaneHttpVersion::Http2),
        _ => None,
    }
}

/// Maps a send failure onto a kind using reqwest's own predicates, so the
/// classification never depends on parsing English error text.
///
/// ponytail: a TLS failure — including a pin mismatch raised by
/// `PinnedServerCertVerifier` — reports `Transport`, not `Tls`. reqwest folds
/// it into `is_connect()`, and the `rustls::Error` underneath is not reachable
/// through `source()` because `io::Error` skips its own inner error there.
/// Upgrade path if a caller needs it: have the verifier record the rejection on
/// the client and read it back here. The HTTP/3 path, where Vane's own pin code
/// runs, does report `Tls`.
fn classify_send_error(error: reqwest::Error) -> VaneError {
    let timeout = error.is_timeout();
    let connect = error.is_connect();
    let message = format!("HTTP request failed: {}", describe(error));
    match (timeout, connect) {
        (true, true) => VaneError::ConnectTimeout(message),
        (true, false) => VaneError::Timeout(message),
        _ => VaneError::Transport(message),
    }
}

/// Renders a reqwest error with its whole source chain.
///
/// reqwest's own `Display` is "error sending request" for everything from a
/// refused connection to a rejected certificate — the part worth reading is
/// always a source or two down, e.g. the rustls "invalid peer certificate"
/// text. `without_url` still drops the URL reqwest appends to its own Display,
/// which would otherwise put query-string tokens into caller-visible errors and
/// application logs; no error further down the chain carries one.
fn describe(error: reqwest::Error) -> String {
    let error = error.without_url();
    let mut message = error.to_string();
    let mut source = std::error::Error::source(&error);
    while let Some(cause) = source {
        use std::fmt::Write as _;
        let _ = write!(message, ": {cause}");
        source = cause.source();
    }
    message
}

fn collect_set_cookie(response: &reqwest::blocking::Response) -> Vec<String> {
    response
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .map(|value| String::from_utf8_lossy(value.as_bytes()).to_string())
        .collect()
}

/// Reads the redirect target off a reqwest response and hands the decision to
/// the rule both transports share. `None` means "treat this as the final
/// response" — which hands the 3xx back to the caller exactly as the HTTP/3
/// path would.
fn redirect_target(
    response: &reqwest::blocking::Response,
    current: &Url,
    request: &VaneRequest,
    hops: usize,
    certificate_pins: &HashMap<String, Vec<String>>,
) -> RedirectDecision {
    // `get` takes the first Location if a server sent several; a response with
    // conflicting Location headers is malformed either way and the hop is
    // gated by the scheme/pin/origin rules regardless of which we pick.
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|value| value.to_str().ok());
    next_redirect_url(
        response.status().as_u16(),
        location,
        current,
        request,
        hops,
        certificate_pins,
    )
}

fn read_body(
    mut response: reqwest::blocking::Response,
    state: &mut ResponseState,
    cancel_token: Option<&AtomicBool>,
    progress: Option<&VaneProgressState>,
) -> Result<(), VaneError> {
    state.status_code = response.status().as_u16();
    for (name, value) in response.headers() {
        // One `(name, value)` pair per occurrence; the shared merge joins
        // repeats and diverts `set-cookie` to its own list, so the map cannot
        // depend on which transport served the response. `Set-Cookie` is
        // surfaced even with the jar off — the harvest above is gated on
        // `cookies_enabled`, this is not, or the caller loses it entirely.
        state.merge_header(
            name.as_str().to_string(),
            String::from_utf8_lossy(value.as_bytes()).to_string(),
        );
    }

    let mut buf = vec![0; H3_BODY_BUFFER_BYTES];
    loop {
        // ponytail: only between reads, so a cancel lands on a chunk boundary
        // instead of the ~50 ms the HTTP/3 loop manages. Needs a wrapping
        // reader to do better.
        check_cancelled(cancel_token)?;
        match response.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(read) => {
                state.push_body(&buf[..read])?;
                progress_download(progress, state.body_len as u64, state.download_total);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                return Err(VaneError::Transport(format!(
                    "Failed to read HTTP response body: {e}"
                )));
            }
        }
    }
}

#[cfg(test)]
#[path = "tcp/tests.rs"]
mod tests;
