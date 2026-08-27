//! TCP fallback backend: HTTP/1.1 and HTTP/2 over TLS 1.2/1.3.
//!
//! Gated behind the `tcp-fallback` feature so the HTTP/3-only artifact never
//! links reqwest, hyper, tokio or rustls. Everything user-visible — the cookie
//! jar, retry policy, body limits, progress, cancellation and certificate pins
//! — is the same machinery the HTTP/3 path uses, so the two transports are
//! interchangeable from the caller's side.

use std::collections::{HashMap, HashSet};
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
use rustls::client::{
    ClientSessionMemoryCache, ClientSessionStore, Resumption, Tls12ClientSessionValue,
    Tls13ClientSessionValue, WebPkiServerVerifier,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, NamedGroup, SignatureScheme};

use super::{
    BodyStep, ClientDnsResolver, ClientIdentity, H3_BODY_BUFFER_BYTES, REDIRECT_REFUSED_HEADER,
    RedirectDecision, RedirectRewrite, RequestBodyStream, ResponseState, StreamingBodySource,
    StreamingHopResult, Url, VaneClient, VaneClientConfig, VaneError, VaneHeader, VaneHttpVersion,
    VaneProgressState, VaneProtocolMode, VaneRequest, VaneResponse, VaneResponseStream,
    VaneTlsVersion, cancel_token, check_cancelled, for_each_regular_header,
    header_survives_origin_change, may_resume_tls_session, next_redirect_url, origin_port,
    progress_download, progress_handle, progress_init, progress_upload, redact_url_userinfo,
    redirect_rewrite, resolve_peer_addr, streaming_head, upload_total, verify_certificate_pins,
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

/// OR-composes the platform verifier with a webpki verifier over the
/// caller's `custom_root_certificates`: a chain is accepted iff EITHER full
/// verifier accepts it. Each arm performs complete chain, name and validity
/// verification over its own root set, so the composition is exactly
/// extend-only semantics — it cannot accept anything outside the union of
/// the two trust sets.
///
/// One uniform mechanism on every platform, deliberately: Android's platform
/// verifier has no extra-roots API at all, so a per-OS `new_with_extra_roots`
/// would be a build break or a silent no-op there. Built only when the list
/// is non-empty; [`PinnedServerCertVerifier`] wraps THIS, so pins are
/// enforced above whichever arm accepted.
///
/// Revocation asymmetry, by design: the custom arm is pure webpki with no
/// revocation checking (no CRLs are configured), while the platform arm
/// inherits the OS verifier's revocation behavior (Apple/Windows check;
/// rustls-platform-verifier's Android and Linux arms do not). So on
/// platforms that check, a chain the platform arm rejects as REVOKED is
/// still accepted here whenever the custom roots also anchor it — custom
/// roots are for private CAs whose revocation the deployer owns.
#[derive(Debug)]
struct ExtendedTrustVerifier {
    platform: Arc<dyn ServerCertVerifier>,
    custom: Arc<WebPkiServerVerifier>,
}

impl ServerCertVerifier for ExtendedTrustVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match self.platform.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(verified) => Ok(verified),
            Err(platform_err) => self
                .custom
                .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
                // Both arms refused: report the platform's error — platform
                // trust is the rule callers reason about, custom roots the
                // exception.
                .map_err(|_| platform_err),
        }
    }

    // Signature checks are chain-independent; the platform arm's schemes are
    // what the handshake offered, so it stays the authority for them.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.platform.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.platform.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.platform.supported_verify_schemes()
    }
}

/// Parses every `custom_root_certificates` entry into one root store. Shared
/// by `VaneClient::new` (so a bad entry fails construction) and [`tls_config`]
/// (which builds the webpki arm over it); the error names the entry index
/// only — never certificate content.
pub(crate) fn parse_custom_roots(entries: &[String]) -> Result<rustls::RootCertStore, VaneError> {
    let mut roots = rustls::RootCertStore::empty();
    for (index, pem) in entries.iter().enumerate() {
        let invalid = || {
            VaneError::InvalidRequest(format!(
                "customRootCertificates[{index}] is not valid PEM certificate data"
            ))
        };
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem.as_bytes())
            .collect::<Result<_, _>>()
            .map_err(|_| invalid())?;
        if certs.is_empty() {
            return Err(invalid());
        }
        for cert in certs {
            roots.add(cert).map_err(|_| invalid())?;
        }
    }
    Ok(roots)
}

/// Parses the client certificate's PEM chain + key into rustls types. Shared
/// by `VaneClient::new` (construction-time validation) and [`tls_config`];
/// error messages are fixed strings — no PEM or key material, ever.
pub(crate) fn parse_client_identity(
    identity: &ClientIdentity,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), VaneError> {
    let invalid_chain =
        || VaneError::InvalidRequest("clientCertificate PEM did not parse".to_string());
    let chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(identity.chain_pem.as_bytes())
            .collect::<Result<_, _>>()
            .map_err(|_| invalid_chain())?;
    if chain.is_empty() {
        return Err(invalid_chain());
    }
    let key = PrivateKeyDer::from_pem_slice(identity.key_pem.as_bytes()).map_err(|_| {
        VaneError::InvalidRequest("clientCertificate privateKey did not parse".to_string())
    })?;
    Ok((chain, key))
}

/// The TCP spelling of the HTTP/3 rule in [`super::may_resume_tls_session`]:
/// a pinned host never stores or offers a TLS session.
///
/// A resumed handshake — TLS 1.3 PSK or TLS 1.2 abbreviated — carries no
/// Certificate message; rustls restores the chain cached when the session was
/// stored and never calls [`PinnedServerCertVerifier::verify_server_cert`],
/// so a resumed connection to a pinned host would complete with no pin check
/// at all. Gated per host, so pins on one host cost no resumption anywhere
/// else.
///
/// Both directions are refused for a pinned host: never offering alone would
/// leave tickets banked for a future code path to misuse, and never storing
/// alone would trust nothing else ever writing to the cache.
///
/// The pin set is a snapshot with exactly the verifier's lifetime —
/// `set_certificate_pins` rebuilds the whole TCP client (dropping this store
/// and any tickets in it), so the store and the verifier can never disagree
/// about which hosts are pinned.
#[derive(Debug)]
struct PinAwareSessionStore {
    inner: ClientSessionMemoryCache,
    /// Hosts with at least one pin, spelled the way [`pin_lookup_host`]
    /// spells them.
    pinned_hosts: HashSet<String>,
}

impl PinAwareSessionStore {
    fn may_resume(&self, server_name: &ServerName<'_>) -> bool {
        if self.pinned_hosts.is_empty() {
            return true;
        }
        // Fail closed, exactly like the verifier: a name shape we cannot
        // spell cannot be looked up, and this client has pins configured.
        match pin_lookup_host(server_name) {
            Some(host) => !self.pinned_hosts.contains(&host),
            None => false,
        }
    }
}

impl ClientSessionStore for PinAwareSessionStore {
    // Key-exchange hints carry no trust — only a round trip saved on the next
    // full handshake — so pinned hosts keep them.
    fn set_kx_hint(&self, server_name: ServerName<'static>, group: NamedGroup) {
        self.inner.set_kx_hint(server_name, group);
    }

    fn kx_hint(&self, server_name: &ServerName<'_>) -> Option<NamedGroup> {
        self.inner.kx_hint(server_name)
    }

    fn set_tls12_session(&self, server_name: ServerName<'static>, value: Tls12ClientSessionValue) {
        if self.may_resume(&server_name) {
            self.inner.set_tls12_session(server_name, value);
        }
    }

    fn tls12_session(&self, server_name: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
        if !self.may_resume(server_name) {
            return None;
        }
        self.inner.tls12_session(server_name)
    }

    fn remove_tls12_session(&self, server_name: &ServerName<'static>) {
        self.inner.remove_tls12_session(server_name);
    }

    fn insert_tls13_ticket(
        &self,
        server_name: ServerName<'static>,
        value: Tls13ClientSessionValue,
    ) {
        if self.may_resume(&server_name) {
            self.inner.insert_tls13_ticket(server_name, value);
        }
    }

    fn take_tls13_ticket(
        &self,
        server_name: &ServerName<'static>,
    ) -> Option<Tls13ClientSessionValue> {
        if !self.may_resume(server_name) {
            return None;
        }
        self.inner.take_tls13_ticket(server_name)
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
    config: &VaneClientConfig,
    client_identity: Option<&ClientIdentity>,
    certificate_pins: HashMap<String, Vec<String>>,
) -> Result<ClientConfig, VaneError> {
    // Before `Verifier::new`, not after: this is the only place a platform
    // verifier is constructed, so every TCP request is covered by this one
    // guard regardless of which entry point it came in through.
    #[cfg(target_os = "android")]
    check_android_trust_ready()?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let platform = inner_verifier(&provider)?;
    // Custom roots EXTEND platform trust through the OR-composite
    // [`ExtendedTrustVerifier`]; the empty list keeps the bare platform
    // verifier — today's path exactly.
    let inner: Arc<dyn ServerCertVerifier> = if config.custom_root_certificates.is_empty() {
        platform
    } else {
        let roots = parse_custom_roots(&config.custom_root_certificates)?;
        let custom = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()
            .map_err(|e| {
                VaneError::Tls(format!("Failed to build the custom-roots verifier: {e}"))
            })?;
        Arc::new(ExtendedTrustVerifier { platform, custom })
    };

    // Lowercased like every pin lookup; an entry that only differs by case
    // still marks the host pinned here, which errs toward a full handshake.
    let pinned_hosts = certificate_pins
        .iter()
        .filter(|(_, pins)| !pins.is_empty())
        .map(|(host, _)| host.to_ascii_lowercase())
        .collect();

    // Unset bounds mean rustls's defaults: TLS 1.2 + 1.3. `min > max` was
    // rejected at construction, so the filtered list is never empty. This is
    // the only enforcement site — HTTP/3 is TLS 1.3-always (quiche pins it
    // per connection; RFC 9001), which construction validation accounts for.
    let mut versions: Vec<&'static rustls::SupportedProtocolVersion> = Vec::new();
    if config.tls_min_version.unwrap_or(VaneTlsVersion::Tls12) == VaneTlsVersion::Tls12 {
        versions.push(&rustls::version::TLS12);
    }
    if config.tls_max_version.unwrap_or(VaneTlsVersion::Tls13) == VaneTlsVersion::Tls13 {
        versions.push(&rustls::version::TLS13);
    }
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&versions)
        .map_err(|e| VaneError::Tls(format!("Failed to configure TLS versions: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedServerCertVerifier {
            inner,
            certificate_pins,
        }));
    let mut tls = match client_identity {
        // mTLS toward the origin: the ONE shared [`ClientIdentity`] the
        // HTTP/3 builder path also consumes (taken out of the config at
        // construction — see `VaneClient::client_identity`), parsed by
        // rustls here. Construction already ran this parse, so a failure at
        // this point is a rustls-level rejection of the material itself —
        // surfaced without echoing any of it.
        Some(identity) => {
            let (chain, key) = parse_client_identity(identity)?;
            builder.with_client_auth_cert(chain, key).map_err(|e| {
                VaneError::Tls(format!("Failed to configure client certificate: {e}"))
            })?
        }
        None => builder.with_no_client_auth(),
    };

    // rustls's default resumption would happily resume a pinned host, and a
    // resumed handshake never reaches the verifier installed above. The
    // 256-entry cache matches the default this replaces; 0-RTT stays off
    // (rustls clients never send early data unless `enable_early_data` is
    // set, and it is not).
    tls.resumption = Resumption::store(Arc::new(PinAwareSessionStore {
        inner: ClientSessionMemoryCache::new(256),
        pinned_hosts,
    }));

    // reqwest only fills these in on its own TLS path; a preconfigured config
    // is passed through untouched, so without this nothing offers ALPN, HTTP/2
    // is never negotiated, and prior-knowledge h2 violates RFC 9113 3.4.
    tls.alpn_protocols = match config.protocol_mode {
        VaneProtocolMode::Http1Only => vec![b"http/1.1".to_vec()],
        VaneProtocolMode::Http2Only => vec![b"h2".to_vec()],
        _ => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
    };

    Ok(tls)
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

/// The cached blocking client together with the exact rustls config it was
/// built from.
///
/// The config is kept so [`warmup`]'s probe can handshake through the *same*
/// verifier instance the client's own connections use. On Android the
/// platform verifier carries per-instance state whose first verification
/// costs hundreds of ms on top of the process-global trust-store init
/// (measured: a probe through a separate verifier left ~380 ms in the first
/// real request; the matrix benchmark's second in-process TCP client shows
/// the same per-instance cost). Sharing the config also shares the TLS
/// session cache, so for an unpinned host the first real connection can
/// resume the probe's session instead of running a full handshake. A pinned
/// host never resumes (see [`PinAwareSessionStore`]); its probe still buys
/// the warm verifier and an early pin check.
#[derive(Debug)]
pub(crate) struct SharedTcpClient {
    http: Client,
    tls: ClientConfig,
}

/// Bridges the client's installed [`ClientDnsResolver`] into reqwest.
///
/// The resolve — including the Dart rendezvous, which can park for up to its
/// 10 s timeout — must NOT run inline in the returned future: reqwest's
/// blocking client polls every in-flight request on one shared
/// current-thread runtime, so an inline blocking resolve would
/// head-of-line-block every concurrent TCP request AND park the tokio timer
/// so their timeouts could not fire. `spawn_blocking` restores exactly the
/// threading of hyper's default `GaiResolver`, which runs `getaddrinfo` on
/// the same blocking pool.
///
/// Goes through [`resolve_peer_addr`], so both transports share one decision
/// chain: the overrides win in here too (reqwest's own `builder.resolve`
/// entries also short-circuit ahead of this adapter, saying the same thing).
/// The resolved address only ever steers the socket — reqwest takes the TLS
/// server name from the URL host, and the pin lookup
/// ([`PinnedServerCertVerifier`]) keys off that same name.
struct ResolverAdapter {
    resolver: Arc<ClientDnsResolver>,
    dns_overrides: HashMap<String, String>,
}

impl reqwest::dns::Resolve for ResolverAdapter {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let resolver = Arc::clone(&self.resolver);
        let overrides = self.dns_overrides.clone();
        Box::pin(async move {
            let addr = tokio::task::spawn_blocking(move || {
                // Port 0 tells reqwest to take the port from the URL — the
                // same trick as the `builder.resolve` overrides.
                resolve_peer_addr(name.as_str(), 0, &overrides, Some(&resolver))
            })
            .await
            .map_err(|e| format!("dns resolver task failed: {e}"))?
            .map_err(|e| e.to_string())?;
            Ok(Box::new(std::iter::once(addr)) as reqwest::dns::Addrs)
        })
    }
}

fn build_client(
    client: &VaneClient,
    certificate_pins: HashMap<String, Vec<String>>,
) -> Result<SharedTcpClient, VaneError> {
    let config = &client.config;
    let tls = tls_config(config, client.client_identity.as_deref(), certificate_pins)?;
    let mut builder = Client::builder()
        // A clone shares the verifier and session cache by `Arc`, so the
        // retained copy IS the client's TLS identity, not a twin.
        .use_preconfigured_tls(tls.clone())
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

    // With no resolver installed this branch is never taken and the path
    // above is byte-for-byte today's. The setter clears the cached client, so
    // a rebuild always captures the currently-installed resolver.
    if let Some(resolver) = client.dns_resolver_snapshot() {
        builder = builder.dns_resolver(Arc::new(ResolverAdapter {
            resolver,
            dns_overrides: config.dns_overrides.clone(),
        }));
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

    let http = builder
        .build()
        .map_err(|e| VaneError::Generic(format!("Failed to build TCP client: {e}")))?;
    Ok(SharedTcpClient { http, tls })
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
        return Ok((existing.http.clone(), certificate_pins));
    }
    let built = build_client(client, certificate_pins.clone())?;
    Ok((cached.insert(built).http.clone(), certificate_pins))
}

/// Pays the TCP transport's one-time costs ahead of the first real request:
/// builds (and caches) the shared reqwest client — the tokio runtime, the
/// rustls config and the platform verifier — and then, given a target and no
/// proxy, runs one TLS handshake against it.
///
/// The handshake is the load-bearing half on Android: the platform
/// verifier's *first* verification initializes conscrypt and loads the
/// system trust store over JNI — the bulk of the measured ~1 s first-request
/// cost, part process-global and part per-verifier-instance. The probe
/// therefore handshakes through the cached client's own `ClientConfig`
/// (see [`SharedTcpClient`]), so both layers are paid here and the client's
/// first real handshake finds a warm verifier and — for an unpinned host —
/// a resumable TLS session.
/// No HTTP bytes are ever written — the probe completes the handshake, sends
/// close_notify and hangs up, so the server sees a connection but never a
/// request, and nothing caller-visible happens on either side.
///
/// The probe socket is discarded rather than pooled: reqwest has no way to
/// adopt a foreign connection, so the first real request still performs its
/// own (now cheap, likely resumed) handshake.
///
/// ponytail: with a proxy configured the probe is skipped — a CONNECT tunnel
/// dance isn't worth building for a best-effort path; client construction
/// still runs.
pub(crate) fn warmup(client: &VaneClient, url: Option<&Url>) -> Result<(), VaneError> {
    // One critical section builds (or reuses) the cached client and clones
    // its TLS config — Arc-backed, so this IS the client's verifier and
    // session cache, not a copy. Same lock order as `shared_client`, and the
    // pins are read inside it, so they are exactly the set the cached
    // client's verifier and session store were built with.
    let (tls, certificate_pins) = {
        let mut cached = client
            .tcp_client
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let certificate_pins = client.certificate_pins_snapshot()?;
        if cached.is_none() {
            *cached = Some(build_client(client, certificate_pins.clone())?);
        }
        let entry = cached.as_ref().expect("cached TCP client was just built");
        (entry.tls.clone(), certificate_pins)
    };
    let Some(url) = url else { return Ok(()) };
    if client.config.proxy_url.is_some() {
        return Ok(());
    }
    let host = url
        .host_str()
        .ok_or_else(|| VaneError::InvalidRequest("URL is missing host".to_string()))?;
    let peer_addr = resolve_peer_addr(
        host,
        url.port_or_known_default().unwrap_or(443),
        &client.config.dns_overrides,
        client.dns_resolver_snapshot().as_deref(),
    )?;
    let timeout = Duration::from_secs(client.config.timeout_seconds.unwrap_or(30));
    let deadline = Instant::now() + timeout;

    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| VaneError::InvalidRequest(format!("Invalid TLS server name {host}: {e}")))?;
    let mut conn = rustls::ClientConnection::new(Arc::new(tls), server_name)
        .map_err(|e| VaneError::Tls(format!("Failed to start warmup TLS handshake: {e}")))?;

    let mut stream = std::net::TcpStream::connect_timeout(&peer_addr, timeout)
        .map_err(classify_warmup_io_error)?;
    while conn.is_handshaking() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(VaneError::ConnectTimeout(
                "Warmup TLS handshake timed out".to_string(),
            ));
        }
        // Re-armed per step so the whole handshake — not each blocking
        // syscall — is bounded by the one deadline.
        stream
            .set_read_timeout(Some(remaining))
            .and_then(|()| stream.set_write_timeout(Some(remaining)))
            .map_err(classify_warmup_io_error)?;
        conn.complete_io(&mut stream).map_err(|e| {
            // rustls reports TLS failures — including a refused certificate or
            // a pin mismatch — through io::Error too, so split on the kinds
            // the socket timeouts produce.
            if matches!(
                e.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) {
                VaneError::ConnectTimeout(format!("Warmup TLS handshake timed out: {e}"))
            } else {
                VaneError::Tls(format!("Warmup TLS handshake failed: {e}"))
            }
        })?;
    }
    // The handshake alone leaves nothing to resume: the server's TLS 1.3
    // NewSessionTickets arrive one round trip AFTER the client Finished, so
    // wait briefly and read them into the shared session cache. That is what
    // lets the client's first real handshake resume — and a resumed
    // handshake carries no certificate, which on Android skips the
    // platform verifier's per-verification JNI cost (~350–400 ms per full
    // handshake on the emulator benchmark; the verifier re-runs PKIX
    // building and revocation per call, so a warm verifier alone does not
    // help).
    //
    // Two bounded reads: the first waits for the ticket flight, the second
    // briefly sweeps for the rest of it in case the flight crossed a TCP
    // segment boundary and the first read caught only part of a ticket. One
    // whole ticket is all resumption needs. A server that sends none costs
    // the cap once and nothing else; failures are ignored because the
    // handshake already succeeded and its other value (warm trust store,
    // warm DNS) is banked. (Resumption remains the server's call — a
    // declined ticket just means the first request runs a full handshake.)
    //
    // A pinned host is skipped: its tickets are exactly the ones
    // `PinAwareSessionStore` refuses to bank — a pinned host never resumes —
    // so waiting for them would spend up to ~850 ms collecting bytes that get
    // dropped. The probe's full handshake above already delivered the pinned
    // host's whole value: warm verifier, warm DNS, early pin check.
    if may_resume_tls_session(host, &certificate_pins) {
        let ticket_wait = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(750));
        for wait in [ticket_wait, Duration::from_millis(100)] {
            let wait = wait.min(deadline.saturating_duration_since(Instant::now()));
            if wait.is_zero() || stream.set_read_timeout(Some(wait)).is_err() {
                break;
            }
            match conn.read_tls(&mut stream) {
                Ok(read) if read > 0 => {
                    conn.process_new_packets().ok();
                }
                _ => break,
            }
        }
    }
    conn.send_close_notify();
    // Best-effort flush of the close alert; the handshake already succeeded.
    conn.complete_io(&mut stream).ok();
    Ok(())
}

fn classify_warmup_io_error(error: io::Error) -> VaneError {
    if matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ) {
        VaneError::ConnectTimeout(format!("Warmup connection timed out: {error}"))
    } else {
        VaneError::Transport(format!("Warmup connection failed: {error}"))
    }
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
    body_stream: Option<&Arc<RequestBodyStream>>,
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
    let progress = progress_init(request.progress_id, upload_total(request_body, body_stream));
    // `execute` marks the request done once the whole dispatch resolves, so a
    // poller never sees `done` flip while a fallback is still to come.
    follow_and_read(
        client,
        request,
        url,
        request_body,
        body_stream,
        cancel_token.as_deref(),
        progress.as_deref(),
    )
}

#[allow(clippy::too_many_arguments)]
fn follow_and_read(
    client: &VaneClient,
    request: &VaneRequest,
    url: &Url,
    request_body: &[u8],
    body_stream: Option<&Arc<RequestBodyStream>>,
    cancel_token: Option<&AtomicBool>,
    progress: Option<&VaneProgressState>,
) -> Result<VaneResponse, VaneError> {
    // One deadline for the whole chain. Applying the timeout per hop would let
    // a hostile server hold a caller thread for hop-cap times the requested
    // timeout, and the retry loop multiplies that again.
    let deadline = request_deadline(client, request);
    let (http, certificate_pins) = shared_client(client)?;

    // Created before anything goes on the wire so a bad response_body_path
    // fails without having sent a request, matching the HTTP/3 path.
    let mut state = ResponseState::new(
        client.config.max_response_body_bytes,
        request.response_body_path.as_deref(),
    )?;

    let hop = follow(
        client,
        request,
        url,
        request_body,
        body_stream,
        cancel_token,
        progress,
        &http,
        &certificate_pins,
        deadline,
    )?;

    // Read off the final hop only — Vane runs `redirect::Policy::none()` and
    // does its own hops — and before `read_body` moves the response. Through
    // a CONNECT proxy `remote_addr` reports the socket peer (the proxy),
    // consistent with the H3 MASQUE rule by construction.
    let http_version = http_version_of(hop.response.version());
    let remote_ip = hop.response.remote_addr().map(|addr| addr.ip().to_string());
    read_body(hop.response, &mut state, cancel_token, progress)?;

    if let Some(reason) = hop.refused {
        // Direct push, NOT `push_header`: the reserved refusal marker is
        // dropped there when it arrives from the peer, and this is the one
        // place the TCP buffered path appends Vane's own.
        state.headers.push(VaneHeader {
            name: REDIRECT_REFUSED_HEADER.to_string(),
            value: reason.to_string(),
        });
    }

    let status_code = state.status_code;
    Ok(VaneResponse {
        status_code,
        headers: state.headers,
        body: state.body,
        body_file_path: state.body_file_path,
        is_success: (200..=299).contains(&status_code),
        url: hop.url.to_string(),
        http_version,
        remote_ip,
    })
}

fn request_deadline(client: &VaneClient, request: &VaneRequest) -> Instant {
    Instant::now()
        + std::time::Duration::from_secs(
            request
                .timeout_seconds
                .or(client.config.timeout_seconds)
                .unwrap_or(30),
        )
}

/// The redirect chain's final hop, its body still unread.
struct TcpFinalHop {
    response: reqwest::blocking::Response,
    /// Why the chain stopped on a 3xx it refused to follow, if it did.
    refused: Option<&'static str>,
    /// URL the final hop was served from.
    url: Url,
}

/// Runs the redirect chain and returns the final hop with its body untouched,
/// so the caller can read it whole or stream it. Intermediate 3xx bodies are
/// never read: reqwest drops them with the hop's response.
#[allow(clippy::too_many_arguments)]
fn follow(
    client: &VaneClient,
    request: &VaneRequest,
    url: &Url,
    request_body: &[u8],
    body_stream: Option<&Arc<RequestBodyStream>>,
    cancel_token: Option<&AtomicBool>,
    progress: Option<&VaneProgressState>,
    http: &Client,
    certificate_pins: &HashMap<String, Vec<String>>,
    deadline: Instant,
) -> Result<TcpFinalHop, VaneError> {
    let origin = (
        url.host_str().unwrap_or_default().to_string(),
        origin_port(url),
    );
    let mut current = url.clone();
    let mut method = reqwest::Method::from_bytes(request.method.to_ascii_uppercase().as_bytes())
        .map_err(|_| {
            VaneError::InvalidRequest(format!("Invalid HTTP method {}", request.method))
        })?;
    let mut body = request_body;
    let mut body_stream = body_stream;
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
            if let Some(stream) = body_stream {
                // The reqwest blocking client pumps this reader on the
                // calling thread through a rendezvous channel that hyper
                // drains as the connection accepts bytes (verified against
                // reqwest 0.13.4, blocking/body.rs `send_future`), so a full
                // send window parks the reader and, through it, the writer.
                // `sized` sends `Content-Length`; `new` has no length and
                // sends chunked on HTTP/1.1, plain DATA on h2.
                //
                // The per-request timeout above covers the whole body send
                // plus the wait for headers as ONE budget — reqwest wraps
                // them in a single `wait::timeout` — so a streamed TCP upload
                // must complete within the request timeout. Documented
                // ceiling; the response-body phase re-anchors per read as
                // before.
                let reader = BodyStreamReader::new(
                    stream,
                    client.config.max_request_body_bytes,
                    request.cancel_token_id,
                    request.progress_id,
                );
                builder = builder.body(match stream.content_length {
                    Some(declared) => reqwest::blocking::Body::sized(reader, declared),
                    None => reqwest::blocking::Body::new(reader),
                });
            } else if !body.is_empty() {
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
                //
                // A streamed body additionally requires that nothing was
                // consumed: bytes hyper already pulled died with the stale
                // connection and cannot be sent again.
                let stale_pooled_connection = allow_reuse_retry
                    && client.config.connection_pool_enabled
                    && !error.is_timeout()
                    && !error.is_connect()
                    && check_cancelled(cancel_token).is_ok()
                    && body_stream.is_none_or(|stream| stream.consumed() == 0);
                if !stale_pooled_connection {
                    return Err(streamed_send_error(body_stream, error));
                }
                allow_reuse_retry = false;
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(VaneError::Timeout("HTTP request timed out".to_string()));
                }
                build(remaining)?
                    .send()
                    .map_err(|error| streamed_send_error(body_stream, error))?
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
        // cumulative figure stands. A streamed body reported its own counters
        // from the reader as chunks were consumed; publish its final figure
        // instead of stomping them with the empty slice's zero.
        match body_stream {
            Some(stream) => {
                let sent = stream.consumed();
                progress_upload(progress, sent, sent);
            }
            None => progress_upload(
                progress,
                request_body.len() as u64,
                request_body.len() as u64,
            ),
        }

        // Harvested per hop: only the final response reaches the body read, so
        // a `Set-Cookie` on a 302 would otherwise be dropped and the caller
        // would look silently logged out.
        if client.config.cookies_enabled {
            let set_cookies = collect_set_cookie(&response);
            if !set_cookies.is_empty() {
                client.store_response_cookies(&current, &set_cookies)?;
            }
        }

        let next = match redirect_target(
            &response,
            &current,
            request,
            hops,
            client.config.max_redirects,
            certificate_pins,
        ) {
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
            body_stream.is_some(),
            cross_origin,
        ) {
            // The hop would need the body again — replayed at a different
            // origin, or replayed at all for a one-shot streamed body.
            RedirectRewrite::Refuse(reason) => {
                refused = Some(reason);
                break response;
            }
            RedirectRewrite::ToGet => {
                method = reqwest::Method::GET;
                body = &[];
                body_dropped = true;
                // The rewrite dropped the body for good; a writer still
                // pushing must learn that now, not at chain end.
                if let Some(stream) = body_stream.take() {
                    stream.release();
                }
            }
            RedirectRewrite::Keep => {}
        }
        current = next;
        hops += 1;
    };

    Ok(TcpFinalHop {
        response,
        refused,
        url: current,
    })
}

/// The `Read` bridge that feeds a [`RequestBodyStream`] into a reqwest
/// blocking body. reqwest reads it on the request's calling thread and only
/// as hyper drains its rendezvous channel, so `read` blocking on the caller's
/// pushes IS how transport backpressure reaches the writer.
struct BodyStreamReader {
    source: Arc<RequestBodyStream>,
    limit: u64,
    /// Owned handles, re-resolved by id: the reader outlives `follow`'s
    /// borrowed copies inside reqwest's request object.
    cancel: Option<Arc<AtomicBool>>,
    progress: Option<Arc<VaneProgressState>>,
    current: Vec<u8>,
    offset: usize,
}

impl BodyStreamReader {
    fn new(
        source: &Arc<RequestBodyStream>,
        limit: u64,
        cancel_token_id: Option<u64>,
        progress_id: Option<u64>,
    ) -> Self {
        Self {
            source: Arc::clone(source),
            limit,
            cancel: cancel_token(cancel_token_id),
            progress: progress_handle(progress_id),
            current: Vec::new(),
            offset: 0,
        }
    }
}

impl io::Read for BodyStreamReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.offset >= self.current.len() {
            // Waits in 50 ms slices so a cancel interrupts a parked upload
            // promptly; the terminal error this latches is also what the
            // request fails with (see `streamed_send_error`).
            match self.source.pull_blocking(
                self.limit,
                self.cancel.as_deref(),
                Duration::from_millis(50),
            ) {
                Ok(Some(chunk)) => {
                    self.current = chunk;
                    self.offset = 0;
                    let sent = self.source.consumed();
                    let total = self.source.content_length.unwrap_or(0);
                    progress_upload(self.progress.as_deref(), sent, total);
                }
                // Clean end of body. A short body under a declared length
                // cannot reach here: `finish()` refuses the mismatch and
                // latches the stream's terminal error instead.
                Ok(None) => return Ok(0),
                Err(err) => return Err(io::Error::other(err.to_string())),
            }
        }
        let n = buf.len().min(self.current.len() - self.offset);
        buf[..n].copy_from_slice(&self.current[self.offset..self.offset + n]);
        self.offset += n;
        Ok(n)
    }
}

/// Send-failure classification for a request with a streamed body. The
/// stream's own latched terminal error — a cancel, the body limit, a
/// declared-length violation, a freed writer — wins over reqwest's generic
/// send error, which by then only says "error sending request: body error".
/// Without a latched error the failure is the transport's and classifies as
/// always.
fn streamed_send_error(
    body_stream: Option<&Arc<RequestBodyStream>>,
    error: reqwest::Error,
) -> VaneError {
    body_stream
        .and_then(|stream| stream.latched_error())
        .unwrap_or_else(|| classify_send_error(error))
}

/// Streaming twin of [`execute_tcp_once`]: identical up to the final hop's
/// headers, after which the unread reqwest response becomes the stream's body
/// source. The per-request timeout armed on the hop keeps working after this
/// returns: reqwest re-anchors it on every blocking body read, which makes it
/// the stream's per-pull inactivity budget.
pub(crate) fn execute_tcp_streaming_once(
    client: &VaneClient,
    request: &VaneRequest,
    url: &Url,
    request_body: &[u8],
    body_stream: Option<&Arc<RequestBodyStream>>,
) -> Result<VaneResponseStream, VaneError> {
    // Same guard as the HTTP/3 path; see `execute_tcp_once`.
    if url.scheme() != "https" {
        return Err(VaneError::InvalidRequest(
            "Vane only supports https:// URLs".to_string(),
        ));
    }

    let cancel_token = cancel_token(request.cancel_token_id);
    let progress = progress_init(request.progress_id, upload_total(request_body, body_stream));
    let deadline = request_deadline(client, request);
    let (http, certificate_pins) = shared_client(client)?;
    // No body file: `execute_streaming` already refused `response_body_path`.
    let mut state = ResponseState::new(client.config.max_response_body_bytes, None)?;

    let hop = follow(
        client,
        request,
        url,
        request_body,
        body_stream,
        cancel_token.as_deref(),
        progress.as_deref(),
        &http,
        &certificate_pins,
        deadline,
    )?;
    // The blocking client finishes sending the body before it surfaces the
    // response headers (reqwest 0.13.4 `execute_request` awaits `body.send()`
    // ahead of the response oneshot), so by this point the upload phase is
    // over on TCP — successful or abandoned by an early-answering server —
    // and a still-pushing writer can be released without waiting for the
    // response stream to end.
    if let Some(stream) = body_stream {
        stream.release();
    }

    let http_version = http_version_of(hop.response.version());
    let remote_ip = hop.response.remote_addr().map(|addr| addr.ip().to_string());
    merge_response_head(&hop.response, &mut state);
    let mut head = streaming_head(&mut state, &hop.url, http_version, remote_ip);
    if let Some(reason) = hop.refused {
        head.headers.push(VaneHeader {
            name: REDIRECT_REFUSED_HEADER.to_string(),
            value: reason.to_string(),
        });
    }

    let source = StreamingBodySource::Tcp(Box::new(TcpBodyStream {
        response: Some(hop.response),
        state,
        buf: vec![0; H3_BODY_BUFFER_BYTES],
    }));
    Ok(StreamingHopResult { head, source }.into_stream(cancel_token, progress))
}

/// A live TCP response body: the unread reqwest response plus the shared
/// accumulator that enforces the body limit and feeds progress.
pub(crate) struct TcpBodyStream {
    /// `None` once abandoned. Dropping a reqwest response mid-body discards
    /// its connection — hyper only pools a connection whose body was read to
    /// EOF — which is exactly the pool rule streaming needs.
    response: Option<reqwest::blocking::Response>,
    /// Headers already stripped into the caller's head; carries the body
    /// accumulator and the cumulative limit counters.
    state: ResponseState,
    buf: Vec<u8>,
}

impl TcpBodyStream {
    pub(crate) fn next(
        &mut self,
        cancel: Option<&AtomicBool>,
        progress: Option<&VaneProgressState>,
    ) -> Result<BodyStep, VaneError> {
        let Some(response) = self.response.as_mut() else {
            return Err(VaneError::Generic(
                "Response stream connection is gone".to_string(),
            ));
        };
        loop {
            // ponytail: only between reads, so a cancel lands on a chunk
            // boundary — on a stalled stream it takes effect when the read
            // returns, at worst after the per-read timeout.
            check_cancelled(cancel)?;
            match response.read(&mut self.buf) {
                Ok(0) => break,
                Ok(read) => {
                    self.state.push_body(&self.buf[..read])?;
                    progress_download(
                        progress,
                        self.state.body_len as u64,
                        self.state.download_total,
                    );
                    return Ok(BodyStep::Chunk(std::mem::take(&mut self.state.body)));
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if is_read_timeout(&e) => {
                    return Err(VaneError::Timeout(format!(
                        "HTTP response body read timed out: {e}"
                    )));
                }
                Err(e) => {
                    return Err(VaneError::Transport(format!(
                        "Failed to read HTTP response body: {e}"
                    )));
                }
            }
        }
        // EOF: dropping the drained response hands its connection back to
        // hyper's pool. Publish the final figure so a poller sees
        // received == total even without a content-length.
        self.response = None;
        progress_download(
            progress,
            self.state.body_len as u64,
            self.state.body_len as u64,
        );
        Ok(BodyStep::Eof)
    }

    pub(crate) fn abandon(&mut self) {
        // Dropping mid-body closes the connection; nothing else to do.
        self.response = None;
    }
}

/// Whether a blocking body-read error is the per-read timeout. reqwest
/// surfaces it as `ErrorKind::Other` wrapping its own `Error`, so the kind
/// alone cannot say; `TimedOut`/`WouldBlock` are kept for plain socket-level
/// timeouts.
fn is_read_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ) || error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<reqwest::Error>())
        .is_some_and(reqwest::Error::is_timeout)
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
    max_redirects: u32,
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
        max_redirects,
        certificate_pins,
    )
}

/// Folds the final hop's status and headers into the shared state.
fn merge_response_head(response: &reqwest::blocking::Response, state: &mut ResponseState) {
    state.status_code = response.status().as_u16();
    for (name, value) in response.headers() {
        // One `(name, value)` pair per occurrence, appended in `HeaderMap`
        // iteration order (duplicates of a name grouped), so the list cannot
        // depend on which transport served the response. `Set-Cookie` rides
        // inline even with the jar off — the cookie harvest in `follow` is
        // gated on `cookies_enabled`, this is not, or the caller loses it
        // entirely. `from_utf8_lossy` rather than a `to_str` skip: a garbled
        // byte becomes U+FFFD, not a vanished header.
        state.push_header(
            name.as_str().to_string(),
            String::from_utf8_lossy(value.as_bytes()).to_string(),
        );
    }
}

fn read_body(
    mut response: reqwest::blocking::Response,
    state: &mut ResponseState,
    cancel_token: Option<&AtomicBool>,
    progress: Option<&VaneProgressState>,
) -> Result<(), VaneError> {
    merge_response_head(&response, state);

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
