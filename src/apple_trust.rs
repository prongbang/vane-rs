//! HTTP/3 server-certificate verification on Apple platforms.
//!
//! # Why this module exists
//!
//! `load_platform_roots` finds a CA bundle by walking well-known filesystem
//! paths (`/etc/ssl/cert.pem`, `/etc/ssl/certs`, the Android Conscrypt APEX).
//! That is correct on Android and on Linux. It is correct on **macOS** and on
//! the **iOS simulator** only by accident: both run on a Mac filesystem where
//! `/etc/ssl/cert.pem` happens to exist.
//!
//! A real iOS device has none of those paths inside the app sandbox, so
//! `load_platform_roots` returned `Err` and **every HTTP/3 request on a real
//! iPhone failed** with "No platform CA bundle found for quiche certificate
//! verification". Verified on an iPhone 15 / iOS 26.2.1 on 2026-08-29; it had
//! never shown up before because every prior iOS measurement was taken on the
//! simulator.
//!
//! The TCP path was never affected: it goes through `rustls-platform-verifier`,
//! which does not enumerate roots at all. Cargo.toml already says as much
//! ("iOS ships no PEM bundle at all") — this module brings the HTTP/3 path in
//! line with what the TCP path already knew.
//!
//! # Why it is a verify callback rather than a root list
//!
//! iOS has no public API to enumerate the system trust store —
//! `SecTrustCopyAnchorCertificates` is macOS-only. The supported way to
//! validate against platform trust is to hand the chain to `SecTrust` and let
//! `SecTrustEvaluateWithError` decide, which is exactly what
//! `rustls-platform-verifier` does on Apple. So instead of filling BoringSSL's
//! certificate store, we install a custom verify callback and delegate.
//!
//! # What this replaces, and what it must therefore do itself
//!
//! `SSL_CTX_set_custom_verify` takes over verification wholesale: BoringSSL's
//! own chain building and its certificate store are no longer consulted. Two
//! consequences this module has to handle rather than inherit:
//!
//! 1. **Hostname verification is ours now.** `SecPolicyCreateSSL` with a
//!    hostname performs it, so the policy is always built with the SNI name and
//!    a connection with no SNI is refused rather than validated name-blind.
//! 2. **`customRootCertificates` no longer reach verification through
//!    `cert_store_mut()`.** They are passed to `SecTrust` as additional
//!    anchors, with `SetAnchorCertificatesOnly(false)` so the system anchors
//!    still apply — preserving the documented additive semantics of that knob.
//!
//! Certificate **pinning is not involved here.** On HTTP/3 it runs
//! post-handshake against `conn.peer_cert()` (`verify_certificate_pins`), so it
//! composes with this change without either side knowing about the other.

use boring::ssl::{NameType, SslAlert, SslContextBuilder, SslVerifyError, SslVerifyMode};
use security_framework::certificate::SecCertificate;
use security_framework::policy::SecPolicy;
use security_framework::secure_transport::SslProtocolSide;
use security_framework::trust::SecTrust;

/// Installs Apple platform-trust verification on `builder`.
///
/// `custom_roots_der` is the DER form of the caller's `customRootCertificates`,
/// added as *extra* anchors on top of the system trust store. Empty means
/// "system trust only".
///
/// The anchors are carried as DER bytes rather than as `SecCertificate`s so the
/// closure is plainly `Send + Sync` without leaning on the framework types'
/// thread-safety; rebuilding them per handshake is a few microseconds against a
/// QUIC handshake's network round trip.
pub(crate) fn install_platform_verify(
    builder: &mut SslContextBuilder,
    custom_roots_der: Vec<Vec<u8>>,
) {
    builder.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
        // Fail closed on every path below: an unreadable chain, an absent
        // hostname, or a Security-framework error is a rejected connection,
        // never a silently accepted one.
        let chain = ssl
            .peer_cert_chain()
            .ok_or(SslVerifyError::Invalid(SslAlert::CERTIFICATE_UNKNOWN))?;

        let mut certs = Vec::with_capacity(chain.len());
        for cert in chain {
            let der = cert
                .to_der()
                .map_err(|_| SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE))?;
            certs.push(
                SecCertificate::from_der(&der)
                    .map_err(|_| SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE))?,
            );
        }
        if certs.is_empty() {
            return Err(SslVerifyError::Invalid(SslAlert::CERTIFICATE_UNKNOWN));
        }

        // Name verification rides on the policy, so a missing SNI is refused
        // rather than quietly evaluated without a hostname — the latter would
        // accept any valid certificate for any name.
        let hostname = ssl
            .servername(NameType::HOST_NAME)
            .ok_or(SslVerifyError::Invalid(SslAlert::HANDSHAKE_FAILURE))?;
        let policy = SecPolicy::create_ssl(SslProtocolSide::SERVER, Some(hostname));

        let mut trust = SecTrust::create_with_certificates(&certs, &[policy])
            .map_err(|_| SslVerifyError::Invalid(SslAlert::INTERNAL_ERROR))?;

        if !custom_roots_der.is_empty() {
            let mut anchors = Vec::with_capacity(custom_roots_der.len());
            for der in &custom_roots_der {
                anchors.push(
                    SecCertificate::from_der(der)
                        .map_err(|_| SslVerifyError::Invalid(SslAlert::INTERNAL_ERROR))?,
                );
            }
            trust
                .set_anchor_certificates(&anchors)
                .map_err(|_| SslVerifyError::Invalid(SslAlert::INTERNAL_ERROR))?;
            // Additive, not replacing: without this the custom roots would
            // become the *only* anchors and every ordinary public site would
            // stop validating the moment a caller set one custom root.
            trust
                .set_trust_anchor_certificates_only(false)
                .map_err(|_| SslVerifyError::Invalid(SslAlert::INTERNAL_ERROR))?;
        }

        trust
            .evaluate_with_error()
            .map_err(|_| SslVerifyError::Invalid(SslAlert::CERTIFICATE_UNKNOWN))
    });
}
