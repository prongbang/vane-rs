//! Live check that the TCP fallback negotiates the protocol it claims to.
//!
//! ALPN silently regressed once (the TLS config is handed to reqwest through
//! `use_preconfigured_tls`, which does not fill in `alpn_protocols`), and no
//! unit test can catch it: every mode still returns 200 over HTTP/1.1. This
//! reads `VaneResponse::http_version`, so the server no longer has to echo its
//! protocol in the page — but it must still speak h2 AND h3, because the loop
//! also asserts the `Http3Only` mode (otherwise nothing exercises the h3
//! constant at all). Use cloudflare-quic.com; an h2-only endpoint fails the
//! last iteration for a reason that has nothing to do with ALPN.
//!
//!     VANE_TEST_BASE_URL=https://cloudflare-quic.com \
//!         cargo run --release --example protocol_check

fn get(
    base_url: &str,
    mode: vane::VaneProtocolMode,
) -> Result<Option<vane::VaneHttpVersion>, String> {
    let client = vane::VaneClient::new(vane::VaneClientConfig {
        base_url: Some(base_url.to_string()),
        protocol_mode: mode,
        timeout_seconds: Some(20),
        ..vane::VaneClientConfig::default()
    })
    .map_err(|e| e.to_string())?;

    let response = client
        .get_request("/".to_string())
        .map_err(|e| e.to_string())?;
    if !response.is_success {
        return Err(format!("status {}", response.status_code));
    }
    Ok(response.http_version)
}

fn main() {
    let Ok(base_url) = std::env::var("VANE_TEST_BASE_URL") else {
        println!("protocol_check: skipped (VANE_TEST_BASE_URL not set)");
        return;
    };

    use vane::VaneHttpVersion::{Http2, Http3, Http11};
    use vane::VaneProtocolMode::{Http1Only, Http2Only, Http2ThenHttp1, Http3Only};

    for (mode, expected) in [
        (Http1Only, Http11),
        (Http2Only, Http2),
        // The regression this example exists for: with ALPN unset the TLS
        // handshake offers nothing, and the server answers HTTP/1.1.
        (Http2ThenHttp1, Http2),
        (Http3Only, Http3),
    ] {
        let actual = get(&base_url, mode.clone()).unwrap_or_else(|e| panic!("{mode:?}: {e}"));
        assert_eq!(
            actual,
            Some(expected),
            "{mode:?} negotiated the wrong protocol"
        );
        println!("protocol_check: {mode:?} -> {expected:?}");
    }

    println!("protocol_check: ok");
}
