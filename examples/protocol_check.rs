//! Live check that the TCP fallback negotiates the protocol it claims to.
//!
//! ALPN silently regressed once (the TLS config is handed to reqwest through
//! `use_preconfigured_tls`, which does not fill in `alpn_protocols`), and no
//! unit test can catch it: every mode still returns 200 over HTTP/1.1. This
//! asserts against a server that echoes the negotiated protocol in its body.
//!
//!     VANE_TEST_BASE_URL=https://cloudflare-quic.com \
//!         cargo run --release --example protocol_check

fn get(base_url: &str, mode: vane::VaneProtocolMode) -> Result<String, String> {
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
    Ok(String::from_utf8_lossy(&response.body).into_owned())
}

fn main() {
    let Ok(base_url) = std::env::var("VANE_TEST_BASE_URL") else {
        println!("protocol_check: skipped (VANE_TEST_BASE_URL not set)");
        return;
    };

    let http1 = get(&base_url, vane::VaneProtocolMode::Http1Only).expect("Http1Only");
    let http2 = get(&base_url, vane::VaneProtocolMode::Http2Only).expect("Http2Only");
    let alpn = get(&base_url, vane::VaneProtocolMode::Http2ThenHttp1).expect("Http2ThenHttp1");

    // The echo server must actually distinguish the two, or this proves nothing.
    assert_ne!(
        http1, http2,
        "endpoint does not echo the negotiated protocol; pick one that does"
    );
    assert_eq!(
        alpn, http2,
        "Http2ThenHttp1 negotiated HTTP/1.1, not h2 — ALPN is not being offered"
    );

    println!("protocol_check: ok (Http2ThenHttp1 negotiates h2 via ALPN)");
}
