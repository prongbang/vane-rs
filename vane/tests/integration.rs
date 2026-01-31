use std::net::TcpListener;
use std::sync::Arc;
use std::time::Instant;

use httpmock::Method::GET;
use httpmock::MockServer;
use vane::{VaneBytes, VaneClient, VaneClientConfig, VaneError, VaneRequest};

fn vb(data: Vec<u8>) -> VaneBytes {
    VaneBytes::try_from(data).expect("VaneBytes")
}

#[tokio::test]
async fn dns_failure_returns_connection_or_timeout() {
    let client = VaneClient::new(VaneClientConfig::default()).expect("client build");
    let err = client
        .execute_request(VaneRequest {
            url: "http://nonexistent.invalid".to_string(),
            method: "GET".to_string(),
            headers: Default::default(),
            query_params: Default::default(),
            body: None,
            timeout_seconds: Some(2),
            follow_redirects: true,
        })
        .await
        .err()
        .expect("dns error");

    match err {
        VaneError::Connection(_) | VaneError::Timeout(_) => {}
        _ => panic!("expected Connection/Timeout for DNS failure"),
    }
}

#[tokio::test]
async fn connection_refused_returns_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);

    let client = VaneClient::new(VaneClientConfig::default()).expect("client build");
    let err = client
        .execute_request(VaneRequest {
            url: format!("http://127.0.0.1:{port}/refused"),
            method: "GET".to_string(),
            headers: Default::default(),
            query_params: Default::default(),
            body: None,
            timeout_seconds: Some(2),
            follow_redirects: true,
        })
        .await
        .err()
        .expect("connection refused");

    match err {
        VaneError::Connection(_) => {}
        _ => panic!("expected Connection for refused"),
    }
}

#[tokio::test]
async fn tls_error_returns_tls() {
    let server = MockServer::start();
    let https_base = server.base_url().replacen("http://", "https://", 1);

    let client = VaneClient::new(VaneClientConfig::default()).expect("client build");
    let err = client
        .execute_request(VaneRequest {
            url: format!("{https_base}/tls"),
            method: "GET".to_string(),
            headers: Default::default(),
            query_params: Default::default(),
            body: None,
            timeout_seconds: Some(2),
            follow_redirects: true,
        })
        .await
        .err()
        .expect("tls error");

    match err {
        VaneError::Tls(_) => {}
        _ => panic!("expected Tls error"),
    }
}

#[tokio::test]
async fn large_payload_request_and_response() {
    let server = MockServer::start();

    let upload_mock = server.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/upload")
            .header("content-length", "2097152");
        then.status(200).body("ok");
    });

    let large_response = vec![b'a'; 2 * 1024 * 1024];
    let download_mock = server.mock(|when, then| {
        when.method(GET).path("/large");
        then.status(200).body(large_response.clone());
    });

    let client = VaneClient::new(VaneClientConfig {
        base_url: Some(server.base_url()),
        ..VaneClientConfig::default()
    })
    .expect("client build");

    let upload = client
        .execute_request(VaneRequest {
            url: "/upload".to_string(),
            method: "POST".to_string(),
            headers: Default::default(),
            query_params: Default::default(),
            body: Some(vb(vec![b'b'; 2 * 1024 * 1024])),
            timeout_seconds: Some(5),
            follow_redirects: true,
        })
        .await
        .expect("upload");

    let download = client
        .get_request("/large".to_string())
        .await
        .expect("download");

    upload_mock.assert();
    download_mock.assert();
    assert_eq!(upload.status_code, 200);
    assert_eq!(download.body.as_ref().len(), large_response.len());
}

#[tokio::test]
#[ignore]
async fn load_soak_smoke() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/ping");
        then.status(200).body("ok");
    });

    let client = Arc::new(
        VaneClient::new(VaneClientConfig {
            base_url: Some(server.base_url()),
            ..VaneClientConfig::default()
        })
        .expect("client build"),
    );

    let start = Instant::now();
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..500 {
        let client = Arc::clone(&client);
        set.spawn(async move { client.get_request("/ping".to_string()).await });
    }

    let mut ok = 0usize;
    while let Some(res) = set.join_next().await {
        let resp = res.expect("task");
        if resp.is_ok() {
            ok += 1;
        }
    }

    let elapsed = start.elapsed();
    eprintln!("load_soak_smoke: {ok} requests in {:?}", elapsed);
    assert_eq!(ok, 500);
}
