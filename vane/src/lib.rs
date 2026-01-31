uniffi::setup_scaffolding!();

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use std::error::Error;

use bytes::Bytes;
use reqwest::{Client, Method, Response, redirect::Policy};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use url::Url;

// ---------- Models ----------
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct VaneRequest {
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub query_params: HashMap<String, String>,
    pub body: Option<VaneBytes>,
    pub timeout_seconds: Option<u64>,
    pub follow_redirects: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct VaneResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: VaneBytes,
    pub is_success: bool,
    pub url: String,
}

#[derive(Debug, Clone)]
pub struct VaneBytes(Bytes);

impl VaneBytes {
    fn into_bytes(self) -> Bytes {
        self.0
    }

    #[cfg(test)]
    fn from_vec(vec: Vec<u8>) -> Self {
        Self(Bytes::from(vec))
    }
}

impl AsRef<[u8]> for VaneBytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<Bytes> for VaneBytes {
    fn from(bytes: Bytes) -> Self {
        Self(bytes)
    }
}

impl TryFrom<Vec<u8>> for VaneBytes {
    type Error = uniffi::deps::anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self(Bytes::from(value)))
    }
}

impl From<VaneBytes> for Vec<u8> {
    fn from(value: VaneBytes) -> Self {
        value.0.to_vec()
    }
}

impl Serialize for VaneBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(self.as_ref())
    }
}

impl<'de> Deserialize<'de> for VaneBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Ok(VaneBytes::from(Bytes::from(bytes)))
    }
}

uniffi::custom_type!(VaneBytes, Vec<u8>);

#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct VaneClientConfig {
    pub base_url: Option<String>,
    pub default_headers: HashMap<String, String>,
    pub timeout_seconds: Option<u64>,
    pub follow_redirects: bool,
    pub user_agent: Option<String>,
}

#[derive(uniffi::Object)]
pub struct VanePreparedRequest {
    method: Method,
    url: Url,
    headers: HashMap<String, String>,
    timeout_seconds: Option<u64>,
    body: Option<VaneBytes>,
    follow_redirects: bool,
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
    Timeout(String),
    #[error("{0}")]
    Connection(String),
    #[error("{0}")]
    Decode(String),
    #[error("{0}")]
    Tls(String),
    #[error("{0}")]
    Http(String),
    #[error("{0}")]
    InvalidUrl(String),
    #[error("{0}")]
    InvalidMethod(String),
    #[error("{0}")]
    Utf8(String),
    #[error("{0}")]
    Other(String),
}

impl From<reqwest::Error> for VaneError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_timeout() {
            return VaneError::Timeout(err.to_string());
        }
        if err.is_connect() {
            return VaneError::Connection(err.to_string());
        }
        if err.is_decode() {
            return VaneError::Decode(err.to_string());
        }
        if err.is_builder() {
            return VaneError::Other(err.to_string());
        }
        if err.is_request() {
            return VaneError::Http(err.to_string());
        }
        if let Some(source) = err.source() {
            let msg = source.to_string().to_lowercase();
            if msg.contains("tls") || msg.contains("ssl") || msg.contains("certificate") {
                return VaneError::Tls(err.to_string());
            }
        }
        VaneError::Other(err.to_string())
    }
}

// ---------- Client ----------
#[derive(uniffi::Object)]
pub struct VaneClient {
    client_follow: Client,
    client_no_follow: Client,
    config: VaneClientConfig,
}

impl VaneClient {
    pub fn new(config: VaneClientConfig) -> Result<Self, VaneError> {
        let client_follow = Self::build_client(&config, true)?;
        let client_no_follow = Self::build_client(&config, false)?;

        Ok(Self {
            client_follow,
            client_no_follow,
            config,
        })
    }

    fn build_client(config: &VaneClientConfig, follow_redirects: bool) -> Result<Client, VaneError> {
        Client::builder()
            // Connection & Pool
            .pool_idle_timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(16)
            // Timeout & UA
            .timeout(Duration::from_secs(config.timeout_seconds.unwrap_or(30)))
            .user_agent(
                config
                    .user_agent
                    .clone()
                    .unwrap_or_else(|| "Vane/1.1".into()),
            )
            // Redirect
            .redirect(if follow_redirects {
                Policy::limited(10)
            } else {
                Policy::none()
            })
            .build()
            .map_err(|e| VaneError::Other(format!("Failed to create client: {e}")))
    }

    fn prepare_request_inner(&self, request: VaneRequest) -> Result<VanePreparedRequest, VaneError> {
        let mut url = self.build_url(&request.url)?;
        if !request.query_params.is_empty() {
            let mut pairs = url.query_pairs_mut();
            for (k, v) in &request.query_params {
                pairs.append_pair(k, v);
            }
        }

        let method = Method::from_bytes(request.method.as_bytes())
            .map_err(|_| VaneError::InvalidMethod(format!("Invalid method: {}", request.method)))?;

        Ok(VanePreparedRequest {
            method,
            url,
            headers: request.headers,
            timeout_seconds: request.timeout_seconds,
            body: request.body,
            follow_redirects: request.follow_redirects,
        })
    }

    async fn execute(&self, request: VaneRequest) -> Result<VaneResponse, VaneError> {
        let prepared = self.prepare_request_inner(request)?;
        self.execute_prepared_inner(&prepared).await
    }

    async fn execute_prepared_inner(
        &self,
        prepared: &VanePreparedRequest,
    ) -> Result<VaneResponse, VaneError> {
        let client = if prepared.follow_redirects {
            &self.client_follow
        } else {
            &self.client_no_follow
        };

        let mut req_builder = client.request(prepared.method.clone(), prepared.url.clone());

        // headers
        for (k, v) in &self.config.default_headers {
            req_builder = req_builder.header(k, v);
        }
        for (k, v) in &prepared.headers {
            req_builder = req_builder.header(k, v);
        }

        // body
        if let Some(b) = prepared.body.clone() {
            req_builder = req_builder.body(b.into_bytes());
        }

        // timeout override
        if let Some(t) = prepared.timeout_seconds {
            req_builder = req_builder.timeout(Duration::from_secs(t));
        }

        let response = req_builder.send().await?;
        self.convert_response(response).await
    }

    fn build_url(&self, url: &str) -> Result<Url, VaneError> {
        if let Some(base) = &self.config.base_url {
            let base_url = Url::parse(base)
                .map_err(|e| VaneError::InvalidUrl(format!("Invalid base URL: {e}")))?;
            base_url
                .join(url)
                .map_err(|e| VaneError::InvalidUrl(format!("Failed to join URL: {e}")))
        } else {
            Url::parse(url).map_err(|e| VaneError::InvalidUrl(format!("Invalid URL: {e}")))
        }
    }

    async fn convert_response(&self, resp: Response) -> Result<VaneResponse, VaneError> {
        let status = resp.status().as_u16();
        let ok = resp.status().is_success();
        let url = resp.url().to_string();

        let mut headers = HashMap::with_capacity(resp.headers().len());
        for (k, v) in resp.headers() {
            headers.insert(k.to_string(), v.to_str().unwrap_or_default().to_string());
        }

        let body = VaneBytes::from(resp.bytes().await?);

        Ok(VaneResponse {
            status_code: status,
            headers,
            body,
            is_success: ok,
            url,
        })
    }

    async fn make_request(
        &self,
        method: &str,
        url: &str,
        body: Option<VaneBytes>,
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
        .await
    }
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
    pub fn prepare_request(
        &self,
        request: VaneRequest,
    ) -> Result<Arc<VanePreparedRequest>, VaneError> {
        Ok(Arc::new(self.prepare_request_inner(request)?))
    }

    pub async fn execute_request(
        &self,
        request: VaneRequest,
    ) -> Result<VaneResponse, VaneError> {
        self.execute(request).await
    }

    pub async fn execute_prepared(
        &self,
        request: Arc<VanePreparedRequest>,
    ) -> Result<VaneResponse, VaneError> {
        self.execute_prepared_inner(&request).await
    }

    pub async fn get_request(&self, url: String) -> Result<VaneResponse, VaneError> {
        self.make_request("GET", &url, None).await
    }

    pub async fn post_request(
        &self,
        url: String,
        body: Option<VaneBytes>,
    ) -> Result<VaneResponse, VaneError> {
        self.make_request("POST", &url, body).await
    }

    pub async fn put_request(
        &self,
        url: String,
        body: Option<VaneBytes>,
    ) -> Result<VaneResponse, VaneError> {
        self.make_request("PUT", &url, body).await
    }

    pub async fn delete_request(&self, url: String) -> Result<VaneResponse, VaneError> {
        self.make_request("DELETE", &url, None).await
    }

    pub async fn patch_request(
        &self,
        url: String,
        body: Option<VaneBytes>,
    ) -> Result<VaneResponse, VaneError> {
        self.make_request("PATCH", &url, body).await
    }
}

// ---------- Helpers ----------
#[uniffi::export]
pub fn parse_json_response(resp: &VaneResponse) -> Result<String, VaneError> {
    let parsed: Value = serde_json::from_slice(resp.body.as_ref())
        .map_err(|e| VaneError::Decode(format!("Parse JSON failed: {e}")))?;
    serde_json::to_string_pretty(&parsed)
        .map_err(|e| VaneError::Decode(format!("Serialize JSON failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::{Method::DELETE, Method::GET, Method::PATCH, Method::POST, Method::PUT};
    use httpmock::MockServer;

    fn client_with_base(server: &MockServer) -> VaneClient {
        let mut config = VaneClientConfig::default();
        config.base_url = Some(server.base_url());
        VaneClient::new(config).expect("client build")
    }

    fn client_with_base_and_headers(server: &MockServer) -> VaneClient {
        let mut config = VaneClientConfig::default();
        config.base_url = Some(server.base_url());
        config.default_headers.insert("x-default".to_string(), "yes".to_string());
        VaneClient::new(config).expect("client build")
    }

    fn bytes(data: &[u8]) -> VaneBytes {
        VaneBytes::from_vec(data.to_vec())
    }

    #[tokio::test]
    async fn execute_request_sends_headers_query_and_body() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(POST)
                .path("/exec")
                .header("x-req", "1")
                .query_param("q", "v")
                .body("hello");
            then.status(201)
                .header("x-resp", "ok")
                .body("world");
        });

        let client = client_with_base(&server);
        let mut headers = HashMap::new();
        headers.insert("x-req".to_string(), "1".to_string());
        let mut query_params = HashMap::new();
        query_params.insert("q".to_string(), "v".to_string());

        let resp = client
            .execute_request(VaneRequest {
                url: "/exec".to_string(),
                method: "POST".to_string(),
                headers,
                query_params,
                body: Some(bytes(b"hello")),
                timeout_seconds: None,
                follow_redirects: true,
            })
            .await
            .expect("execute_request");

        mock.assert();
        assert_eq!(resp.status_code, 201);
        assert_eq!(resp.body.as_ref(), b"world");
        assert_eq!(resp.headers.get("x-resp").map(String::as_str), Some("ok"));
        assert!(resp.is_success);
        assert!(resp.url.contains("/exec"));
    }

    #[tokio::test]
    async fn execute_prepared_request_works() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(POST)
                .path("/prep")
                .query_param("q", "1")
                .header("x-req", "p")
                .body("data");
            then.status(200).body("ok");
        });

        let client = client_with_base(&server);
        let mut headers = HashMap::new();
        headers.insert("x-req".to_string(), "p".to_string());
        let mut query_params = HashMap::new();
        query_params.insert("q".to_string(), "1".to_string());

        let prepared = client
            .prepare_request(VaneRequest {
                url: "/prep".to_string(),
                method: "POST".to_string(),
                headers,
                query_params,
                body: Some(bytes(b"data")),
                timeout_seconds: None,
                follow_redirects: true,
            })
            .expect("prepare_request");

        let resp = client
            .execute_prepared(prepared)
            .await
            .expect("execute_prepared");

        mock.assert();
        assert_eq!(resp.body.as_ref(), b"ok");
    }

    #[tokio::test]
    async fn content_types_are_sent_as_requested() {
        let server = MockServer::start();
        let client = client_with_base(&server);

        let cases: Vec<(&str, &str, Vec<u8>)> = vec![
            ("/ct-json", "application/json", br#"{"a":1}"#.to_vec()),
            ("/ct-bin", "application/octet-stream", b"BIN".to_vec()),
            ("/ct-text", "text/plain", b"hello".to_vec()),
            ("/ct-form", "application/x-www-form-urlencoded", b"a=1&b=2".to_vec()),
            (
                "/ct-multipart",
                "multipart/form-data; boundary=----vane",
                b"------vane\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nv\r\n------vane--\r\n"
                    .to_vec(),
            ),
            ("/ct-html", "text/html", b"<p>hi</p>".to_vec()),
            ("/ct-xml", "application/xml", b"<a>1</a>".to_vec()),
        ];

        for (path, content_type, body) in cases {
            let mock = server.mock(|when, then| {
                when.method(POST)
                    .path(path)
                    .header("content-type", content_type)
                    .body(String::from_utf8(body.clone()).expect("utf8 body"));
                then.status(200).body("ok");
            });

            let mut headers = HashMap::new();
            headers.insert("content-type".to_string(), content_type.to_string());

            let resp = client
                .execute_request(VaneRequest {
                    url: path.to_string(),
                    method: "POST".to_string(),
                    headers,
                query_params: HashMap::new(),
                body: Some(bytes(&body)),
                timeout_seconds: None,
                follow_redirects: true,
            })
                .await
                .expect("execute_request");

            mock.assert();
            assert_eq!(resp.status_code, 200);
        }
    }

    #[tokio::test]
    async fn request_level_follow_redirects_overrides_default() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/redir");
            then.status(302).header("Location", "/final");
        });
        let final_mock = server.mock(|when, then| {
            when.method(GET).path("/final");
            then.status(200).body("final");
        });

        let mut config = VaneClientConfig::default();
        config.base_url = Some(server.base_url());
        config.follow_redirects = true;
        let client = VaneClient::new(config).expect("client build");

        let resp = client
            .execute_request(VaneRequest {
                url: "/redir".to_string(),
                method: "GET".to_string(),
                headers: HashMap::new(),
                query_params: HashMap::new(),
                body: None,
                timeout_seconds: None,
                follow_redirects: false,
            })
            .await
            .expect("execute_request");

        assert_eq!(resp.status_code, 302);
        assert!(resp.url.contains("/redir"));
        assert_eq!(final_mock.hits(), 0);
    }

    #[tokio::test]
    async fn timeout_returns_error() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/slow");
            then.status(200)
                .delay(Duration::from_millis(1500))
                .body("ok");
        });

        let mut config = VaneClientConfig::default();
        config.base_url = Some(server.base_url());
        let client = VaneClient::new(config).expect("client build");

        let err = client
            .execute_request(VaneRequest {
                url: "/slow".to_string(),
                method: "GET".to_string(),
                headers: HashMap::new(),
                query_params: HashMap::new(),
                body: None,
                timeout_seconds: Some(1),
                follow_redirects: true,
            })
            .await
            .err()
            .expect("timeout error");

        match err {
            VaneError::Timeout(_) => {}
            _ => panic!("expected Timeout"),
        }
    }

    #[test]
    fn response_body_utf8_fails_on_invalid_utf8() {
        let resp = VaneResponse {
            status_code: 200,
            headers: HashMap::new(),
            body: bytes(&[0xff, 0xfe]),
            is_success: true,
            url: "http://example.com".to_string(),
        };

        let err = response_body_utf8(&resp).err().expect("utf8 error");
        match err {
            VaneError::Utf8(msg) => assert!(msg.contains("Invalid UTF-8")),
            _ => panic!("expected Utf8"),
        }
    }

    #[tokio::test]
    async fn get_request_works() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/get");
            then.status(200).body("ok");
        });

        let client = client_with_base(&server);
        let resp = client
            .get_request("/get".to_string())
            .await
            .expect("get_request");

        mock.assert();
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.body.as_ref(), b"ok");
        assert!(resp.is_success);
    }

    #[tokio::test]
    async fn post_request_works() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(POST).path("/post").body("ping");
            then.status(200).body("pong");
        });

        let client = client_with_base(&server);
        let resp = client
            .post_request("/post".to_string(), Some(bytes(b"ping")))
            .await
            .expect("post_request");

        mock.assert();
        assert_eq!(resp.body.as_ref(), b"pong");
    }

    #[tokio::test]
    async fn put_request_works() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(PUT).path("/put").body("data");
            then.status(204);
        });

        let client = client_with_base(&server);
        let resp = client
            .put_request("/put".to_string(), Some(bytes(b"data")))
            .await
            .expect("put_request");

        mock.assert();
        assert_eq!(resp.status_code, 204);
    }

    #[tokio::test]
    async fn delete_request_works() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(DELETE).path("/delete");
            then.status(202);
        });

        let client = client_with_base(&server);
        let resp = client
            .delete_request("/delete".to_string())
            .await
            .expect("delete_request");

        mock.assert();
        assert_eq!(resp.status_code, 202);
    }

    #[tokio::test]
    async fn patch_request_works() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(PATCH).path("/patch").body("p");
            then.status(200).body("patched");
        });

        let client = client_with_base(&server);
        let resp = client
            .patch_request("/patch".to_string(), Some(bytes(b"p")))
            .await
            .expect("patch_request");

        mock.assert();
        assert_eq!(resp.body.as_ref(), b"patched");
    }

    #[tokio::test]
    async fn default_headers_applied() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/hdr").header("x-default", "yes");
            then.status(200).body("ok");
        });

        let client = client_with_base_and_headers(&server);
        let resp = client
            .get_request("/hdr".to_string())
            .await
            .expect("get_request");

        mock.assert();
        assert_eq!(resp.status_code, 200);
    }

    #[tokio::test]
    async fn invalid_method_returns_error() {
        let server = MockServer::start();
        let client = client_with_base(&server);
        let err = client
            .execute_request(VaneRequest {
                url: "/x".to_string(),
                method: "BAD METHOD".to_string(),
                headers: HashMap::new(),
                query_params: HashMap::new(),
                body: None,
                timeout_seconds: None,
                follow_redirects: true,
            })
            .await
            .err()
            .expect("invalid method error");

        match err {
            VaneError::InvalidMethod(msg) => assert!(msg.contains("Invalid method")),
            _ => panic!("expected InvalidMethod"),
        }
    }

    #[tokio::test]
    async fn invalid_url_returns_error() {
        let client = VaneClient::new(VaneClientConfig::default()).expect("client build");
        let err = client
            .get_request("://invalid".to_string())
            .await
            .err()
            .expect("invalid url error");

        match err {
            VaneError::InvalidUrl(msg) => assert!(msg.contains("Invalid URL")),
            _ => panic!("expected InvalidUrl"),
        }
    }

    #[tokio::test]
    async fn redirect_not_followed_when_disabled() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/redir");
            then.status(302)
                .header("Location", "/final");
        });
        let final_mock = server.mock(|when, then| {
            when.method(GET).path("/final");
            then.status(200).body("final");
        });

        let mut config = VaneClientConfig::default();
        config.base_url = Some(server.base_url());
        config.follow_redirects = false;
        let client = VaneClient::new(config).expect("client build");

        let resp = client
            .get_request("/redir".to_string())
            .await
            .expect("get_request");

        assert_eq!(resp.status_code, 302);
        assert!(resp.url.contains("/redir"));
        assert_eq!(final_mock.hits(), 0);
    }

    #[tokio::test]
    async fn redirect_followed_when_enabled() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/redir");
            then.status(302)
                .header("Location", "/final");
        });
        let final_mock = server.mock(|when, then| {
            when.method(GET).path("/final");
            then.status(200).body("final");
        });

        let client = client_with_base(&server);
        let resp = client
            .get_request("/redir".to_string())
            .await
            .expect("get_request");

        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.body.as_ref(), b"final");
        assert!(resp.url.contains("/final"));
        assert_eq!(final_mock.hits(), 1);
    }

    #[test]
    fn parse_json_response_works() {
        let resp = VaneResponse {
            status_code: 200,
            headers: HashMap::new(),
            body: bytes(br#"{"a":1}"#),
            is_success: true,
            url: "http://example.com".to_string(),
        };

        let out = parse_json_response(&resp).expect("parse_json_response");
        assert!(out.contains("\"a\": 1"));
    }

    #[test]
    fn parse_json_response_fails_on_invalid_json() {
        let resp = VaneResponse {
            status_code: 200,
            headers: HashMap::new(),
            body: bytes(b"not-json"),
            is_success: true,
            url: "http://example.com".to_string(),
        };

        let err = parse_json_response(&resp).err().expect("parse_json_response error");
        match err {
            VaneError::Decode(msg) => assert!(msg.contains("Parse JSON failed")),
            _ => panic!("expected Decode"),
        }
    }
}

#[uniffi::export]
pub fn response_body_utf8(resp: &VaneResponse) -> Result<String, VaneError> {
    String::from_utf8(Vec::<u8>::from(resp.body.clone()))
        .map_err(|e| VaneError::Utf8(format!("Invalid UTF-8 in response body: {e}")))
}
