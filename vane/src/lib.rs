uniffi::setup_scaffolding!();

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use reqwest::{
    Client,
    Method,
    Response,
    redirect::Policy,
};
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
    pub body: Option<Vec<u8>>,
    pub timeout_seconds: Option<u64>,
    pub follow_redirects: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct VaneResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub is_success: bool,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct VaneClientConfig {
    pub base_url: Option<String>,
    pub default_headers: HashMap<String, String>,
    pub timeout_seconds: Option<u64>,
    pub follow_redirects: bool,
    pub user_agent: Option<String>,
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
    Generic(String),
}

impl From<reqwest::Error> for VaneError {
    fn from(err: reqwest::Error) -> Self {
        let kind = if err.is_timeout() {
            "Timeout"
        } else if err.is_connect() {
            "Connection"
        } else if err.is_decode() {
            "Decode"
        } else {
            "Request"
        };
        VaneError::Generic(format!("{kind} error: {err}"))
    }
}

// ---------- Client ----------
#[derive(uniffi::Object)]
pub struct VaneClient {
    client: Client,
    config: VaneClientConfig,
    runtime: tokio::runtime::Runtime,
}

impl VaneClient {
    pub fn new(config: VaneClientConfig) -> Result<Self, VaneError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| VaneError::Generic(format!("Failed to create runtime: {e}")))?;

        let client = Client::builder()
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
            .redirect(if config.follow_redirects {
                Policy::limited(10)
            } else {
                Policy::none()
            })
            .build()
            .map_err(|e| VaneError::Generic(format!("Failed to create client: {e}")))?;

        Ok(Self {
            client,
            config,
            runtime,
        })
    }

    pub fn execute(&self, request: VaneRequest) -> Result<VaneResponse, VaneError> {
        self.runtime.block_on(self.execute_async(request))
    }

    async fn execute_async(&self, request: VaneRequest) -> Result<VaneResponse, VaneError> {
        let url = self.build_url(&request.url)?;
        let method = Method::from_bytes(request.method.as_bytes())
            .map_err(|_| VaneError::Generic(format!("Invalid method: {}", request.method)))?;

        let mut req_builder = self.client.request(method, url.clone());

        // headers
        for (k, v) in &self.config.default_headers {
            req_builder = req_builder.header(k, v);
        }
        for (k, v) in &request.headers {
            req_builder = req_builder.header(k, v);
        }

        // query
        if !request.query_params.is_empty() {
            req_builder = req_builder.query(&request.query_params);
        }

        // body
        if let Some(b) = &request.body {
            req_builder = req_builder.body(b.clone());
        }

        // timeout override
        if let Some(t) = request.timeout_seconds {
            req_builder = req_builder.timeout(Duration::from_secs(t));
        }

        let response = req_builder.send().await?;
        self.convert_response(response).await
    }

    fn build_url(&self, url: &str) -> Result<Url, VaneError> {
        if let Some(base) = &self.config.base_url {
            let base_url = Url::parse(base)
                .map_err(|e| VaneError::Generic(format!("Invalid base URL: {e}")))?;
            base_url
                .join(url)
                .map_err(|e| VaneError::Generic(format!("Failed to join URL: {e}")))
        } else {
            Url::parse(url).map_err(|e| VaneError::Generic(format!("Invalid URL: {e}")))
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

        let body = resp.bytes().await?.to_vec();

        Ok(VaneResponse {
            status_code: status,
            headers,
            body,
            is_success: ok,
            url,
        })
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
pub fn parse_json_response(resp: &VaneResponse) -> Result<String, VaneError> {
    let parsed: Value = serde_json::from_slice(&resp.body)
        .map_err(|e| VaneError::Generic(format!("Parse JSON failed: {e}")))?;
    serde_json::to_string_pretty(&parsed)
        .map_err(|e| VaneError::Generic(format!("Serialize JSON failed: {e}")))
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

    #[test]
    fn execute_request_sends_headers_query_and_body() {
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
                body: Some(b"hello".to_vec()),
                timeout_seconds: None,
                follow_redirects: true,
            })
            .expect("execute_request");

        mock.assert();
        assert_eq!(resp.status_code, 201);
        assert_eq!(resp.body, b"world");
        assert_eq!(resp.headers.get("x-resp").map(String::as_str), Some("ok"));
        assert!(resp.is_success);
        assert!(resp.url.contains("/exec"));
    }

    #[test]
    fn get_request_works() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/get");
            then.status(200).body("ok");
        });

        let client = client_with_base(&server);
        let resp = client.get_request("/get".to_string()).expect("get_request");

        mock.assert();
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.body, b"ok");
        assert!(resp.is_success);
    }

    #[test]
    fn post_request_works() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(POST).path("/post").body("ping");
            then.status(200).body("pong");
        });

        let client = client_with_base(&server);
        let resp = client
            .post_request("/post".to_string(), Some(b"ping".to_vec()))
            .expect("post_request");

        mock.assert();
        assert_eq!(resp.body, b"pong");
    }

    #[test]
    fn put_request_works() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(PUT).path("/put").body("data");
            then.status(204);
        });

        let client = client_with_base(&server);
        let resp = client
            .put_request("/put".to_string(), Some(b"data".to_vec()))
            .expect("put_request");

        mock.assert();
        assert_eq!(resp.status_code, 204);
    }

    #[test]
    fn delete_request_works() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(DELETE).path("/delete");
            then.status(202);
        });

        let client = client_with_base(&server);
        let resp = client
            .delete_request("/delete".to_string())
            .expect("delete_request");

        mock.assert();
        assert_eq!(resp.status_code, 202);
    }

    #[test]
    fn patch_request_works() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(PATCH).path("/patch").body("p");
            then.status(200).body("patched");
        });

        let client = client_with_base(&server);
        let resp = client
            .patch_request("/patch".to_string(), Some(b"p".to_vec()))
            .expect("patch_request");

        mock.assert();
        assert_eq!(resp.body, b"patched");
    }

    #[test]
    fn default_headers_applied() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/hdr").header("x-default", "yes");
            then.status(200).body("ok");
        });

        let client = client_with_base_and_headers(&server);
        let resp = client.get_request("/hdr".to_string()).expect("get_request");

        mock.assert();
        assert_eq!(resp.status_code, 200);
    }

    #[test]
    fn invalid_method_returns_error() {
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
            .err()
            .expect("invalid method error");

        match err {
            VaneError::Generic(msg) => assert!(msg.contains("Invalid method")),
        }
    }

    #[test]
    fn invalid_url_returns_error() {
        let client = VaneClient::new(VaneClientConfig::default()).expect("client build");
        let err = client
            .get_request("://invalid".to_string())
            .err()
            .expect("invalid url error");

        match err {
            VaneError::Generic(msg) => assert!(msg.contains("Invalid URL")),
        }
    }

    #[test]
    fn redirect_not_followed_when_disabled() {
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

        let resp = client.get_request("/redir".to_string()).expect("get_request");

        assert_eq!(resp.status_code, 302);
        assert!(resp.url.contains("/redir"));
        assert_eq!(final_mock.hits(), 0);
    }

    #[test]
    fn redirect_followed_when_enabled() {
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
        let resp = client.get_request("/redir".to_string()).expect("get_request");

        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.body, b"final");
        assert!(resp.url.contains("/final"));
        assert_eq!(final_mock.hits(), 1);
    }

    #[test]
    fn parse_json_response_works() {
        let resp = VaneResponse {
            status_code: 200,
            headers: HashMap::new(),
            body: br#"{"a":1}"#.to_vec(),
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
            body: b"not-json".to_vec(),
            is_success: true,
            url: "http://example.com".to_string(),
        };

        let err = parse_json_response(&resp).err().expect("parse_json_response error");
        match err {
            VaneError::Generic(msg) => assert!(msg.contains("Parse JSON failed")),
        }
    }
}

#[uniffi::export]
pub fn response_body_utf8(resp: &VaneResponse) -> Result<String, VaneError> {
    String::from_utf8(resp.body.clone())
        .map_err(|e| VaneError::Generic(format!("Invalid UTF-8 in response body: {e}")))
}
