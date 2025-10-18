uniffi::setup_scaffolding!();

use std::collections::HashMap;
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use reqwest::{
    Method,
    blocking::{Client, Response},
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
}

impl VaneClient {
    pub fn new(config: VaneClientConfig) -> Result<Self, VaneError> {
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

        Ok(Self { client, config })
    }

    pub fn execute(&self, request: VaneRequest) -> Result<VaneResponse, VaneError> {
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

        let response = req_builder.send()?;
        self.convert_response(response)
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

    fn convert_response(&self, resp: Response) -> Result<VaneResponse, VaneError> {
        let status = resp.status().as_u16();
        let ok = resp.status().is_success();
        let url = resp.url().to_string();

        let mut headers = HashMap::with_capacity(resp.headers().len());
        for (k, v) in resp.headers() {
            headers.insert(k.to_string(), v.to_str().unwrap_or_default().to_string());
        }

        let mut reader = resp;
        let mut body = Vec::new();
        reader
            .read_to_end(&mut body)
            .map_err(|e| VaneError::Generic(format!("Read body failed: {e}")))?;

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

#[uniffi::export]
pub fn response_body_utf8(resp: &VaneResponse) -> Result<String, VaneError> {
    String::from_utf8(resp.body.clone())
        .map_err(|e| VaneError::Generic(format!("Invalid UTF-8 in response body: {e}")))
}
