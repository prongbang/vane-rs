use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use reqwest::{Client, Method, Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::runtime::Runtime;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct VaneRequest {
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub query_params: HashMap<String, String>,
    pub body: Option<String>,
    pub timeout_seconds: Option<u64>,
    pub follow_redirects: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct VaneResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub is_success: bool,
    pub url: String,
}

// #[derive(Debug, Clone, Serialize, Deserialize, uniffi::Object)]
// pub struct VaneError {
//     pub message: String,
//     pub error_type: String,
//     pub status_code: Option<u16>,
// }

#[derive(Debug, Clone, thiserror::Error, uniffi::Error)]
pub enum VaneError {
    #[error("{message}")]
    Generic {
        message: String,
        error_type: String,
        status_code: Option<u16>,
    },
}

impl From<reqwest::Error> for VaneError {
    fn from(error: reqwest::Error) -> Self {
        VaneError::Generic {
            message: error.to_string(),
            error_type: if error.is_timeout() {
                "timeout".to_string()
            } else if error.is_connect() {
                "connection".to_string()
            } else if error.is_decode() {
                "decode".to_string()
            } else {
                "request".to_string()
            },
            status_code: error.status().map(|s| s.as_u16()),
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct VaneClientConfig {
    pub base_url: Option<String>,
    pub default_headers: HashMap<String, String>,
    pub timeout_seconds: Option<u64>,
    pub follow_redirects: bool,
    pub user_agent: Option<String>,
}

impl Default for VaneClientConfig {
    fn default() -> Self {
        VaneClientConfig {
            base_url: None,
            default_headers: HashMap::new(),
            timeout_seconds: Some(30),
            follow_redirects: true,
            user_agent: Some("Vane/0.1.0".to_string()),
        }
    }
}

#[derive(uniffi::Object)]
pub struct VaneClient {
    client: Client,
    config: VaneClientConfig,
    runtime: Arc<Runtime>,
}

impl VaneClient {
    pub fn new(config: VaneClientConfig) -> Result<Self, VaneError> {
        let runtime = Arc::new(Runtime::new().map_err(|e| VaneError::Generic {
            message: format!("Failed to create runtime: {}", e),
            error_type: "runtime".to_string(),
            status_code: None,
        })?);

        let mut client_builder = Client::builder().redirect(if config.follow_redirects {
            reqwest::redirect::Policy::limited(10)
        } else {
            reqwest::redirect::Policy::none()
        });

        if let Some(timeout) = config.timeout_seconds {
            client_builder = client_builder.timeout(Duration::from_secs(timeout));
        }

        if let Some(user_agent) = &config.user_agent {
            client_builder = client_builder.user_agent(user_agent);
        }

        let client = client_builder.build().map_err(|e| VaneError::Generic {
            message: format!("Failed to create client: {}", e),
            error_type: "client".to_string(),
            status_code: None,
        })?;

        Ok(VaneClient {
            client,
            config,
            runtime,
        })
    }

    pub fn execute(&self, request: VaneRequest) -> Result<VaneResponse, VaneError> {
        self.runtime
            .block_on(async { self.execute_async(request).await })
    }

    async fn execute_async(&self, request: VaneRequest) -> Result<VaneResponse, VaneError> {
        let url = self.build_url(&request.url)?;
        let method =
            Method::from_bytes(request.method.as_bytes()).map_err(|_| VaneError::Generic {
                message: format!("Invalid HTTP method: {}", request.method),
                error_type: "method".to_string(),
                status_code: None,
            })?;

        let mut req_builder = self.client.request(method, url.clone());

        // Add default headers
        for (key, value) in &self.config.default_headers {
            req_builder = req_builder.header(key, value);
        }

        // Add request headers
        for (key, value) in &request.headers {
            req_builder = req_builder.header(key, value);
        }

        // Add query parameters
        if !request.query_params.is_empty() {
            req_builder = req_builder.query(&request.query_params);
        }

        // Add body if present
        if let Some(body) = &request.body {
            req_builder = req_builder.body(body.clone());
        }

        // Set timeout if specified
        if let Some(timeout) = request.timeout_seconds {
            req_builder = req_builder.timeout(Duration::from_secs(timeout));
        }

        let response = req_builder.send().await?;
        self.convert_response(response).await
    }

    fn build_url(&self, url: &str) -> Result<Url, VaneError> {
        if let Some(base_url) = &self.config.base_url {
            let base = Url::parse(base_url).map_err(|e| VaneError::Generic {
                message: format!("Invalid base URL: {}", e),
                error_type: "url".to_string(),
                status_code: None,
            })?;

            base.join(url).map_err(|e| VaneError::Generic {
                message: format!("Failed to join URL: {}", e),
                error_type: "url".to_string(),
                status_code: None,
            })
        } else {
            Url::parse(url).map_err(|e| VaneError::Generic {
                message: format!("Invalid URL: {}", e),
                error_type: "url".to_string(),
                status_code: None,
            })
        }
    }

    async fn convert_response(&self, response: Response) -> Result<VaneResponse, VaneError> {
        let status_code = response.status().as_u16();
        let is_success = response.status().is_success();
        let url = response.url().to_string();

        let mut headers = HashMap::new();
        for (key, value) in response.headers() {
            headers.insert(key.to_string(), value.to_str().unwrap_or("").to_string());
        }

        let body = response.text().await.map_err(|e| VaneError::Generic {
            message: format!("Failed to read response body: {}", e),
            error_type: "response".to_string(),
            status_code: Some(status_code),
        })?;

        Ok(VaneResponse {
            status_code,
            headers,
            body,
            is_success,
            url,
        })
    }

    // Convenience methods similar to Alamofire/Retrofit
    pub fn get(&self, url: &str) -> Result<VaneResponse, VaneError> {
        self.execute(VaneRequest {
            url: url.to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
            body: None,
            timeout_seconds: None,
            follow_redirects: self.config.follow_redirects,
        })
    }

    pub fn post(&self, url: &str, body: Option<String>) -> Result<VaneResponse, VaneError> {
        self.execute(VaneRequest {
            url: url.to_string(),
            method: "POST".to_string(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
            body,
            timeout_seconds: None,
            follow_redirects: self.config.follow_redirects,
        })
    }

    pub fn put(&self, url: &str, body: Option<String>) -> Result<VaneResponse, VaneError> {
        self.execute(VaneRequest {
            url: url.to_string(),
            method: "PUT".to_string(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
            body,
            timeout_seconds: None,
            follow_redirects: self.config.follow_redirects,
        })
    }

    pub fn delete(&self, url: &str) -> Result<VaneResponse, VaneError> {
        self.execute(VaneRequest {
            url: url.to_string(),
            method: "DELETE".to_string(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
            body: None,
            timeout_seconds: None,
            follow_redirects: self.config.follow_redirects,
        })
    }

    pub fn patch(&self, url: &str, body: Option<String>) -> Result<VaneResponse, VaneError> {
        self.execute(VaneRequest {
            url: url.to_string(),
            method: "PATCH".to_string(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
            body,
            timeout_seconds: None,
            follow_redirects: self.config.follow_redirects,
        })
    }
}

// UniFFI exports
#[uniffi::export]
pub fn create_vane_client(config: VaneClientConfig) -> Result<Arc<VaneClient>, VaneError> {
    Ok(Arc::new(VaneClient::new(config)?))
}

#[uniffi::export]
pub fn create_default_config() -> VaneClientConfig {
    VaneClientConfig::default()
}

#[uniffi::export]
impl VaneClient {
    pub fn execute_request(&self, request: VaneRequest) -> Result<VaneResponse, VaneError> {
        self.execute(request)
    }

    pub fn get_request(&self, url: String) -> Result<VaneResponse, VaneError> {
        self.get(&url)
    }

    pub fn post_request(
        &self,
        url: String,
        body: Option<String>,
    ) -> Result<VaneResponse, VaneError> {
        self.post(&url, body)
    }

    pub fn put_request(
        &self,
        url: String,
        body: Option<String>,
    ) -> Result<VaneResponse, VaneError> {
        self.put(&url, body)
    }

    pub fn delete_request(&self, url: String) -> Result<VaneResponse, VaneError> {
        self.delete(&url)
    }

    pub fn patch_request(
        &self,
        url: String,
        body: Option<String>,
    ) -> Result<VaneResponse, VaneError> {
        self.patch(&url, body)
    }
}

// Helper functions for JSON handling
#[uniffi::export]
pub fn parse_json_response(response: &VaneResponse) -> Result<String, VaneError> {
    let parsed: Value = serde_json::from_str(&response.body).map_err(|e| VaneError::Generic {
        message: format!("Failed to parse JSON: {}", e),
        error_type: "json".to_string(),
        status_code: Some(response.status_code),
    })?;

    serde_json::to_string_pretty(&parsed).map_err(|e| VaneError::Generic {
        message: format!("Failed to serialize JSON: {}", e),
        error_type: "json".to_string(),
        status_code: Some(response.status_code),
    })
}

#[uniffi::export]
pub fn create_json_body(json_string: String) -> Result<String, VaneError> {
    // Validate JSON
    let _: Value = serde_json::from_str(&json_string).map_err(|e| VaneError::Generic {
        message: format!("Invalid JSON: {}", e),
        error_type: "json".to_string(),
        status_code: None,
    })?;

    Ok(json_string)
}

uniffi::setup_scaffolding!();
