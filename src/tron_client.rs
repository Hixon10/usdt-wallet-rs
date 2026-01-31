use reqwest::blocking::Client;
use serde::Deserialize;
use std::fmt;
use std::time::Duration;

pub struct TrongridClient {
    http_client: Client,
    base_url: String,
    api_key: Option<String>,
}

#[derive(Debug)]
pub enum TronError {
    Network(String),
    HttpClient(String),
    Http(u16),
    Json(String),
    EmptyData,
}

impl fmt::Display for TronError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(msg) => write!(f, "Network error: {msg}"),
            Self::HttpClient(msg) => write!(f, "HttpClient error: {msg}"),
            Self::Http(code) => write!(f, "HTTP error: status code {code}"),
            Self::Json(msg) => write!(f, "JSON parsing error: {msg}"),
            Self::EmptyData => write!(f, "Missing expected field"),
        }
    }
}

#[derive(Debug, Deserialize)]
struct AccountResponse {
    data: Vec<AccountData>,
}

#[derive(Debug, Deserialize)]
struct AccountData {
    balance: u64,
}

impl TrongridClient {
    /// Create a client with a reusable internal HTTP client.
    pub fn new(
        base_url: impl Into<String>,
        api_key: Option<String>,
        timeout: Duration,
    ) -> Result<Self, TronError> {
        let http_client = Client::builder()
            .timeout(timeout)
            .tls_danger_accept_invalid_certs(false) // enforce trusted CA certs
            .build()
            .map_err(|err| TronError::HttpClient(err.to_string()))?;

        Ok(Self {
            http_client,
            base_url: base_url.into().trim_end_matches('/').to_string(),
            api_key,
        })
    }

    pub fn get_trx_balance(&self, address: &str) -> Result<u64, TronError> {
        let url = format!("{}/v1/accounts/{}", self.base_url, address);

        let mut request = self.http_client.get(&url);

        // Add TRON-PRO-API-KEY only if provided
        if let Some(ref key) = self.api_key {
            request = request.header("TRON-PRO-API-KEY", key);
        }

        // 1. network
        let response = request
            .send()
            .map_err(|err| TronError::Network(err.to_string()))?;

        // 2. http code
        if !response.status().is_success() {
            return Err(TronError::Http(response.status().as_u16()));
        }

        // 3. parse as struct (no manual JSON traversal!)
        let parsed: AccountResponse = response
            .json()
            .map_err(|err| TronError::Json(err.to_string()))?;

        // 4. data must contain at least 1 entry
        let account = parsed.data.first().ok_or(TronError::EmptyData)?;

        Ok(account.balance)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use httpmock::prelude::*;

    #[test]
    fn get_balance_success() {
        let server = MockServer::start();

        let _m = server.mock(|when, then| {
            when.method(GET).path("/v1/accounts/T123");
            then.status(200)
                .header("content-type", "application/json")
                .body(r#"{"data":[{"balance":322342}],"success":true}"#);
        });

        let client = TrongridClient::new(server.base_url(), None, Duration::from_secs(2)).unwrap();
        let bal = client.get_trx_balance("T123").unwrap();
        assert_eq!(bal, 322_342);
    }

    #[test]
    fn get_balance_timeout() {
        let server = MockServer::start();

        let _m = server.mock(|when, then| {
            when.method(GET).path("/v1/accounts/T123");
            then.status(200)
                .header("content-type", "application/json")
                .delay(std::time::Duration::from_millis(2000))
                .body(r#"{"data":[{"balance":1}]}"#);
        });

        let client =
            TrongridClient::new(server.base_url(), None, Duration::from_millis(50)).unwrap();
        let err = client.get_trx_balance("T123").unwrap_err();

        match err {
            TronError::Network(msg) => {
                // Message varies by OS, so assert on a substring.
                assert!(
                    msg.contains("Connection refused")
                        || msg.contains("connection refused")
                        || msg.contains("failed to connect")
                        || msg.contains("error sending request for url")
                        || msg.contains("tcp connect"),
                    "unexpected network error message: {msg}"
                );
            }
            other => panic!("expected TronError::Network, got: {other:?}"),
        }
    }

    #[test]
    fn get_balance_invalid_json_response() {
        let server = MockServer::start();

        let _m = server.mock(|when, then| {
            when.method(GET).path("/v1/accounts/T123");
            then.status(200)
                .header("content-type", "application/json")
                // Intentionally invalid JSON
                .body(r#"{"data":[{"balance":123}]"#);
        });

        let client = TrongridClient::new(server.base_url(), None, Duration::from_secs(2)).unwrap();
        let err = client.get_trx_balance("T123").unwrap_err();

        // This error originates from JSON parsing (serde_json via reqwest::Response::json()).
        // The exact message can vary by versions, so keep the assertion slightly flexible.
        match err {
            TronError::Json(msg) => {
                // Message varies by OS, so assert on a substring.
                assert!(
                    msg.contains("error decoding response body"),
                    "unexpected network error message: {msg}"
                );
            }
            other => panic!("expected TronError::Network, got: {other:?}"),
        }
    }
}
