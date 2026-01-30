use reqwest::blocking::Client;
use serde::Deserialize;
use std::fmt;
use std::time::Duration;

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

pub fn get_trx_balance(address: &str, api_key: Option<&str>) -> Result<u64, TronError> {
    let url = format!("https://api.trongrid.io/v1/accounts/{address}");

    let client = Client::builder()
        .timeout(Duration::from_secs(5)) // 5 seconds for request
        .tls_danger_accept_invalid_certs(false) // enforce trusted CA certs
        .build()
        .map_err(|err| TronError::HttpClient(err.to_string()))?;

    let mut request = client.get(&url);

    // Add TRON-PRO-API-KEY only if provided
    if let Some(key) = api_key {
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
