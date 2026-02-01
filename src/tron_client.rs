use hmac::digest::Digest;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
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
    InvalidAddress(String),
    InvalidHex(String),
    ContractCall(String),
    MissingConstantResult,
}

impl fmt::Display for TronError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(msg) => write!(f, "Network error: {msg}"),
            Self::HttpClient(msg) => write!(f, "HttpClient error: {msg}"),
            Self::Http(code) => write!(f, "HTTP error: status code {code}"),
            Self::Json(msg) => write!(f, "JSON parsing error: {msg}"),
            Self::EmptyData => write!(f, "Missing expected field"),
            Self::InvalidAddress(msg) => write!(f, "Invalid address: {msg}"),
            Self::InvalidHex(msg) => write!(f, "Invalid hex: {msg}"),
            Self::ContractCall(msg) => write!(f, "Contract call error: {msg}"),
            Self::MissingConstantResult => write!(f, "Missing constant_result in response"),
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

#[derive(Debug, Serialize)]
struct TriggerConstantContractRequest {
    owner_address: String,
    contract_address: String,
    function_selector: String,
    parameter: String,
    visible: bool,
}

#[derive(Debug, Deserialize)]
struct TronRpcResult {
    result: bool,
    #[serde(default)]
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TriggerConstantContractResponse {
    result: TronRpcResult,
    #[serde(default)]
    constant_result: Option<Vec<String>>,
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

    /// On-chain USDT balance via `balanceOf(address)` (TRC20).
    /// Returns base units (USDT decimals=6) as u128.
    pub fn get_usdt_balance(&self, owner_base58: &str) -> Result<u128, TronError> {
        const USDT_CONTRACT_BASE58: &str = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

        let owner_hex41 = Self::tron_base58_to_hex41(owner_base58)?;
        let contract_hex41 = Self::tron_base58_to_hex41(USDT_CONTRACT_BASE58)?;

        // ABI address is 20 bytes; Tron hex address is 21 bytes with 0x41 prefix.
        let owner_evm20 = &owner_hex41[1..];
        let parameter = Self::abi_encode_balance_of(owner_evm20);

        let body = TriggerConstantContractRequest {
            owner_address: hex::encode(&owner_hex41),
            contract_address: hex::encode(&contract_hex41),
            function_selector: "balanceOf(address)".to_string(),
            parameter: hex::encode(parameter),
            visible: false,
        };

        let url = format!("{}/wallet/triggerconstantcontract", self.base_url);
        let mut request = self.http_client.post(&url).json(&body);

        // Add TRON-PRO-API-KEY only if provided
        if let Some(ref key) = self.api_key {
            request = request.header("TRON-PRO-API-KEY", key);
        }

        let response = request
            .send()
            .map_err(|err| TronError::Network(err.to_string()))?;

        if !response.status().is_success() {
            return Err(TronError::Http(response.status().as_u16()));
        }

        let parsed: TriggerConstantContractResponse = response
            .json()
            .map_err(|err| TronError::Json(err.to_string()))?;

        if !parsed.result.result {
            return Err(TronError::ContractCall(
                parsed
                    .result
                    .message
                    .unwrap_or_else(|| "triggerconstantcontract failed".to_string()),
            ));
        }

        let hex_uint = parsed
            .constant_result
            .as_ref()
            .and_then(|v| v.first())
            .ok_or(TronError::MissingConstantResult)?;

        let raw32 = hex::decode(hex_uint).map_err(|e| TronError::InvalidHex(e.to_string()))?;
        if raw32.len() != 32 {
            return Err(TronError::ContractCall(format!(
                "constant_result len {}, expected 32",
                raw32.len()
            )));
        }

        // uint256 -> u128 (assumes fits). Take low 16 bytes.
        let mut low16 = [0u8; 16];
        low16.copy_from_slice(&raw32[16..32]);
        Ok(u128::from_be_bytes(low16))
    }

    fn abi_encode_balance_of(owner20: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 32);
        out.extend_from_slice(&[0u8; 12]); // left pad
        out.extend_from_slice(owner20);
        out
    }

    fn tron_base58_to_hex41(addr: &str) -> Result<Vec<u8>, TronError> {
        let data_with_checksum = bs58::decode(addr)
            .into_vec()
            .map_err(|e| TronError::InvalidAddress(e.to_string()))?;

        if data_with_checksum.len() != 25 {
            return Err(TronError::InvalidAddress(format!(
                "expected 25 bytes (21 payload + 4 checksum), got {}",
                data_with_checksum.len()
            )));
        }

        let (payload, checksum) = data_with_checksum.split_at(21);

        let hash1 = Sha256::digest(payload);
        let hash2 = Sha256::digest(hash1);
        if checksum != &hash2[0..4] {
            return Err(TronError::InvalidAddress("bad checksum".to_string()));
        }

        if payload.len() != 21 || payload[0] != 0x41 {
            return Err(TronError::InvalidAddress(format!(
                "expected payload[0]==0x41 and len==21, got first={:02x} len={}",
                payload.first().copied().unwrap_or(0),
                payload.len()
            )));
        }

        Ok(payload.to_vec())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use httpmock::prelude::*;

    #[test]
    fn tron_base58_to_hex41_success() {
        let result =
            TrongridClient::tron_base58_to_hex41("TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC").unwrap();
        let result_hex = hex::encode(result);
        assert_eq!("417e5f4552091a69125d5dfcb7b8c2659029395bdf", result_hex);
    }

    #[test]
    fn get_usdt_balance_success() {
        // Known mainnet Tron address (USDT contract itself).
        // It is a valid base58check address and decodes cleanly.
        let owner_base58 = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

        // Precomputed:
        // tron_base58_to_hex41("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t") == 41a614f803b6fd780986a42c78ec9c7f77e6ded13c
        // (This is widely used as USDT contract hex41, and also works as an "owner" for the test.)
        let owner_hex41 = "41a614f803b6fd780986a42c78ec9c7f77e6ded13c";

        // ABI encoding for balanceOf(address) where address is 20 bytes (drop 0x41 prefix)
        // selector(balanceOf(address)) = 70a08231
        // parameter = 12-bytes-zero + 20-byte-address
        let expected_parameter = "000000000000000000000000\
             a614f803b6fd780986a42c78ec9c7f77e6ded13c";

        let server = MockServer::start();

        // Mock expects exact JSON body (as a JSON object, not as a raw string)
        let m = server.mock(|when, then| {
            when.method(POST)
                .path("/wallet/triggerconstantcontract")
                .json_body_obj(&serde_json::json!({
                    "owner_address": owner_hex41,
                    "contract_address": owner_hex41, // in your implementation USDT contract is also used as contract address; here owner==contract for simplicity
                    "function_selector": "balanceOf(address)",
                    "parameter": expected_parameter,
                    "visible": false
                }));

            // Return a uint256 = 1_500_000 (1.5 USDT with 6 decimals) encoded as 32-byte hex
            then.status(200)
                .header("content-type", "application/json")
                .body(
                    r#"{
                      "result": { "result": true },
                      "constant_result": [
                        "000000000000000000000000000000000000000000000000000000000016e360"
                      ]
                    }"#,
                );
        });

        let client = TrongridClient::new(server.base_url(), None, Duration::from_secs(2)).unwrap();

        let bal = client.get_usdt_balance(owner_base58).unwrap();
        assert_eq!(bal, 1_500_000u128);

        // Extra: ensure the mock was hit exactly once
        m.assert_calls(1);
    }

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
