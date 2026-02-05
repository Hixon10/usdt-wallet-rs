use k256::SecretKey;
use k256::ecdsa::{RecoveryId, Signature, SigningKey};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
    BroadcastFailed(String),
    InvalidArgument(String),
    CreatingSignatureFailed(String),
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
            Self::BroadcastFailed(msg) => write!(f, "BroadcastTransaction call error: {msg}"),
            Self::InvalidArgument(msg) => write!(f, "Invalid argument: {msg}"),
            Self::CreatingSignatureFailed(msg) => write!(f, "Creating Signature Failed: {msg}"),
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

#[derive(Debug, Serialize)]
pub struct CreateTransactionRequest {
    pub owner_address: String, // hex (41...)
    pub to_address: String,    // hex (41...)
    pub amount: i64,           // in SUN (1 TRX = 1_000_000 SUN)
    pub visible: bool,
}

#[derive(Debug, Deserialize)]
pub struct CreateTransactionResponse {
    pub visible: Option<bool>,
    pub txid: Option<String>,
    pub raw_data_hex: String,
    pub raw_data: serde_json::Value, // not needed for signing; keep flexible
}

#[derive(Debug, Serialize)]
pub struct BroadcastTransactionRequest {
    pub raw_data: serde_json::Value,
    pub raw_data_hex: String,
    pub signature: Vec<String>, // hex signature(s)
    pub txid: Option<String>,
    pub visible: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BroadcastTransactionResponse {
    pub result: bool,
    pub code: Option<String>,
    pub message: Option<String>, // often base64-ish; treat as string
    pub txid: Option<String>,
}

impl TrongridClient {
    /// Create a client with a reusable internal HTTP client.
    ///
    /// # Errors
    /// If this function encounters any form of error, an error
    /// variant will be returned.
    pub fn new(
        base_url: impl Into<String>,
        api_key: Option<String>,
        timeout: Duration,
    ) -> Result<Self, TronError> {
        let http_client = Self::build_client(timeout) // enforce trusted CA certs
            .build()
            .map_err(|err| TronError::HttpClient(err.to_string()))?;

        Ok(Self {
            http_client,
            base_url: base_url.into().trim_end_matches('/').to_string(),
            api_key,
        })
    }

    #[cfg(target_arch = "wasm32")]
    fn build_client(_: Duration) -> reqwest::ClientBuilder {
        Client::builder()
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn build_client(timeout: Duration) -> reqwest::ClientBuilder {
        Client::builder()
            .timeout(timeout)
            .danger_accept_invalid_certs(false)
    }

    /// Returns a trx balance for the address.
    ///
    /// # Errors
    /// If this function encounters any form of error, an error
    /// variant will be returned.
    pub async fn get_trx_balance(&self, address: &str) -> Result<u64, TronError> {
        let url = format!("{}/v1/accounts/{}", self.base_url, address);

        let mut request = self.http_client.get(&url);

        // Add TRON-PRO-API-KEY only if provided
        if let Some(ref key) = self.api_key {
            request = request.header("TRON-PRO-API-KEY", key);
        }

        // 1. network
        let response = request
            .send()
            .await
            .map_err(|err| TronError::Network(err.to_string()))?;

        // 2. http code
        if !response.status().is_success() {
            return Err(TronError::Http(response.status().as_u16()));
        }

        // 3. parse as struct (no manual JSON traversal!)
        let parsed: AccountResponse = response
            .json()
            .await
            .map_err(|err| TronError::Json(err.to_string()))?;

        // 4. data must contain at least 1 entry
        let account = parsed.data.first().ok_or(TronError::EmptyData)?;

        Ok(account.balance)
    }

    /// On-chain USDT balance via `balanceOf(address)` (TRC20).
    /// Returns base units (USDT decimals=6) as u128.
    ///
    /// # Errors
    /// If this function encounters any form of error, an error
    /// variant will be returned.
    pub async fn get_usdt_balance(&self, owner_base58: &str) -> Result<u128, TronError> {
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
            .await
            .map_err(|err| TronError::Network(err.to_string()))?;

        if !response.status().is_success() {
            return Err(TronError::Http(response.status().as_u16()));
        }

        let parsed: TriggerConstantContractResponse = response
            .json()
            .await
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

    /// Send native TRX (amount is in SUN: 1 TRX = `1_000_000` SUN)
    ///
    /// # Errors
    /// If this function encounters any form of error, an error
    /// variant will be returned.
    #[allow(dead_code)]
    pub async fn send_trx(
        &self,
        wallet_secret_key: &SecretKey,
        from_base58: &str,
        to_base58: &str,
        amount_sun: i64,
    ) -> Result<String, TronError> {
        if amount_sun <= 0 {
            return Err(TronError::InvalidArgument(
                "amount_sun must be > 0".to_string(),
            ));
        }

        // 1) Build unsigned transaction
        let from_hex41 = Self::tron_base58_to_hex41(from_base58)?;
        let to_hex41 = Self::tron_base58_to_hex41(to_base58)?;

        let create_body = CreateTransactionRequest {
            owner_address: hex::encode(&from_hex41),
            to_address: hex::encode(&to_hex41),
            amount: amount_sun,
            visible: false,
        };

        let create_url = format!("{}/wallet/createtransaction", self.base_url);
        let mut create_req = self.http_client.post(&create_url).json(&create_body);
        if let Some(ref key) = self.api_key {
            create_req = create_req.header("TRON-PRO-API-KEY", key);
        }

        let create_resp = create_req
            .send()
            .await
            .map_err(|err| TronError::Network(err.to_string()))?;

        if !create_resp.status().is_success() {
            return Err(TronError::Http(create_resp.status().as_u16()));
        }

        let unsigned: CreateTransactionResponse = create_resp.json().await.map_err(|err| {
            TronError::Json(format!(
                "cannot deserialize CreateTransactionResponse: {err}"
            ))
        })?;

        let signature = Self::build_tron_signature_from_raw_data_hex(
            wallet_secret_key,
            &unsigned.raw_data_hex,
        )?;

        // 3) Broadcast signed transaction
        let broadcast_body = BroadcastTransactionRequest {
            raw_data: unsigned.raw_data,
            raw_data_hex: unsigned.raw_data_hex,
            signature: vec![signature],
            txid: unsigned.txid.clone(),
            visible: unsigned.visible,
        };

        let broadcast_url = format!("{}/wallet/broadcasttransaction", self.base_url);
        let mut broadcast_req = self.http_client.post(&broadcast_url).json(&broadcast_body);
        if let Some(ref key) = self.api_key {
            broadcast_req = broadcast_req.header("TRON-PRO-API-KEY", key);
        }

        let broadcast_resp = broadcast_req
            .send()
            .await
            .map_err(|err| TronError::Network(err.to_string()))?;

        if !broadcast_resp.status().is_success() {
            return Err(TronError::Http(broadcast_resp.status().as_u16()));
        }

        let br: BroadcastTransactionResponse = broadcast_resp.json().await.map_err(|err| {
            TronError::Json(format!(
                "cannot deserialize BroadcastTransactionResponse: {err}"
            ))
        })?;

        if !br.result {
            return Err(TronError::BroadcastFailed(format!(
                "broadcasttransaction failed: code={:?}, message={:?}",
                br.code, br.message
            )));
        }

        br.txid.clone().ok_or_else(|| {
            TronError::BroadcastFailed(format!(
                "broadcasttransaction failed, txid is empty: code={:?}, message={:?}",
                br.code, br.message
            ))
        })
    }

    fn build_tron_signature_from_raw_data_hex(
        wallet_secret_key: &SecretKey,
        raw_data_hex: &str,
    ) -> Result<String, TronError> {
        let raw_bytes =
            hex::decode(raw_data_hex).map_err(|e| TronError::InvalidHex(e.to_string()))?;

        let signing_key = SigningKey::from_bytes(&wallet_secret_key.to_bytes())
            .map_err(|e| TronError::CreatingSignatureFailed(e.to_string()))?;
        // 4) sign digest and obtain recovery id (v)
        // In k256 0.13, use sign_digest_recoverable.
        let (sig, recid): (Signature, RecoveryId) = signing_key
            .sign_digest_recoverable(Sha256::new_with_prefix(&raw_bytes))
            .map_err(|e| TronError::CreatingSignatureFailed(e.to_string()))?;
        // NOTE: Above line signs the digest of raw_bytes using Sha256::new_with_prefix.
        // If you prefer to sign the digest you already computed, see the alternative below.

        // 5) serialize signature as 65 bytes: r(32) || s(32) || v(1)
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(sig.to_bytes().as_slice());
        out[64] = recid.to_byte(); // 0 or 1
        Ok(hex::encode(out))
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

    use crate::tron_wallet;
    use k256::Secp256k1;
    use k256::elliptic_curve::SecretKey as ECSecretKey;

    #[test]
    fn build_signature_rejects_invalid_hex() {
        let sk =
            secret_key_from_hex("1111111111111111111111111111111111111111111111111111111111111111");
        let err =
            TrongridClient::build_tron_signature_from_raw_data_hex(&sk, "zz-not-hex").unwrap_err();

        match err {
            TronError::InvalidHex(msg) => {
                assert!(
                    msg.contains("Invalid character"),
                    "unexpected network error message: {msg}"
                );
            }
            other => panic!("expected TronError::InvalidHex, got: {other:?}"),
        }
    }

    #[test]
    fn build_signature_output_has_expected_format() {
        let sk =
            secret_key_from_hex("1111111111111111111111111111111111111111111111111111111111111111");

        // Any valid hex is fine. Keep it small and explicit.
        let raw_data_hex = "0a0b0c";

        let sig_hex =
            TrongridClient::build_tron_signature_from_raw_data_hex(&sk, raw_data_hex).unwrap();

        // Must be 65 bytes => 130 hex chars.
        assert_eq!(sig_hex.len(), 130);

        let sig_bytes = hex::decode(&sig_hex).unwrap();
        assert_eq!(sig_bytes.len(), 65);

        // v / recovery id must be 0 or 1 according to your code.
        assert!(sig_bytes[64] == 0 || sig_bytes[64] == 1, "v must be 0 or 1");
    }

    #[test]
    fn build_signature_golden_vector_1_contract_test() {
        const EXPECTED_SIG_HEX: &str = "3c561edf3cc0467052c311f03dbd546a0d9222d75941e3748d7076e07195ebc714f5e337282f97ff07f77b593c1db6383b99913930cae55f28f2aad1c60b4fb700";

        let sk =
            secret_key_from_hex("1111111111111111111111111111111111111111111111111111111111111111");
        let raw_data_hex = "0a0b0c";

        let sig_hex =
            TrongridClient::build_tron_signature_from_raw_data_hex(&sk, raw_data_hex).unwrap();
        assert_eq!(sig_hex, EXPECTED_SIG_HEX);
    }

    #[test]
    fn build_signature_golden_vector_2_contract_test() {
        const EXPECTED_SIG_HEX: &str = "022a64abe3013591cf8a0a8ea61bf458a831c2fd43fc9b7ea82c043948d0474804c4ca22d3e78ac8b7b0c2055d489334756cbd4244692eaed8d15e6da0a84f2c01";

        let (_, secret_key) = tron_wallet::mnemonic_to_tron_address_and_private_key(
            "because power elegant ranch excuse plug six wasp sunny radar car topple",
            "",
            0,
        );

        let raw_data_hex = "0a1b2c3d4e5f00112233445566778899aabbccddeeff0123456789abcdef";

        let sig_hex =
            TrongridClient::build_tron_signature_from_raw_data_hex(&secret_key, raw_data_hex)
                .unwrap();
        assert_eq!(sig_hex, EXPECTED_SIG_HEX);
    }

    #[test]
    fn tron_base58_to_hex41_success() {
        let result =
            TrongridClient::tron_base58_to_hex41("TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC").unwrap();
        let result_hex = hex::encode(result);
        assert_eq!("417e5f4552091a69125d5dfcb7b8c2659029395bdf", result_hex);
    }

    #[tokio::test]
    async fn send_trx_success() {
        let (sender_base58, secret_key) = tron_wallet::mnemonic_to_tron_address_and_private_key(
            "because power elegant ranch excuse plug six wasp sunny radar car topple",
            "",
            0,
        );
        let sender_hex41 = TrongridClient::tron_base58_to_hex41(sender_base58.as_str()).unwrap();
        let receiver_base58 = "TRjE1H8dxypKM1NZRdysbs9wo7huR4bdNz";
        let receiver_hex41 = TrongridClient::tron_base58_to_hex41(receiver_base58).unwrap();

        let amount = 3134;

        let server = MockServer::start();

        // Mock expects exact JSON body (as a JSON object, not as a raw string)
        let createtransaction_mock = server.mock(|when, then| {
            when.method(POST)
                .path("/wallet/createtransaction")
                .json_body(serde_json::json!({
                    "owner_address": hex::encode(sender_hex41),
                    "to_address": hex::encode(receiver_hex41),
                    "amount": amount,
                    "visible": false
                }));
            then.status(200)
                .header("content-type", "application/json")
                .json_body(serde_json::json!({
                    "visible": false,
                    "raw_data_hex": "0a1b2c3d4e5f00112233445566778899aabbccddeeff0123456789abcdef",
                    "raw_data": {}
                }));
        });

        let broadcast_transaction_mock = server.mock(|when, then| {
            when.method(POST)
                .json_body(serde_json::json!({
                    "raw_data": {},
                    "raw_data_hex": "0a1b2c3d4e5f00112233445566778899aabbccddeeff0123456789abcdef",
                    "signature": [
                        "022a64abe3013591cf8a0a8ea61bf458a831c2fd43fc9b7ea82c043948d0474804c4ca22d3e78ac8b7b0c2055d489334756cbd4244692eaed8d15e6da0a84f2c01"
                    ],
                    "txid": null,
                    "visible": false
                }))
                .path("/wallet/broadcasttransaction");
            then.status(200)
                .header("content-type", "application/json")
                .json_body(serde_json::json!({
                    "result": true,
                    "txid": "test_txid"
                }));
        });

        let client = TrongridClient::new(server.base_url(), None, Duration::from_secs(2)).unwrap();

        let send_trx_result = client
            .send_trx(&secret_key, sender_base58.as_str(), receiver_base58, amount)
            .await;
        assert!(
            send_trx_result.is_ok(),
            "send_trx failed: {:?}",
            send_trx_result.err()
        );
        assert_eq!(send_trx_result.unwrap(), "test_txid");

        createtransaction_mock.assert_calls(1);
        broadcast_transaction_mock.assert_calls(1);
    }

    #[tokio::test]
    async fn get_usdt_balance_success() {
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

        let bal = client.get_usdt_balance(owner_base58).await.unwrap();
        assert_eq!(bal, 1_500_000u128);

        // Extra: ensure the mock was hit exactly once
        m.assert_calls(1);
    }

    #[tokio::test]
    async fn get_balance_success() {
        let server = MockServer::start();

        let _m = server.mock(|when, then| {
            when.method(GET).path("/v1/accounts/T123");
            then.status(200)
                .header("content-type", "application/json")
                .body(r#"{"data":[{"balance":322342}],"success":true}"#);
        });

        let client = TrongridClient::new(server.base_url(), None, Duration::from_secs(2)).unwrap();
        let bal = client.get_trx_balance("T123").await.unwrap();
        assert_eq!(bal, 322_342);
    }

    #[tokio::test]
    async fn get_balance_timeout() {
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
        let err = client.get_trx_balance("T123").await.unwrap_err();

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

    #[tokio::test]
    async fn get_balance_invalid_json_response() {
        let server = MockServer::start();

        let _m = server.mock(|when, then| {
            when.method(GET).path("/v1/accounts/T123");
            then.status(200)
                .header("content-type", "application/json")
                // Intentionally invalid JSON
                .body(r#"{"data":[{"balance":123}]"#);
        });

        let client = TrongridClient::new(server.base_url(), None, Duration::from_secs(2)).unwrap();
        let err = client.get_trx_balance("T123").await.unwrap_err();

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

    // Helper: make a SecretKey from 32-byte hex.
    #[allow(clippy::expect_used)]
    fn secret_key_from_hex(sk_hex: &str) -> SecretKey {
        let bytes = hex::decode(sk_hex).expect("valid sk hex");
        assert_eq!(bytes.len(), 32, "secret key must be 32 bytes");
        let arr: [u8; 32] = bytes.try_into().unwrap();
        ECSecretKey::<Secp256k1>::from_bytes(&arr.into()).expect("valid secret key")
    }
}
