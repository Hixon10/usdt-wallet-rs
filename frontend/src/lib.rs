use std::process;
use std::time::Duration;
use usdt_wallet_core::tron_client::TrongridClient;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub async fn get_trx_balance(wallet: String, trongrid_api_key: String) -> Result<String, JsValue> {
    let api_key_opt: Option<String> = {
        let s = trongrid_api_key.trim();
        if s.is_empty() {
            None
        } else {
            Some(s.to_owned())
        }
    };

    let client = TrongridClient::new(
        "https://api.trongrid.io",
        api_key_opt,
        Duration::from_secs(5),
    )
    .unwrap_or_else(|err| {
        // Print to stderr
        eprintln!("Error creating TrongridClient: {err:?}");
        // Exit with non-zero status code
        process::exit(1);
    });

    let trx_balance = client
        .get_trx_balance(wallet.as_str())
        .await
        .unwrap_or_else(|err| {
            // Print to stderr
            eprintln!("Error fetching trx balance: {err:?}");
            // Exit with non-zero status code
            process::exit(1);
        });

    #[allow(clippy::cast_precision_loss)]
    let trx: f64 = trx_balance as f64 / 1_000_000.0;

    Ok(format!("test3--{trx}"))
}
