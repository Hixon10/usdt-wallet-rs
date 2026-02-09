use std::time::Duration;
use usdt_wallet_core::tron_client::TrongridClient;
use usdt_wallet_core::tron_wallet;
use usdt_wallet_core::tron_wallet::mnemonic_to_tron_address_and_private_key;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub async fn generate_new_mnemonic() -> Result<String, String> {
    let new_mnemonic = tron_wallet::generate_new_mnemonic();
    Ok(new_mnemonic)
}

#[wasm_bindgen]
pub async fn mnemonic_to_tron_address(mnemonic: String, account: u32) -> Result<String, String> {
    let (tron_wallet, _) =
        mnemonic_to_tron_address_and_private_key(mnemonic.as_str(), "", account, 0);
    Ok(tron_wallet)
}

#[wasm_bindgen]
pub async fn get_trx_balance(wallet: String, trongrid_api_key: String) -> Result<String, String> {
    let client = build_client(trongrid_api_key)?;

    let trx_balance = client
        .get_trx_balance(wallet.as_str())
        .await
        .map_err(|err| format!("Error fetching trx balance: {err:?}"))?;

    #[allow(clippy::cast_precision_loss)]
    let trx: f64 = trx_balance as f64 / 1_000_000.0;

    Ok(format!("{trx}"))
}

#[wasm_bindgen]
pub async fn get_usdt_balance(wallet: String, trongrid_api_key: String) -> Result<String, String> {
    let client = build_client(trongrid_api_key)?;

    let usdt_balance = client
        .get_usdt_balance(wallet.as_str())
        .await
        .map_err(|err| format!("Error fetching usdt balance: {err:?}"))?;

    #[allow(clippy::cast_precision_loss)]
    let usdt: f64 = usdt_balance as f64 / 1_000_000.0;

    Ok(format!("{usdt}"))
}

#[wasm_bindgen]
pub async fn send_trx(
    mnemonic: String,
    account: u32,
    to_wallet: String,
    amount: f64,
    trongrid_api_key: String,
) -> Result<String, String> {
    let amount_sun = usdt_to_sun_units(amount)?;

    let client = build_client(trongrid_api_key)?;

    let (from_wallet, from_secret_key) =
        mnemonic_to_tron_address_and_private_key(mnemonic.as_str(), "", account, 0);

    let send_trx_response = client
        .send_trx(
            &from_secret_key,
            from_wallet.as_str(),
            to_wallet.as_str(),
            amount_sun,
        )
        .await
        .map_err(|err| format!("Error sending trx: {err:?}"))?;

    Ok(send_trx_response)
}

#[wasm_bindgen]
pub async fn send_usdt(
    mnemonic: String,
    account: u32,
    to_wallet: String,
    amount: f64,
    trongrid_api_key: String,
) -> Result<String, String> {
    let amount_sun = usdt_to_sun_units(amount)?;

    let client = build_client(trongrid_api_key)?;

    let (from_wallet, from_secret_key) =
        mnemonic_to_tron_address_and_private_key(mnemonic.as_str(), "", account, 0);

    let send_trx_response = client
        .send_usdt(
            &from_secret_key,
            from_wallet.as_str(),
            to_wallet.as_str(),
            amount_sun as u128,
        )
        .await
        .map_err(|err| format!("Error sending usdt: {err:?}"))?;

    Ok(send_trx_response)
}

fn build_client(trongrid_api_key: String) -> Result<TrongridClient, String> {
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
    .map_err(|err| format!("Error creating TrongridClient: {err:?}"))?;
    Ok(client)
}

fn usdt_to_sun_units(amount: f64) -> Result<i64, String> {
    if !amount.is_finite() {
        return Err("amount must be finite".to_string());
    }
    if amount < 0.0 {
        return Err("amount must be non-negative".to_string());
    }

    // Convert to "micro-USDT" (10^-6), aka the integer units typically used for USDT.
    let scaled = amount * 1_000_000.0;

    // If you want "slight error is fine", rounding is usually preferable to truncation.
    // (Use floor() if you want to never overshoot.)
    let rounded = scaled.round();

    // Guard rails before casting
    if rounded > i64::MAX as f64 {
        return Err("amount is too large (overflows i64)".to_string());
    }
    if rounded < 0.0 {
        // should not happen due to amount>=0, but keeps it robust
        return Err("amount underflow".to_string());
    }

    Ok(rounded as i64)
}
