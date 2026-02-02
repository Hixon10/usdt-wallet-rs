mod tron_client;
mod tron_wallet;
mod wordlist;

use crate::tron_client::TrongridClient;
use std::time::Duration;
use std::{fs, process};

fn main() {
    println!("1. Recover wallet/private key from mnemonic");
    // 1. Recover wallet/private key from mnemonic
    // --- INPUT YOUR 12 WORDS HERE ---

    // let mnemonic =
    //     "country position lady inflict alcohol broken off awesome poem shaft badge current";
    let mnemonic = fs::read_to_string("test_mnemonic.txt").unwrap_or_else(|err| {
        // Print to stderr
        eprintln!("Cannot read test mnemonic: {err:?}");
        process::exit(1);
    });

    let trongrid_api_key = fs::read_to_string("test_trongrid_api_key.txt").unwrap_or_else(|err| {
        // Print to stderr
        eprintln!("Cannot read trongrid api key: {err:?}");
        process::exit(1);
    });

    let passphrase = ""; // Leave empty unless you specifically set one
    let address_index = 0;
    // --------------------------------

    let (tron_wallet, _) = tron_wallet::mnemonic_to_tron_address_and_private_key(
        mnemonic.as_str(),
        passphrase,
        address_index,
    );

    // 2. Generate a NEW Mnemonic (12 words)
    println!("--------------------------------------------------");
    println!("--------------------------------------------------");
    println!("2. Generate a NEW Mnemonic (12 words)");
    let new_mnemonic = tron_wallet::generate_new_mnemonic();
    println!("Generated Mnemonic: {new_mnemonic}");

    let address_index = 0;
    tron_wallet::mnemonic_to_tron_address_and_private_key(
        new_mnemonic.as_str(),
        passphrase,
        address_index,
    );

    // get balances
    let client = TrongridClient::new(
        "https://api.trongrid.io",
        Some(trongrid_api_key),
        Duration::from_secs(5),
    )
    .unwrap_or_else(|err| {
        // Print to stderr
        eprintln!("Error creating TrongridClient: {err:?}");
        // Exit with non-zero status code
        process::exit(1);
    });

    let trx_balance = client
        .get_trx_balance(tron_wallet.as_str())
        .unwrap_or_else(|err| {
            // Print to stderr
            eprintln!("Error fetching trx balance: {err:?}");
            // Exit with non-zero status code
            process::exit(1);
        });

    #[allow(clippy::cast_precision_loss)]
    let trx: f64 = trx_balance as f64 / 1_000_000.0;
    println!("The trx balance is: {trx}");

    let usdt_balance = client
        .get_usdt_balance(tron_wallet.as_str())
        .unwrap_or_else(|err| {
            // Print to stderr
            eprintln!("Error fetching usdt balance: {err:?}");
            // Exit with non-zero status code
            process::exit(1);
        });

    #[allow(clippy::cast_precision_loss)]
    let usdt: f64 = usdt_balance as f64 / 1_000_000.0;
    println!("The usdt_balance balance is: {usdt}");

    // // 3. send RTX
    // let send_trx_response = client
    //     .send_trx(
    //         &wallet_secret_key,
    //         tron_wallet.as_str(),
    //         "TEAqZKYBjbEs5eipqHWMP9kGzWrT2v8pdr",
    //         1000,
    //     )
    //     .unwrap_or_else(|err| {
    //         // Print to stderr
    //         eprintln!("Error sending trx: {err:?}");
    //         // Exit with non-zero status code
    //         process::exit(1);
    //     });
    // println!("Send rtx response txid: {send_trx_response}");
}
