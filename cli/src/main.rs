use clap::{Parser, Subcommand};
use std::process::ExitCode;
use std::time::Duration;
use usdt_wallet_core::tron_client::TrongridClient;
use usdt_wallet_core::tron_wallet;
use usdt_wallet_core::tron_wallet::mnemonic_to_tron_address_and_private_key;

/// Demo CLI for tron usdt wallet SDK
#[derive(Parser, Debug)]
#[command(name = "usdt-wallet-rs")]
#[command(
    about = "Demo CLI for tron usdt wallet SDK",
    long_about = "Source code at https://github.com/Hixon10/usdt-wallet-rs"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate a new mnemonic phrase
    GenerateMnemonic,

    /// Convert mnemonic to Tron address
    ConvertMnemonicToWallet {
        /// BIP39 mnemonic phrase (wrap in quotes)
        mnemonic: String,

        /// Account number (optional)
        #[arg(long, default_value_t = 0)]
        account: u32,

        /// Address index number (optional)
        #[arg(long = "address-index", default_value_t = 0)]
        address_index: u32,
    },

    /// Get TRX balance for a given address
    GetTrxBalance {
        /// Tron address (base58)
        tron_wallet: String,

        /// Optional TronGrid API key
        #[arg(long = "trongrid-api-key")]
        trongrid_api_key: Option<String>,
    },

    /// Get USDT balance for a given address
    GetUSDTBalance {
        /// Tron address (base58)
        tron_wallet: String,

        /// Optional TronGrid API key
        #[arg(long = "trongrid-api-key")]
        trongrid_api_key: Option<String>,
    },

    /// Send TRX to a given address
    SendTrx {
        /// FROM account as BIP39 mnemonic phrase (wrap in quotes)
        #[arg(long = "from-mnemonic")]
        from_mnemonic: String,

        /// FROM account number (optional)
        #[arg(long = "from-account", default_value_t = 0)]
        from_account: u32,

        /// FROM address index number (optional)
        #[arg(long = "from-address-index", default_value_t = 0)]
        from_address_index: u32,

        /// TO address (base58)
        #[arg(long = "to-tron-wallet")]
        to_tron_wallet: String,

        /// TRX Amount to transfer
        #[arg(long = "amount")]
        amount: f64,

        /// Optional TronGrid API key
        #[arg(long = "trongrid-api-key")]
        trongrid_api_key: Option<String>,

        /// Do not broadcast signed transaction; just print what would be done
        #[arg(long = "dry-run")]
        dry_run: bool,
    },

    /// Send USDT to a given address
    SendUSDT {
        /// FROM account as BIP39 mnemonic phrase (wrap in quotes)
        #[arg(long = "from-mnemonic")]
        from_mnemonic: String,

        /// FROM account number (optional)
        #[arg(long = "from-account", default_value_t = 0)]
        from_account: u32,

        /// FROM address index number (optional)
        #[arg(long = "from-address-index", default_value_t = 0)]
        from_address_index: u32,

        /// TO address (base58)
        #[arg(long = "to-tron-wallet")]
        to_tron_wallet: String,

        /// USDT Amount to transfer
        #[arg(long = "amount")]
        amount: f64,

        /// Optional TronGrid API key
        #[arg(long = "trongrid-api-key")]
        trongrid_api_key: Option<String>,

        /// Do not broadcast signed transaction; just print what would be done
        #[arg(long = "dry-run")]
        dry_run: bool,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    // Any error returned here becomes a non-zero exit and prints nicely.
    if let Err(e) = run(cli).await {
        eprintln!("{e}");
        return ExitCode::from(1);
    }

    ExitCode::SUCCESS
}

async fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Commands::GenerateMnemonic => {
            let m = tron_wallet::generate_new_mnemonic();
            println!("{m}");
            Ok(())
        }

        Commands::ConvertMnemonicToWallet {
            mnemonic,
            account,
            address_index,
        } => {
            let (tron_wallet, _) = mnemonic_to_tron_address_and_private_key(
                mnemonic.as_str(),
                "",
                account,
                address_index,
            );
            println!("{tron_wallet}");
            Ok(())
        }

        Commands::GetTrxBalance {
            tron_wallet,
            trongrid_api_key,
        } => {
            let client = build_client(trongrid_api_key)?;

            let trx_balance = client
                .get_trx_balance(&tron_wallet)
                .await
                .map_err(|e| format!("get-trx-balance failed for {tron_wallet}: {e:?}"))?;

            #[allow(clippy::cast_precision_loss)]
            let trx: f64 = trx_balance as f64 / 1_000_000.0;
            println!("{trx}");
            Ok(())
        }

        Commands::GetUSDTBalance {
            tron_wallet,
            trongrid_api_key,
        } => {
            let client = build_client(trongrid_api_key)?;

            let usdt_balance = client
                .get_usdt_balance(&tron_wallet)
                .await
                .map_err(|e| format!("get-usdt-balance failed for {tron_wallet}: {e:?}"))?;

            #[allow(clippy::cast_precision_loss)]
            let usdt: f64 = usdt_balance as f64 / 1_000_000.0;
            println!("{usdt}");
            Ok(())
        }

        Commands::SendTrx {
            from_mnemonic,
            from_account,
            from_address_index,
            to_tron_wallet,
            amount,
            trongrid_api_key,
            dry_run,
        } => {
            let client = build_client(trongrid_api_key)?;

            let (from_tron_wallet, from_wallet_secret_key) =
                mnemonic_to_tron_address_and_private_key(
                    from_mnemonic.as_str(),
                    "",
                    from_account,
                    from_address_index,
                );

            let amount_sun = usdt_to_sun_units(amount)?;

            let send_trx_response = client
                .send_trx(
                    &from_wallet_secret_key,
                    from_tron_wallet.as_str(),
                    to_tron_wallet.as_str(),
                    amount_sun,
                    dry_run,
                )
                .await
                .map_err(|e| format!("send-trx failed: {e:?}"))?;

            println!("{send_trx_response}");
            Ok(())
        }

        Commands::SendUSDT {
            from_mnemonic,
            from_account,
            from_address_index,
            to_tron_wallet,
            amount,
            trongrid_api_key,
            dry_run,
        } => {
            let client = build_client(trongrid_api_key)?;

            let (from_tron_wallet, from_wallet_secret_key) =
                mnemonic_to_tron_address_and_private_key(
                    from_mnemonic.as_str(),
                    "",
                    from_account,
                    from_address_index,
                );

            let amount_sun = usdt_to_sun_units(amount)?;

            let send_usdt_response = client
                .send_usdt(
                    &from_wallet_secret_key,
                    from_tron_wallet.as_str(),
                    to_tron_wallet.as_str(),
                    amount_sun as u128,
                    dry_run,
                )
                .await
                .map_err(|e| format!("send-usdt failed: {e:?}"))?;

            println!("{send_usdt_response}");
            Ok(())
        }
    }
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

fn build_client(trongrid_api_key: Option<String>) -> Result<TrongridClient, String> {
    TrongridClient::new(
        "https://api.trongrid.io",
        trongrid_api_key,
        Duration::from_secs(5),
    )
    .map_err(|e| format!("failed to create tron wallet client: {e}"))
}
