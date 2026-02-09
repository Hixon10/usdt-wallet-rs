# Tether USDT TRC20 (Tron) Wallet

This tool provides a suite of commands to interact with a USDT TRC20 Wallet via
a [Web UI](https://hixon10.github.io/usdt-wallet-rs/) (via WASM), or CLI.

**Privacy Note**: The WASM UI works entirely locally. Data is sent to the network (https://api.trongrid.io) only
when necessary (e.g., to query balances or broadcast a signed transaction).

## Features

1. Generate Wallet: Create a new `public + private` key pair and the corresponding 12-word mnemonic phrase (
   see [BIP-0039](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)).
2. Restore Wallet: Convert a mnemonic phrase into a Base58 Tron wallet address.
3. Check TRX Balance: View the TRX balance for a specific wallet.
4. Check USDT Balance: View the USDT balance for a specific wallet.
5. Send TRX: Transfer TRX to another wallet.
6. Send USDT: Transfer USDT to another Tron wallet.

## CLI Usage & Examples

You can run the CLI tool using `cargo`. Below are examples for common operations.

### 1. General Help

```bash
cargo run -p cli -- help
```

### 2. Generate Mnemonic

Generate a new mnemonic phrase (along with public and private keys).

```bash
cargo run -p cli -- generate-mnemonic
```

### 3. Recover TRON Wallet Address

Convert an existing mnemonic phrase to a Base58 Tron wallet address.

```bash
cargo run -p cli -- convert-mnemonic-to-wallet "flip depart foam toward horn snap welcome man stadium pattern sketch subject"
```

### 4. Check Balances

**Get TRX Balance:**

```bash
cargo run -p cli -- get-trx-balance TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t
```

**Get USDT Balance:**
You can optionally provide a TronGrid API Key for better rate limits.

```bash
cargo run -p cli -- get-usdt-balance TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t --trongrid-api-key <YOUR_API_KEY>
```

### 5. Send Funds

> **Note:** Use the `--dry-run` flag to simulate the transaction without broadcasting it to the network.

**Send TRX:**

```bash
cargo run -p cli -- send-trx \
  --from-mnemonic "<YOUR_MNEMONIC_PHRASE>" \
  --to-tron-wallet <RECIPIENT_WALLET_ADDRESS> \
  --amount 0.01 \
  --dry-run
```

**Send USDT:**

```bash
cargo run -p cli -- send-usdt \
  --from-mnemonic "<YOUR_MNEMONIC_PHRASE>" \
  --to-tron-wallet <RECIPIENT_WALLET_ADDRESS> \
  --amount 0.03 \
  --dry-run
```
