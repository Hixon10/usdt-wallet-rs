use hmac::{Hmac, Mac};
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{NonZeroScalar, Scalar, SecretKey};
use pbkdf2::pbkdf2;
use sha2::{Digest, Sha256, Sha512};
use sha3::Keccak256;
use std::convert::TryInto;

// Type alias for HMAC-SHA512
type HmacSha512 = Hmac<Sha512>;

fn main() {
    // --- INPUT YOUR 12 WORDS HERE ---

    let mnemonic = "hungry into place frozen dice sail essay weird trust great any primary";
    let passphrase = ""; // Leave empty unless you specifically set one
    // --------------------------------

    mnemonic_to_tron_address_and_private_key(mnemonic, passphrase);
}

fn private_key_to_tron_address(secret_key: &SecretKey) -> String {
    // 1. Get the Public Key from the Private Key
    let public_key = secret_key.public_key();

    // 2. Serialize to UNCOMPRESSED format (65 bytes: 0x04 + X + Y)
    // Tron/Ethereum use uncompressed keys for address generation.
    let encoded_point = public_key.to_encoded_point(false);
    let encoded_bytes = encoded_point.as_bytes();

    // 3. Drop the first byte (0x04) to get the raw 64-byte public key (X + Y)
    let raw_public_key = &encoded_bytes[1..];

    // 4. Hash the raw public key using Keccak-256
    let mut hasher = Keccak256::new();
    hasher.update(raw_public_key);
    let hash = hasher.finalize();

    // 5. Take the last 20 bytes of the hash (this is the "Pub Key Hash")
    let last_20_bytes = &hash[12..];

    // 6. Prepend 0x41 (The Tron Version Byte)
    // 0x41 corresponds to 'T' in base58, ensuring addresses start with T.
    let mut address_bytes = Vec::with_capacity(21);
    address_bytes.push(0x41);
    address_bytes.extend_from_slice(last_20_bytes);

    // 7. Encode using Base58Check
    base58_check_encode(&address_bytes)
}

// --- Helper Functions for Encoding ---

// Manual Base58 implementation (No external crate)
fn encode_base58(input: &[u8]) -> String {
    let alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut output = Vec::new();

    // Count leading zeros (Base58 preserves leading zero bytes as '1')
    let mut zeros = 0;
    while zeros < input.len() && input[zeros] == 0 {
        zeros += 1;
    }

    // Convert byte array to a big integer representation
    // Estimate size: log(256) / log(58) is approx 1.37
    let size = (input.len() - zeros) * 138 / 100 + 1;
    let mut buffer = vec![0u8; size];

    let mut length = 0;
    for &byte in &input[zeros..] {
        let mut carry = u32::from(byte);
        let mut i = 0;

        // Perform (buffer * 256) + byte
        // We iterate specifically over the active part of the buffer
        while i < length || carry != 0 {
            if i >= buffer.len() {
                buffer.push(0);
            }
            let val = u32::from(buffer[i]) * 256 + carry;
            buffer[i] = (val % 58) as u8;
            carry = val / 58;
            i += 1;
        }
        length = i;
    }

    // Add leading '1's for zero bytes
    for _ in 0..zeros {
        output.push(alphabet[0] as char);
    }

    // Add the converted digits (in reverse order)
    for i in (0..length).rev() {
        output.push(alphabet[buffer[i] as usize] as char);
    }

    output.into_iter().collect()
}

// --- BIP39 Implementation ---

fn mnemonic_to_tron_address_and_private_key(
    mnemonic: &str,
    passphrase: &str,
) -> (String, SecretKey) {
    println!(" recovering TRC20 wallet...");

    // 1. BIP39: Mnemonic -> Seed
    let seed = mnemonic_to_seed(mnemonic, passphrase);
    println!("Seed calculated.");

    // 2. BIP32: Master Key Generation
    let (master_secret, chain_code) = master_key_from_seed(&seed);

    // 3. BIP44: Derive Path m/44'/195'/0'/0/0 (Tron standard)
    // 44' (Purpose) -> 195' (Tron Coin Type) -> 0' (Account) -> 0 (Change) -> 0 (Index)
    let path = [
        2147483692, // 44'  (Hardened: 44 | 0x80000000)
        2147483843, // 195' (Hardened: 195 | 0x80000000)
        2147483648, // 0'   (Hardened: 0 | 0x80000000)
        0,          // 0    (External)
        0,          // 0    (Address Index)
    ];

    let mut current_sk: SecretKey = master_secret;
    let mut current_cc = chain_code;

    for &index in &path {
        let (next_sk, next_cc) = ckd_priv(&current_sk, &current_cc, index);
        current_sk = next_sk;
        current_cc = next_cc;
    }

    // 4. Output Results
    let private_key_hex = hex::encode(&current_sk.to_bytes());
    let tron_wallet_address: String = private_key_to_tron_address(&current_sk);

    // Get the Public Key object
    let public_key = current_sk.public_key();
    // 2. Get Uncompressed Hex (Standard for Tron/Eth)
    // 'false' means uncompressed
    let uncompressed_point = public_key.to_encoded_point(false);
    let pub_key_hex = hex::encode(uncompressed_point.as_bytes());

    // 3. Prepare Compressed Key (For display/comparison with your expected value)
    // 'true' asks for the compressed format (33 bytes, starts with 02 or 03)
    let compressed_point = public_key.to_encoded_point(true);
    let compressed_public_hex = hex::encode(compressed_point.as_bytes());

    println!("--------------------------------------------------");
    println!("TRON (TRC20) Wallet Recovered");
    println!("--------------------------------------------------");
    println!("Private Key: {private_key_hex}");
    println!("Public Key: {pub_key_hex}");
    println!("Public Key (Compressed): {compressed_public_hex}");
    println!("Tron Address:     {tron_wallet_address}");
    println!("--------------------------------------------------");
    println!("Import this Private Key into TronLink or TrustWallet to access USDT.");

    (tron_wallet_address, current_sk)
}

fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> [u8; 64] {
    let salt_prefix = "mnemonic";
    let salt = format!("{salt_prefix}{passphrase}");
    let mut seed = [0u8; 64];

    // BIP39 uses PBKDF2 with HMAC-SHA512, 2048 rounds
    pbkdf2::<HmacSha512>(mnemonic.as_bytes(), salt.as_bytes(), 2048, &mut seed)
        .expect("PBKDF2 failed");

    seed
}

// --- BIP32 Implementation (HD Wallet) ---

fn master_key_from_seed(seed: &[u8]) -> (SecretKey, [u8; 32]) {
    let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed").expect("HMAC init failed");
    mac.update(seed);
    let result = mac.finalize().into_bytes();

    let (secret_bytes, chain_code) = result.split_at(32);

    let secret_key = SecretKey::from_slice(secret_bytes).expect("Invalid seed for secp256k1");
    let chain_code_arr: [u8; 32] = chain_code.try_into().expect("Slice length error");

    (secret_key, chain_code_arr)
}

fn ckd_priv(parent_sk: &SecretKey, parent_cc: &[u8; 32], index: u32) -> (SecretKey, [u8; 32]) {
    let mut mac = HmacSha512::new_from_slice(parent_cc).expect("HMAC init failed");

    // Handle Hardened vs Normal derivation
    if index >= 0x80000000 {
        // Hardened: 0x00 || parent_priv_key || index
        mac.update(&[0x00]);
        mac.update(&parent_sk.to_bytes());
        mac.update(&index.to_be_bytes());
    } else {
        // Normal: parent_pub_key_compressed || index
        let pub_key = parent_sk.public_key();
        let pub_point = pub_key.to_encoded_point(true); // true = compressed
        mac.update(pub_point.as_bytes());
        mac.update(&index.to_be_bytes());
    }

    let result = mac.finalize().into_bytes();
    let (tweak_bytes, next_cc) = result.split_at(32);

    // --- FIX STARTS HERE ---

    // 1. Convert the tweak (HMAC output) into a Scalar
    // from_repr returns a CtOption (Constant Time Option), we simplify with unwrap (conceptually)
    let tweak_scalar = Option::<Scalar>::from(Scalar::from_repr(*k256::FieldBytes::from_slice(
        tweak_bytes,
    )))
    .expect("Tweak is not a valid scalar");

    // 2. Convert the Parent Secret Key into a NonZeroScalar
    let parent_scalar = parent_sk.to_nonzero_scalar();

    // 3. Perform the addition: (Parent + Tweak) % CurveOrder
    // The Add implementation for NonZeroScalar handles the modular arithmetic for us.
    let child_scalar = *parent_scalar + tweak_scalar;

    // 4. Convert back to SecretKey
    // It is mathematically possible (but astronomically unlikely) for the result to be zero.
    let next_sk_scalar = NonZeroScalar::new(child_scalar).expect("Child key is zero (invalid)");
    let next_sk = SecretKey::from(next_sk_scalar);

    // --- FIX ENDS HERE ---

    let next_cc_arr: [u8; 32] = next_cc.try_into().unwrap();

    (next_sk, next_cc_arr)
}

// --- TRON Address Logic (Keccak + Base58Check) ---

fn base58_check_encode(payload: &[u8]) -> String {
    // 1. Calculate the checksum: Double SHA256
    let hash1 = Sha256::digest(payload);
    let hash2 = Sha256::digest(hash1);

    // 2. Take the first 4 bytes as the checksum
    let checksum = &hash2[0..4];

    // 3. Append checksum to the end of the data
    let mut full_payload = payload.to_vec();
    full_payload.extend_from_slice(checksum);

    // 4. Convert to Base58 string
    encode_base58(&full_payload)
}

// Helper for hex printing
mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestCase {
        mnemonic: &'static str,
        passphrase: &'static str,
        expected_address: &'static str,
        expected_private_key_hex: &'static str,
    }

    #[test]
    fn mnemonic_to_tron_address_and_private_key_works_for_known_vectors() {
        let cases = vec![
            TestCase {
                mnemonic: "hungry into place frozen dice sail essay weird trust great any primary",
                passphrase: "",
                expected_address: "TSQBcxmU7bYYztRBGJiL9PJxc5Pk99dnkc",
                expected_private_key_hex: "c5669bb6c9cb47a43cff130634cba7c9f6ff93b3608d02a5c8ff14993629bdf2",
            },
            TestCase {
                mnemonic: "core lecture blood old acoustic blame draft broccoli orange earn text crush",
                passphrase: "",
                expected_address: "TEeJmK1dviuFeSjavQn4uPQTaSnEvywqUY",
                expected_private_key_hex: "f55827cbdbbf48ad11f0d27ca3051f803a182d1d38582f5a8d852d0729b0d463",
            },
            TestCase {
                mnemonic: "crouch project sunset display just excuse pulp mercy equal employ despair spirit",
                passphrase: "",
                expected_address: "TSkjVcUSym3EWa2sJajjc8wLs387pCFCDD",
                expected_private_key_hex: "d67debb7b7121a9bb81d3643a24ddda50d1bb79aec3baf3f69da11bce9110d39",
            },
            TestCase {
                mnemonic: "bulk elegant gauge gold raw kit smile bamboo fragile twelve put sponsor",
                passphrase: "",
                expected_address: "TYt9FKELbGU2woBRnX3sfMSdr8W7BPUGHA",
                expected_private_key_hex: "e51ba316ac90dc21cfd07ec8b4bf763520df4b6fa8ed1dcb84be17e5ad5387ef",
            },
            TestCase {
                mnemonic: "neglect cup token diagram vanish attack flame taste canyon warrior impulse fence",
                passphrase: "",
                expected_address: "TJE8axEkLSZZ2jNHh5bJgfpSJCcsMSk8VK",
                expected_private_key_hex: "697e24e9ac8e22a09252ae0fa52b9e4463cb2681bec0550bc97eda175aaffc29",
            },
            TestCase {
                mnemonic: "twenty orange brand clerk other review gauge emerge unknown army away grit",
                passphrase: "",
                expected_address: "TQNU2oVJDDJWUHQsR4eovuJerqc64wvjZi",
                expected_private_key_hex: "5a9af1e04cea61cf97a4e7ac57aa0d9347a2d99653b80958119dca185d1782af",
            },
        ];

        for (i, case) in cases.iter().enumerate() {
            let (address, secret_key) =
                mnemonic_to_tron_address_and_private_key(case.mnemonic, case.passphrase);
            let private_key_hex = hex::encode(&secret_key.to_bytes());

            assert_eq!(
                address, case.expected_address,
                "failed address on case #{i}"
            );
            assert_eq!(
                private_key_hex, case.expected_private_key_hex,
                "failed private key on case #{i}"
            );
        }
    }
}
