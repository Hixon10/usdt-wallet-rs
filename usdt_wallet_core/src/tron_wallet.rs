// ==========================================================
// BIP39 GENERATION LOGIC
// ==========================================================

use crate::wordlist::get_word;
use hmac::{Hmac, Mac};
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::rand_core::OsRng;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{NonZeroScalar, Scalar, SecretKey};
use pbkdf2::pbkdf2;
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};
use sha3::Keccak256;
use std::convert::TryInto;

// Type alias for HMAC-SHA512
type HmacSha512 = Hmac<Sha512>;

#[must_use]
pub fn generate_new_mnemonic() -> String {
    // 1. Generate 128 bits (16 bytes) of Entropy
    let mut entropy = [0u8; 16];
    OsRng.fill_bytes(&mut entropy);

    // 2. Calculate Checksum
    // SHA256(entropy), take first (ENT / 32) bits.
    // 128 / 32 = 4 bits.
    let hash = Sha256::digest(entropy);
    let checksum_byte = hash[0]; // We only need the top 4 bits of this byte

    // 3. Combine Entropy + Checksum
    // We create a buffer. 16 bytes entropy + 1 byte containing checksum.
    let mut combined = Vec::with_capacity(17);
    combined.extend_from_slice(&entropy);
    combined.push(checksum_byte);

    // 4. Split into 11-bit chunks and map to words
    // Total bits = 128 + 4 = 132 bits.
    // 132 / 11 = 12 words.
    let mut words: Vec<&str> = Vec::new();

    for i in 0..12 {
        // We need to extract 11 bits starting at bit offset (i * 11)
        let bit_offset = i * 11;
        let index = read_11_bits(&combined, bit_offset);

        words.push(get_word(index as usize));
    }

    words.join(" ")
}

// Helper to read 11 bits from a byte array at an arbitrary bit offset
fn read_11_bits(data: &[u8], bit_offset: usize) -> u16 {
    let byte_idx = bit_offset / 8;
    let bit_rem = bit_offset % 8;

    // We read 3 bytes to ensure we have enough coverage for 11 bits
    // (though 2 bytes is often enough, 3 covers the edge cases safely)
    let b0 = u32::from(data[byte_idx]);
    let b1 = if byte_idx + 1 < data.len() {
        u32::from(data[byte_idx + 1])
    } else {
        0
    };
    let b2 = if byte_idx + 2 < data.len() {
        u32::from(data[byte_idx + 2])
    } else {
        0
    };

    // Combine into a 24-bit window
    let window = (b0 << 16) | (b1 << 8) | b2;

    // We want the 11 bits starting at `bit_rem` from the MSB of the window.
    // Window width is 24.
    // We want to right-shift such that our 11 bits are at the bottom.
    // Shift = 24 - 11 - bit_rem = 13 - bit_rem
    let shift = 13 - bit_rem;

    ((window >> shift) & 0x7FF) as u16
}

// ==========================================================

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
    bs58::encode(&address_bytes).with_check().into_string()
}

// --- BIP39 Implementation ---

#[must_use]
pub fn mnemonic_to_tron_address_and_private_key(
    mnemonic: &str,
    passphrase: &str,
    address_index: u32,
) -> (String, SecretKey) {
    println!(" recovering TRC20 wallet...");

    // 1. BIP39: Mnemonic -> Seed
    let seed = mnemonic_to_seed(mnemonic, passphrase);
    println!("Seed calculated.");

    // 2. BIP32: Master Key Generation
    let (master_secret, chain_code) = master_key_from_seed(&seed);

    // 3. BIP44: Derive Path m/44'/195'/0'/0/0 (Tron standard)
    // 44' (Purpose) -> 195' (Tron Coin Type) -> 0' (Account) -> 0 (Change) -> 0 (Index)
    #[allow(clippy::unreadable_literal)]
    let path = [
        44 | 0x80000000,  // 44'  (Hardened: 44 | 0x80000000)
        195 | 0x80000000, // 195' (Hardened: 195 | 0x80000000)
        0x80000000,       // 0'   (Hardened: 0 | 0x80000000)
        0,                // 0    (External)
        address_index,    // 0    (Address Index)
    ];

    let mut current_sk: SecretKey = master_secret;
    let mut current_cc = chain_code;

    for &index in &path {
        let (next_sk, next_cc) = ckd_priv(&current_sk, &current_cc, index);
        current_sk = next_sk;
        current_cc = next_cc;
    }

    // 4. Output Results
    let private_key_hex = hex::encode(current_sk.to_bytes());
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

#[allow(clippy::expect_used)]
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

#[allow(clippy::expect_used)]
fn master_key_from_seed(seed: &[u8]) -> (SecretKey, [u8; 32]) {
    let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed").expect("HMAC init failed");
    mac.update(seed);
    let result = mac.finalize().into_bytes();

    let (secret_bytes, chain_code) = result.split_at(32);

    let secret_key = SecretKey::from_slice(secret_bytes).expect("Invalid seed for secp256k1");
    let chain_code_arr: [u8; 32] = chain_code.try_into().expect("Slice length error");

    (secret_key, chain_code_arr)
}

#[allow(clippy::unwrap_used)]
#[allow(clippy::expect_used)]
fn ckd_priv(parent_sk: &SecretKey, parent_cc: &[u8; 32], index: u32) -> (SecretKey, [u8; 32]) {
    let mut mac = HmacSha512::new_from_slice(parent_cc).expect("HMAC init failed");

    // Handle Hardened vs Normal derivation
    if index >= 0x8000_0000 {
        // Hardened: 0x00 || parent_priv_key || index
        mac.update(&[0x00]);
        mac.update(&parent_sk.to_bytes());
    } else {
        // Normal: parent_pub_key_compressed || index
        let pub_key = parent_sk.public_key();
        let pub_point = pub_key.to_encoded_point(true); // true = compressed
        mac.update(pub_point.as_bytes());
    }

    mac.update(&index.to_be_bytes());

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wordlist::WORDS;

    struct TestCase {
        mnemonic: &'static str,
        passphrase: &'static str,
        address_index: u32,
        expected_address: &'static str,
        expected_private_key_hex: &'static str,
    }

    #[test]
    fn mnemonic_to_tron_address_and_private_key_works_for_known_vectors() {
        let cases = [
            TestCase {
                mnemonic: "hungry into place frozen dice sail essay weird trust great any primary",
                passphrase: "",
                address_index: 0,
                expected_address: "TSQBcxmU7bYYztRBGJiL9PJxc5Pk99dnkc",
                expected_private_key_hex: "c5669bb6c9cb47a43cff130634cba7c9f6ff93b3608d02a5c8ff14993629bdf2",
            },
            TestCase {
                mnemonic: "core lecture blood old acoustic blame draft broccoli orange earn text crush",
                passphrase: "",
                address_index: 0,
                expected_address: "TEeJmK1dviuFeSjavQn4uPQTaSnEvywqUY",
                expected_private_key_hex: "f55827cbdbbf48ad11f0d27ca3051f803a182d1d38582f5a8d852d0729b0d463",
            },
            TestCase {
                mnemonic: "crouch project sunset display just excuse pulp mercy equal employ despair spirit",
                passphrase: "",
                address_index: 0,
                expected_address: "TSkjVcUSym3EWa2sJajjc8wLs387pCFCDD",
                expected_private_key_hex: "d67debb7b7121a9bb81d3643a24ddda50d1bb79aec3baf3f69da11bce9110d39",
            },
            TestCase {
                mnemonic: "bulk elegant gauge gold raw kit smile bamboo fragile twelve put sponsor",
                passphrase: "",
                address_index: 0,
                expected_address: "TYt9FKELbGU2woBRnX3sfMSdr8W7BPUGHA",
                expected_private_key_hex: "e51ba316ac90dc21cfd07ec8b4bf763520df4b6fa8ed1dcb84be17e5ad5387ef",
            },
            TestCase {
                mnemonic: "neglect cup token diagram vanish attack flame taste canyon warrior impulse fence",
                passphrase: "",
                address_index: 0,
                expected_address: "TJE8axEkLSZZ2jNHh5bJgfpSJCcsMSk8VK",
                expected_private_key_hex: "697e24e9ac8e22a09252ae0fa52b9e4463cb2681bec0550bc97eda175aaffc29",
            },
            TestCase {
                mnemonic: "twenty orange brand clerk other review gauge emerge unknown army away grit",
                passphrase: "",
                address_index: 0,
                expected_address: "TQNU2oVJDDJWUHQsR4eovuJerqc64wvjZi",
                expected_private_key_hex: "5a9af1e04cea61cf97a4e7ac57aa0d9347a2d99653b80958119dca185d1782af",
            },
            TestCase {
                mnemonic: "country position lady inflict alcohol broken off awesome poem shaft badge current",
                passphrase: "",
                address_index: 0,
                expected_address: "TW2U7X49anPe9X9e9npUQLoyi8DQQJMjat",
                expected_private_key_hex: "e035bfc7c540e60ac5c2695d153810505f5dee782d48b1860a09815209b40977",
            },
            TestCase {
                mnemonic: "country position lady inflict alcohol broken off awesome poem shaft badge current",
                passphrase: "",
                address_index: 4,
                expected_address: "TPgPUkb8M2NDLfoxwFicgJ95dK8PZYhisG",
                expected_private_key_hex: "27ea2f56ecca8dd42cbf0cad492c654bcf97bcca60d5711f553985d9ec8fc223",
            },
            TestCase {
                mnemonic: "country position lady inflict alcohol broken off awesome poem shaft badge current",
                passphrase: "",
                address_index: 1,
                expected_address: "TS1ub3AFNQ6jZguPd69LXYfZuu7ByaeZjW",
                expected_private_key_hex: "8b7cc6d401bb8f529322cf1196b1d201bafc3871db5733f7a45fcc7a8e364679",
            },
            TestCase {
                mnemonic: "merit inform happy chest stem opinion coil surprise alter sibling year rack",
                passphrase: "",
                address_index: 13,
                expected_address: "TBHje3Bo7gWXdnC3CPybKayBgesMzzCv5w",
                expected_private_key_hex: "d3dd8bd75ef332f6f600de56bfe4ed21111c62f8ff969d5b16b14aad1703d540",
            },
        ];

        for (i, case) in cases.iter().enumerate() {
            let (address, secret_key) = mnemonic_to_tron_address_and_private_key(
                case.mnemonic,
                case.passphrase,
                case.address_index,
            );
            let private_key_hex = hex::encode(secret_key.to_bytes());

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

    #[test]
    fn generated_mnemonic_has_12_valid_words() {
        let mnemonic = generate_new_mnemonic();

        let words: Vec<&str> = mnemonic.split_whitespace().collect();

        // Check word count
        assert_eq!(words.len(), 12, "Mnemonic must have 12 words");

        // Check each word is in WORDS
        for word in words {
            assert!(
                WORDS.contains(&word),
                "Word '{word}' is not in the WORDS list"
            );
        }

        // Verify that we can restore private key from it
        let (address, secret_key) =
            mnemonic_to_tron_address_and_private_key(mnemonic.as_str(), "", 0);
        let private_key_hex = hex::encode(secret_key.to_bytes());

        assert!(!address.is_empty(), "Restored address must not be empty");

        assert!(
            !private_key_hex.is_empty(),
            "Restored secret key must not be empty"
        );
    }

    #[test]
    fn generates_two_different_non_empty_mnemonics() {
        let mnemonic1 = generate_new_mnemonic();
        let mnemonic2 = generate_new_mnemonic();

        // Not empty
        assert!(
            !mnemonic1.trim().is_empty(),
            "First mnemonic must not be empty"
        );
        assert!(
            !mnemonic2.trim().is_empty(),
            "Second mnemonic must not be empty"
        );

        // Not equal
        assert_ne!(
            mnemonic1, mnemonic2,
            "Two generated mnemonics should not be equal"
        );
    }
}
