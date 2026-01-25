// use hmac::{Hmac, Mac};
// use k256::elliptic_curve::sec1::ToEncodedPoint;
// use k256::{ProjectivePoint, Scalar, SecretKey};
// use pbkdf2::pbkdf2;
// use sha2::{Digest, Sha256, Sha512};
// use sha3::Keccak256;
// use std::convert::TryInto;
// use crate::hex;
//
// // Type alias for HMAC-SHA512
// type HmacSha512 = Hmac<Sha512>;
//
// fn main() {
//     // ==========================================
//     // PUT YOUR 12 WORDS HERE
//     // ==========================================
//     let mnemonic =
//         "attack define property output update mass farm never uniform search weasel relax";
//     let passphrase = ""; // Leave empty strictly unless you used one during creation
//     // ==========================================
//
//     println!("Starting recovery...");
//
//     // 1. Generate Seed (BIP39)
//     let seed = generate_seed(mnemonic, passphrase);
//     println!("Seed generated.");
//
//     // 2. Generate Master Key (BIP32 Root)
//     let (mut private_key, mut chain_code) = generate_master_key(&seed);
//
//     // 3. Derive Path: m / 44' / 195' / 0' / 0 / 0
//     // 44'  = Purpose (BIP44)
//     // 195' = Coin Type (Tron)
//     // 0'   = Account
//     // 0    = Change
//     // 0    = Index
//     let path: [u32; 5] = [
//         2147483648 + 44,  // 44'
//         2147483648 + 195, // 195'
//         2147483648 + 0,   // 0'
//         0,                // 0
//         0,                // 0
//     ];
//
//     println!("Deriving keys along path m/44'/195'/0'/0/0...");
//     for (i, &index) in path.iter().enumerate() {
//         let (next_sk, next_cc) = derive_child_key(&private_key, &chain_code, index);
//         private_key = next_sk;
//         chain_code = next_cc;
//         // println!("Derived level {}", i + 1);
//     }
//
//     // 4. Output Result
//     let pk_bytes = private_key.to_bytes();
//     let pk_hex = hex::encode(pk_bytes);
//     let address = derive_tron_address(&private_key);
//
//     println!("\n==========================================");
//     println!("RECOVERY SUCCESSFUL");
//     println!("==========================================");
//     println!("Private Key: {}", pk_hex);
//     println!("Address:     {}", address);
//     println!("==========================================\n");
// }
//
// /// BIP39: Converts Mnemonic + Passphrase into a 64-byte Seed using PBKDF2
// fn generate_seed(mnemonic: &str, passphrase: &str) -> [u8; 64] {
//     let salt = format!("mnemonic{}", passphrase);
//     let mut seed = [0u8; 64];
//
//     // PBKDF2 with HMAC-SHA512, 2048 iterations
//     pbkdf2::<HmacSha512>(mnemonic.as_bytes(), salt.as_bytes(), 2048, &mut seed)
//         .expect("PBKDF2 calculation failed");
//
//     seed
// }
//
// /// BIP32: Generate Master Key and ChainCode from Seed
// fn generate_master_key(seed: &[u8]) -> (SecretKey, [u8; 32]) {
//     let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed").unwrap();
//     mac.update(seed);
//     let result = mac.finalize().into_bytes();
//
//     let (secret_bytes, chain_code) = result.split_at(32);
//
//     let sk = SecretKey::from_slice(secret_bytes).expect("Invalid seed for secp256k1");
//     let cc: [u8; 32] = chain_code.try_into().unwrap();
//
//     (sk, cc)
// }
//
// /// BIP32: Child Key Derivation (CKD)
// /// Handles Hardened (> 2^31) and Normal derivation logic
// fn derive_child_key(
//     parent_sk: &SecretKey,
//     parent_cc: &[u8; 32],
//     index: u32,
// ) -> (SecretKey, [u8; 32]) {
//     let mut mac = HmacSha512::new_from_slice(parent_cc).unwrap();
//
//     if index >= 0x80000000 {
//         // Hardened Derivation: data = 0x00 || parent_private_key || index
//         mac.update(&[0x00]);
//         mac.update(&parent_sk.to_bytes());
//         mac.update(&index.to_be_bytes());
//     } else {
//         // Normal Derivation: data = parent_public_key (compressed) || index
//         let pub_key = parent_sk.public_key();
//         let pub_point = pub_key.to_encoded_point(true); // true = compressed (33 bytes)
//         mac.update(pub_point.as_bytes());
//         mac.update(&index.to_be_bytes());
//     }
//
//     let result = mac.finalize().into_bytes();
//     let (tweak_bytes, next_cc) = result.split_at(32);
//
//     // BIP32 Math: Child_Priv = (Parent_Priv + Left_Hmac_Output) % Group_Order
//     let tweak = Scalar::from_repr(*k256::FieldBytes::from_slice(tweak_bytes)).unwrap();
//     let next_sk = parent_sk.add_tweak(&tweak).expect("Tweak addition failed");
//
//     let next_cc_arr: [u8; 32] = next_cc.try_into().unwrap();
//
//     (next_sk, next_cc_arr)
// }
//
// /// Tron Address Logic: Keccak256 -> Base58Check
// fn derive_tron_address(sk: &SecretKey) -> String {
//     // 1. Get Public Key (Uncompressed: 65 bytes, starts with 0x04)
//     let pk = sk.public_key();
//     let encoded = pk.to_encoded_point(false);
//     let pk_bytes = encoded.as_bytes();
//
//     // 2. Discard first byte (0x04), keep X and Y (64 bytes)
//     let raw_pub = &pk_bytes[1..];
//
//     // 3. Keccak-256 Hash (NOTE: Standard Ethereum/Tron use Keccak, not SHA3)
//     let mut hasher = Keccak256::new();
//     hasher.update(raw_pub);
//     let hash = hasher.finalize();
//
//     // 4. Take last 20 bytes
//     let last_20 = &hash[12..];
//
//     // 5. Prepend 0x41 (Tron Version Byte)
//     let mut address_bytes = Vec::with_capacity(21);
//     address_bytes.push(0x41);
//     address_bytes.extend_from_slice(last_20);
//
//     // 6. Base58Check Encode
//     base58_check_encode(&address_bytes)
// }
//
// /// Base58Check: Base58( Payload + DoubleSHA256(Payload)[0..4] )
// fn base58_check_encode(payload: &[u8]) -> String {
//     // 1. Calculate Checksum (Double SHA256)
//     let h1 = Sha256::digest(payload);
//     let h2 = Sha256::digest(h1);
//     let checksum = &h2[0..4];
//
//     // 2. Append Checksum
//     let mut final_bytes = payload.to_vec();
//     final_bytes.extend_from_slice(checksum);
//
//     // 3. Base58 Encode
//     base58_encode(&final_bytes)
// }
//
// /// Manual Base58 Encoder (Avoids external crate)
// fn base58_encode(input: &[u8]) -> String {
//     let alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
//     let mut output = Vec::new();
//
//     // Count leading zeros
//     let mut zeros = 0;
//     while zeros < input.len() && input[zeros] == 0 {
//         zeros += 1;
//     }
//
//     // Convert byte array to big integer, then mod 58
//     let mut size = (input.len() - zeros) * 138 / 100 + 1;
//     let mut buffer = vec![0u8; size];
//
//     let mut length = 0;
//     for &byte in &input[zeros..] {
//         let mut carry = byte as u32;
//         let mut i = 0;
//
//         // bignum = bignum * 256 + byte
//         while i < length || carry != 0 {
//             if i == size {
//                 size += 1;
//                 buffer.push(0);
//             }
//             let val = (buffer[i] as u32) * 256 + carry;
//             buffer[i] = (val % 58) as u8;
//             carry = val / 58;
//             i += 1;
//         }
//         length = i;
//     }
//
//     // Append '1' for each leading zero byte
//     for _ in 0..zeros {
//         output.push(alphabet[0] as char);
//     }
//     // Append the calculated base58 characters (reversed)
//     for i in (0..length).rev() {
//         output.push(alphabet[buffer[i] as usize] as char);
//     }
//
//     output.into_iter().collect()
// }
