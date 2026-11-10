//! Command-line demonstration of BIP-340 Schnorr signatures on top of the
//! `ecc` library.
//!
//! Usage:
//!
//! ```text
//! cargo run -p schnorr                          # the teaching curve (fast)
//! cargo run -p schnorr -- --secp256k1           # the real Bitcoin curve
//! cargo run -p schnorr -- --secp256k1 "hello"   # sign a custom message
//! ```

use num_bigint::BigUint;
use rand::RngCore;
use rand::thread_rng;
use schnorr::{Schnorr, Signature};
use std::env;

fn describe(value: &BigUint) -> String {
    format!("{value}")
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    let use_secp = args.iter().any(|a| a == "--secp256k1");
    let message = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .cloned()
        .unwrap_or_else(|| "Alice sends 1 BTC to Bob".to_string());

    let schnorr = if use_secp {
        Schnorr::secp256k1()
    } else {
        Schnorr::teaching()
    };

    let curve_name = if use_secp {
        "secp256k1: y^2 = x^3 + 7"
    } else {
        "teaching curve: y^2 = x^3 + 10 (mod 19)"
    };

    println!("=== BIP-340 Schnorr ===");
    println!("Curve:   {curve_name}");
    println!("Message: {message}\n");

    // 1. Key generation: the public key is the x-coordinate of d*G.
    let mut secret_key_bytes = [0u8; 32];
    thread_rng().fill_bytes(&mut secret_key_bytes);
    let secret_key = BigUint::from_bytes_be(&secret_key_bytes);
    let secret_key = secret_key % &schnorr.order;
    let secret_key = if secret_key == BigUint::from(0u32) {
        BigUint::from(1u32)
    } else {
        secret_key
    };

    let public_key = match schnorr.public_key(&secret_key) {
        Ok(key) => key,
        Err(error) => {
            eprintln!("Could not derive the public key: {error}");
            std::process::exit(1);
        }
    };

    println!("Secret key d = {}", describe(&secret_key));
    println!(
        "Public key  = {}",
        hex::encode(schnorr::encoding::encode_field_element(&public_key))
    );
    println!();

    // 2. Signing. The auxiliary randomness is 32 fresh bytes.
    let mut aux = [0u8; 32];
    thread_rng().fill_bytes(&mut aux);

    let signature: Signature = match schnorr.sign(&secret_key, message.as_bytes(), Some(&aux)) {
        Ok(signature) => signature,
        Err(error) => {
            eprintln!("Could not sign: {error}");
            std::process::exit(1);
        }
    };

    println!("Signature (64 bytes) =");
    println!("  {}", signature.to_hex());
    println!("  r = {}", describe(&signature.r));
    println!("  s = {}", describe(&signature.s));
    println!();

    // 3. Verification.
    let valid = schnorr.verify(&public_key, message.as_bytes(), &signature);
    println!("Verify original message:  {valid}");

    let tampered = format!("{message} (tampered)");
    let tampered_ok = schnorr.verify(&public_key, tampered.as_bytes(), &signature);
    println!("Verify tampered message:  {tampered_ok}");

    let mut tampered_signature = signature.clone();
    tampered_signature.r = (tampered_signature.r + BigUint::from(1u32)) % &schnorr.order;
    let tampered_ok = schnorr.verify(&public_key, message.as_bytes(), &tampered_signature);
    println!("Verify tampered signature: {tampered_ok}");
}
