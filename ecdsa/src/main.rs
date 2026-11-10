//! Command-line demonstration of ECDSA on top of the `ecc` library.
//!
//! Usage:
//!
//! ```text
//! cargo run -p ecdsa                          # small teaching curve (fast)
//! cargo run -p ecdsa -- --secp256k1           # real Bitcoin curve
//! cargo run -p ecdsa -- --secp256k1 "hello"   # sign a custom message
//! ```
//!
//! secp256k1 uses 256-bit scalars and is noticeably slow in a debug build; run
//! it with `--release` for a pleasant experience.

use ecc::Point;
use ecdsa::{Ecdsa, secp256k1, small_curve};
use num_bigint::BigUint;
use std::env;

fn describe(point: &Point) -> String {
    match point {
        Point::Coordinate(x, y) => format!("({x},\n     {y})"),
        Point::Identity => "O (point at infinity)".to_string(),
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    let use_secp256k1 = args.iter().any(|a| a == "--secp256k1");
    let message = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .cloned()
        .unwrap_or_else(|| "Alice sends 1 BTC to Bob".to_string());

    let ecdsa: Ecdsa = if use_secp256k1 {
        secp256k1()
    } else {
        small_curve()
    };

    let curve_name = if use_secp256k1 {
        "secp256k1: y^2 = x^3 + 7 (mod p)"
    } else {
        "teaching curve: y^2 = x^3 + 2x + 2 (mod 17)"
    };

    println!("=== ECDSA ===");
    println!("Curve:   {curve_name}");
    println!("Message: {message}\n");

    // 1. Key generation: Q = d G
    let (private_key, public_key) = ecdsa.generate_key_pair();
    println!("Private key d = {private_key}");
    println!("Public key  Q = {}", describe(&public_key));
    println!();

    // 2. Signing: s = k^-1 (H(M) + r d) mod n.
    // Standard ECDSA requires a new nonce whenever r = 0 or s = 0.
    let hash = Ecdsa::generate_hash_less_than(&message, &ecdsa.order);
    let zero = BigUint::from(0u32);
    let (k, signature) = loop {
        let k = ecdsa.generate_random_positive(&ecdsa.order);
        let signature = ecdsa.sign(&hash, &private_key, &k);
        if signature.0 != zero && signature.1 != zero {
            break (k, signature);
        }
    };

    println!("Hash H(M) = {hash}");
    println!("Nonce k   = {k}");
    println!("Signature (r, s) =");
    println!("  r = {}", signature.0);
    println!("  s = {}", signature.1);
    println!();

    // 3. Verification
    let valid = ecdsa.verify(&hash, &public_key, &signature);
    println!("Verify original message:  {valid}");

    let tampered = format!("{message} (tampered)");
    let tampered_hash = Ecdsa::generate_hash_less_than(&tampered, &ecdsa.order);
    let tampered_message_ok = ecdsa.verify(&tampered_hash, &public_key, &signature);
    println!("Verify tampered message:  {tampered_message_ok}");

    let tampered_signature = ((&signature.0 + 1u32) % &ecdsa.order, signature.1.clone());
    let tampered_signature_ok = ecdsa.verify(&hash, &public_key, &tampered_signature);
    println!("Verify tampered signature: {tampered_signature_ok}");
}
