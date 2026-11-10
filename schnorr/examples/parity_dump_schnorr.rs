//! Dumps the crate's Schnorr results so the JavaScript visualizer can be
//! diffed against them.
//!
//! The visualizers re-implement BIP-340 in JavaScript. This example prints
//! the Rust answers for the same inputs; the companion script
//! `visualizers/assets/parity-check.mjs` recomputes them in JavaScript and
//! compares the two.
//!
//! ```text
//! cargo run --release --example parity_dump_schnorr -p schnorr
//! node visualizers/assets/parity-check.mjs
//! ```
//!
//! The output file lands in `target/parity-dump-schnorr.txt` and is not
//! committed.

use num_bigint::BigUint;
use schnorr::Schnorr;
use std::fs;

fn main() {
    // The crate panics on invalid input; the visualizer mirrors that as a
    // "PANIC" marker, so silence the default hook while we probe.
    std::panic::set_hook(Box::new(|_| {}));

    let mut out = String::new();

    for (name, schnorr) in [
        ("teaching", Schnorr::teaching()),
        ("secp256k1", Schnorr::secp256k1()),
    ] {
        // The teaching curve is small enough to sweep exhaustively; on
        // secp256k1 a handful of keys is enough to exercise every branch.
        let keys: Vec<u32> = if name == "teaching" {
            (1..=18).collect()
        } else {
            vec![1, 2, 3, 7, 42, 12345]
        };
        let messages: Vec<&[u8]> = vec![b"", b"a", b"Alice sends 1 BTC to Bob"];

        for d in &keys {
            let secret_key = BigUint::from(*d);

            let public_key = match schnorr.public_key(&secret_key) {
                Ok(key) => key,
                Err(_) => {
                    out.push_str(&format!("schnorr {name} {d} pk PANIC\n"));
                    continue;
                }
            };
            out.push_str(&format!("schnorr {name} {d} pk {public_key}\n"));

            for (mi, message) in messages.iter().enumerate() {
                let signature = match schnorr.sign(&secret_key, message, None) {
                    Ok(signature) => signature,
                    Err(_) => {
                        out.push_str(&format!("schnorr {name} {d} {mi} sig PANIC\n"));
                        continue;
                    }
                };
                out.push_str(&format!(
                    "schnorr {name} {d} {mi} sig {} {}\n",
                    signature.r, signature.s
                ));

                let valid = schnorr.verify(&public_key, message, &signature);
                let tampered = schnorr.verify(&public_key, b"different", &signature);

                let mut broken = signature.clone();
                broken.r = (broken.r + BigUint::from(1u32)) % &schnorr.order;
                let broken_valid = schnorr.verify(&public_key, message, &broken);

                out.push_str(&format!(
                    "schnorr {name} {d} {mi} ver {valid} {tampered} {broken_valid}\n"
                ));
            }
        }
    }

    let path = std::env::var("CARGO_TARGET_DIR")
        .map(|d| std::path::Path::new(&d).join("parity-dump-schnorr.txt"))
        .unwrap_or_else(|_| std::path::Path::new("target").join("parity-dump-schnorr.txt"));

    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    fs::write(&path, &out).expect("Could not write the parity dump");
    println!("Wrote {} ({} lines)", path.display(), out.lines().count());
}
