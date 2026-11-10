//! Dumps the ECDSA crate's results so the JavaScript visualizer can be diffed
//! against them.
//!
//! The visualizers in `docs/visualizers/` re-implement `Ecdsa` in JavaScript.
//! This example prints the Rust answers for the same inputs; the companion
//! script `docs/visualizers/assets/parity-check.mjs` recomputes them in
//! JavaScript and compares the two.
//!
//! ```text
//! cargo run --release --example parity_dump_ecdsa -p ecdsa
//! node docs/visualizers/assets/parity-check.mjs
//! ```
//!
//! The output file lands in `target/parity-dump-ecdsa.txt` and is not committed.

use ecdsa::{Ecdsa, small_curve};
use num_bigint::BigUint;
use std::fs;

fn b(n: u32) -> BigUint {
    BigUint::from(n)
}

fn main() {
    // The crate panics on invalid input; the visualizer mirrors that as a
    // "PANIC" marker, so silence the default hook while we probe.
    std::panic::set_hook(Box::new(|_| {}));

    let mut out = String::new();
    let c = small_curve();
    let order = c.order.to_u32_digits()[0];

    for d in 1..order {
        for k in 1..order {
            for message in ["parity", "Alice sends 1 BTC to Bob", ""] {
                let hash = Ecdsa::generate_hash_less_than(message, &c.order);
                let public = c.generate_public_key(&b(d));

                // `Ecdsa::verify` calls `EllipticCurve::add`, which asserts that
                // the two points differ. On the teaching curve u1·G and u2·Q
                // sometimes coincide, so verification can panic — the crate
                // does not guard against it. Both sides record "PANIC".
                let sign = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    c.sign(&hash, &b(d), &b(k))
                }));
                let (r, s) = match sign {
                    Ok(sig) => (sig.0, sig.1),
                    Err(_) => (BigUint::from(0u32), BigUint::from(0u32)),
                };

                let check = |h: &BigUint| match std::panic::catch_unwind(
                    std::panic::AssertUnwindSafe(|| c.verify(h, &public, &(r.clone(), s.clone()))),
                ) {
                    Ok(v) => format!("{}", v),
                    Err(_) => "PANIC".to_string(),
                };

                let valid = check(&hash);
                let tampered = check(&Ecdsa::generate_hash_less_than("tampered", &c.order));

                out.push_str(&format!(
                    "ecdsa {} {} {} {} {} {} {} {}\n",
                    message.len(),
                    d,
                    k,
                    hash,
                    r,
                    s,
                    valid,
                    tampered
                ));
            }
        }
    }

    let path = std::env::var("CARGO_TARGET_DIR")
        .map(|d| std::path::Path::new(&d).join("parity-dump-ecdsa.txt"))
        .unwrap_or_else(|_| std::path::Path::new("target").join("parity-dump-ecdsa.txt"));

    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    fs::write(&path, &out).expect("Could not write the parity dump");
    println!("Wrote {} ({} lines)", path.display(), out.lines().count());
}
