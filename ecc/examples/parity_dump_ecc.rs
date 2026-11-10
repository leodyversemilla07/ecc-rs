//! Dumps the crate's arithmetic results so the JavaScript visualizer can be
//! diffed against them.
//!
//! The visualizers in `docs/visualizers/` re-implement `FiniteField` and
//! `EllipticCurve` in JavaScript so they can animate the operations. This
//! example prints the Rust answers for the same inputs; the companion script
//! `docs/visualizers/assets/parity-check.mjs` recomputes them in JavaScript and
//! compares the two.
//!
//! ```text
//! cargo run --release --example parity_dump_ecc -p ecc
//! node docs/visualizers/assets/parity-check.mjs
//! ```
//!
//! The output file lands in `target/parity-dump-ecc.txt` and is not committed.
//! The `ecdsa` crate has its own example for the signature layer.

use ecc::{EllipticCurve, FiniteField, Point};
use num_bigint::BigUint;
use std::fs;

fn b(n: u32) -> BigUint {
    BigUint::from(n)
}

fn curve(p: u32, a: u32, bb: u32) -> EllipticCurve {
    EllipticCurve {
        a: b(a),
        b: b(bb),
        p: b(p),
    }
}

fn pt(x: u32, y: u32) -> Point {
    Point::Coordinate(b(x), b(y))
}

fn show(p: Point) -> String {
    match p {
        Point::Coordinate(x, y) => format!("{},{}", x, y),
        Point::Identity => "O".to_string(),
    }
}

fn main() {
    // The crate panics on invalid input; the visualizer mirrors that as a
    // "PANIC" marker, so silence the default hook while we probe.
    std::panic::set_hook(Box::new(|_| {}));

    let mut out = String::new();

    // ── FiniteField: every operation, every pair, for eleven primes ──
    for p in [2u32, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31] {
        for a in 0..p {
            for d in 0..p {
                let (pa, pd, pp) = (b(a), b(d), b(p));
                out.push_str(&format!(
                    "ff {} {} {} add {} sub {} mul {} invadd {} invmul {} div {}\n",
                    p,
                    a,
                    d,
                    FiniteField::add(&pa, &pd, &pp),
                    FiniteField::sub(&pa, &pd, &pp),
                    FiniteField::mul(&pa, &pd, &pp),
                    FiniteField::inverse_add(&pa, &pp),
                    FiniteField::inverse_mul(&pa, &pp),
                    FiniteField::div(&pa, &pd, &pp),
                ));
            }
        }
    }

    // ── EllipticCurve ──
    // The exhaustive point-addition sweep is p⁴ operations, so it is only run
    // for the small curves; the larger ones get a sampled sweep instead.
    for (p, a, bb) in [(17u32, 2u32, 2u32), (11, 2, 2), (23, 1, 1), (31, 5, 7), (17, 3, 0)] {
        let c = curve(p, a, bb);

        for x in 0..p {
            for y in 0..p {
                let q = pt(x, y);
                let on = c.on_curve(&q);
                let doubled = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    c.double(&q)
                })) {
                    Ok(v) => show(v),
                    Err(_) => "PANIC".to_string(),
                };
                out.push_str(&format!("curve {} {} {} on {} double {}\n", p, a, bb, on, doubled));
            }
        }

        if p <= 17 {
            for x1 in 0..p {
                for y1 in 0..p {
                    for x2 in 0..p {
                        for y2 in 0..p {
                            let c1 = pt(x1, y1);
                            let c2 = pt(x2, y2);
                            let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                c.add(&c1, &c2)
                            }));
                            let text = match res {
                                Ok(v) => show(v),
                                Err(_) => "PANIC".to_string(),
                            };
                            out.push_str(&format!(
                                "add {} {} {} {} {} {} {} {}\n",
                                p, a, bb, x1, y1, x2, y2, text
                            ));
                        }
                    }
                }
            }
        } else {
            for x1 in 0..p {
                for y1 in 0..p {
                    for x2 in 0..p {
                        let y2 = (x2 * 7 + y1) % p;
                        let c1 = pt(x1, y1);
                        let c2 = pt(x2, y2);
                        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            c.add(&c1, &c2)
                        }));
                        let text = match res {
                            Ok(v) => show(v),
                            Err(_) => "PANIC".to_string(),
                        };
                        out.push_str(&format!(
                            "add {} {} {} {} {} {} {} {}\n",
                            p, a, bb, x1, y1, x2, y2, text
                        ));
                    }
                }
            }
        }

        for k in 0..40u32 {
            for x in 0..p {
                for y in 0..p {
                    let g = pt(x, y);
                    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        c.multiply(&b(k), &g)
                    }));
                    let text = match res {
                        Ok(v) => show(v),
                        Err(_) => "PANIC".to_string(),
                    };
                    out.push_str(&format!("mul {} {} {} {} {} {} {}\n", p, a, bb, k, x, y, text));
                }
            }
        }
    }

    // ── ECDSA lives in the `ecdsa` crate; its dump is a separate example ──
    // See `ecdsa/examples/parity_dump.rs`.

    let path = std::env::var("CARGO_TARGET_DIR")
        .map(|d| std::path::Path::new(&d).join("parity-dump-ecc.txt"))
        .unwrap_or_else(|_| std::path::Path::new("target").join("parity-dump-ecc.txt"));

    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    fs::write(&path, &out).expect("Could not write the parity dump");
    println!("Wrote {} ({} lines)", path.display(), out.lines().count());
}
