# ecc-rs

Rust implementation of the **Elliptic Curve Cryptography** course transcript in
this repository. The code follows the lessons step by step: finite fields →
elliptic curve arithmetic → ECDSA.

The course transcript itself lives in a **private** repository,
[`ecc-rs-transcript`](https://github.com/leodyversemilla07/ecc-rs-transcript).
This repository holds the code and the [visualizers](#visualizers).

## Workspace layout

```text
ecc/                 library crate: the elliptic curve "pyramid"
  src/lib.rs         re-exports the public types
  src/point.rs       Point::{Coordinate, Identity}
  src/finite_field.rs FiniteField (add/sub/mul/div/inverse_*)
  src/elliptic_curve.rs EllipticCurve (on_curve/add/double/multiply)
  src/secp256k1.rs   the standard secp256k1 parameters
  examples/          parity dump used to check the visualizers
ecdsa/               application crate built on `ecc`
  src/lib.rs         Ecdsa (key generation, sign, verify) + secp256k1
  src/main.rs        command-line demonstration
  examples/          parity dump used to check the visualizers
schnorr/             BIP-340 Schnorr signatures built on `ecc`
  src/lib.rs         Schnorr (public_key/sign/verify/lift_x)
  src/main.rs        command-line demonstration
  examples/          parity dump used to check the visualizers
visualizers/         static site: four interactive pages (no build step)
```

| Layer | Transcript lessons |
| --- | --- |
| Group & number theory | 2–12 |
| Elliptic curve theory | 13–15 |
| Finite fields | 16–18 |
| Point & curve operations | 19–27 |
| Double-and-add scalar multiplication | 23–26 |
| ECDSA key generation / sign / verify | 28–35 |

## Usage

```sh
# fast teaching curve y^2 = x^3 + 2x + 2 (mod 17)
cargo run -p ecdsa

# real 256-bit secp256k1 curve (use --release)
cargo run --release -p ecdsa -- --secp256k1 "Bob sends two bitcoins to Alice"

# BIP-340 Schnorr signatures
cargo run -p schnorr
cargo run --release -p schnorr -- --secp256k1 "Bob sends two bitcoins to Alice"
```

## Visualizers

Four interactive pages show the mathematics behind the code. They are plain
HTML with no build step.

**Live site:** <https://leodyversemilla07.github.io/ecc-rs/>

| Page | Covers |
| --- | --- |
| [Finite field operations](visualizers/finite-field.html) | `FiniteField` — add/sub/mul/div, both inverses, Fermat's little theorem, modulo for big numbers |
| [Elliptic curve operations](visualizers/point-arithmetic.html) | `EllipticCurve` — `on_curve`, `add`, `double`, `multiply`, the double-and-add ladder |
| [ECDSA](visualizers/ecdsa.html) | `Ecdsa` — key generation, signing, verification, and why verification works |
| [Schnorr](visualizers/schnorr.html) | `Schnorr` — BIP-340 signing and verification, the x-only public key, the even-y convention |

Each page mirrors the Rust line by line: the code shown next to the animation
is generated from the real files in this repository, and the arithmetic is a
JavaScript re-implementation of the crate that is checked against it.

```sh
# regenerate the Rust source snapshots shown in the pages
node visualizers/assets/sync-rs-source.mjs

# check the JavaScript against the crate (run the Rust dumps first)
cargo run --release --example parity_dump_ecc -p ecc
cargo run --release --example parity_dump_ecdsa -p ecdsa
cargo run --release --example parity_dump_schnorr -p schnorr
node visualizers/assets/parity-check.mjs

# publish the pages to GitHub Pages
node visualizers/assets/publish.mjs
```

See [`visualizers/README.md`](visualizers/README.md) for details.

## Tests

```sh
cargo test                                  # fast unit tests
cargo test --release -- --ignored           # 256-bit secp256k1 stress tests
cargo test --release -p schnorr --test vectors   # the official BIP-340 vectors
```

The secp256k1 tests are ignored by default because scalar multiplication
performs 256-bit modular inverses and is slow in a debug build.

## Notes

- Arithmetic uses `num-bigint` `BigUint`, so the same code handles small
  teaching numbers and 256-bit cryptography.
- `FiniteField::inverse_mul` uses Fermat's little theorem and assumes a prime
  modulus.
- `Ecdsa::sign` takes the nonce `k` from the caller; standard ECDSA requires a
  fresh `k` whenever `r = 0` or `s = 0` (the CLI retries).
- `Ecdsa::verify` calls `EllipticCurve::add`, which asserts that its two
  points differ. On a curve as small as the teaching one, `u₁·G` and `u₂·Q`
  coincide for roughly one nonce in nineteen, and the crate panics instead of
  returning false. The ECDSA visualizer reproduces this.
- `EllipticCurve::multiply` handles the case where the double-and-add ladder
  lands on the base point again (`2 · prefix ≡ 1 (mod order)`), where the
  result is a doubling rather than an addition.
- The `schnorr` crate implements BIP-340 and is checked against the official
  test vectors. Its `sign` retries with a counter mixed into the auxiliary
  randomness when the derived nonce is zero — a case BIP-340 says should fail,
  but which happens once in `n` signatures on a small curve.
- The secp256k1 parameters live in `ecc/src/secp256k1.rs` so that both
  `ecdsa` and `schnorr` share one source of truth.
