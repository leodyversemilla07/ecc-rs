//! # ecdsa
//!
//! The Elliptic Curve Digital Signature Algorithm, built on the [`ecc`] library
//! exactly as developed in the course transcript.
//!
//! It provides the three stages of the algorithm:
//!
//! - key generation: `Q = d G`
//! - signing: `s = k^-1 (H(M) + r d) mod n`
//! - verification: `P = u1 G + u2 Q`, valid when `x(P) = r`
//!
//! [`secp256k1`] builds the real 256-bit curve used by Bitcoin; [`small_curve`]
//! builds the tiny `y^2 = x^3 + 2x + 2 (mod 17)` curve used in the lessons.

use ecc::{EllipticCurve, FiniteField, Point};
use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;
use sha2::{Digest, Sha256};

/// State required to sign and verify with a given elliptic curve.
pub struct Ecdsa {
    pub curve: EllipticCurve,
    pub generator: Point,
    /// Order (number of elements) of the group. Must be prime so that the
    /// multiplicative inverse can be computed with Fermat's little theorem.
    pub order: BigUint,
}

impl Ecdsa {
    /// Generates a fresh private/public key pair.
    ///
    /// Returns `(private_key, public_key)`.
    pub fn generate_key_pair(&self) -> (BigUint, Point) {
        let private_key = self.generate_private_key();
        let public_key = self.generate_public_key(&private_key);
        (private_key, public_key)
    }

    /// Generates a private key `d` with `1 <= d < order`.
    pub fn generate_private_key(&self) -> BigUint {
        self.generate_random_positive(&self.order)
    }

    /// Generates a random number in `[1, limit)`.
    ///
    /// `gen_biguint_range` is used instead of `gen_biguint_below` so that the
    /// result is guaranteed to be strictly positive.
    pub fn generate_random_positive(&self, limit: &BigUint) -> BigUint {
        let mut rng = thread_rng();
        rng.gen_biguint_range(&BigUint::from(1u32), limit)
    }

    /// Computes the public key `Q = d G`.
    pub fn generate_public_key(&self, private_key: &BigUint) -> Point {
        self.curve.multiply(private_key, &self.generator)
    }

    /// Signs a message hash and returns the signature `(r, s)`.
    ///
    /// ```text
    /// 1. R = k G
    /// 2. r = x(R) mod n
    /// 3. s = k^-1 (hash + d r) mod n
    /// ```
    ///
    /// The nonce `k` is supplied by the caller. As in the transcript, standard
    /// ECDSA requires a fresh `k` whenever `r = 0` or `s = 0`; those cases are
    /// not retried here, so callers that can hit them should retry with a new
    /// nonce (see the `ecdsa` binary for an example).
    pub fn sign(&self, hash: &BigUint, private_key: &BigUint, k: &BigUint) -> (BigUint, BigUint) {
        assert!(hash < &self.order, "Hash must be less than the order");
        assert!(
            private_key < &self.order,
            "Private key must be less than the order"
        );
        assert!(k < &self.order, "k must be less than the order");

        let random_point = self.curve.multiply(k, &self.generator);
        let r = match random_point {
            // Reduce the x-coordinate modulo the order, as standard ECDSA does.
            Point::Coordinate(x, _) => x % &self.order,
            Point::Identity => {
                panic!("The random point should not be the identity")
            }
        };

        let d_times_r = FiniteField::mul(private_key, &r, &self.order);
        let hash_plus_d_times_r = FiniteField::add(hash, &d_times_r, &self.order);
        let k_inverse = FiniteField::inverse_mul(k, &self.order);
        let s = FiniteField::mul(&hash_plus_d_times_r, &k_inverse, &self.order);

        (r, s)
    }

    /// Verifies a signature over a message hash with a public key.
    ///
    /// ```text
    /// w  = s^-1 mod n
    /// u1 = hash * w mod n
    /// u2 = r * w mod n
    /// P  = u1 G + u2 Q
    /// valid  <=>  x(P) mod n = r
    /// ```
    pub fn verify(
        &self,
        hash: &BigUint,
        public_key: &Point,
        signature: &(BigUint, BigUint),
    ) -> bool {
        let (r, s) = signature;

        assert!(hash < &self.order, "Hash must be less than the order");

        let s_inverse = FiniteField::inverse_mul(s, &self.order);
        let u1 = FiniteField::mul(hash, &s_inverse, &self.order);
        let u2 = FiniteField::mul(r, &s_inverse, &self.order);

        let u1_generator = self.curve.multiply(&u1, &self.generator);
        let u2_public_key = self.curve.multiply(&u2, public_key);
        let p = self.curve.add(&u1_generator, &u2_public_key);

        match p {
            Point::Coordinate(x, _) => (x % &self.order) == *r,
            Point::Identity => false,
        }
    }

    /// Hashes a message with SHA-256 and maps it into `[1, max)`.
    ///
    /// The digest is a 256-bit number; reducing it modulo `max - 1` and adding
    /// one guarantees a result that is both positive and smaller than `max`.
    pub fn generate_hash_less_than(message: &str, max: &BigUint) -> BigUint {
        let digest = Sha256::digest(message);
        let hash_hex = format!("{:x}", digest);
        let hash_bytes = hex::decode(hash_hex).expect("Could not convert hash to bytes");
        let hash = BigUint::from_bytes_be(&hash_bytes);

        let modulus = max - BigUint::from(1u32);
        let hash = hash.modpow(&BigUint::from(1u32), &modulus);
        hash + BigUint::from(1u32)
    }
}

/// The secp256k1 curve used by Bitcoin: `y^2 = x^3 + 7 (mod p)`.
pub fn secp256k1() -> Ecdsa {
    let p = BigUint::parse_bytes(
        b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
        16,
    )
    .expect("Could not convert p");

    let order = BigUint::parse_bytes(
        b"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        16,
    )
    .expect("Could not convert order");

    let gx = BigUint::parse_bytes(
        b"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        16,
    )
    .expect("Could not convert gx");

    let gy = BigUint::parse_bytes(
        b"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        16,
    )
    .expect("Could not convert gy");

    Ecdsa {
        curve: EllipticCurve {
            a: BigUint::from(0u32),
            b: BigUint::from(7u32),
            p,
        },
        generator: Point::Coordinate(gx, gy),
        order,
    }
}

/// The tiny teaching curve used throughout the course:
/// `y^2 = x^3 + 2x + 2 (mod 17)` with generator `(5, 1)` and prime order `19`.
pub fn small_curve() -> Ecdsa {
    Ecdsa {
        curve: EllipticCurve {
            a: BigUint::from(2u32),
            b: BigUint::from(2u32),
            p: BigUint::from(17u32),
        },
        generator: Point::Coordinate(BigUint::from(5u32), BigUint::from(1u32)),
        order: BigUint::from(19u32),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verifiable() {
        let ecdsa = small_curve();

        let private_key = BigUint::from(7u32);
        let public_key = ecdsa.generate_public_key(&private_key);

        let hash = BigUint::from(10u32);
        let k = BigUint::from(2u32);

        let signature = ecdsa.sign(&hash, &private_key, &k);

        // The valid signature verifies.
        assert!(ecdsa.verify(&hash, &public_key, &signature));

        // A tampered message does not verify.
        let tampered_message = "Bob sends two bitcoins to Alice";
        let tampered_hash = Ecdsa::generate_hash_less_than(tampered_message, &ecdsa.order);
        assert!(!ecdsa.verify(&tampered_hash, &public_key, &signature));

        // A tampered signature does not verify either.
        let (r, s) = &signature;
        let tampered_r = (r + BigUint::from(1u32)) % &ecdsa.order;
        let tampered_signature = (tampered_r, s.clone());
        assert!(!ecdsa.verify(&hash, &public_key, &tampered_signature));
    }

    #[test]
    fn generate_hash_is_in_range() {
        let order = BigUint::from(19u32);
        let hash = Ecdsa::generate_hash_less_than("hello", &order);

        assert!(hash > BigUint::from(0u32));
        assert!(hash < order);
    }

    fn secp256k1_setup() -> (Ecdsa, BigUint, Point, BigUint) {
        let ecdsa = secp256k1();

        let private_key = BigUint::parse_bytes(
            b"a0b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f9",
            16,
        )
        .expect("Could not convert to private key");

        let public_key = ecdsa.generate_public_key(&private_key);

        let k = BigUint::parse_bytes(
            b"48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5",
            16,
        )
        .expect("Could not convert to random number");

        (ecdsa, private_key, public_key, k)
    }

    /// Full 256-bit sign/verify round trip. Slow in debug; run with `--release`.
    #[test]
    #[ignore = "256-bit scalar multiplication; run with --release --ignored"]
    fn test_verify_secp256k1_sign() {
        let (ecdsa, private_key, public_key, k) = secp256k1_setup();

        let message = "Bob sends two bitcoins to Alice";
        let hash = Ecdsa::generate_hash_less_than(message, &ecdsa.order);

        let signature = ecdsa.sign(&hash, &private_key, &k);

        assert!(ecdsa.verify(&hash, &public_key, &signature));
    }

    #[test]
    #[ignore = "256-bit scalar multiplication; run with --release --ignored"]
    fn test_verify_secp256k1_tampered_message() {
        let (ecdsa, private_key, public_key, k) = secp256k1_setup();

        let message = "Bob sends two bitcoins to Alice";
        let hash = Ecdsa::generate_hash_less_than(message, &ecdsa.order);
        let signature = ecdsa.sign(&hash, &private_key, &k);

        let tampered_message = "Bob sends three bitcoins to Alice";
        let tampered_hash = Ecdsa::generate_hash_less_than(tampered_message, &ecdsa.order);

        assert!(!ecdsa.verify(&tampered_hash, &public_key, &signature));
    }

    #[test]
    #[ignore = "256-bit scalar multiplication; run with --release --ignored"]
    fn test_verify_secp256k1_tampered_signature() {
        let (ecdsa, private_key, public_key, k) = secp256k1_setup();

        let message = "Bob sends two bitcoins to Alice";
        let hash = Ecdsa::generate_hash_less_than(message, &ecdsa.order);
        let signature = ecdsa.sign(&hash, &private_key, &k);

        let tampered_signature = (
            (&signature.0 + BigUint::from(1u32)) % &ecdsa.order,
            signature.1.clone(),
        );

        assert!(!ecdsa.verify(&hash, &public_key, &tampered_signature));
    }
}
