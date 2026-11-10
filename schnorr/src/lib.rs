//! # schnorr
//!
//! [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
//! Schnorr signatures for secp256k1, built on the [`ecc`] library.
//!
//! Where [`ecdsa`](../../ecdsa/index.html) signs with the pair `(r, s)` where
//! `r` comes from the x-coordinate of the nonce point, Schnorr keeps the whole
//! relation in one line:
//!
//! ```text
//! s·G = R + e·P
//! ```
//!
//! with `e = tagged_hash("BIP0340/challenge", R.x ‖ P.x ‖ message)`. That gives
//! three properties ECDSA does not have:
//!
//! * **provable security** — Schnorr is strongly unforgeable under a chosen
//!   message attack,
//! * **non-malleability** — flipping `s` to `n − s` does not yield a second
//!   valid signature,
//! * **linearity** — `s·G = R + e·P` is additive, which is what makes
//!   MuSig and threshold signatures possible.
//!
//! ## Example
//!
//! ```
//! use num_bigint::BigUint;
//! use schnorr::Schnorr;
//!
//! let schnorr = Schnorr::secp256k1();
//! let secret_key = BigUint::from(7u32);
//! let message = b"Bob sends two bitcoins to Alice";
//!
//! let public_key = schnorr.public_key(&secret_key).unwrap();
//! let signature = schnorr.sign(&secret_key, message, None).unwrap();
//!
//! assert!(schnorr.verify(&public_key, message, &signature));
//! ```

pub mod encoding;

use ecc::{EllipticCurve, FiniteField, Point};
use num_bigint::BigUint;
use sha2::{Digest, Sha256};

/// The tag used for the auxiliary randomness.
pub const TAG_AUX: &str = "BIP0340/aux";
/// The tag used to derive the nonce.
pub const TAG_NONCE: &str = "BIP0340/nonce";
/// The tag used to derive the challenge.
pub const TAG_CHALLENGE: &str = "BIP0340/challenge";

/// A BIP-340 signature: the pair `(r, s)`.
///
/// `r` is the x-coordinate of the nonce point `R`; `s` is the scalar that
/// satisfies `s·G = R + e·P`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// The x-coordinate of the nonce point `R`.
    pub r: BigUint,
    /// The scalar `s`.
    pub s: BigUint,
}

impl Signature {
    /// The 64-byte BIP-340 encoding: `r ‖ s`, each a 32-byte big-endian
    /// integer.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&encoding::encode_field_element(&self.r));
        out[32..].copy_from_slice(&encoding::encode_scalar(&self.s));
        out
    }

    /// Parses the 64-byte BIP-340 encoding.
    pub fn from_bytes(bytes: &[u8; 64]) -> Result<Self, SchnorrError> {
        let r = encoding::decode_field_element(&bytes[..32])?;
        let s = encoding::decode_scalar(&bytes[32..])?;
        Ok(Signature { r, s })
    }

    /// The signature as lowercase hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }
}

/// Everything that can go wrong in the scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchnorrError {
    /// The secret key was zero or not smaller than the group order.
    InvalidSecretKey,
    /// The public key was not the x-coordinate of a point on the curve.
    InvalidPublicKey,
    /// The signature was malformed: `r ≥ p` or `s ≥ n`.
    InvalidSignature,
    /// The derived nonce was zero. BIP-340 says to fail here.
    NonceIsZero,
    /// The signature failed the self-check that signing performs.
    VerificationFailed,
}

impl std::fmt::Display for SchnorrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            SchnorrError::InvalidSecretKey => "the secret key must be in 1 … n−1",
            SchnorrError::InvalidPublicKey => "the public key is not a valid x-coordinate",
            SchnorrError::InvalidSignature => "the signature is malformed",
            SchnorrError::NonceIsZero => "the derived nonce was zero",
            SchnorrError::VerificationFailed => "the signature did not verify",
        };
        write!(f, "{message}")
    }
}

impl std::error::Error for SchnorrError {}

/// Schnorr signatures over a prime-order elliptic curve.
pub struct Schnorr {
    /// The curve the signatures live on.
    pub curve: EllipticCurve,
    /// The generator `G`.
    pub generator: Point,
    /// The order `n` of the group.
    pub order: BigUint,
}

impl Schnorr {
    /// Builds a scheme from its parts.
    pub fn new(curve: EllipticCurve, generator: Point, order: BigUint) -> Self {
        Schnorr {
            curve,
            generator,
            order,
        }
    }

    /// The scheme BIP-340 defines: secp256k1 with its standard generator.
    pub fn secp256k1() -> Self {
        Schnorr::new(
            ecc::secp256k1::curve(),
            ecc::secp256k1::generator(),
            ecc::secp256k1::order(),
        )
    }

    /// A small curve with the same shape as secp256k1 (`a = 0`) that is small
    /// enough to draw: `y² = x³ + 10 (mod 19)`, generator `(1, 12)`, order 19.
    ///
    /// The scheme is exactly the one BIP-340 specifies; only the curve
    /// changes. The field size is `3 (mod 4)`, so `lift_x` works with the
    /// `c^((p+1)/4)` shortcut the BIP uses.
    pub fn teaching() -> Self {
        Schnorr::new(
            EllipticCurve {
                a: BigUint::from(0u32),
                b: BigUint::from(10u32),
                p: BigUint::from(19u32),
            },
            Point::Coordinate(BigUint::from(1u32), BigUint::from(12u32)),
            BigUint::from(19u32),
        )
    }

    /// The public key for a secret key: the x-coordinate of `d·G`.
    ///
    /// The y-coordinate is not published. BIP-340 fixes it implicitly to the
    /// even one, which is what makes a 32-byte public key unambiguous.
    pub fn public_key(&self, secret_key: &BigUint) -> Result<BigUint, SchnorrError> {
        if *secret_key == BigUint::from(0u32) || secret_key >= &self.order {
            return Err(SchnorrError::InvalidSecretKey);
        }

        let point = self.curve.multiply(secret_key, &self.generator);
        match point {
            Point::Coordinate(x, _) => Ok(x),
            Point::Identity => Err(SchnorrError::InvalidSecretKey),
        }
    }

    /// Signs a message.
    ///
    /// `aux` is 32 bytes of extra randomness. BIP-340 recommends it, because
    /// the nonce is derived from the secret key and a bad RNG can otherwise
    /// leak the key. Pass `None` for 32 zero bytes.
    ///
    /// BIP-340 says to fail when the derived nonce is zero. On secp256k1 that
    /// has probability `2⁻²⁵⁶` and never happens in practice; on a small
    /// teaching curve it happens once in `n` signatures, which is far too
    /// often to be useful. This implementation therefore retries with a
    /// counter mixed into the auxiliary randomness. The first attempt always
    /// uses the auxiliary randomness exactly as given, so signatures are
    /// identical to plain BIP-340 whenever the first attempt succeeds.
    pub fn sign(
        &self,
        secret_key: &BigUint,
        message: &[u8],
        aux: Option<&[u8; 32]>,
    ) -> Result<Signature, SchnorrError> {
        let base_aux = aux.copied().unwrap_or([0u8; 32]);

        for attempt in 0u32..8 {
            // The counter is mixed in with xor, so the first attempt uses the
            // auxiliary randomness exactly as the caller gave it.
            let mut attempt_aux = base_aux;
            for (byte, counter) in attempt_aux[28..].iter_mut().zip(attempt.to_be_bytes()) {
                *byte ^= counter;
            }

            match self.sign_once(secret_key, message, &attempt_aux) {
                Err(SchnorrError::NonceIsZero) => continue,
                other => return other,
            }
        }

        Err(SchnorrError::NonceIsZero)
    }

    /// One signing attempt with fixed auxiliary randomness.
    fn sign_once(
        &self,
        secret_key: &BigUint,
        message: &[u8],
        aux: &[u8; 32],
    ) -> Result<Signature, SchnorrError> {
        let n = &self.order;
        if *secret_key == BigUint::from(0u32) || secret_key >= n {
            return Err(SchnorrError::InvalidSecretKey);
        }

        // P = d'·G. The y-coordinate is not published, but it decides whether
        // the secret key is used as-is or negated, so that the point we sign
        // with is always the even-y one.
        let p_point = self.curve.multiply(secret_key, &self.generator);
        let p_x = match &p_point {
            Point::Coordinate(x, _) => x.clone(),
            Point::Identity => return Err(SchnorrError::InvalidSecretKey),
        };
        let d = if has_even_y(&p_point) {
            secret_key.clone()
        } else {
            n - secret_key
        };

        // t = bytes(d) XOR hash_aux(a)
        let mut t = encoding::encode_scalar(&d);
        for (byte, hash_byte) in t.iter_mut().zip(tagged_hash(TAG_AUX, &[aux])) {
            *byte ^= hash_byte;
        }

        // rand = hash_nonce(t ‖ bytes(P) ‖ m)
        let rand = tagged_hash(
            TAG_NONCE,
            &[&t, &encoding::encode_field_element(&p_x), message],
        );

        // k' = int(rand) mod n
        let k_prime = BigUint::from_bytes_be(&rand) % n;
        if k_prime == BigUint::from(0u32) {
            return Err(SchnorrError::NonceIsZero);
        }

        // R = k'·G, and the nonce is negated when R has an odd y-coordinate.
        let r_point = self.curve.multiply(&k_prime, &self.generator);
        let r_x = match &r_point {
            Point::Coordinate(x, _) => x.clone(),
            Point::Identity => return Err(SchnorrError::NonceIsZero),
        };
        let k = if has_even_y(&r_point) {
            k_prime
        } else {
            n - k_prime
        };

        // e = int(hash_challenge(bytes(R) ‖ bytes(P) ‖ m)) mod n
        let e = BigUint::from_bytes_be(&tagged_hash(
            TAG_CHALLENGE,
            &[
                &encoding::encode_field_element(&r_x),
                &encoding::encode_field_element(&p_x),
                message,
            ],
        )) % n;

        // sig = bytes(R) ‖ bytes((k + e·d) mod n)
        let s = (k + FiniteField::mul(&e, &d, n)) % n;
        let signature = Signature { r: r_x, s };

        // The signer checks its own work: publishing an invalid signature can
        // leak the secret key.
        if !self.verify(&p_x, message, &signature) {
            return Err(SchnorrError::VerificationFailed);
        }

        Ok(signature)
    }

    /// Verifies a signature.
    ///
    /// The verifier needs nothing but the public key, the message and the
    /// signature — never the secret key or the nonce.
    pub fn verify(&self, public_key: &BigUint, message: &[u8], signature: &Signature) -> bool {
        let p = &self.curve.p;
        let n = &self.order;

        // P = lift_x(int(pk))
        let Some(p_point) = self.lift_x(public_key) else {
            return false;
        };
        let p_x = match &p_point {
            Point::Coordinate(x, _) => x.clone(),
            Point::Identity => return false,
        };

        // The bounds are part of the signature format, not a sanity check.
        if signature.r >= *p || signature.s >= *n {
            return false;
        }

        // e = int(hash_challenge(bytes(r) ‖ bytes(P) ‖ m)) mod n
        let e = BigUint::from_bytes_be(&tagged_hash(
            TAG_CHALLENGE,
            &[
                &encoding::encode_field_element(&signature.r),
                &encoding::encode_field_element(&p_x),
                message,
            ],
        )) % n;

        // R = s·G − e·P
        let s_g = self.curve.multiply(&signature.s, &self.generator);
        let e_p = self.curve.multiply(&e, &p_point);
        let neg_e_p = self.negate(&e_p);

        // `EllipticCurve::add` refuses to add a point to itself, and here the
        // two terms can be equal: when s·G = −e·P the sum is a doubling, not
        // an error. When they are reflections instead, `add` returns the
        // identity and the signature simply fails to verify.
        let r_point = if s_g == neg_e_p {
            self.curve.double(&s_g)
        } else {
            self.curve.add(&s_g, &neg_e_p)
        };

        match r_point {
            Point::Coordinate(x, y) => {
                has_even_y(&Point::Coordinate(x.clone(), y)) && x == signature.r
            }
            Point::Identity => false,
        }
    }

    /// Recovers the point with the given x-coordinate, choosing the even
    /// y-coordinate.
    ///
    /// This is BIP-340's `lift_x`. It uses the `c^((p+1)/4)` shortcut, which
    /// is valid because the field size is `3 (mod 4)` — true for secp256k1 and
    /// for the teaching curve.
    pub fn lift_x(&self, x: &BigUint) -> Option<Point> {
        let p = &self.curve.p;
        if x >= p {
            return None;
        }

        // c = x³ + ax + b mod p
        let x3 = x.modpow(&BigUint::from(3u32), p);
        let ax = FiniteField::mul(x, &self.curve.a, p);
        let c = (x3 + ax + &self.curve.b) % p;

        // y = c^((p+1)/4) mod p
        let exponent = (p + BigUint::from(1u32)) / BigUint::from(4u32);
        let y = c.modpow(&exponent, p);

        // Fail if c is not a square.
        if y.modpow(&BigUint::from(2u32), p) != c {
            return None;
        }

        // Pick the even root.
        let y = if (&y % &BigUint::from(2u32)) == BigUint::from(0u32) {
            y
        } else {
            p - &y
        };

        Some(Point::Coordinate(x.clone(), y))
    }

    /// The negation of a point: the same x, the opposite y.
    fn negate(&self, point: &Point) -> Point {
        match point {
            Point::Coordinate(x, y) => {
                Point::Coordinate(x.clone(), (&self.curve.p - y) % &self.curve.p)
            }
            Point::Identity => Point::Identity,
        }
    }
}

/// Whether the point's y-coordinate is even.
pub fn has_even_y(point: &Point) -> bool {
    match point {
        Point::Coordinate(_, y) => y % BigUint::from(2u32) == BigUint::from(0u32),
        Point::Identity => false,
    }
}

/// A tagged hash: `SHA256(SHA256(tag) ‖ SHA256(tag) ‖ data)`.
///
/// The tag makes a hash used in one context unusable in another.
pub fn tagged_hash(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());

    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn teaching() -> Schnorr {
        Schnorr::teaching()
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let schnorr = teaching();
        let secret_key = BigUint::from(7u32);
        let message = b"a message";

        let public_key = schnorr.public_key(&secret_key).unwrap();
        let signature = schnorr.sign(&secret_key, message, None).unwrap();

        assert!(schnorr.verify(&public_key, message, &signature));
    }

    #[test]
    fn a_different_message_does_not_verify() {
        let schnorr = teaching();
        let secret_key = BigUint::from(7u32);

        let public_key = schnorr.public_key(&secret_key).unwrap();
        let signature = schnorr.sign(&secret_key, b"one", None).unwrap();

        assert!(!schnorr.verify(&public_key, b"two", &signature));
    }

    #[test]
    fn a_different_key_does_not_verify() {
        let schnorr = teaching();
        let signature = schnorr.sign(&BigUint::from(7u32), b"m", None).unwrap();
        let other_key = schnorr.public_key(&BigUint::from(8u32)).unwrap();

        assert!(!schnorr.verify(&other_key, b"m", &signature));
    }

    #[test]
    fn the_secret_key_is_negated_when_the_public_point_has_an_odd_y() {
        let schnorr = teaching();

        // Find a secret key whose public point has an odd y-coordinate.
        let odd = (1u32..19)
            .map(BigUint::from)
            .find(|k| {
                let point = schnorr.curve.multiply(k, &schnorr.generator);
                !has_even_y(&point)
            })
            .expect("some key has an odd public point");

        // The signature must still verify against the same public key: the
        // negated key produces the even-y point, which is what the public
        // key stands for.
        let public_key = schnorr.public_key(&odd).unwrap();
        let signature = schnorr.sign(&odd, b"m", None).unwrap();
        assert!(schnorr.verify(&public_key, b"m", &signature));
    }

    #[test]
    fn an_out_of_range_secret_key_is_rejected() {
        let schnorr = teaching();
        assert_eq!(
            schnorr.public_key(&BigUint::from(0u32)),
            Err(SchnorrError::InvalidSecretKey)
        );
        assert_eq!(
            schnorr.public_key(&BigUint::from(19u32)),
            Err(SchnorrError::InvalidSecretKey)
        );
    }

    #[test]
    fn a_public_key_that_is_not_on_the_curve_is_rejected() {
        let schnorr = teaching();
        let signature = schnorr.sign(&BigUint::from(7u32), b"m", None).unwrap();

        // x = 5 is not the x-coordinate of any point on y² = x³ + 10 (mod 19).
        assert!(!schnorr.verify(&BigUint::from(5u32), b"m", &signature));
    }

    #[test]
    fn lift_x_always_returns_the_even_point() {
        let schnorr = teaching();

        for x in 0u32..19 {
            if let Some(point) = schnorr.lift_x(&BigUint::from(x)) {
                assert!(has_even_y(&point));
                assert!(schnorr.curve.on_curve(&point));
            }
        }
    }

    #[test]
    fn tagged_hash_separates_contexts() {
        let a = tagged_hash("BIP0340/challenge", &[b"data"]);
        let b = tagged_hash("BIP0340/nonce", &[b"data"]);
        assert_ne!(a, b);
    }
}
