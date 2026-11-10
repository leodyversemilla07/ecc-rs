//! The standard secp256k1 parameters: `y² = x³ + 7` over `F_p`.
//!
//! These live in the `ecc` crate because they describe the curve itself, not
//! any particular signature scheme. Both [`ecdsa`](../../ecdsa/index.html) and
//! [`schnorr`](../../schnorr/index.html) build on them.

use crate::elliptic_curve::EllipticCurve;
use crate::point::Point;
use num_bigint::BigUint;

/// The field size, `p = 2²⁵⁶ − 2³² − 977`.
pub const P: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";

/// The order of the group, `n`.
pub const N: &str = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

/// The x-coordinate of the generator.
pub const GX: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

/// The y-coordinate of the generator.
pub const GY: &str = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

/// The field size `p`.
pub fn p() -> BigUint {
    BigUint::parse_bytes(P.as_bytes(), 16).expect("Could not parse p")
}

/// The group order `n`.
pub fn order() -> BigUint {
    BigUint::parse_bytes(N.as_bytes(), 16).expect("Could not parse n")
}

/// The curve equation's coefficients: `a = 0`, `b = 7`.
pub fn curve() -> EllipticCurve {
    EllipticCurve {
        a: BigUint::from(0u32),
        b: BigUint::from(7u32),
        p: p(),
    }
}

/// The generator `G`.
pub fn generator() -> Point {
    Point::Coordinate(
        BigUint::parse_bytes(GX.as_bytes(), 16).expect("Could not parse Gx"),
        BigUint::parse_bytes(GY.as_bytes(), 16).expect("Could not parse Gy"),
    )
}
