//! # ecc
//!
//! Elliptic curve cryptography, built from scratch as in the course transcript.
//!
//! The library is organised as the "pyramid" of the course:
//!
//! ```text
//! EllipticCurve   point addition, doubling, scalar multiplication
//!      |
//! FiniteField     modular add/sub/mul/div and inverses on BigUint
//!      |
//! Point           coordinate (x, y) or the point at infinity
//! ```
//!
//! Everything works modulo a prime `p` using arbitrary-precision integers
//! ([`num_bigint::BigUint`]), so the same code supports tiny teaching curves and
//! 256-bit curves such as secp256k1.

pub mod elliptic_curve;
pub mod finite_field;
pub mod point;

pub use elliptic_curve::EllipticCurve;
pub use finite_field::FiniteField;
pub use point::Point;
