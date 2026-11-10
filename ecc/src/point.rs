use num_bigint::BigUint;

/// A point on an elliptic curve.
///
/// A point is either an affine coordinate `(x, y)` or the identity element of
/// the group, the point at infinity. The identity has no graphical
/// representation; it is the neutral element for point addition.
#[derive(Clone, PartialEq, Debug)]
pub enum Point {
    /// An affine point `(x, y)` on the curve.
    Coordinate(BigUint, BigUint),
    /// The point at infinity `O`, identity of the group.
    Identity,
}
