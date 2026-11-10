use crate::finite_field::FiniteField;
use crate::point::Point;
use num_bigint::BigUint;

/// An elliptic curve over a prime field:
///
/// ```text
/// y^2 = x^3 + a x + b (mod p)
/// ```
///
/// The curve plus the point at infinity forms an abelian group under the point
/// addition defined below.
pub struct EllipticCurve {
    pub a: BigUint,
    pub b: BigUint,
    pub p: BigUint,
}

impl EllipticCurve {
    /// Returns `true` when the point satisfies the curve equation.
    ///
    /// The identity is not an affine coordinate and therefore returns `false`.
    pub fn on_curve(&self, point: &Point) -> bool {
        match point {
            Point::Coordinate(x, y) => {
                let lhs = y.modpow(&BigUint::from(2u32), &self.p);

                let x3 = x.modpow(&BigUint::from(3u32), &self.p);
                let ax = (x * &self.a) % &self.p;
                let rhs = (x3 + ax + &self.b) % &self.p;

                lhs == rhs
            }
            Point::Identity => false,
        }
    }

    /// Point addition `c + d`.
    ///
    /// Handles the three exceptional cases before applying the chord formula:
    /// the identity, a point plus its reflection (which yields the identity),
    /// and the prohibition on adding a point to itself (use [`Self::double`]).
    pub fn add(&self, c: &Point, d: &Point) -> Point {
        match (c, d) {
            (Point::Identity, _) => d.clone(),
            (_, Point::Identity) => c.clone(),
            (Point::Coordinate(x1, y1), Point::Coordinate(x2, y2)) => {
                assert!(self.on_curve(c), "Point c is not on the curve");
                assert!(self.on_curve(d), "Point d is not on the curve");

                // Vertical line: c and d are reflections, so c + d = O.
                if x1 == x2 && FiniteField::add(y1, y2, &self.p) == BigUint::from(0u32) {
                    return Point::Identity;
                }

                assert!(c != d, "Points must be different for addition");

                // s = (y2 - y1) / (x2 - x1) (mod p)
                let s = FiniteField::div(
                    &FiniteField::sub(y2, y1, &self.p),
                    &FiniteField::sub(x2, x1, &self.p),
                    &self.p,
                );

                let (x3, y3) = self.compute_x3_y3(&s, x1, y1, x2);

                Point::Coordinate(x3, y3)
            }
        }
    }

    /// Point doubling `2c`.
    ///
    /// Uses the tangent line at `c`. If `c` has `y = 0` it is its own additive
    /// inverse, so `2c = O` (this is the case from the assignment).
    pub fn double(&self, c: &Point) -> Point {
        match c {
            Point::Identity => Point::Identity,
            Point::Coordinate(x1, y1) => {
                assert!(self.on_curve(c), "Point is not on the curve");

                // The tangent line is vertical when y = 0: 2P = O.
                if y1 == &BigUint::from(0u32) {
                    return Point::Identity;
                }

                // numerator   = 3 * x1^2 + a
                // denominator = 2 * y1
                let numerator = FiniteField::add(
                    &FiniteField::mul(
                        &BigUint::from(3u32),
                        &FiniteField::mul(x1, x1, &self.p),
                        &self.p,
                    ),
                    &self.a,
                    &self.p,
                );

                let denominator = FiniteField::mul(&BigUint::from(2u32), y1, &self.p);

                let s = FiniteField::div(&numerator, &denominator, &self.p);

                let (x3, y3) = self.compute_x3_y3(&s, x1, y1, x1);

                Point::Coordinate(x3, y3)
            }
        }
    }

    /// Scalar multiplication `d * c` using the double-and-add algorithm.
    ///
    /// The scalar is processed from the most significant bit down to the least
    /// significant one. `d = 0` yields the identity.
    pub fn multiply(&self, d: &BigUint, c: &Point) -> Point {
        if *d == BigUint::from(0u32) {
            return Point::Identity;
        }

        let mut t = c.clone();

        for i in (0..(d.bits() - 1)).rev() {
            t = self.double(&t);

            if d.bit(i) {
                // `add` refuses to add a point to itself, and the ladder can
                // land on exactly that: when `2 * prefix ≡ 1 (mod order)` the
                // doubled accumulator is the base point again. The value the
                // ladder wants is `t + c`, which for `t == c` is `2c` — the
                // double of the point we are holding.
                t = if t == *c {
                    self.double(&t)
                } else {
                    self.add(&t, c)
                };
            }
        }

        t
    }

    /// Shared computation of the resulting coordinates, used by both addition
    /// and doubling:
    ///
    /// ```text
    /// x3 = s^2 - x1 - x2
    /// y3 = s (x1 - x3) - y1
    /// ```
    ///
    /// For doubling, `x2 = x1`, so the caller passes `x1` as `x2`.
    fn compute_x3_y3(
        &self,
        s: &BigUint,
        x1: &BigUint,
        y1: &BigUint,
        x2: &BigUint,
    ) -> (BigUint, BigUint) {
        let x3 = FiniteField::sub(
            &FiniteField::sub(&s.modpow(&BigUint::from(2u32), &self.p), x1, &self.p),
            x2,
            &self.p,
        );

        let y3 = FiniteField::sub(
            &FiniteField::mul(s, &FiniteField::sub(x1, &x3, &self.p), &self.p),
            y1,
            &self.p,
        );

        (x3, y3)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn teaching_curve() -> EllipticCurve {
        // y^2 = x^3 + 2x + 2 (mod 17)
        EllipticCurve {
            a: BigUint::from(2u32),
            b: BigUint::from(2u32),
            p: BigUint::from(17u32),
        }
    }

    fn generator() -> Point {
        Point::Coordinate(BigUint::from(5u32), BigUint::from(1u32))
    }

    #[test]
    fn test_ec_point_add() {
        let curve = teaching_curve();

        let p1 = Point::Coordinate(BigUint::from(6u32), BigUint::from(3u32));
        let p2 = Point::Coordinate(BigUint::from(5u32), BigUint::from(1u32));
        let expected = Point::Coordinate(BigUint::from(10u32), BigUint::from(6u32));

        assert_eq!(curve.add(&p1, &p2), expected);
    }

    #[test]
    fn test_add_identity() {
        let curve = teaching_curve();
        let p1 = Point::Coordinate(BigUint::from(6u32), BigUint::from(3u32));

        assert_eq!(curve.add(&p1, &Point::Identity), p1);
        assert_eq!(curve.add(&Point::Identity, &p1), p1);
    }

    #[test]
    fn test_add_commutative() {
        let curve = teaching_curve();

        let p1 = Point::Coordinate(BigUint::from(6u32), BigUint::from(3u32));
        let p2 = Point::Coordinate(BigUint::from(5u32), BigUint::from(1u32));

        assert_eq!(curve.add(&p1, &p2), curve.add(&p2, &p1));
    }

    #[test]
    fn test_add_reflected_points() {
        let curve = teaching_curve();

        // 16 + 1 = 17 = 0 (mod 17)
        let p1 = Point::Coordinate(BigUint::from(5u32), BigUint::from(16u32));
        let p2 = Point::Coordinate(BigUint::from(5u32), BigUint::from(1u32));

        assert_eq!(curve.add(&p1, &p2), Point::Identity);
    }

    #[test]
    fn test_point_double() {
        let curve = teaching_curve();

        let p = generator();
        let expected = Point::Coordinate(BigUint::from(6u32), BigUint::from(3u32));

        assert_eq!(curve.double(&p), expected);
    }

    #[test]
    fn test_double_identity() {
        let curve = teaching_curve();

        assert_eq!(curve.double(&Point::Identity), Point::Identity);
    }

    #[test]
    fn test_double_y_zero_is_identity() {
        // y^2 = x^3 + 3x (mod 17) contains the point (0, 0).
        let curve = EllipticCurve {
            a: BigUint::from(3u32),
            b: BigUint::from(0u32),
            p: BigUint::from(17u32),
        };
        let p = Point::Coordinate(BigUint::from(0u32), BigUint::from(0u32));

        assert!(curve.on_curve(&p));
        assert_eq!(curve.double(&p), Point::Identity);
    }

    #[test]
    fn test_multiply_2() {
        let curve = teaching_curve();
        let expected = Point::Coordinate(BigUint::from(6u32), BigUint::from(3u32));

        assert_eq!(curve.multiply(&BigUint::from(2u32), &generator()), expected);
    }

    #[test]
    fn test_multiply_10() {
        let curve = teaching_curve();
        let expected = Point::Coordinate(BigUint::from(7u32), BigUint::from(11u32));

        assert_eq!(
            curve.multiply(&BigUint::from(10u32), &generator()),
            expected
        );
    }

    #[test]
    fn test_multiply_16() {
        let curve = teaching_curve();
        let expected = Point::Coordinate(BigUint::from(10u32), BigUint::from(11u32));

        assert_eq!(
            curve.multiply(&BigUint::from(16u32), &generator()),
            expected
        );
    }

    #[test]
    fn test_multiply_17() {
        let curve = teaching_curve();
        let expected = Point::Coordinate(BigUint::from(6u32), BigUint::from(14u32));

        assert_eq!(
            curve.multiply(&BigUint::from(17u32), &generator()),
            expected
        );
    }

    #[test]
    fn test_multiply_18() {
        let curve = teaching_curve();
        let expected = Point::Coordinate(BigUint::from(5u32), BigUint::from(16u32));

        assert_eq!(
            curve.multiply(&BigUint::from(18u32), &generator()),
            expected
        );
    }

    #[test]
    fn test_multiply_19() {
        let curve = teaching_curve();

        assert_eq!(
            curve.multiply(&BigUint::from(19u32), &generator()),
            Point::Identity
        );
    }

    /// The double-and-add ladder can produce a point equal to the base point
    /// again, when `2 * prefix ≡ 1 (mod order)`. Adding it to itself must not
    /// panic: the ladder wants the double.
    #[test]
    fn test_multiply_does_not_add_a_point_to_itself() {
        let curve = teaching_curve();
        let g = generator();

        // The order of G is 19, so 21 * G = 2 * G. While doubling the
        // accumulator for 21 = 10101₂ the ladder reaches 10 * G, doubles it to
        // 20 * G = G, and then wants to add G to itself.
        assert_eq!(
            curve.multiply(&BigUint::from(21u32), &g),
            curve.multiply(&BigUint::from(2u32), &g)
        );
    }

    /// Every scalar must work, not just the ones the lessons happened to use.
    #[test]
    fn test_multiply_is_consistent_with_repeated_addition() {
        let curve = teaching_curve();
        let g = generator();

        // Walk the multiples of G one at a time with the group law. Adding a
        // point to itself is a doubling, which is why the walk uses `double`
        // there — `add` deliberately refuses that case.
        let mut acc = Point::Identity;
        for k in 0u32..40 {
            assert_eq!(
                curve.multiply(&BigUint::from(k), &g),
                acc,
                "multiply({k}, G) disagrees with repeated addition"
            );
            acc = if acc == g {
                curve.double(&g)
            } else {
                curve.add(&acc, &g)
            };
        }
    }

    #[test]
    fn test_multiply_zero() {
        let curve = teaching_curve();

        assert_eq!(
            curve.multiply(&BigUint::from(0u32), &generator()),
            Point::Identity
        );
    }

    #[test]
    fn test_multiply_one() {
        let curve = teaching_curve();

        assert_eq!(
            curve.multiply(&BigUint::from(1u32), &generator()),
            generator()
        );
    }

    #[test]
    fn test_bit_order() {
        let d = BigUint::from(2u32); // binary 10

        assert!(!d.bit(0)); // least significant bit
        assert!(d.bit(1)); // most significant bit
    }

    /// Full 256-bit stress test: the order `n` of secp256k1 satisfies `nG = O`.
    ///
    /// This is extremely slow in a debug build because every field inverse is a
    /// 256-bit modular exponentiation.
    #[test]
    #[ignore = "256-bit scalar multiplication; run with --release --ignored"]
    fn test_secp256k1() {
        let p = BigUint::parse_bytes(
            b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
            16,
        )
        .expect("Could not convert p");

        let n = BigUint::parse_bytes(
            b"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            16,
        )
        .expect("Could not convert n");

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

        let curve = EllipticCurve {
            a: BigUint::from(0u32),
            b: BigUint::from(7u32),
            p,
        };

        let g = Point::Coordinate(gx, gy);

        assert_eq!(curve.multiply(&n, &g), Point::Identity);
    }
}
