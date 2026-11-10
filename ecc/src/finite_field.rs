use num_bigint::BigUint;

/// Operations on the finite field `F_p` for a prime modulus `p`.
///
/// The type is stateless: every function receives the modulus `p` explicitly so
/// that the field elements do not need to carry it around.
///
/// All values are [`BigUint`], i.e. arbitrary-precision unsigned integers, so
/// the same operations work for tiny curves and for 256-bit cryptography.
pub struct FiniteField;

impl FiniteField {
    /// Field addition: `a + b (mod p)`.
    ///
    /// The operands must already be reduced elements of the field (`< p`).
    pub fn add(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
        assert!(a < p, "a must be less than p");
        assert!(b < p, "b must be less than p");

        // Raising to the power one and applying the modulus is the idiomatic
        // way to reduce a value with this library.
        (a + b).modpow(&BigUint::from(1u32), p)
    }

    /// Field subtraction: `c - d (mod p)`.
    ///
    /// Subtraction is addition with the additive inverse.
    pub fn sub(c: &BigUint, d: &BigUint, p: &BigUint) -> BigUint {
        let d_inv = Self::inverse_add(d, p);
        Self::add(c, &d_inv, p)
    }

    /// Field multiplication: `a * b (mod p)`.
    ///
    /// The operands must already be reduced elements of the field (`< p`).
    pub fn mul(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
        assert!(a < p, "a must be less than p");
        assert!(b < p, "b must be less than p");

        (a * b).modpow(&BigUint::from(1u32), p)
    }

    /// Additive inverse: `-c (mod p)`.
    ///
    /// In modular arithmetic the additive inverse of `c` is `p - c`. For `c = 0`
    /// this is reduced back to `0`, since `0` is its own inverse.
    pub fn inverse_add(c: &BigUint, p: &BigUint) -> BigUint {
        assert!(c < p, "c must be smaller than p");

        (p - c) % p
    }

    /// Multiplicative inverse: `c^-1 (mod p)`, using Fermat's little theorem.
    ///
    /// For a prime `p` and a non-zero `c`:
    ///
    /// ```text
    /// c^(p-1) = 1 (mod p)  =>  c^-1 = c^(p-2) (mod p)
    /// ```
    ///
    /// This function assumes that `p` is prime. It does **not** verify
    /// primality, which is a known limitation of the implementation taught in
    /// the course.
    pub fn inverse_mul(c: &BigUint, p: &BigUint) -> BigUint {
        let exponent = p - BigUint::from(2u32);
        c.modpow(&exponent, p)
    }

    /// Field division: `c / d (mod p)`.
    ///
    /// Division is multiplication by the multiplicative inverse.
    pub fn div(c: &BigUint, d: &BigUint, p: &BigUint) -> BigUint {
        let d_inv = Self::inverse_mul(d, p);
        Self::mul(c, &d_inv, p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add() {
        let c = BigUint::from(4u32);
        let d = BigUint::from(10u32);
        let p = BigUint::from(11u32);

        let r = FiniteField::add(&c, &d, &p);

        // 4 + 10 = 14 = 3 (mod 11)
        assert_eq!(r, BigUint::from(3u32));
    }

    #[test]
    fn test_add_no_wrap() {
        let c = BigUint::from(20u32);
        let d = BigUint::from(20u32);
        let p = BigUint::from(51u32);

        let r = FiniteField::add(&c, &d, &p);

        // 20 + 20 = 40, already smaller than the modulus
        assert_eq!(r, BigUint::from(40u32));
    }

    #[test]
    fn test_mul() {
        let c = BigUint::from(4u32);
        let d = BigUint::from(10u32);
        let p = BigUint::from(11u32);

        let r = FiniteField::mul(&c, &d, &p);

        // 4 * 10 = 40 = 7 (mod 11)
        assert_eq!(r, BigUint::from(7u32));
    }

    #[test]
    fn test_mul_no_wrap() {
        let c = BigUint::from(4u32);
        let d = BigUint::from(10u32);
        let p = BigUint::from(51u32);

        let r = FiniteField::mul(&c, &d, &p);

        // 4 * 10 = 40, already smaller than the modulus
        assert_eq!(r, BigUint::from(40u32));
    }

    #[test]
    fn test_sub() {
        let c = BigUint::from(7u32);
        let p = BigUint::from(17u32);

        // c - c = 0
        assert_eq!(FiniteField::sub(&c, &c, &p), BigUint::from(0u32));
    }

    #[test]
    fn test_add_inverse_of_zero_is_zero() {
        let c = BigUint::from(0u32);
        let p = BigUint::from(17u32);

        assert_eq!(FiniteField::inverse_add(&c, &p), BigUint::from(0u32));
    }

    #[test]
    fn test_inverse_add() {
        let c = BigUint::from(4u32);
        let p = BigUint::from(51u32);

        // -4 = 51 - 4 = 47 (mod 51)
        assert_eq!(FiniteField::inverse_add(&c, &p), BigUint::from(47u32));
    }

    #[test]
    #[should_panic]
    fn test_inverse_add_out_of_range() {
        let c = BigUint::from(52u32);
        let p = BigUint::from(51u32);

        FiniteField::inverse_add(&c, &p);
    }

    #[test]
    fn test_inverse_add_identity() {
        let c = BigUint::from(4u32);
        let p = BigUint::from(51u32);

        let c_inv = FiniteField::inverse_add(&c, &p);
        let sum = FiniteField::add(&c, &c_inv, &p);

        // 4 + 47 = 51 = 0 (mod 51)
        assert_eq!(sum, BigUint::from(0u32));
    }

    #[test]
    fn test_inverse_mul() {
        let c = BigUint::from(4u32);
        let p = BigUint::from(11u32);

        let c_inv = FiniteField::inverse_mul(&c, &p);

        // 4^-1 = 3 (mod 11), because 4 * 3 = 12 = 1 (mod 11)
        assert_eq!(c_inv, BigUint::from(3u32));
        assert_eq!(FiniteField::mul(&c, &c_inv, &p), BigUint::from(1u32));
    }

    #[test]
    fn test_div() {
        let c = BigUint::from(7u32);
        let p = BigUint::from(17u32);

        // c / c = 1
        assert_eq!(FiniteField::div(&c, &c, &p), BigUint::from(1u32));
    }
}
