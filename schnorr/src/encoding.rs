//! Byte encodings for the BIP-340 wire format.
//!
//! * a public key is 32 bytes: the x-coordinate of the point,
//! * a signature is 64 bytes: `r ‖ s`, each a 32-byte big-endian integer,
//! * a field element (`r`, a public key) is at most `p − 1`,
//! * a scalar (`s`, a secret key) is at most `n − 1`.

use crate::{Schnorr, SchnorrError};
use num_bigint::BigUint;

/// The 32-byte big-endian encoding of a field element.
///
/// Fails if the value does not fit in 32 bytes.
pub fn encode_field_element(value: &BigUint) -> [u8; 32] {
    let bytes = value.to_bytes_be();
    let mut out = [0u8; 32];
    let start = 32usize.saturating_sub(bytes.len());
    out[start..].copy_from_slice(&bytes[bytes.len().saturating_sub(32)..]);
    out
}

/// The 32-byte big-endian encoding of a scalar.
pub fn encode_scalar(value: &BigUint) -> [u8; 32] {
    encode_field_element(value)
}

/// Decodes a 32-byte field element, checking that it is smaller than `p`.
pub fn decode_field_element(bytes: &[u8]) -> Result<BigUint, SchnorrError> {
    if bytes.len() != 32 {
        return Err(SchnorrError::InvalidPublicKey);
    }
    Ok(BigUint::from_bytes_be(bytes))
}

/// Decodes a 32-byte scalar, checking that it is smaller than `n`.
pub fn decode_scalar(bytes: &[u8]) -> Result<BigUint, SchnorrError> {
    if bytes.len() != 32 {
        return Err(SchnorrError::InvalidSignature);
    }
    Ok(BigUint::from_bytes_be(bytes))
}

/// The 32-byte public key for a secret key, as lowercase hex.
pub fn public_key_hex(schnorr: &Schnorr, secret_key: &BigUint) -> Result<String, SchnorrError> {
    let x = schnorr.public_key(secret_key)?;
    Ok(hex::encode(encode_field_element(&x)))
}

/// The 64-byte signature, as lowercase hex.
pub fn signature_hex(signature: &crate::Signature) -> String {
    signature.to_hex()
}
