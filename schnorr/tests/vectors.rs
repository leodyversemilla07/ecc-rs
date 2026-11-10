//! The official BIP-340 test vectors.
//!
//! The CSV file is the one published with the BIP:
//! <https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv>
//!
//! Each vector gives a secret key, the expected public key, the auxiliary
//! randomness, a message, the expected signature and the expected result of
//! verifying it. Vectors without a secret key only exercise verification.

use num_bigint::BigUint;
use schnorr::{Schnorr, Signature};

/// One row of the CSV.
struct Vector {
    index: usize,
    secret_key: Option<[u8; 32]>,
    public_key: [u8; 32],
    aux_rand: Option<[u8; 32]>,
    message: Vec<u8>,
    signature: [u8; 64],
    verification_result: bool,
    comment: String,
}

fn hex_to_32(text: &str) -> [u8; 32] {
    let bytes = hex::decode(text).expect("Could not decode hex");
    assert_eq!(bytes.len(), 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn hex_to_64(text: &str) -> [u8; 64] {
    let bytes = hex::decode(text).expect("Could not decode hex");
    assert_eq!(bytes.len(), 64);
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    out
}

fn parse() -> Vec<Vector> {
    let csv = include_str!("bip340_vectors.csv");
    let mut lines = csv.lines();

    let header = lines.next().expect("the CSV has a header");
    assert!(
        header.starts_with("index,secret key,public key"),
        "unexpected header"
    );

    let mut vectors = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split(',').collect();
        assert_eq!(fields.len(), 8, "unexpected number of fields in: {line}");

        vectors.push(Vector {
            index: fields[0].parse().expect("could not parse the index"),
            secret_key: if fields[1].is_empty() {
                None
            } else {
                Some(hex_to_32(fields[1]))
            },
            public_key: hex_to_32(fields[2]),
            aux_rand: if fields[3].is_empty() {
                None
            } else {
                Some(hex_to_32(fields[3]))
            },
            message: hex::decode(fields[4]).expect("could not decode the message"),
            signature: hex_to_64(fields[5]),
            verification_result: fields[6] == "TRUE",
            comment: fields[7].to_string(),
        });
    }
    vectors
}

#[test]
fn public_keys_match_the_vectors() {
    let schnorr = Schnorr::secp256k1();

    for vector in parse() {
        let Some(secret_key) = vector.secret_key else {
            continue;
        };

        let public_key = schnorr
            .public_key(&BigUint::from_bytes_be(&secret_key))
            .expect("the secret key should be valid");

        assert_eq!(
            schnorr::encoding::encode_field_element(&public_key),
            vector.public_key,
            "vector {}: wrong public key ({})",
            vector.index,
            vector.comment
        );
    }
}

#[test]
fn signatures_match_the_vectors() {
    let schnorr = Schnorr::secp256k1();

    for vector in parse() {
        let Some(secret_key) = vector.secret_key else {
            continue;
        };

        let signature = schnorr
            .sign(
                &BigUint::from_bytes_be(&secret_key),
                &vector.message,
                vector.aux_rand.as_ref(),
            )
            .unwrap_or_else(|error| panic!("vector {} could not be signed: {error}", vector.index));

        assert_eq!(
            signature.to_bytes(),
            vector.signature,
            "vector {}: wrong signature ({})",
            vector.index,
            vector.comment
        );
    }
}

#[test]
fn verification_matches_the_vectors() {
    let schnorr = Schnorr::secp256k1();

    for vector in parse() {
        let public_key = BigUint::from_bytes_be(&vector.public_key);
        let signature =
            Signature::from_bytes(&vector.signature).expect("could not parse the signature");

        assert_eq!(
            schnorr.verify(&public_key, &vector.message, &signature),
            vector.verification_result,
            "vector {}: wrong verification result ({})",
            vector.index,
            vector.comment
        );
    }
}

#[test]
fn every_vector_is_covered() {
    // Guard against the CSV being silently truncated.
    assert_eq!(parse().len(), 19);
}
