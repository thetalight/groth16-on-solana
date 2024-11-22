use ark_ff::PrimeField;
use num_bigint::BigUint;

pub fn convert_endianness_32(input: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    for (i, &byte) in input.iter().enumerate().take(32) {
        output[i] = byte.swap_bytes(); // This swaps endianness for each byte
    }
    output
}

pub fn is_less_than_bn254_field_size_be(bytes: &[u8; 32]) -> bool {
    let bigint = BigUint::from_bytes_be(bytes);
    bigint < ark_bn254::Fr::MODULUS.into()
}
