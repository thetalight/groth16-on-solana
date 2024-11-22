use ark_ff::PrimeField;
use borsh::{BorshDeserialize, BorshSerialize};
use num_bigint::BigUint;
use solana_program::{
    account_info::AccountInfo, alt_bn128::prelude::*, entrypoint, entrypoint::ProgramResult, msg,
    program_error::ProgramError, pubkey::Pubkey,
};
use verifier_key::{PI_LENGTH, VERIFIER_KEY};

pub mod verifier_key;

const INVALID_PUBLIC_INPUTS_LENGTH: ProgramError = ProgramError::Custom(1);
const PUBLIC_INPUT_GREATER_THEN_FIELD_SIZE: ProgramError = ProgramError::Custom(2);
const PREPARING_INPUTS_G1_MUL_FAILED: ProgramError = ProgramError::Custom(3);
const PREPARING_INPUTS_G1_ADDITION_FAILED: ProgramError = ProgramError::Custom(4);
const VERIFY_PROOF_FAILED: ProgramError = ProgramError::Custom(5);
const PAIRING_ERROR: ProgramError = ProgramError::Custom(6);

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let proof = ConvertedProof::try_from_slice(instruction_data)?;
    verify_proof(program_id, accounts, proof)
}

fn verify_proof(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    proof: ConvertedProof,
) -> ProgramResult {
    let prepare_input = prepare_inputs(proof.public_inputs.as_slice(), &VERIFIER_KEY)?;

    let pairing_input = [
        proof.a.as_slice(),
        proof.b.as_slice(),
        prepare_input.as_slice(),
        VERIFIER_KEY.vk_gamma_g2.as_slice(),
        proof.c.as_slice(),
        VERIFIER_KEY.vk_delta_g2.as_slice(),
        VERIFIER_KEY.vk_alpha_g1.as_slice(),
        VERIFIER_KEY.vk_beta_g2.as_slice(),
    ]
    .concat();

    let pairing_res = alt_bn128_pairing(pairing_input.as_slice()).map_err(|_| PAIRING_ERROR)?;

    if pairing_res[31] != 1 {
        return Err(VERIFY_PROOF_FAILED);
    }

    msg!("Proof is valid!");

    Ok(())
}

pub fn prepare_inputs(
    pi: &[[u8; 32]],
    vk: &Groth16VerifyingKeyPrepared,
) -> Result<Vec<u8>, ProgramError> {
    if pi.len() + 1 != vk.vk_ic.len() {
        return Err(INVALID_PUBLIC_INPUTS_LENGTH);
    }

    let mut prepared_public_inputs = vk.vk_ic[0].to_vec();
    for (i, input) in pi.iter().enumerate() {
        if !is_less_than_bn254_field_size_be(input) {
            return Err(PUBLIC_INPUT_GREATER_THEN_FIELD_SIZE);
        }

        let mul_res = alt_bn128_multiplication(&[&vk.vk_ic[i + 1][..], &input[..]].concat())
            .map_err(|_| PREPARING_INPUTS_G1_MUL_FAILED)?;
        
        prepared_public_inputs =
            alt_bn128_addition(&[&mul_res[..], &prepared_public_inputs[..]].concat())
                .map_err(|_| PREPARING_INPUTS_G1_ADDITION_FAILED)?;
    }

    Ok(prepared_public_inputs)
}

pub fn is_less_than_bn254_field_size_be(bytes: &[u8; 32]) -> bool {
    let bigint = BigUint::from_bytes_be(bytes);
    bigint < ark_bn254::Fr::MODULUS.into()
}

#[derive(PartialEq, Eq, Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct ConvertedProof {
    a: [u8; 64],
    b: [u8; 128],
    c: [u8; 64],
    public_inputs: [[u8; 32]; PI_LENGTH],
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct Groth16VerifyingKeyPrepared {
    pub vk_alpha_g1: [u8; 64],
    pub vk_beta_g2: [u8; 128],
    pub vk_gamma_g2: [u8; 128],
    pub vk_delta_g2: [u8; 128],
    pub vk_ic: [[u8; 64]; PI_LENGTH + 1],
}
