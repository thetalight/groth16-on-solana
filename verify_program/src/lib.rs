use ark_ff::PrimeField;
use borsh::{BorshDeserialize, BorshSerialize};
use errors::Groth16Error;
use num_bigint::BigUint;
use solana_program::{
    account_info::AccountInfo, alt_bn128::prelude::*, entrypoint, entrypoint::ProgramResult, msg,
    program_error::ProgramError, pubkey::Pubkey,
};
use verifier_key::VERIFIER_KEY;

pub mod errors;
pub mod verifier_key;
entrypoint!(process_instruction);

const PI_LENGTH: usize = 1;

// Define the instruction enum
#[derive(BorshSerialize, BorshDeserialize)]
pub enum ProgramInstruction {
    Verify(Proof),
}

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let instruction = ProgramInstruction::try_from_slice(instruction_data)?;

    match instruction {
        ProgramInstruction::Verify(proof) => verify_proof(program_id, accounts, proof),
    }
}

fn verify_proof(_program_id: &Pubkey, _accounts: &[AccountInfo], proof: Proof) -> ProgramResult {
    let prepare_input = prepare_inputs(proof.public_inputs.as_slice(), &VERIFIER_KEY)
        .map_err(|_| ProgramError::Custom(1))?;

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

    let pairing_res =
        alt_bn128_pairing(pairing_input.as_slice()).map_err(|_| ProgramError::Custom(2))?;

    if pairing_res[31] != 1 {
        return Err(ProgramError::Custom(3));
    }

    msg!("Proof is valid!");

    Ok(())
}

pub fn prepare_inputs(
    pi: &[[u8; 32]],
    vk: &Groth16VerifyingKeyPrepared,
) -> Result<[u8; 64], Groth16Error> {
    if pi.len() + 1 != vk.vk_ic.len() {
        return Err(Groth16Error::InvalidPublicInputsLength);
    }

    let mut prepared_public_inputs = vk.vk_ic[0];
    for (i, input) in pi.iter().enumerate() {
        if !is_less_than_bn254_field_size_be(input) {
            return Err(Groth16Error::PublicInputGreaterThenFieldSize);
        }
        let mul_res = alt_bn128_multiplication(&[&vk.vk_ic[i + 1][..], &input[..]].concat())
            .map_err(|_| Groth16Error::PreparingInputsG1MulFailed)?;
        prepared_public_inputs =
            alt_bn128_addition(&[&mul_res[..], &prepared_public_inputs[..]].concat())
                .map_err(|_| Groth16Error::PreparingInputsG1AdditionFailed)?[..]
                .try_into()
                .map_err(|_| Groth16Error::PreparingInputsG1AdditionFailed)?;
    }

    Ok(prepared_public_inputs)
}

pub fn is_less_than_bn254_field_size_be(bytes: &[u8; 32]) -> bool {
    let bigint = BigUint::from_bytes_be(bytes);
    bigint < ark_bn254::Fr::MODULUS.into()
}

#[derive(PartialEq, Eq, Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct Proof {
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
