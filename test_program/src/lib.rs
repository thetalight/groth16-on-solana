use std::ops::Neg;

use ark_bn254::{Bn254, Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::CanonicalSerialize;
use errors::Groth16Error;
use solana_program::alt_bn128::{
    compression::prelude::convert_endianness,
    prelude::{alt_bn128_addition, alt_bn128_multiplication, alt_bn128_pairing},
};
use utils::{convert_endianness_32, is_less_than_bn254_field_size_be};

pub mod circuit;
pub mod errors;
pub mod utils;

pub struct ConvertedProof {
    pub a: [u8; 64],
    pub b: [u8; 128],
    pub c: [u8; 64],
}


#[derive(Debug)]
pub struct ConvertedVK {
    pub vk_alpha_g1: [u8; 64],
    pub vk_beta_g2: [u8; 128],
    pub vk_gamma_g2: [u8; 128],
    pub vk_delta_g2: [u8; 128],
    pub vk_ic: Box<[[u8; 64]]>,
}

pub type ConvertedPI = Vec<[u8; 32]>;

pub struct Groth16Verifier;

impl Groth16Verifier {
    pub fn convert_proof(proof: &Proof<Bn254>) -> ConvertedProof {
        let proof_with_neg_a = Proof::<Bn254> {
            a: proof.a.neg(),
            b: proof.b,
            c: proof.c,
        };

        let mut bytes = vec![];
        proof_with_neg_a.serialize_uncompressed(&mut bytes).unwrap();

        let a: [u8; 64] = convert_endianness::<32, 64>(bytes[0..64].try_into().unwrap());
        let b: [u8; 128] = convert_endianness::<64, 128>(bytes[64..192].try_into().unwrap());
        let c: [u8; 64] = convert_endianness::<32, 64>(bytes[192..256].try_into().unwrap());

        ConvertedProof { a, b, c }
    }

    pub fn convert_vk(vk: &VerifyingKey<Bn254>) -> ConvertedVK {
        let mut vk_alpha_g1 = [0u8; 64];
        vk.alpha_g1
            .serialize_uncompressed(&mut vk_alpha_g1[..])
            .unwrap();

        let mut vk_beta_g2 = [0u8; 128];
        vk.beta_g2
            .serialize_uncompressed(&mut vk_beta_g2[..])
            .unwrap();

        let mut vk_gamma_g2 = [0u8; 128];
        vk.gamma_g2
            .serialize_uncompressed(&mut vk_gamma_g2[..])
            .unwrap();

        let mut vk_delta_g2 = [0u8; 128];
        vk.delta_g2
            .serialize_uncompressed(&mut vk_delta_g2[..])
            .unwrap();

        let vk_ic: Vec<[u8; 64]> = vk
            .gamma_abc_g1
            .iter()
            .map(|point| {
                let mut buf = [0u8; 64];
                point.serialize_uncompressed(&mut buf[..]).unwrap();
                convert_endianness::<32, 64>(&buf)
            })
            .collect();

        let vk_alpha_g1_converted = convert_endianness::<32, 64>(&vk_alpha_g1);
        let vk_beta_g2_converted = convert_endianness::<64, 128>(&vk_beta_g2);
        let vk_gamma_g2_converted = convert_endianness::<64, 128>(&vk_gamma_g2);
        let vk_delta_g2_converted = convert_endianness::<64, 128>(&vk_delta_g2);

        ConvertedVK {
            vk_alpha_g1: vk_alpha_g1_converted,
            vk_beta_g2: vk_beta_g2_converted,
            vk_gamma_g2: vk_gamma_g2_converted,
            vk_delta_g2: vk_delta_g2_converted,
            vk_ic: vk_ic.into_boxed_slice(),
        }
    }

    pub fn convert_public_input(pi: &[Fr]) -> ConvertedPI {
        let mut converted = vec![];
        for x in pi {
            let bytes = x.into_bigint().to_bytes_be();
            converted.push(convert_endianness_32(&bytes));
        }
        converted
    }

    pub fn prepare_inputs(
        converted_pi: &ConvertedPI,
        converted_vk: &ConvertedVK,
    ) -> Result<[u8; 64], Groth16Error> {
        assert_eq!(converted_pi.len() + 1, converted_vk.vk_ic.len());

        let mut prepared_public_inputs = converted_vk.vk_ic[0];
        for (i, input) in converted_pi.iter().enumerate() {
            if !is_less_than_bn254_field_size_be(input) {
                return Err(Groth16Error::PublicInputGreaterThenFieldSize);
            }
            let mul_res =
                alt_bn128_multiplication(&[&converted_vk.vk_ic[i + 1][..], &input[..]].concat())
                    .map_err(|_| Groth16Error::PreparingInputsG1MulFailed)?;
            prepared_public_inputs =
                alt_bn128_addition(&[&mul_res[..], &prepared_public_inputs[..]].concat())
                    .map_err(|_| Groth16Error::PreparingInputsG1AdditionFailed)?[..]
                    .try_into()
                    .map_err(|_| Groth16Error::PreparingInputsG1AdditionFailed)?;
        }

        Ok(prepared_public_inputs)
    }

    pub fn verify(
        proof: &Proof<Bn254>,
        pi: &[Fr],
        vk: &VerifyingKey<Bn254>,
    ) -> Result<(), Groth16Error> {
        let converted_proof = Self::convert_proof(proof);
        let converted_pi = Self::convert_public_input(pi);
        let converted_vk = Self::convert_vk(vk);
        println!("{:?}",converted_vk);
        Self::verify_with_converted(&converted_proof, &converted_pi, &converted_vk)
    }

    pub fn verify_with_converted(
        proof: &ConvertedProof,
        pi: &ConvertedPI,
        vk: &ConvertedVK,
    ) -> Result<(), Groth16Error> {
        let prepare_inputs = Self::prepare_inputs(pi, vk).unwrap();

        let pairing_input = [
            proof.a.as_slice(),
            proof.b.as_slice(),
            prepare_inputs.as_slice(),
            vk.vk_gamma_g2.as_slice(),
            proof.c.as_slice(),
            vk.vk_delta_g2.as_slice(),
            vk.vk_alpha_g1.as_slice(),
            vk.vk_beta_g2.as_slice(),
        ]
        .concat();

        let pairing_res = alt_bn128_pairing(pairing_input.as_slice())
            .map_err(|_| Groth16Error::ProofVerificationFailed)?;

        if pairing_res[31] != 1 {
            return Err(Groth16Error::ProofVerificationFailed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use ark_bn254::{Bn254, Fr};
    use ark_groth16::Groth16;
    use ark_serialize::CanonicalSerialize;
    use ark_snark::SNARK;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    use crate::{circuit::Multiplier2Circuit, Groth16Verifier};

    #[test]
    fn test_circuit() {
        let mut rng = ChaChaRng::from_seed([0u8; 32]);

        let a = Fr::from(3);
        let b = Fr::from(4);
        let circuit = Multiplier2Circuit::new(a, b);

        let (prover_key, verifier_key) =
            Groth16::<Bn254>::circuit_specific_setup(Multiplier2Circuit::default(), &mut rng)
                .unwrap();

            // {
            //     let mut p_bytes = vec![];
            //      prover_key.serialize_compressed(&mut p_bytes).unwrap();
            //     println!("pbytes:{:?}",p_bytes);
            //      let mut v_bytes = vec![];
            //      verifier_key.serialize_compressed(&mut v_bytes).unwrap();
            //      println!("vbytes:{:?}",p_bytes);
            // }

        let proof = Groth16::<Bn254>::prove(&prover_key, circuit.clone(), &mut rng).unwrap();

        let pvk = Groth16::<Bn254>::process_vk(&verifier_key).unwrap();
        assert!(Groth16::<ark_bn254::Bn254>::verify_with_processed_vk(
            &pvk,
            &circuit.public_inputs(),
            &proof
        )
        .unwrap());

        Groth16Verifier::verify(&proof, &circuit.public_inputs(), &pvk.vk).unwrap();
    }
}
