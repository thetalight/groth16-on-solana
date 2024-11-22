use ark_ff::PrimeField;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct Multiplier2Circuit<F: PrimeField> {
    pub a: F,
    pub b: F,
    pub c: F,
}

impl<F: PrimeField> Multiplier2Circuit<F> {
    pub fn new(a: F, b: F) -> Self {
        let c = a.mul(&b);
        Self { a, b, c }
    }

    pub fn public_inputs(&self) -> Vec<F> {
        vec![self.c]
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for Multiplier2Circuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let a_var = cs.new_witness_variable(|| Ok(self.a))?;
        let b_var = cs.new_witness_variable(|| Ok(self.b))?;
        let c_var = cs.new_input_variable(|| Ok(self.c))?;

        cs.enforce_constraint(lc!() + a_var, lc!() + b_var, lc!() + c_var)?;

        Ok(())
    }
}
