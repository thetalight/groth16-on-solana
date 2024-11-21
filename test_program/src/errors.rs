use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Groth16Error {
    #[error("ProofVerificationFailed")]
    ProofVerificationFailed,
    #[error("PreparingInputsG1AdditionFailed")]
    PreparingInputsG1AdditionFailed,
    #[error("PreparingInputsG1MulFailed")]
    PreparingInputsG1MulFailed,
    #[error("InvalidPublicInputsLength")]
    InvalidPublicInputsLength,
    #[error("DecompressingG1Failed")]
    DecompressingG1Failed,
    #[error("DecompressingG2Failed")]
    DecompressingG2Failed,
    #[error("PublicInputGreaterThenFieldSize")]
    PublicInputGreaterThenFieldSize,
}
