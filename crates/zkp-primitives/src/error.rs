use core::fmt;

use serde::{Deserialize, Serialize};

/// Errors returned when data crosses the protocol primitive boundary.
///
/// Every variant is intentionally data-free so error display and serialized
/// payloads never disclose identity, salt, or secret values.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrimitiveError {
    /// A date is malformed or outside the supported protocol range.
    InvalidDate,
    /// A verifier scope is blank after trimming whitespace.
    EmptyVerifierScope,
    /// A payload declares an unsupported protocol schema.
    UnsupportedSchema,
    /// A payload is not canonically encoded.
    InvalidEncoding,
    /// A credential does not satisfy the protocol's structural requirements.
    InvalidCredential,
    /// The requested proof cannot be produced.
    ProofPrevented,
    /// A proof cannot be verified.
    InvalidProof,
    /// A proof has already been accepted for the same replay context.
    ReplayDetected,
}

impl PrimitiveError {
    /// Returns the stable machine-readable code for this error.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidDate => "invalid_date",
            Self::EmptyVerifierScope => "empty_verifier_scope",
            Self::UnsupportedSchema => "unsupported_schema",
            Self::InvalidEncoding => "invalid_encoding",
            Self::InvalidCredential => "invalid_credential",
            Self::ProofPrevented => "proof_prevented",
            Self::InvalidProof => "invalid_proof",
            Self::ReplayDetected => "replay_detected",
        }
    }

    /// Returns a safe, constant description suitable for a response payload.
    pub const fn message(&self) -> &'static str {
        match self {
            Self::InvalidDate => "The date is invalid.",
            Self::EmptyVerifierScope => "The verifier scope is required.",
            Self::UnsupportedSchema => "The protocol schema is unsupported.",
            Self::InvalidEncoding => "The protocol encoding is invalid.",
            Self::InvalidCredential => "The credential is invalid.",
            Self::ProofPrevented => "The proof cannot be produced.",
            Self::InvalidProof => "The proof is invalid.",
            Self::ReplayDetected => "The proof has already been used.",
        }
    }
}

impl fmt::Display for PrimitiveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl std::error::Error for PrimitiveError {}
