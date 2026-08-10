use serde::{Deserialize, Serialize};

/// The public outcome of verifying an age proof.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    /// The proof establishes eligibility.
    Eligible,
    /// The proof is malformed or fails verification.
    InvalidProof,
    /// The proof was previously accepted in this replay context.
    ReplayDetected,
}

/// A privacy-safe verification response with fixed public messages.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VerificationResult {
    status: VerificationStatus,
    code: String,
    message: String,
}

impl VerificationStatus {
    /// Returns the safe, fixed response associated with this status.
    pub fn result(self) -> VerificationResult {
        match self {
            Self::Eligible => VerificationResult {
                status: Self::Eligible,
                code: "eligible".into(),
                message: "The proof establishes eligibility.".into(),
            },
            Self::InvalidProof => VerificationResult {
                status: Self::InvalidProof,
                code: "invalid_proof".into(),
                message: "The proof is invalid.".into(),
            },
            Self::ReplayDetected => VerificationResult {
                status: Self::ReplayDetected,
                code: "replay_detected".into(),
                message: "The proof has already been used.".into(),
            },
        }
    }
}

impl VerificationResult {
    /// Returns the verification status.
    pub const fn status(&self) -> VerificationStatus {
        self.status
    }

    /// Returns the stable public response code.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Returns the safe, fixed public response message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Deserialize)]
struct VerificationResultWire {
    status: VerificationStatus,
    code: String,
    message: String,
}

impl<'de> Deserialize<'de> for VerificationResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = VerificationResultWire::deserialize(deserializer)?;
        let result = wire.status.result();

        if result.code != wire.code || result.message != wire.message {
            return Err(serde::de::Error::custom("invalid verification result"));
        }

        Ok(result)
    }
}
