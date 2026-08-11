use core::fmt;

/// An opaque artifact emitted by a terminal proof backend.
pub trait ProofArtifact: Send + Sync {
    /// Returns the canonical opaque artifact bytes.
    fn bytes(&self) -> Result<Vec<u8>, ProofError>;

    /// Verifies this artifact through a configured verifier.
    fn verify(&self, verifier: &dyn Verifier) -> Result<Verification, ProofError>;
}

/// A verifier that knows the expected policy and verifying material out of band.
pub trait Verifier: Send + Sync {
    /// Verifies opaque artifact bytes and returns only root validity.
    fn verify(&self, artifact: &[u8]) -> Result<Verification, ProofError>;
}

/// The privacy-safe outcome of artifact verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Verification {
    valid: bool,
}

impl Verification {
    /// Returns whether the root proof relation verified.
    pub const fn valid(&self) -> bool {
        self.valid
    }

    pub(crate) const fn accepted() -> Self {
        Self { valid: true }
    }

    pub(crate) const fn rejected() -> Self {
        Self { valid: false }
    }
}

/// A data-free failure returned by proof construction or verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofError {
    /// The selected claim cannot be compiled by the active backend.
    UnsupportedClaim,
    /// A credential is structurally invalid or lacks a valid issuer binding.
    InvalidCredential,
    /// The private relation cannot be satisfied.
    Unprovable,
    /// The selected backend cannot prove this opaque request.
    IncompatibleBackend,
    /// Artifact bytes are malformed or not canonical.
    InvalidArtifact,
    /// Verification cannot establish the requested root relation.
    VerificationFailed,
}

impl fmt::Display for ProofError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnsupportedClaim => "The claim is unsupported.",
            Self::InvalidCredential => "The credential is invalid.",
            Self::Unprovable => "The proof cannot be produced.",
            Self::IncompatibleBackend => "The proof backend is incompatible.",
            Self::InvalidArtifact => "The proof artifact is invalid.",
            Self::VerificationFailed => "The proof did not verify.",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ProofError {}
