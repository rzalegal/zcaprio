//! Composable, opaque proof objects backed by Groth16.
//!
//! See the [library guide](../../../README.md) for direct and composed proof examples.
#![doc = include_str!("../../../README.md")]
#![deny(missing_docs)]

mod age;
mod claim;
mod commitment;
mod credential;
mod encoding;
mod error;
mod groth16;
mod issuer;
mod policy;
mod proof;
mod verification;

pub use age::{BirthDay, RawDemoIdentity};
pub use claim::{
    AgeIsAbove, AgeIsBelow, Claim, ClaimKind, ClaimName, Country, CountryIsEu, Role, RoleIs,
};
pub use commitment::{
    AgeCommitment, AgeSalt, AttributeCommitment, Nullifier, OwnerCommitment, WalletSecret,
    commit_age, commit_attributes, commit_owner, derive_nullifier, protocol_poseidon_parameters,
};
pub use credential::{
    Credential, CredentialAttributes, CredentialHash, IssuerCredentials, SignedAttributeCredential,
};
pub use encoding::{bytes, hex};
pub use error::PrimitiveError;
pub use groth16::{Groth16Backend, Groth16Prover, Groth16Verifier, VerificationPolicy};
pub use issuer::{
    AGE_CREDENTIAL_SCHEMA_V1, AGE_CREDENTIAL_SCHEMA_V2, AgeCredential, IssuerKeyPair,
    IssuerPublicKey, IssuerSignature, credential_challenge_transcript, credential_message,
    issuer_generator_coordinates, issuer_signature_salt,
};
pub use policy::{AgePolicy, IssuerKeyFingerprint, VerifierScope};
pub use proof::{Proof, ProofRequest, Prover};
pub use verification::{ProofArtifact, ProofError, Verification, Verifier};
