//! Shared types and operations for the ZK protocol lab.
#![deny(missing_docs)]

mod age;
mod commitment;
mod encoding;
mod error;
mod issuer;
mod policy;
mod proof;

pub use age::{BirthDay, RawDemoIdentity};
pub use commitment::{
    AgeCommitment, AgeSalt, Nullifier, OwnerCommitment, WalletSecret, commit_age, commit_owner,
    derive_nullifier, protocol_poseidon_parameters,
};
pub use encoding::{bytes, hex};
pub use error::PrimitiveError;
pub use issuer::{
    AGE_CREDENTIAL_SCHEMA_V1, AgeCredential, IssuerKeyPair, IssuerPublicKey, IssuerSignature,
    credential_challenge_transcript, credential_message, issuer_generator_coordinates,
    issuer_signature_salt,
};
pub use policy::{AgePolicy, IssuerKeyFingerprint, VerifierScope};
pub use proof::{VerificationResult, VerificationStatus};
