//! Shared types and operations for the ZK protocol lab.

mod age;
mod encoding;
mod error;
mod policy;
mod proof;

pub use age::{BirthDay, RawDemoIdentity};
pub use encoding::{bytes, hex};
pub use error::PrimitiveError;
pub use policy::{AgePolicy, IssuerKeyFingerprint, VerifierScope};
pub use proof::{VerificationResult, VerificationStatus};
