use core::fmt;
use std::sync::OnceLock;

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::{
    CryptographicSponge,
    poseidon::{PoseidonConfig, PoseidonSponge, find_poseidon_ark_and_mds},
};
use ark_ff::{PrimeField, UniformRand};
use rand::rngs::OsRng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{BirthDay, Country, PrimitiveError, Role, VerifierScope, encoding};

const AGE_DOMAIN: &[u8] = b"ZKPLAB_AGE_V1";
const OWNER_DOMAIN: &[u8] = b"ZKPLAB_OWNER_V1";
const ATTRIBUTE_DOMAIN: &[u8] = b"ZKPLAB_ATTR_V2";
const NULLIFIER_DOMAIN: &[u8] = b"ZKPLAB_NULLIFIER_V1";

static POSEIDON_PARAMETERS: OnceLock<PoseidonConfig<Fr>> = OnceLock::new();

/// A random opening value for an age commitment.
#[derive(Clone, Eq, PartialEq)]
pub struct AgeSalt(Fr);

/// A high-entropy secret that binds a credential to its holder.
#[derive(Clone, Eq, PartialEq)]
pub struct WalletSecret(Fr);

/// A domain-separated commitment to a birth day and random salt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgeCommitment(Fr);

/// A domain-separated commitment to a holder's wallet secret.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnerCommitment(Fr);

/// A domain-separated commitment to the non-age attributes in a credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttributeCommitment(Fr);

/// A scope-specific value used to detect replay without linking verifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Nullifier(Fr);

impl AgeSalt {
    /// Generates a fresh age-commitment salt from operating-system randomness.
    pub fn generate() -> Self {
        Self(Fr::rand(&mut OsRng))
    }

    pub(crate) const fn field_element(&self) -> Fr {
        self.0
    }
}

impl WalletSecret {
    /// Generates a fresh wallet secret from operating-system randomness.
    pub fn generate() -> Self {
        Self(Fr::rand(&mut OsRng))
    }

    pub(crate) const fn field_element(&self) -> Fr {
        self.0
    }
}

impl AgeCommitment {
    /// Checks whether a birth day and salt open this commitment.
    pub fn matches(&self, birth_day: BirthDay, salt: &AgeSalt) -> bool {
        *self == commit_age(birth_day, salt)
    }

    /// Returns the commitment as the protocol's scalar field element.
    pub const fn field_element(self) -> Fr {
        self.0
    }
}

impl OwnerCommitment {
    /// Checks whether a wallet secret opens this commitment.
    pub fn matches(&self, secret: &WalletSecret) -> bool {
        *self == commit_owner(secret)
    }

    /// Returns the commitment as the protocol's scalar field element.
    pub const fn field_element(self) -> Fr {
        self.0
    }
}

impl AttributeCommitment {
    /// Checks whether private country, role, and salt open this commitment.
    pub fn matches(&self, country: &Country, role: Role, salt: &AgeSalt) -> bool {
        *self == commit_attributes(country, role, salt)
    }

    /// Returns the commitment as the protocol's scalar field element.
    pub const fn field_element(self) -> Fr {
        self.0
    }
}

impl Nullifier {
    /// Returns the nullifier as the protocol's scalar field element.
    pub const fn field_element(self) -> Fr {
        self.0
    }
}

impl fmt::Debug for AgeSalt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AgeSalt(REDACTED)")
    }
}

impl fmt::Debug for WalletSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalletSecret(REDACTED)")
    }
}

/// Creates a domain-separated age commitment.
pub fn commit_age(birth_day: BirthDay, salt: &AgeSalt) -> AgeCommitment {
    AgeCommitment(poseidon_hash(&[
        domain(AGE_DOMAIN),
        Fr::from(birth_day.days_since_1900()),
        salt.field_element(),
    ]))
}

/// Creates a domain-separated holder-binding commitment.
pub fn commit_owner(secret: &WalletSecret) -> OwnerCommitment {
    OwnerCommitment(poseidon_hash(&[
        domain(OWNER_DOMAIN),
        secret.field_element(),
    ]))
}

/// Creates a blinded, domain-separated commitment to a credential country and role.
pub fn commit_attributes(country: &Country, role: Role, salt: &AgeSalt) -> AttributeCommitment {
    AttributeCommitment(poseidon_hash(&[
        domain(ATTRIBUTE_DOMAIN),
        country.field_element(),
        role.field_element(),
        salt.field_element(),
    ]))
}

/// Derives a deterministic, verifier-scoped nullifier.
pub fn derive_nullifier(secret: &WalletSecret, scope: &VerifierScope) -> Nullifier {
    Nullifier(poseidon_hash(&[
        domain(NULLIFIER_DOMAIN),
        secret.field_element(),
        scope_field(scope),
    ]))
}

/// Returns the fixed Poseidon parameters shared by native and circuit code.
pub fn protocol_poseidon_parameters() -> PoseidonConfig<Fr> {
    poseidon_parameters().clone()
}

pub(crate) fn age_domain() -> Fr {
    domain(AGE_DOMAIN)
}

pub(crate) fn owner_domain() -> Fr {
    domain(OWNER_DOMAIN)
}

pub(crate) fn attribute_domain() -> Fr {
    domain(ATTRIBUTE_DOMAIN)
}

fn poseidon_hash(input: &[Fr]) -> Fr {
    let mut sponge = PoseidonSponge::new(poseidon_parameters());
    sponge.absorb(&input);
    sponge.squeeze_field_elements(1)[0]
}

fn poseidon_parameters() -> &'static PoseidonConfig<Fr> {
    POSEIDON_PARAMETERS.get_or_init(|| {
        let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(Fr::MODULUS_BIT_SIZE as u64, 3, 8, 56, 0);
        PoseidonConfig::new(8, 56, 5, mds, ark, 3, 1)
    })
}

fn domain(label: &[u8]) -> Fr {
    Fr::from_le_bytes_mod_order(label)
}

fn scope_field(scope: &VerifierScope) -> Fr {
    scope.field_element()
}

macro_rules! field_serde {
    ($type:ty) => {
        impl Serialize for $type {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&encoding::hex(&encoding::canonical(&self.0)))
            }
        }

        impl<'de> Deserialize<'de> for $type {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                encoding::parse(&value)
                    .map(Self)
                    .map_err(|error| serde::de::Error::custom(error.code()))
            }
        }

        impl TryFrom<String> for $type {
            type Error = PrimitiveError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                encoding::parse(&value).map(Self)
            }
        }

        impl From<$type> for String {
            fn from(value: $type) -> Self {
                encoding::hex(&encoding::canonical(&value.0))
            }
        }
    };
}

field_serde!(AgeCommitment);
field_serde!(OwnerCommitment);
field_serde!(AttributeCommitment);
field_serde!(Nullifier);
