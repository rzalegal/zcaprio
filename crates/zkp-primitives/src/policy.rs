use ark_bn254::Fr;
use ark_ff::PrimeField;
use chrono::{Datelike, NaiveDate};
use serde::{Deserialize, Serialize};

use crate::{BirthDay, PrimitiveError};

/// A verifier-controlled context that scopes an age verification request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct VerifierScope(String);

impl VerifierScope {
    /// Validates a verifier scope in the protocol's canonical ASCII form.
    pub fn new(value: String) -> Result<Self, PrimitiveError> {
        if value.trim().is_empty() {
            return Err(PrimitiveError::EmptyVerifierScope);
        }
        if value.len() > 30
            || !value
                .bytes()
                .enumerate()
                .all(|(index, byte)| scope_byte(index, byte))
        {
            return Err(PrimitiveError::InvalidVerifierScope);
        }

        Ok(Self(value))
    }

    /// Returns the normalized verifier scope.
    pub fn value(&self) -> &str {
        &self.0
    }

    /// Packs this validated scope injectively into the protocol scalar field.
    pub fn field_element(&self) -> Fr {
        let mut encoded = Vec::with_capacity(self.0.len() + 1);
        encoded.push(self.0.len() as u8);
        encoded.extend_from_slice(self.0.as_bytes());
        Fr::from_le_bytes_mod_order(&encoded)
    }
}

fn scope_byte(index: usize, byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || (index > 0 && matches!(byte, b'-' | b'_'))
}

impl TryFrom<String> for VerifierScope {
    type Error = PrimitiveError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<VerifierScope> for String {
    fn from(value: VerifierScope) -> Self {
        value.0
    }
}

/// A stable identifier for the issuer key that signed a credential.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct IssuerKeyFingerprint(String);

impl IssuerKeyFingerprint {
    /// Validates and normalizes an issuer-key fingerprint.
    pub fn new(value: String) -> Result<Self, PrimitiveError> {
        let value = value.trim().to_owned();
        if value.is_empty() {
            return Err(PrimitiveError::InvalidCredential);
        }

        Ok(Self(value))
    }

    /// Returns the normalized issuer-key fingerprint.
    pub fn value(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for IssuerKeyFingerprint {
    type Error = PrimitiveError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<IssuerKeyFingerprint> for String {
    fn from(value: IssuerKeyFingerprint) -> Self {
        value.0
    }
}

/// A verifier's public policy for establishing age eligibility.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AgePolicy {
    issuer_key_fingerprint: IssuerKeyFingerprint,
    as_of_day: BirthDay,
    cutoff_day: BirthDay,
    verifier_scope: VerifierScope,
}

#[derive(Deserialize)]
struct AgePolicyWire {
    issuer_key_fingerprint: IssuerKeyFingerprint,
    as_of_day: BirthDay,
    cutoff_day: BirthDay,
    verifier_scope: VerifierScope,
}

impl<'de> Deserialize<'de> for AgePolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = AgePolicyWire::deserialize(deserializer)?;
        let policy = Self::from_as_of(
            wire.as_of_day,
            wire.verifier_scope,
            wire.issuer_key_fingerprint,
        )
        .map_err(serde::de::Error::custom)?;

        if policy.cutoff_day != wire.cutoff_day {
            return Err(serde::de::Error::custom(PrimitiveError::InvalidCredential));
        }

        Ok(policy)
    }
}

impl AgePolicy {
    /// Derives an 18-year age cutoff from the verifier's requested date.
    ///
    /// A February 29 cutoff in a non-leap year is represented as February 28.
    pub fn from_as_of(
        as_of_day: BirthDay,
        verifier_scope: VerifierScope,
        issuer_key_fingerprint: IssuerKeyFingerprint,
    ) -> Result<Self, PrimitiveError> {
        let cutoff = Self::cutoff(as_of_day.date())?;

        Ok(Self {
            issuer_key_fingerprint,
            as_of_day,
            cutoff_day: BirthDay::from_date(cutoff)?,
            verifier_scope,
        })
    }

    /// Returns the issuer-key fingerprint accepted by this policy.
    pub fn issuer_key_fingerprint(&self) -> &IssuerKeyFingerprint {
        &self.issuer_key_fingerprint
    }

    /// Returns the verifier date used to derive the policy.
    pub fn as_of_day(&self) -> &BirthDay {
        &self.as_of_day
    }

    /// Returns the latest birth date that satisfies this 18-year policy.
    pub fn cutoff_day(&self) -> &BirthDay {
        &self.cutoff_day
    }

    /// Returns the verifier scope for this policy.
    pub fn verifier_scope(&self) -> &VerifierScope {
        &self.verifier_scope
    }

    fn cutoff(as_of_day: NaiveDate) -> Result<NaiveDate, PrimitiveError> {
        let year = as_of_day
            .year()
            .checked_sub(18)
            .ok_or(PrimitiveError::InvalidDate)?;
        let month = as_of_day.month();
        let day = if month == 2 && as_of_day.day() == 29 {
            28
        } else {
            as_of_day.day()
        };

        NaiveDate::from_ymd_opt(year, month, day).ok_or(PrimitiveError::InvalidDate)
    }
}
