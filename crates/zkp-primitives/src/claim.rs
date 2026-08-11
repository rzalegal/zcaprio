use core::fmt;

use crate::ProofError;

/// A named predicate that a credential holder can establish privately.
pub trait Claim: Send + Sync {
    /// Returns the stable name of this predicate.
    fn name(&self) -> ClaimName;

    /// Returns the built-in relation requested by this claim.
    fn kind(&self) -> ClaimKind;
}

/// A built-in predicate relation understood by the Groth16 backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimKind {
    /// Requires an age of at least the supplied number of years.
    AgeAbove(u8),
    /// Requires an age of at most the supplied number of years.
    AgeBelow(u8),
    /// Requires an EU country code.
    CountryIsEu,
    /// Requires a specific role.
    Role(Role),
    /// A custom claim whose compiler is not installed.
    Custom,
}

/// A two-letter ISO-style country code held inside an issued credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Country([u8; 2]);

impl Country {
    /// Returns the country code as uppercase ASCII text.
    pub fn code(&self) -> &str {
        std::str::from_utf8(&self.0).expect("validated country code is ASCII")
    }

    pub(crate) fn is_eu(&self) -> bool {
        matches!(
            self.code(),
            "AT" | "BE"
                | "BG"
                | "HR"
                | "CY"
                | "CZ"
                | "DK"
                | "EE"
                | "FI"
                | "FR"
                | "DE"
                | "GR"
                | "HU"
                | "IE"
                | "IT"
                | "LV"
                | "LT"
                | "LU"
                | "MT"
                | "NL"
                | "PL"
                | "PT"
                | "RO"
                | "SK"
                | "SI"
                | "ES"
                | "SE"
        )
    }
}

impl TryFrom<String> for Country {
    type Error = ProofError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let bytes = value.as_bytes();
        if bytes.len() != 2 || !bytes.iter().all(u8::is_ascii_uppercase) {
            return Err(ProofError::InvalidCredential);
        }
        Ok(Self([bytes[0], bytes[1]]))
    }
}

/// A role included in a signed attribute credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// A staff member.
    Staff,
    /// A student.
    Student,
    /// A visitor.
    Visitor,
}

/// A claim requiring an age at or above a whole-year threshold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgeIsAbove(u8);

impl AgeIsAbove {
    /// Creates an age-at-least claim.
    pub const fn new(years: u8) -> Self {
        Self(years)
    }
}

impl Claim for AgeIsAbove {
    fn name(&self) -> ClaimName {
        ClaimName::try_from(format!("age_is_above_{}", self.0))
            .expect("built-in claim name is valid")
    }

    fn kind(&self) -> ClaimKind {
        ClaimKind::AgeAbove(self.0)
    }
}

/// A claim requiring an age at or below a whole-year threshold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgeIsBelow(u8);

impl AgeIsBelow {
    /// Creates an age-at-most claim.
    pub const fn new(years: u8) -> Self {
        Self(years)
    }
}

impl Claim for AgeIsBelow {
    fn name(&self) -> ClaimName {
        ClaimName::try_from(format!("age_is_below_{}", self.0))
            .expect("built-in claim name is valid")
    }

    fn kind(&self) -> ClaimKind {
        ClaimKind::AgeBelow(self.0)
    }
}

/// A claim requiring an EU country.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CountryIsEu;

impl Claim for CountryIsEu {
    fn name(&self) -> ClaimName {
        ClaimName::try_from("country_is_eu".to_owned()).expect("built-in claim name is valid")
    }

    fn kind(&self) -> ClaimKind {
        ClaimKind::CountryIsEu
    }
}

/// A claim requiring a credential role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoleIs(Role);

impl RoleIs {
    /// Creates a role claim.
    pub const fn new(role: Role) -> Self {
        Self(role)
    }
}

impl Claim for RoleIs {
    fn name(&self) -> ClaimName {
        ClaimName::try_from("role_is".to_owned()).expect("built-in claim name is valid")
    }

    fn kind(&self) -> ClaimKind {
        ClaimKind::Role(self.0)
    }
}

/// A validated, human-readable claim name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimName(String);

impl ClaimName {
    /// Returns this claim name as protocol text.
    pub fn value(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ClaimName {
    type Error = ProofError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty()
            || value.len() > 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(ProofError::UnsupportedClaim);
        }

        Ok(Self(value))
    }
}

impl fmt::Display for ClaimName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}
