use chrono::NaiveDate;

use crate::PrimitiveError;

const FIRST_SUPPORTED_DAY: &str = "1900-01-01";
const LAST_SUPPORTED_DAY: &str = "2099-12-31";
const ISO_DATE_FORMAT: &str = "%Y-%m-%d";

/// A birth date within the protocol's fixed supported date range.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct BirthDay(NaiveDate);

impl BirthDay {
    /// Parses a calendar date in canonical `YYYY-MM-DD` form.
    pub fn parse_iso(value: &str) -> Result<Self, PrimitiveError> {
        let date = NaiveDate::parse_from_str(value, ISO_DATE_FORMAT)
            .map_err(|_| PrimitiveError::InvalidDate)?;
        let first = NaiveDate::parse_from_str(FIRST_SUPPORTED_DAY, ISO_DATE_FORMAT)
            .expect("the fixed first supported day is valid");
        let last = NaiveDate::parse_from_str(LAST_SUPPORTED_DAY, ISO_DATE_FORMAT)
            .expect("the fixed last supported day is valid");

        if date < first || date > last || date.format(ISO_DATE_FORMAT).to_string() != value {
            return Err(PrimitiveError::InvalidDate);
        }

        Ok(Self(date))
    }

    /// Returns the number of whole days elapsed since 1900-01-01.
    pub fn days_since_1900(&self) -> u32 {
        let first = NaiveDate::parse_from_str(FIRST_SUPPORTED_DAY, ISO_DATE_FORMAT)
            .expect("the fixed first supported day is valid");

        (self.0 - first).num_days() as u32
    }

    /// Returns this date in canonical `YYYY-MM-DD` form.
    pub fn to_iso_string(&self) -> String {
        self.0.format(ISO_DATE_FORMAT).to_string()
    }

    pub(crate) fn date(&self) -> NaiveDate {
        self.0
    }

    pub(crate) fn from_date(value: NaiveDate) -> Result<Self, PrimitiveError> {
        Self::parse_iso(&value.format(ISO_DATE_FORMAT).to_string())
    }
}

impl TryFrom<String> for BirthDay {
    type Error = PrimitiveError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse_iso(&value)
    }
}

impl From<BirthDay> for String {
    fn from(value: BirthDay) -> Self {
        value.to_iso_string()
    }
}

/// Classroom-only raw identity input.
///
/// `display_name` is display-only and is deliberately absent from credentials
/// and other serializable protocol types. This type must not be persisted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawDemoIdentity {
    /// A display-only name for the classroom demo.
    pub display_name: String,
    /// The raw birth date used only to create a classroom-demo credential.
    pub birth_date: BirthDay,
}

impl RawDemoIdentity {
    /// Creates display-only classroom input from already validated values.
    pub fn new(display_name: String, birth_date: BirthDay) -> Self {
        Self {
            display_name,
            birth_date,
        }
    }
}
