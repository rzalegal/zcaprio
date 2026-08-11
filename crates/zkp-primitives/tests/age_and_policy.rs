use zcaprio::{AgePolicy, BirthDay, IssuerKeyFingerprint, RawDemoIdentity, VerifierScope};

fn scope(value: &str) -> VerifierScope {
    VerifierScope::new(value.into()).unwrap()
}

#[test]
fn derives_the_18_year_cutoff_from_the_verifier_date() {
    let as_of = BirthDay::parse_iso("2026-08-11").unwrap();
    let policy = AgePolicy::from_as_of(
        as_of,
        scope("campus-bar"),
        IssuerKeyFingerprint::new("edu-issuer-v1".into()).unwrap(),
    )
    .unwrap();

    assert_eq!(policy.cutoff_day().to_iso_string(), "2008-08-11");
}

#[test]
fn uses_february_28_for_a_leap_day_cutoff_in_a_non_leap_threshold_year() {
    let policy = AgePolicy::from_as_of(
        BirthDay::parse_iso("2020-02-29").unwrap(),
        scope("campus-bar"),
        IssuerKeyFingerprint::new("edu-issuer-v1".into()).unwrap(),
    )
    .unwrap();

    assert_eq!(policy.cutoff_day().to_iso_string(), "2002-02-28");
}

#[test]
fn rejects_invalid_and_out_of_range_dates_with_a_stable_code() {
    for value in ["2026-02-29", "1899-12-31", "2100-01-01"] {
        let error = BirthDay::parse_iso(value).unwrap_err();

        assert_eq!(error.code(), "invalid_date");
    }
}

#[test]
fn blank_scope_is_a_safe_validation_error() {
    let error = VerifierScope::new("  ".into()).unwrap_err();

    assert_eq!(error.code(), "empty_verifier_scope");
    assert!(!error.to_string().contains("birth"));
}

#[test]
fn verifier_scope_accepts_only_the_injective_protocol_alphabet() {
    for invalid in [
        "EU",
        "_issuer",
        "issuer space",
        "issuer.",
        "issuer\0",
        "a".repeat(31).as_str(),
    ] {
        assert!(
            VerifierScope::new(invalid.to_owned()).is_err(),
            "{invalid:?} must be rejected"
        );
    }

    assert!(VerifierScope::new("issuer-01_eu".to_owned()).is_ok());

    assert_ne!(
        scope("passport-check").field_element(),
        scope("residence-check").field_element()
    );
}

#[test]
fn deserialization_preserves_the_protocol_invariants() {
    let policy = AgePolicy::from_as_of(
        BirthDay::parse_iso("2026-08-11").unwrap(),
        scope("campus-bar"),
        IssuerKeyFingerprint::new("edu-issuer-v1".into()).unwrap(),
    )
    .unwrap();
    let mut encoded = serde_json::to_value(policy).unwrap();
    encoded["cutoff_day"] = serde_json::Value::String("2008-08-10".into());

    assert!(serde_json::from_value::<AgePolicy>(encoded).is_err());
    assert!(serde_json::from_str::<BirthDay>("\"1899-12-31\"").is_err());
    assert!(serde_json::from_str::<VerifierScope>("\"  \"").is_err());
}

#[test]
fn raw_demo_identity_serializes_with_a_validated_birth_date() {
    let identity = RawDemoIdentity::new(
        "Demo Learner".into(),
        BirthDay::parse_iso("2008-08-11").unwrap(),
    );

    let encoded = serde_json::to_string(&identity).unwrap();
    let decoded: RawDemoIdentity = serde_json::from_str(&encoded).unwrap();

    assert_eq!(decoded, identity);
}
