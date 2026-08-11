use zcaprio::{
    AgeIsAbove, AgeSalt, BirthDay, Country, CountryIsEu, Credential, CredentialAttributes,
    Groth16Backend, IssuerKeyPair, Role, RoleIs, VerificationPolicy, WalletSecret,
};

fn day(value: &str) -> BirthDay {
    BirthDay::parse_iso(value).expect("fixture date is valid")
}

fn country(value: &str) -> Country {
    Country::try_from(value.to_owned()).expect("fixture country is valid")
}

fn credential(
    issuer: &IssuerKeyPair,
    birth_day: &str,
    country_code: &str,
    role: Role,
) -> zcaprio::SignedAttributeCredential {
    issuer.credentials().issue(CredentialAttributes::new(
        day(birth_day),
        country(country_code),
        role,
        AgeSalt::generate(),
        WalletSecret::generate(),
    ))
}

#[test]
fn issued_cross_credential_composition_proves_as_one_opaque_artifact() {
    let passport_issuer = IssuerKeyPair::generate();
    let residence_issuer = IssuerKeyPair::generate();
    let badge_issuer = IssuerKeyPair::generate();
    let passport = credential(&passport_issuer, "2000-01-01", "US", Role::Student);
    let residence = credential(&residence_issuer, "2010-01-01", "DE", Role::Visitor);
    let badge = credential(&badge_issuer, "2010-01-01", "US", Role::Staff);
    let backend = Groth16Backend::setup(VerificationPolicy::new(day("2026-08-11")))
        .expect("backend setup succeeds");

    let proof = passport
        .is(Box::new(AgeIsAbove::new(18)))
        .and(residence.is(Box::new(CountryIsEu)))
        .or(badge.is(Box::new(RoleIs::new(Role::Staff))));
    let artifact = proof.prove(backend.prover()).expect("issued claims prove");

    assert!(
        artifact
            .verify(backend.verifier())
            .expect("artifact verifies")
            .valid()
    );
    let encoded = artifact.bytes().expect("artifact serializes");
    let rendered = String::from_utf8_lossy(&encoded);
    assert!(!rendered.contains("passport"));
    assert!(!rendered.contains("left"));
    assert!(!rendered.contains("right"));
}

#[test]
fn unsigned_age_is_not_provable_through_the_public_credential_api() {
    let issuer = IssuerKeyPair::generate();
    let underage = credential(&issuer, "2015-01-01", "US", Role::Visitor);
    let backend = Groth16Backend::setup(VerificationPolicy::new(day("2026-08-11")))
        .expect("backend setup succeeds");

    let result = underage
        .is(Box::new(AgeIsAbove::new(18)))
        .prove(backend.prover());

    assert!(matches!(result, Err(zcaprio::ProofError::Unprovable)));
}
