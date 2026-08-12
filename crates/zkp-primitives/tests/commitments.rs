use zcaprio::{
    AgeCommitment, AgeSalt, BirthDay, Country, OwnerCommitment, Role, VerifierScope, WalletSecret,
    commit_age, commit_attributes, commit_owner, derive_nullifier,
};

fn day(value: &str) -> BirthDay {
    BirthDay::parse_iso(value).expect("fixture date is valid")
}

fn scope(value: &str) -> VerifierScope {
    VerifierScope::new(value.to_owned()).expect("fixture scope is valid")
}

fn age_salt() -> AgeSalt {
    AgeSalt::generate()
}

fn wallet_secret() -> WalletSecret {
    WalletSecret::generate()
}

#[test]
fn commitment_opening_requires_matching_date_and_salt() {
    let salt = age_salt();
    let commitment = commit_age(day("2000-01-02"), &salt);

    assert!(commitment.matches(day("2000-01-02"), &salt));
    assert!(!commitment.matches(day("2000-01-03"), &salt));
    assert!(!commitment.matches(day("2000-01-02"), &age_salt()));
}

#[test]
fn owner_commitment_requires_the_matching_wallet_secret() {
    let secret = wallet_secret();
    let commitment = commit_owner(&secret);

    assert!(commitment.matches(&secret));
    assert!(!commitment.matches(&wallet_secret()));
}

#[test]
fn attribute_commitment_requires_the_matching_private_salt() {
    let salt = age_salt();
    let country = Country::try_from("DE".to_owned()).expect("fixture country is valid");
    let commitment = commit_attributes(&country, Role::Staff, &salt);

    assert!(commitment.matches(&country, Role::Staff, &salt));
    assert!(!commitment.matches(&country, Role::Student, &salt));
    assert!(!commitment.matches(&country, Role::Staff, &age_salt()));
}

#[test]
fn commitment_domains_produce_distinct_artifacts() {
    let age = commit_age(day("1900-01-01"), &age_salt());
    let owner = commit_owner(&wallet_secret());

    assert_ne!(
        serde_json::to_value(age).unwrap(),
        serde_json::to_value(owner).unwrap()
    );
}

#[test]
fn nullifier_is_stable_within_a_scope_and_changes_across_scopes() {
    let secret = wallet_secret();
    let first = derive_nullifier(&secret, &scope("campus-bar"));
    let repeated = derive_nullifier(&secret, &scope("campus-bar"));
    let independent = derive_nullifier(&secret, &scope("music-venue"));

    assert_eq!(first, repeated);
    assert_ne!(first, independent);
}

#[test]
fn salt_and_secret_debug_output_is_redacted() {
    let salt = age_salt();
    let secret = wallet_secret();

    assert_eq!(format!("{salt:?}"), "AgeSalt(REDACTED)");
    assert_eq!(format!("{secret:?}"), "WalletSecret(REDACTED)");
}

#[test]
fn generated_salt_and_secret_are_usable() {
    let salt = AgeSalt::generate();
    let secret = WalletSecret::generate();

    assert!(commit_age(day("2000-01-02"), &salt).matches(day("2000-01-02"), &salt));
    assert!(commit_owner(&secret).matches(&secret));
}

#[test]
fn protocol_artifacts_round_trip_through_canonical_hex() {
    let age = commit_age(day("2000-01-02"), &age_salt());
    let owner = commit_owner(&wallet_secret());

    let age_json = serde_json::to_string(&age).unwrap();
    let owner_json = serde_json::to_string(&owner).unwrap();

    assert_eq!(
        serde_json::from_str::<AgeCommitment>(&age_json).unwrap(),
        age
    );
    assert_eq!(
        serde_json::from_str::<OwnerCommitment>(&owner_json).unwrap(),
        owner
    );
}

#[test]
fn invalid_hex_is_rejected_as_invalid_encoding() {
    let error = serde_json::from_str::<AgeCommitment>("\"NOT-HEX\"").unwrap_err();

    assert!(error.to_string().contains("invalid_encoding"));
}
