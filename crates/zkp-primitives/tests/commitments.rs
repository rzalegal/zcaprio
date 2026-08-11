use ark_bn254::Fr;
use ark_ff::UniformRand;
use ark_serialize::CanonicalSerialize;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use zcaprio::{
    AgeCommitment, AgeSalt, BirthDay, OwnerCommitment, VerifierScope, WalletSecret, commit_age,
    commit_owner, derive_nullifier, hex,
};

fn day(value: &str) -> BirthDay {
    BirthDay::parse_iso(value).expect("fixture date is valid")
}

fn scope(value: &str) -> VerifierScope {
    VerifierScope::new(value.to_owned()).expect("fixture scope is valid")
}

fn fixed_field(seed: u64) -> String {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let value = Fr::rand(&mut rng);
    let mut bytes = Vec::new();
    value
        .serialize_compressed(&mut bytes)
        .expect("field serialization succeeds");
    hex(&bytes)
}

fn fixed_age_salt(seed: u64) -> AgeSalt {
    serde_json::from_value(serde_json::Value::String(fixed_field(seed)))
        .expect("fixture salt is canonical")
}

fn fixed_wallet_secret(seed: u64) -> WalletSecret {
    serde_json::from_value(serde_json::Value::String(fixed_field(seed)))
        .expect("fixture secret is canonical")
}

#[test]
fn commitment_opening_requires_matching_date_and_salt() {
    let salt = fixed_age_salt(7);
    let commitment = commit_age(day("2000-01-02"), &salt);

    assert!(commitment.matches(day("2000-01-02"), &salt));
    assert!(!commitment.matches(day("2000-01-03"), &salt));
    assert!(!commitment.matches(day("2000-01-02"), &fixed_age_salt(8)));
}

#[test]
fn owner_commitment_requires_the_matching_wallet_secret() {
    let secret = fixed_wallet_secret(11);
    let commitment = commit_owner(&secret);

    assert!(commitment.matches(&secret));
    assert!(!commitment.matches(&fixed_wallet_secret(12)));
}

#[test]
fn commitment_domains_produce_distinct_artifacts() {
    let age = commit_age(day("1900-01-01"), &fixed_age_salt(17));
    let owner = commit_owner(&fixed_wallet_secret(17));

    assert_ne!(
        serde_json::to_value(age).unwrap(),
        serde_json::to_value(owner).unwrap()
    );
}

#[test]
fn nullifier_is_stable_within_a_scope_and_changes_across_scopes() {
    let secret = fixed_wallet_secret(23);
    let first = derive_nullifier(&secret, &scope("campus-bar"));
    let repeated = derive_nullifier(&secret, &scope("campus-bar"));
    let independent = derive_nullifier(&secret, &scope("music-venue"));

    assert_eq!(first, repeated);
    assert_ne!(first, independent);
}

#[test]
fn salt_and_secret_debug_output_is_redacted() {
    let salt = fixed_age_salt(29);
    let secret = fixed_wallet_secret(31);

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
    let age = commit_age(day("2000-01-02"), &fixed_age_salt(37));
    let owner = commit_owner(&fixed_wallet_secret(41));

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
