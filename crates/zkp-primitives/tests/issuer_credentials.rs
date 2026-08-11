use ark_bn254::Fr;
use ark_ff::UniformRand;
use ark_serialize::CanonicalSerialize;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use serde_json::Value;
use zcaprio::{
    AgeCommitment, AgeCredential, AgeSalt, BirthDay, IssuerKeyPair, OwnerCommitment, WalletSecret,
    commit_age, commit_owner, hex,
};

fn day(value: &str) -> BirthDay {
    BirthDay::parse_iso(value).expect("fixture date is valid")
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
    serde_json::from_value(Value::String(fixed_field(seed))).expect("fixture salt is canonical")
}

fn fixed_wallet_secret(seed: u64) -> WalletSecret {
    serde_json::from_value(Value::String(fixed_field(seed))).expect("fixture secret is canonical")
}

fn fixed_issuer(seed: u64) -> IssuerKeyPair {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    IssuerKeyPair::generate_with_rng(&mut rng)
}

fn age_commitment(seed: u64) -> AgeCommitment {
    commit_age(day("2000-01-02"), &fixed_age_salt(seed))
}

fn owner_commitment(seed: u64) -> OwnerCommitment {
    commit_owner(&fixed_wallet_secret(seed))
}

#[test]
fn issuer_signature_binds_both_commitments() {
    let issuer = fixed_issuer(43);
    let credential = issuer.issue(age_commitment(1), owner_commitment(2));

    assert!(credential.verify(&issuer.public_key()).is_ok());

    let mut changed_age = credential.clone();
    changed_age.age_commitment = age_commitment(3);
    assert!(changed_age.verify(&issuer.public_key()).is_err());

    let mut changed_owner = credential;
    changed_owner.owner_commitment = owner_commitment(4);
    assert!(changed_owner.verify(&issuer.public_key()).is_err());
}

#[test]
fn modified_schema_invalidates_the_credential() {
    let issuer = fixed_issuer(47);
    let mut credential = issuer.issue(age_commitment(5), owner_commitment(6));

    credential.schema_version = 2;

    assert_eq!(
        credential.verify(&issuer.public_key()).unwrap_err().code(),
        "unsupported_schema"
    );
}

#[test]
fn modified_signature_invalidates_the_credential() {
    let issuer = fixed_issuer(53);
    let credential = issuer.issue(age_commitment(7), owner_commitment(8));
    let mut wire = serde_json::to_value(credential).unwrap();
    let signature = wire["signature"].as_str().unwrap();
    let replacement = if signature.starts_with('0') { "1" } else { "0" };
    wire["signature"] = Value::String(format!("{replacement}{}", &signature[1..]));
    let tampered: AgeCredential = serde_json::from_value(wire).unwrap();

    assert_eq!(
        tampered.verify(&issuer.public_key()).unwrap_err().code(),
        "invalid_credential"
    );
}

#[test]
fn a_different_issuer_key_invalidates_the_credential() {
    let issuer = fixed_issuer(59);
    let other = fixed_issuer(61);
    let credential = issuer.issue(age_commitment(9), owner_commitment(10));

    assert_eq!(
        credential.verify(&other.public_key()).unwrap_err().code(),
        "invalid_credential"
    );
}

#[test]
fn credential_names_the_fingerprint_of_the_signing_key() {
    let issuer = fixed_issuer(67);
    let public_key = issuer.public_key();
    let credential = issuer.issue(age_commitment(11), owner_commitment(12));

    assert_eq!(credential.issuer_key_fingerprint, public_key.fingerprint());
}

#[test]
fn credential_and_public_key_round_trip_through_canonical_hex() {
    let issuer = fixed_issuer(71);
    let public_key = issuer.public_key();
    let credential = issuer.issue(age_commitment(13), owner_commitment(14));

    let public_key_json = serde_json::to_string(&public_key).unwrap();
    let credential_json = serde_json::to_string(&credential).unwrap();

    assert_eq!(
        serde_json::from_str::<zcaprio::IssuerPublicKey>(&public_key_json).unwrap(),
        public_key
    );
    let decoded: AgeCredential = serde_json::from_str(&credential_json).unwrap();
    assert_eq!(decoded, credential);
    assert!(decoded.verify(&public_key).is_ok());
}
