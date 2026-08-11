use ark_bn254::Fr;
use ark_ed_on_bn254::{EdwardsAffine, Fr as JubJubScalar};
use ark_serialize::CanonicalSerialize;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use serde_json::Value;
use zcaprio::{
    AgeCommitment, AgeCredential, AgeSalt, AttributeCommitment, BirthDay, IssuerKeyPair,
    IssuerSignature, OwnerCommitment, WalletSecret, commit_age, commit_owner,
    credential_challenge_transcript, credential_message, hex,
};

fn day(value: &str) -> BirthDay {
    BirthDay::parse_iso(value).expect("fixture date is valid")
}

fn age_salt() -> AgeSalt {
    AgeSalt::generate()
}

fn wallet_secret() -> WalletSecret {
    WalletSecret::generate()
}

fn fixed_issuer(seed: u64) -> IssuerKeyPair {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    IssuerKeyPair::generate_with_rng(&mut rng)
}

fn age_commitment(_seed: u64) -> AgeCommitment {
    commit_age(day("2000-01-02"), &age_salt())
}

fn owner_commitment(_seed: u64) -> OwnerCommitment {
    commit_owner(&wallet_secret())
}

fn field_hex(value: u64) -> String {
    let mut encoded = Vec::new();
    Fr::from(value)
        .serialize_compressed(&mut encoded)
        .expect("field encodes in memory");
    hex(&encoded)
}

fn scalar_hex(value: u64) -> String {
    let mut encoded = Vec::new();
    JubJubScalar::from(value)
        .serialize_compressed(&mut encoded)
        .expect("scalar encodes in memory");
    hex(&encoded)
}

fn commitment(value: u64) -> AgeCommitment {
    serde_json::from_str(&format!("\"{}\"", field_hex(value)))
        .expect("commitment fixture is canonical")
}

fn owner(value: u64) -> OwnerCommitment {
    serde_json::from_str(&format!("\"{}\"", field_hex(value))).expect("owner fixture is canonical")
}

fn attributes(value: u64) -> AttributeCommitment {
    serde_json::from_str(&format!("\"{}\"", field_hex(value)))
        .expect("attribute commitment fixture is canonical")
}

fn signature(response: u64, challenge: u64) -> IssuerSignature {
    let encoded = format!("\"{}{}\"", scalar_hex(response), scalar_hex(challenge));
    serde_json::from_str(&encoded).expect("signature fixture is canonical")
}

#[test]
fn issuer_signature_binds_both_commitments() {
    let issuer = fixed_issuer(43);
    let credential = issuer.issue(age_commitment(1), owner_commitment(2), attributes(3));

    assert!(credential.verify(&issuer.public_key()).is_ok());

    let mut changed_age = credential.clone();
    changed_age.age_commitment = age_commitment(3);
    assert!(changed_age.verify(&issuer.public_key()).is_err());

    let mut changed_owner = credential;
    changed_owner.owner_commitment = owner_commitment(4);
    assert!(changed_owner.verify(&issuer.public_key()).is_err());
}

#[test]
fn issuer_signature_binds_the_attribute_commitment() {
    let issuer = fixed_issuer(45);
    let credential = issuer.issue(age_commitment(1), owner_commitment(2), attributes(3));

    assert!(credential.verify(&issuer.public_key()).is_ok());

    let mut changed = credential;
    changed.attribute_commitment = attributes(4);

    assert!(changed.verify(&issuer.public_key()).is_err());
}

#[test]
fn modified_schema_invalidates_the_credential() {
    let issuer = fixed_issuer(47);
    let mut credential = issuer.issue(age_commitment(5), owner_commitment(6), attributes(7));

    credential.schema_version = 3;

    assert_eq!(
        credential.verify(&issuer.public_key()).unwrap_err().code(),
        "unsupported_schema"
    );
}

#[test]
fn modified_signature_invalidates_the_credential() {
    let issuer = fixed_issuer(53);
    let credential = issuer.issue(age_commitment(7), owner_commitment(8), attributes(9));
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
    let credential = issuer.issue(age_commitment(9), owner_commitment(10), attributes(11));

    assert_eq!(
        credential.verify(&other.public_key()).unwrap_err().code(),
        "invalid_credential"
    );
}

#[test]
fn credential_names_the_fingerprint_of_the_signing_key() {
    let issuer = fixed_issuer(67);
    let public_key = issuer.public_key();
    let credential = issuer.issue(age_commitment(11), owner_commitment(12), attributes(13));

    assert_eq!(credential.issuer_key_fingerprint, public_key.fingerprint());
}

#[test]
fn credential_and_public_key_round_trip_through_canonical_hex() {
    let issuer = fixed_issuer(71);
    let public_key = issuer.public_key();
    let credential = issuer.issue(age_commitment(13), owner_commitment(14), attributes(15));

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

#[test]
fn rejects_an_identity_issuer_public_key() {
    let mut encoded = Vec::new();
    EdwardsAffine::zero()
        .serialize_compressed(&mut encoded)
        .expect("identity encodes in memory");
    let identity = format!("\"{}\"", hex(&encoded));

    assert!(serde_json::from_str::<zcaprio::IssuerPublicKey>(&identity).is_err());
}

#[test]
fn transcript_matches_the_pinned_v2_wire_vector() {
    let issuer = fixed_issuer(101);
    let signature = signature(5, 7);
    let message = credential_message(commitment(11), owner(13), attributes(17), 2);

    let transcript = credential_challenge_transcript(&issuer.public_key(), &signature, &message);

    assert_eq!(
        hex(&transcript),
        "0f821bc0f51832d8a2aefd20d1207c375b38639709ecf683913f7b1336a9ecdeef107f70581dc87cbe984d2d98e51fed745aa867de8c0945533555ff46f04701a1cdc809be3d48c7e6498086d00260565cac06fd16ed915fd7943a2f74a4312180000000000000000b000000000000000000000000000000000000000000000000000000000000000d0000000000000000000000000000000000000000000000000000000000000011000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000"
    );
}
