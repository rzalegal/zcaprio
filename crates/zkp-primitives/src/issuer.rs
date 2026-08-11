use core::{fmt, ops::Mul};
use std::sync::OnceLock;

use ark_bn254::Fr;
use ark_crypto_primitives::signature::{
    SignatureScheme,
    schnorr::{Parameters, Schnorr, SecretKey, Signature},
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective, Fr as JubJubScalar};
use ark_ff::{Field, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use blake2::{Blake2s256, Digest};
use rand::{CryptoRng, Rng, SeedableRng, rngs::OsRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{AgeCommitment, IssuerKeyFingerprint, OwnerCommitment, PrimitiveError, encoding};

/// The supported age-credential schema version.
pub const AGE_CREDENTIAL_SCHEMA_V1: u8 = 1;

const PARAMETER_SEED: [u8; 32] = *b"ZKPLAB_ISSUER_SCHNORR_PARAMS_V1!";

type IssuerSchnorr = Schnorr<EdwardsProjective, Blake2s256>;

static SCHNORR_PARAMETERS: OnceLock<Parameters<EdwardsProjective, Blake2s256>> = OnceLock::new();

/// A Baby-JubJub Schnorr issuer key pair.
pub struct IssuerKeyPair {
    public_key: IssuerPublicKey,
    secret_key: SecretKey<EdwardsProjective>,
}

/// A public Baby-JubJub issuer verification key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerPublicKey(EdwardsAffine);

/// A stable, serialization-independent Schnorr signature wrapper.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerSignature {
    prover_response: JubJubScalar,
    verifier_challenge: JubJubScalar,
}

/// An issuer-signed credential over age and holder commitments.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct AgeCredential {
    /// The stable fingerprint of the key that issued this credential.
    pub issuer_key_fingerprint: IssuerKeyFingerprint,
    /// The protocol schema covered by the issuer signature.
    pub schema_version: u8,
    /// The issuer-approved commitment to the holder's birth day.
    pub age_commitment: AgeCommitment,
    /// The commitment that binds the credential to the holder's secret.
    pub owner_commitment: OwnerCommitment,
    /// The issuer's signature over the canonical credential message.
    pub signature: IssuerSignature,
}

impl IssuerKeyPair {
    /// Generates an issuer key pair using operating-system randomness.
    pub fn generate() -> Self {
        Self::generate_with_rng(&mut OsRng)
    }

    /// Generates an issuer key pair with caller-provided cryptographic randomness.
    ///
    /// This injection point exists for reproducible issuer-key test fixtures. It
    /// does not generate holder salts or wallet secrets.
    pub fn generate_with_rng<R: CryptoRng + Rng>(rng: &mut R) -> Self {
        let (public_key, secret_key) = IssuerSchnorr::keygen(schnorr_parameters(), rng)
            .expect("Schnorr key generation with in-memory parameters cannot fail");
        Self {
            public_key: IssuerPublicKey(public_key),
            secret_key,
        }
    }

    /// Returns the public verification key for this issuer.
    pub fn public_key(&self) -> IssuerPublicKey {
        self.public_key.clone()
    }

    /// Issues a schema-v1 credential over the supplied commitments.
    pub fn issue(&self, age: AgeCommitment, owner: OwnerCommitment) -> AgeCredential {
        let message = credential_message(age, owner, AGE_CREDENTIAL_SCHEMA_V1);
        let signature = loop {
            let random_scalar = JubJubScalar::rand(&mut OsRng);
            let commitment = schnorr_parameters()
                .generator
                .mul(random_scalar)
                .into_affine();
            let transcript = SchnorrTranscript::from_commitment(commitment, &message);
            if let Some(verifier_challenge) = transcript.challenge() {
                break IssuerSignature {
                    prover_response: random_scalar - (verifier_challenge * self.secret_key.0),
                    verifier_challenge,
                };
            }
        };

        AgeCredential {
            issuer_key_fingerprint: self.public_key.fingerprint(),
            schema_version: AGE_CREDENTIAL_SCHEMA_V1,
            age_commitment: age,
            owner_commitment: owner,
            signature,
        }
    }
}

impl fmt::Debug for IssuerKeyPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuerKeyPair")
            .field("public_key", &self.public_key)
            .field("secret_key", &"REDACTED")
            .finish()
    }
}

impl IssuerPublicKey {
    /// Decodes a canonical, non-identity issuer public key from hexadecimal.
    pub fn from_hex(value: &str) -> Result<Self, PrimitiveError> {
        let encoded = encoding::bytes(value)?;
        let mut input = encoded.as_slice();
        let point = EdwardsAffine::deserialize_compressed(&mut input)
            .map_err(|_| PrimitiveError::InvalidEncoding)?;
        if !input.is_empty() || point.is_zero() || encoding::canonical(&point) != encoded {
            return Err(PrimitiveError::InvalidEncoding);
        }

        Ok(Self(point))
    }

    /// Returns this public key's stable canonical fingerprint.
    pub fn fingerprint(&self) -> IssuerKeyFingerprint {
        IssuerKeyFingerprint::new(encoding::hex(&encoding::canonical(&self.0)))
            .expect("a canonical public key fingerprint is non-empty")
    }

    /// Returns the public key's affine coordinates for circuit allocation.
    pub fn coordinates(&self) -> (Fr, Fr) {
        (self.0.x, self.0.y)
    }

    fn is_identity(&self) -> bool {
        self.0.is_zero()
    }
}

impl IssuerSignature {
    /// Returns the canonical compressed prover-response bytes.
    pub fn prover_response_bytes(&self) -> Vec<u8> {
        encoding::canonical(&self.prover_response)
    }

    /// Returns the canonical compressed verifier-challenge bytes.
    pub fn verifier_challenge_bytes(&self) -> Vec<u8> {
        encoding::canonical(&self.verifier_challenge)
    }
}

impl AgeCredential {
    /// Verifies schema, issuer identity, and signature integrity.
    pub fn verify(&self, issuer: &IssuerPublicKey) -> Result<(), PrimitiveError> {
        if self.schema_version != AGE_CREDENTIAL_SCHEMA_V1 {
            return Err(PrimitiveError::UnsupportedSchema);
        }
        if issuer.is_identity() {
            return Err(PrimitiveError::InvalidCredential);
        }
        if self.issuer_key_fingerprint != issuer.fingerprint() {
            return Err(PrimitiveError::InvalidCredential);
        }

        let message = credential_message(
            self.age_commitment,
            self.owner_commitment,
            self.schema_version,
        );
        let is_valid = self.signature.is_valid(issuer, &message);

        is_valid
            .then_some(())
            .ok_or(PrimitiveError::InvalidCredential)
    }
}

/// Constructs the exact field-element tuple covered by an issuer signature.
pub fn credential_message(
    age: AgeCommitment,
    owner: OwnerCommitment,
    schema_version: u8,
) -> [Fr; 3] {
    [
        age.field_element(),
        owner.field_element(),
        Fr::from(schema_version),
    ]
}

/// Returns the exact Arkworks Schnorr challenge input for a credential relation.
///
/// The result is `salt || compressed(commitment) || u64_le(message_length) || message`,
/// where `commitment = generator * response + public_key * challenge` and `message`
/// is the three canonical field encodings returned by [`credential_message`].
pub fn credential_challenge_transcript(
    key: &IssuerPublicKey,
    signature: &IssuerSignature,
    message: &[Fr; 3],
) -> Vec<u8> {
    SchnorrTranscript::from_signature(key, signature, message).bytes()
}

/// Returns the fixed Schnorr generator coordinates shared by native and circuit code.
pub fn issuer_generator_coordinates() -> (Fr, Fr) {
    let generator = schnorr_parameters().generator;
    (generator.x, generator.y)
}

/// Returns the fixed Schnorr transcript salt shared by native and circuit code.
pub fn issuer_signature_salt() -> [u8; 32] {
    schnorr_parameters().salt
}

impl From<Signature<EdwardsProjective>> for IssuerSignature {
    fn from(value: Signature<EdwardsProjective>) -> Self {
        Self {
            prover_response: value.prover_response,
            verifier_challenge: value.verifier_challenge,
        }
    }
}

impl From<&IssuerSignature> for Signature<EdwardsProjective> {
    fn from(value: &IssuerSignature) -> Self {
        Self {
            prover_response: value.prover_response,
            verifier_challenge: value.verifier_challenge,
        }
    }
}

impl Serialize for IssuerPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&encoding::hex(&encoding::canonical(&self.0)))
    }
}

impl<'de> Deserialize<'de> for IssuerPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_hex(&value).map_err(|error| serde::de::Error::custom(error.code()))
    }
}

impl Serialize for IssuerSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&encoding::hex(&self.encoded()))
    }
}

impl<'de> Deserialize<'de> for IssuerSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::decoded(&value).map_err(|error| serde::de::Error::custom(error.code()))
    }
}

impl IssuerSignature {
    fn encoded(&self) -> Vec<u8> {
        let mut encoded = self.prover_response_bytes();
        encoded.extend(self.verifier_challenge_bytes());
        encoded
    }

    fn decoded(value: &str) -> Result<Self, PrimitiveError> {
        let encoded = encoding::bytes(value)?;
        let element_size = JubJubScalar::default().compressed_size();
        if encoded.len() != element_size * 2 {
            return Err(PrimitiveError::InvalidEncoding);
        }

        let prover_response = JubJubScalar::deserialize_compressed(&encoded[..element_size])
            .map_err(|_| PrimitiveError::InvalidEncoding)?;
        let verifier_challenge = JubJubScalar::deserialize_compressed(&encoded[element_size..])
            .map_err(|_| PrimitiveError::InvalidEncoding)?;
        Ok(Self {
            prover_response,
            verifier_challenge,
        })
    }

    fn is_valid(&self, key: &IssuerPublicKey, message: &[Fr; 3]) -> bool {
        SchnorrTranscript::from_signature(key, self, message)
            .challenge()
            .is_some_and(|challenge| challenge == self.verifier_challenge)
    }
}

struct SchnorrTranscript {
    bytes: Vec<u8>,
}

impl SchnorrTranscript {
    fn from_commitment(commitment: EdwardsAffine, message: &[Fr; 3]) -> Self {
        let mut bytes = encoding::canonical(&schnorr_parameters().salt);
        bytes.extend(encoding::canonical(&commitment));
        bytes.extend(encoding::canonical(&message_bytes(message).as_slice()));
        Self { bytes }
    }

    fn from_signature(
        key: &IssuerPublicKey,
        signature: &IssuerSignature,
        message: &[Fr; 3],
    ) -> Self {
        let mut commitment = schnorr_parameters()
            .generator
            .mul(signature.prover_response);
        commitment += key.0.mul(signature.verifier_challenge);
        Self::from_commitment(commitment.into_affine(), message)
    }

    fn bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    fn challenge(&self) -> Option<JubJubScalar> {
        JubJubScalar::from_random_bytes(&Blake2s256::digest(&self.bytes))
    }
}

fn schnorr_parameters() -> &'static Parameters<EdwardsProjective, Blake2s256> {
    SCHNORR_PARAMETERS.get_or_init(|| {
        let mut rng = ChaCha20Rng::from_seed(PARAMETER_SEED);
        IssuerSchnorr::setup(&mut rng).expect("fixed Schnorr parameter setup cannot fail")
    })
}

fn message_bytes(message: &[Fr; 3]) -> Vec<u8> {
    message
        .iter()
        .flat_map(encoding::canonical)
        .collect::<Vec<_>>()
}
