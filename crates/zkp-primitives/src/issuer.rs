use core::fmt;
use std::sync::OnceLock;

use ark_bn254::Fr;
use ark_crypto_primitives::signature::{
    SignatureScheme,
    schnorr::{Parameters, Schnorr, SecretKey, Signature},
};
use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective, Fr as JubJubScalar};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use blake2::Blake2s256;
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
        let signature = IssuerSchnorr::sign(
            schnorr_parameters(),
            &self.secret_key,
            &message_bytes(&message),
            &mut OsRng,
        )
        .expect("Schnorr signing with in-memory values cannot fail");

        AgeCredential {
            issuer_key_fingerprint: self.public_key.fingerprint(),
            schema_version: AGE_CREDENTIAL_SCHEMA_V1,
            age_commitment: age,
            owner_commitment: owner,
            signature: signature.into(),
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
    /// Returns this public key's stable canonical fingerprint.
    pub fn fingerprint(&self) -> IssuerKeyFingerprint {
        IssuerKeyFingerprint::new(encoding::hex(&encoding::canonical(&self.0)))
            .expect("a canonical public key fingerprint is non-empty")
    }

    /// Returns the public key's affine coordinates for circuit allocation.
    pub fn coordinates(&self) -> (Fr, Fr) {
        (self.0.x, self.0.y)
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
        if self.issuer_key_fingerprint != issuer.fingerprint() {
            return Err(PrimitiveError::InvalidCredential);
        }

        let message = credential_message(
            self.age_commitment,
            self.owner_commitment,
            self.schema_version,
        );
        let signature = Signature::<EdwardsProjective>::from(&self.signature);
        let is_valid = IssuerSchnorr::verify(
            schnorr_parameters(),
            &issuer.0,
            &message_bytes(&message),
            &signature,
        )
        .map_err(|_| PrimitiveError::InvalidCredential)?;

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
        encoding::parse(&value)
            .map(Self)
            .map_err(|error| serde::de::Error::custom(error.code()))
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
