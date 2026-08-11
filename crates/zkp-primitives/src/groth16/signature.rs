use ark_bn254::Fr;
use ark_ec::AffineRepr;
use ark_ed_on_bn254::{EdwardsAffine, Fr as JubJubScalar, constraints::EdwardsVar};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    boolean::Boolean,
    prelude::{CurveVar, EqGadget, ToBitsGadget, ToBytesGadget, UInt8},
};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};

use crate::{
    IssuerPublicKey, IssuerSignature, issuer_generator_coordinates, issuer_signature_salt,
};

/// The circuit relation that accepts only a valid issuer Schnorr signature.
pub(crate) struct SchnorrRelation;

impl SchnorrRelation {
    pub(crate) fn enforce(
        cs: ConstraintSystemRef<Fr>,
        key: &IssuerPublicKey,
        signature: Option<&IssuerSignature>,
        message: &[ark_r1cs_std::fields::fp::FpVar<Fr>],
    ) -> Result<(), SynthesisError> {
        let response = ScalarBytes::witness(
            cs.clone(),
            signature.map(IssuerSignature::prover_response_bytes),
        )?;
        let challenge = ScalarBytes::witness(
            cs.clone(),
            signature.map(IssuerSignature::verifier_challenge_bytes),
        )?;
        response.canonical()?;
        challenge.canonical()?;

        let commitment = CommitmentPoint::new(key).point(&response.bits()?, &challenge.bits()?)?;
        let transcript = TranscriptBytes::new(&commitment, message)?;
        let expected = Blake2s::hash(&transcript)?;
        challenge.matches(&expected)
    }
}

struct ScalarBytes {
    bytes: Vec<UInt8<Fr>>,
}

impl ScalarBytes {
    fn witness(
        cs: ConstraintSystemRef<Fr>,
        value: Option<Vec<u8>>,
    ) -> Result<Self, SynthesisError> {
        Ok(Self {
            bytes: UInt8::new_witness_vec(cs, &value.unwrap_or_else(|| vec![0; 32]))?,
        })
    }

    fn canonical(&self) -> Result<(), SynthesisError> {
        Boolean::enforce_smaller_or_equal_than_le(
            &self.bits()?,
            (-JubJubScalar::ONE).into_bigint(),
        )?;
        Ok(())
    }

    fn bits(&self) -> Result<Vec<Boolean<Fr>>, SynthesisError> {
        self.bytes
            .iter()
            .map(ToBitsGadget::to_bits_le)
            .collect::<Result<Vec<_>, _>>()
            .map(|chunks| chunks.into_iter().flatten().collect())
    }

    fn matches(&self, digest: &[UInt8<Fr>]) -> Result<(), SynthesisError> {
        let challenge = self.bits()?;
        let digest = digest
            .iter()
            .map(ToBitsGadget::to_bits_le)
            .collect::<Result<Vec<_>, _>>()
            .map(|chunks| chunks.into_iter().flatten().collect::<Vec<Boolean<Fr>>>())?;
        challenge[..251].enforce_equal(&digest[..251])?;
        challenge[251..].enforce_equal(&vec![Boolean::FALSE; 5])
    }
}

struct CommitmentPoint {
    generator: EdwardsVar,
    issuer: EdwardsVar,
}

impl CommitmentPoint {
    fn new(key: &IssuerPublicKey) -> Self {
        let (generator_x, generator_y) = issuer_generator_coordinates();
        let (issuer_x, issuer_y) = key.coordinates();
        Self {
            generator: EdwardsVar::constant(
                EdwardsAffine::new_unchecked(generator_x, generator_y).into_group(),
            ),
            issuer: EdwardsVar::constant(
                EdwardsAffine::new_unchecked(issuer_x, issuer_y).into_group(),
            ),
        }
    }

    fn point(
        &self,
        response: &[Boolean<Fr>],
        challenge: &[Boolean<Fr>],
    ) -> Result<EdwardsVar, SynthesisError> {
        Ok(&self.generator.scalar_mul_le(response.iter())?
            + &self.issuer.scalar_mul_le(challenge.iter())?)
    }
}

struct TranscriptBytes {
    bytes: Vec<UInt8<Fr>>,
}

impl TranscriptBytes {
    fn new(
        commitment: &EdwardsVar,
        message: &[ark_r1cs_std::fields::fp::FpVar<Fr>],
    ) -> Result<Self, SynthesisError> {
        let mut bytes = UInt8::constant_vec(&issuer_signature_salt());
        bytes.extend(commitment.x.to_bytes_le()?);
        bytes.extend(commitment.y.to_bytes_le()?);
        bytes.extend(UInt8::constant_vec(&Self::length(message)?));
        for element in message {
            bytes.extend(element.to_bytes_le()?);
        }
        Ok(Self { bytes })
    }

    fn length(message: &[ark_r1cs_std::fields::fp::FpVar<Fr>]) -> Result<[u8; 8], SynthesisError> {
        let length = u64::try_from(message.len())
            .ok()
            .and_then(|count| count.checked_mul(32))
            .ok_or(SynthesisError::Unsatisfiable)?;
        Ok(length.to_le_bytes())
    }
}

struct Blake2s;

impl Blake2s {
    fn hash(bytes: &TranscriptBytes) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
        let bits = bytes
            .bytes
            .iter()
            .map(ToBitsGadget::to_bits_le)
            .collect::<Result<Vec<_>, _>>()
            .map(|chunks| chunks.into_iter().flatten().collect::<Vec<Boolean<Fr>>>())?;
        let words = ark_crypto_primitives::prf::blake2s::constraints::evaluate_blake2s(&bits)?;
        Ok(words
            .into_iter()
            .flat_map(|word| word.to_bytes_le().expect("Blake2s words always serialize"))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use ark_r1cs_std::prelude::{AllocVar, GR1CSVar};
    use ark_relations::gr1cs::ConstraintSystem;

    use super::*;
    use crate::{
        AgeSalt, BirthDay, Country, IssuerKeyPair, Role, WalletSecret, commit_age,
        commit_attributes, commit_owner, credential_message,
    };

    #[test]
    fn accepts_the_native_signature_relation() {
        let issuer = IssuerKeyPair::generate();
        let birth_day = BirthDay::parse_iso("2000-01-01").expect("date is valid");
        let country = Country::try_from("DE".to_owned()).expect("country is valid");
        let age_salt = AgeSalt::generate();
        let wallet_secret = WalletSecret::generate();
        let age = commit_age(birth_day, &age_salt);
        let owner = commit_owner(&wallet_secret);
        let attributes = commit_attributes(&country, Role::Staff, &age_salt);
        let credential = issuer.issue(age, owner, attributes);
        let message = credential_message(age, owner, attributes, credential.schema_version);
        let cs = ConstraintSystem::new_ref();
        let message = message
            .iter()
            .map(|element| {
                ark_r1cs_std::fields::fp::FpVar::new_witness(cs.clone(), || Ok(*element))
            })
            .collect::<Result<Vec<_>, _>>()
            .expect("message allocates");

        SchnorrRelation::enforce(
            cs.clone(),
            &issuer.public_key(),
            Some(&credential.signature),
            &message,
        )
        .expect("relation allocates");

        assert!(cs.is_satisfied().expect("constraint system evaluates"));
        assert!(cs.num_constraints() > 1);

        let mut wire = serde_json::to_value(&credential).expect("credential serializes");
        let signature = wire["signature"]
            .as_str()
            .expect("signature is text")
            .to_owned();
        let replacement = if signature.starts_with('0') { "1" } else { "0" };
        wire["signature"] = serde_json::Value::String(format!("{replacement}{}", &signature[1..]));
        let altered: crate::AgeCredential =
            serde_json::from_value(wire).expect("altered wire still decodes");
        let altered_cs = ConstraintSystem::new_ref();
        let altered_message = message
            .iter()
            .map(|element| {
                ark_r1cs_std::fields::fp::FpVar::new_witness(altered_cs.clone(), || element.value())
            })
            .collect::<Result<Vec<_>, _>>()
            .expect("altered message allocates");
        SchnorrRelation::enforce(
            altered_cs.clone(),
            &issuer.public_key(),
            Some(&altered.signature),
            &altered_message,
        )
        .expect("altered relation allocates");

        assert!(
            !altered_cs
                .is_satisfied()
                .expect("altered constraint system evaluates")
        );
    }

    #[test]
    fn transcript_gadget_matches_the_native_signature_bytes() {
        let issuer = IssuerKeyPair::generate();
        let country = Country::try_from("DE".to_owned()).expect("country is valid");
        let age_salt = AgeSalt::generate();
        let wallet_secret = WalletSecret::generate();
        let age = commit_age(
            BirthDay::parse_iso("2000-01-01").expect("date is valid"),
            &age_salt,
        );
        let owner = commit_owner(&wallet_secret);
        let attributes = commit_attributes(&country, Role::Staff, &age_salt);
        let credential = issuer.issue(age, owner, attributes);
        let message = credential_message(age, owner, attributes, credential.schema_version);
        let cs = ConstraintSystem::new_ref();
        let message = message
            .iter()
            .map(|element| {
                ark_r1cs_std::fields::fp::FpVar::new_witness(cs.clone(), || Ok(*element))
            })
            .collect::<Result<Vec<_>, _>>()
            .expect("message allocates");
        let response = ScalarBytes::witness(
            cs.clone(),
            Some(credential.signature.prover_response_bytes()),
        )
        .expect("response allocates");
        let challenge = ScalarBytes::witness(
            cs.clone(),
            Some(credential.signature.verifier_challenge_bytes()),
        )
        .expect("challenge allocates");
        let commitment = CommitmentPoint::new(&issuer.public_key())
            .point(
                &response.bits().expect("response bits allocate"),
                &challenge.bits().expect("challenge bits allocate"),
            )
            .expect("commitment allocates");
        let transcript = TranscriptBytes::new(&commitment, &message).expect("transcript allocates");
        let bytes = transcript
            .bytes
            .iter()
            .map(GR1CSVar::value)
            .collect::<Result<Vec<_>, _>>()
            .expect("transcript has values");

        assert_eq!(
            bytes,
            crate::credential_challenge_transcript(
                &issuer.public_key(),
                &credential.signature,
                &message_native(age, owner, attributes, credential.schema_version)
            ),
        );
    }

    fn message_native(
        age: crate::AgeCommitment,
        owner: crate::OwnerCommitment,
        attributes: crate::AttributeCommitment,
        schema: u8,
    ) -> [Fr; 4] {
        credential_message(age, owner, attributes, schema)
    }
}
