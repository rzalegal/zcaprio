use ark_bn254::Fr;
use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar, poseidon::constraints::PoseidonSpongeVar,
};
use ark_r1cs_std::{
    boolean::Boolean,
    fields::fp::FpVar,
    prelude::{AllocVar, EqGadget},
};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};

use crate::commitment::{age_domain, attribute_domain, owner_domain};
use crate::{
    AGE_CREDENTIAL_SCHEMA_V2, IssuerPublicKey, SignedAttributeCredential,
    protocol_poseidon_parameters,
};

use super::signature::SchnorrRelation;

/// Private R1CS variables for one credential whose commitments and signature hold.
pub(crate) struct CredentialRelation {
    birth_day: FpVar<Fr>,
    country: FpVar<Fr>,
    role: FpVar<Fr>,
}

impl CredentialRelation {
    pub(crate) fn enforce(
        cs: ConstraintSystemRef<Fr>,
        expected_issuer: &IssuerPublicKey,
        credential: Option<&SignedAttributeCredential>,
    ) -> Result<Self, SynthesisError> {
        let birth_day = FpVar::new_witness(cs.clone(), || {
            Ok(credential.map_or(Fr::from(0u64), |value| {
                Fr::from(value.birth_day().days_since_1900())
            }))
        })?;
        let country = FpVar::new_witness(cs.clone(), || {
            Ok(credential.map_or(Fr::from(0u64), |value| value.country().field_element()))
        })?;
        let role = FpVar::new_witness(cs.clone(), || {
            Ok(credential.map_or(Fr::from(0u64), |value| value.role().field_element()))
        })?;
        let salt = FpVar::new_witness(cs.clone(), || {
            Ok(credential.map_or(Fr::from(0u64), SignedAttributeCredential::age_salt))
        })?;
        let secret = FpVar::new_witness(cs.clone(), || {
            Ok(credential.map_or(Fr::from(0u64), SignedAttributeCredential::wallet_secret))
        })?;
        let age = PoseidonRelation::hash(
            cs.clone(),
            &[
                FpVar::Constant(age_domain()),
                birth_day.clone(),
                salt.clone(),
            ],
        )?;
        let owner = PoseidonRelation::hash(cs.clone(), &[FpVar::Constant(owner_domain()), secret])?;
        let attributes = PoseidonRelation::hash(
            cs.clone(),
            &[
                FpVar::Constant(attribute_domain()),
                country.clone(),
                role.clone(),
                salt.clone(),
            ],
        )?;
        let message = vec![
            age,
            owner,
            attributes,
            FpVar::Constant(Fr::from(AGE_CREDENTIAL_SCHEMA_V2)),
        ];
        SchnorrRelation::enforce(
            cs,
            expected_issuer,
            credential
                .map(SignedAttributeCredential::issued)
                .map(|issued| &issued.signature),
            &message,
        )?;

        Ok(Self {
            birth_day,
            country,
            role,
        })
    }

    pub(crate) fn age(&self, cutoff: Fr, at_least: bool) -> Result<Boolean<Fr>, SynthesisError> {
        let cutoff = FpVar::Constant(cutoff);
        if at_least {
            self.birth_day
                .is_cmp(&cutoff, core::cmp::Ordering::Less, true)
        } else {
            self.birth_day
                .is_cmp(&cutoff, core::cmp::Ordering::Greater, false)
        }
    }

    pub(crate) fn country(&self, values: &[Fr]) -> Result<Boolean<Fr>, SynthesisError> {
        let matches = values
            .iter()
            .map(|value| self.country.is_eq(&FpVar::Constant(*value)))
            .collect::<Result<Vec<_>, _>>()?;
        Boolean::kary_or(&matches)
    }

    pub(crate) fn role(&self, expected: Fr) -> Result<Boolean<Fr>, SynthesisError> {
        self.role.is_eq(&FpVar::Constant(expected))
    }
}

struct PoseidonRelation;

impl PoseidonRelation {
    fn hash(cs: ConstraintSystemRef<Fr>, input: &[FpVar<Fr>]) -> Result<FpVar<Fr>, SynthesisError> {
        let mut sponge = PoseidonSpongeVar::new(cs, &protocol_poseidon_parameters());
        sponge.absorb(&input.to_vec())?;
        sponge
            .squeeze_field_elements(1)?
            .into_iter()
            .next()
            .ok_or(SynthesisError::Unsatisfiable)
    }
}
