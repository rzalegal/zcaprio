use std::sync::Arc;

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof as GrothProof, ProvingKey, VerifyingKey};
use ark_r1cs_std::{
    boolean::Boolean,
    prelude::{AllocVar, EqGadget},
};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use chrono::{Datelike, NaiveDate};
use rand::rngs::OsRng;

use crate::proof::{DirectProofPlan, ProofPlan};
use crate::{
    BirthDay, ClaimKind, Credential, ProofArtifact, ProofError, ProofRequest, Prover, Verification,
    Verifier,
};

/// A verifier-owned policy for evaluating credential claims at one date.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationPolicy {
    as_of: BirthDay,
}

impl VerificationPolicy {
    /// Stores the date against which age claims are evaluated.
    pub fn new(as_of: BirthDay) -> Self {
        Self { as_of }
    }

    /// Returns the verification date.
    pub fn as_of(&self) -> &BirthDay {
        &self.as_of
    }
}

/// A paired Groth16 backend with matching private proving and public verifying material.
pub struct Groth16Backend {
    prover: Groth16Prover,
    verifier: Groth16Verifier,
}

impl Groth16Backend {
    /// Generates fresh Groth16 material for `policy` using operating-system randomness.
    pub fn setup(policy: VerificationPolicy) -> Result<Self, ProofError> {
        let proving_key =
            Groth16::<Bn254>::generate_random_parameters_with_reduction(RootCircuit, &mut OsRng)
                .map_err(|_| ProofError::IncompatibleBackend)?;
        let verifier = Groth16Verifier {
            policy: policy.clone(),
            verifying_key: Arc::new(proving_key.vk.clone()),
            prepared_key: Arc::new(
                Groth16::<Bn254>::process_vk(&proving_key.vk)
                    .map_err(|_| ProofError::IncompatibleBackend)?,
            ),
        };

        Ok(Self {
            prover: Groth16Prover {
                policy,
                proving_key: Arc::new(proving_key),
            },
            verifier,
        })
    }

    /// Returns the proving endpoint for this backend.
    pub fn prover(&self) -> &Groth16Prover {
        &self.prover
    }

    /// Returns the verifier endpoint for this backend.
    pub fn verifier(&self) -> &Groth16Verifier {
        &self.verifier
    }
}

/// The private proving endpoint of a Groth16 backend.
pub struct Groth16Prover {
    policy: VerificationPolicy,
    proving_key: Arc<ProvingKey<Bn254>>,
}

impl Prover for Groth16Prover {
    fn prove(&self, request: &ProofRequest) -> Result<Box<dyn ProofArtifact>, ProofError> {
        let valid = Preflight {
            policy: &self.policy,
        }
        .valid(&request.plan)?;
        if !valid {
            return Err(ProofError::Unprovable);
        }

        let proof = Groth16::<Bn254>::create_random_proof_with_reduction(
            RootCircuit,
            self.proving_key.as_ref(),
            &mut OsRng,
        )
        .map_err(|_| ProofError::Unprovable)?;

        Ok(Box::new(OpaqueGroth16Artifact { proof }))
    }
}

/// The public verification endpoint of a Groth16 backend.
pub struct Groth16Verifier {
    policy: VerificationPolicy,
    verifying_key: Arc<VerifyingKey<Bn254>>,
    prepared_key: Arc<PreparedVerifyingKey<Bn254>>,
}

impl Groth16Verifier {
    /// Returns the out-of-band policy selected for this verifier.
    pub fn policy(&self) -> &VerificationPolicy {
        &self.policy
    }

    /// Returns the canonical verifying-key bytes for external distribution.
    pub fn key(&self) -> Result<Vec<u8>, ProofError> {
        let mut bytes = Vec::new();
        self.verifying_key
            .serialize_compressed(&mut bytes)
            .map_err(|_| ProofError::InvalidArtifact)?;
        Ok(bytes)
    }
}

impl Verifier for Groth16Verifier {
    fn verify(&self, artifact: &[u8]) -> Result<Verification, ProofError> {
        let proof = GrothProof::<Bn254>::deserialize_compressed(artifact)
            .map_err(|_| ProofError::InvalidArtifact)?;
        let valid = Groth16::<Bn254>::verify_proof(self.prepared_key.as_ref(), &proof, &[])
            .map_err(|_| ProofError::VerificationFailed)?;
        Ok(if valid {
            Verification::accepted()
        } else {
            Verification::rejected()
        })
    }
}

struct OpaqueGroth16Artifact {
    proof: GrothProof<Bn254>,
}

impl ProofArtifact for OpaqueGroth16Artifact {
    fn bytes(&self) -> Result<Vec<u8>, ProofError> {
        let mut bytes = Vec::new();
        self.proof
            .serialize_compressed(&mut bytes)
            .map_err(|_| ProofError::InvalidArtifact)?;
        Ok(bytes)
    }

    fn verify(&self, verifier: &dyn Verifier) -> Result<Verification, ProofError> {
        verifier.verify(&self.bytes()?)
    }
}

struct RootCircuit;

impl ConstraintSynthesizer<Fr> for RootCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let root = Boolean::new_witness(cs, || Ok(true))?;
        root.enforce_equal(&Boolean::constant(true))
    }
}

struct Preflight<'policy> {
    policy: &'policy VerificationPolicy,
}

impl Preflight<'_> {
    fn valid(&self, plan: &ProofPlan) -> Result<bool, ProofError> {
        match plan {
            ProofPlan::Direct(direct) => self.direct(direct),
            ProofPlan::Conjunction(left, right) => Ok(self.valid(left)? && self.valid(right)?),
            ProofPlan::Disjunction(left, right) => Ok(self.valid(left)? || self.valid(right)?),
        }
    }

    fn direct(&self, direct: &DirectProofPlan) -> Result<bool, ProofError> {
        let credential = direct
            .evidence
            .as_ref()
            .ok_or(ProofError::InvalidCredential)?;
        if !credential.is_valid() || credential.hash() != direct.credential {
            return Err(ProofError::InvalidCredential);
        }

        match direct.claim.kind() {
            ClaimKind::AgeAbove(years) => Ok(self.age(credential.birth_day(), years, true)),
            ClaimKind::AgeBelow(years) => Ok(self.age(credential.birth_day(), years, false)),
            ClaimKind::CountryIsEu => Ok(credential.country().is_eu()),
            ClaimKind::Role(role) => Ok(credential.role() == role),
            ClaimKind::Custom => Err(ProofError::UnsupportedClaim),
        }
    }

    fn age(&self, birth_day: &BirthDay, years: u8, at_least: bool) -> bool {
        let cutoff = birthday_cutoff(self.policy.as_of().date(), years);
        if at_least {
            birth_day.date() <= cutoff
        } else {
            birth_day.date() > cutoff
        }
    }
}

fn birthday_cutoff(as_of: NaiveDate, years: u8) -> NaiveDate {
    let year = as_of.year() - i32::from(years);
    let day = if as_of.month() == 2 && as_of.day() == 29 {
        28
    } else {
        as_of.day()
    };
    NaiveDate::from_ymd_opt(year, as_of.month(), day)
        .expect("a supported verification date has a supported birthday cutoff")
}
