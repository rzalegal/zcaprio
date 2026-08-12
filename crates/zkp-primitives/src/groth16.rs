use std::sync::Arc;

use ark_bn254::Bn254;
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof as GrothProof, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use chrono::{Datelike, NaiveDate};
use rand::rngs::OsRng;

use crate::{
    BirthDay, Proof, ProofArtifact, ProofError, ProofRequest, Prover, Verification, Verifier,
};

mod circuit;
mod commitment;
mod signature;
mod template;

use circuit::ProofCircuit;
use template::CircuitTemplate;

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
    /// Generates fresh Groth16 material for the opaque `proof` and `policy`.
    ///
    /// The supplied proof is compiled to a verifier-held template. Its issuer
    /// keys, claims, and composition shape are fixed in the generated keys and
    /// never included in a proof artifact.
    pub fn setup(proof: &Proof, policy: VerificationPolicy) -> Result<Self, ProofError> {
        let template = CircuitTemplate::from_plan(&proof.request().plan)?;
        let proving_key = Groth16::<Bn254>::generate_random_parameters_with_reduction(
            ProofCircuit {
                policy: policy.clone(),
                template: template.clone(),
                plan: None,
            },
            &mut OsRng,
        )
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
                template,
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
    template: CircuitTemplate,
    proving_key: Arc<ProvingKey<Bn254>>,
}

impl Prover for Groth16Prover {
    fn prove(&self, request: &ProofRequest) -> Result<Box<dyn ProofArtifact>, ProofError> {
        if !self.template.accepts(&request.plan) {
            return Err(ProofError::IncompatibleBackend);
        }

        let circuit = ProofCircuit {
            policy: self.policy.clone(),
            template: self.template.clone(),
            plan: Some(request.plan.clone()),
        };
        if !circuit.is_satisfied().map_err(|_| ProofError::Unprovable)? {
            return Err(ProofError::Unprovable);
        }

        let proof = Groth16::<Bn254>::create_random_proof_with_reduction(
            circuit,
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
