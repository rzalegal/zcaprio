use ark_bn254::Fr;
use ark_r1cs_std::{boolean::Boolean, prelude::EqGadget};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};

use crate::proof::ProofPlan;

use super::{VerificationPolicy, template::CircuitTemplate};

/// The private complete relation for one verifier-held proof template.
#[derive(Clone)]
pub(crate) struct ProofCircuit {
    pub(crate) policy: VerificationPolicy,
    pub(crate) template: CircuitTemplate,
    pub(crate) plan: Option<ProofPlan>,
}

impl ProofCircuit {
    pub(crate) fn is_satisfied(&self) -> Result<bool, SynthesisError> {
        let cs = ConstraintSystem::new_ref();
        self.clone().generate_constraints(cs.clone())?;
        cs.is_satisfied()
    }
}

impl ConstraintSynthesizer<Fr> for ProofCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let root = self
            .template
            .relation(cs, self.plan.as_ref(), &self.policy)?;
        root.enforce_equal(&Boolean::constant(true))
    }
}
