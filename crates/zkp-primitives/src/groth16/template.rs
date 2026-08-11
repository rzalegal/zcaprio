use ark_bn254::Fr;
use ark_r1cs_std::boolean::Boolean;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};

use crate::proof::{DirectProofPlan, ProofPlan};
use crate::{ClaimKind, Credential, IssuerPublicKey, ProofError, SignedAttributeCredential};

use super::commitment::CredentialRelation;
use super::{VerificationPolicy, birthday_cutoff};

/// A verifier-held proof shape with issuer keys and claim statements as constants.
#[derive(Clone)]
pub(crate) enum CircuitTemplate {
    Direct(DirectTemplate),
    Conjunction(Box<Self>, Box<Self>),
    Disjunction(Box<Self>, Box<Self>),
}

#[derive(Clone)]
pub(crate) struct DirectTemplate {
    issuer: IssuerPublicKey,
    claim: ClaimKind,
}

impl CircuitTemplate {
    pub(crate) fn from_plan(plan: &ProofPlan) -> Result<Self, ProofError> {
        match plan {
            ProofPlan::Direct(direct) => DirectTemplate::from_plan(direct).map(Self::Direct),
            ProofPlan::Conjunction(left, right) => Ok(Self::Conjunction(
                Box::new(Self::from_plan(left)?),
                Box::new(Self::from_plan(right)?),
            )),
            ProofPlan::Disjunction(left, right) => Ok(Self::Disjunction(
                Box::new(Self::from_plan(left)?),
                Box::new(Self::from_plan(right)?),
            )),
        }
    }

    pub(crate) fn accepts(&self, plan: &ProofPlan) -> bool {
        match (self, plan) {
            (Self::Direct(template), ProofPlan::Direct(direct)) => template.accepts(direct),
            (Self::Conjunction(left, right), ProofPlan::Conjunction(other_left, other_right))
            | (Self::Disjunction(left, right), ProofPlan::Disjunction(other_left, other_right)) => {
                left.accepts(other_left) && right.accepts(other_right)
            }
            _ => false,
        }
    }

    pub(crate) fn relation(
        &self,
        cs: ConstraintSystemRef<Fr>,
        plan: Option<&ProofPlan>,
        policy: &VerificationPolicy,
    ) -> Result<Boolean<Fr>, SynthesisError> {
        match (self, plan) {
            (Self::Direct(template), Some(ProofPlan::Direct(direct))) => {
                template.relation(cs, direct.evidence.as_deref(), policy)
            }
            (Self::Direct(template), None) => template.relation(cs, None, policy),
            (
                Self::Conjunction(left, right),
                Some(ProofPlan::Conjunction(other_left, other_right)),
            ) => Ok(&left.relation(cs.clone(), Some(other_left), policy)?
                & &right.relation(cs, Some(other_right), policy)?),
            (
                Self::Disjunction(left, right),
                Some(ProofPlan::Disjunction(other_left, other_right)),
            ) => Ok(&left.relation(cs.clone(), Some(other_left), policy)?
                | &right.relation(cs, Some(other_right), policy)?),
            (Self::Conjunction(left, right), None) => Ok(&left.relation(
                cs.clone(),
                None,
                policy,
            )? & &right.relation(cs, None, policy)?),
            (Self::Disjunction(left, right), None) => Ok(&left.relation(
                cs.clone(),
                None,
                policy,
            )? | &right.relation(cs, None, policy)?),
            _ => Err(SynthesisError::Unsatisfiable),
        }
    }
}

impl DirectTemplate {
    fn from_plan(plan: &DirectProofPlan) -> Result<Self, ProofError> {
        let credential = plan
            .evidence
            .as_ref()
            .ok_or(ProofError::InvalidCredential)?;
        if credential.hash() != plan.credential {
            return Err(ProofError::InvalidCredential);
        }
        if matches!(plan.claim.kind(), ClaimKind::Custom) {
            return Err(ProofError::UnsupportedClaim);
        }
        Ok(Self {
            issuer: credential.issuer().clone(),
            claim: plan.claim.kind(),
        })
    }

    fn accepts(&self, plan: &DirectProofPlan) -> bool {
        plan.evidence.as_ref().is_some_and(|credential| {
            credential.hash() == plan.credential
                && credential.issuer() == &self.issuer
                && plan.claim.kind() == self.claim
        })
    }

    fn relation(
        &self,
        cs: ConstraintSystemRef<Fr>,
        credential: Option<&SignedAttributeCredential>,
        policy: &VerificationPolicy,
    ) -> Result<Boolean<Fr>, SynthesisError> {
        let credential = CredentialRelation::enforce(cs, &self.issuer, credential)?;
        match self.claim {
            ClaimKind::AgeAbove(years) => credential.age(cutoff(policy, years), true),
            ClaimKind::AgeBelow(years) => credential.age(cutoff(policy, years), false),
            ClaimKind::CountryIsEu => credential.country(&eu_countries()),
            ClaimKind::Role(role) => credential.role(role.field_element()),
            ClaimKind::Custom => Err(SynthesisError::Unsatisfiable),
        }
    }
}

fn cutoff(policy: &VerificationPolicy, years: u8) -> Fr {
    let birthday = birthday_cutoff(policy.as_of().date(), years);
    Fr::from(
        crate::BirthDay::from_date(birthday)
            .expect("a supported cutoff is a supported birthday")
            .days_since_1900(),
    )
}

fn eu_countries() -> Vec<Fr> {
    [
        b"AT", b"BE", b"BG", b"HR", b"CY", b"CZ", b"DK", b"EE", b"FI", b"FR", b"DE", b"GR", b"HU",
        b"IE", b"IT", b"LV", b"LT", b"LU", b"MT", b"NL", b"PL", b"PT", b"RO", b"SK", b"SI", b"ES",
        b"SE",
    ]
    .into_iter()
    .map(|country| Fr::from(u64::from(u16::from_be_bytes(*country))))
    .collect()
}
