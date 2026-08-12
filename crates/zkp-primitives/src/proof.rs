use std::sync::Arc;

use crate::{
    Claim, Credential, CredentialHash, ProofArtifact, ProofError, SignedAttributeCredential,
};

/// An immutable, lazy proof recipe.
///
/// A proof exposes method-only composition. It does not expose child proofs,
/// credential data, claims, witnesses, or an OR branch selector.
pub struct Proof {
    node: Box<dyn ProofNode>,
}

impl Proof {
    /// Conjoins this proof with `other` without proving either child.
    pub fn and(self, other: Self) -> Self {
        Self {
            node: Box::new(ConjunctionProof {
                left: self.node,
                right: other.node,
            }),
        }
    }

    /// Disjoins this proof with `other` without proving either child.
    ///
    /// The final artifact never reveals which branch satisfied the relation.
    pub fn or(self, other: Self) -> Self {
        Self {
            node: Box::new(DisjunctionProof {
                left: self.node,
                right: other.node,
            }),
        }
    }

    /// Compiles and proves the complete composition through `prover` once.
    pub fn prove(&self, prover: &dyn Prover) -> Result<Box<dyn ProofArtifact>, ProofError> {
        prover.prove(&self.request())
    }

    pub(crate) fn request(&self) -> ProofRequest {
        ProofRequest {
            plan: self.node.plan(),
        }
    }
}

/// A proof backend that compiles one opaque proof request.
pub trait Prover: Send + Sync {
    /// Produces one artifact for the complete opaque proof request.
    fn prove(&self, request: &ProofRequest) -> Result<Box<dyn ProofArtifact>, ProofError>;
}

/// An opaque request passed from a lazy proof to its terminal backend.
///
/// Its contents are crate-private so callers cannot inspect a proof tree,
/// credential, claim, witness, or satisfying OR branch.
pub struct ProofRequest {
    pub(crate) plan: ProofPlan,
}

pub(crate) struct Proofs;

impl Proofs {
    #[cfg(test)]
    pub(crate) fn credential(&self, credential: CredentialHash, claim: Box<dyn Claim>) -> Proof {
        Proof {
            node: Box::new(CredentialProof {
                plan: DirectProofPlan {
                    credential,
                    claim: Arc::from(claim),
                    evidence: None,
                },
            }),
        }
    }

    pub(crate) fn signed(
        &self,
        evidence: SignedAttributeCredential,
        claim: Box<dyn Claim>,
    ) -> Proof {
        let evidence = Arc::new(evidence);
        Proof {
            node: Box::new(CredentialProof {
                plan: DirectProofPlan {
                    credential: evidence.hash(),
                    claim: Arc::from(claim),
                    evidence: Some(evidence),
                },
            }),
        }
    }
}

trait ProofNode: Send + Sync {
    fn plan(&self) -> ProofPlan;
}

struct CredentialProof {
    plan: DirectProofPlan,
}

impl ProofNode for CredentialProof {
    fn plan(&self) -> ProofPlan {
        ProofPlan::Direct(self.plan.clone())
    }
}

struct ConjunctionProof {
    left: Box<dyn ProofNode>,
    right: Box<dyn ProofNode>,
}

impl ProofNode for ConjunctionProof {
    fn plan(&self) -> ProofPlan {
        ProofPlan::Conjunction(Box::new(self.left.plan()), Box::new(self.right.plan()))
    }
}

struct DisjunctionProof {
    left: Box<dyn ProofNode>,
    right: Box<dyn ProofNode>,
}

impl ProofNode for DisjunctionProof {
    fn plan(&self) -> ProofPlan {
        ProofPlan::Disjunction(Box::new(self.left.plan()), Box::new(self.right.plan()))
    }
}

#[derive(Clone)]
pub(crate) struct DirectProofPlan {
    pub(crate) credential: CredentialHash,
    pub(crate) claim: Arc<dyn Claim>,
    pub(crate) evidence: Option<Arc<SignedAttributeCredential>>,
}

#[derive(Clone)]
pub(crate) enum ProofPlan {
    Direct(DirectProofPlan),
    Conjunction(Box<ProofPlan>, Box<ProofPlan>),
    Disjunction(Box<ProofPlan>, Box<ProofPlan>),
}

#[cfg(test)]
impl ProofPlan {
    pub(crate) const fn kind(&self) -> ProofKind {
        match self {
            Self::Direct(_) => ProofKind::Direct,
            Self::Conjunction(_, _) => ProofKind::Conjunction,
            Self::Disjunction(_, _) => ProofKind::Disjunction,
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProofKind {
    Direct,
    Conjunction,
    Disjunction,
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;
    use crate::{ClaimName, Verification, Verifier};

    struct TestClaim(&'static str);

    impl Claim for TestClaim {
        fn name(&self) -> ClaimName {
            ClaimName::try_from(self.0.to_owned()).expect("test claim name is valid")
        }

        fn kind(&self) -> crate::ClaimKind {
            crate::ClaimKind::Custom
        }
    }

    struct TestArtifact;

    impl ProofArtifact for TestArtifact {
        fn bytes(&self) -> Result<Vec<u8>, ProofError> {
            Ok(vec![1])
        }

        fn verify(&self, _verifier: &dyn Verifier) -> Result<Verification, ProofError> {
            Ok(Verification::accepted())
        }
    }

    struct RecordingProver {
        calls: AtomicUsize,
        roots: Mutex<Vec<ProofKind>>,
    }

    impl RecordingProver {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                roots: Mutex::new(Vec::new()),
            }
        }
    }

    impl Prover for RecordingProver {
        fn prove(&self, request: &ProofRequest) -> Result<Box<dyn ProofArtifact>, ProofError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.roots
                .lock()
                .expect("test recorder is available")
                .push(request.plan.kind());
            Ok(Box::new(TestArtifact))
        }
    }

    fn proof(credential: u8, claim: &'static str) -> Proof {
        Proofs.credential(
            CredentialHash::from_bytes([credential; 32]),
            Box::new(TestClaim(claim)),
        )
    }

    #[test]
    fn composition_sends_one_opaque_root_to_the_terminal_prover() {
        let prover = RecordingProver::new();
        let proof = proof(1, "adult").and(proof(2, "eu")).or(proof(3, "staff"));

        let artifact = proof.prove(&prover).expect("root proves once");

        assert_eq!(prover.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            prover
                .roots
                .lock()
                .expect("test recorder is available")
                .as_slice(),
            [ProofKind::Disjunction]
        );
        assert!(
            artifact
                .verify(&AcceptingVerifier)
                .expect("artifact verifies")
                .valid()
        );
    }

    struct AcceptingVerifier;

    impl Verifier for AcceptingVerifier {
        fn verify(&self, _artifact: &[u8]) -> Result<Verification, ProofError> {
            Ok(Verification::accepted())
        }
    }
}
