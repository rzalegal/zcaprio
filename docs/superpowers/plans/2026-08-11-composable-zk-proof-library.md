# Composable Opaque ZK Proof Library Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** Deliver a Rust library that turns credential-bound claims into lazy proof objects, composes them with opaque .and() and .or() methods, and produces one real Groth16 artifact whose verification reveals only the root result.

**Architecture:** The zcaprio crate owns the immutable public Credential, Claim, Proof, and ProofArtifact contracts plus native signed-credential primitives. Its private groth16 module lowers the complete private proof tree to one R1CS relation and verifies one opaque Groth16 artifact against a verifier-owned policy; no HTTP, browser, or localhost application remains.

**Tech Stack:** Rust stable, Arkworks 0.6, BN254 Groth16, Baby-JubJub Schnorr, Poseidon, Blake2s, Serde, Cargo doctests, Clippy, and rustfmt.

## Global Constraints

- The final project is a library only. Remove zkp-lab, all Axum/Tokio server dependencies, web assets, HTTP routes, and localhost behavior.
- Preserve Rust stable and Arkworks 0.6. Keep all proof-system details behind a library backend interface.
- The only public composition entry points are Proof::and and Proof::or. Both return new immutable proof objects; there is no free-standing public And or Or constructor.
- Credential::is returns a lazy proof. No child proof is finalized, verified, serialized, or exposed until the terminal Proof::prove call compiles the complete tree.
- Credentials in one proof tree may come from different issuers and carry unrelated attribute sources.
- .and and .or produce one opaque final artifact. Artifact serialization and verifier output contain no child proof, credential hash, claim name, proof-tree shape, witness, selector, or OR-branch identity.
- A verifier selects the expected verification policy and key out of band. The artifact does not carry a circuit identifier or shape fingerprint.
- Use only explicit OsRng factories for holder salts and wallet secrets. Do not expose deterministic, string, byte, serde, or generic-RNG production constructors for either sensitive type.
- Reject identity issuer public keys and noncanonical point encodings. Use injective verifier scope encoding: normalized ASCII [a-z0-9][a-z0-9_-]{0,29}, packed as one length byte followed by scope bytes into an Fr value.
- Native and R1CS signature operations must share one exact documented transcript builder and test vector. Every public item receives Rustdoc; error messages remain data-free.
- Constructors only assign fields. Factories and backend methods perform validation, randomness, key generation, serialization, or proof work.
- Run cargo fmt --check, cargo clippy --workspace --all-targets -- -D warnings, and relevant tests per task. Run RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps and cargo test --workspace before final completion.

---

## File Structure

~~~text
Cargo.toml
Cargo.lock
README.md
crates/
  zkp-primitives/                    # package and public crate name: zcaprio
    src/
      {lib,error,age,commitment,issuer,credential,claim,proof,policy,encoding}.rs
    tests/
      {age_and_policy,commitments,issuer_credentials,lazy_proofs,claims}.rs
    src/groth16/
      {mod,fragment,circuit,signature_gadget,prover,key_store,artifact,policy}.rs
    tests/
      {native_transcript,constraints,compositions,groth16_lifecycle,opaque_artifact}.rs
docs/
  superpowers/{specs,plans}/
~~~

The public zcaprio crate exposes object contracts and uses private decorators for direct, conjunction, and disjunction proofs. Its private groth16 module is the only concrete Prover and Verifier implementation. It owns circuit lowering, keys, artifact encoding, and opaque verification.

## Task 1: Convert the workspace to library-only packages

**Files:**
- Modify: Cargo.toml
- Modify: Cargo.lock
- Modify: crates/zkp-primitives/Cargo.toml
- Modify: .gitignore
- Delete: crates/age-credential-circuit/Cargo.toml
- Delete: crates/age-credential-circuit/src/lib.rs
- Delete: crates/zkp-lab/Cargo.toml
- Delete: crates/zkp-lab/src/app.rs
- Delete: crates/zkp-lab/src/lib.rs
- Delete: crates/zkp-lab/src/main.rs
- Delete: crates/zkp-lab/tests/health.rs
- Create: crates/zkp-primitives/tests/library_only.rs

**Interfaces:**
- Produces package zcaprio from crates/zkp-primitives.
- Produces a workspace containing exactly one member crate.
- Removes all executable, server, web, HTTP, and localhost surfaces.

- [ ] **Step 1: Write a failing library-only workspace test**

~~~rust
#[test]
fn public_library_has_no_server_or_http_dependency() {
    let manifest = std::fs::read_to_string(env!("CARGO_MANIFEST_DIR").to_owned() + "/Cargo.toml").unwrap();

    assert!(!manifest.contains("axum"));
    assert!(!manifest.contains("tokio"));
    assert_eq!(env!("CARGO_PKG_NAME"), "zcaprio");
}
~~~

- [ ] **Step 2: Run the test to verify it fails**

Run: cargo test -p zcaprio --test library_only

Expected: FAIL because the package name and workspace still follow the teaching-app layout.

- [ ] **Step 3: Reshape Cargo membership and package identities**

Remove zkp-lab and age-credential-circuit from the workspace and delete their files. Rename zkp-primitives to package zcaprio while retaining its directory to avoid an unrelated move. Move the empty circuit crate boundary into private zcaprio::groth16 modules in later tasks. Remove Axum, Tokio, and server-only dependencies from the lockfile through Cargo resolution. Keep .zkp-lab/ ignored for backend test key material and retain .superpowers/ and .worktrees/ ignores.

- [ ] **Step 4: Run workspace checks**

Run: cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace

Expected: PASS with one library package and no executable target.

- [ ] **Step 5: Commit the library-only conversion**

~~~bash
git add Cargo.toml Cargo.lock .gitignore crates/zkp-primitives
git rm -r crates/age-credential-circuit crates/zkp-lab
git commit -m "refactor: make ZK project library-only"
~~~

## Task 2: Repair and harden native credential primitives

**Files:**
- Modify: crates/zkp-primitives/src/{age,commitment,issuer,encoding,error,lib}.rs
- Modify: crates/zkp-primitives/tests/{age_and_policy,commitments,issuer_credentials}.rs
- Create: crates/zkp-primitives/tests/native_transcript.rs

**Interfaces:**
- Produces VerifierScope::new(String) accepting only ASCII [a-z0-9][a-z0-9_-]{0,29}.
- Produces VerifierScope::field_element() -> ark_bn254::Fr through injective length-prefixed packing.
- Produces AgeSalt::generate() and WalletSecret::generate() as the only production constructors.
- Produces IssuerPublicKey::from_hex(&str) -> Result<IssuerPublicKey, PrimitiveError>, rejecting noncanonical and identity encodings.
- Produces credential_challenge_transcript(public_key, signature_commitment, credential_message) -> Vec<u8>.
- Produces a native transcript test vector consumed by the circuit crate.

- [ ] **Step 1: Write failing security-boundary tests**

~~~rust
#[test]
fn holder_secrets_have_no_public_deserialization_or_string_construction() {
    let source = std::fs::read_to_string("src/commitment.rs").unwrap();

    assert!(!source.contains("impl Deserialize for AgeSalt"));
    assert!(!source.contains("impl Deserialize for WalletSecret"));
    assert!(!source.contains("TryFrom<String> for AgeSalt"));
    assert!(!source.contains("TryFrom<String> for WalletSecret"));
}

#[test]
fn scope_packing_is_injective_for_distinct_valid_scopes() {
    assert_ne!(scope("passport-check").field_element(), scope("residence-check").field_element());
    assert!(VerifierScope::new("EU".into()).is_err());
    assert!(VerifierScope::new("a".repeat(31)).is_err());
}
~~~

Add tests for identity and sign-bit-alternative public-key encodings, canonical reserialization, all invalid scope character classes, and an exact fixed challenge-transcript byte vector.

- [ ] **Step 2: Run the security tests to verify they fail**

Run: cargo test -p zcaprio --test age_and_policy --test commitments --test issuer_credentials

Expected: FAIL because current secret construction, scope mapping, key decoding, or transcript surface does not meet the required contract.

- [ ] **Step 3: Implement the fixed native boundary**

Remove serde and public text construction from AgeSalt and WalletSecret. Keep only a read-only field-element accessor required by the backend crate. Use tests with OsRng-generated values rather than deterministic holder-secret fixtures.

Pack scope as [byte_length, byte_0, ..., byte_n] and convert that at-most-31-byte integer to Fr. Require the exact ASCII grammar before packing.

Decode issuer keys, reject identity, canonical-reserialize, and compare bytes to the input before accepting. Recheck nonidentity in credential verification.

Read Arkworks 0.6 Schnorr source and define one public documented transcript builder that returns every exact byte consumed by the challenge hash, including message-length framing, salt, point encoding, and canonical field encodings. Make native signing and verification call this builder or an internal function sharing the same implementation.

~~~rust
pub fn credential_challenge_transcript(
    key: &IssuerPublicKey,
    commitment: &IssuerCommitment,
    message: &CredentialMessage,
) -> Vec<u8> {
    SchnorrTranscript::new(key, commitment, message).bytes()
}
~~~

- [ ] **Step 4: Run native and cross-crate transcript checks**

Run: cargo test -p zcaprio --test age_and_policy --test commitments --test issuer_credentials --test native_transcript

Expected: PASS. Sensitive types have no public deterministic construction path; malformed keys/scopes fail; the exact transcript vector is accepted by both crates.

- [ ] **Step 5: Commit hardened primitives**

~~~bash
git add crates/zkp-primitives
git commit -m "fix: harden credential primitive boundaries"
~~~

## Task 3: Add the lazy object-oriented proof contract

**Files:**
- Create: crates/zkp-primitives/src/{claim,credential}.rs
- Modify: crates/zkp-primitives/src/proof.rs
- Modify: crates/zkp-primitives/src/{lib,error}.rs
- Create: crates/zkp-primitives/tests/lazy_proofs.rs

**Interfaces:**
- Produces public Credential, Claim, Proof, ProofArtifact, Prover, Verifier, Verification, ClaimName, CredentialHash, and ProofError types.
- Produces Proof::and(self: Box<Self>, other: Box<dyn Proof>) -> Box<dyn Proof>.
- Produces Proof::or(self: Box<Self>, other: Box<dyn Proof>) -> Box<dyn Proof>.
- Produces Credential::is(&self, claim: Box<dyn Claim>) -> Box<dyn Proof>.
- Produces private CredentialProof, ConjunctionProof, and DisjunctionProof decorators.
- Produces private ProofPlan emitted only to backend implementations.

- [ ] **Step 1: Write failing composition-contract tests**

~~~rust
#[test]
fn composition_is_only_a_method_on_a_proof_object() {
    let proof = credential("passport")
        .is(Box::new(TestClaim::named("adult")))
        .and(credential("residence").is(Box::new(TestClaim::named("eu"))))
        .or(credential("badge").is(Box::new(TestClaim::named("staff"))));

    assert_eq!(proof.plan_for_test().kind(), ProofKind::Disjunction);
}

#[test]
fn composing_proofs_does_not_prove_or_verify_children() {
    let recorder = RecordingProver::new();
    let proof = credential("passport").is(Box::new(TestClaim::named("adult")))
        .and(credential("residence").is(Box::new(TestClaim::named("eu"))));

    assert_eq!(recorder.calls(), 0);
    let _artifact = proof.prove(&recorder).unwrap();
    assert_eq!(recorder.calls(), 1);
}
~~~

The test-only RecordingProver may inspect a private plan but must never be part of the public API.

- [ ] **Step 2: Run the contract test to verify it fails**

Run: cargo test -p zcaprio --test lazy_proofs

Expected: FAIL because the proof object contracts and decorators do not exist.

- [ ] **Step 3: Implement immutable proof decorators**

Keep public traits object-safe by using self: Box<Self> for composition. Each decorator constructor only stores its child objects. A private ProofPlan visitor owns tree lowering; it has no Serialize implementation and never becomes an artifact.

~~~rust
impl Proof for ConjunctionProof {
    fn and(self: Box<Self>, other: Box<dyn Proof>) -> Box<dyn Proof> {
        Box::new(ConjunctionProof::from(self, other))
    }

    fn or(self: Box<Self>, other: Box<dyn Proof>) -> Box<dyn Proof> {
        Box::new(DisjunctionProof::from(self, other))
    }
}
~~~

Define data-free ProofError variants UnsupportedClaim, InvalidCredential, Unprovable, IncompatibleBackend, InvalidArtifact, and VerificationFailed.

- [ ] **Step 4: Run proof-object tests**

Run: cargo test -p zcaprio --test lazy_proofs

Expected: PASS. Cross-credential proof trees compose lazily, no top-level public And/Or surface exists, and exactly one backend prove call occurs at the terminal boundary.

- [ ] **Step 5: Commit the proof object vocabulary**

~~~bash
git add crates/zkp-primitives
git commit -m "feat: add composable lazy proof objects"
~~~

## Task 4: Implement signed attribute credentials and claim fragments

**Files:**
- Modify: crates/zkp-primitives/src/{credential,claim,issuer,proof,lib}.rs
- Create: crates/zkp-primitives/tests/claims.rs
- Create: crates/zkp-primitives/src/groth16/{mod,fragment}.rs
- Modify: crates/zkp-primitives/src/lib.rs

**Interfaces:**
- Produces SignedAttributeCredential with private birth day, country code, role, holder binding, issuer signature, and public hash.
- Produces AgeIsAbove::new(u8), AgeIsBelow::new(u8), CountryIsEu, and RoleIs::new(Role).
- Produces Claim::compile(&self, credential: &dyn CredentialEvidence) -> Result<ClaimFragment, ProofError> as a crate-private backend bridge.
- Produces ClaimFragment::validity() -> Boolean<Fr> and ClaimFragment::public_inputs() -> Vec<Fr>.
- Produces ClaimFragment::and and ClaimFragment::or without exposing child fragments publicly.

- [ ] **Step 1: Write failing direct-claim tests**

~~~rust
#[test]
fn each_claim_is_bound_to_a_signed_credential() {
    let passport = signed_credential(birth_day("2000-01-01"), country("DE"), role("student"));
    let proof = passport.is(Box::new(AgeIsAbove::new(18)));

    assert!(proof.native_preflight().is_ok());
    assert!(tamper_signature(&passport).is(Box::new(AgeIsAbove::new(18)))
        .native_preflight()
        .is_err());
}

#[test]
fn country_and_role_claims_use_distinct_credentials() {
    let residence = signed_credential(birth_day("2012-01-01"), country("DE"), role("visitor"));
    let badge = signed_credential(birth_day("2012-01-01"), country("US"), role("staff"));

    assert!(residence.is(Box::new(CountryIsEu)).native_preflight().is_ok());
    assert!(badge.is(Box::new(RoleIs::new(Role::staff()))).native_preflight().is_ok());
}
~~~

- [ ] **Step 2: Run claim tests to verify they fail**

Run: cargo test -p zcaprio --test claims

Expected: FAIL because signed attribute credentials and public claims are absent.

- [ ] **Step 3: Implement concrete claims and internal fragments**

Encode country and role into fixed bounded field representations. Keep issuer signature and all attributes private from the public proof object and artifact. Each claim produces a total Boolean validity fragment: invalid data yields false rather than leaking a failure-specific private value. CountryIsEu uses a fixed library-owned EU code table encoded into circuit-safe comparisons.

- [ ] **Step 4: Run direct-claim tests**

Run: cargo test -p zcaprio --test claims

Expected: PASS. Valid signed attributes pass their claim; invalid age, country, role, or signature becomes a data-free invalid/unprovable result.

- [ ] **Step 5: Commit credential claim support**

~~~bash
git add crates/zkp-primitives
git commit -m "feat: add signed credential claim objects"
~~~

## Task 5: Lower opaque AND and OR trees into one R1CS circuit

**Files:**
- Create: crates/zkp-primitives/src/groth16/{circuit,signature_gadget}.rs
- Modify: crates/zkp-primitives/src/groth16/{fragment,mod}.rs
- Create: crates/zkp-primitives/tests/{constraints,compositions}.rs

**Interfaces:**
- Consumes private ProofPlan and ClaimFragment from Tasks 3–4.
- Produces Groth16Circuit::from_plan(&ProofPlan, &VerificationPolicy) -> Result<Groth16Circuit, ProofError>.
- Produces total Boolean validity for direct, conjunction, and disjunction fragments.
- Produces internal SignatureGadget::validity(...) -> Result<Boolean<Fr>, SynthesisError>.
- Produces no serialized tree, child artifact, selector, or claim identifier.

- [ ] **Step 1: Write failing composition and privacy-layout tests**

~~~rust
#[test]
fn conjunction_of_different_credentials_satisfies_one_root_relation() {
    let proof = adult_passport()
        .is(Box::new(AgeIsAbove::new(18)))
        .and(eu_residence().is(Box::new(CountryIsEu)));

    assert!(satisfies(&proof, expected_policy()).unwrap());
}

#[test]
fn either_or_branch_satisfies_the_same_public_input_layout() {
    let left = adult_passport().is(Box::new(AgeIsAbove::new(18)))
        .or(non_eu_staff_badge().is(Box::new(RoleIs::new(Role::staff()))));
    let right = underage_passport().is(Box::new(AgeIsAbove::new(18)))
        .or(eu_staff_badge().is(Box::new(RoleIs::new(Role::staff()))));

    assert_eq!(public_input_layout(&left), public_input_layout(&right));
    assert!(satisfies(&left, expected_policy()).unwrap());
    assert!(satisfies(&right, expected_policy()).unwrap());
}
~~~

Add a negative test for neither OR branch and a test that a mismatched verifier policy cannot satisfy the root relation.

- [ ] **Step 2: Run circuit tests to verify they fail**

Run: cargo test -p zcaprio --test constraints --test compositions

Expected: FAIL because proof-tree lowering and R1CS relation do not exist.

- [ ] **Step 3: Implement total Boolean circuit fragments**

Use the Task 2 transcript vector and native signature semantics to implement SignatureGadget. It returns a constrained Boolean validity, not an unconditional assertion. Claims also return Boolean validity. Conjunction lowers to left.and(right); disjunction lowers to left.or(right). The root circuit alone enforces validity equal to true.

Allocate all witness data privately. Allocate only verifier-owned policy fields as public inputs. Do not allocate a child result, credential hash, proof-tree shape, or branch selector publicly.

~~~rust
let root = left_validity.or(&right_validity)?;
root.enforce_equal(&Boolean::constant(true))?;
~~~

- [ ] **Step 4: Run relation and layout tests**

Run: cargo test -p zcaprio --test constraints --test compositions

Expected: PASS. Both OR branches prove with identical public input layouts; neither branch, tampered signatures, invalid ages, invalid country, invalid role, and policy mismatches fail at the root relation.

- [ ] **Step 5: Commit opaque circuit composition**

~~~bash
git add crates/zkp-primitives
git commit -m "feat: compile opaque proof compositions"
~~~

## Task 6: Add Groth16 backend objects and opaque artifact verification

**Files:**
- Create: crates/zkp-primitives/src/groth16/{prover,key_store,artifact,policy}.rs
- Modify: crates/zkp-primitives/src/{lib,proof}.rs
- Modify: crates/zkp-primitives/src/{proof,lib}.rs
- Create: crates/zkp-primitives/tests/{groth16_lifecycle,opaque_artifact}.rs

**Interfaces:**
- Produces VerificationPolicy owned by a verifier and excluded from artifact serialization.
- Produces Groth16Prover implementing zcaprio::Prover.
- Produces Groth16Verifier implementing zcaprio::Verifier.
- Produces OpaqueGroth16Artifact implementing zcaprio::ProofArtifact.
- Produces ProofArtifact::verify(&dyn Verifier) -> Result<Verification, ProofError>.

- [ ] **Step 1: Write failing opaque-artifact tests**

~~~rust
#[test]
fn serialized_artifact_has_no_child_or_branch_metadata() {
    let artifact = prove_or_fixture_with_left_branch().unwrap();
    let encoded = artifact.to_bytes().unwrap();
    let rendered = String::from_utf8_lossy(&encoded);

    for forbidden in ["AgeIsAbove", "CountryIsEu", "RoleIs", "left", "right", "selector", "credential_hash"] {
        assert!(!rendered.contains(forbidden), "artifact leaked {forbidden}");
    }
}

#[test]
fn one_verifier_policy_accepts_both_hidden_or_branches() {
    let verifier = verifier_for(expected_policy()).unwrap();

    assert!(prove_or_fixture_with_left_branch().unwrap().verify(&verifier).unwrap().valid());
    assert!(prove_or_fixture_with_right_branch().unwrap().verify(&verifier).unwrap().valid());
}
~~~

- [ ] **Step 2: Run backend tests to verify they fail**

Run: cargo test -p zcaprio --test groth16_lifecycle --test opaque_artifact

Expected: FAIL because concrete prover, verifier, policy, and artifact objects do not exist.

- [ ] **Step 3: Implement verifier-owned policy and backend adapters**

Generate/load Groth16 keys only through explicit backend methods. Tie a verifier object to its policy and matching verifying key without serializing that policy with the artifact. Prove the complete lazy ProofPlan once. OpaqueGroth16Artifact stores canonical proof bytes and the fixed public input vector only.

Verify the artifact against the verifier's preconfigured policy. Return Verification { valid: bool } or a data-free ProofError; never return child results.

- [ ] **Step 4: Run real proof lifecycle tests**

Run: cargo test -p zcaprio --test groth16_lifecycle --test opaque_artifact

Expected: PASS. Direct claims, cross-credential AND, and both OR branches generate one artifact and verify; tampered artifact, public inputs, or verifier policy fail without exposing composition details.

- [ ] **Step 5: Commit Groth16 proof artifacts**

~~~bash
git add crates/zkp-primitives
git commit -m "feat: add opaque Groth16 proof artifacts"
~~~

## Task 7: Write doctested library documentation and final checks

**Files:**
- Create: README.md
- Modify: crates/zkp-primitives/src/{lib,claim,credential,proof}.rs
- Modify: crates/zkp-primitives/src/groth16/mod.rs
- Create: crates/zkp-primitives/tests/readme_contract.rs

**Interfaces:**
- Produces public README examples for direct claims, cross-credential AND, hidden-branch OR, and custom Claim implementation.
- Produces the documented opaque composition contract.
- Produces crate-level Rustdoc linked to README examples.

- [ ] **Step 1: Write failing README contract tests**

~~~rust
#[test]
fn readme_states_opaque_composition_contract() {
    let readme = std::fs::read_to_string("../../README.md").unwrap();

    assert!(readme.contains("does not expose child proofs, credentials, witnesses, predicates"));
    assert!(readme.contains("does not reveal the satisfying branch"));
}

#[test]
fn readme_uses_only_method_composition() {
    let readme = std::fs::read_to_string("../../README.md").unwrap();

    assert!(readme.contains(".and("));
    assert!(readme.contains(".or("));
    assert!(!readme.contains("And::new"));
    assert!(!readme.contains("Or::new"));
}
~~~

- [ ] **Step 2: Run documentation tests to verify they fail**

Run: cargo test -p zcaprio --test readme_contract

Expected: FAIL because the library README does not exist.

- [ ] **Step 3: Write public examples and Rustdoc**

README must start with a minimal direct proof, then show cross-credential composition:

~~~rust
let eligibility = passport
    .is(Box::new(AgeIsAbove::new(18)))
    .and(residence_card.is(Box::new(CountryIsEu)))
    .or(employee_badge.is(Box::new(RoleIs::staff())));

let artifact = eligibility.prove(&groth16)?;
assert!(artifact.verify(&verifier)?.valid());
~~~

State that artifact and verifier output reveal only root validity, and explicitly say OR does not reveal its satisfying branch. Mark all executable snippets as Rust doctests and supply deterministic public test fixtures through test-only helpers, never holder-secret constructors.

- [ ] **Step 4: Run complete documentation and verification suite**

Run: cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps && cargo test --workspace

Expected: PASS. Doctests compile; all native, object-model, circuit, artifact, composition, and redaction tests pass.

- [ ] **Step 5: Commit final library documentation**

~~~bash
git add README.md crates/zkp-primitives
git commit -m "docs: add composable proof library guide"
~~~

## Plan Self-Review

### Spec coverage

- Task 1 removes all UI, HTTP, server, and localhost behavior.
- Task 2 resolves every outstanding native cryptographic review finding before circuit work begins.
- Task 3 implements the immutable public object model and method-only composition.
- Task 4 adds claims and distinct signed credentials.
- Task 5 compiles one opaque tree with hidden OR branch selection.
- Task 6 creates real Groth16 artifacts verified through out-of-band policy objects.
- Task 7 supplies the requested README snippets, opaque-composition description, doctests, and final verification.

### Consistency review

Credential, Claim, Proof, ProofArtifact, Prover, Verifier, Verification, ProofError, VerificationPolicy, Groth16Prover, Groth16Verifier, and OpaqueGroth16Artifact are introduced before their first consuming task. Proof::and and Proof::or are the sole public composition methods throughout the plan. Only the verifier owns a VerificationPolicy; OpaqueGroth16Artifact never stores or serializes one.

### Ambiguity review

A proof object is lazy until prove is called. Claims are public predicate values because Credential::is requires them; knowledge, witnesses, fragments, tree plans, selectors, issuer-signature details, and backend circuit structures are internal. Different credentials are allowed in one composition. Both AND and OR are opaque; OR branch choice is private and never serialized or reported.
