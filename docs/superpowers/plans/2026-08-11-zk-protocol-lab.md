# ZK Protocol Lab Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** Build a Rust-first localhost teaching lab that issues a commitment-backed age credential, creates a real Groth16 proof that the holder is at least 18, and verifies it without exposing private witness data.

**Architecture:** A Cargo workspace separates typed protocol primitives, the age credential R1CS and Groth16 implementation, and the Axum teaching app. The browser renders a guided seven-stage workbench and calls loopback-only JSON endpoints; all cryptographic operations and policy validation remain in Rust.

**Tech Stack:** Rust stable, Arkworks 0.6 (ark-groth16, ark-bn254, ark-r1cs-std, ark-crypto-primitives, ark-ed-on-bn254), Axum, Tokio, Serde, Chrono, HTML, CSS, and ES modules.

## Global Constraints

- Use Rust stable and Arkworks 0.6. Use ark-ed-on-bn254 for Baby-JubJub issuer Schnorr keys because its base field is BN254’s scalar field.
- Serve only 127.0.0.1:3000 by default. Do not add a public deployment target.
- Persist Groth16 setup material under .zkp-lab/ only. Never persist raw identity data, salts, wallet secrets, credentials, proofs, or replay state.
- Display that the lab models privacy from the verifier at protocol level; the local teaching server can technically observe its own requests.
- Keep zkp-primitives free of HTTP, HTML, session, and UI dependencies. Keep browser code free of cryptographic calculations and protocol validation.
- Use a domain-separated Poseidon hash for C_age, C_owner, and nullifiers. Sign the exact tuple (C_age, C_owner, schema_v1) with issuer Schnorr keys.
- Return typed, redacted errors. A verifier payload or error must never include a birth day, salt, wallet secret, signature, commitment opening, or private witness.
- Do not put computation, I/O, setup, or random generation in constructors. Use explicit factory or service methods.
- Every public library item requires Rustdoc. Keep modules focused and below 200 lines where practical.
- Before every implementation commit run cargo fmt --check, cargo clippy --workspace --all-targets -- -D warnings, and relevant cargo test commands. Run cargo test --workspace before final integration.

---

## File Structure

~~~text
Cargo.toml
.gitignore
README.md
crates/
  zkp-primitives/
    Cargo.toml
    src/{lib,error,age,commitment,issuer,policy,proof,encoding}.rs
    tests/{age_and_policy,commitments,issuer_credentials}.rs
  age-credential-circuit/
    Cargo.toml
    src/{lib,circuit,signature_gadget,prover,key_store}.rs
    tests/{constraints,groth16_lifecycle}.rs
  zkp-lab/
    Cargo.toml
    src/{main,app,api,models,session,assets}.rs
    tests/{health,api_flow,redaction,replay,page_shell,full_walkthrough}.rs
web/
  templates/index.html
  static/{app.css,app.js}
~~~

The root workspace pins shared dependency versions. zkp-primitives defines native protocol operations and serialization; age-credential-circuit constrains the same operations; zkp-lab owns runtime orchestration, HTTP, and static asset delivery.

## Task 1: Scaffold the workspace and loopback health route

**Files:**
- Create: Cargo.toml
- Create: .gitignore
- Create: crates/zkp-primitives/Cargo.toml
- Create: crates/zkp-primitives/src/lib.rs
- Create: crates/age-credential-circuit/Cargo.toml
- Create: crates/age-credential-circuit/src/lib.rs
- Create: crates/zkp-lab/Cargo.toml
- Create: crates/zkp-lab/src/main.rs
- Create: crates/zkp-lab/src/app.rs
- Test: crates/zkp-lab/tests/health.rs

**Interfaces:**
- Produces zkp_lab::app::router() -> axum::Router.
- Produces zkp_lab::app::bind_address() -> std::net::SocketAddr.
- Produces empty public zkp_primitives and age_credential_circuit crate roots.

- [ ] **Step 1: Write the failing health-route test**

~~~rust
#[tokio::test]
async fn health_route_reports_ready() {
    let response = zkp_lab::app::router()
        .oneshot(request("/api/health"))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}
~~~

- [ ] **Step 2: Run the test to verify it fails**

Run: cargo test -p zkp-lab --test health

Expected: FAIL because the workspace and router do not exist.

- [ ] **Step 3: Add the workspace and the minimal Axum app**

~~~rust
pub fn bind_address() -> SocketAddr {
    let port = std::env::var("ZKP_LAB_PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(3000);
    SocketAddr::from(([127, 0, 0, 1], port))
}

pub fn router() -> Router {
    Router::new().route("/api/health", get(|| async { StatusCode::OK }))
}
~~~

Pin all Arkworks dependencies to 0.6. Add /.zkp-lab/, /.superpowers/, and /target/ to .gitignore.

- [ ] **Step 4: Run the foundational checks**

Run: cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test -p zkp-lab --test health

Expected: PASS.

- [ ] **Step 5: Commit the foundation**

~~~bash
git add Cargo.toml .gitignore crates/zkp-primitives crates/age-credential-circuit crates/zkp-lab
git commit -m "feat: scaffold ZK protocol lab workspace"
~~~

## Task 2: Define dates, policies, errors, and serializable protocol types

**Files:**
- Create: crates/zkp-primitives/src/error.rs
- Create: crates/zkp-primitives/src/age.rs
- Create: crates/zkp-primitives/src/policy.rs
- Create: crates/zkp-primitives/src/proof.rs
- Create: crates/zkp-primitives/src/encoding.rs
- Modify: crates/zkp-primitives/src/lib.rs
- Test: crates/zkp-primitives/tests/age_and_policy.rs

**Interfaces:**
- Produces BirthDay::parse_iso(&str) -> Result<BirthDay, PrimitiveError>.
- Produces BirthDay::days_since_1900() -> u32 and BirthDay::to_iso_string() -> String.
- Produces VerifierScope::new(String) -> Result<VerifierScope, PrimitiveError>.
- Produces IssuerKeyFingerprint::new(String) -> Result<IssuerKeyFingerprint, PrimitiveError>.
- Produces AgePolicy::from_as_of(BirthDay, VerifierScope, IssuerKeyFingerprint) -> Result<AgePolicy, PrimitiveError>.
- Produces PrimitiveError with codes invalid_date, empty_verifier_scope, unsupported_schema, invalid_encoding, invalid_credential, proof_prevented, invalid_proof, and replay_detected.

- [ ] **Step 1: Write failing policy tests**

Define a private test helper named scope that calls VerifierScope::new(value.into()).unwrap().

~~~rust
#[test]
fn derives_the_18_year_cutoff_from_the_verifier_date() {
    let as_of = BirthDay::parse_iso("2026-08-11").unwrap();
    let policy = AgePolicy::from_as_of(
        as_of,
        scope("campus-bar"),
        IssuerKeyFingerprint::new("edu-issuer-v1".into()).unwrap(),
    ).unwrap();

    assert_eq!(policy.cutoff_day().to_iso_string(), "2008-08-11");
}

#[test]
fn blank_scope_is_a_safe_validation_error() {
    let error = VerifierScope::new("  ".into()).unwrap_err();

    assert_eq!(error.code(), "empty_verifier_scope");
    assert!(!error.to_string().contains("birth"));
}
~~~

- [ ] **Step 2: Run the test to verify it fails**

Run: cargo test -p zkp-primitives --test age_and_policy

Expected: FAIL because date and policy types do not exist.

- [ ] **Step 3: Implement the typed data boundary**

Parse ISO dates with chrono::NaiveDate. Reject values before 1900-01-01 or after 2099-12-31. For a February 29 birth date, calculate the non-leap-year threshold as February 28. Make RawDemoIdentity.display_name explicitly display-only; it is not part of the credential.

~~~rust
pub struct VerifierScope(String);

impl VerifierScope {
    pub fn new(value: String) -> Result<Self, PrimitiveError> {
        let value = value.trim().to_owned();
        if value.is_empty() {
            return Err(PrimitiveError::EmptyVerifierScope);
        }
        Ok(Self(value))
    }
}
~~~

- [ ] **Step 4: Run all date and policy tests**

Run: cargo test -p zkp-primitives --test age_and_policy

Expected: PASS for valid normal and leap-year dates; invalid dates, out-of-range dates, and blank scopes fail with stable codes.

- [ ] **Step 5: Commit the protocol types**

~~~bash
git add crates/zkp-primitives
git commit -m "feat: add age policy protocol types"
~~~

## Task 3: Implement commitments, nullifiers, and issuer credentials

**Files:**
- Create: crates/zkp-primitives/src/commitment.rs
- Create: crates/zkp-primitives/src/issuer.rs
- Modify: crates/zkp-primitives/src/{lib,error,encoding,proof}.rs
- Test: crates/zkp-primitives/tests/commitments.rs
- Test: crates/zkp-primitives/tests/issuer_credentials.rs

**Interfaces:**
- Consumes BirthDay, VerifierScope, and PrimitiveError from Task 2.
- Consumes IssuerKeyFingerprint from Task 2.
- Produces AgeSalt::generate, WalletSecret::generate, AgeCommitment, OwnerCommitment, Nullifier, IssuerKeyPair, IssuerPublicKey, and AgeCredential.
- Produces commit_age(BirthDay, &AgeSalt) -> AgeCommitment.
- Produces commit_owner(&WalletSecret) -> OwnerCommitment.
- Produces derive_nullifier(&WalletSecret, &VerifierScope) -> Nullifier.
- Produces IssuerKeyPair::issue(AgeCommitment, OwnerCommitment) -> AgeCredential.
- Produces AgeCredential::verify(&IssuerPublicKey) -> Result<(), PrimitiveError>.
- Produces IssuerPublicKey::fingerprint() -> IssuerKeyFingerprint.
- Produces credential_message(AgeCommitment, OwnerCommitment, u8) -> [ark_bn254::Fr; 3].

- [ ] **Step 1: Write failing commitment and issuer-binding tests**

Define private test helpers day, scope, fixed_age_salt, fixed_wallet_secret, fixed_issuer, age_commitment, and owner_commitment. Each fixed helper uses a ChaCha20Rng seeded with the displayed integer and the relevant public factory; no production API accepts deterministic entropy.

~~~rust
#[test]
fn commitment_opening_requires_matching_date_and_salt() {
    let salt = fixed_age_salt(7);
    let commitment = commit_age(day("2000-01-02"), &salt);

    assert!(commitment.matches(day("2000-01-02"), &salt));
    assert!(!commitment.matches(day("2000-01-03"), &salt));
}

#[test]
fn issuer_signature_binds_both_commitments() {
    let issuer = fixed_issuer();
    let credential = issuer.issue(age_commitment(1), owner_commitment(2));

    assert!(credential.verify(&issuer.public_key()).is_ok());
    let mut tampered = credential.clone();
    tampered.owner_commitment = owner_commitment(3);
    assert!(tampered.verify(&issuer.public_key()).is_err());
}
~~~

Add tests that a same-secret, same-scope nullifier is identical; a different scope changes it; a modified schema, signature, or issuer key invalidates a credential.

- [ ] **Step 2: Run the primitive tests to verify they fail**

Run: cargo test -p zkp-primitives --test commitments --test issuer_credentials

Expected: FAIL because the primitives do not exist.

- [ ] **Step 3: Implement domain-separated native primitives**

Centralize exactly three Poseidon domains: ZKPLAB_AGE_V1, ZKPLAB_OWNER_V1, and ZKPLAB_NULLIFIER_V1. Generate salt and secret only in explicit factories using OsRng; redact their Debug output. Wrap Arkworks Baby-JubJub Schnorr types so no public library signature depends on an Arkworks internal representation. Sign only the canonical credential_message.

~~~rust
pub fn derive_nullifier(secret: &WalletSecret, scope: &VerifierScope) -> Nullifier {
    Nullifier(poseidon_hash([NULLIFIER_DOMAIN, secret.field_element(), scope.field_element()]))
}

pub fn issue(&self, age: AgeCommitment, owner: OwnerCommitment) -> AgeCredential {
    let signature = self.signer.sign(&credential_message(age, owner, SCHEMA_V1));
    AgeCredential::signed(self.issuer_id.clone(), age, owner, signature)
}
~~~

- [ ] **Step 4: Run primitive, mutation, and serialization tests**

Run: cargo test -p zkp-primitives --test commitments --test issuer_credentials

Expected: PASS. Commitment domains differ, invalid hex is invalid_encoding, altered dates/salts/secrets fail to open, and changed credential data fails signature verification.

- [ ] **Step 5: Commit native cryptographic primitives**

~~~bash
git add crates/zkp-primitives
git commit -m "feat: add commitment-backed issuer credentials"
~~~

## Task 4: Constrain the age credential relation in R1CS

**Files:**
- Create: crates/age-credential-circuit/src/circuit.rs
- Create: crates/age-credential-circuit/src/signature_gadget.rs
- Modify: crates/age-credential-circuit/src/lib.rs
- Test: crates/age-credential-circuit/tests/constraints.rs

**Interfaces:**
- Consumes all Task 2 and Task 3 types.
- Produces AgeCredentialWitness { birth_day, age_salt, wallet_secret, credential }.
- Produces AgeCredentialPublicInputs { issuer_key, as_of_day, cutoff_day, verifier_scope, nullifier }.
- Produces AgeCredentialCircuit::new(witness, public_inputs).
- Produces AgeCredentialCircuit::is_satisfied(witness, public_inputs) -> Result<(), CircuitError>.
- Produces ConstraintSynthesizer<ark_bn254::Fr> for AgeCredentialCircuit.

- [ ] **Step 1: Write failing invariant tests**

Define a private adult_fixture(birth_date, scope) helper in this test module. It generates an issuer, salt, and wallet secret with ChaCha20Rng, creates both commitments, issues a credential, derives a policy and nullifier, then returns the exact witness and public inputs.

~~~rust
#[test]
fn a_valid_adult_witness_satisfies_every_constraint() {
    let fixture = adult_fixture("2000-01-01", "campus-bar");

    assert!(AgeCredentialCircuit::is_satisfied(fixture.witness, fixture.public_inputs).is_ok());
}

#[test]
fn an_underage_witness_cannot_satisfy_the_age_constraint() {
    let fixture = adult_fixture("2010-01-01", "campus-bar");

    assert_eq!(
        AgeCredentialCircuit::is_satisfied(fixture.witness, fixture.public_inputs)
            .unwrap_err()
            .code(),
        "proof_prevented"
    );
}
~~~

Add separate tests changing one item each: age salt, wallet secret, C_age, C_owner, signature, issuer key, cutoff day, scope, and nullifier.

- [ ] **Step 2: Run constraint tests to verify they fail**

Run: cargo test -p age-credential-circuit --test constraints

Expected: FAIL because the circuit does not exist.

- [ ] **Step 3: Implement the complete constrained relation**

Allocate issuer key, policy day values, verifier scope, and nullifier as public inputs. Allocate birth day, salt, wallet secret, commitments, and issuer signature as private witnesses. Recompute C_age, C_owner, and nullifier with the Task 3 Poseidon domains. Verify the Task 3 canonical credential message with the Baby-JubJub Schnorr R1CS gadget.

Constrain age with bounded unsigned arithmetic: decompose birth_day, cutoff_day, and private age_delta as 17-bit values and enforce birth_day + age_delta = cutoff_day. This blocks finite-field underflow and means an underage witness cannot satisfy the relation.

~~~rust
fn enforce_age_at_least_18(
    birth_day: UInt32<Fr>,
    cutoff_day: UInt32<Fr>,
    age_delta: UInt32<Fr>,
) -> Result<(), SynthesisError> {
    birth_day.addmany(&[&age_delta])?.enforce_equal(&cutoff_day)
}
~~~

Use the equivalent concrete Arkworks UInt32 operation if its 0.6 spelling differs, while retaining the same equation and 17-bit bounds.

- [ ] **Step 4: Run all satisfiable and unsatisfiable relation tests**

Run: cargo test -p age-credential-circuit --test constraints

Expected: PASS. The valid adult fixture satisfies; every one-field mutation returns proof_prevented without requiring Groth16 setup.

- [ ] **Step 5: Commit the R1CS relation**

~~~bash
git add crates/age-credential-circuit crates/zkp-primitives
git commit -m "feat: constrain signed private age credential"
~~~

## Task 5: Add Groth16 key management, proof construction, and verification

**Files:**
- Create: crates/age-credential-circuit/src/key_store.rs
- Create: crates/age-credential-circuit/src/prover.rs
- Modify: crates/age-credential-circuit/src/lib.rs
- Test: crates/age-credential-circuit/tests/groth16_lifecycle.rs

**Interfaces:**
- Consumes Task 4 circuit, witness, and public input types.
- Produces LabKeyStore::open(&Path) -> Result<LabKeyStore, CircuitError>.
- Produces LabKeyStore::load_or_generate() -> Result<Groth16Material, CircuitError>.
- Produces Groth16Material { proving_key, verifying_key, verifying_key_fingerprint }.
- Produces AgeProver::prove(witness, inputs) -> Result<AgeProof, CircuitError>.
- Produces AgeVerifier::verify(&AgeProof, &AgeCredentialPublicInputs) -> Result<(), CircuitError>.

- [ ] **Step 1: Write failing Groth16 lifecycle tests**

Define private temporary_key_store and verified_fixture helpers in this test module. temporary_key_store creates a TempDir-backed LabKeyStore; verified_fixture builds the adult_fixture from Task 4, proves it, and returns the proof, inputs, and verifier.

~~~rust
#[test]
fn proof_verifies_using_only_public_inputs() {
    let fixture = adult_fixture("2000-01-01", "campus-bar");
    let material = temporary_key_store().load_or_generate().unwrap();
    let proof = AgeProver::new(&material.proving_key)
        .prove(fixture.witness, fixture.public_inputs.clone())
        .unwrap();

    assert!(AgeVerifier::new(&material.verifying_key)
        .verify(&proof, &fixture.public_inputs)
        .is_ok());
}

#[test]
fn changed_scope_invalidates_a_real_proof() {
    let (proof, mut inputs, verifier) = verified_fixture();
    inputs.verifier_scope = scope("concert");

    assert_eq!(verifier.verify(&proof, &inputs).unwrap_err().code(), "invalid_proof");
}
~~~

- [ ] **Step 2: Run lifecycle tests to verify they fail**

Run: cargo test -p age-credential-circuit --test groth16_lifecycle

Expected: FAIL because key, proof, and verifier services do not exist.

- [ ] **Step 3: Implement explicit setup and proving services**

Generate runtime setup material with OsRng. Persist versioned, checksummed serializations under .zkp-lab/groth16-v1/ using a temporary file followed by rename. Reject material whose circuit fingerprint differs. Never use deterministic runtime randomness.

~~~rust
pub fn load_or_generate(&self) -> Result<Groth16Material, CircuitError> {
    match self.load() {
        Ok(material) => Ok(material),
        Err(CircuitError::MissingKeyMaterial) => self.generate_with(OsRng),
        Err(error) => Err(error),
    }
}
~~~

After proving, verify the result once before returning it. Map an unsatisfied relation to proof_prevented and malformed proof encoding to invalid_proof.

- [ ] **Step 4: Run proof lifecycle and tampering tests**

Run: cargo test -p age-credential-circuit --test groth16_lifecycle

Expected: PASS. Valid proof verifies. Changed proof bytes, issuer key, cutoff, scope, or nullifier fail verification.

- [ ] **Step 5: Commit proof lifecycle support**

~~~bash
git add crates/age-credential-circuit
git commit -m "feat: add Groth16 age proof lifecycle"
~~~

## Task 6: Implement in-memory sessions and role-redacted APIs

**Files:**
- Create: crates/zkp-lab/src/api.rs
- Create: crates/zkp-lab/src/models.rs
- Create: crates/zkp-lab/src/session.rs
- Modify: crates/zkp-lab/src/{app,main}.rs
- Test: crates/zkp-lab/tests/api_flow.rs
- Test: crates/zkp-lab/tests/redaction.rs
- Test: crates/zkp-lab/tests/replay.rs

**Interfaces:**
- Consumes Task 2–5 public APIs.
- Produces LabSession::reset, create_age_commitment, create_owner_commitment, issue_credential, construct_proof, and verify_proof.
- Produces POST /api/lab/reset, /api/commitments/age, /api/commitments/owner, /api/issuer/credentials, /api/proofs/age, and /api/verifications/age.
- Produces IssuerArtifact, HolderArtifact, and VerifierArtifact response models.

- [ ] **Step 1: Write failing API flow, privacy, and replay tests**

Define private test_app, post_json, response_text, and drive_issue_and_prove_flow helpers in this test module. drive_issue_and_prove_flow must call the six teaching routes in their UI order and return the generated proof identifier.

~~~rust
#[tokio::test]
async fn verifier_response_contains_no_private_witness_fields() {
    let app = test_app();
    let proof_id = drive_issue_and_prove_flow(&app).await;
    let response = post_json(&app, "/api/verifications/age", json!({ "proof_id": proof_id })).await;
    let body = response_text(response).await;

    assert_eq!(response.status(), StatusCode::OK);
    for forbidden in ["birth_day", "age_salt", "wallet_secret", "signature", "age_commitment", "owner_commitment"] {
        assert!(!body.contains(forbidden), "leaked {forbidden}");
    }
}
~~~

Add a test that invokes verification twice and expects replay_detected the second time, plus a test where an underage date returns proof_prevented.

- [ ] **Step 2: Run API tests to verify they fail**

Run: cargo test -p zkp-lab --test api_flow --test redaction --test replay

Expected: FAIL because session and endpoints do not exist.

- [ ] **Step 3: Implement explicit local teaching state**

Store raw demo data, salts, secrets, credentials, proofs, and the replay set only in a LabSession behind Arc<Mutex<...>>. Reset must replace the whole session. The issuance handler recomputes C_age from the displayed date and stored salt before signing. The owner endpoint generates a wallet secret internally and returns only a redacted descriptor.

~~~rust
pub struct VerifierArtifact {
    pub status: VerificationStatus,
    pub policy: PublicPolicyView,
    pub issuer_key_fingerprint: String,
    pub nullifier: String,
    pub proof_bytes: usize,
}
~~~

Use per-role response types rather than one reusable artifact with optional private properties. The verifier type must not have private fields at all.

- [ ] **Step 4: Run route and redaction tests**

Run: cargo test -p zkp-lab --test api_flow --test redaction --test replay

Expected: PASS. Issue → prove → verify succeeds; reset clears session state; same scope rejects a replay; all verifier payloads remain private-field-free.

- [ ] **Step 5: Commit the teaching API**

~~~bash
git add crates/zkp-lab
git commit -m "feat: add local protocol lab API"
~~~

## Task 7: Build the guided, role-led workbench

**Files:**
- Create: web/templates/index.html
- Create: web/static/app.css
- Create: web/static/app.js
- Create: crates/zkp-lab/src/assets.rs
- Modify: crates/zkp-lab/src/app.rs
- Test: crates/zkp-lab/tests/page_shell.rs

**Interfaces:**
- Consumes Task 6 endpoints.
- Produces GET /, GET /static/app.css, and GET /static/app.js.
- Produces browser actions resetLab, createAgeCommitment, createOwnerCommitment, issueCredential, constructProof, and verifyProof.
- Produces semantic sections setup, raw-data, commitments, issuance, policy, proof, and verification.

- [ ] **Step 1: Write a failing workbench-shell test**

Define private get and response_text helpers that execute an Axum Router request and collect its body.

~~~rust
#[tokio::test]
async fn root_page_has_all_stages_and_the_security_boundary() {
    let response = get(zkp_lab::app::router(), "/").await;
    let body = response_text(response).await;

    for marker in [
        "id=\"setup\"",
        "id=\"raw-data\"",
        "id=\"commitments\"",
        "id=\"issuance\"",
        "id=\"policy\"",
        "id=\"proof\"",
        "id=\"verification\"",
        "Educational localhost lab",
    ] {
        assert!(body.contains(marker), "missing {marker}");
    }
}
~~~

- [ ] **Step 2: Run the shell test to verify it fails**

Run: cargo test -p zkp-lab --test page_shell

Expected: FAIL because root rendering and static assets do not exist.

- [ ] **Step 3: Implement the static interface**

Create an ordered seven-stage protocol board. Use purple for issuer/trust, teal for holder/private computation, and amber for verifier/public result. Use accessible institution, shield, commitment, proof, and verification pictograms alongside text. Each card must state what it does and label its artifact with visible or private markers.

In app.js, call only Task 6 endpoints with fetch. Render the role-specific JSON values as supplied; do not recalculate commitments, policies, proofs, or verification outcomes. Add a Teaching reveal control that is disabled by default and appears only in the holder area. Use aria-live for status messages.

~~~javascript
async function constructProof() {
  const response = await post("/api/proofs/age", selectedPolicy());
  renderHolderProof(await response.json());
}
~~~

- [ ] **Step 4: Run page and privacy tests**

Run: cargo test -p zkp-lab --test page_shell && cargo test -p zkp-lab --test redaction

Expected: PASS. The page has every stage and explanation; the interface integration does not alter verifier redaction.

- [ ] **Step 5: Smoke-test the local walkthrough**

Run: cargo run -p zkp-lab

Expected: http://127.0.0.1:3000 shows a fake adult walkthrough. Complete it, change the birth date to underage, and reuse a proof in the same scope. Each result must be visible in the correct role panel.

- [ ] **Step 6: Commit the workbench**

~~~bash
git add web crates/zkp-lab
git commit -m "feat: add guided ZK protocol workbench"
~~~

## Task 8: Document, test, and verify the full experience

**Files:**
- Create: README.md
- Create: crates/zkp-lab/tests/full_walkthrough.rs
- Create: crates/zkp-primitives/tests/public_docs.rs
- Modify: public modules under crates/zkp-primitives/src
- Modify: public modules under crates/age-credential-circuit/src
- Modify: public modules under crates/zkp-lab/src

**Interfaces:**
- Consumes the complete implementation from Tasks 1–7.
- Produces a copyable local launch path, glossary, endpoint list, 18+ walkthrough, and exact educational/non-production boundary.
- Produces one integration flow covering issue → prove → verify → replay rejection.

- [ ] **Step 1: Write failing final-flow and documentation tests**

Define private test_app, drive_issue_and_prove_flow, and verify helpers in full_walkthrough.rs; their sequence must match the concrete endpoints from Task 6.

~~~rust
#[tokio::test]
async fn adult_flow_verifies_then_replay_is_rejected() {
    let app = test_app();
    let proof_id = drive_issue_and_prove_flow(&app).await;

    assert_eq!(verify(&app, &proof_id).await.status, "eligible");
    assert_eq!(verify(&app, &proof_id).await.status, "replay_detected");
}

#[test]
fn public_primitive_api_is_rustdoc_documented() {
    let source = std::fs::read_to_string("src/lib.rs").unwrap();

    assert!(source.contains("/// Create a domain-separated age commitment."));
}
~~~

- [ ] **Step 2: Run the final tests to verify they fail**

Run: cargo test -p zkp-lab --test full_walkthrough && cargo test -p zkp-primitives --test public_docs

Expected: FAIL until the full walkthrough and Rustdoc are present.

- [ ] **Step 3: Write documentation and complete acceptance fixtures**

README must include Rust installation, cargo run -p zkp-lab, the 127.0.0.1:3000 URL, .zkp-lab key material location, glossary entries for witness, commitment, credential, public input, nullifier, and proof, the default 18+ walkthrough, verifier-visible fields, and the explicit educational/non-production warning. Explain that all roles are simulated in one local app.

Add Rustdoc to every exported primitive, circuit service, and error code. The final fixture must assert that neither raw fields nor private opening data are present in a verifier result.

- [ ] **Step 4: Run the complete verification suite**

Run: cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace

Expected: PASS for primitive, constraint, proof, API, redaction, replay, workbench, and walkthrough suites.

- [ ] **Step 5: Run the localhost accessibility check**

Run in one terminal: cargo run -p zkp-lab

Run in a second terminal: curl -sS http://127.0.0.1:3000/api/health

Expected: HTTP 200. Load the page and confirm issuer, holder, and verifier lanes display visible/private labels and all default actions work.

- [ ] **Step 6: Commit final documentation and verification**

~~~bash
git add README.md crates/zkp-primitives crates/age-credential-circuit crates/zkp-lab
git commit -m "docs: complete ZK protocol lab walkthrough"
~~~

## Plan Self-Review

### Spec coverage

- Tasks 1, 4, 5, and 6 deliver the Rust workspace, actual R1CS/Groth16 proof system, and localhost application.
- Tasks 2–5 implement the two-commitment issuer protocol, holder binding, public policy, issuer-signature validation, and scope-derived nullifier.
- Task 7 implements the guided construction blocks, institution icons, colour-coded roles, visibility labels, teaching reveal, and clear rejection states.
- Task 6 prevents persistence of private classroom data, enforces verifier response redaction, resets state, and rejects replay.
- Task 8 covers README, Rustdoc, end-to-end flow, format, lint, tests, and localhost validation.

### Consistency review

BirthDay, VerifierScope, AgePolicy, AgeCommitment, OwnerCommitment, WalletSecret, IssuerPublicKey, AgeCredential, AgeCredentialWitness, AgeCredentialPublicInputs, AgeProof, AgeProver, and AgeVerifier are introduced before their first consumer. The same credential_message and public input fields flow from native issuance through R1CS constraints, proof construction, API response models, and verification.

### Ambiguity review

The first release is a guided fixed age-credential protocol, not a free-form graph editor. The name field is explicitly display-only. The issuer sees the birth date and age salt only during simulated issuance; it never receives the wallet secret. The verifier sees only public policy inputs, issuer key, proof, and nullifier.
