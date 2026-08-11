# Signed Attribute Schnorr Circuit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make each final Groth16 artifact prove that its age, country, or role claim comes from an issuer-signed credential, rather than from a native preflight check.

**Architecture:** A schema-v2 credential adds a blinded Poseidon commitment to country and role to the issuer-signed message. A verifier-owned circuit template fixes the expected issuer keys and claims outside the artifact, while private witnesses open all commitments and satisfy a Baby-JubJub Schnorr equation. The native signer and the R1CS gadget share the Arkworks Blake2s Fiat-Shamir transcript and its canonical scalar conversion.

**Tech Stack:** Rust stable, Arkworks 0.6, BN254 Groth16, Baby-JubJub, Poseidon, R1CS standard gadgets, Cargo tests and doctests.

## Global Constraints

- Keep `Credential`, `Claim`, `Proof`, and `ProofArtifact` opaque; no artifact contains child proofs, witnesses, claims, credential hashes, or a branch selector.
- Bind age, country, role, and the holder commitment to one schema-v2 issuer signature.
- Allocate issuer keys and claim statements as verifier-owned circuit constants; allocate credential material only as private witnesses.
- Keep all challenge and response scalar encodings canonical before scalar multiplication.
- Use no native validity preflight as a substitute for a circuit relation.

---

### Task 1: Bind all credential attributes in schema v2

**Files:**
- Modify: `crates/zkp-primitives/src/{commitment,issuer,credential,claim,lib}.rs`
- Test: `crates/zkp-primitives/tests/issuer_credentials.rs`

**Interfaces:**
- Produces `AttributeCommitment` from country and role.
- Produces `credential_message(age, owner, attributes, schema) -> [Fr; 4]`.
- Produces a schema-v2 `AgeCredential` whose signature validates only when all three commitments match.

- [x] Write a failing test that changes a signed attribute commitment and expects signature verification to fail.
- [x] Update the native message, signer, verifier, JSON round-trip fixture, and pinned transcript test to include the attribute commitment.
- [x] Make `IssuerCredentials::issue` construct the age, owner, and attribute commitments before signing.
- [x] Run `cargo test -p zcaprio --test issuer_credentials` and commit the schema change with the circuit work.

### Task 2: Add the private Schnorr and commitment relations

**Files:**
- Create: `crates/zkp-primitives/src/groth16/{commitment,signature}.rs`
- Test: `crates/zkp-primitives/src/groth16/signature.rs`

**Interfaces:**
- `CommitmentRelation` calculates the three fixed Poseidon openings in R1CS.
- `SchnorrRelation` calculates `R = G * response + public_key * challenge` and derives the same challenge from the exact native Blake2s transcript.

- [x] Write a direct-circuit test that is satisfied for an issued credential and unsatisfied when one witness signature byte is altered.
- [x] Allocate all credential openings privately, derive each commitment with shared Poseidon parameters, and pass the derived values to the signature relation.
- [x] Constrain response and challenge bytes below the Baby-JubJub scalar modulus, require the challenge's high five bits to be zero, and compare its low 251 bits to the Blake2s transcript hash—the same conversion Arkworks uses.
- [x] Run the relation test and the native transcript test.

### Task 3: Compile the whole opaque proof tree to one relation

**Files:**
- Modify: `crates/zkp-primitives/src/{proof,groth16,lib}.rs`
- Create: `crates/zkp-primitives/src/groth16/{circuit,template}.rs`
- Modify: `crates/zkp-primitives/tests/composed_proofs.rs`

**Interfaces:**
- `Groth16Backend::setup(&Proof, VerificationPolicy)` creates keys for a private verifier template.
- A template accepts only the same issuer keys, claim kinds, and composition shape during `prove`.
- A circuit recursively combines private claim booleans with R1CS `and` and `or`, then enforces one true root.

- [x] Write tests for a changed issuer and altered signed witness being rejected by a backend configured for the original proof.
- [x] Build the template from opaque proof plans; it stores issuer keys, claims, and shape only inside the prover/verifier endpoints, never in an artifact.
- [x] Lower every direct proof to the commitment/signature relation and every composition node to a Boolean relation; enforce the root only.
- [x] Update examples to construct the proof before obtaining its matching backend and run direct, AND, and OR proof tests.

### Task 4: Document and verify the real boundary

**Files:**
- Modify: `README.md`, `crates/zkp-primitives/src/{issuer,groth16}.rs`
- Test: all workspace tests and doctests

- [x] Replace the preflight disclaimer with the actual circuit relation and explain the verifier-held template.
- [x] Run `cargo fmt --check`, strict Clippy, Rustdoc warnings, unit/integration tests, and doctests.
- [x] Inspect the staged diff, then commit only the schema-v2 circuit implementation and documentation.
