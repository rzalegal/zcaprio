# ZK Protocol Lab — Design Specification

**Status:** Approved for implementation planning
**Date:** 2026-08-11
**Primary language:** Rust

## Purpose

ZK Protocol Lab is a localhost teaching application and reusable Rust library for demonstrating real zero-knowledge proofs in a sequence students can inspect:

1. enter simulated identity data;
2. create commitments;
3. issue an issuer-signed credential;
4. construct a proof of a hidden age claim; and
5. independently verify the proof without receiving the birth date, credential, or holder secret.

The first complete example proves that a holder is at least 18. It must make clear why a user cannot invent an age: a simulated identity issuer verifies the input during issuance and signs commitments derived from it. The proof circuit validates that signature before it evaluates the age predicate.

This is educational cryptographic software, not production identity infrastructure. It must prominently state that it is unaudited and that its local roles are protocol simulations, not process or network isolation boundaries.

## Scope

### Included in the first release

- A Cargo workspace whose core protocol and proof implementation are Rust.
- A reusable `zkp-primitives` library with documented, typed APIs for commitments, issuer credentials, proof construction, and verification.
- An `age-credential-circuit` crate containing a real Arkworks R1CS circuit and Groth16 proof implementation.
- An Axum teaching application, `zkp-lab`, hosted at `http://localhost:3000` by default.
- A guided workbench with these editable, observable blocks:
  - raw demo identity data;
  - age commitment;
  - holder-binding commitment;
  - credential issuance;
  - public policy inputs;
  - proof construction; and
  - verification and replay detection.
- A simulated issuer, holder, and verifier visual language:
  - institution/role pictograms;
  - purple issuer, teal holder/private computation, and amber verifier/result regions;
  - `👁 visible` and `🔒 private` labels on every artifact; and
  - labelled arrows for exchanged data.
- A default 18+ walkthrough plus ability to change birth date, policy date, and verifier scope.
- In-memory demo state with a reset action. No raw demo identity data is written to disk.
- Locally persisted Groth16 setup material so restarts do not require a setup ceremony for every proof.

### Explicitly out of scope

- Real government, university, or commercial identity integrations.
- Production deployment, multi-user accounts, credential revocation, key rotation, or audit claims.
- Blockchain integration or on-chain verification.
- An arbitrary circuit-graph editor or a generic visual programming language.
- Browser-side proving in the first release. The local Rust teaching app performs the proof construction.
- Privacy from the local teaching server. The lab models privacy from the verifier at the protocol level.

## Technical approach

### Proof stack

Use Arkworks 0.6 on stable Rust:

- `ark-groth16` with the BN254 pairing curve for a real Groth16 proof.
- `ark-relations` and `ark-r1cs-std` for the age credential R1CS circuit.
- `ark-crypto-primitives` for circuit-compatible commitments, hashing, and Schnorr signature support.
- `ark-ed-on-bn254` (Baby-JubJub, whose base field is BN254’s scalar field) for issuer Schnorr keys and signatures that can be checked efficiently in the R1CS circuit.
- A domain-separated Poseidon hash for the commitments and nullifier.

The lab performs a Groth16 setup once per persisted local lab instance, using operating-system randomness. The proving key is only available to the simulated holder/prover. The verifying key and issuer public key are displayed as public artifacts. Test fixtures may use deterministic randomness solely for reproducible tests; runtime setup and proving do not.

Groth16’s circuit-specific setup is deliberately part of the lesson. The UI has a short “Setup” explainer and identifies the persisted verifying key fingerprint used by a proof.

### Workspace boundaries

```text
zcaprio/
├── crates/
│   ├── zkp-primitives/          # Commitment, credential, encoding, error APIs
│   ├── age-credential-circuit/  # R1CS constraints and Groth16 adapter
│   └── zkp-lab/                 # Axum server, session state, HTTP handlers
├── web/                         # Semantic HTML, CSS, and minimal UI interaction code
├── docs/
│   └── superpowers/specs/
└── .zkp-lab/                    # Local runtime keys only; gitignored
```

`zkp-primitives` must not depend on HTTP or browser code. `age-credential-circuit` depends on the primitives crate, and `zkp-lab` orchestrates both through their public APIs. The UI must never duplicate or reimplement protocol rules.

The browser layer is deliberately thin. It renders server-provided models, lets students enter data and select actions, and shows returned artifacts. All cryptographic computation and validation remain in Rust.

## Protocol design

### Types

The public library exposes serializable, documented domain types. Hex or base64 representations shown in the UI use a stable encoding and include a short explanatory label.

- `RawDemoIdentity`: a display-only fake name and an ISO-8601 birth date used only by the local issuer workflow. The name is intentionally not bound into the first credential; the lab proves an age property, not identity.
- `AgeCommitment`: `C_age = Poseidon(age_domain, birth_day, age_salt)`.
- `OwnerCommitment`: `C_owner = Poseidon(owner_domain, wallet_secret)`.
- `IssuerKeyPair` and `IssuerPublicKey`.
- `AgeCredential`: issuer identifier, schema version, `C_age`, `C_owner`, and an issuer Schnorr signature over those values and the schema version.
- `AgePolicy`: issuer public-key fingerprint, public `as_of_day`, derived public 18+ `cutoff_day`, and non-empty verifier scope.
- `AgeProof`: serialized Groth16 proof plus its public inputs.
- `VerificationResult`: `Eligible`, `InvalidProof`, or `ReplayDetected`, with a student-readable reason and a machine-readable error code.

`birth_day` and policy days are unsigned days since `1900-01-01`. The issuer parses and validates the ISO date before converting it. The verifier computes `cutoff_day` from its public policy date; the circuit checks the integer comparison `birth_day <= cutoff_day`. This avoids a calendar implementation inside the circuit while keeping the policy decision visible and deterministic.

### Issuance

1. The holder enters fake demo identity data and generates a random age salt and high-entropy wallet secret.
2. The holder creates `C_age` from the birth day and salt, and `C_owner` from the wallet secret.
3. The simulated issuer sees the fake identity data, the birth day, the age salt, `C_age`, and `C_owner`. It validates the date, recomputes `C_age`, and signs `(C_age, C_owner, schema_v1)`.
4. The holder receives `AgeCredential`; the wallet secret is not sent to or stored by the issuer.

The issuer can authenticate the age commitment because it receives the birth day and age salt during issuance. It cannot derive the wallet secret from `C_owner`. The holder-binding commitment prevents use of the credential without the secret, although no protocol can prevent a holder deliberately sharing their secret and credential.

### Proof construction

The holder submits the credential and private witness to the local teaching app’s prover role.

Private witness:

- birth day and age salt;
- wallet secret;
- `C_age` and `C_owner`;
- issuer signature; and
- issuer identifier and schema version.

Public inputs:

- issuer public key;
- `as_of_day` and `cutoff_day` from the verifier’s policy;
- verifier scope; and
- `nullifier = Poseidon(nullifier_domain, wallet_secret, verifier_scope)`.

The R1CS circuit enforces all of the following:

1. the private birth day and salt open `C_age`;
2. the private wallet secret opens `C_owner`;
3. the issuer Schnorr signature is valid over the two commitments and schema version, using the public issuer key;
4. the birth day is in the allowed representation range and is no later than the public 18+ cutoff; and
5. the public nullifier is derived from the private wallet secret and public verifier scope.

The proof does not disclose the birth day, salts, wallet secret, commitments, or issuer signature. It proves only that a valid issuer credential and valid holder secret exist for the requested policy.

### Verification and replay handling

The verifier accepts an `AgeProof`, the public policy, and the Groth16 verifying key. It verifies the proof using only public inputs. It then checks an in-memory set of `(verifier_scope, nullifier)` values:

- absent: store it and return `Eligible`;
- present: return `ReplayDetected` without accepting the proof again.

Changing scope changes the nullifier, so independent verifiers cannot link use by nullifier. The replay set resets with the teaching session; this limitation is shown in the UI.

## Guided workbench

The initial page is an ordered protocol board, not a free-form graph editor. The selected 18+ scenario is prefilled with clearly fake data. Each block has a one-sentence purpose, role icon, visibility labels, inputs, outputs, and a copyable raw artifact representation.

1. **Setup** — show the Groth16 circuit identity, proving/verifying-key roles, issuer public key, and the educational-only notice.
2. **Raw ID data** — holder enters a display name and birth date; only the simulated issuer panel is marked as able to see it.
3. **Create commitments** — expose `C_age` and `C_owner`; salts and secrets remain redacted unless the holder activates a clearly marked teaching reveal.
4. **Issue credential** — show what the issuer has checked and the signature-bearing credential returned to the holder.
5. **Choose verification policy** — verifier sets the public `as_of_day` and scope; the UI derives and displays the 18+ cutoff.
6. **Construct proof** — enumerate the circuit assertions, display elapsed time and proof byte length, and show a proof artifact without private witness data.
7. **Verify proof** — show exactly what the verifier receives, proof validity, and replay status.

The visual language is mandatory: purple for issuer/trust anchor, teal for holder and private computation, amber for verifier and public decision, `👁` for visible data, and `🔒` for private data. Institution, shield, commitment, proof, and verification pictograms reinforce roles without replacing written explanations.

## HTTP surface

The teaching application is served by the `zkp-lab` binary on port 3000 by default. Its JSON endpoints mirror library actions so students can inspect simple actionable primitives:

- `POST /api/lab/reset`
- `POST /api/commitments/age`
- `POST /api/commitments/owner`
- `POST /api/issuer/credentials`
- `POST /api/proofs/age`
- `POST /api/verifications/age`

Responses include an artifact model for the relevant role panel. Private fields must not appear in a verifier response. The server accepts only loopback requests by default.

## Failure behavior

The workbench explains rejections at the correct step:

- malformed dates, empty scopes, invalid encodings, and unsupported schema versions are input errors;
- a mismatched commitment opening, invalid issuer signature, wrong holder secret, or underage witness results in `ProofPrevented` and names the failed invariant;
- an altered proof, public-input mismatch, or unknown issuer key results in `InvalidProof`;
- a previously accepted scope/nullifier pair results in `ReplayDetected`.

Errors are typed in Rust and serialized with stable codes and safe student-facing messages. The app does not emit private witness values in error payloads. A “teaching reveal” is holder-only in the UI and is disabled by default.

## Testing and documentation

The implementation must include:

- native primitive tests for commitments, Schnorr signing, encoding, and error handling;
- circuit tests for a valid 18+ credential and each invalid invariant individually;
- mutation tests that alter date, salt, holder secret, commitment, signature, proof bytes, public cutoff, and scope;
- integration tests for issue → prove → verify and a second same-scope verification producing `ReplayDetected`;
- HTTP tests for success and redaction behavior; and
- `cargo test`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo fmt --check` in the verification workflow.

Every public library item and every workbench stage includes concise Rustdoc or user-facing explanation. The README provides the localhost launch command, a glossary, the 18+ walkthrough, and the educational/non-production security boundary.

## Acceptance criteria

The first release is complete when:

1. `cargo run -p zkp-lab` starts the guided app at `http://localhost:3000`.
2. A student can issue a credential from fake identity data, create a real Groth16 proof, and verify it successfully.
3. The verifier view cannot obtain the birth date, salts, wallet secret, commitments, or issuer signature from its response model.
4. Altering any proof-critical private or public input prevents proof construction or verification.
5. A second verification of the same proof in the same scope is rejected as a replay, while a proof for a different scope has a distinct nullifier.
6. The UI visibly distinguishes issuer, holder, and verifier roles and marks who can see each artifact.
7. The project documentation says it is an educational localhost lab, not production credential infrastructure.
