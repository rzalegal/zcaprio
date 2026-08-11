# Composable Opaque ZK Proof Library — Design Specification

**Status:** Approved for implementation planning
**Date:** 2026-08-11
**Primary language:** Rust
**Supersedes:** The localhost teaching-workbench direction in `2026-08-11-zk-protocol-lab-design.md`.

## Purpose

Build a Rust library of small, immutable, object-oriented proof building blocks. Users construct a proof statement from credentials and claims, compose it through methods on the resulting proof objects, and generate one zero-knowledge artifact only at the end.

The library follows an object-oriented, decorator-oriented style: public objects expose behavior; private witnesses, circuit fragments, signature checks, and proving details remain internal. Constructors only assign fields. Factories and service methods perform validation, randomness, compilation, or I/O.

The first release remains educational and unaudited. It creates real Groth16 proofs, but it is not production identity infrastructure.

## Product boundary

This replaces the UI-first localhost workbench. The final product is a library with a README containing small, compile-tested Rust snippets. It has no Axum server, browser application, static assets, REST API, session store, or localhost port.

The existing native primitive work is useful only after outstanding cryptographic review findings are fixed. No R1CS, proving, or documentation work may build on unresolved native issues.

## Public object model

The public library has three primary concepts: `Credential`, `Claim`, and `Proof`.

```rust
pub trait Credential {
    fn hash(&self) -> CredentialHash;
    fn is(&self, claim: Box<dyn Claim>) -> Box<dyn Proof>;
}

pub trait Claim {
    fn name(&self) -> ClaimName;
}

pub trait Proof {
    fn and(self: Box<Self>, other: Box<dyn Proof>) -> Box<dyn Proof>;
    fn or(self: Box<Self>, other: Box<dyn Proof>) -> Box<dyn Proof>;
    fn prove(&self, prover: &dyn Prover) -> Result<Box<dyn ProofArtifact>, ProofError>;
}

pub trait ProofArtifact {
    fn verify(&self, verifier: &dyn Verifier) -> Result<Verification, ProofError>;
}
```

`AgeIsAbove`, `AgeIsBelow`, `CountryIsEu`, and `RoleIs` are small immutable `Claim` objects. Calling `credential.is(claim)` returns a lazy `Proof`: it binds the claim to private credential evidence but does not create proof bytes or expose its witness.

`Proof::and` and `Proof::or` are the only composition entry points. There is no free-standing `And` or `Or` constructor in the public API. Each method returns a new immutable proof decorator. Different child proofs may originate from different credentials.

Internally, direct, conjunction, and disjunction proofs are represented by focused private objects such as `CredentialProof`, `ConjunctionProof`, and `DisjunctionProof`. Their implementation can change without changing the public trait contract.

## Opaque composition contract

The README and Rustdoc must state this contract verbatim in substance:

> `and()` and `or()` return a new opaque proof object. They do not expose child proofs, credentials, witnesses, predicates, or—when using `or()`—the satisfying branch. `prove()` compiles the whole tree to one artifact, and `verify()` reveals only the overall result.

An artifact's serialization contains proof bytes and declared public inputs only. It must not contain a serializable proof tree, child-proof byte strings, credential hashes, claim names, child verification results, or an OR selector.

The verifier is configured out of band for the expected verification policy and matching verification key. The artifact does not carry a circuit-shape identifier, because such an identifier could reveal the composed predicate or its child structure.

## Compilation model

`Proof` objects are lazy recipes. The first release uses a single final compilation boundary:

1. Each credential proof contributes a private witness, credential commitment opening, issuer-signature relation, and claim-specific circuit fragment.
2. `.and()` joins both child relations into one constraint system.
3. `.or()` creates a private boolean selector and gates each child relation. The selected relation must hold; the selector is never a public input.
4. `.prove()` lowers the complete tree to one R1CS circuit and asks `Groth16Prover` for one proof artifact.
5. `ProofArtifact::verify()` passes only the artifact's public inputs to a verifier configured for the expected policy.

This is not recursive proof aggregation. Finalized child proof artifacts are never supplied to `and()` or `or()`. Recursive aggregation may later be added as a separate backend without changing the public `Proof` composition methods.

Every first-release claim fragment must implement an internal gated-constraint contract. This lets `DisjunctionProof` disable the non-selected branch without requiring it to have a valid witness and without publishing which branch was selected.

## Credentials and claims

Credentials may be different objects and come from different issuers. Composition does not require shared raw data, a shared issuer, or a shared credential hash. The common boundary is the selected Groth16 backend and its field representation, not the credential source.

The first release provides a signed attribute credential implementation containing private age and country attributes plus a holder-binding secret. Its issuer signs commitments to the credential attributes and holder binding. Claims consume only the attributes they require:

- `AgeIsAbove(years)` proves hidden age satisfies a public lower bound.
- `AgeIsBelow(years)` proves hidden age satisfies a public upper bound.
- `CountryIsEu` proves hidden country belongs to the library's fixed EU country-code set.
- `RoleIs(role)` proves a hidden signed role equals the requested public role.

The final verification policy selects the public thresholds or roles required by the intended statement. Policy construction is outside the proof artifact and is owned by the verifier.

## Proof backend

`Groth16Prover` and `Groth16Verifier` are the first concrete backend objects. A proving key and verifying key are generated for one verifier-owned policy shape. The verifier keeps the policy and verifying key together; the prover receives compatible proving material through its backend object.

Proof objects do not expose Arkworks types. The backend owns R1CS lowering, key serialization, proof serialization, and verification. `ProofArtifact` exposes a stable library encoding and opaque verification behavior.

All native credential operations and circuit gadgets must agree exactly on domain-separated commitment parameters, canonical encoding, issuer-signature transcript construction, and field mappings. Before the compiler is implemented, native primitives must reject identity issuer keys, use canonical point encodings, prohibit public deterministic holder-secret construction, use injective bounded verifier-scope encoding, and expose an exact circuit-facing signature transcript builder with test vectors.

## Errors

Use data-free typed errors:

- `UnsupportedClaim`
- `InvalidCredential`
- `Unprovable`
- `IncompatibleBackend`
- `InvalidArtifact`
- `VerificationFailed`

No error, debug representation, artifact encoding, or verifier result may include private witness values or opaque child structure.

## README examples

The README must begin with short doctested examples that use only the public object model. One composition example must look substantively like this:

```rust
let eligibility = passport
    .is(Box::new(AgeIsAbove::new(18)))
    .and(residence_card.is(Box::new(CountryIsEu)))
    .or(employee_badge.is(Box::new(RoleIs::staff())));

let artifact = eligibility.prove(&groth16)?;
assert!(artifact.verify(&verifier)?.valid());
```

Additional examples show a single claim, conjunction of proofs from distinct credentials, opaque disjunction, and a custom claim implementation. The README explains that the verifier learns only the root result and that OR does not reveal its satisfying branch.

## Testing

Tests must cover:

- unit behavior for each public claim and credential relation;
- native commitment, issuer signature, canonical encoding, and malformed-input boundaries;
- real Groth16 proof generation and verification for each direct claim;
- `and()` across distinct credentials;
- `or()` with either branch satisfying, with no branch selector, child artifact, credential hash, or claim name in serialized artifacts or verifier results;
- invalid witness, underage, non-EU country, wrong role, tampered credential, and mismatched verifier policy cases;
- public README snippets as doctests; and
- format, strict Clippy, Rustdoc warnings, and the full workspace test suite.

## Acceptance criteria

The first library release is complete when:

1. A user can compose proof objects only through `credential.is(...)`, `.and(...)`, and `.or(...)`.
2. Credentials from different issuers can contribute to one lazy proof tree.
3. `.prove()` produces one real Groth16 artifact for the complete tree.
4. `.verify()` exposes only the root validity result for the verifier's preconfigured policy.
5. Neither artifact serialization nor verifier output reveals child proofs, credentials, witnesses, claims, circuit shape, or an OR branch selector.
6. README examples compile and demonstrate single, AND, OR, and custom claim composition.
7. The project contains no runtime UI/server/localhost application code.
