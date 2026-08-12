# zcaprio

[![CI](https://github.com/rzalegal/zcaprio/actions/workflows/ci.yml/badge.svg)](https://github.com/rzalegal/zcaprio/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/rzalegal/zcaprio/branch/master/graph/badge.svg)](https://app.codecov.io/gh/rzalegal/zcaprio)
[![License: MIT](https://img.shields.io/badge/license-MIT-0f766e.svg)](LICENSE)
[![Rust 2024](https://img.shields.io/badge/rust-2024-edition-7c3aed.svg)](https://doc.rust-lang.org/edition-guide/rust-2024/)

> Compose credential-backed zero-knowledge proofs without composing their disclosures.

`zcaprio` is a small Rust library for exploring credential-bound, composable zero-knowledge proofs. An issuer creates a signed credential; a holder turns it into a lazy proof object; a verifier checks one opaque Groth16 artifact.

| Holder keeps private | Verifier configures | Artifact reveals |
| --- | --- | --- |
| Birth date, country, role, salts, wallet secret | Issuer keys, claims, composition shape, evaluation date | Only that the configured relation is valid |

The artifact contains no credential hash, claim name, proof-tree shape, child artifact, witness, predicate, or OR-branch selection. The verifier keeps its policy and verification key out of band.

## Why it exists

- **Concrete primitives** — issuer-signed credentials, domain-separated commitments, scoped nullifiers, and Groth16 verification.
- **Object-oriented composition** — a credential yields a proof; `Proof::and` and `Proof::or` build the only composition surface.
- **Inspectability without leakage** — source and examples make the relation approachable while the artifact stays opaque.
- **Teaching boundary** — this is experimental, unaudited cryptographic software, deliberately scoped for learning rather than identity production.

## The protocol in one view

```text
Issuer ── signs ──> Credential ── is(claim) ──> Proof ── prove ──> Opaque Groth16 artifact
                                                          │
Verifier ── template + policy ── Groth16Backend::setup ──┘
```

`Groth16Backend::setup` compiles the requested proof into a verifier-held template. The prover supplies private credential openings; the circuit checks commitments, the issuer signature, each claim, and the complete Boolean tree.

## Quick start

Add the current development release from this repository:

```toml
[dependencies]
zcaprio = { git = "https://github.com/rzalegal/zcaprio" }
```

Issue a credential, state a claim, and prove it:

```rust,no_run
use zcaprio::{
    AgeIsAbove, AgeSalt, BirthDay, Country, Credential, CredentialAttributes,
    Groth16Backend, IssuerKeyPair, Role, VerificationPolicy, WalletSecret,
};

let issuer = IssuerKeyPair::generate();
let passport = issuer.credentials().issue(CredentialAttributes::new(
    BirthDay::parse_iso("2000-01-01").expect("date is valid"),
    Country::try_from("DE".to_owned()).expect("country is valid"),
    Role::Student,
    AgeSalt::generate(),
    WalletSecret::generate(),
));
let proof = passport.is(Box::new(AgeIsAbove::new(18)));
let backend = Groth16Backend::setup(&proof, VerificationPolicy::new(
    BirthDay::parse_iso("2026-08-11").expect("date is valid"),
)).expect("backend setup succeeds");
let artifact = proof.prove(backend.prover()).expect("proof succeeds");
assert!(artifact.verify(backend.verifier()).expect("proof verifies").valid());
```

The holder cannot create a `SignedAttributeCredential` directly. It comes from `IssuerKeyPair::credentials().issue(...)`, which creates an issuer signature over the age, holder, country, and role commitments. The country-and-role commitment is blinded with the holder’s private salt, so its public wire value is not a small attribute lookup table. A holder presenting an underage credential cannot produce an 18+ proof through the public API.

## Compose without exposing children

Each direct proof can originate from a different issuer and credential. There is no public `And` or `Or` constructor.

```rust,no_run
use zcaprio::{AgeIsAbove, CountryIsEu, Credential, Role, RoleIs};

# let passport: zcaprio::SignedAttributeCredential = todo!();
# let residence_card: zcaprio::SignedAttributeCredential = todo!();
# let employee_badge: zcaprio::SignedAttributeCredential = todo!();
let eligibility = passport
    .is(Box::new(AgeIsAbove::new(18)))
    .and(residence_card.is(Box::new(CountryIsEu)))
    .or(employee_badge.is(Box::new(RoleIs::new(Role::Staff))));
```

`eligibility` does not provide child accessors. Calling `prove` passes one private composition to the backend. An OR proof does not reveal which side satisfied the relation; verification returns only `Verification::valid()`.

## Built-in claim vocabulary

- `AgeIsAbove::new(years)`
- `AgeIsBelow::new(years)`
- `CountryIsEu`
- `RoleIs::new(Role::Staff | Role::Student | Role::Visitor)`

The verifier selects the date in `VerificationPolicy`, so age thresholds are evaluated consistently at proof time.

## What happens inside the circuit

`Groth16Backend::setup(&proof, policy)` makes a verifier-held template from the opaque proof recipe. That template fixes the issuer keys, requested claims, and composition shape outside the artifact; a later proof must match it.

Inside R1CS, each credential opens its private age, holder, country, and role commitments, recomputes the signed message, and verifies the Baby-JubJub Schnorr relation. The circuit then evaluates the complete `and()` / `or()` tree and requires only its root to be true. The artifact remains a single Groth16 proof with no public inputs, so it discloses neither the template nor an OR branch.

## Development

The project is a library-only Cargo workspace. The CI workflow runs formatting, strict Clippy, documentation checks, the full test suite, and coverage upload on every pull request.

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
cargo test --workspace
```

## Security note

This is educational, unaudited cryptographic software—not production identity infrastructure. Do not use it to make access-control or identity decisions without a complete security review and a protocol suitable for your threat model.

## License

Licensed under the [MIT License](LICENSE).
