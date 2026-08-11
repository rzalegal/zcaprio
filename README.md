# zcaprio

`zcaprio` is a Rust library for teaching credential-bound zero-knowledge proof composition. A holder first receives an issuer-signed credential, then asks that credential to build lazy proof objects. Only `Proof::and`, `Proof::or`, and terminal `prove` compose or execute a proof.

The final Groth16 artifact is opaque. It contains no credential hash, claim name, proof-tree shape, child artifact, witness, predicate, or OR-branch selection. The verifier holds its policy and verifying key out of band.

## Issue first, prove later

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

## Compose credentials without exposing children

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

## Built-in claims

- `AgeIsAbove::new(years)`
- `AgeIsBelow::new(years)`
- `CountryIsEu`
- `RoleIs::new(Role::Staff | Role::Student | Role::Visitor)`

The verifier selects the date in `VerificationPolicy`, so age thresholds are evaluated consistently at proof time.

## What the circuit proves

`Groth16Backend::setup(&proof, policy)` makes a verifier-held template from the opaque proof recipe. That template fixes the issuer keys, requested claims, and composition shape outside the artifact; a later proof must match it.

Inside R1CS, each credential opens its private age, holder, country, and role commitments, recomputes the signed message, and verifies the Baby-JubJub Schnorr relation. The circuit then evaluates the complete `and()` / `or()` tree and requires only its root to be true. The artifact remains a single Groth16 proof with no public inputs, so it discloses neither the template nor an OR branch.

This is educational, unaudited cryptographic software—not production identity infrastructure.
