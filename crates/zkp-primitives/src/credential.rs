use blake2::{Blake2s256, Digest};

use crate::{
    AgeCredential, AgeSalt, BirthDay, Claim, Country, IssuerKeyPair, IssuerPublicKey, Proof, Role,
    WalletSecret, commit_age, commit_owner,
};

/// A holder-controlled credential that can produce a lazy proof recipe.
pub trait Credential: Send + Sync {
    /// Returns the credential's stable public hash.
    fn hash(&self) -> CredentialHash;

    /// Builds a lazy proof that this credential satisfies `claim`.
    fn is(&self, claim: Box<dyn Claim>) -> Proof;
}

/// A stable public hash of a credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialHash([u8; 32]);

impl CredentialHash {
    /// Returns the protocol bytes of this credential hash.
    pub const fn bytes(&self) -> [u8; 32] {
        self.0
    }

    pub(crate) const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Private holder and attribute values that an issuer should certify.
pub struct CredentialAttributes {
    birth_day: BirthDay,
    country: Country,
    role: Role,
    age_salt: AgeSalt,
    wallet_secret: WalletSecret,
}

impl CredentialAttributes {
    /// Stores already validated private attributes for issuance.
    pub fn new(
        birth_day: BirthDay,
        country: Country,
        role: Role,
        age_salt: AgeSalt,
        wallet_secret: WalletSecret,
    ) -> Self {
        Self {
            birth_day,
            country,
            role,
            age_salt,
            wallet_secret,
        }
    }
}

/// An issuer-bound factory for signed holder credentials.
pub struct IssuerCredentials<'issuer> {
    issuer: &'issuer IssuerKeyPair,
}

impl IssuerKeyPair {
    /// Returns a credential issuer bound to this signing key pair.
    pub fn credentials(&self) -> IssuerCredentials<'_> {
        IssuerCredentials { issuer: self }
    }
}

impl IssuerCredentials<'_> {
    /// Issues a credential after binding its private values to issuer-signed commitments.
    pub fn issue(&self, attributes: CredentialAttributes) -> SignedAttributeCredential {
        let age = commit_age(attributes.birth_day.clone(), &attributes.age_salt);
        let owner = commit_owner(&attributes.wallet_secret);
        let credential = self.issuer.issue(age, owner);

        SignedAttributeCredential {
            birth_day: attributes.birth_day,
            country: attributes.country,
            role: attributes.role,
            age_salt: attributes.age_salt,
            wallet_secret: attributes.wallet_secret,
            issuer: self.issuer.public_key(),
            credential,
        }
    }
}

/// A holder-owned credential with issuer-bound commitments and private attributes.
#[derive(Clone)]
pub struct SignedAttributeCredential {
    birth_day: BirthDay,
    country: Country,
    role: Role,
    age_salt: AgeSalt,
    wallet_secret: WalletSecret,
    issuer: IssuerPublicKey,
    credential: AgeCredential,
}

impl SignedAttributeCredential {
    /// Returns the private birth day for crate-internal circuit allocation.
    pub(crate) fn birth_day(&self) -> &BirthDay {
        &self.birth_day
    }

    /// Returns the private country for crate-internal circuit allocation.
    pub(crate) fn country(&self) -> &Country {
        &self.country
    }

    /// Returns the private role for crate-internal circuit allocation.
    pub(crate) const fn role(&self) -> Role {
        self.role
    }

    pub(crate) fn is_valid(&self) -> bool {
        self.credential.verify(&self.issuer).is_ok()
            && self
                .credential
                .age_commitment
                .matches(self.birth_day.clone(), &self.age_salt)
            && self
                .credential
                .owner_commitment
                .matches(&self.wallet_secret)
    }
}

impl Credential for SignedAttributeCredential {
    fn hash(&self) -> CredentialHash {
        let mut hasher = Blake2s256::new();
        hasher.update(self.credential.issuer_key_fingerprint.value());
        hasher.update([self.credential.schema_version]);
        hasher.update(self.credential.signature.prover_response_bytes());
        hasher.update(self.credential.signature.verifier_challenge_bytes());
        CredentialHash::from_bytes(hasher.finalize().into())
    }

    fn is(&self, claim: Box<dyn Claim>) -> Proof {
        crate::proof::Proofs.signed(self.clone(), claim)
    }
}
