//! Credentials signed by the owner's offline key, and proofs of holding the credential's key.
//!
//! A credential binds a holder public key to a role (controller or device), a label, a serial and a validity
//! window. The owner signs it with the issuer key; every verifier carries only the issuer's public key.
//! To use a credential the holder signs a context (for example "this login, this challenge") with its own
//! secret key; the proof is checked against the key inside the credential.
//!
//! Wire layout of a credential (all integers big-endian):
//! `version(1)=1 | role(1) | serial(8) | not_before(8) | not_after(8) | holder_pk(32) | label_len(1) | label | signature(64)`
//! where the signature covers every preceding byte under the domain `handover-cred-v1`.

use sodiumoxide::crypto::sign::ed25519::{self, PublicKey, SecretKey, Seed};
use std::fmt;

pub use sodiumoxide::crypto::sign::ed25519::{PublicKey as IssuerPublicKey, SecretKey as IssuerSecretKey};

const VERSION: u8 = 1;
const CRED_DOMAIN: &[u8] = b"handover-cred-v1\0";
const PROOF_DOMAIN: &[u8] = b"handover-proof-v1\0";
const FIXED_LEN: usize = 1 + 1 + 8 + 8 + 8 + 32 + 1;
const SIG_LEN: usize = 64;
pub const MAX_LABEL_LEN: usize = 64;
pub const MAX_CREDENTIAL_LEN: usize = FIXED_LEN + MAX_LABEL_LEN + SIG_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Role {
    Controller = 1,
    Device = 2,
}

impl Role {
    fn from_u8(v: u8) -> Option<Role> {
        match v {
            1 => Some(Role::Controller),
            2 => Some(Role::Device),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Role::Controller => "controller",
            Role::Device => "device",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Malformed,
    BadSignature,
    NotYetValid,
    Expired,
    WrongRole,
    BadLabel,
    BadProof,
    BadFile,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::Malformed => "malformed credential",
            Error::BadSignature => "credential not signed by the trusted issuer",
            Error::NotYetValid => "credential not valid yet",
            Error::Expired => "credential expired",
            Error::WrongRole => "credential has the wrong role",
            Error::BadLabel => "label must be 1-64 printable ASCII characters",
            Error::BadProof => "proof of key possession failed",
            Error::BadFile => "unreadable credential file",
        })
    }
}

impl std::error::Error for Error {}

/// A credential whose issuer signature has been verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    pub role: Role,
    pub serial: u64,
    pub not_before: u64,
    pub not_after: u64,
    pub holder: [u8; 32],
    pub label: String,
}

fn label_ok(label: &str) -> bool {
    !label.is_empty() && label.len() <= MAX_LABEL_LEN && label.bytes().all(|b| (0x20..0x7f).contains(&b))
}

fn body(role: Role, serial: u64, not_before: u64, not_after: u64, holder: &[u8; 32], label: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(FIXED_LEN + label.len() + SIG_LEN);
    v.push(VERSION);
    v.push(role as u8);
    v.extend_from_slice(&serial.to_be_bytes());
    v.extend_from_slice(&not_before.to_be_bytes());
    v.extend_from_slice(&not_after.to_be_bytes());
    v.extend_from_slice(holder);
    v.push(label.len() as u8);
    v.extend_from_slice(label.as_bytes());
    v
}

fn signed_message(body: &[u8]) -> Vec<u8> {
    let mut m = CRED_DOMAIN.to_vec();
    m.extend_from_slice(body);
    m
}

/// Sign a credential for `holder` with the issuer secret key.
pub fn issue(
    issuer: &SecretKey,
    role: Role,
    label: &str,
    serial: u64,
    not_before: u64,
    not_after: u64,
    holder: &PublicKey,
) -> Result<Vec<u8>, Error> {
    if !label_ok(label) {
        return Err(Error::BadLabel);
    }
    let mut v = body(role, serial, not_before, not_after, &holder.0, label);
    let sig = ed25519::sign_detached(&signed_message(&v), issuer);
    v.extend_from_slice(&sig.to_bytes());
    Ok(v)
}

/// Parse a credential and verify the issuer's signature and the validity window at `now` (unix seconds).
pub fn verify(bytes: &[u8], issuer: &PublicKey, now: u64) -> Result<Credential, Error> {
    verify_with_leeway(bytes, issuer, now, 0)
}

/// Like [`verify`], but tolerates a verifier clock that is off by up to `leeway` seconds.
pub fn verify_with_leeway(bytes: &[u8], issuer: &PublicKey, now: u64, leeway: u64) -> Result<Credential, Error> {
    if bytes.len() < FIXED_LEN + SIG_LEN || bytes.len() > MAX_CREDENTIAL_LEN || bytes[0] != VERSION {
        return Err(Error::Malformed);
    }
    let role = Role::from_u8(bytes[1]).ok_or(Error::Malformed)?;
    let serial = u64::from_be_bytes(bytes[2..10].try_into().map_err(|_| Error::Malformed)?);
    let not_before = u64::from_be_bytes(bytes[10..18].try_into().map_err(|_| Error::Malformed)?);
    let not_after = u64::from_be_bytes(bytes[18..26].try_into().map_err(|_| Error::Malformed)?);
    let mut holder = [0u8; 32];
    holder.copy_from_slice(&bytes[26..58]);
    let label_len = bytes[58] as usize;
    if bytes.len() != FIXED_LEN + label_len + SIG_LEN {
        return Err(Error::Malformed);
    }
    let label = std::str::from_utf8(&bytes[FIXED_LEN..FIXED_LEN + label_len]).map_err(|_| Error::Malformed)?;
    if !label_ok(label) {
        return Err(Error::Malformed);
    }
    let split = FIXED_LEN + label_len;
    let sig = ed25519::Signature::from_bytes(&bytes[split..]).map_err(|_| Error::Malformed)?;
    if !ed25519::verify_detached(&sig, &signed_message(&bytes[..split]), issuer) {
        return Err(Error::BadSignature);
    }
    if now.saturating_add(leeway) < not_before {
        return Err(Error::NotYetValid);
    }
    if now > not_after.saturating_add(leeway) {
        return Err(Error::Expired);
    }
    Ok(Credential { role, serial, not_before, not_after, holder, label: label.to_owned() })
}

impl Credential {
    pub fn expect_role(&self, role: Role) -> Result<(), Error> {
        if self.role == role {
            Ok(())
        } else {
            Err(Error::WrongRole)
        }
    }
}

fn proof_message(domain: &str, context: &[u8]) -> Vec<u8> {
    let mut m = PROOF_DOMAIN.to_vec();
    m.extend_from_slice(domain.as_bytes());
    m.push(0);
    m.extend_from_slice(context);
    m
}

/// Sign `context` (a statement about this one use) with the holder's secret key.
pub fn prove(holder: &SecretKey, domain: &str, context: &[u8]) -> Vec<u8> {
    ed25519::sign_detached(&proof_message(domain, context), holder).to_bytes().to_vec()
}

/// Check a proof against the key inside a verified credential.
pub fn check_proof(cred: &Credential, domain: &str, context: &[u8], proof: &[u8]) -> Result<(), Error> {
    let sig = ed25519::Signature::from_bytes(proof).map_err(|_| Error::BadProof)?;
    if ed25519::verify_detached(&sig, &proof_message(domain, context), &PublicKey(cred.holder)) {
        Ok(())
    } else {
        Err(Error::BadProof)
    }
}

/// A holder's file: the credential and the secret seed of its key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HolderFile {
    pub credential: Vec<u8>,
    pub seed: [u8; 32],
}

impl HolderFile {
    pub fn to_text(&self) -> String {
        use base64::{engine::general_purpose::STANDARD, Engine};
        format!(
            "# Handover credential. SECRET: keep this file private (mode 0600) and never commit it.\ncredential={}\nsecret={}\n",
            STANDARD.encode(&self.credential),
            STANDARD.encode(self.seed)
        )
    }

    pub fn from_text(text: &str) -> Result<HolderFile, Error> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let (mut cred, mut seed) = (None, None);
        for line in text.lines() {
            let line = line.trim();
            if let Some(v) = line.strip_prefix("credential=") {
                cred = STANDARD.decode(v.trim()).ok();
            } else if let Some(v) = line.strip_prefix("secret=") {
                seed = STANDARD.decode(v.trim()).ok();
            }
        }
        let credential = cred.ok_or(Error::BadFile)?;
        let seed: [u8; 32] = seed.ok_or(Error::BadFile)?.try_into().map_err(|_| Error::BadFile)?;
        if credential.len() > MAX_CREDENTIAL_LEN {
            return Err(Error::BadFile);
        }
        Ok(HolderFile { credential, seed })
    }

    pub fn secret_key(&self) -> SecretKey {
        ed25519::keypair_from_seed(&Seed(self.seed)).1
    }
}

/// Generate a fresh holder key pair (secret as seed, public key).
pub fn new_holder() -> ([u8; 32], PublicKey) {
    let _ = sodiumoxide::init();
    let (pk, sk) = ed25519::gen_keypair();
    let seed = sk.0[..32].try_into().expect("an ed25519 secret key starts with its 32-byte seed");
    (seed, pk)
}

/// Generate the issuer key pair.
pub fn new_issuer() -> (PublicKey, SecretKey) {
    let _ = sodiumoxide::init();
    ed25519::gen_keypair()
}

/// Public key of a holder given its seed.
pub fn holder_public_key(seed: &[u8; 32]) -> PublicKey {
    ed25519::keypair_from_seed(&Seed(*seed)).0
}

/// Base64 of an issuer public key, as baked into builds and server configuration.
pub fn encode_public_key(pk: &PublicKey) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.encode(pk.0)
}

pub fn decode_public_key(text: &str) -> Option<PublicKey> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let v = STANDARD.decode(text.trim()).ok()?;
    PublicKey::from_slice(&v)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn sample() -> (PublicKey, SecretKey, [u8; 32], Vec<u8>) {
        let (ipk, isk) = new_issuer();
        let (seed, hpk) = new_holder();
        let cred = issue(&isk, Role::Controller, "my laptop", 42, NOW - 10, NOW + 1000, &hpk).unwrap();
        (ipk, isk, seed, cred)
    }

    #[test]
    fn a_credential_from_the_trusted_issuer_verifies() {
        let (ipk, _, seed, cred) = sample();
        let c = verify(&cred, &ipk, NOW).unwrap();
        assert_eq!((c.role, c.serial, c.label.as_str()), (Role::Controller, 42, "my laptop"));
        assert_eq!(c.holder, holder_public_key(&seed).0);
    }

    #[test]
    fn a_credential_signed_by_another_issuer_is_refused() {
        let (_, _, _, cred) = sample();
        let (other, _) = new_issuer();
        assert_eq!(verify(&cred, &other, NOW), Err(Error::BadSignature));
    }

    #[test]
    fn expired_and_not_yet_valid_credentials_are_refused() {
        let (ipk, _, _, cred) = sample();
        assert_eq!(verify(&cred, &ipk, NOW + 1001), Err(Error::Expired));
        assert_eq!(verify(&cred, &ipk, NOW - 11), Err(Error::NotYetValid));
        assert!(verify(&cred, &ipk, NOW + 1000).is_ok());
    }

    #[test]
    fn leeway_tolerates_a_skewed_clock_but_not_a_stale_credential() {
        let (ipk, _, _, cred) = sample();
        assert!(verify_with_leeway(&cred, &ipk, NOW + 1000 + 86_400, 86_400).is_ok());
        assert_eq!(verify_with_leeway(&cred, &ipk, NOW + 1001 + 86_400, 86_400), Err(Error::Expired));
        assert!(verify_with_leeway(&cred, &ipk, NOW - 10 - 86_400, 86_400).is_ok());
        assert_eq!(verify_with_leeway(&cred, &ipk, NOW - 11 - 86_400, 86_400), Err(Error::NotYetValid));
    }

    #[test]
    fn changing_any_single_byte_breaks_the_credential() {
        let (ipk, _, _, cred) = sample();
        for i in 0..cred.len() {
            let mut t = cred.clone();
            t[i] ^= 0x01;
            assert!(verify(&t, &ipk, NOW).is_err(), "byte {i} could be changed");
        }
    }

    #[test]
    fn truncated_and_oversized_input_is_refused() {
        let (ipk, _, _, cred) = sample();
        for n in 0..cred.len() {
            assert!(verify(&cred[..n], &ipk, NOW).is_err());
        }
        let mut long = cred.clone();
        long.extend_from_slice(&[0u8; 200]);
        assert_eq!(verify(&long, &ipk, NOW), Err(Error::Malformed));
        assert_eq!(verify(&[], &ipk, NOW), Err(Error::Malformed));
    }

    #[test]
    fn labels_must_be_short_printable_ascii() {
        let (_, isk) = new_issuer();
        let (_, hpk) = new_holder();
        for bad in ["", "tab\there", "naïve", &"x".repeat(65)] {
            assert_eq!(issue(&isk, Role::Device, bad, 1, 0, 10, &hpk), Err(Error::BadLabel));
        }
    }

    #[test]
    fn the_role_is_checked_by_the_caller() {
        let (ipk, _, _, cred) = sample();
        let c = verify(&cred, &ipk, NOW).unwrap();
        assert!(c.expect_role(Role::Controller).is_ok());
        assert_eq!(c.expect_role(Role::Device), Err(Error::WrongRole));
    }

    #[test]
    fn a_proof_is_bound_to_its_context_domain_and_key() {
        let (ipk, _, seed, cred) = sample();
        let c = verify(&cred, &ipk, NOW).unwrap();
        let sk = HolderFile { credential: cred, seed }.secret_key();
        let proof = prove(&sk, "login", b"challenge-1");
        assert!(check_proof(&c, "login", b"challenge-1", &proof).is_ok());
        assert_eq!(check_proof(&c, "login", b"challenge-2", &proof), Err(Error::BadProof));
        assert_eq!(check_proof(&c, "relay", b"challenge-1", &proof), Err(Error::BadProof));
        let (other_seed, _) = new_holder();
        let other = HolderFile { credential: vec![], seed: other_seed }.secret_key();
        assert_eq!(check_proof(&c, "login", b"challenge-1", &prove(&other, "login", b"challenge-1")), Err(Error::BadProof));
        assert_eq!(check_proof(&c, "login", b"challenge-1", &proof[..63]), Err(Error::BadProof));
    }

    #[test]
    fn a_holder_file_round_trips_and_rejects_garbage() {
        let (_, _, seed, cred) = sample();
        let f = HolderFile { credential: cred, seed };
        assert_eq!(HolderFile::from_text(&f.to_text()).unwrap(), f);
        assert_eq!(HolderFile::from_text("nothing here"), Err(Error::BadFile));
        assert_eq!(HolderFile::from_text("credential=AAAA\nsecret=AAAA"), Err(Error::BadFile));
    }
}
