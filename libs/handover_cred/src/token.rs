//! Tokens for rendezvous and relay servers: a credential plus a proof bound to one message.
//!
//! A token is the text `hc1.<credential>.<proof>.<unix seconds>.<nonce>` (base64 parts). The proof is a
//! signature over `kind`, the message-specific `context`, the timestamp and the nonce, so a token made for
//! one message type or one subject (an id, a relay uuid) is useless for anything else. A server accepts a
//! token once, within a short window, from an unrevoked credential of an allowed role.

use super::{check_proof, prove, verify_with_leeway, Credential, Error, HolderFile, IssuerPublicKey, Role};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const PREFIX: &str = "hc1";
/// How far a token's timestamp may be from the verifier's clock.
pub const WINDOW_SECS: u64 = 120;
const CLOCK_LEEWAY: u64 = 86_400;
const MAX_SEEN: usize = 200_000;
const MAX_TOKEN_LEN: usize = 512;
const REVOKED_RECHECK: Duration = Duration::from_secs(5);

fn domain(kind: &str) -> String {
    format!("token:{kind}")
}

fn full_context(context: &str, ts: u64, nonce: &str) -> Vec<u8> {
    format!("{context}\n{ts}\n{nonce}").into_bytes()
}

/// Base64 (standard alphabet, padded) of raw bytes, for building token contexts on both ends.
pub fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Make a token for one message of type `kind` about `context` (an id, a uuid, a digest ...).
pub fn make(holder: &HolderFile, kind: &str, context: &str, now: u64) -> String {
    let nonce = STANDARD.encode(sodiumoxide::randombytes::randombytes(8));
    let proof = prove(&holder.secret_key(), &domain(kind), &full_context(context, now, &nonce));
    format!("{PREFIX}.{}.{}.{}.{}", STANDARD.encode(&holder.credential), STANDARD.encode(proof), now, nonce)
}

struct Parts {
    credential: Vec<u8>,
    proof: Vec<u8>,
    ts: u64,
    nonce: String,
}

fn parse(token: &str) -> Result<Parts, Error> {
    if token.len() > MAX_TOKEN_LEN {
        return Err(Error::BadToken);
    }
    let mut it = token.split('.');
    if it.next() != Some(PREFIX) {
        return Err(Error::BadToken);
    }
    let (c, p, t, n) = (it.next(), it.next(), it.next(), it.next());
    if it.next().is_some() {
        return Err(Error::BadToken);
    }
    let (c, p, t, n) = (c.ok_or(Error::BadToken)?, p.ok_or(Error::BadToken)?, t.ok_or(Error::BadToken)?, n.ok_or(Error::BadToken)?);
    Ok(Parts {
        credential: STANDARD.decode(c).map_err(|_| Error::BadToken)?,
        proof: STANDARD.decode(p).map_err(|_| Error::BadToken)?,
        ts: t.parse().map_err(|_| Error::BadToken)?,
        nonce: n.to_owned(),
    })
}

/// Stateless part: credential, role, timestamp window and proof. Revocation and replay are the [`Gate`]'s job.
pub fn verify_stateless(
    token: &str,
    kind: &str,
    context: &str,
    issuer: &IssuerPublicKey,
    roles: &[Role],
    now: u64,
) -> Result<(Credential, [u8; 16]), Error> {
    let p = parse(token)?;
    let cred = verify_with_leeway(&p.credential, issuer, now, CLOCK_LEEWAY)?;
    if !roles.contains(&cred.role) {
        return Err(Error::WrongRole);
    }
    if p.ts.abs_diff(now) > WINDOW_SECS {
        return Err(Error::StaleToken);
    }
    check_proof(&cred, &domain(kind), &full_context(context, p.ts, &p.nonce), &p.proof)?;
    let mut id = [0u8; 16];
    id.copy_from_slice(&p.proof[..16]);
    Ok((cred, id))
}

/// A server's admission check: the issuer's public key, a revocation list file and a replay cache.
pub struct Gate {
    issuer: IssuerPublicKey,
    revoked_path: Option<PathBuf>,
    revoked: Mutex<Revoked>,
    seen: Mutex<HashMap<[u8; 16], u64>>,
}

struct Revoked {
    checked: Option<Instant>,
    modified: Option<SystemTime>,
    serials: HashSet<u64>,
}

impl Gate {
    pub fn new(issuer: IssuerPublicKey, revoked_path: Option<PathBuf>) -> Gate {
        Gate {
            issuer,
            revoked_path,
            revoked: Mutex::new(Revoked { checked: None, modified: None, serials: HashSet::new() }),
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Build the gate from `HANDOVER_CA_PUB` (base64) and the optional `HANDOVER_REVOKED` file path.
    /// A server without an issuer key must not start (fail closed).
    pub fn from_env() -> Result<Gate, String> {
        let text = std::env::var("HANDOVER_CA_PUB").map_err(|_| "HANDOVER_CA_PUB is not set".to_owned())?;
        let issuer = super::decode_public_key(&text).ok_or_else(|| "HANDOVER_CA_PUB is not a public key".to_owned())?;
        Ok(Gate::new(issuer, std::env::var("HANDOVER_REVOKED").ok().filter(|p| !p.is_empty()).map(PathBuf::from)))
    }

    fn is_revoked(&self, serial: u64) -> bool {
        let Some(path) = &self.revoked_path else { return false };
        let mut r = self.revoked.lock().unwrap_or_else(|e| e.into_inner());
        if r.checked.map(|t| t.elapsed() >= REVOKED_RECHECK).unwrap_or(true) {
            r.checked = Some(Instant::now());
            match std::fs::metadata(path).and_then(|m| m.modified()) {
                Ok(modified) => {
                    if r.modified != Some(modified) {
                        r.modified = Some(modified);
                        r.serials = std::fs::read_to_string(path)
                            .unwrap_or_default()
                            .lines()
                            .filter_map(|l| l.split('#').next().and_then(|v| v.trim().parse::<u64>().ok()))
                            .collect();
                    }
                }
                // an unreadable list is treated as empty; a missing file means nothing is revoked
                Err(_) => r.serials.clear(),
            }
        }
        r.serials.contains(&serial)
    }

    pub fn check(&self, token: &str, kind: &str, context: &str, roles: &[Role]) -> Result<Credential, Error> {
        self.check_at(token, kind, context, roles, now_secs())
    }

    pub fn check_at(&self, token: &str, kind: &str, context: &str, roles: &[Role], now: u64) -> Result<Credential, Error> {
        let (cred, id) = verify_stateless(token, kind, context, &self.issuer, roles, now)?;
        if self.is_revoked(cred.serial) {
            return Err(Error::Revoked);
        }
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        if seen.len() >= MAX_SEEN || seen.len() > 1000 && seen.len() % 1000 == 0 {
            seen.retain(|_, until| *until > now);
        }
        if seen.len() >= MAX_SEEN {
            return Err(Error::Replayed);
        }
        if seen.insert(id, now + 2 * WINDOW_SECS + 5).is_some() {
            return Err(Error::Replayed);
        }
        Ok(cred)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{issue, new_holder, new_issuer};

    const NOW: u64 = 1_800_000_000;

    fn holder(role: Role) -> (IssuerPublicKey, HolderFile) {
        let (ipk, isk) = new_issuer();
        let (seed, hpk) = new_holder();
        let credential = issue(&isk, role, "t", 5, NOW - 100, NOW + 100_000, &hpk).unwrap();
        (ipk, HolderFile { credential, seed })
    }

    #[test]
    fn a_fresh_token_for_the_right_subject_is_accepted_once() {
        let (ipk, h) = holder(Role::Device);
        let gate = Gate::new(ipk, None);
        let t = make(&h, "register", "123456789", NOW);
        assert_eq!(gate.check_at(&t, "register", "123456789", &[Role::Device], NOW).unwrap().serial, 5);
        assert_eq!(gate.check_at(&t, "register", "123456789", &[Role::Device], NOW), Err(Error::Replayed));
    }

    #[test]
    fn a_token_is_bound_to_its_kind_subject_and_roles() {
        let (ipk, h) = holder(Role::Device);
        let gate = Gate::new(ipk, None);
        let t = make(&h, "register", "123456789", NOW);
        assert_eq!(gate.check_at(&t, "relay", "123456789", &[Role::Device], NOW), Err(Error::BadProof));
        assert_eq!(gate.check_at(&t, "register", "987654321", &[Role::Device], NOW), Err(Error::BadProof));
        assert_eq!(gate.check_at(&t, "register", "123456789", &[Role::Controller], NOW), Err(Error::WrongRole));
    }

    #[test]
    fn stale_and_future_tokens_are_refused() {
        let (ipk, h) = holder(Role::Device);
        let gate = Gate::new(ipk, None);
        let t = make(&h, "register", "x", NOW);
        assert_eq!(gate.check_at(&t, "register", "x", &[Role::Device], NOW + WINDOW_SECS + 1), Err(Error::StaleToken));
        let t2 = make(&h, "register", "x", NOW + 3 * WINDOW_SECS);
        assert_eq!(gate.check_at(&t2, "register", "x", &[Role::Device], NOW), Err(Error::StaleToken));
        let t3 = make(&h, "register", "x", NOW);
        assert!(gate.check_at(&t3, "register", "x", &[Role::Device], NOW + WINDOW_SECS).is_ok());
    }

    #[test]
    fn a_credential_from_another_issuer_or_with_a_forged_proof_is_refused() {
        let (ipk, h) = holder(Role::Device);
        let (other_ipk, other_h) = holder(Role::Device);
        let gate = Gate::new(ipk, None);
        let foreign = make(&other_h, "register", "x", NOW);
        assert_eq!(gate.check_at(&foreign, "register", "x", &[Role::Device], NOW), Err(Error::BadSignature));
        // the right credential with a proof made by somebody else's key
        let stolen = HolderFile { credential: h.credential.clone(), seed: other_h.seed };
        let t = make(&stolen, "register", "x", NOW);
        assert_eq!(gate.check_at(&t, "register", "x", &[Role::Device], NOW), Err(Error::BadProof));
        let _ = other_ipk;
    }

    #[test]
    fn malformed_tokens_are_refused_without_panicking() {
        let (ipk, _) = holder(Role::Device);
        let gate = Gate::new(ipk, None);
        for t in ["", "hc1", "hc1....", "hc2.a.b.1.n", "hc1.!!.!!.1.n", "hc1.AA.AA.notanumber.n", &"x".repeat(2000)] {
            assert!(gate.check_at(t, "register", "x", &[Role::Device], NOW).is_err(), "{t:?}");
        }
    }

    #[test]
    fn a_revoked_serial_is_refused_and_the_list_is_reread() {
        let (ipk, h) = holder(Role::Device);
        let dir = std::env::temp_dir().join(format!("handover-revoked-{}", std::process::id()));
        std::fs::write(&dir, "# revoked\n99\n").unwrap();
        let gate = Gate::new(ipk, Some(dir.clone()));
        let t = make(&h, "register", "x", NOW);
        assert!(gate.check_at(&t, "register", "x", &[Role::Device], NOW).is_ok());
        std::fs::write(&dir, "99\n5 # this one\n").unwrap();
        gate.revoked.lock().unwrap().checked = None;
        gate.revoked.lock().unwrap().modified = None;
        let t2 = make(&h, "register", "x", NOW);
        assert_eq!(gate.check_at(&t2, "register", "x", &[Role::Device], NOW), Err(Error::Revoked));
        std::fs::remove_file(dir).ok();
    }
}
