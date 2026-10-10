//! Handover: only controllers holding a credential signed by the owner's issuer may log in.
//!
//! The controller attaches its credential and a proof (a signature over this connection's login context)
//! to the login request; the controlled side checks both against the issuer public key baked into the
//! build (`CONTROLLER_CA`). Nothing here trusts the rendezvous or relay server.

use base::message_proto::{Hash, LoginRequest};
use handover_cred::{self as cred, Credential, Error, HolderFile, IssuerPublicKey, Role};
use hbb_common::{
    config::{Config, CONTROLLER_CA},
    log,
};
use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

const PROOF_DOMAIN: &str = "login";
/// A controlled machine's clock may be off; a credential is accepted up to a day outside its window.
const CLOCK_LEEWAY: u64 = 86_400;

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// What the controller signs: the id it is connecting to and the two values the controlled side
/// chose for this very connection, so a captured proof is useless on any other connection.
fn login_context(controlled_id: &str, hash: &Hash) -> Vec<u8> {
    format!("{}\n{}\n{}", controlled_id, hash.salt, hash.challenge).into_bytes()
}

pub fn credential_path() -> PathBuf {
    Config::path("controller.cred")
}

/// Controller side: add the credential and the proof for this connection to the login request.
pub fn attach(lr: &mut LoginRequest, hash: &Hash) {
    let path = credential_path();
    let Ok(text) = std::fs::read_to_string(&path) else {
        log::info!("no controller credential at {}", path.display());
        return;
    };
    let Ok(file) = HolderFile::from_text(&text) else {
        log::warn!("the controller credential at {} is unreadable", path.display());
        return;
    };
    let proof = cred::prove(&file.secret_key(), PROOF_DOMAIN, &login_context(&lr.username, hash));
    lr.controller_cred = file.credential.into();
    lr.controller_proof = proof.into();
}

fn verify_login_with(
    issuer: &IssuerPublicKey,
    lr: &LoginRequest,
    controlled_id: &str,
    hash: &Hash,
    now: u64,
) -> Result<Credential, Error> {
    let c = cred::verify_with_leeway(&lr.controller_cred, issuer, now, CLOCK_LEEWAY)?;
    c.expect_role(Role::Controller)?;
    cred::check_proof(&c, PROOF_DOMAIN, &login_context(controlled_id, hash), &lr.controller_proof)?;
    Ok(c)
}

/// Controlled side: is this login from a controller the owner signed? With no issuer key baked in, nobody is.
pub fn verify_login(lr: &LoginRequest, controlled_id: &str, hash: &Hash) -> Result<Credential, Error> {
    let issuer = cred::decode_public_key(CONTROLLER_CA).ok_or(Error::BadSignature)?;
    verify_login_with(&issuer, lr, controlled_id, hash, now_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use handover_cred::{issue, new_holder, new_issuer};

    struct Setup {
        issuer: IssuerPublicKey,
        hash: Hash,
        lr: LoginRequest,
    }

    fn controller(role: Role, valid_for: u64) -> (IssuerPublicKey, handover_cred::IssuerSecretKey, HolderFile) {
        let (ipk, isk) = new_issuer();
        let (seed, hpk) = new_holder();
        let now = now_secs();
        let credential = issue(&isk, role, "test", 7, now - 60, now + valid_for, &hpk).unwrap();
        (ipk, isk, HolderFile { credential, seed })
    }

    fn login(file: &HolderFile, id: &str, hash: &Hash) -> LoginRequest {
        let mut lr = LoginRequest { username: id.to_owned(), ..Default::default() };
        let proof = cred::prove(&file.secret_key(), PROOF_DOMAIN, &login_context(id, hash));
        lr.controller_cred = file.credential.clone().into();
        lr.controller_proof = proof.into();
        lr
    }

    fn setup(role: Role) -> Setup {
        let (issuer, _, file) = controller(role, 1000);
        let hash = Hash { salt: "salt".into(), challenge: "challenge-1".into(), ..Default::default() };
        let lr = login(&file, "123456789", &hash);
        Setup { issuer, hash, lr }
    }

    #[test]
    fn a_signed_controller_is_accepted_for_the_connection_it_signed() {
        let s = setup(Role::Controller);
        assert!(verify_login_with(&s.issuer, &s.lr, "123456789", &s.hash, now_secs()).is_ok());
    }

    #[test]
    fn a_login_without_a_credential_is_refused() {
        let s = setup(Role::Controller);
        let bare = LoginRequest { username: "123456789".into(), ..Default::default() };
        assert!(verify_login_with(&s.issuer, &bare, "123456789", &s.hash, now_secs()).is_err());
    }

    #[test]
    fn a_proof_does_not_work_on_another_connection_or_another_machine() {
        let s = setup(Role::Controller);
        let other_conn = Hash { challenge: "challenge-2".into(), ..s.hash.clone() };
        assert_eq!(verify_login_with(&s.issuer, &s.lr, "123456789", &other_conn, now_secs()), Err(Error::BadProof));
        assert_eq!(verify_login_with(&s.issuer, &s.lr, "987654321", &s.hash, now_secs()), Err(Error::BadProof));
    }

    #[test]
    fn a_credential_from_another_issuer_is_refused() {
        let s = setup(Role::Controller);
        let (other, _) = new_issuer();
        assert!(verify_login_with(&other, &s.lr, "123456789", &s.hash, now_secs()).is_err());
    }

    #[test]
    fn a_device_credential_cannot_log_in_as_a_controller() {
        let s = setup(Role::Device);
        assert_eq!(verify_login_with(&s.issuer, &s.lr, "123456789", &s.hash, now_secs()), Err(Error::WrongRole));
    }

    #[test]
    fn an_expired_credential_is_refused_beyond_the_clock_leeway() {
        let s = setup(Role::Controller);
        assert!(verify_login_with(&s.issuer, &s.lr, "123456789", &s.hash, now_secs() + 1000 + CLOCK_LEEWAY + 5).is_err());
    }

    #[test]
    fn someone_holding_a_valid_credential_but_not_its_key_is_refused() {
        let s = setup(Role::Controller);
        let (other_seed, _) = new_holder();
        let thief = HolderFile { credential: s.lr.controller_cred.to_vec(), seed: other_seed };
        let lr = login(&thief, "123456789", &s.hash);
        assert_eq!(verify_login_with(&s.issuer, &lr, "123456789", &s.hash, now_secs()), Err(Error::BadProof));
    }

    #[test]
    fn with_no_issuer_key_baked_in_nobody_is_trusted() {
        // the unit-test build has no HANDOVER_CONTROLLER_CA unless the environment sets one
        if CONTROLLER_CA.is_empty() {
            let s = setup(Role::Controller);
            assert!(verify_login(&s.lr, "123456789", &s.hash).is_err());
        }
    }
}
