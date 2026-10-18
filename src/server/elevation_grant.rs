//! The service's record of administrator-access requests and grants (`docs/ELEVATION_SPEC.md` 4.4, S2, S3;
//! stories E7, E8). Pure state: the service loop (`platform/windows.rs::run_service`) authorises the caller and
//! passes the facts about it in. One request or grant at a time per machine (spec section 5).
#![cfg_attr(not(windows), allow(dead_code))]

use serde_derive::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Hard upper bound for a request in the service: the person's decision (60 s) plus the UAC prompt (120 s).
pub const REQUEST_TTL: Duration = Duration::from_secs(180);

/// Time limit of a grant (spec F6): `HANDOVER_ELEVATION_MINUTES` at build time, 30 minutes by default.
pub fn grant_minutes() -> u64 {
    option_env!("HANDOVER_ELEVATION_MINUTES")
        .and_then(|m| m.parse().ok())
        .filter(|m| (1..=480).contains(m))
        .unwrap_or(30)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServiceRequest {
    /// From the user-level server: a controller asks for administrator access; the reply is `Created(nonce)`.
    Create { conn_id: i32, serial: u64 },
    /// From the user-level server: the request ended (denied, expired, connection closed).
    Cancel { nonce: String },
    /// From `--elevation-proof`, started through the UAC prompt; `keep`: the person ticked "keep connected" (E10).
    Proof { nonce: String, keep: bool },
    /// From the user-level server: is the request still waiting, granted, or gone?
    Poll { nonce: String },
    /// From the user-level server: the grant ends (drop, local stop, time limit, connection closed). `keep_resume`:
    /// a resume grant of it survives (the connection closed; it did not end by a decision).
    End { nonce: String, keep_resume: bool },
    /// From a server of this machine: a controller reconnects with a resume token (E10); `challenge` is the one this
    /// connection's login was made over, `peer_id` the controller's ID.
    ResumeCheck { id: Vec<u8>, mac: Vec<u8>, challenge: String, peer_id: String, serial: u64 },
    /// From the user-level server: start the privileged helper (E9) for this grant on its shared memory.
    StartHelper { nonce: String, shmem_name: String },
    /// From the user-level server (APPROVAL_SPEC.md): is an administrator signed in at this session and would the UAC prompt mean
    /// something? `Done`, or `Denied(<`Refusal::log_word`>)`.
    ApprovalCheck,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ServiceReply {
    Created(String),
    Done,
    Denied(String),
    Waiting,
    /// `resume`: the resume grant's id and secret (16 + 32 bytes), handed over once (E10).
    Granted { secs_left: u64, account: String, resume: Vec<u8> },
    Gone(String),
}

/// Time limit of a resume grant (spec S7).
pub const RESUME_TTL: Duration = Duration::from_secs(15 * 60);
const RESUME_ID_LEN: usize = 16;
const RESUME_SECRET_LEN: usize = 32;

/// The controller's proof of a resume secret for one login: an HMAC over the connection's fresh challenge and the
/// controller's ID, so a captured token is worthless for any other connection.
pub fn resume_mac(secret: &[u8], challenge: &str, peer_id: &str) -> Option<Vec<u8>> {
    use hbb_common::sodiumoxide::crypto::auth::hmacsha256;
    let key = hmacsha256::Key::from_slice(secret)?;
    let mut message = b"handover-resume\0".to_vec();
    message.extend_from_slice(challenge.as_bytes());
    message.push(0);
    message.extend_from_slice(peer_id.as_bytes());
    Some(hmacsha256::authenticate(&message, &key).as_ref().to_vec())
}

/// The token a controller sends: the grant's id and the MAC; `blob` is what `Granted.resume` handed over.
pub fn resume_token(blob: &[u8], challenge: &str, peer_id: &str) -> Option<Vec<u8>> {
    if blob.len() != RESUME_ID_LEN + RESUME_SECRET_LEN {
        return None;
    }
    let (id, secret) = blob.split_at(RESUME_ID_LEN);
    let mut token = id.to_vec();
    token.extend(resume_mac(secret, challenge, peer_id)?);
    Some(token)
}

/// What the service found out about the process that sent a proof.
#[derive(Debug, Clone)]
pub struct ProofFacts {
    pub session_id: u32,
    /// Its token is elevated (`TokenElevation`): it came through the UAC prompt.
    pub elevated: bool,
    /// The account that approved the UAC prompt (the elevated token's user).
    pub account: String,
    /// "Keep connected" was ticked, and the SID of the user signed in to the request's session (E10).
    pub keep: bool,
    pub session_user_sid: Option<String>,
}

/// "Keep connected" (spec F7, S7): lets the same controller back in without a click after sign-out, for a while,
/// as long as nobody else signs in.
#[derive(Debug)]
struct ResumeGrant {
    id: Vec<u8>,
    secret: Vec<u8>,
    grant_nonce: String,
    serial: u64,
    user_sid: String,
    until: Instant,
    delivered: bool,
}

#[derive(Debug)]
struct Pending {
    nonce: String,
    conn_id: i32,
    serial: u64,
    session_id: u32,
    created: Instant,
}

#[derive(Debug)]
struct Grant {
    nonce: String,
    conn_id: i32,
    serial: u64,
    until: Instant,
    account: String,
}

#[derive(Debug, Default)]
pub struct Requests {
    pending: Option<Pending>,
    grant: Option<Grant>,
    /// The server process and session the current request or grant belongs to.
    owner: Option<(u32, u32)>,
    resume: Option<ResumeGrant>,
}

impl Requests {
    pub fn create(
        &mut self,
        conn_id: i32,
        serial: u64,
        server_pid: u32,
        session_id: u32,
        nonce: String,
        now: Instant,
    ) -> ServiceReply {
        self.expire(now);
        if self.pending.is_some() || self.grant.is_some() {
            return ServiceReply::Denied("another request for administrator access is pending".to_owned());
        }
        self.owner = Some((server_pid, session_id));
        self.pending = Some(Pending {
            nonce: nonce.clone(),
            conn_id,
            serial,
            session_id,
            created: now,
        });
        ServiceReply::Created(nonce)
    }

    pub fn cancel(&mut self, nonce: &str) -> ServiceReply {
        if self.pending.as_ref().map_or(false, |p| p.nonce == nonce) {
            self.pending = None;
        }
        ServiceReply::Done
    }

    /// S2/S3: a proof creates the grant only for the pending request with this nonce, from an elevated process in
    /// the same session; the nonce is used up. A refused proof leaves the request waiting for a real one.
    pub fn prove(&mut self, nonce: &str, facts: &ProofFacts, now: Instant) -> ServiceReply {
        self.expire(now);
        let Some(pending) = self.pending.as_ref().filter(|p| p.nonce == nonce) else {
            return ServiceReply::Denied("no such request (unknown, used or expired)".to_owned());
        };
        if !facts.elevated {
            return ServiceReply::Denied("the proof did not come from an elevated process".to_owned());
        }
        if facts.session_id != pending.session_id {
            return ServiceReply::Denied("the proof came from another session".to_owned());
        }
        let Some(pending) = self.pending.take() else {
            return ServiceReply::Denied("no such request".to_owned());
        };
        self.resume = match (facts.keep, facts.session_user_sid.as_ref()) {
            (true, Some(sid)) => Some(ResumeGrant {
                id: hbb_common::sodiumoxide::randombytes::randombytes(RESUME_ID_LEN),
                secret: hbb_common::sodiumoxide::randombytes::randombytes(RESUME_SECRET_LEN),
                grant_nonce: pending.nonce.clone(),
                serial: pending.serial,
                user_sid: sid.clone(),
                until: now + RESUME_TTL,
                delivered: false,
            }),
            _ => None,
        };
        self.grant = Some(Grant {
            nonce: pending.nonce,
            conn_id: pending.conn_id,
            serial: pending.serial,
            until: now + Duration::from_secs(grant_minutes() * 60),
            account: facts.account.clone(),
        });
        ServiceReply::Done
    }

    pub fn poll(&mut self, nonce: &str, now: Instant) -> ServiceReply {
        self.expire(now);
        if let Some(g) = self.grant.as_ref().filter(|g| g.nonce == nonce) {
            let mut resume = vec![];
            if let Some(r) = self.resume.as_mut().filter(|r| r.grant_nonce == nonce && !r.delivered) {
                r.delivered = true;
                resume = [r.id.as_slice(), r.secret.as_slice()].concat();
            }
            return ServiceReply::Granted {
                secs_left: g.until.saturating_duration_since(now).as_secs(),
                account: g.account.clone(),
                resume,
            };
        }
        if self.pending.as_ref().map_or(false, |p| p.nonce == nonce) {
            return ServiceReply::Waiting;
        }
        ServiceReply::Gone("administrator access ended".to_owned())
    }

    pub fn end(&mut self, nonce: &str, keep_resume: bool) -> ServiceReply {
        if self.grant.as_ref().map_or(false, |g| g.nonce == nonce) {
            self.grant = None;
        }
        if !keep_resume && self.resume.as_ref().map_or(false, |r| r.grant_nonce == nonce) {
            self.resume = None;
        }
        self.cancel(nonce)
    }

    /// F7/S7: a reconnecting controller is let in without a click if it proves the secret of an unexpired resume
    /// grant over this connection's challenge, holds the same controller credential, and either nobody is signed in
    /// or the user who granted it is. Usable more than once (sign-in screen, then the same user's session).
    pub fn resume_check(
        &mut self,
        id: &[u8],
        mac: &[u8],
        challenge: &str,
        peer_id: &str,
        serial: u64,
        signed_in_sid: Option<&str>,
        now: Instant,
    ) -> ServiceReply {
        self.void_resume_if_other_user(signed_in_sid, now);
        let Some(r) = self.resume.as_ref().filter(|r| r.id == id) else {
            return ServiceReply::Denied("no such resume grant (unknown, ended or expired)".to_owned());
        };
        if r.serial != serial {
            return ServiceReply::Denied("another controller credential".to_owned());
        }
        let expected = resume_mac(&r.secret, challenge, peer_id).unwrap_or_default();
        if expected.is_empty() || !hbb_common::sodiumoxide::utils::memcmp(&expected, mac) {
            return ServiceReply::Denied("wrong resume proof".to_owned());
        }
        ServiceReply::Done
    }

    /// Expiry, and "another user signed in" ends a resume grant for good (F7).
    pub fn void_resume_if_other_user(&mut self, signed_in_sid: Option<&str>, now: Instant) -> bool {
        let void = self.resume.as_ref().map_or(false, |r| {
            now >= r.until || signed_in_sid.map_or(false, |sid| sid != r.user_sid)
        });
        if void {
            self.resume = None;
        }
        void
    }

    pub fn has_resume(&self) -> bool {
        self.resume.is_some()
    }

    /// Sign-out, user switch, a new server process: nothing granted to the old session survives (F6). A resume grant
    /// is meant for exactly this and stays (it ends by time, by decision, or when another user signs in).
    pub fn reset(&mut self) -> Option<i32> {
        self.pending = None;
        self.owner = None;
        self.grant.take().map(|g| g.conn_id)
    }

    /// Called on every turn of the service loop: when the server process or the session that asked is gone,
    /// the request or grant goes too. Returns the connection of an ended grant.
    pub fn check_owner(&mut self, server_pid: u32, session_id: u32) -> Option<i32> {
        match self.owner {
            Some(owner) if owner != (server_pid, session_id) => self.reset(),
            _ => None,
        }
    }

    pub fn describe(&self) -> String {
        match (&self.grant, &self.pending) {
            (Some(g), _) => format!("connection {}, controller serial {}, approved by {}", g.conn_id, g.serial, g.account),
            (None, Some(p)) => format!("connection {}, controller serial {}", p.conn_id, p.serial),
            _ => String::new(),
        }
    }

    pub fn is_granted_to(&mut self, nonce: &str, now: Instant) -> bool {
        self.expire(now);
        self.grant.as_ref().map_or(false, |g| g.nonce == nonce)
    }

    pub fn is_granted(&mut self, now: Instant) -> bool {
        self.expire(now);
        self.grant.is_some()
    }

    pub fn is_pending(&mut self, now: Instant) -> bool {
        self.expire(now);
        self.pending.is_some()
    }

    fn expire(&mut self, now: Instant) {
        if self.grant.as_ref().map_or(false, |g| now >= g.until) {
            self.grant = None;
        }
        if self
            .pending
            .as_ref()
            .map_or(false, |p| now.saturating_duration_since(p.created) >= REQUEST_TTL)
        {
            self.pending = None;
        }
    }
}

/// 32 random bytes as hex: the one-time value that ties a UAC proof to one request.
pub fn new_nonce() -> String {
    hbb_common::sodiumoxide::randombytes::randombytes(32)
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_request_at_a_time_until_cancelled_or_expired() {
        let t0 = Instant::now();
        let mut r = Requests::default();
        assert_eq!(r.create(1, 7, 100, 1, "n1".into(), t0), ServiceReply::Created("n1".into()));
        assert!(matches!(r.create(2, 8, 100, 1, "n2".into(), t0), ServiceReply::Denied(_)));
        assert_eq!(r.cancel("wrong"), ServiceReply::Done);
        assert!(r.is_pending(t0), "a wrong nonce does not cancel");
        r.cancel("n1");
        assert!(!r.is_pending(t0));
        r.create(2, 8, 100, 1, "n2".into(), t0);
        assert!(r.is_pending(t0 + REQUEST_TTL - Duration::from_secs(1)));
        assert!(!r.is_pending(t0 + REQUEST_TTL));
        assert_eq!(r.create(3, 9, 100, 1, "n3".into(), t0 + REQUEST_TTL), ServiceReply::Created("n3".into()));
    }

    fn facts(session_id: u32, elevated: bool) -> ProofFacts {
        ProofFacts {
            session_id,
            elevated,
            account: "PC\\admin".to_owned(),
            keep: false,
            session_user_sid: Some("S-1-5-21-1".to_owned()),
        }
    }

    #[test]
    fn only_an_elevated_proof_from_the_same_session_grants_once() {
        let t0 = Instant::now();
        let mut r = Requests::default();
        r.create(1, 7, 100, 2, "n".into(), t0);
        assert_eq!(r.poll("n", t0), ServiceReply::Waiting);
        assert!(matches!(r.prove("n", &facts(2, false), t0), ServiceReply::Denied(_)), "not elevated");
        assert!(matches!(r.prove("n", &facts(3, true), t0), ServiceReply::Denied(_)), "other session");
        assert!(matches!(r.prove("x", &facts(2, true), t0), ServiceReply::Denied(_)), "wrong nonce");
        assert_eq!(r.prove("n", &facts(2, true), t0), ServiceReply::Done);
        assert!(matches!(r.prove("n", &facts(2, true), t0), ServiceReply::Denied(_)), "replay");
        assert!(matches!(r.poll("n", t0), ServiceReply::Granted { account, resume, .. } if account == "PC\\admin" && resume.is_empty()));
        assert!(matches!(r.create(9, 9, 100, 2, "m".into(), t0), ServiceReply::Denied(_)), "one grant per machine");
    }

    #[test]
    fn a_proof_after_the_request_expired_is_refused() {
        let t0 = Instant::now();
        let mut r = Requests::default();
        r.create(1, 7, 100, 2, "n".into(), t0);
        assert!(matches!(r.prove("n", &facts(2, true), t0 + REQUEST_TTL), ServiceReply::Denied(_)));
        assert!(matches!(r.poll("n", t0 + REQUEST_TTL), ServiceReply::Gone(_)));
    }

    #[test]
    fn a_grant_ends_by_time_limit_end_or_reset() {
        let t0 = Instant::now();
        let limit = Duration::from_secs(grant_minutes() * 60);
        let mut r = Requests::default();
        r.create(1, 7, 100, 2, "n".into(), t0);
        r.prove("n", &facts(2, true), t0);
        assert!(matches!(r.poll("n", t0 + limit - Duration::from_secs(1)), ServiceReply::Granted { secs_left: 1, .. }));
        assert!(matches!(r.poll("n", t0 + limit), ServiceReply::Gone(_)));

        r.create(1, 7, 100, 2, "a".into(), t0);
        r.prove("a", &facts(2, true), t0);
        r.end("other", false);
        assert!(r.is_granted(t0), "only the own nonce ends a grant");
        r.end("a", false);
        assert!(!r.is_granted(t0));

        r.create(5, 7, 100, 2, "b".into(), t0);
        r.prove("b", &facts(2, true), t0);
        assert_eq!(r.reset(), Some(5));
        assert!(matches!(r.poll("b", t0), ServiceReply::Gone(_)));
    }

    #[test]
    fn a_new_server_process_or_session_ends_everything() {
        let t0 = Instant::now();
        let mut r = Requests::default();
        assert_eq!(r.check_owner(100, 2), None);
        r.create(4, 7, 100, 2, "n".into(), t0);
        r.prove("n", &facts(2, true), t0);
        assert_eq!(r.check_owner(100, 2), None);
        assert_eq!(r.check_owner(101, 2), Some(4), "server relaunched");
        assert!(!r.is_granted(t0));
        r.create(4, 7, 100, 2, "m".into(), t0);
        r.prove("m", &facts(2, true), t0);
        assert_eq!(r.check_owner(100, 3), Some(4), "session changed");
    }

    fn granted_with_resume(r: &mut Requests, t0: Instant) -> Vec<u8> {
        r.create(1, 7, 100, 2, "n".into(), t0);
        let mut f = facts(2, true);
        f.keep = true;
        assert_eq!(r.prove("n", &f, t0), ServiceReply::Done);
        let ServiceReply::Granted { resume, .. } = r.poll("n", t0) else { panic!("not granted") };
        assert_eq!(resume.len(), 48, "id and secret handed over once");
        assert!(matches!(r.poll("n", t0), ServiceReply::Granted { resume, .. } if resume.is_empty()), "only once");
        resume
    }

    fn check(r: &mut Requests, blob: &[u8], challenge: &str, serial: u64, sid: Option<&str>, now: Instant) -> bool {
        let token = resume_token(blob, challenge, "ctl").unwrap();
        let (id, mac) = token.split_at(16);
        r.resume_check(id, mac, challenge, "ctl", serial, sid, now) == ServiceReply::Done
    }

    #[test]
    fn a_resume_grant_lets_the_same_controller_back_in_through_sign_out() {
        let t0 = Instant::now();
        let mut r = Requests::default();
        let blob = granted_with_resume(&mut r, t0);
        assert_eq!(r.reset(), Some(1), "sign-out ends the grant ...");
        assert!(r.has_resume(), "... but not the resume grant");
        assert!(check(&mut r, &blob, "c1", 7, None, t0), "nobody signed in: the sign-in screen");
        assert!(check(&mut r, &blob, "c2", 7, Some("S-1-5-21-1"), t0), "the same user signed in again");
    }

    #[test]
    fn a_resume_grant_refuses_other_controllers_wrong_proofs_and_replays() {
        let t0 = Instant::now();
        let mut r = Requests::default();
        let blob = granted_with_resume(&mut r, t0);
        assert!(!check(&mut r, &blob, "c1", 8, None, t0), "another controller credential");
        let mut forged = blob.clone();
        forged[20] ^= 1;
        assert!(!check(&mut r, &forged, "c1", 7, None, t0), "wrong secret");
        let token = resume_token(&blob, "old challenge", "ctl").unwrap();
        let (id, mac) = token.split_at(16);
        assert_ne!(r.resume_check(id, mac, "new challenge", "ctl", 7, None, t0), ServiceReply::Done, "replayed proof");
        assert_ne!(r.resume_check(id, mac, "old challenge", "other", 7, None, t0), ServiceReply::Done, "other peer id");
    }

    #[test]
    fn a_resume_grant_ends_by_time_decision_or_another_user() {
        let t0 = Instant::now();
        let mut r = Requests::default();
        let blob = granted_with_resume(&mut r, t0);
        assert!(!check(&mut r, &blob, "c", 7, None, t0 + RESUME_TTL), "expired");

        let mut r = Requests::default();
        let blob = granted_with_resume(&mut r, t0);
        assert!(!check(&mut r, &blob, "c", 7, Some("S-1-5-21-2"), t0), "another user signed in ...");
        assert!(!check(&mut r, &blob, "c", 7, None, t0), "... voids it for good");

        let mut r = Requests::default();
        let blob = granted_with_resume(&mut r, t0);
        r.end("n", true);
        assert!(check(&mut r, &blob, "c", 7, None, t0), "the connection closed: kept");
        r.end("n", false);
        assert!(!check(&mut r, &blob, "c", 7, None, t0), "drop or stop: gone");

        let mut r = Requests::default();
        r.create(1, 7, 100, 2, "n".into(), t0);
        r.prove("n", &facts(2, true), t0);
        assert!(!r.has_resume(), "no box ticked, no resume grant");
    }

    #[test]
    fn nonces_are_long_and_fresh() {
        let a = new_nonce();
        assert_eq!(a.len(), 64);
        assert_ne!(a, new_nonce());
    }
}
