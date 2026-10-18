//! Service side of an approval (docs/APPROVAL_SPEC.md section 5), pure bookkeeping: a user's server registers a one-time
//! nonce, a root process (started through sudo) proves it, the user's server collects the result once. The caller supplies
//! who is asking (peer uid) and who the proof came from (the uid sudo recorded), so no clock or socket is needed here.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

/// How long a registered request waits for its proof.
pub const PROOF_TTL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Poll {
    Waiting,
    Granted,
    /// Unknown, expired, already collected, or registered by someone else.
    Gone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofError {
    UnknownOrExpired,
    /// The proof ran for a different user than the one that asked.
    OtherUser,
}

struct Pending {
    uid: u32,
    created: Instant,
    granted: bool,
}

#[derive(Default)]
pub struct Approvals {
    map: HashMap<String, Pending>,
}

impl Approvals {
    fn expire(&mut self, now: Instant) {
        self.map.retain(|_, p| now.duration_since(p.created) < PROOF_TTL);
    }

    /// Register a nonce for `uid`. A user has one open request: a new one replaces the old.
    pub fn create(&mut self, uid: u32, nonce: &str, now: Instant) {
        self.expire(now);
        self.map.retain(|_, p| p.uid != uid);
        if nonce.len() >= 32 {
            self.map.insert(nonce.to_owned(), Pending { uid, created: now, granted: false });
        }
    }

    /// The proof process ran as root; `sudo_uid` is the user that invoked sudo.
    pub fn prove(&mut self, nonce: &str, sudo_uid: Option<u32>, now: Instant) -> Result<(), ProofError> {
        self.expire(now);
        let p = self.map.get_mut(nonce).ok_or(ProofError::UnknownOrExpired)?;
        if sudo_uid != Some(p.uid) {
            return Err(ProofError::OtherUser);
        }
        p.granted = true;
        Ok(())
    }

    /// `granted` is reported once: the entry is consumed.
    pub fn poll(&mut self, uid: u32, nonce: &str, now: Instant) -> Poll {
        self.expire(now);
        match self.map.get(nonce) {
            Some(p) if p.uid == uid && p.granted => {
                self.map.remove(nonce);
                Poll::Granted
            }
            Some(p) if p.uid == uid => Poll::Waiting,
            _ => Poll::Gone,
        }
    }

    pub fn cancel(&mut self, uid: u32, nonce: &str) {
        if self.map.get(nonce).map_or(false, |p| p.uid == uid) {
            self.map.remove(nonce);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const N: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const M: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    #[test]
    fn a_proof_for_the_asking_user_is_collected_once() {
        let (mut a, t) = (Approvals::default(), Instant::now());
        a.create(1000, N, t);
        assert_eq!(a.poll(1000, N, t), Poll::Waiting);
        assert_eq!(a.prove(N, Some(1000), t), Ok(()));
        assert_eq!(a.poll(1000, N, t), Poll::Granted);
        assert_eq!(a.poll(1000, N, t), Poll::Gone);
    }

    #[test]
    fn a_proof_run_for_another_user_is_refused_and_grants_nothing() {
        let (mut a, t) = (Approvals::default(), Instant::now());
        a.create(1000, N, t);
        assert_eq!(a.prove(N, Some(1001), t), Err(ProofError::OtherUser));
        assert_eq!(a.prove(N, None, t), Err(ProofError::OtherUser));
        assert_eq!(a.poll(1000, N, t), Poll::Waiting);
    }

    #[test]
    fn another_user_cannot_poll_or_cancel_a_request() {
        let (mut a, t) = (Approvals::default(), Instant::now());
        a.create(1000, N, t);
        a.prove(N, Some(1000), t).unwrap();
        assert_eq!(a.poll(1001, N, t), Poll::Gone);
        a.cancel(1001, N);
        assert_eq!(a.poll(1000, N, t), Poll::Granted);
    }

    #[test]
    fn an_unknown_or_expired_nonce_is_refused() {
        let (mut a, t) = (Approvals::default(), Instant::now());
        assert_eq!(a.prove(N, Some(1000), t), Err(ProofError::UnknownOrExpired));
        a.create(1000, N, t);
        let late = t + PROOF_TTL;
        assert_eq!(a.prove(N, Some(1000), late), Err(ProofError::UnknownOrExpired));
        assert_eq!(a.poll(1000, N, late), Poll::Gone);
    }

    #[test]
    fn a_new_request_replaces_the_users_old_one_and_short_nonces_are_ignored() {
        let (mut a, t) = (Approvals::default(), Instant::now());
        a.create(1000, N, t);
        a.create(1000, M, t);
        assert_eq!(a.prove(N, Some(1000), t), Err(ProofError::UnknownOrExpired));
        a.create(1000, "short", t);
        assert_eq!(a.poll(1000, "short", t), Poll::Gone);
        assert_eq!(a.poll(1000, M, t), Poll::Gone);
    }

    #[test]
    fn a_cancelled_request_cannot_be_proven() {
        let (mut a, t) = (Approvals::default(), Instant::now());
        a.create(1000, N, t);
        a.cancel(1000, N);
        assert_eq!(a.prove(N, Some(1000), t), Err(ProofError::UnknownOrExpired));
    }
}
