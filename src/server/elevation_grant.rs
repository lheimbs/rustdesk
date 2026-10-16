//! The service's record of administrator-access requests (`docs/ELEVATION_SPEC.md` 4.4, S3; stories E7, E8).
//! Pure state: the service loop (`platform/windows.rs::run_service`) authorises the caller and passes the facts
//! in. One request at a time per machine (spec section 5: one elevation grant per machine).

use serde_derive::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Hard upper bound for a request in the service: the person's decision (60 s) plus the UAC prompt (120 s).
pub const REQUEST_TTL: Duration = Duration::from_secs(180);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServiceRequest {
    /// From the user-level server: a controller asks for administrator access; the reply is `Created(nonce)`.
    Create { conn_id: i32, serial: u64 },
    /// From the user-level server: the request ended (denied, expired, connection closed).
    Cancel { nonce: String },
    /// From `--elevation-proof`, started through the UAC prompt.
    Proof { nonce: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ServiceReply {
    Created(String),
    Done,
    Denied(String),
}

/// `conn_id`, `serial` and `session_id` bind the proof to this request (checked with E8).
#[allow(dead_code)]
#[derive(Debug)]
struct Pending {
    nonce: String,
    conn_id: i32,
    serial: u64,
    session_id: u32,
    created: Instant,
}

#[derive(Debug, Default)]
pub struct Requests {
    pending: Option<Pending>,
}

impl Requests {
    pub fn create(
        &mut self,
        conn_id: i32,
        serial: u64,
        session_id: u32,
        nonce: String,
        now: Instant,
    ) -> ServiceReply {
        self.expire(now);
        if self.pending.is_some() {
            return ServiceReply::Denied("another request for administrator access is pending".to_owned());
        }
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

    pub fn is_pending(&mut self, now: Instant) -> bool {
        self.expire(now);
        self.pending.is_some()
    }

    fn expire(&mut self, now: Instant) {
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
        assert_eq!(r.create(1, 7, 1, "n1".into(), t0), ServiceReply::Created("n1".into()));
        assert!(matches!(r.create(2, 8, 1, "n2".into(), t0), ServiceReply::Denied(_)));
        assert_eq!(r.cancel("wrong"), ServiceReply::Done);
        assert!(r.is_pending(t0), "a wrong nonce does not cancel");
        r.cancel("n1");
        assert!(!r.is_pending(t0));
        r.create(2, 8, 1, "n2".into(), t0);
        assert!(r.is_pending(t0 + REQUEST_TTL - Duration::from_secs(1)));
        assert!(!r.is_pending(t0 + REQUEST_TTL));
        assert_eq!(r.create(3, 9, 1, "n3".into(), t0 + REQUEST_TTL), ServiceReply::Created("n3".into()));
    }

    #[test]
    fn nonces_are_long_and_fresh() {
        let a = new_nonce();
        assert_eq!(a.len(), 64);
        assert_ne!(a, new_nonce());
    }
}
