//! The sign broker (`docs/ELEVATION_SPEC.md` S4 and 4.6).
//!
//! On Windows the `--server` runs as the signed-in user, so it must not hold the machine's secret key or the
//! device credential. The service keeps them, and the user-level server asks it for exactly three things:
//! the machine's ID and public key, a signature over its own identity handshake structure (`IdPk`), and an
//! admission token for one of the messages it sends to `hbbs`/`hbbr`. Everything else is refused, and the
//! request is checked against the machine's own ID and public key before anything is signed.
//!
//! This file holds the checks and the client side; the service side is a thin arm in
//! `platform/windows.rs::run_service` that calls [`serve`]. Callers are authorised there: only the very
//! server process the service launched may ask.

use handover_cred::token::b64;
use hbb_common::{
    protobuf::Message as _,
    rendezvous_proto::IdPk,
    sodiumoxide::crypto::{box_, sign},
    tcp::KX_VERSION_LATEST,
};
use serde_derive::{Deserialize, Serialize};
use std::time::Instant;

const MAX_ID_PK_LEN: usize = 512;
const MAX_FINGERPRINT_LEN: usize = 200;
const MAX_UUID_LEN: usize = 96;
const MAX_KIND_LEN: usize = 16;
const MAX_CONTEXT_LEN: usize = 512;
const MAX_SIGNED_AT_SKEW: u64 = 60;

/// A burst the busiest legitimate moment needs, then a rate far above what a machine ever sends (a
/// registration every few seconds plus a token per connection attempt).
const BURST: u32 = 60;
const REFILL_PER_SEC: f64 = 4.0;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BrokerRequest {
    /// The machine's ID and public key (not secret).
    Identity,
    /// The serialized [`IdPk`] of this machine's handshake; the reply is the signed message.
    SignIdPk(Vec<u8>),
    /// An admission token for one message of type `kind` about `context`.
    Token { kind: String, context: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BrokerReply {
    Identity { id: String, pk: Vec<u8> },
    Signed(Vec<u8>),
    Token(String),
    Denied(String),
}

/// Token bucket over all callers: a flood costs the supervisor nothing more than a refusal.
pub struct RateLimit {
    tokens: f64,
    last: Instant,
}

impl RateLimit {
    pub fn new(now: Instant) -> Self {
        Self {
            tokens: BURST as f64,
            last: now,
        }
    }

    pub fn allow(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * REFILL_PER_SEC).min(BURST as f64);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

fn check_id_pk(bytes: &[u8], own_id: &str) -> Result<(), &'static str> {
    if bytes.len() > MAX_ID_PK_LEN {
        return Err("identity message too long");
    }
    let msg = IdPk::parse_from_bytes(bytes).map_err(|_| "not an identity message")?;
    if msg.special_fields.unknown_fields().iter().next().is_some()
        || msg.write_to_bytes().ok().as_deref() != Some(bytes)
    {
        return Err("identity message not in canonical form");
    }
    if msg.id != own_id {
        return Err("identity message is not for this machine");
    }
    if msg.pk.len() != box_::PUBLICKEYBYTES {
        return Err("bad ephemeral key length");
    }
    if msg.kx_version > KX_VERSION_LATEST {
        return Err("unknown key exchange version");
    }
    // the service and the server share a clock: only a handshake of right now is signed (#83)
    if msg.signed_at.abs_diff(handover_cred::token::now_secs()) > MAX_SIGNED_AT_SKEW {
        return Err("identity message is not of now");
    }
    if msg.dtls_fingerprint.len() > MAX_FINGERPRINT_LEN
        || !msg
            .dtls_fingerprint
            .bytes()
            .all(|b| b.is_ascii_graphic() || b == b' ')
    {
        return Err("bad transport fingerprint");
    }
    Ok(())
}

fn is_uuid_like(s: &str) -> bool {
    s.len() <= MAX_UUID_LEN
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn is_base64_text(s: &str) -> bool {
    s.len() <= MAX_UUID_LEN
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
}

fn check_token(kind: &str, context: &str, own_id: &str, own_pk: &[u8]) -> Result<(), &'static str> {
    if kind.len() > MAX_KIND_LEN || context.len() > MAX_CONTEXT_LEN {
        return Err("request too long");
    }
    let ok = match kind {
        "register" | "localaddr" | "holesent" => context == own_id,
        "relay" | "relayresp" => is_uuid_like(context),
        "registerpk" => {
            let mut parts = context.split('\n');
            match (parts.next(), parts.next(), parts.next(), parts.next()) {
                (Some(id), Some(uuid), Some(pk), None) => {
                    id == own_id && is_base64_text(uuid) && pk == b64(own_pk)
                }
                _ => false,
            }
        }
        _ => return Err("this kind of message is not served"),
    };
    if ok {
        Ok(())
    } else {
        Err("the request is not about this machine")
    }
}

/// Answers one request. `sign_bytes` signs with the machine's secret key and `make_token` builds a token
/// from the device credential; both are only called for a request that passed every check.
pub fn serve(
    request: BrokerRequest,
    own_id: &str,
    own_pk: &[u8],
    limiter: &mut RateLimit,
    now: Instant,
    sign_bytes: impl FnOnce(&[u8]) -> Option<Vec<u8>>,
    make_token: impl FnOnce(&str, &str) -> String,
) -> BrokerReply {
    if !limiter.allow(now) {
        return BrokerReply::Denied("too many requests".to_owned());
    }
    match request {
        BrokerRequest::Identity => BrokerReply::Identity {
            id: own_id.to_owned(),
            pk: own_pk.to_vec(),
        },
        BrokerRequest::SignIdPk(bytes) => match check_id_pk(&bytes, own_id) {
            Ok(()) => match sign_bytes(&bytes) {
                Some(signed) => BrokerReply::Signed(signed),
                None => BrokerReply::Denied("no secret key".to_owned()),
            },
            Err(why) => BrokerReply::Denied(why.to_owned()),
        },
        BrokerRequest::Token { kind, context } => {
            match check_token(&kind, &context, own_id, own_pk) {
                Ok(()) => {
                    let token = make_token(&kind, &context);
                    if token.is_empty() {
                        BrokerReply::Denied("no device credential".to_owned())
                    } else {
                        BrokerReply::Token(token)
                    }
                }
                Err(why) => BrokerReply::Denied(why.to_owned()),
            }
        }
    }
}

/// Signs `bytes` with the machine's secret key, or, in a user-level server, has the service do it.
pub async fn sign_identity(bytes: &[u8], sk: &[u8]) -> hbb_common::ResultType<Vec<u8>> {
    #[cfg(windows)]
    if hbb_common::config::Config::is_brokered_identity() {
        return match call(BrokerRequest::SignIdPk(bytes.to_vec())).await? {
            BrokerReply::Signed(signed) => Ok(signed),
            BrokerReply::Denied(why) => hbb_common::bail!("the service refused to sign: {}", why),
            _ => hbb_common::bail!("unexpected reply from the service"),
        };
    }
    let key = sign::SecretKey::from_slice(sk)
        .ok_or_else(|| hbb_common::anyhow::anyhow!("no usable secret key"))?;
    Ok(sign::sign(bytes, &key))
}

#[cfg(windows)]
async fn call(request: BrokerRequest) -> hbb_common::ResultType<BrokerReply> {
    let mut conn = crate::ipc::connect_service(1000).await?;
    conn.send(&crate::ipc::Data::Broker(request)).await?;
    match conn.next_timeout(3000).await? {
        Some(crate::ipc::Data::BrokerReply(reply)) => Ok(reply),
        _ => hbb_common::bail!("no reply from the service"),
    }
}

/// A user-level server takes the machine's ID and public key from the service. Fails closed: without them
/// it exits and the service starts it again.
#[cfg(windows)]
pub async fn adopt_machine_identity() {
    for _ in 0..10 {
        match call(BrokerRequest::Identity).await {
            Ok(BrokerReply::Identity { id, pk })
                if !id.is_empty() && pk.len() == sign::PUBLICKEYBYTES =>
            {
                hbb_common::config::Config::set_brokered_identity(id, pk);
                hbb_common::log::info!("machine identity taken from the service");
                return;
            }
            Ok(_) => {}
            Err(err) => hbb_common::log::debug!("machine identity not available yet: {}", err),
        }
        hbb_common::sleep(1.).await;
    }
    hbb_common::log::error!("no machine identity from the service, exiting");
    std::process::exit(1);
}

/// A token for a message this machine sends to `hbbs`/`hbbr`; empty (and so refused by the servers) when the
/// service does not give one.
#[cfg(windows)]
pub async fn brokered_token(kind: &str, context: &str) -> String {
    let request = BrokerRequest::Token {
        kind: kind.to_owned(),
        context: context.to_owned(),
    };
    match call(request).await {
        Ok(BrokerReply::Token(token)) => token,
        Ok(other) => {
            hbb_common::throttled_log!(
                std::time::Duration::from_secs(10),
                warn,
                "no admission token from the service for '{}': {:?}",
                kind,
                other
            );
            String::new()
        }
        Err(err) => {
            hbb_common::throttled_log!(
                std::time::Duration::from_secs(10),
                warn,
                "no admission token from the service for '{}': {}",
                kind,
                err
            );
            String::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const ID: &str = "480179879";

    fn pk() -> Vec<u8> {
        vec![7u8; sign::PUBLICKEYBYTES]
    }

    fn id_pk() -> IdPk {
        IdPk {
            id: ID.to_owned(),
            pk: vec![1u8; box_::PUBLICKEYBYTES].into(),
            kx_version: KX_VERSION_LATEST,
            signed_at: handover_cred::token::now_secs(),
            ..Default::default()
        }
    }

    fn ask(request: BrokerRequest) -> BrokerReply {
        let mut limiter = RateLimit::new(Instant::now());
        serve(
            request,
            ID,
            &pk(),
            &mut limiter,
            Instant::now(),
            |b| Some([b"signed:".as_slice(), b].concat()),
            |kind, context| format!("tok:{kind}:{context}"),
        )
    }

    fn denied(reply: &BrokerReply) -> bool {
        matches!(reply, BrokerReply::Denied(_))
    }

    #[test]
    fn identity_is_the_machines_own() {
        match ask(BrokerRequest::Identity) {
            BrokerReply::Identity { id, pk: key } => {
                assert_eq!(id, ID);
                assert_eq!(key, pk());
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn signs_the_machines_own_handshake_structure() {
        let bytes = id_pk().write_to_bytes().unwrap();
        match ask(BrokerRequest::SignIdPk(bytes.clone())) {
            BrokerReply::Signed(s) => assert_eq!(s, [b"signed:".as_slice(), &bytes].concat()),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn refuses_to_sign_anything_else() {
        let mut other_machine = id_pk();
        other_machine.id = "111111111".to_owned();
        let mut long_key = id_pk();
        long_key.pk = vec![1u8; 64].into();
        let mut future_kx = id_pk();
        future_kx.kx_version = KX_VERSION_LATEST + 1;
        let mut bad_fingerprint = id_pk();
        bad_fingerprint.dtls_fingerprint = "a\nb".to_owned();
        let mut huge_fingerprint = id_pk();
        huge_fingerprint.dtls_fingerprint = "a".repeat(MAX_FINGERPRINT_LEN + 1);
        let mut unknown_field = id_pk().write_to_bytes().unwrap();
        unknown_field.extend_from_slice(&[0xa8, 0x06, 0x01]); // field 105, varint 1
        let mut not_canonical = vec![0x20, 0x00]; // kx_version = 0 written explicitly
        not_canonical.extend(id_pk().write_to_bytes().unwrap());
        let cases: Vec<Vec<u8>> = vec![
            vec![],
            b"hello".to_vec(),
            vec![0xff; 40],
            other_machine.write_to_bytes().unwrap(),
            long_key.write_to_bytes().unwrap(),
            future_kx.write_to_bytes().unwrap(),
            bad_fingerprint.write_to_bytes().unwrap(),
            huge_fingerprint.write_to_bytes().unwrap(),
            unknown_field,
            not_canonical,
            vec![0u8; MAX_ID_PK_LEN + 1],
        ];
        for (i, bytes) in cases.into_iter().enumerate() {
            assert!(
                denied(&ask(BrokerRequest::SignIdPk(bytes))),
                "case {i} was signed"
            );
        }
    }

    #[test]
    fn tokens_only_for_this_machines_messages() {
        let own_pk_b64 = b64(&pk());
        let token = |kind: &str, context: &str| {
            ask(BrokerRequest::Token {
                kind: kind.to_owned(),
                context: context.to_owned(),
            })
        };
        for kind in ["register", "localaddr", "holesent"] {
            assert!(matches!(token(kind, ID), BrokerReply::Token(_)), "{kind}");
            assert!(denied(&token(kind, "111111111")), "{kind} for another id");
            assert!(denied(&token(kind, "")), "{kind} empty");
        }
        for kind in ["relay", "relayresp"] {
            assert!(matches!(
                token(kind, "0b9f4c1e-6d3a-4f08-9c52-7a1d3e5b8f20"),
                BrokerReply::Token(_)
            ));
            assert!(matches!(token(kind, ""), BrokerReply::Token(_)));
            assert!(denied(&token(kind, "a b")));
            assert!(denied(&token(kind, "x\n y")));
            assert!(denied(&token(kind, &"a".repeat(MAX_UUID_LEN + 1))));
        }
        let register_pk =
            |id: &str, uuid: &str, pk: &str| token("registerpk", &format!("{id}\n{uuid}\n{pk}"));
        assert!(matches!(
            register_pk(ID, "AAAAAAAAAAAAAAAAAAAAAA==", &own_pk_b64),
            BrokerReply::Token(_)
        ));
        assert!(
            denied(&register_pk("111111111", "AAAA", &own_pk_b64)),
            "new id"
        );
        assert!(denied(&register_pk(ID, "AAAA", "")), "empty key");
        assert!(
            denied(&register_pk(ID, "AAAA", &b64(&[9u8; 32]))),
            "foreign key"
        );
        assert!(
            denied(&register_pk(ID, "A A", &own_pk_b64)),
            "bad uuid text"
        );
        assert!(denied(&token(
            "registerpk",
            &format!("{ID}\nAAAA\n{own_pk_b64}\nextra")
        )));
        assert!(denied(&token("registerpk", ID)));
    }

    #[test]
    fn unknown_or_oversized_requests_get_nothing() {
        for kind in [
            "",
            "punch",
            "REGISTER",
            "register ",
            "controller",
            "relay\0",
        ] {
            let reply = ask(BrokerRequest::Token {
                kind: kind.to_owned(),
                context: ID.to_owned(),
            });
            assert!(denied(&reply), "kind {kind:?}");
        }
        assert!(denied(&ask(BrokerRequest::Token {
            kind: "register".to_owned(),
            context: "9".repeat(MAX_CONTEXT_LEN + 1),
        })));
        assert!(denied(&ask(BrokerRequest::Token {
            kind: "k".repeat(MAX_KIND_LEN + 1),
            context: String::new(),
        })));
    }

    #[test]
    fn no_device_credential_means_no_token() {
        let mut limiter = RateLimit::new(Instant::now());
        let reply = serve(
            BrokerRequest::Token {
                kind: "register".to_owned(),
                context: ID.to_owned(),
            },
            ID,
            &pk(),
            &mut limiter,
            Instant::now(),
            |_| None,
            |_, _| String::new(),
        );
        assert!(denied(&reply));
    }

    #[test]
    fn flood_is_cut_off_and_recovers() {
        let t0 = Instant::now();
        let mut limiter = RateLimit::new(t0);
        let mut answered = 0;
        for _ in 0..1000 {
            let reply = serve(
                BrokerRequest::Identity,
                ID,
                &pk(),
                &mut limiter,
                t0,
                |_| None,
                |_, _| String::new(),
            );
            if !denied(&reply) {
                answered += 1;
            }
        }
        assert_eq!(answered, BURST);
        assert!(!limiter.allow(t0));
        assert!(limiter.allow(t0 + Duration::from_secs(1)));
    }
}
