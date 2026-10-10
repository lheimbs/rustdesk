//! Handover: admission tokens for the rendezvous and relay servers (see `libs/handover_cred`).
//!
//! Every message that reaches `hbbs` or `hbbr` carries a token made from a credential signed by the owner's
//! issuer. Messages that start a connection need a controller credential (`controller.cred`); the ones a
//! machine sends to be reachable need a device credential (`device.cred`, else the one baked into the build),
//! and a controller credential is also accepted there. Without a credential the token is empty and the
//! servers refuse the message.

use handover_cred::{token, HolderFile};
use hbb_common::{
    config::{Config, DEVICE_CRED},
    log,
};

fn from_file(name: &str) -> Option<HolderFile> {
    let path = Config::path(name);
    let text = std::fs::read_to_string(&path).ok()?;
    match HolderFile::from_text(&text) {
        Ok(h) => Some(h),
        Err(_) => {
            log::warn!("the credential file {} is unreadable", path.display());
            None
        }
    }
}

fn controller() -> Option<HolderFile> {
    from_file("controller.cred")
}

fn device() -> Option<HolderFile> {
    from_file("device.cred").or_else(|| HolderFile::from_compact(DEVICE_CRED).ok())
}

fn make(holder: Option<HolderFile>, kind: &str, context: &str) -> String {
    holder.map(|h| token::make(&h, kind, context, token::now_secs())).unwrap_or_default()
}

/// For messages that start a connection to another machine.
pub fn controller_token(kind: &str, context: &str) -> String {
    make(controller(), kind, context)
}

/// For messages a machine sends to be registered and relayed: its device credential, else a controller one.
pub fn machine_token(kind: &str, context: &str) -> String {
    make(device().or_else(controller), kind, context)
}

/// The context both ends use for a public-key registration.
pub fn register_pk_context(id: &str, uuid: &[u8], pk: &[u8]) -> String {
    format!("{}\n{}\n{}", id, token::b64(uuid), token::b64(pk))
}

pub fn relay_request_context(peer_id: &str, uuid: &str) -> String {
    format!("{peer_id}\n{uuid}")
}
