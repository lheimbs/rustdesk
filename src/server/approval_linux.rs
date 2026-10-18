//! Linux side of the administrator approval (docs/APPROVAL_SPEC.md sections 4 and 5).
//!
//! The root service listens on the `_approval` socket. A user's `--server` asks about itself only (the peer uid, not an id the
//! caller names): `Check` (is this user an administrator, would the proof mean something), `Create`/`Poll`/`Cancel` for one
//! request. The proof is a root process started through `sudo` (`--approval-proof <nonce>`): only a root peer may send `Proof`,
//! and the uid sudo recorded in that process must be the user that asked. A user who cannot become root cannot prove anything.

use super::{
    approval::{self, Approval, Refusal},
    approval_grant::{Approvals, Poll, PROOF_TTL},
};
use crate::ipc::{self, Data};
use hbb_common::{log, tokio, ResultType};
use serde_derive::{Deserialize, Serialize};
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    Check,
    Create { nonce: String },
    Poll { nonce: String },
    Cancel { nonce: String },
    Proof { nonce: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Reply {
    Approver,
    Refused(Refusal),
    Done,
    Waiting,
    Granted,
    Gone,
    Denied,
}

pub const POSTFIX: &str = "_approval";
static APPROVALS: Mutex<Option<Approvals>> = Mutex::new(None);

fn with_approvals<T>(f: impl FnOnce(&mut Approvals) -> T) -> T {
    let mut g = APPROVALS.lock().unwrap();
    f(g.get_or_insert_with(Approvals::default))
}

// ---- service (root) ----

pub(crate) fn user_name(uid: u32) -> Option<String> {
    use hbb_common::libc;
    let mut buf = vec![0u8; 4096];
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr() as *mut _, buf.len(), &mut result) };
    if rc != 0 || result.is_null() {
        return None;
    }
    unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) }.to_str().ok().map(str::to_owned)
}

/// `sudo -l -U <name>` as root: what sudo itself says about the user.
fn check_user(uid: u32) -> Approval {
    let Some(name) = user_name(uid) else {
        return Approval::Refused(Refusal::NoAdministrator);
    };
    let out = std::process::Command::new("sudo")
        .args(["-n", "-l", "-U"])
        .arg(&name)
        .stdin(std::process::Stdio::null())
        .env("LC_ALL", "C")
        .output();
    let text = match out {
        Ok(o) => String::from_utf8_lossy(&o.stdout).into_owned(),
        Err(err) => {
            log::warn!("approval: sudo -l failed to run: {}", err);
            String::new()
        }
    };
    let (who, proof) = approval::classify_sudo_list(&text);
    approval::decide(who, proof)
}

/// The uid sudo recorded in the environment of the proof process (a root process can read it).
fn sudo_uid_of(pid: u32) -> Option<u32> {
    let env = std::fs::read(format!("/proc/{}/environ", pid)).ok()?;
    env.split(|b| *b == 0)
        .filter_map(|kv| std::str::from_utf8(kv).ok())
        .find_map(|kv| kv.strip_prefix("SUDO_UID="))
        .and_then(|v| v.parse().ok())
}

fn answer(req: Request, peer_uid: u32, peer_pid: Option<u32>) -> Reply {
    let now = Instant::now();
    match req {
        Request::Check => match check_user(peer_uid) {
            Approval::Approver => Reply::Approver,
            Approval::Refused(r) => Reply::Refused(r),
        },
        Request::Create { nonce } => {
            with_approvals(|a| a.create(peer_uid, &nonce, now));
            Reply::Done
        }
        Request::Poll { nonce } => match with_approvals(|a| a.poll(peer_uid, &nonce, now)) {
            Poll::Waiting => Reply::Waiting,
            Poll::Granted => Reply::Granted,
            Poll::Gone => Reply::Gone,
        },
        Request::Cancel { nonce } => {
            with_approvals(|a| a.cancel(peer_uid, &nonce));
            Reply::Done
        }
        Request::Proof { nonce } => {
            if peer_uid != 0 {
                log::warn!("approval: a proof from uid {} (not root) was refused", peer_uid);
                return Reply::Denied;
            }
            let sudo_uid = peer_pid.and_then(sudo_uid_of);
            match with_approvals(|a| a.prove(&nonce, sudo_uid, now)) {
                Ok(()) => {
                    log::info!("approval: granted for uid {:?}", sudo_uid);
                    Reply::Done
                }
                Err(e) => {
                    log::warn!("approval: proof refused: {:?} (sudo uid {:?})", e, sudo_uid);
                    Reply::Denied
                }
            }
        }
    }
}

#[tokio::main(flavor = "current_thread")]
pub async fn serve() -> ResultType<()> {
    use hbb_common::futures::StreamExt;
    let mut incoming = ipc::new_listener(POSTFIX).await?;
    while let Some(result) = incoming.next().await {
        let Ok(stream) = result else { continue };
        tokio::spawn(async move {
            let mut stream = ipc::Connection::new(stream);
            let (uid, pid) = (stream.peer_uid(), stream.peer_pid());
            let Some(uid) = uid else { return };
            while let Ok(Some(Data::Approval(req))) = stream.next_timeout(5000).await {
                // sudo may take a moment; keep the loop off the other connections
                let reply = tokio::task::spawn_blocking(move || answer(req, uid, pid))
                    .await
                    .unwrap_or(Reply::Denied);
                if stream.send(&Data::ApprovalReply(reply)).await.is_err() {
                    break;
                }
            }
        });
    }
    Ok(())
}

// ---- user side ----

async fn ask(req: Request) -> ResultType<Reply> {
    let mut c = ipc::connect(3000, POSTFIX).await?;
    c.send(&Data::Approval(req)).await?;
    match c.next_timeout(15000).await? {
        Some(Data::ApprovalReply(r)) => Ok(r),
        _ => hbb_common::bail!("no reply from the approval service"),
    }
}

/// Is an administrator signed in here, and would their approval mean something? No service: refuse (fail closed).
pub async fn check() -> Result<(), Refusal> {
    match ask(Request::Check).await {
        Ok(Reply::Approver) => Ok(()),
        Ok(Reply::Refused(r)) => Err(r),
        other => {
            log::warn!("approval: no answer from the service: {:?}", other.map(|_| ()).err());
            Err(Refusal::ServiceUnavailable)
        }
    }
}

/// Start the sudo proof (password dialog) and wait for the service to confirm it. True only when it did.
pub async fn request() -> bool {
    let nonce = super::elevation_grant::new_nonce();
    if !matches!(ask(Request::Create { nonce: nonce.clone() }).await, Ok(Reply::Done)) {
        return false;
    }
    let exe = std::env::current_exe().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
    let cmd = format!("'{}' --approval-proof {}", exe.replace('\'', "'\\''"), nonce);
    let mut dialog = tokio::task::spawn_blocking(move || crate::platform::gtk_sudo::run_as_self(vec![&cmd]).is_ok());
    let deadline = Instant::now() + PROOF_TTL;
    let mut done = false;
    let granted = loop {
        if matches!(ask(Request::Poll { nonce: nonce.clone() }).await, Ok(Reply::Granted)) {
            break true;
        }
        if done || Instant::now() >= deadline {
            break false;
        }
        tokio::select! {
            r = &mut dialog => { done = true; let _ = r; }
            _ = tokio::time::sleep(Duration::from_millis(300)) => {}
        }
    };
    if !granted {
        let _ = ask(Request::Cancel { nonce }).await;
    }
    granted
}

// ---- proof process (root, started through sudo) ----

#[tokio::main(flavor = "current_thread")]
pub async fn send_proof(nonce: &str) -> ResultType<()> {
    match ask(Request::Proof { nonce: nonce.to_owned() }).await? {
        Reply::Done => Ok(()),
        _ => hbb_common::bail!("the approval service refused the proof"),
    }
}
