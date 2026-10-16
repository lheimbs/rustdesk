//! Administrator access (tier 1) requests from the controller (`docs/ELEVATION_SPEC.md` F3, F4, F10, S6; stories
//! E6, E7). The controller asks with `ElevationRequest.direct` and gives up with `Misc.elevation_drop`; it is told
//! the state with `Misc.elevation_status`. Credentials from the controller (`ElevationRequest.logon`) are always
//! refused. On Windows a request is checked (keyboard permission, nothing pending, UAC policy), recorded in the
//! service, and shown to the person at the machine; Allow starts `--elevation-proof` through the UAC prompt. The
//! grant itself (proof check, time limit) is the service's (E8); until it exists no request ends in a grant.

use base::message_proto::{
    elevation_request, elevation_status::State, ElevationRequest, ElevationStatus, Message, Misc,
};
#[cfg(windows)]
use hbb_common::tokio;
use serde_derive::{Deserialize, Serialize};
use std::time::{Duration, Instant};

pub const NOT_AVAILABLE: &str = "Administrator access is not available on this machine";
pub const NO_CREDENTIALS: &str = "Credentials from the controller are not accepted";
pub const NO_KEYBOARD: &str = "Administrator access needs the keyboard permission";
pub const BUSY: &str = "A request for administrator access is already pending";
pub const UAC_OFF: &str = "Administrator access needs Windows UAC with a prompt on the secure desktop";
pub const DENIED_LOCALLY: &str = "The person at the remote machine denied administrator access";
pub const UAC_DECLINED: &str = "The Windows prompt was declined";
/// How long the person at the machine has to decide, and then to answer the Windows prompt.
pub const DECISION_SECS: u64 = 60;
pub const PROOF_SECS: u64 = 120;

/// The UAC settings that decide whether a UAC consent is an authentication (`HKLM\...\Policies\System`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UacPolicy {
    pub enable_lua: u32,
    pub consent_prompt_behavior_admin: u32,
    pub prompt_on_secure_desktop: u32,
}

/// F10: elevation is offered only while UAC is on, administrators are prompted (not elevated silently), and the
/// prompt is shown on the secure desktop, where a tier-0 controller can neither see nor answer it (plan 2s, 2u).
pub fn uac_allows_elevation(policy: &UacPolicy) -> bool {
    let admin = policy.consent_prompt_behavior_admin;
    policy.enable_lua == 1
        && admin != 0
        && (admin == 1 || admin == 2 || policy.prompt_on_secure_desktop == 1)
}

/// Whether a connection may ask: keyboard permission, nothing pending or granted for it, UAC as F10 wants.
pub fn check_request(keyboard: bool, busy: bool, uac_ok: bool) -> Result<(), &'static str> {
    if !keyboard {
        return Err(NO_KEYBOARD);
    }
    if busy {
        return Err(BUSY);
    }
    if !uac_ok {
        return Err(UAC_OFF);
    }
    Ok(())
}

pub fn answer_request(request: &ElevationRequest) -> ElevationStatus {
    match request.union {
        Some(elevation_request::Union::Direct(_)) => status(State::Denied, NOT_AVAILABLE),
        Some(elevation_request::Union::Logon(_)) => {
            hbb_common::throttled_log!(
                Duration::from_secs(60),
                warn,
                "elevation: refused a request that carried credentials"
            );
            status(State::Denied, NO_CREDENTIALS)
        }
        _ => status(State::Denied, NOT_AVAILABLE),
    }
}

/// Between a connection and the connection manager (both directions).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CmMessage {
    /// Show the request: the person has `decision_secs` to answer; `minutes` is the grant's time limit.
    Prompt { nonce: String, decision_secs: u64, minutes: u64 },
    /// The request is over; hide it.
    Close,
    /// The person's answer; `uac_declined` when Allow was pressed but the Windows prompt was refused.
    Decision { allow: bool, uac_declined: bool },
}

/// What the connection has to do after an event of the flow.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Controller(ElevationStatus),
    Cm(CmMessage),
    /// Withdraw the request from the service.
    Cancel(String),
}

/// Grant time limit shown to the person (spec F6 default; the service enforces it with E8).
pub const GRANT_MINUTES: u64 = 30;

#[derive(Debug)]
struct PendingRequest {
    nonce: String,
    deadline: Instant,
    allowed: bool,
}

/// One connection's request: created after the service accepted it, ended by the person's answer, the Windows
/// prompt, a timeout or the connection closing.
#[derive(Debug, Default)]
pub struct ConnElevation {
    pending: Option<PendingRequest>,
}

impl ConnElevation {
    pub fn busy(&self) -> bool {
        self.pending.is_some()
    }

    pub fn created(&mut self, nonce: String, now: Instant) -> Vec<Action> {
        self.pending = Some(PendingRequest {
            nonce: nonce.clone(),
            deadline: now + Duration::from_secs(DECISION_SECS),
            allowed: false,
        });
        vec![
            Action::Controller(status(State::Requested, "")),
            Action::Cm(CmMessage::Prompt {
                nonce,
                decision_secs: DECISION_SECS,
                minutes: GRANT_MINUTES,
            }),
        ]
    }

    pub fn decision(&mut self, allow: bool, uac_declined: bool, now: Instant) -> Vec<Action> {
        let Some(pending) = self.pending.as_mut() else {
            return vec![];
        };
        if allow && !uac_declined {
            // The proof is on its way to the service; the grant (E8) ends the wait, the deadline bounds it.
            pending.allowed = true;
            pending.deadline = now + Duration::from_secs(PROOF_SECS);
            return vec![Action::Cm(CmMessage::Close)];
        }
        let reason = if uac_declined { UAC_DECLINED } else { DENIED_LOCALLY };
        self.end(State::Denied, reason)
    }

    pub fn tick(&mut self, now: Instant) -> Vec<Action> {
        match self.pending.as_ref() {
            Some(p) if now >= p.deadline => self.end(State::Expired, ""),
            _ => vec![],
        }
    }

    pub fn closed(&mut self) -> Vec<Action> {
        match self.pending.take() {
            Some(p) => vec![Action::Cancel(p.nonce), Action::Cm(CmMessage::Close)],
            None => vec![],
        }
    }

    fn end(&mut self, state: State, reason: &str) -> Vec<Action> {
        match self.pending.take() {
            Some(p) => vec![
                Action::Cancel(p.nonce),
                Action::Cm(CmMessage::Close),
                Action::Controller(status(state, reason)),
            ],
            None => vec![],
        }
    }
}

/// Asks the service to record a request; the reply carries the nonce for the UAC proof.
#[cfg(windows)]
pub async fn create_in_service(conn_id: i32, serial: u64) -> Result<String, String> {
    use super::elevation_grant::{ServiceReply, ServiceRequest};
    match call_service(ServiceRequest::Create { conn_id, serial }).await {
        Ok(ServiceReply::Created(nonce)) => Ok(nonce),
        Ok(ServiceReply::Denied(why)) => Err(why),
        Ok(other) => Err(format!("unexpected answer from the service: {:?}", other)),
        Err(err) => Err(err.to_string()),
    }
}

#[cfg(windows)]
pub fn cancel_in_service(nonce: String) {
    use super::elevation_grant::ServiceRequest;
    tokio::spawn(async move {
        if let Err(err) = call_service(ServiceRequest::Cancel { nonce }).await {
            hbb_common::log::warn!("elevation: could not withdraw a request from the service: {}", err);
        }
    });
}

#[cfg(windows)]
pub async fn call_service(
    request: super::elevation_grant::ServiceRequest,
) -> hbb_common::ResultType<super::elevation_grant::ServiceReply> {
    let mut conn = crate::ipc::connect_service(1000).await?;
    conn.send(&crate::ipc::Data::Elevation(request)).await?;
    match conn.next_timeout(3000).await? {
        Some(crate::ipc::Data::ElevationReply(reply)) => Ok(reply),
        _ => hbb_common::bail!("no reply from the service"),
    }
}

/// `--elevation-proof <nonce>`: started elevated through the UAC prompt; hands the nonce to the service, which
/// checks this process (E8), and exits.
#[cfg(windows)]
#[tokio::main(flavor = "current_thread")]
pub async fn send_proof(nonce: &str) {
    use super::elevation_grant::ServiceRequest;
    let request = ServiceRequest::Proof {
        nonce: nonce.to_owned(),
    };
    match call_service(request).await {
        Ok(reply) => hbb_common::log::info!("elevation proof: the service answered {:?}", reply),
        Err(err) => hbb_common::log::error!("elevation proof: no answer from the service: {}", err),
    }
}

pub fn answer_drop() -> ElevationStatus {
    status(State::None, "")
}

pub fn message(status: ElevationStatus) -> Message {
    let mut misc = Misc::new();
    misc.set_elevation_status(status);
    let mut msg = Message::new();
    msg.set_misc(misc);
    msg
}

pub fn status(state: State, reason: &str) -> ElevationStatus {
    ElevationStatus {
        state: state.into(),
        reason: reason.to_owned(),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base::message_proto::ElevationRequestWithLogon;

    #[test]
    fn elevation_needs_uac_prompting_on_the_secure_desktop() {
        let p = |enable_lua, consent_prompt_behavior_admin, prompt_on_secure_desktop| UacPolicy {
            enable_lua,
            consent_prompt_behavior_admin,
            prompt_on_secure_desktop,
        };
        assert!(uac_allows_elevation(&p(1, 5, 1)), "Windows default");
        assert!(uac_allows_elevation(&p(1, 2, 0)), "always the secure desktop");
        assert!(!uac_allows_elevation(&p(0, 5, 1)), "UAC off");
        assert!(!uac_allows_elevation(&p(1, 0, 1)), "administrators elevated without a prompt");
        assert!(!uac_allows_elevation(&p(1, 5, 0)), "prompt on the normal desktop");
    }

    #[test]
    fn a_request_needs_keyboard_permission_no_pending_request_and_uac() {
        assert_eq!(check_request(true, false, true), Ok(()));
        assert_eq!(check_request(false, false, true), Err(NO_KEYBOARD));
        assert_eq!(check_request(true, true, true), Err(BUSY));
        assert_eq!(check_request(true, false, false), Err(UAC_OFF));
    }

    fn controller_states(actions: &[Action]) -> Vec<State> {
        actions
            .iter()
            .filter_map(|a| match a {
                Action::Controller(s) => s.state.enum_value().ok(),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn the_person_decides_within_the_time_limit() {
        let t0 = Instant::now();
        let mut flow = ConnElevation::default();
        let a = flow.created("n".into(), t0);
        assert_eq!(controller_states(&a), vec![State::Requested]);
        assert!(a.iter().any(|a| matches!(a, Action::Cm(CmMessage::Prompt { .. }))));
        assert!(flow.busy());

        let a = flow.decision(false, false, t0);
        assert_eq!(controller_states(&a), vec![State::Denied]);
        assert!(a.contains(&Action::Cancel("n".into())));
        assert!(!flow.busy());

        flow.created("n".into(), t0);
        assert_eq!(flow.tick(t0 + Duration::from_secs(DECISION_SECS - 1)), vec![]);
        let a = flow.tick(t0 + Duration::from_secs(DECISION_SECS));
        assert_eq!(controller_states(&a), vec![State::Expired]);
        assert!(a.contains(&Action::Cm(CmMessage::Close)));

        flow.created("n".into(), t0);
        let a = flow.decision(true, true, t0);
        assert_eq!(controller_states(&a), vec![State::Denied]);
        assert!(a.iter().any(|a| matches!(a, Action::Controller(s) if s.reason == UAC_DECLINED)));
    }

    #[test]
    fn after_allow_the_wait_for_the_windows_prompt_is_bounded() {
        let t0 = Instant::now();
        let mut flow = ConnElevation::default();
        flow.created("n".into(), t0);
        let later = t0 + Duration::from_secs(DECISION_SECS - 1);
        assert_eq!(flow.decision(true, false, later), vec![Action::Cm(CmMessage::Close)]);
        assert_eq!(flow.tick(t0 + Duration::from_secs(DECISION_SECS + 1)), vec![]);
        let a = flow.tick(later + Duration::from_secs(PROOF_SECS));
        assert_eq!(controller_states(&a), vec![State::Expired]);
        assert_eq!(flow.decision(true, false, later), vec![], "an answer after the end is ignored");
        flow.created("m".into(), t0);
        assert_eq!(flow.closed(), vec![Action::Cancel("m".into()), Action::Cm(CmMessage::Close)]);
    }

    #[test]
    fn credentials_from_the_controller_are_refused() {
        let mut request = ElevationRequest::new();
        request.set_logon(ElevationRequestWithLogon {
            username: "administrator".to_owned(),
            password: "secret".to_owned(),
            ..Default::default()
        });
        let answer = answer_request(&request);
        assert_eq!(answer.state.enum_value(), Ok(State::Denied));
        assert_eq!(answer.reason, NO_CREDENTIALS);
    }

    #[test]
    fn a_request_is_never_granted_before_the_grant_machinery_exists() {
        let mut request = ElevationRequest::new();
        request.set_direct(true);
        assert_eq!(answer_request(&request).state.enum_value(), Ok(State::Denied));
        assert_eq!(answer_request(&ElevationRequest::new()).state.enum_value(), Ok(State::Denied));
        assert_eq!(answer_drop().state.enum_value(), Ok(State::None));
    }
}
