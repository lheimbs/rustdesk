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
use super::elevation_grant::ServiceReply;
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
    /// Administrator access is active for `minutes_left` more minutes; show it and a Stop button (F9, S8).
    Active { minutes_left: u64 },
    /// The request or grant is over; hide it.
    Close,
    /// The person's answer; `uac_declined` when Allow was pressed but the Windows prompt was refused.
    Decision { allow: bool, uac_declined: bool },
    /// The person ends administrator access.
    Stop,
}

/// What the connection has to do after an event of the flow.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Controller(ElevationStatus),
    Cm(CmMessage),
    /// Withdraw the request or end the grant in the service; `true`: keep its resume grant (the connection closed).
    Withdraw(String, bool),
    /// A line for the local connection log (F9).
    Log(&'static str, String),
    /// Start the privileged helper for this grant (E9).
    StartHelper(String),
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Phase {
    /// Waiting for the person's Allow or Deny.
    Asked,
    /// Allow pressed and the UAC prompt passed: waiting for the service to accept the proof.
    Allowed,
    Granted,
}

#[derive(Debug)]
struct Current {
    nonce: String,
    phase: Phase,
    /// End of the current phase: the decision time, the proof time, or the grant's time limit.
    deadline: Instant,
}

/// One connection's request and grant (spec 4.3/4.4): created after the service accepted the request, ended by
/// the person's answer, the Windows prompt, a time limit, the controller's drop, the local Stop, the service, or
/// the connection closing.
#[derive(Debug, Default)]
pub struct ConnElevation {
    current: Option<Current>,
}

impl ConnElevation {
    pub fn busy(&self) -> bool {
        self.current.is_some()
    }

    /// The nonce to ask the service about: while it checks a proof, and during a grant.
    pub fn poll_target(&self) -> Option<String> {
        self.current
            .as_ref()
            .filter(|c| c.phase != Phase::Asked)
            .map(|c| c.nonce.clone())
    }

    pub fn created(&mut self, nonce: String, now: Instant) -> Vec<Action> {
        self.current = Some(Current {
            nonce: nonce.clone(),
            phase: Phase::Asked,
            deadline: now + Duration::from_secs(DECISION_SECS),
        });
        vec![
            Action::Controller(status(State::Requested, "")),
            Action::Cm(CmMessage::Prompt {
                nonce,
                decision_secs: DECISION_SECS,
                minutes: super::elevation_grant::grant_minutes(),
            }),
            Action::Log("elevation-requested", String::new()),
        ]
    }

    pub fn decision(&mut self, allow: bool, uac_declined: bool, now: Instant) -> Vec<Action> {
        let Some(current) = self.current.as_mut().filter(|c| c.phase == Phase::Asked) else {
            return vec![];
        };
        if allow && !uac_declined {
            current.phase = Phase::Allowed;
            current.deadline = now + Duration::from_secs(PROOF_SECS);
            return vec![Action::Cm(CmMessage::Close)];
        }
        let reason = if uac_declined { UAC_DECLINED } else { DENIED_LOCALLY };
        self.end(State::Denied, reason, "elevation-denied")
    }

    /// The service's answer to a poll; `None` when the service could not be asked.
    pub fn polled(&mut self, reply: Option<ServiceReply>, now: Instant) -> Vec<Action> {
        let Some(phase) = self.current.as_ref().map(|c| c.phase) else {
            return vec![];
        };
        match (phase, reply) {
            (Phase::Allowed | Phase::Granted, Some(ServiceReply::Granted { secs_left, account, resume })) => {
                let Some(current) = self.current.as_mut() else {
                    return vec![];
                };
                current.deadline = now + Duration::from_secs(secs_left);
                if phase == Phase::Granted {
                    return vec![];
                }
                current.phase = Phase::Granted;
                let nonce = current.nonce.clone();
                let mut granted = status(State::Granted, "");
                granted.expires_in_secs = secs_left as u32;
                let keep = !resume.is_empty();
                granted.resume_secret = resume.into();
                vec![
                    Action::Controller(granted),
                    Action::Cm(CmMessage::Active {
                        minutes_left: (secs_left + 59) / 60,
                    }),
                    Action::Log(
                        "elevation-granted",
                        format!("approved by {}{}", account, if keep { ", keep connected" } else { "" }),
                    ),
                    Action::StartHelper(nonce),
                ]
            }
            (Phase::Allowed, Some(ServiceReply::Waiting)) => vec![],
            // A grant the service no longer knows (sign-out, user switch, service restart) or cannot confirm
            // is over: fail closed.
            (Phase::Granted, _) => self.end(State::Revoked, "", "elevation-revoked"),
            _ => vec![],
        }
    }

    pub fn tick(&mut self, now: Instant) -> Vec<Action> {
        match self.current.as_ref() {
            Some(c) if now >= c.deadline => self.end(State::Expired, "", "elevation-expired"),
            _ => vec![],
        }
    }

    /// The controller gives up administrator access (or withdraws its request).
    pub fn dropped(&mut self) -> Vec<Action> {
        let mut actions = self.end(State::None, "", "elevation-dropped");
        if actions.is_empty() {
            actions.push(Action::Controller(status(State::None, "")));
        }
        actions
    }

    /// The person at the machine stops administrator access (CM Stop).
    pub fn stopped(&mut self) -> Vec<Action> {
        if self.current.as_ref().map_or(true, |c| c.phase != Phase::Granted) {
            return vec![];
        }
        self.end(State::Revoked, "", "elevation-stopped")
    }

    pub fn closed(&mut self) -> Vec<Action> {
        match self.current.take() {
            Some(c) => vec![
                Action::Withdraw(c.nonce, true),
                Action::Cm(CmMessage::Close),
                Action::Log("elevation-ended", "connection closed".to_owned()),
            ],
            None => vec![],
        }
    }

    fn end(&mut self, state: State, reason: &str, event: &'static str) -> Vec<Action> {
        match self.current.take() {
            Some(c) => vec![
                Action::Withdraw(c.nonce, false),
                Action::Cm(CmMessage::Close),
                Action::Controller(status(state, reason)),
                Action::Log(event, reason.to_owned()),
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

/// APPROVAL_SPEC.md: ask the service whether an administrator is signed in at this session. No answer: refuse (fail closed).
#[cfg(windows)]
pub async fn approval_check() -> Result<(), super::approval::Refusal> {
    use super::{approval::Refusal, elevation_grant::{ServiceReply, ServiceRequest}};
    match call_service(ServiceRequest::ApprovalCheck).await {
        Ok(ServiceReply::Done) => Ok(()),
        Ok(ServiceReply::Denied(word)) => Err(Refusal::from_log_word(&word)),
        _ => Err(Refusal::ServiceUnavailable),
    }
}

/// The Accept click is not enough (APPROVAL_SPEC.md): the administrator answers the Windows (UAC) prompt, and the service
/// confirms that proof. Uses the E7/E8 request, ended again at once: this approves the connection, it grants no tier 1.
#[cfg(windows)]
pub async fn approve_connection(conn_id: i32, serial: u64) -> bool {
    use super::elevation_grant::ServiceReply;
    let Ok(nonce) = create_in_service(conn_id, serial).await else {
        return false;
    };
    let arg = format!("--elevation-proof {}", nonce);
    std::thread::spawn(move || {
        if let Err(err) = crate::platform::elevate(&arg) {
            hbb_common::log::warn!("approval: the UAC prompt could not be started: {}", err);
        }
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(PROOF_SECS);
    let mut granted = false;
    while std::time::Instant::now() < deadline {
        match poll_service(nonce.clone()).await {
            Some(ServiceReply::Granted { .. }) => {
                granted = true;
                break;
            }
            Some(ServiceReply::Waiting) | None => {}
            Some(_) => break, // denied or gone
        }
        hbb_common::tokio::time::sleep(Duration::from_millis(300)).await;
    }
    withdraw_in_service(nonce, false);
    granted
}

#[cfg(windows)]
pub fn withdraw_in_service(nonce: String, keep_resume: bool) {
    use super::elevation_grant::ServiceRequest;
    tokio::spawn(async move {
        if let Err(err) = call_service(ServiceRequest::End { nonce, keep_resume }).await {
            hbb_common::log::warn!("elevation: could not end a request or grant in the service: {}", err);
        }
    });
}

/// Runs on its own thread (from the proxy's start): asks the service to start the helper on this shared memory.
#[cfg(windows)]
#[tokio::main(flavor = "current_thread")]
pub async fn start_helper_in_service(nonce: String, shmem_name: String) -> hbb_common::ResultType<()> {
    use super::elevation_grant::ServiceRequest;
    match call_service(ServiceRequest::StartHelper { nonce, shmem_name }).await? {
        ServiceReply::Done => Ok(()),
        other => hbb_common::bail!("{:?}", other),
    }
}

/// E10: is this login a valid resume of a "keep connected" grant? `token` is the controller's `resume_token`.
#[cfg(windows)]
pub async fn resume_check_in_service(token: &[u8], challenge: &str, peer_id: &str, serial: u64) -> Result<(), String> {
    use super::elevation_grant::ServiceRequest;
    if token.len() <= 16 || token.len() > 16 + 64 {
        return Err("malformed resume token".to_owned());
    }
    let (id, mac) = token.split_at(16);
    let request = ServiceRequest::ResumeCheck {
        id: id.to_vec(),
        mac: mac.to_vec(),
        challenge: challenge.to_owned(),
        peer_id: peer_id.to_owned(),
        serial,
    };
    match call_service(request).await {
        Ok(ServiceReply::Done) => Ok(()),
        Ok(ServiceReply::Denied(why)) => Err(why),
        Ok(other) => Err(format!("{:?}", other)),
        Err(err) => Err(err.to_string()),
    }
}

/// The service's view of a request or grant; `None` if it cannot be asked (treated as "gone" for a grant).
#[cfg(windows)]
pub async fn poll_service(nonce: String) -> Option<ServiceReply> {
    use super::elevation_grant::ServiceRequest;
    call_service(ServiceRequest::Poll { nonce }).await.ok()
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
pub async fn send_proof(nonce: &str, keep: bool) {
    use super::elevation_grant::ServiceRequest;
    let request = ServiceRequest::Proof {
        nonce: nonce.to_owned(),
        keep,
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
        assert!(a.contains(&Action::Withdraw("n".into(), false)));
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
        let a = flow.closed();
        assert!(a.contains(&Action::Withdraw("m".into(), true)) && a.contains(&Action::Cm(CmMessage::Close)));
        assert!(!flow.busy());
    }

    fn granted(flow: &mut ConnElevation, t0: Instant, secs_left: u64) {
        flow.created("n".into(), t0);
        flow.decision(true, false, t0);
        assert_eq!(flow.poll_target(), Some("n".into()));
        assert_eq!(flow.polled(Some(ServiceReply::Waiting), t0), vec![]);
        let a = flow.polled(
            Some(ServiceReply::Granted {
                secs_left,
                account: "PC\\admin".into(),
                resume: vec![],
            }),
            t0,
        );
        assert_eq!(controller_states(&a), vec![State::Granted]);
        assert!(a.iter().any(|a| matches!(a, Action::Controller(s) if s.expires_in_secs == secs_left as u32)));
        assert!(a.contains(&Action::Cm(CmMessage::Active { minutes_left: (secs_left + 59) / 60 })));
        assert!(a.contains(&Action::Log("elevation-granted", "approved by PC\\admin".into())));
        assert!(a.contains(&Action::StartHelper("n".into())), "the grant starts the helper (E9)");
    }

    #[test]
    fn a_grant_ends_by_time_limit_drop_local_stop_or_the_service() {
        let t0 = Instant::now();
        let mut flow = ConnElevation::default();
        granted(&mut flow, t0, 1800);
        assert_eq!(flow.tick(t0 + Duration::from_secs(1799)), vec![]);
        let a = flow.tick(t0 + Duration::from_secs(1800));
        assert_eq!(controller_states(&a), vec![State::Expired]);
        assert!(a.contains(&Action::Withdraw("n".into(), false)));

        granted(&mut flow, t0, 1800);
        assert_eq!(controller_states(&flow.dropped()), vec![State::None]);
        assert!(!flow.busy());

        granted(&mut flow, t0, 1800);
        assert_eq!(controller_states(&flow.stopped()), vec![State::Revoked]);

        granted(&mut flow, t0, 1800);
        let a = flow.polled(Some(ServiceReply::Gone("ended".into())), t0);
        assert_eq!(controller_states(&a), vec![State::Revoked]);

        granted(&mut flow, t0, 1800);
        let a = flow.polled(None, t0);
        assert_eq!(controller_states(&a), vec![State::Revoked], "service unreachable: fail closed");
    }

    #[test]
    fn out_of_order_messages_change_nothing() {
        let t0 = Instant::now();
        let mut flow = ConnElevation::default();
        assert_eq!(flow.polled(Some(ServiceReply::Granted { secs_left: 60, account: String::new(), resume: vec![] }), t0), vec![]);
        assert_eq!(flow.stopped(), vec![]);
        assert_eq!(flow.decision(true, false, t0), vec![]);
        flow.created("n".into(), t0);
        assert_eq!(flow.poll_target(), None, "nothing to poll before Allow");
        assert_eq!(
            flow.polled(Some(ServiceReply::Granted { secs_left: 60, account: String::new(), resume: vec![] }), t0),
            vec![],
            "a grant before Allow is ignored"
        );
        assert_eq!(flow.stopped(), vec![], "Stop only ends a grant");
        assert!(flow.busy());
        assert_eq!(controller_states(&flow.dropped()), vec![State::None], "the controller withdraws its request");
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
