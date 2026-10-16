//! Administrator access (tier 1) requests from the controller (`docs/ELEVATION_SPEC.md` F3, S6; story E6).
//! The controller asks with `ElevationRequest.direct` and gives up with `Misc.elevation_drop`; it is told the state
//! with `Misc.elevation_status`. Credentials from the controller (`ElevationRequest.logon`) are always refused.
//! The grant itself (local consent, UAC proof, privileged helper) comes with stories E7-E9; until then a request
//! is denied, so nothing here can raise a session above tier 0.

use base::message_proto::{
    elevation_request, elevation_status::State, ElevationRequest, ElevationStatus, Message, Misc,
};
use std::time::Duration;

pub const NOT_AVAILABLE: &str = "Administrator access is not available on this machine";
pub const NO_CREDENTIALS: &str = "Credentials from the controller are not accepted";

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

fn status(state: State, reason: &str) -> ElevationStatus {
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
