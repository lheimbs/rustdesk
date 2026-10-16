//! Controller side of administrator access (`docs/ELEVATION_SPEC.md` F3, story E6): passes the state the controlled
//! side reports to the UI and explains the end states. The controller never sends credentials (S6).

use crate::{
    client::Interface,
    ui_session_interface::{InvokeUiSession, Session},
};
use base::message_proto::{elevation_status::State, ElevationStatus};

pub const TITLE: &str = "Administrator access";

pub fn on_status<T: InvokeUiSession>(handler: &Session<T>, status: &ElevationStatus) {
    let state = status.state.enum_value().unwrap_or(State::None);
    handler.elevation_status(state as i32, status.expires_in_secs, &status.reason);
    if let Some(text) = notice(state, &status.reason) {
        handler.msgbox("custom-nocancel-nook-hasclose", TITLE, text, "");
    }
}

/// The message shown when a request or a grant ends; none for the states the toolbar badge already shows.
pub fn notice(state: State, reason: &str) -> Option<&str> {
    match state {
        State::Denied if !reason.is_empty() => Some(reason),
        State::Denied => Some("Administrator access was denied"),
        State::Expired => Some("Administrator access has expired"),
        State::Revoked => Some("Administrator access was ended on the remote machine"),
        State::None | State::Requested | State::Granted => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn end_states_are_explained_and_running_states_are_not() {
        assert_eq!(
            notice(State::Denied, "Credentials from the controller are not accepted"),
            Some("Credentials from the controller are not accepted")
        );
        assert_eq!(notice(State::Denied, ""), Some("Administrator access was denied"));
        assert!(notice(State::Expired, "").is_some());
        assert!(notice(State::Revoked, "").is_some());
        assert_eq!(notice(State::None, ""), None);
        assert_eq!(notice(State::Requested, ""), None);
        assert_eq!(notice(State::Granted, ""), None);
    }
}
