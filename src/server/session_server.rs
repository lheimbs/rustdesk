//! Which `--server` the Windows service runs for a console session. While a user is signed in the server
//! runs as that user with the normal token (tier 0, see `docs/ELEVATION_SPEC.md`); with nobody signed in it is
//! the sign-in server with the SYSTEM token, as before.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerKind {
    User,
    SignIn,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Running {
    pub session_id: u32,
    pub kind: ServerKind,
}

/// `session_user` is the user name Windows reports for the session; it is empty at the sign-in screen.
pub fn server_kind(session_user: &str) -> ServerKind {
    if session_user.trim().is_empty() {
        ServerKind::SignIn
    } else {
        ServerKind::User
    }
}

/// A server has to be (re)launched when none runs, the one that runs has exited, or it serves another
/// session or kind than the one wanted now.
pub fn should_relaunch(running: Option<Running>, wanted: Running, process_alive: bool) -> bool {
    !process_alive || running != Some(wanted)
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER: Running = Running {
        session_id: 1,
        kind: ServerKind::User,
    };

    #[test]
    fn empty_or_blank_user_name_means_sign_in_screen() {
        assert_eq!(server_kind(""), ServerKind::SignIn);
        assert_eq!(server_kind("  "), ServerKind::SignIn);
        assert_eq!(server_kind("alice"), ServerKind::User);
    }

    #[test]
    fn nothing_runs_or_process_died_means_relaunch() {
        assert!(should_relaunch(None, USER, false));
        assert!(should_relaunch(Some(USER), USER, false));
    }

    #[test]
    fn sign_in_to_user_in_the_same_session_means_relaunch() {
        let sign_in = Running {
            kind: ServerKind::SignIn,
            ..USER
        };
        assert!(should_relaunch(Some(sign_in), USER, true));
        assert!(should_relaunch(Some(USER), sign_in, true));
    }

    #[test]
    fn session_change_means_relaunch_and_same_state_means_none() {
        let other = Running {
            session_id: 3,
            ..USER
        };
        assert!(should_relaunch(Some(other), USER, true));
        assert!(!should_relaunch(Some(USER), USER, true));
    }
}
