//! Tier 0 on Windows (`docs/ELEVATION_SPEC.md` F2, story E5). While the server runs as the signed-in user, the
//! lock screen, the sign-in screen and UAC prompts are protected: no pixels of them are captured or sent, no
//! controller input reaches them, and the controller sees a notice instead. A locked session counts as
//! protected even while the lock-screen picture is still drawn on the normal desktop (plan 2s).
//!
//! The SYSTEM server (sign-in screen, upstream behaviour) is never affected: the state applies only where the
//! machine identity is brokered, i.e. in the user-level server.
#![cfg_attr(not(windows), allow(dead_code))]

use super::service::{GenericService, Service};
use base::message_proto::{Message, Misc};
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

const RECHECK: Duration = Duration::from_millis(100);
const WAIT_STEP: Duration = Duration::from_millis(250);

/// Protected when the server is the user-level one and the session is locked or another desktop (UAC prompt,
/// sign-in screen) has the input.
pub fn decide(user_level: bool, locked: bool, input_desktop_is_ours: bool) -> bool {
    user_level && (locked || !input_desktop_is_ours)
}

fn evaluate() -> bool {
    #[cfg(windows)]
    {
        let user_level = hbb_common::config::Config::is_brokered_identity();
        // Tier 1 (elevation E9): the SYSTEM helper captures and injects, the secure desktop is no longer out of reach.
        if !user_level || crate::portable_service::client::running() {
            return false;
        }
        decide(
            user_level,
            crate::platform::windows::is_locked(),
            !crate::platform::windows::desktop_changed(),
        )
    }
    #[cfg(not(windows))]
    {
        false
    }
}

lazy_static::lazy_static! {
    static ref LAST: Mutex<Option<(Instant, bool)>> = Default::default();
}

/// The current state, evaluated at most every 100 ms (input events can arrive far more often).
pub fn is_protected() -> bool {
    let mut last = LAST.lock().unwrap();
    if let Some((at, value)) = *last {
        if at.elapsed() < RECHECK {
            return value;
        }
    }
    let value = evaluate();
    *last = Some((Instant::now(), value));
    value
}

/// The current state, evaluated now. The video loop asks this after each capture, so a frame taken just as the
/// screen became protected is dropped instead of sent.
pub fn protected_now() -> bool {
    let value = evaluate();
    *LAST.lock().unwrap() = Some((Instant::now(), value));
    value
}

/// Whether a key or button release may still be injected while protected: only while the input desktop is the
/// user's own (locked, splash still on the normal desktop). On a secure desktop it cannot be delivered anyway.
pub fn release_passes() -> bool {
    #[cfg(windows)]
    {
        !crate::platform::windows::desktop_changed()
    }
    #[cfg(not(windows))]
    {
        true
    }
}

fn notice(on: bool) -> Message {
    let mut misc = Misc::new();
    misc.set_protected_screen(on);
    let mut msg = Message::new();
    msg.set_misc(misc);
    msg
}

/// Called by the video loop before it captures. While the screen is protected it captures nothing, tells the
/// controllers once and waits; afterwards it withdraws the notice. Returns true when it waited, so the caller
/// starts a fresh capturer (the desktop may have changed under the old one).
pub fn wait_while_protected(sp: &GenericService) -> bool {
    if !is_protected() {
        return false;
    }
    hbb_common::log::info!("protected screen: video paused");
    sp.send(notice(true));
    while sp.ok() && is_protected() {
        std::thread::sleep(WAIT_STEP);
    }
    sp.send(notice(false));
    hbb_common::log::info!("protected screen: video resumed");
    true
}

#[cfg(test)]
mod tests {
    use super::decide;

    #[test]
    fn only_the_user_level_server_treats_lock_and_secure_desktops_as_protected() {
        assert!(!decide(true, false, true), "normal desktop");
        assert!(decide(true, true, true), "locked, lock picture still on the normal desktop");
        assert!(decide(true, false, false), "UAC prompt or sign-in screen has the input");
        assert!(decide(true, true, false), "locked and sign-in screen");
        assert!(!decide(false, true, false), "SYSTEM server keeps upstream behaviour");
    }
}
