//! The upstream auto-updater (download from GitHub, run the installer as root/SYSTEM) is not part of Handover.
//! What remains is the session bookkeeping other modules still call.
use hbb_common::ResultType;
use std::{
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

static CONTROLLING_SESSION_COUNT: AtomicUsize = AtomicUsize::new(0);

pub fn update_controlling_session_count(count: usize) {
    CONTROLLING_SESSION_COUNT.store(count, Ordering::SeqCst);
}

#[allow(dead_code)]
pub fn start_auto_update() {}

#[allow(dead_code)]
pub fn manually_check_update() -> ResultType<()> {
    Ok(())
}

#[inline]
/// Returns true when there are no active incoming or outgoing connections.
pub fn has_no_active_conns() -> bool {
    let conns = crate::Connection::alive_conns();
    conns.is_empty() && has_no_controlling_conns()
}

#[cfg(any(not(target_os = "windows"), feature = "flutter"))]
fn has_no_controlling_conns() -> bool {
    CONTROLLING_SESSION_COUNT.load(Ordering::SeqCst) == 0
}

#[cfg(not(any(not(target_os = "windows"), feature = "flutter")))]
fn has_no_controlling_conns() -> bool {
    let app_exe = format!("{}.exe", crate::get_app_name().to_lowercase());
    for arg in [
        "--connect",
        "--play",
        "--file-transfer",
        "--view-camera",
        "--port-forward",
        "--rdp",
    ] {
        if !crate::platform::get_pids_of_process_with_first_arg(&app_exe, arg).is_empty() {
            return false;
        }
    }
    true
}

pub fn get_download_file_from_url(_url: &str) -> Option<PathBuf> {
    None
}

#[cfg(target_os = "macos")]
pub fn start_auto_update_macos() {}

/// macOS is not a supported target; assume sessions may be active.
#[cfg(target_os = "macos")]
pub fn has_no_active_conns_ipc() -> bool {
    false
}
