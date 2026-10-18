//! Who sees the one-time password (docs/APPROVAL_SPEC.md, story A4): only a person who could approve a connection.
//! This is convenience, not the gate: the gate is the service-verified approval itself.

#[cfg(target_os = "linux")]
mod linux {
    use hbb_common::tokio;
    use std::{
        sync::{
            atomic::{AtomicBool, AtomicU8, Ordering},
            Mutex,
        },
        time::{Duration, Instant},
    };

    const UNKNOWN: u8 = 0;
    const YES: u8 = 1;
    const NO: u8 = 2;
    static STATE: AtomicU8 = AtomicU8::new(UNKNOWN);
    static ASKING: AtomicBool = AtomicBool::new(false);
    static LAST: Mutex<Option<Instant>> = Mutex::new(None);

    #[tokio::main(flavor = "current_thread")]
    async fn ask() {
        let answer = match tokio::time::timeout(Duration::from_millis(1500), crate::server::approval_linux::check()).await {
            Ok(Ok(())) => YES,
            _ => NO,
        };
        STATE.store(answer, Ordering::SeqCst);
    }

    fn refresh() {
        if ASKING.swap(true, Ordering::SeqCst) {
            return;
        }
        std::thread::spawn(|| {
            ask();
            ASKING.store(false, Ordering::SeqCst);
        });
    }

    /// The first call waits for the answer (at most about 1.5 s); later calls answer from the last one and refresh it in the background.
    pub fn is_approver() -> bool {
        let first = STATE.load(Ordering::SeqCst) == UNKNOWN;
        let stale = LAST.lock().map(|mut l| {
            let stale = l.map_or(true, |t| t.elapsed() > Duration::from_secs(5));
            if stale {
                *l = Some(Instant::now());
            }
            stale
        });
        if first {
            ask();
        } else if stale.unwrap_or(false) {
            refresh();
        }
        STATE.load(Ordering::SeqCst) == YES
    }
}

pub fn is_approver() -> bool {
    #[cfg(windows)]
    {
        return crate::platform::windows::current_user_is_admin();
    }
    #[cfg(target_os = "linux")]
    {
        return linux::is_approver();
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    true
}
