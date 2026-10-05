use hbb_common::{chrono, config::Config, log};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

const MAX_BYTES: u64 = 5 * 1024 * 1024;
const MAX_FIELD_CHARS: usize = 120;

fn log_file() -> PathBuf {
    Config::log_path().join("connections.log")
}

/// Peer-controlled text (display name, id) must not be able to forge log lines.
fn clean(field: &str) -> String {
    field
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_FIELD_CHARS)
        .collect()
}

fn append_line(path: &Path, line: &str) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    if fs::metadata(path).map(|m| m.len() > MAX_BYTES).unwrap_or(false) {
        fs::rename(path, path.with_extension("log.old"))?;
    }
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    writeln!(options.open(path)?, "{line}")
}

/// Append one line to the local connection log (who connected, when, what happened).
pub fn record(conn_id: i32, event: &str, detail: &str) {
    let line = format!(
        "{} #{} {} {}",
        chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%z"),
        conn_id,
        event,
        clean(detail)
    );
    if let Err(err) = append_line(&log_file(), &line) {
        log::error!("Failed to write the connection log: {}", err);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_text_cannot_forge_a_log_line() {
        let cleaned = clean("evil\n2026-01-01T00:00:00+0000 #1 accepted admin");
        assert!(!cleaned.contains('\n'));
        let path = std::env::temp_dir().join(format!("handover_connlog_{}.log", std::process::id()));
        let _ = fs::remove_file(&path);
        append_line(&path, &format!("a {cleaned}")).unwrap();
        append_line(&path, "b").unwrap();
        let text = fs::read_to_string(&path).unwrap();
        let _ = fs::remove_file(&path);
        assert_eq!(text.lines().count(), 2);
    }
}
