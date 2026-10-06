//! Stand-in for the upstream HTTP/API layer (Pro server API, accounts, downloads, uploads, strategy sync).
//! Handover talks to nothing but its own rendezvous/relay server and the peer, so every entry point that
//! outside code still calls is kept here and reports "not available". There is no HTTP client in this build.

pub mod downloader {
    use hbb_common::{bail, ResultType};
    use serde_derive::Serialize;
    use std::{path::PathBuf, time::Duration};

    #[derive(Serialize, Debug)]
    pub struct DownloadData {
        #[serde(skip_serializing_if = "Vec::is_empty")]
        pub data: Vec<u8>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub path: Option<PathBuf>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub total_size: Option<u64>,
        pub downloaded_size: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
    }

    pub fn download_file(
        _url: String,
        _path: Option<PathBuf>,
        _auto_del_dur: Option<Duration>,
    ) -> ResultType<String> {
        bail!("downloads are not available in this build");
    }

    pub fn get_download_data(_id: &str) -> ResultType<DownloadData> {
        bail!("downloads are not available in this build");
    }

    pub fn cancel(_id: &str) {}

    pub fn remove(_id: &str) {}
}

pub mod record_upload {
    use scrap::record::RecordState;
    use std::sync::mpsc::Receiver;

    pub fn is_enable() -> bool {
        false
    }

    pub fn run(_rx: Receiver<RecordState>) {}
}

#[allow(dead_code)]
pub mod sync {
    use hbb_common::{lazy_static, tokio::sync::broadcast};

    lazy_static::lazy_static! {
        static ref SENDER: broadcast::Sender<Vec<i32>> = broadcast::channel(1).0;
    }

    pub fn start() {}

    pub fn signal_receiver() -> broadcast::Receiver<Vec<i32>> {
        SENDER.subscribe()
    }

    pub fn is_pro() -> bool {
        false
    }

    pub fn register_switch_grant(_switch_uuid: String) {}
}

#[cfg(feature = "flutter")]
pub mod account {
    use serde::Serialize;

    #[derive(Serialize)]
    pub struct AuthResult {
        pub state_msg: String,
        pub failed_msg: String,
        pub url: Option<String>,
        pub auth_body: Option<serde_json::Value>,
    }

    pub struct OidcSession;

    impl OidcSession {
        pub fn account_auth(
            _api_server: String,
            _op: String,
            _id: String,
            _uuid: String,
            _remember_me: bool,
        ) {
        }

        pub fn auth_cancel() {}

        pub fn get_result() -> AuthResult {
            AuthResult {
                state_msg: "not available".to_owned(),
                failed_msg: "account login is not available in this build".to_owned(),
                url: None,
                auth_body: None,
            }
        }
    }
}
