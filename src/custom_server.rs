use hbb_common::{bail, ResultType};
use serde_derive::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Default, Serialize, Deserialize, Clone)]
pub struct CustomServer {
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub api: String,
    #[serde(default)]
    pub relay: String,
}

pub fn get_custom_server_from_string(_s: &str) -> ResultType<CustomServer> {
    bail!("custom server configuration is not supported");
}
