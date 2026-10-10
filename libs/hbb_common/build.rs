// The server address and key are baked in at build time from the environment or the git-ignored
// `.env` in the repository root (see `.env.example`).
fn bake_from_dotenv() {
    let path = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("../../.env");
    println!("cargo:rerun-if-changed={}", path.display());
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    for name in ["HANDOVER_RENDEZVOUS_SERVER", "HANDOVER_SERVER_KEY", "HANDOVER_CONTROLLER_CA"] {
        println!("cargo:rerun-if-env-changed={name}");
        if std::env::var_os(name).is_some() {
            continue;
        }
        let prefix = format!("{name}=");
        if let Some(value) = text
            .lines()
            .filter_map(|l| l.trim().strip_prefix(prefix.as_str()))
            .next()
        {
            let value = value.trim().trim_matches(|c| c == '"' || c == '\'');
            if !value.is_empty() {
                println!("cargo:rustc-env={name}={value}");
            }
        }
    }
}

fn main() {
    bake_from_dotenv();
    let out_dir = format!("{}/protos", std::env::var("OUT_DIR").unwrap());

    std::fs::create_dir_all(&out_dir).unwrap();

    protobuf_codegen::Codegen::new()
        .pure()
        .out_dir(out_dir)
        .inputs(["protos/rendezvous.proto"])
        .include("protos")
        .customize(protobuf_codegen::Customize::default().tokio_bytes(true))
        .run()
        .expect("Codegen failed.");
}
