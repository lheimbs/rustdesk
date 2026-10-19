//! Offline issuer for Handover credentials.
//!
//!   handover-ca init <dir>                                     create the issuer key (encrypted) and print its public key
//!   handover-ca issue <dir> --role controller|device --label <text> [--days N] [--holder-pub <key>] --out <file>
//!   handover-ca request <file>                                 on the holder's machine: make its secret, print its public key
//!   handover-ca combine <request file> <credential file> --ca-pub <key> --out <file>   holder: credential + own secret
//!   handover-ca inspect <file> [--ca-pub <base64 or file>]     show a credential; verify it when the public key is given
//!   handover-ca compact <file>                                 one-line form of a credential file (HANDOVER_DEVICE_CRED for a build)
//!
//! Run it on a machine that is not a controller. The issuer key never leaves <dir>/ca.key, which is encrypted with
//! a passphrase (Argon2id + XSalsa20-Poly1305). HANDOVER_CA_PASSPHRASE overrides the prompt (scripts and tests only).
//! With `--holder-pub` the holder's secret never reaches the issuer: `request` makes it where it is used, `issue` signs
//! only its public key, `combine` puts the two together there. Every issue is recorded in <dir>/issued.log (serials for
//! the servers' revocation file).

use base64::{engine::general_purpose::STANDARD, Engine};
use handover_cred::{
    decode_public_key, encode_public_key, holder_public_key, issue, new_holder, new_issuer, verify, HolderFile,
    IssuerSecretKey, Role,
};
use sodiumoxide::crypto::{pwhash::argon2id13, secretbox};
use std::{
    fs,
    io::{self, Write},
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const KEY_HEADER: &str = "handover-ca-key-v1";

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1)
}

fn passphrase(prompt: &str) -> String {
    if let Ok(p) = std::env::var("HANDOVER_CA_PASSPHRASE") {
        return p;
    }
    eprint!("{prompt}");
    io::stderr().flush().ok();
    let _ = Command::new("stty").arg("-echo").status();
    let mut line = String::new();
    let read = io::stdin().read_line(&mut line);
    let _ = Command::new("stty").arg("echo").status();
    eprintln!();
    if read.is_err() {
        die("could not read the passphrase");
    }
    line.trim_end_matches(['\r', '\n']).to_owned()
}

fn derive(pass: &str, salt: &argon2id13::Salt) -> secretbox::Key {
    let mut key = [0u8; secretbox::KEYBYTES];
    argon2id13::derive_key(
        &mut key,
        pass.as_bytes(),
        salt,
        argon2id13::OPSLIMIT_SENSITIVE,
        argon2id13::MEMLIMIT_INTERACTIVE,
    )
    .unwrap_or_else(|_| die("key derivation failed (not enough memory?)"));
    secretbox::Key(key)
}

fn write_secret(path: &Path, text: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap_or_else(|e| die(&format!("cannot create {}: {e}", path.display())));
        f.write_all(text.as_bytes()).unwrap_or_else(|e| die(&format!("cannot write {}: {e}", path.display())));
    }
    #[cfg(not(unix))]
    {
        if path.exists() {
            die(&format!("{} exists; refusing to overwrite it", path.display()));
        }
        fs::write(path, text).unwrap_or_else(|e| die(&format!("cannot write {}: {e}", path.display())));
        // only the current user, nothing inherited from the folder (#89)
        let user = std::env::var("USERNAME").unwrap_or_else(|_| die("USERNAME is not set"));
        let ok = Command::new("icacls")
            .arg(path)
            .args(["/inheritance:r", "/grant:r", &format!("{user}:F")])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            let _ = fs::remove_file(path);
            die(&format!("cannot restrict access to {}", path.display()));
        }
    }
}

/// The issuance ledger: what was issued, so a lost credential can be revoked by its serial (#86).
fn record_issue(dir: &Path, role: Role, label: &str, serial: u64, not_before: u64, not_after: u64, holder: &[u8]) {
    let line = format!(
        "{} serial={} role={} label={:?} not_before={} not_after={} holder={}\n",
        now(),
        serial,
        role.name(),
        label,
        not_before,
        not_after,
        STANDARD.encode(holder)
    );
    let written = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("issued.log"))
        .and_then(|mut f| f.write_all(line.as_bytes()));
    if let Err(e) = written {
        eprintln!("warning: could not record the issue in issued.log: {e}; note serial {serial}");
    }
}

fn load_issuer(dir: &Path) -> IssuerSecretKey {
    let text = fs::read_to_string(dir.join("ca.key")).unwrap_or_else(|e| die(&format!("cannot read ca.key: {e}")));
    let field = |name: &str| -> Vec<u8> {
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("{name}=")))
            .and_then(|v| STANDARD.decode(v.trim()).ok())
            .unwrap_or_else(|| die("ca.key is damaged"))
    };
    if text.lines().next() != Some(KEY_HEADER) {
        die("ca.key has an unknown format");
    }
    let salt = argon2id13::Salt::from_slice(&field("salt")).unwrap_or_else(|| die("ca.key is damaged"));
    let nonce = secretbox::Nonce::from_slice(&field("nonce")).unwrap_or_else(|| die("ca.key is damaged"));
    let key = derive(&passphrase("CA passphrase: "), &salt);
    let plain = secretbox::open(&field("ciphertext"), &nonce, &key).unwrap_or_else(|_| die("wrong passphrase"));
    IssuerSecretKey::from_slice(&plain).unwrap_or_else(|| die("ca.key is damaged"))
}

fn cmd_init(dir: &Path) {
    if dir.join("ca.key").exists() {
        die("ca.key already exists there; refusing to overwrite an issuer key");
    }
    fs::create_dir_all(dir).unwrap_or_else(|e| die(&format!("cannot create {}: {e}", dir.display())));
    let pass = passphrase("New CA passphrase: ");
    if pass.len() < 12 {
        die("use a passphrase of at least 12 characters");
    }
    if std::env::var("HANDOVER_CA_PASSPHRASE").is_err() && pass != passphrase("Repeat passphrase: ") {
        die("the passphrases differ");
    }
    let (pk, sk) = new_issuer();
    let salt = argon2id13::gen_salt();
    let nonce = secretbox::gen_nonce();
    let sealed = secretbox::seal(&sk.0, &nonce, &derive(&pass, &salt));
    write_secret(
        &dir.join("ca.key"),
        &format!(
            "{KEY_HEADER}\nsalt={}\nnonce={}\nciphertext={}\n",
            STANDARD.encode(salt.0),
            STANDARD.encode(nonce.0),
            STANDARD.encode(sealed)
        ),
    );
    fs::write(dir.join("ca.pub"), format!("{}\n", encode_public_key(&pk)))
        .unwrap_or_else(|e| die(&format!("cannot write ca.pub: {e}")));
    println!("issuer key written to {}/ca.key (encrypted; back it up offline)", dir.display());
    println!("public key (put this in .env of the build and in the server configuration):");
    println!("HANDOVER_CONTROLLER_CA={}", encode_public_key(&pk));
}

fn cmd_issue(dir: &Path, args: &[String]) {
    let (mut role, mut label, mut days, mut out, mut holder_pub) = (None, None, None, None, None);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let v = it.next().cloned().unwrap_or_else(|| die(&format!("{a} needs a value")));
        match a.as_str() {
            "--role" => role = Some(v),
            "--label" => label = Some(v),
            "--days" => days = Some(v.parse::<u64>().unwrap_or_else(|_| die("--days must be a number"))),
            "--out" => out = Some(v),
            "--holder-pub" => holder_pub = Some(decode_public_key(&v).unwrap_or_else(|| die("--holder-pub is not a public key"))),
            _ => die(&format!("unknown option {a}")),
        }
    }
    let role = match role.as_deref() {
        Some("controller") => Role::Controller,
        Some("device") => Role::Device,
        _ => die("--role controller|device is required"),
    };
    let label = label.unwrap_or_else(|| die("--label is required"));
    let out = out.unwrap_or_else(|| die("--out is required"));
    if Path::new(&out).exists() {
        die("the output file exists; refusing to overwrite it");
    }
    // controllers are people's laptops: short-lived, so a lost one stops working soon even if nobody revokes it (#86)
    let days = days.unwrap_or(if role == Role::Controller { 30 } else { 365 });
    if days == 0 || days > 3650 {
        die("--days must be between 1 and 3650");
    }
    let sk = load_issuer(dir);
    let (seed, pk) = match holder_pub {
        Some(pk) => (None, pk),
        None => {
            let (seed, pk) = new_holder();
            (Some(seed), pk)
        }
    };
    let serial = u64::from_be_bytes(sodiumoxide::randombytes::randombytes(8).try_into().unwrap_or([0; 8]));
    let (nb, na) = (now().saturating_sub(60), now() + days * 86_400);
    let cred = issue(&sk, role, &label, serial, nb, na, &pk).unwrap_or_else(|e| die(&e.to_string()));
    record_issue(dir, role, &label, serial, nb, na, &pk.0);
    match seed {
        Some(seed) => {
            let file = HolderFile { credential: cred, seed };
            write_secret(Path::new(&out), &file.to_text());
            println!("{} credential '{}' serial {} valid {} days -> {} (secret: keep private)", role.name(), label, serial, days, out);
        }
        None => {
            fs::write(&out, format!("credential={}\n", STANDARD.encode(&cred)))
                .unwrap_or_else(|e| die(&format!("cannot write {out}: {e}")));
            println!("{} credential '{}' serial {} valid {} days -> {} (no secret in it: give it to the holder for combine)", role.name(), label, serial, days, out);
        }
    }
}

const REQUEST_HEADER: &str = "# Handover credential request. SECRET: keep this file private; it never goes to the issuer.";

fn cmd_request(path: &str) {
    if Path::new(path).exists() {
        die("the request file exists; refusing to overwrite it");
    }
    let (seed, pk) = new_holder();
    write_secret(Path::new(path), &format!("{REQUEST_HEADER}\nsecret={}\n", STANDARD.encode(seed)));
    println!("secret written to {path}; give the issuer this public key (--holder-pub):");
    println!("{}", encode_public_key(&pk));
}

fn cmd_combine(request: &str, credential: &str, args: &[String]) {
    let (mut ca, mut out) = (None, None);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let v = it.next().cloned().unwrap_or_else(|| die(&format!("{a} needs a value")));
        match a.as_str() {
            "--ca-pub" => {
                let raw = fs::read_to_string(&v).unwrap_or_else(|_| v.clone());
                ca = Some(decode_public_key(&raw).unwrap_or_else(|| die("--ca-pub is not a public key")));
            }
            "--out" => out = Some(v),
            _ => die(&format!("unknown option {a}")),
        }
    }
    let (ca, out) = (ca.unwrap_or_else(|| die("--ca-pub is required")), out.unwrap_or_else(|| die("--out is required")));
    let field = |path: &str, name: &str| -> Vec<u8> {
        let text = fs::read_to_string(path).unwrap_or_else(|e| die(&format!("cannot read {path}: {e}")));
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("{name}=")))
            .and_then(|v| STANDARD.decode(v.trim()).ok())
            .unwrap_or_else(|| die(&format!("{path} has no {name}")))
    };
    let seed: [u8; 32] = field(request, "secret").try_into().unwrap_or_else(|_| die("the request file is damaged"));
    let cred = field(credential, "credential");
    let c = verify(&cred, &ca, now()).unwrap_or_else(|e| die(&format!("INVALID: {e}")));
    if c.holder != holder_public_key(&seed).0 {
        die("this credential was issued for another public key");
    }
    write_secret(Path::new(&out), &HolderFile { credential: cred, seed }.to_text());
    println!("{} credential '{}' serial {} -> {} (secret: keep private)", c.role.name(), c.label, c.serial, out);
}

fn cmd_inspect(path: &str, args: &[String]) {
    let text = fs::read_to_string(path).unwrap_or_else(|e| die(&format!("cannot read {path}: {e}")));
    let file = HolderFile::from_text(&text).unwrap_or_else(|e| die(&e.to_string()));
    let ca = match args {
        [flag, v] if flag == "--ca-pub" => {
            let raw = fs::read_to_string(v).unwrap_or_else(|_| v.clone());
            Some(decode_public_key(&raw).unwrap_or_else(|| die("--ca-pub is not a public key")))
        }
        [] => None,
        _ => die("usage: inspect <file> [--ca-pub <base64 or file>]"),
    };
    match ca {
        Some(pk) => match verify(&file.credential, &pk, now()) {
            Ok(c) => {
                let key_ok = c.holder == holder_public_key(&file.seed).0;
                println!(
                    "valid: role {} label '{}' serial {} not_before {} not_after {} secret-matches-credential {}",
                    c.role.name(), c.label, c.serial, c.not_before, c.not_after, key_ok
                );
            }
            Err(e) => die(&format!("INVALID: {e}")),
        },
        None => println!("credential of {} bytes (no --ca-pub given: signature not checked)", file.credential.len()),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("init") if args.len() == 2 => cmd_init(Path::new(&args[1])),
        Some("issue") if args.len() >= 2 => cmd_issue(Path::new(&args[1]), &args[2..]),
        Some("inspect") if args.len() >= 2 => cmd_inspect(&args[1], &args[2..]),
        Some("request") if args.len() == 2 => cmd_request(&args[1]),
        Some("combine") if args.len() >= 3 => cmd_combine(&args[1], &args[2], &args[3..]),
        Some("compact") if args.len() == 2 => {
            let text = fs::read_to_string(&args[1]).unwrap_or_else(|e| die(&format!("cannot read {}: {e}", args[1])));
            println!("{}", HolderFile::from_text(&text).unwrap_or_else(|e| die(&e.to_string())).to_compact());
        }
        _ => {
            eprintln!(
                "usage:\n  handover-ca init <dir>\n  handover-ca issue <dir> --role controller|device --label <text> [--days N] [--holder-pub <key>] --out <file>\n  handover-ca request <file>\n  handover-ca combine <request file> <credential file> --ca-pub <base64|file> --out <file>\n  handover-ca inspect <file> [--ca-pub <base64|file>]\n  handover-ca compact <file>"
            );
            std::process::exit(2)
        }
    }
}
