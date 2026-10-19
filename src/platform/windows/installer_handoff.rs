use super::{
    installer_shell::{
        get_system_executable, path_for_cmd_assignment, path_for_cmd_environment,
        run_elevated_and_wait, trusted_install_environment,
        BATCH_SHORTCUT_DECODE_FAILURE_EXIT_CODE, CMD_RELATIVE_PATH,
    },
    validate_install_app_name, ResultType,
};
use hbb_common::{
    bail, log,
    sha2::{Digest, Sha256},
};
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

const CERTUTIL_RELATIVE_PATH: &str = "certutil.exe";
const CHCP_RELATIVE_PATH: &str = "chcp.com";
const FINDSTR_RELATIVE_PATH: &str = "findstr.exe";
const UTF8_CODE_PAGE: u32 = 65001;
const INSTALL_HANDOFF_RUNNER_EXISTS_EXIT_CODE: u32 = 0x5253_0001;
const INSTALL_HANDOFF_COPY_FAILURE_EXIT_CODE: u32 = 0x5253_0002;
const INSTALL_HANDOFF_HASH_FAILURE_EXIT_CODE: u32 = 0x5253_0003;
const INSTALL_HANDOFF_HASH_MISMATCH_EXIT_CODE: u32 = 0x5253_0004;
const BATCH_CODE_PAGE_FAILURE_EXIT_CODE: u32 = 0x5253_0005;
const BATCH_OUTPUT_DIRECTORY_EXISTS_EXIT_CODE: u32 = 0x5253_0006;
const BATCH_OUTPUT_DIRECTORY_CREATE_FAILURE_EXIT_CODE: u32 = 0x5253_0007;
const INSTALL_COPY_FAILURE_EXIT_CODE: u32 = 0x5253_0008;
const INSTALL_COPY_HASH_MISMATCH_EXIT_CODE: u32 = 0x5253_0009;
const SHA256_HASH_LENGTH: usize = 32;

type BatchHash = [u8; SHA256_HASH_LENGTH];

struct InstallCommandScript {
    path: PathBuf,
    expected_hash: BatchHash,
}

impl Drop for InstallCommandScript {
    fn drop(&mut self) {
        if let Err(err) = fs::remove_file(&self.path) {
            if err.kind() != io::ErrorKind::NotFound {
                log::warn!(
                    "Failed to remove temporary installer file {:?}: {err}",
                    self.path
                );
            }
        }
    }
}

fn prepare_install_commands(commands: &str) -> ResultType<String> {
    let commands = commands.replace("\r\n", "\n").replace('\n', "\r\n");
    let chcp_path = get_system_executable(CHCP_RELATIVE_PATH)?;
    let chcp = path_for_cmd_environment(&chcp_path)?;
    Ok(format!(
        "@echo off\r\nsetlocal EnableExtensions DisableDelayedExpansion\r\n\
         \"{chcp}\" {UTF8_CODE_PAGE} > nul || exit /b \
         {BATCH_CODE_PAGE_FAILURE_EXIT_CODE}\r\n\
         {}\r\n\
         if exist \"%~f0.dir\" exit /b {BATCH_OUTPUT_DIRECTORY_EXISTS_EXIT_CODE}\r\n\
         md \"%~f0.dir\" || exit /b {BATCH_OUTPUT_DIRECTORY_CREATE_FAILURE_EXIT_CODE}\r\n\
         set \"RUSTDESK_OUTPUT_DIR=%~f0.dir\"\r\n{commands}\r\nexit /b 0\r\n",
        trusted_install_environment()?
    ))
}

fn write_install_script(cmds: String) -> ResultType<InstallCommandScript> {
    let directory = std::env::temp_dir();
    path_for_cmd_environment(&directory)?;
    let commands = prepare_install_commands(&cmds)?;
    let expected_hash = Sha256::digest(commands.as_bytes()).into();
    let path = directory.join(format!(
        "rustdesk_install_{}.bat",
        uuid::Uuid::new_v4().simple()
    ));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    let script = InstallCommandScript {
        path,
        expected_hash,
    };
    file.write_all(commands.as_bytes())?;
    file.sync_all()?;
    Ok(script)
}

fn install_hash_pattern(hash: &BatchHash) -> String {
    hash.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" *")
}

/// Handover (#73): the elevated copy into the install directory. The source directory belongs to the user, so it takes
/// exactly the files that were there, with these contents, when the script was written (before the UAC prompt): each is
/// copied into the protected runner directory, checked there, and only that checked copy goes on to `dst`.
pub(super) fn verified_copy_commands(src_dir: &Path, dst: &str) -> ResultType<String> {
    let certutil = get_system_executable(CERTUTIL_RELATIVE_PATH)?;
    let findstr = get_system_executable(FINDSTR_RELATIVE_PATH)?;
    let (certutil, findstr) = (path_for_cmd_environment(&certutil)?, path_for_cmd_environment(&findstr)?);
    let src = path_for_cmd_environment(src_dir)?;
    let mut files = vec![];
    collect_files(src_dir, Path::new(""), &mut files)?;
    if files.is_empty() {
        bail!("Nothing to install in {:?}", src_dir);
    }
    let stage = "%RUSTDESK_OUTPUT_DIR%\\stage";
    let hashes = "%RUSTDESK_OUTPUT_DIR%\\stage.hash";
    let mut out = format!("md \"{stage}\" || exit /b {INSTALL_COPY_FAILURE_EXIT_CODE}\r\n");
    let mut made = std::collections::HashSet::new();
    for (rel, hash) in files {
        let rel = rel
            .to_str()
            .filter(|r| r.chars().all(|c| c.is_ascii_alphanumeric() || " ._-+@()[]~,=#\\".contains(c)))
            .ok_or_else(|| hbb_common::anyhow::anyhow!("Installer file name unsafe for cmd.exe: {:?}", rel))?;
        if let Some((parent, _)) = rel.rsplit_once('\\') {
            let mut sub = String::new();
            for part in parent.split('\\') {
                sub = if sub.is_empty() { part.to_owned() } else { format!("{sub}\\{part}") };
                if made.insert(sub.clone()) {
                    out += &format!("md \"{stage}\\{sub}\" || exit /b {INSTALL_COPY_FAILURE_EXIT_CODE}\r\n");
                }
            }
        }
        out += &format!(
            "copy /Y \"{src}\\{rel}\" \"{stage}\\{rel}\" > nul || exit /b {INSTALL_COPY_FAILURE_EXIT_CODE}\r\n\
             \"{certutil}\" -hashfile \"{stage}\\{rel}\" SHA256 > \"{hashes}\" || exit /b {INSTALL_COPY_HASH_MISMATCH_EXIT_CODE}\r\n\
             \"{findstr}\" /R /I /X /C:\"{}\" \"{hashes}\" > nul || exit /b {INSTALL_COPY_HASH_MISMATCH_EXIT_CODE}\r\n",
            install_hash_pattern(&hash)
        );
    }
    out += &format!("XCOPY \"{stage}\" \"{dst}\" /Y /E /H /C /I /K /R /Z\r\n");
    Ok(out)
}

fn collect_files(base: &Path, rel: &Path, out: &mut Vec<(PathBuf, BatchHash)>) -> ResultType<()> {
    for entry in fs::read_dir(base.join(rel))? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let rel = rel.join(entry.file_name());
        if kind.is_dir() {
            collect_files(base, &rel, out)?;
        } else if kind.is_file() {
            out.push((rel.clone(), Sha256::digest(fs::read(base.join(&rel))?).into()));
        } else {
            bail!("Installer source holds a link: {:?}", rel);
        }
    }
    Ok(())
}

fn verified_install_bootstrap(
    script: &InstallCommandScript,
    runner_directory: &Path,
) -> ResultType<String> {
    let source = path_for_cmd_assignment(&script.path)?;
    let runner = runner_directory.join(format!(
        "rustdesk_install_{}.bat",
        uuid::Uuid::new_v4().simple()
    ));
    let runner = path_for_cmd_assignment(&runner)?;
    let cmd_path = get_system_executable(CMD_RELATIVE_PATH)?;
    let certutil_path = get_system_executable(CERTUTIL_RELATIVE_PATH)?;
    let findstr_path = get_system_executable(FINDSTR_RELATIVE_PATH)?;
    let cmd = path_for_cmd_assignment(&cmd_path)?;
    let certutil = path_for_cmd_assignment(&certutil_path)?;
    let findstr = path_for_cmd_assignment(&findstr_path)?;
    // Short names preserve headroom under the Windows 7 ShellExecuteExW 2,048
    // UTF-16-character parameter limit. Paths are stored with delayed expansion
    // disabled, then expanded indirectly so literal `!` survives: S=source,
    // R=runner, Q=cmd.exe, H=certutil.exe, F=findstr.exe, C=created flag, E=exit code.
    Ok(format!(
        "setlocal DisableDelayedExpansion & set \"S={source}\" & set \"R={runner}\" & \
         set \"Q={cmd}\" & set \"H={certutil}\" & set \"F={findstr}\" & \
         set \"C=0\" & set \"E=0\" & setlocal EnableDelayedExpansion & \
         if exist \"!R!\" (set \"E={INSTALL_HANDOFF_RUNNER_EXISTS_EXIT_CODE}\") else (\
         set \"C=1\" & copy /Y \"!S!\" \"!R!\" > nul || \
         (set \"E={INSTALL_HANDOFF_COPY_FAILURE_EXIT_CODE}\") & \
         if \"!E!\"==\"0\" (\"!H!\" -hashfile \"!R!\" SHA256 > \"!R!.hash\" || \
         set \"E={INSTALL_HANDOFF_HASH_FAILURE_EXIT_CODE}\") & \
         if \"!E!\"==\"0\" (\"!F!\" /R /I /X /C:\"{}\" \"!R!.hash\" > nul || \
         set \"E={INSTALL_HANDOFF_HASH_MISMATCH_EXIT_CODE}\") & \
         if \"!E!\"==\"0\" (\"!Q!\" /D /E:ON /V:OFF /C \"\"!R!\"\" & \
         set \"E=!errorlevel!\")) & \
         if \"!C!\"==\"1\" (rd /s /q \"!R!.dir\" > nul 2>&1 & \
         del /f /q \"!R!\" \"!R!.*\" > nul 2>&1) & exit /b !E!",
        install_hash_pattern(&script.expected_hash),
    ))
}

fn verified_install_parameters(script: &InstallCommandScript) -> ResultType<String> {
    let system_directory = get_system_executable("")?;
    Ok(format!(
        "/D /E:ON /V:ON /C {}",
        verified_install_bootstrap(script, &system_directory)?
    ))
}

pub(super) fn run_cmds(cmds: String, show: bool, tip: &str) -> ResultType<()> {
    validate_install_app_name(&crate::get_app_name())?;
    let script = write_install_script(cmds)?;
    let cmd_path = get_system_executable(CMD_RELATIVE_PATH)?;
    let parameters = verified_install_parameters(&script)?;
    let exit_code = run_elevated_and_wait(&cmd_path, &parameters, show)?;
    if exit_code != 0 {
        bail!(
            "{tip} failed with elevated exit code {exit_code}: {}",
            elevated_install_failure_reason(exit_code)
        );
    }
    Ok(())
}

fn elevated_install_failure_reason(exit_code: u32) -> &'static str {
    match exit_code {
        INSTALL_HANDOFF_RUNNER_EXISTS_EXIT_CODE => "protected runner already exists",
        INSTALL_HANDOFF_COPY_FAILURE_EXIT_CODE => "failed to copy protected runner",
        INSTALL_HANDOFF_HASH_FAILURE_EXIT_CODE => "failed to hash protected runner",
        INSTALL_HANDOFF_HASH_MISMATCH_EXIT_CODE => "protected runner hash mismatch",
        BATCH_CODE_PAGE_FAILURE_EXIT_CODE => "failed to set the installer code page",
        BATCH_OUTPUT_DIRECTORY_EXISTS_EXIT_CODE => "installer output directory already exists",
        BATCH_OUTPUT_DIRECTORY_CREATE_FAILURE_EXIT_CODE => {
            "failed to create the installer output directory"
        }
        BATCH_SHORTCUT_DECODE_FAILURE_EXIT_CODE => "failed to decode an embedded shortcut",
        INSTALL_COPY_FAILURE_EXIT_CODE => "failed to copy the program files",
        INSTALL_COPY_HASH_MISMATCH_EXIT_CODE => "a program file changed before the installation (hash mismatch)",
        _ => "installer command failed",
    }
}

#[cfg(test)]
mod tests {
    use super::super::installer_shell::{
        embedded_shortcut_commands, shortcut_bytes, WIN7_SHELL_EXECUTE_MAX_PARAMETER_CHARS,
    };
    use super::*;
    use ::windows::Win32::System::Threading;
    use std::os::windows::process::CommandExt;

    #[test]
    fn native_install_handoff_verifies_before_execution() {
        let marker = std::env::temp_dir().join(format!(
            "rustdesk_install_marker_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let runner_dir = std::env::temp_dir().join(format!(
            "rustdesk_install_!RUSTDESK_HANDOFF_EXPAND!&^@()runner_{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir(&runner_dir).expect("runner directory should be created");
        let shortcut_commands = embedded_shortcut_commands(
            shortcut_bytes(r"C:\RustDesk.exe", None, None)
                .expect("native shortcut should be generated"),
            "test.lnk",
            "test",
        );
        let script = write_install_script(format!(
            "if \"%PROGRAMDATA%\"==\"rustdesk_untrusted\" exit /b 77\r\n\
             if \"%PUBLIC%\"==\"rustdesk_untrusted\" exit /b 77\r\n\
             {shortcut_commands}\r\n\
             > \"{}\" echo verified",
            marker.display()
        ))
        .expect("install script should be created");
        let bootstrap = verified_install_bootstrap(&script, &runner_dir)
            .expect("native verifier bootstrap should be generated");
        assert_native_handoff_structure(&script, &shortcut_commands, &bootstrap);

        let output = run_install_bootstrap_for_test(&bootstrap);
        assert!(
            output.status.success(),
            "unchanged script failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(marker.exists(), "verified install script must execute");
        std::fs::remove_file(&marker).expect("test marker should be removed");
        assert_replaced_install_script_is_rejected(&script, &runner_dir, &marker);
        std::fs::remove_dir(runner_dir).expect("runner directory should be empty");
    }

    #[test]
    fn the_install_copy_takes_only_the_files_it_listed_unchanged() {
        let base = std::env::temp_dir().join(format!("handover_copy_{}", uuid::Uuid::new_v4().simple()));
        let (src, out, dst) = (base.join("src"), base.join("out"), base.join("dst"));
        std::fs::create_dir_all(src.join("data")).unwrap();
        std::fs::write(src.join("Handover.exe"), b"exe").unwrap();
        std::fs::write(src.join("data").join("a.dat"), b"data").unwrap();
        let run = |commands: &str| {
            std::fs::remove_dir_all(&out).ok();
            std::fs::create_dir_all(&out).unwrap();
            let bat = base.join("copy.bat");
            std::fs::write(&bat, format!("@echo off\r\n{commands}exit /b 0\r\n")).unwrap();
            let cmd = get_system_executable(CMD_RELATIVE_PATH).unwrap();
            std::process::Command::new(cmd)
                .env("RUSTDESK_OUTPUT_DIR", &out)
                .arg("/D")
                .arg("/C")
                .arg(&bat)
                .creation_flags(Threading::CREATE_NO_WINDOW.0)
                .status()
                .unwrap()
                .code()
        };
        let commands = verified_copy_commands(&src, dst.to_str().unwrap()).unwrap();
        // planted while the prompt is open: never copied
        std::fs::write(src.join("planted.dll"), b"x").unwrap();
        assert_eq!(run(&commands), Some(0));
        assert!(dst.join("data").join("a.dat").exists());
        assert!(!dst.join("planted.dll").exists());
        // changed while the prompt is open: refused
        std::fs::remove_dir_all(&dst).ok();
        std::fs::write(src.join("Handover.exe"), b"evil").unwrap();
        assert_eq!(run(&commands), Some(INSTALL_COPY_HASH_MISMATCH_EXIT_CODE as i32));
        assert!(!dst.join("Handover.exe").exists());
        std::fs::remove_dir_all(&base).ok();
    }

    fn assert_native_handoff_structure(
        script: &InstallCommandScript,
        shortcut_commands: &str,
        bootstrap: &str,
    ) {
        assert!(shortcut_commands.contains("certutil"));
        assert!(shortcut_commands.contains("-decode"));
        assert!(!shortcut_commands.to_ascii_lowercase().contains("cscript"));
        assert!(!shortcut_commands
            .to_ascii_lowercase()
            .contains("powershell"));
        let win7_hash_pattern = script
            .expected_hash
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" *");
        assert!(bootstrap.contains(&format!("/R /I /X /C:\"{win7_hash_pattern}\"")));
        let parameters =
            verified_install_parameters(script).expect("elevated parameters should be generated");
        assert!(bootstrap.contains("certutil.exe"));
        assert!(bootstrap.contains("findstr.exe"));
        assert!(!bootstrap.to_ascii_lowercase().contains("powershell"));
        assert!(parameters.encode_utf16().count() < WIN7_SHELL_EXECUTE_MAX_PARAMETER_CHARS);
    }

    fn assert_replaced_install_script_is_rejected(
        script: &InstallCommandScript,
        runner_dir: &Path,
        marker: &Path,
    ) {
        std::fs::write(
            &script.path,
            format!("> \"{}\" echo hijacked\r\n", marker.display()),
        )
        .expect("install script should be replaceable");
        let replaced = verified_install_bootstrap(&script, &runner_dir)
            .expect("replacement verifier should be generated");
        let output = run_install_bootstrap_for_test(&replaced);
        assert!(
            !output.status.success(),
            "replaced script unexpectedly passed verification"
        );
        assert_eq!(
            output.status.code(),
            Some(INSTALL_HANDOFF_HASH_MISMATCH_EXIT_CODE as i32)
        );
        assert!(!marker.exists(), "replaced script must not execute");
    }

    fn run_install_bootstrap_for_test(bootstrap: &str) -> std::process::Output {
        let cmd = get_system_executable(CMD_RELATIVE_PATH).expect("system cmd.exe should resolve");
        let mut command = std::process::Command::new(cmd);
        command
            .env("PROGRAMDATA", "rustdesk_untrusted")
            .env("PUBLIC", "rustdesk_untrusted")
            .env("RUSTDESK_HANDOFF_EXPAND", "expanded");
        command.raw_arg(format!("/D /E:ON /V:ON /C {bootstrap}"));
        command
            .creation_flags(Threading::CREATE_NO_WINDOW.0)
            .output()
            .expect("native verifier should run")
    }
}
