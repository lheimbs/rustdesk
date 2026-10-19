//! Who may allow an incoming control request (docs/APPROVAL_SPEC.md): only an administrator signed in at the machine
//! (Windows Administrators, Linux sudoer). Pure decision; the platform code supplies the facts and the service checks the
//! proof. No administrator, no connection: there is no override and no unattended access.

/// Who is signed in at the session that would receive the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionUser {
    /// Nobody (sign-in screen, greeter, no session).
    Nobody,
    /// A user who is not an administrator.
    Standard,
    /// A user who is an administrator.
    Administrator,
}

/// Whether the local proof of an administrator's approval would mean anything on this machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofPolicy {
    /// The proof needs a deliberate local act (Windows: a UAC prompt on the secure desktop; Linux: a sudo password).
    Meaningful,
    /// A process of the user could pass the proof without the person noticing (UAC off or elevation without prompt;
    /// Linux sudo without a password).
    Meaningless,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Refusal {
    NoAdministrator,
    NotAdministrator,
    ProofMeaningless,
    /// The service that checks and verifies approvals did not answer (not running, or not reachable): fail closed.
    ServiceUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Approval {
    /// Show the request to this session's user and wait for the proof.
    Approver,
    Refused(Refusal),
}

pub const NO_ADMINISTRATOR: &str = "No administrator is signed in at this machine";
// "not allowed" keeps the controller from retrying on its own (client::check_if_retry).
pub const DECLINED: &str = "Not allowed: the administrator did not approve this connection";
pub const NOT_ADMINISTRATOR: &str = "Only an administrator can allow this connection";
pub const SERVICE_UNAVAILABLE: &str = "The approval service on this machine is not available";
pub const PROOF_MEANINGLESS: &str =
    "This machine's settings would let a program approve silently, so remote control is refused";

impl Refusal {
    /// The login error shown to the controller (English keys; the controller translates them).
    pub fn message(self) -> &'static str {
        match self {
            Refusal::NoAdministrator => NO_ADMINISTRATOR,
            Refusal::NotAdministrator => NOT_ADMINISTRATOR,
            Refusal::ProofMeaningless => PROOF_MEANINGLESS,
            Refusal::ServiceUnavailable => SERVICE_UNAVAILABLE,
        }
    }

    /// The inverse of `log_word` (the service tells the server why in this word).
    pub fn from_log_word(word: &str) -> Refusal {
        match word {
            "no-administrator" => Refusal::NoAdministrator,
            "not-administrator" => Refusal::NotAdministrator,
            "proof-meaningless" => Refusal::ProofMeaningless,
            _ => Refusal::ServiceUnavailable,
        }
    }

    /// The word recorded in the connection log.
    pub fn log_word(self) -> &'static str {
        match self {
            Refusal::NoAdministrator => "no-administrator",
            Refusal::NotAdministrator => "not-administrator",
            Refusal::ProofMeaningless => "proof-meaningless",
            Refusal::ServiceUnavailable => "service-unavailable",
        }
    }
}

pub fn decide(user: SessionUser, proof: ProofPolicy) -> Approval {
    match (user, proof) {
        (SessionUser::Nobody, _) => Approval::Refused(Refusal::NoAdministrator),
        (SessionUser::Standard, _) => Approval::Refused(Refusal::NotAdministrator),
        (SessionUser::Administrator, ProofPolicy::Meaningless) => Approval::Refused(Refusal::ProofMeaningless),
        (SessionUser::Administrator, ProofPolicy::Meaningful) => Approval::Approver,
    }
}

/// Linux: read what `sudo -l -U <user>` (run by root) says about a user.
/// Administrator = a rule that lets the user run ALL commands as ALL users; the proof is meaningless when any rule needs no
/// password (`NOPASSWD:`, also for single commands: many of them lead to a root shell) or when sudo is configured not to
/// authenticate (`!authenticate` in any defaults block), because a program of the user could then pass it silently.
pub fn classify_sudo_list(output: &str) -> (SessionUser, ProofPolicy) {
    let mut admin = false;
    let mut silent = false;
    let mut in_rules = false;
    for line in output.lines() {
        let t = line.trim();
        if t.contains("may run the following commands") {
            in_rules = true;
            continue;
        }
        // Fail closed: wherever it appears (any defaults block, any rule, a continuation line), it is a route to root without
        // a password.
        if t.split(|c: char| c == ',' || c.is_whitespace()).any(|w| w == "!authenticate" || w.contains("NOPASSWD:")) {
            silent = true;
        }
        if !in_rules || !t.starts_with('(') {
            continue;
        }
        let Some((who, rest)) = t.split_once(')') else { continue };
        let runas_all = who.trim_start_matches('(').split(|c| c == ':' || c == ',').any(|w| w.trim() == "ALL");
        let rest = rest.trim();
        let tags_and_cmd: Vec<&str> = rest.split_whitespace().collect();
        let full = tags_and_cmd.last() == Some(&"ALL");
        if runas_all && full {
            admin = true;
        }
    }
    let user = if admin { SessionUser::Administrator } else { SessionUser::Standard };
    let proof = if silent { ProofPolicy::Meaningless } else { ProofPolicy::Meaningful };
    (user, proof)
}

/// `UID_MIN` from /etc/login.defs.
pub fn login_defs_uid_min(text: &str) -> Option<u32> {
    text.lines().find_map(|l| {
        let mut w = l.split_whitespace();
        (w.next() == Some("UID_MIN")).then(|| w.next()?.parse().ok()).flatten()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_administrator_with_a_meaningful_proof_approves() {
        assert_eq!(decide(SessionUser::Administrator, ProofPolicy::Meaningful), Approval::Approver);
    }

    #[test]
    fn nobody_signed_in_is_refused_whatever_the_policy() {
        for p in [ProofPolicy::Meaningful, ProofPolicy::Meaningless] {
            assert_eq!(decide(SessionUser::Nobody, p), Approval::Refused(Refusal::NoAdministrator));
        }
    }

    #[test]
    fn a_standard_user_is_refused_whatever_the_policy() {
        for p in [ProofPolicy::Meaningful, ProofPolicy::Meaningless] {
            assert_eq!(decide(SessionUser::Standard, p), Approval::Refused(Refusal::NotAdministrator));
        }
    }

    #[test]
    fn an_administrator_whose_approval_a_program_could_give_silently_is_refused() {
        assert_eq!(
            decide(SessionUser::Administrator, ProofPolicy::Meaningless),
            Approval::Refused(Refusal::ProofMeaningless)
        );
    }

    #[test]
    fn a_declined_connection_is_not_retried_by_the_controller() {
        assert!(!crate::client::check_if_retry("error", "Connection Error", DECLINED, false));
    }

    #[test]
    fn a_refusal_survives_the_trip_as_its_log_word() {
        for r in [Refusal::NoAdministrator, Refusal::NotAdministrator, Refusal::ProofMeaningless, Refusal::ServiceUnavailable] {
            assert_eq!(Refusal::from_log_word(r.log_word()), r);
        }
        assert_eq!(Refusal::from_log_word("garbage"), Refusal::ServiceUnavailable);
    }

    #[test]
    fn every_refusal_has_its_own_message_and_log_word() {
        let all = [Refusal::NoAdministrator, Refusal::NotAdministrator, Refusal::ProofMeaningless, Refusal::ServiceUnavailable];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a.message(), b.message());
                assert_ne!(a.log_word(), b.log_word());
            }
        }
    }

    const ADMIN: &str = "Matching Defaults entries for a on h:\n    secure_path=/usr/bin\n\nRunas and Command-specific defaults for a:\n    Defaults!/usr/bin/visudo env_keep+=\"EDITOR\"\n\nUser a may run the following commands on h:\n    (ALL : ALL) ALL\n";

    #[test]
    fn a_full_sudo_rule_with_a_password_is_an_administrator_with_a_meaningful_proof() {
        assert_eq!(classify_sudo_list(ADMIN), (SessionUser::Administrator, ProofPolicy::Meaningful));
        assert_eq!(
            classify_sudo_list("User a may run the following commands on h:\n    (ALL) ALL\n"),
            (SessionUser::Administrator, ProofPolicy::Meaningful)
        );
    }

    #[test]
    fn a_user_who_may_not_run_sudo_is_standard() {
        assert_eq!(
            classify_sudo_list("User s is not allowed to run sudo on h.\n").0,
            SessionUser::Standard
        );
        assert_eq!(classify_sudo_list("").0, SessionUser::Standard);
    }

    #[test]
    fn a_partial_rule_does_not_make_an_administrator() {
        let one = "User a may run the following commands on h:\n    (ALL : ALL) /usr/bin/systemctl restart x\n    (root) ALL\n    (ALL) NOPASSWD: /usr/bin/ls\n";
        assert_eq!(classify_sudo_list(one).0, SessionUser::Standard);
    }

    #[test]
    fn a_full_rule_without_a_password_makes_the_proof_meaningless() {
        let n = "User a may run the following commands on h:\n    (ALL : ALL) NOPASSWD: ALL\n";
        assert_eq!(classify_sudo_list(n), (SessionUser::Administrator, ProofPolicy::Meaningless));
        let both = "User a may run the following commands on h:\n    (ALL : ALL) ALL\n    (ALL) NOPASSWD: ALL\n";
        assert_eq!(classify_sudo_list(both).1, ProofPolicy::Meaningless);
    }

    #[test]
    fn any_passwordless_route_to_root_makes_the_proof_meaningless() {
        for rules in [
            "    (ALL : ALL) ALL\n    (root) NOPASSWD: ALL\n",
            "    (ALL : ALL) ALL\n    (root) NOPASSWD: /usr/bin/vim\n",
            "    (ALL : ALL) ALL\n    (root) /usr/bin/ls,\n        NOPASSWD: /bin/sh\n",
        ] {
            let o = format!("User a may run the following commands on h:\n{}", rules);
            assert_eq!(classify_sudo_list(&o), (SessionUser::Administrator, ProofPolicy::Meaningless), "{}", rules);
        }
        let runas = "Runas and Command-specific defaults for a:\n    Defaults>root !authenticate\n\nUser a may run the following commands on h:\n    (ALL : ALL) ALL\n";
        assert_eq!(classify_sudo_list(runas).1, ProofPolicy::Meaningless);
        let cmd = "Runas and Command-specific defaults for a:\n    Defaults!/usr/bin/vi !authenticate\n\nUser a may run the following commands on h:\n    (ALL : ALL) ALL\n";
        assert_eq!(classify_sudo_list(cmd).1, ProofPolicy::Meaningless);
    }

    #[test]
    fn uid_min_comes_from_login_defs() {
        assert_eq!(login_defs_uid_min("# c\nUID_MIN\t\t\t 500\nUID_MAX 60000\n"), Some(500));
        assert_eq!(login_defs_uid_min("UID_MAX 60000\n"), None);
    }

    #[test]
    fn sudo_set_not_to_authenticate_makes_the_proof_meaningless() {
        let o = "Matching Defaults entries for a on h:\n    !authenticate\n\nUser a may run the following commands on h:\n    (ALL : ALL) ALL\n";
        assert_eq!(classify_sudo_list(o).1, ProofPolicy::Meaningless);
        let o2 = "Matching Defaults entries for a on h:\n    Defaults !authenticate\n\nUser a may run the following commands on h:\n    (ALL) ALL\n";
        assert_eq!(classify_sudo_list(o2).1, ProofPolicy::Meaningless);
    }
}
