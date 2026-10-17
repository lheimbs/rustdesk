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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    NoAdministrator,
    NotAdministrator,
    ProofMeaningless,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Approval {
    /// Show the request to this session's user and wait for the proof.
    Approver,
    Refused(Refusal),
}

pub const NO_ADMINISTRATOR: &str = "No administrator is signed in at this machine";
pub const NOT_ADMINISTRATOR: &str = "Only an administrator can allow this connection";
pub const PROOF_MEANINGLESS: &str =
    "This machine's settings would let a program approve silently, so remote control is refused";

impl Refusal {
    /// The login error shown to the controller (English keys; the controller translates them).
    pub fn message(self) -> &'static str {
        match self {
            Refusal::NoAdministrator => NO_ADMINISTRATOR,
            Refusal::NotAdministrator => NOT_ADMINISTRATOR,
            Refusal::ProofMeaningless => PROOF_MEANINGLESS,
        }
    }

    /// The word recorded in the connection log.
    pub fn log_word(self) -> &'static str {
        match self {
            Refusal::NoAdministrator => "no-administrator",
            Refusal::NotAdministrator => "not-administrator",
            Refusal::ProofMeaningless => "proof-meaningless",
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
    fn every_refusal_has_its_own_message_and_log_word() {
        let all = [Refusal::NoAdministrator, Refusal::NotAdministrator, Refusal::ProofMeaningless];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a.message(), b.message());
                assert_ne!(a.log_word(), b.log_word());
            }
        }
    }
}
