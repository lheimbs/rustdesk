//! Handover login policy on the controlled side: the one-time password decides whether an Accept prompt
//! appears at all, and only a click on that prompt authorises the connection. A peer without the current
//! password never raises a prompt; a correct password alone never authorises.

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Gate {
    /// No one-time password exists, so nothing can be presented: refuse, no prompt (fail closed).
    NoPasswordAccess,
    /// The peer sent no password: ask for one, no prompt.
    EmptyPassword,
    /// The peer sent a password that is not the current one: refuse, count the failure, no prompt.
    WrongPassword,
    /// The password is right: raise the Accept prompt and wait for the click.
    Prompt,
}

pub(super) fn decide(password_exists: bool, supplied_is_empty: bool, supplied_is_correct: bool) -> Gate {
    if !password_exists {
        Gate::NoPasswordAccess
    } else if supplied_is_empty {
        Gate::EmptyPassword
    } else if supplied_is_correct {
        Gate::Prompt
    } else {
        Gate::WrongPassword
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_current_password_raises_a_prompt() {
        assert_eq!(decide(true, false, true), Gate::Prompt);
        assert_eq!(decide(true, false, false), Gate::WrongPassword);
        assert_eq!(decide(true, true, false), Gate::EmptyPassword);
    }

    #[test]
    fn nothing_raises_a_prompt_without_a_password_on_this_side() {
        assert_eq!(decide(false, false, true), Gate::NoPasswordAccess);
        assert_eq!(decide(false, true, false), Gate::NoPasswordAccess);
    }

    #[test]
    fn an_empty_password_never_raises_a_prompt_even_if_the_check_says_correct() {
        assert_eq!(decide(true, true, true), Gate::EmptyPassword);
    }
}
