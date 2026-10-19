# Administrator approval and lite (controlled-only) clients

Status: **spec v1, 2026-10-17** (epic in the issue tracker, label `area: approval`). Builds on `docs/ELEVATION_SPEC.md` (D20) and its
service-verified proof. Windows and Linux controlled sides. Always attended.

## 1. Decisions (owner, 2026-10-17)

1. **Only an administrator can allow an incoming control request.** Administrator = Windows Administrators group member /
   Linux sudoer. No exception path ("super override" rejected), no certificate-based skipping of the approval.
2. **Only administrators ever see the request** ("<controller> wants to control this PC. Allow?"). Ordinary users do not.
3. **Always attended:** a person who is an administrator must be signed in at the machine. No unattended access.
4. **Lite client:** a build that can only be controlled, never controls.
5. A controlled machine whose signed-in user is not an administrator (or nobody is signed in) **refuses** the connection with a
   clear reason to the controller. A non-admin user who needs help has an administrator sign in or sit down.

## 2. Terms

| Term | Meaning |
|---|---|
| Approver | The signed-in person at the machine in the session that receives the connection, who is an administrator (section 4). |
| Approval | The service-verified fact that an approver pressed Allow for one connection. Replaces "the click authorises" (the click alone is no longer enough). |
| Lite | Build flavour `lite`: service, `--server`, CM, tray; no connection page, no outgoing peer connections, no controller code. |

## 3. Flow

1. Controller connects; admission (issuer-signed token) and the one-time password gate work as today (`login_gate`).
2. After the password: the service decides whether an approver exists for the target session (section 4). None: login error
   "No administrator is signed in at this machine", logged (`approval-refused`), no UI anywhere.
3. An approver exists: only that session's CM shows the card. The click starts a **local proof** (section 5); the service accepts
   the connection only after the proof arrives (one-time nonce, same session, 60 s).
4. Everything after (tier 0, E5 protected screen, E9 elevation request, E10 resume) is unchanged. The E9 request is a second,
   separate approval. E10 resume stays tied to a grant that an approver gave.
5. The one-time password is shown only to approvers (main window and CM). An ordinary user sees no password and no request.

## 4. Who is an administrator

| | Windows | Linux |
|---|---|---|
| Check (service, not UI) | the session user's token is a member of Administrators (has a linked elevated token) | the session user may run anything through sudo: `sudo -l -U <user>` run by the root service reports `(ALL) ALL` |
| Not an approver | standard user; "Guest"; sign-in screen with nobody signed in | not a sudoer; display manager greeter |
| Refuse when the proof would be meaningless | UAC off / admins elevate without prompt / prompt not on the secure desktop (reuses E9 `uac_allows_elevation`) | `NOPASSWD` sudo for the user (a process of that user could approve silently); refused (owner decision, section 8) |

## 5. The proof

Same shape as E9 `--elevation-proof`, a new mode `--approval-proof <nonce>`:

* **Windows:** the CM's Allow starts the proof through the UAC elevation prompt; the proof process connects to the service, which
  checks (as in `serve_elevation_request`) that the caller is elevated, in the same session, and presents the nonce.
* **Linux:** Allow starts the proof through `sudo` (password dialog via the existing `gtk_sudo` helper). The proof process runs as
  root; the service checks peer credentials (`SO_PEERCRED`: uid 0), that the invoking user (`SUDO_UID`) owns the session that holds
  the nonce, and that the nonce is fresh. A non-sudoer cannot become root, so cannot send a valid proof.
* Neither side lets the controller start, see or answer the proof (E7 still applies: the controller cannot click the CM).

## 6. Lite client

* Cargo feature `lite` and a Flutter compile-time flag. With the feature the connect path (`client.rs` start, controller token
  handling, the connection page) is switched off by compile-time constants (`cfg!(feature = "lite")`): the code is still in the
  binary but cannot run, so the binary cannot open an outgoing peer session. (Corrected 2026-10-19, #89: an earlier version said
  "not compiled".) Egress scenario: only hbbs/hbbr.
* The installer ships the same service; `AGENTS.md` layout lists the `cfg(feature = "lite")` boundaries.

On Linux the lite build is the controlled side: the full Linux build is outgoing-only (`is_outgoing_only()` is true on Linux without the feature), so it
never starts a server. Plan section 2ae.

## 7. Stories  (#56-#61)

| # | Story | Needs laptop |
|---|---|---|
| A1 | Pure decision core `approval.rs`: `decide(admin_present, ...)`, refusal reasons, unit tests | no |
| A2 | Windows: admin check, `--approval-proof`, service accepts only with proof, CM card only for admins, refusals | yes |
| A3 | Linux: sudoer check, sudo proof, CM card only for sudoers, refusals | Linux VM only |
| A4 | OTP visible to approvers only | partly |
| A5 | Lite feature gating + Linux build + egress scenario; Windows lite build | build only |
| A6 | Docs (`docs/ELEVATION.md` operator text), plan section, regression matrix, egress re-run | no |

## 8. Decisions on the open points, and what is still open

1. **Linux `NOPASSWD` is refused** (owner, 2026-10-17), like UAC off on Windows: `sudo -l -U <user>` shows the user needs no
   password, so no approver. Tests use throw-away users on the VM: a sudoer whose sudo asks for a password, a standard user, and a
   `NOPASSWD` sudoer. No change to the VM's own account.
2. **Linux controlled side is verified first** (owner, 2026-10-17): capture, input and the service/`--server` split under the VM's
   headless sessions, before A3. Session = the user whose `--server` serves the display.
3. **Fast user switching:** the approver check follows the active session; a pending request is cancelled, not moved, when the
   active user changes.
4. **Two sessions:** the connection goes to the active console session only.
5. **No setting keeps the old "click authorises" behaviour.**
6. **Two-factor authentication is not asked on the approval path** (#89): an approved login is authorised by the administrator's
   proof; `require_2fa` is dropped there. The proof (UAC / sudo password, typed at the machine) is the second factor.

## 9. Security review 2026-10-18 (#62): changes and known limits

Changes (story #62, issues #63-#89):

* Accept starts the proof only for the card this very login earned (one-time password right, approver check passed), once, and
  never after authorization; a second login request while the card is up is ignored; switch sides is refused on the controlled
  side; permissions in rendezvous messages are ignored; never-available permissions cannot be switched on from the CM.
* Linux: clients of the service sockets accept only a root server; the proof runs `sudo -k` and always asks; any `NOPASSWD` or
  `!authenticate` makes the proof meaningless; root and system accounts are never approvers; the service re-checks at `Create`.
* Windows: clients accept the service pipe only from the process the service control manager reports for the service, and the
  CM pipe only from this program in this session and account; the CM pipe has a per-session name and a user+SYSTEM DACL; the
  approval has its own slot in the service and ends with its connection; the installer copies only the files it listed, checked
  by SHA-256 in a protected folder.
* The controller's login proof covers the session (`Stream::session_binding`), and a machine's signed handshake carries the time
  it was signed (`IdPk.signed_at`, accepted within 30 minutes).

Known limits (accepted, owner to confirm):

1. **The approval is enforced in the user-level `--server`.** Code running as the signed-in user can modify that process
   (Windows: same integrity level; Linux: ptrace when `kernel.yama.ptrace_scope` is 0) and skip the gate. Such code can already
   do anything the user can; the approval protects against remote parties, not against malware in the administrator's session.
2. **Windows UAC level.** At the default `ConsentPromptBehaviorAdmin=5`, known auto-elevation routes elevate silently, so code
   in the administrator's session could also produce the proof. `uac_allows_elevation` still accepts 5, because requiring
   "Always notify" (2) would refuse every default Windows install; an owner who wants it sets UAC to "Always notify" on the
   target machines. Decision pending (#84).
3. **Linux `SUDO_UID`.** The service believes the `SUDO_UID` of any root process. A root process can do anything anyway.
4. **The UAC prompt names "Windows Command Processor"**, not Handover, until the binaries are signed (#18).
5. **Revocation of controller credentials** works at the servers (`HANDOVER_REVOKED`): every connection start needs a fresh
   controller token checked there. A controlled machine has no list of its own (it may not fetch one). Controller credentials are
   issued for 30 days by default and `handover-ca` records every serial in `issued.log`.
6. **Wrong one-time passwords rotate it after ten failures**, counted for all controllers together: any credential holder can
   force a rotation (availability, not access). The password has 6 characters of 32 (about 10^9 values).
7. **`connections.log` is written by the user-level server** and can be changed by the user; the service's own log (root /
   SYSTEM) records every approval and grant and is the authoritative record.
8. **The device credential is shared by all machines.** Its holder (anyone with an installer) can register IDs that are not yet
   registered and exhaust its own half of the servers' replay cache; it cannot change a registered machine's key, use the relay
   without a controller, or ask who is online. Per-machine credentials would close the rest.
9. **A UAC prompt stays open after its connection closed** (Windows cannot close the consent prompt from outside). Answering it
   then approves nothing: the service withdrew the request with the connection (#85).
