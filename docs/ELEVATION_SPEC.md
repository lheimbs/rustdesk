# Two-tier access on the Windows controlled side: user rights by default, administrator on request

Status: **spec v1, 2026-10-10** (epic in the issue tracker, label `area: elevation`). Supersedes the "accepted as is" part of D19 in
`docs/TRUST_HARDENING_PLAN.md` for the Windows controlled side; D19's measurements (section 2r) are the baseline this spec changes.
Decision record: **D20** (written by story E2). Operating notes go to `docs/ADMISSION.md`-style operator text in story E14.

## 1. Why

Measured on a real machine (plan 2r): once a controller is accepted, it runs with SYSTEM-level reach. It sees and types at the lock and
sign-in screens and it can answer UAC (Yes started an elevated command prompt). The reason is structural: the installed `Handover`
service is a LocalSystem service that launches `--server` into the active session with winlogon's SYSTEM token
(`run_service` / `launch_server`, `src/platform/windows.rs:665,820`), so one click on "Accept" hands out SYSTEM rights, and
file transfer and the clipboard also run with them (file transfer: not verified).

Wanted instead (the owner's words: "the AnyDesk way", plus surviving sign-out):

* a session starts with **the rights of the logged-in user only**, non-elevated;
* the controller can **request elevation**; the **person at the machine** answers it, including the Windows UAC prompt; only after that
  is the session administrator-capable;
* the connection can **survive sign-out and user changes** when the person at the machine allows it, without handing out more rights
  than the owner consented to.

## 2. Terms

| Term | Meaning |
|---|---|
| Tier 0 (user) | Session whose capture, input, clipboard, audio and file access happen in a process running as the logged-in user with the normal, filtered (medium integrity) token. Cannot reach the lock screen, the UAC secure desktop or the sign-in screen, and cannot drive elevated windows (UIPI). |
| Tier 1 (administrator) | Tier 0 plus a **privileged helper** that captures and injects input at SYSTEM level for this session: secure desktop, lock screen, elevated windows. Exists only while a grant is valid. |
| Grant | The service's in-memory record that the person at the machine approved elevation for one controller connection, bound to one user session. |
| Resume grant | Optional second record ("keep connected"): lets the same controller reconnect without a new Accept click after sign-out or user switch, within a time limit, bound to the user who granted it. |
| Proof | A short-lived **elevated** process started through a real UAC prompt on the local machine; its existence shows that a local, authenticated administrator consented. |
| Sign-in server | The `--server` instance the service runs while no user is signed in (or at the sign-in/lock desktop), with the SYSTEM token as today. Accepts only resume connections. |
| Controller | The Linux Handover client. Controlled side = Windows machine. |

## 3. Requirements

Functional

* **F1** A new session after Accept is tier 0. A controller cannot start higher.
* **F2** At tier 0 the lock screen, UAC prompts and the sign-in screen are not visible to the controller (a clear "protected screen" notice instead) and no controller input reaches them. A locked session counts as protected by its session lock state: the lock-screen splash is drawn on the normal desktop and a user-level capture would otherwise show it (measured, plan 2s).
* **F3** The controller UI has a "Request administrator access" action (toolbar) and shows the state: none, requested, granted (with time left), denied, expired, revoked.
* **F4** The controlled side shows a prompt for each request (controller name, what it allows, time limit, Allow / Deny, optional "Keep this controller connected through sign-out"), and on Allow triggers the real UAC prompt. A standard user is asked by Windows for an administrator password; that is the authentication.
* **F5** After the proof succeeds the session becomes tier 1: the controller sees and drives UAC prompts, the lock screen and elevated windows.
* **F6** Tier 1 ends on: controller disconnect, controller "drop", local "stop administrator access", time limit (default 30 minutes, configurable at build time), sign-out or user switch of the granting user, service stop. The session continues at tier 0 where the connection survives.
* **F7** Connection survival: sign-out and user switch end the user-level `--server`. With a valid resume grant the controller reconnects automatically (existing reconnect behaviour) to the sign-in server without a click or password, sees the sign-in screen, and can type there (this is what "keep connected" means and the prompt says so). When the **same user** signs in again the connection continues at tier 0. When a **different user** signs in the resume grant is void and a new local Accept is needed.
* **F8** The machine keeps **one ID and one key pair** for all Windows users (the controller addresses the machine, not a user).
* **F9** Everything is visible locally: the connection log records requests, grants, denials, expiries, revocations, resume use, and the approving account; the CM window and tray show tier 1 prominently.
* **F10** Fail closed: if any part of the grant machinery is missing or errors, the session stays at tier 0 (or ends); UAC disabled (`EnableLUA=0` or `ConsentPromptBehaviorAdmin=0` without secure desktop) means **elevation is refused**, because the UAC consent would be no authentication.

Non-functional / security

* **S1** Tier 0 must be enforced by the operating system (process token), not by a policy flag inside a SYSTEM process.
* **S2** A same-user, non-elevated process (malware) cannot create a grant: the proof must come from an elevated process whose token the service verifies.
* **S3** A grant is single-purpose: bound to controller credential serial, connection, user session id and user SID, expiry, and a one-time nonce. No replay.
* **S4** The device identity secrets (key pair, per-machine device credential) stay readable by SYSTEM only. User-level processes obtain signatures through the service (**sign broker**), which signs only the two structures it recognises (the handshake `IdPk` for this machine's own ID, and admission tokens built by `handover_cred`), from authorised callers.
* **S5** No new network endpoints or listeners: all new channels are local named pipes with the existing peer-authorisation (SID, session, exe path, content match). No new outbound connection. The egress check must stay green.
* **S6** The controller can never supply credentials for elevation: remove the `ElevationRequestWithLogon` branch.
* **S7** Resume grants are in service memory only (lost on reboot or service restart), bounded in time (default 15 minutes), bound to the granting user's SID and the controller credential serial, and require a per-grant 256-bit resume secret that the controller proves possession of.
* **S8** Revocation is immediate and local: the person at the machine can always end tier 1 and the whole session from the CM window and the tray.

## 4. Architecture

### 4.1 Processes

| Process | Token / session | Role |
|---|---|---|
| `Handover.exe --service` | LocalSystem, session 0 | Supervisor. Watches the console session (`SERVICE_CONTROL_SESSIONCHANGE`, plus the existing poll). Launches and stops the servers. Holds identity secrets (sign broker), grants and resume grants. Starts and stops the privileged helper. |
| `--server` (user-level) | The signed-in user's filtered token, that user's session | The normal server while a user is signed in: registers with `hbbs`, accepts connections, capture, input, clipboard, audio, file transfer. Launched like `--cm` and `--tray` are today (explorer token, `run_exe_in_cur_session`). Machine-wide ID from the shared config location. |
| `--server` (sign-in server) | SYSTEM with winlogon token, console session while no user is signed in | Same binary and mode as today's server. Accepts **only** resume connections. |
| `--portable-service` (privileged helper) | SYSTEM with winlogon token, the user's session | Tier 1 only. Capture and input for the user-level server through the existing shared-memory proxy (`src/server/portable_service.rs`): capture, cursor, mouse, pointer, keyboard. |
| `--cm`, `--tray`, UI | The user, as today | Prompts, indicators, controls. |
| `--elevation-proof` | The approving administrator, **elevated**, started via `ShellExecute runas` from `--cm` | Exists for a second. Connects to the service pipe and sends the nonce. |

### 4.2 Why this and not the alternatives

* *Keep the SYSTEM server and gate features by policy ("soft tier 0").* Rejected: a policy flag inside a SYSTEM process is not a boundary (file transfer, clipboard, input all run with full rights and every future bug is SYSTEM). Violates S1.
* *Split brain/worker (SYSTEM brain in session 0, workers per session for capture, input, clipboard, audio).* Gives perfect continuity but every interactive service of the server would need a worker and a protocol (clipboard and audio are not behind the existing proxy). Too large and risky for the gain; the resume grant (F7) gives the user-visible behaviour at far lower cost. Remains the fallback if the user-level server proves unworkable (see risk R2).
* *Upstream portable mode as is.* It starts the helper with `ShellExecute runas`, i.e. an **administrator** token, which cannot reach the secure desktop (measured in E1, plan 2s), and its logon variant lets the **controller** supply credentials (S6).

### 4.3 State machine of one session

```
            Accept click (local)                 Allow + UAC proof                      time/revoke/logoff/disconnect
  [none] ---------------------------> [TIER 0] ------------------------> [TIER 1] ---------------------------------> [TIER 0]
                                         |  ^  \                              |
                                 Deny    |  |   \ controller drops              |
                                         v  |    v                              v
                                    [TIER 0, request denied]               [connection ends]

   sign-out / user switch of a TIER 0 session:
      no resume grant  ->  connection ends (as today)
      resume grant     ->  controller auto-reconnects -> sign-in server (SYSTEM) -> controller sees sign-in screen
                           same user signs in  -> user-level server, TIER 0, no click
                           other user signs in -> resume grant void -> new Accept click needed
```

### 4.4 Elevation flow (sequence)

1. Controller (UI toolbar) sends `ElevationRequest{direct}`; state "requested".
2. The user-level server rejects the request unless the session is tier 0, the machine allows elevation (F10 check) and no request is pending. It creates a pending request in the service: IPC `ElevationPending{conn_id, controller_serial, controller_name, nonce, ttl=60s, keep_connected_offered}`.
3. The server tells `--cm` (existing IPC) to show the prompt. The CM shows it with Allow / Deny and the "keep connected" checkbox (unchecked by default).
4. Deny: the server answers the controller (state "denied"), the service drops the pending request. Timeout: same ("expired").
5. Allow: the CM starts `--elevation-proof <nonce>` with `runas` => Windows shows the UAC prompt **on the local secure desktop**. The person at the machine answers it (a standard user enters administrator credentials).
6. The proof process connects to the service pipe and sends `ElevationProof{nonce}`. The service accepts only if: a pending request with that nonce exists and is unexpired, the peer's token is elevated (`TokenElevation`), the peer's exe path and content equal the service's own exe, the peer's session id equals the pending request's session id. The nonce is consumed.
7. The service creates the grant (conn id, session id, user SID, expiry, approving account, resume grant if the box was ticked), starts the privileged helper in that session through `launch_privileged_process`, and tells the user-level server `ElevationGranted{conn_id}`.
8. The server switches its capture/cursor/input to the proxy (`portable_client::running()`), sends `ElevationResponse`/status "granted, N minutes left" to the controller. CM and tray show "Administrator access ACTIVE".
9. End of tier 1: any of F6. The service stops the helper; the server returns to its own capture and tells the controller "ended: reason".

### 4.5 Protocol and IPC changes (summary)

* `message.proto`: keep `ElevationRequest.direct`; **reject** `logon` (S6). Add `ElevationStatus{state, expires_in_secs, reason}` in `Misc` (server to controller). Add `ElevationDrop` (controller to server). Add `LoginRequest.resume_token` (bytes) and an `ElevationStatus.resume_secret` field delivered once, encrypted channel only.
* IPC (named pipes, existing authorisation helpers in `src/ipc/auth.rs`): server to service `ElevationPending`, `SignIdPk`, `SignAdmissionToken`, `ResumeCheck`, `GrantEnded`; service to server `ElevationGranted`, `ElevationEnded`; `--elevation-proof` to service `ElevationProof`; CM to server `ElevationDecision{allow, keep}`.
* No new TCP/UDP. No new URLs.

### 4.6 Machine-wide identity

All users share one ID. The ID, public key and non-secret settings live in a shared directory (`%ProgramData%\Handover`, ACL: SYSTEM and Administrators full, Users read). The secret key and the per-machine device credential stay in the SYSTEM-owned location; the user-level server calls the **sign broker** in the service (S4). Fallback if the broker is too invasive: a Users-readable key file with an explicit, owner-approved regression recorded in D20.

### 4.7 Surviving sign-out and user changes

See F7 and state machine. Mechanics: the service sees the session change, stops the user-level server (as `close_first` does now), launches the sign-in server in the new console session, and keeps the resume grant. The resume grant checks `(controller serial, resume proof, granting SID == signed-in SID or no one signed in, not expired)` through `ResumeCheck`. `login_gate.rs` gets a new input and an `Accept` decision for it; the controller credential check (`controller_auth.rs`) still runs first. The resume secret is proven by an HMAC over a server-provided nonce so a captured token cannot be replayed.

## 5. Out of scope

Unattended access, auto-accept without a prior local click, macOS/Linux controlled sides, controller-supplied credentials, persistence of grants across reboot, multiple simultaneous controllers at different tiers (one elevation grant per machine at a time; a second controller must be accepted separately and starts at tier 0).

## 6. Risks and how the stories deal with them

| # | Risk | Mitigation |
|---|---|---|
| R1 | The privileged helper cannot capture or drive the secure desktop with the chosen token | **Resolved by E1 (plan 2s):** an elevated administrator token cannot open the secure desktop (access denied) and cannot type at the sign-in field; only SYSTEM with a winlogon token can. The tier-1 helper is therefore SYSTEM with the winlogon token, started by the service. |
| R2 | A user-level `--server` in installed mode hits many upstream assumptions (`is_root`, `is_installed`, config paths, IPC postfixes, tray/CM ownership) | E3 is first and has a go/no-go: if it cannot be made to work in bounded effort, fall back to the brain/worker split for capture and input only (portable proxy reversed) and document it |
| R3 | DXGI capture as a non-SYSTEM user behaves differently (lock, UAC transitions, GDI fallback) | E5 and the test matrix T-05..T-09 |
| R4 | The sign broker widens the SYSTEM attack surface | Only two structures are signed, caller checked by SID, session and exe path, rate limit, unit tests with hostile input (E4) |
| R5 | UAC disabled or set to no-prompt makes the proof meaningless | F10: detect and refuse (E7) |
| R6 | Antivirus/EDR dislikes `CreateProcessAsUser`-style launches | Same technique as `--cm`/`--tray` today; no new technique for tier 0; tier 1 reuses `launch_privileged_process` |
| R7 | File transfer as the user changes what the controller can reach | That is the intent; E11 documents and tests it |
| R8 | Large change in the most security-sensitive module | One story per behaviour, tests per story, regression-surface list per PR, full L1-L7 and new T-cases before closing |

## 7. Test matrix (acceptance for the epic; each row is run on the real machine unless marked unit/offline)

| # | Case | Expected |
|---|---|---|
| T-01 | Normal accepted session, check which account the capture, input and file operations run as | The signed-in user, non-elevated; not SYSTEM |
| T-02 | Controller types into an elevated window (admin command prompt opened locally) at tier 0 | Input does not arrive (UIPI); controller sees the window |
| T-03 | Controller opens a file under another user's profile or a SYSTEM-only path | Access denied |
| T-04 | Clipboard and file transfer at tier 0 | Work with the user's rights |
| T-05 | Lock the machine at tier 0 | Controller sees the "protected screen" notice, no lock-screen pixels, no input effect; unlock resumes by itself |
| T-06 | UAC prompt appears at tier 0 (started locally) | Controller sees the notice, cannot answer; local user answers |
| T-07 | Type characters at the lock/sign-in screen from the controller at tier 0 | Nothing arrives (count dots: 0) |
| T-08 | Controller requests elevation, local user presses Deny | Controller sees "denied"; still tier 0 |
| T-09 | Request, nobody answers for 60 s | "expired"; no UAC prompt left behind |
| T-10 | Request, Allow, UAC answered Yes (admin user) | Tier 1: controller sees UAC and lock screen, can answer a later UAC prompt, input reaches an elevated window |
| T-11 | Request, Allow, UAC answered No/cancelled | Stays tier 0, controller sees "denied" |
| T-12 | Standard (non-admin) user: Allow, UAC asks for administrator password | Works with a valid admin password; wrong password keeps tier 0 |
| T-13 | A non-elevated local process sends a forged proof to the service pipe | Refused, logged |
| T-14 | Replay of a used nonce; proof after expiry; proof for a different connection | Refused |
| T-15 | UAC disabled on the machine | Elevation refused with a clear message |
| T-16 | Tier 1 time limit reached | Back to tier 0, controller told, helper process gone |
| T-17 | Local "stop administrator access" / controller "drop" | Back to tier 0 immediately |
| T-18 | Controller disconnects at tier 1 | Helper gone, grant gone |
| T-19 | Sign out at tier 0 without resume grant | Connection ends; reconnect is refused (password rotated, no click possible) |
| T-20 | Sign out with a resume grant | Controller reconnects to the sign-in server without click or password, sees the sign-in screen; same user signs in: continues at tier 0 |
| T-21 | User switch (other user signs in) with a resume grant | Grant void; new Accept click needed |
| T-22 | Resume after the time limit; after reboot; after service restart | Refused; new Accept needed |
| T-23 | Resume with a wrong resume secret / replayed proof / wrong controller credential | Refused |
| T-24 | Sleep and wake at tier 0 and tier 1 | Session continues at its tier |
| T-25 | Service restart during tier 1 | Helper gone; session at tier 0 or ended; no silent re-grant |
| T-26 | Two users: ID and key pair are the same for both | One ID |
| T-27 | Egress audit over the whole run (Windows) and `tools/egress-all.sh` | PASS, no new destination |
| T-28 | Uninstall | No leftover service, helper, firewall rule, ProgramData files |
| T-29 | Unit tests: login gate with resume, grant state machine, proof validation, sign broker input validation | Pass |
| T-30 | Connection log lines for every transition | Present, no secrets, no personal data |

## 8. Stories

The numbered stories E1-E14 are the issues of the epic. Dependency order: E1, E2, then E3 (go/no-go), E4, E5, then E6-E9, E10, then E11-E14. E3 to E9 and E10 need the Windows test machine and the owner for the lock, UAC, sign-out and sleep steps.
