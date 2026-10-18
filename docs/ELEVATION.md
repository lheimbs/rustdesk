# User rights and administrator access on Windows (operator's guide)

Design: `docs/ELEVATION_SPEC.md` (decision D20). Measurements: `docs/TRUST_HARDENING_PLAN.md` sections 2s-2ab. This file says
what a session can do on a Windows machine, how administrator access is asked for and given, how it ends, and what to
tell the person at the machine.

## In one paragraph

A session starts with the **rights of the signed-in user only** (tier 0): what that person could do sitting at the machine
without answering a Windows (UAC) prompt. The controller cannot see or touch the lock screen, the sign-in screen or UAC
prompts. If the controller needs more, it **asks for administrator access**; the person at the machine must press
**Allow** and then answer the **Windows prompt** themselves. Administrator access (tier 1) lasts **30 minutes** at most and
can be ended at any time from either side. The controller never sends a password for it.

## What the controller can do

| | Tier 0 (default after Accept) | Tier 1 (administrator access granted) |
|---|---|---|
| Normal windows of the signed-in user: see, type, click | yes | yes |
| Windows opened "as administrator" (elevated) | sees them, input does not arrive | yes |
| UAC prompts, lock screen, sign-in screen | not shown: a "protected screen" notice instead; input does not reach them | yes: sees and answers them |
| File transfer, clipboard | with the user's rights (files the user cannot read or write stay closed) | unchanged: still the user's rights |
| Change Windows settings that need an administrator | only by asking for tier 1 | yes, through the screens above |

## Who may allow a connection (administrator approval)

Spec: `docs/APPROVAL_SPEC.md`. A connection is only offered to an **administrator signed in at the machine** (Windows: member of
Administrators, Linux: a sudoer). Nobody else sees a request or the one-time password, and nobody can allow a connection by
clicking alone: the click starts a proof that the machine's service checks.

| | Windows | Linux (lite build) |
|---|---|---|
| Who counts | the signed-in user has an administrator account (UAC split token) | the user may run all commands through sudo (`sudo -l -U`, checked by the root service) |
| Refused with a message | nobody signed in; standard user; UAC settings that would let a program answer the prompt | nobody signed in; not a sudoer; sudo without a password (`NOPASSWD`) |
| The proof | the Windows (UAC) prompt, answered Yes | the sudo password dialog, with the user's own name and password |
| Without the service | refused ("approval service not available") | refused (same) |

What the controller sees when refused: "No administrator is signed in at this machine", "Only an administrator can allow this connection", "This
machine's settings would let a program approve silently, so remote control is refused", or "The approval service on this machine is not
available". Connection-log lines: `approval-refused <reason>`, `approval-denied` (the administrator said No, closed the dialog, or did not answer in 2 minutes).
There is no setting that turns this off and no certificate that skips it; a person who is not an administrator and needs help has an
administrator sit down or sign in.

The **lite** build (`HANDOVER_LITE=1` at build time) can only be controlled: no connection page, no outgoing connection, no controller
credential. On Linux the lite build is the controlled side; the full Linux build only controls.

## Asking for administrator access (what happens)

1. The controller picks **Request administrator access** in the toolbar's actions menu (lightning icon) and confirms. Its
   toolbar shows "Administrator access requested".
2. The connection manager on the machine comes to the front and shows the request: who asks, what it allows, the time
   limit, **Allow** and **Deny**. The person has 60 seconds; without an answer the request expires.
3. **Allow** opens the Windows prompt ("Do you want to allow this app to make changes..." for the program). An
   administrator answers Yes; a standard user is asked by Windows for an administrator's password (not tested yet on the
   test machine). Declining it ends the request.
4. When Windows has confirmed it, the controller's toolbar shows **"Administrator access mm:ss"** counting down and the
   connection manager shows **"Administrator access is active"** with a **Stop administrator access** button.

Refused with a clear message when: the controller lacks the keyboard permission, a request is already pending, or the
machine's UAC settings would make the prompt meaningless (UAC off, administrators elevated without asking, or the prompt
not on the secure desktop).

## How administrator access ends

Any of: the time limit; **Drop administrator access** in the controller's actions menu; **Stop administrator access** in the
connection manager; the controller disconnecting; the user signing out or switching users; the Handover service
restarting. The session continues at tier 0 where the connection survives. The controller is told why ("expired",
"ended on the remote machine").

## Keep connected through sign-out

When the person ticks **Stay connected through sign-out** on the request card (and then allows the request), the controller
may come back for 15 minutes after a sign-out without a password or a click: it sees the sign-in screen and can type
there. Say this plainly to the person before they tick it. It ends after 15 minutes, when a different user signs in, with
*Stop administrator access* or *Drop administrator access*, and when the machine restarts. Without the box a sign-out ends
the session as before. Connection-log lines: `resume-accepted`, `resume-refused`.

## What to tell the person at the machine

- "You will see a request for administrator access with Allow and Deny. If you allow it, Windows asks you to confirm.
  Only then can I answer Windows prompts and see the lock screen. It ends by itself after 30 minutes, and you can stop it
  at any time with *Stop administrator access* or by disconnecting me."
- "Before that, I can only do what you can do without answering a Windows prompt, and I cannot see your lock screen."
- Never ask the person for a password; the program has no way to take one from the controller.

## Processes and files (Windows)

| Process | Runs as | When |
|---|---|---|
| `Handover.exe --service` | LocalSystem, session 0 | always (installed); holds the machine's identity and the grant |
| `Handover.exe --server`, `--cm`, `--tray`, the main window | the signed-in user, not elevated | while someone is signed in |
| `Handover.exe --portable-service --portable-service-shmem-name=... --portable-service-server-pid=...` | SYSTEM in the user's session | only during administrator access |
| `Handover.exe --elevation-proof <nonce>` | the approving administrator, elevated | about a second after the Windows prompt was answered Yes |

| File or folder | What |
|---|---|
| `%APPDATA%\Handover\log\connections.log` (the signed-in user) | connection log, including the elevation lines below |
| `%APPDATA%\Handover\log\server\`, `...\cm\`, `...\elevation-proof\` | program logs of those processes |
| service log (the service's profile) | `elevation: request ... recorded`, `granted (... approved by <account>)`, `helper started/stopped`, `ended`, `refused a proof ...` |
| `C:\ProgramData\Handover\portable_service_shmem\` | link file of the shared memory used during administrator access; removed by uninstall |

Connection-log lines: `elevation-requested`, `elevation-granted <peer> approved by <account>`, `elevation-denied`,
`elevation-expired`, `elevation-dropped`, `elevation-stopped`, `elevation-revoked`, `elevation-ended ... connection closed`.

## Build setting

`HANDOVER_ELEVATION_MINUTES` (environment variable at build time, 1-480, default 30): the time limit of administrator
access. It is not read from `.env`.

## Limits (known, measured where possible)

- During administrator access, other programs running as the signed-in user could use it too (it belongs to the session,
  as with any remote-support tool); keep it short and stop it when done.
- A program of the signed-in user can block administrator access (not gain it) by occupying a pipe name; the request
  then ends with "ended on the remote machine".
- The "protected screen" notice can be closed by the controller; it comes back with the next protected period.
- Not yet tested on a real machine: a standard user answering the prompt with an administrator's password, a machine with
  a changed UAC policy, sleep and wake during administrator access.
