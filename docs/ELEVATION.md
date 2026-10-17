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
- Not available yet: **keep connected through sign-out** (story E10). A sign-out ends the session as before.
- Not yet tested on a real machine: a standard user answering the prompt with an administrator's password, a machine with
  a changed UAC policy, sleep and wake during administrator access.
