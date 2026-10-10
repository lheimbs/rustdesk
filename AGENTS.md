# RustDesk Guide

## Fork Mission: Trustworthy Personal-Support Build

This fork exists so one person can use RustDesk for personal remote support with
**no vendor dependency, no hidden outbound traffic, and no opaque binaries**.
Everything below this section is the upstream contributor guide and still applies
(minimal diffs, additive hooks, no drive-by refactors). Where the two conflict,
this section wins for anything that touches network egress, third-party code,
or release artifacts.

The detailed, phased plan is `docs/TRUST_HARDENING_PLAN.md`; follow it and keep it current.
In this fork the plan overrides two upstream rules below: `libs/hbb_common` may be inlined
and edited directly (the "submodule / put client-only code in libs/base" guidance no longer
applies), and network-egress code is deleted or hard-stubbed rather than kept behind a
"feature off runs the old code" path.

### Threat model

* Trusted: the user's own self-hosted `hbbs`/`hbbr` (open-source `rustdesk-server`),
  their own machines, source in this repo.
* Untrusted by default: any `*.rustdesk.com` / `*.rustdesk.cn` host, the
  `rustdesk` and `rustdesk-org` GitHub orgs as *binary* suppliers, prebuilt
  drivers/DLLs, the closed-source RustDesk Pro server and its API, and any
  remote party able to push config to a client.
* Goal: a client that talks to nothing except a server the user configured
  and the peer they chose, and that can be rebuilt from audited source.

### Deployment target: self-hosted server

* Server side is the open-source `rustdesk-server` (`hbbs` rendezvous + `hbbr` relay, AGPL-3.0),
  built from source at a pinned commit, run by the user. Do not use the Pro server or its API.
* The client's only configuration is: `custom-rendezvous-server` (hbbs host), `relay-server`
  (hbbr host) and `key` (contents of hbbs's `id_ed25519.pub`). Bake these in at build time
  (or fail with a clear error when absent); never fall back to vendor values. Deployment-specific
  values (addresses, keys, allowed networks) live only in the git-ignored `.env` (template:
  `.env.example`); never commit hostnames, IPs or keys of the user's own network.
* Admission is by credentials signed with the owner's offline issuer key (`libs/handover_cred`, tool
  `handover-ca`): `hbbs`/`hbbr` serve only messages carrying a token made from such a credential
  (server patches 0004/0005, `HANDOVER_CA_PUB` required to start, `HANDOVER_REVOKED` list), and a customer
  machine accepts a login only from a controller with a signed controller credential (`src/controller_auth.rs`,
  trust anchor `HANDOVER_CONTROLLER_CA` baked into the build). `-k _` alone is no access control: it checks
  a shared string on two messages only (server README). Consider IP allow-listing on hbbs/hbbr. The
  controlled side then needs the current one-time password for a prompt to appear and a click to authorise
  (`src/server/login_gate.rs`); no permanent password is accepted. Secret keys (issuer, controller, device)
  never go in the repo, `.env` or a ticket.
* The server repo and its dependencies need the same audit as this one (C1-style pins,
  `cargo audit`, own build). Treat it as in scope for the egress test: hbbs/hbbr must make
  no outbound connections.

### Audit findings (as of 2026-10-04, master @ e5bc204fe)

Licensing context: the repo is AGPL-3.0 (`LICENCE`), so the client source is
genuinely open. The "proprietary" concerns are the things *around* it: the Pro
server, bundled binaries, and the vendor-controlled defaults.

**A. Vendor-controlled network egress (highest priority)**

| # | Finding | Where |
|---|---------|-------|
| A1 | Default rendezvous/relay servers and the vendor public key (`RENDEZVOUS_SERVERS`, `RS_PUB_KEY`, `PROD_RENDEZVOUS_SERVER`) are compiled in, so an unconfigured client registers its ID and IP with vendor infrastructure. **Verified 2026-10-04** in `libs/hbb_common/src/config.rs:117-118`: `RENDEZVOUS_SERVERS = ["rs-ny.rustdesk.com"]` and `RS_PUB_KEY = "OeVuKk5n…"`; an unconfigured client was measured dialling `rs-ny.rustdesk.com:21116` (see plan §2a). | `libs/hbb_common/src/config.rs`, used in `src/client.rs:468,1650,2946` |
| A2 | Update check POSTs to `https://api.rustdesk.com/version/latest`, enabled by default, skipped only for "custom clients". | `src/common.rs:1020-1075` |
| A3 | Default API server falls back to `https://admin.rustdesk.com`. Heartbeat and sysinfo upload (hostname, OS username, version, UUID, ID, address-book/strategy presets) go to `{api}/api/heartbeat` and `/api/sysinfo` every 15 s once an API server resolves. | `src/common.rs:1143-1163`, `src/hbbs_http/sync.rs` |
| A4 | `is_public()` hard-codes `rustdesk.com` as the "public" host; several code paths branch on it (TLS/proxy choice, API behaviour). | `src/common.rs:1166`, call sites at `:1213,:1226,:1250` |
| A5 | Server-pushed "strategy" can overwrite client config (`StrategyOptions.config_options`); `allow-remote-config-modification` exists as an option. A hostile or compromised API server can therefore change local settings. | `src/hbbs_http/sync.rs`, `libs/base/src/config/keys.rs:55` |
| A6 | Windows: API/server config can be read from the **executable file name** (`get_license_from_exe_name`), so a renamed binary silently redirects the client. | `src/common.rs:1131`, `src/platform/windows.rs` |
| A7 | Session-recording upload and login-option fetch hit the configured API server. | `src/hbbs_http/record_upload.rs`, `account.rs` |
| A8 | Hard-coded vendor URLs in the UI (privacy page, download, pricing, docs). Low risk, but they are click-through leaks and social-engineering surface. | `grep rustdesk.com flutter/lib src` |

**B. Closed-source or unauditable binaries pulled into builds**

| # | Finding | Where |
|---|---------|-------|
| B1 | Windows virtual-display driver `usbmmidd_v2.zip` (third-party, closed, kernel-adjacent) downloaded from a `rustdesk-org` release. | `.github/workflows/*`, `libs/virtual_display` |
| B2 | Windows printer driver zips + `sha256sums` fetched from `rustdesk/hbb_common` releases (a binary host inside the shared submodule repo). | `.github/workflows/*`, `libs/remote_printer` |
| B3 | Custom Flutter **engine** binaries from `rustdesk/engine` releases, and `rustdesk_thirdparty_lib` prebuilt libs. | `.github/workflows/flutter-build.yml`, `build.py:91` |
| B4 | Sciter SDK (legacy UI) is proprietary freeware, not OSI-open. Already deprecated. | `src/ui/`, `Cargo.toml` (`sciter-rs`), `inline` feature |
| B5 | `doc.rustdesk.com` `web_deps.tar.gz` prebuilt web client assets. | workflows |
| B6 | `hwcodec` / `vram` / `mediacodec` features pull vendor GPU codec SDKs (NVENC/AMF/QSV). Opt-in, but not auditable. | `Cargo.toml:30-32`, `libs/scrap` |

**C. Supply chain**

| # | Finding | Where |
|---|---------|-------|
| C1 | ~25 Cargo dependencies are pinned to **branches** (not revs) of forks under `rustdesk-org` (`rdev`, `cpal`, `arboard`, `tao`, `tungstenite-rs`, `webrtc`, `wezterm`, `kcp-sys`, `evdev`, `impersonate-system`, ...). Branch pins move without a diff in this repo. | `Cargo.toml:67-253` |
| C2 | `hbb_common` is a submodule of the vendor repo, tracked by commit but fetched from upstream. | `.gitmodules` |
| C3 | Flutter plugins from `rustdesk-org` and an individual's fork (`21pages/flutter-desktop-embedding`), pinned by commit but unreviewed. | `flutter/pubspec.yaml:41-109` |
| C4 | `build.py` clones `vcpkg`, `flutter_rust_bridge` from a third-party fork, and pulls a Flutter tarball over plain wget, unpinned. | `build.py:191-204` |
| C5 | Signing and notarisation use the vendor's identities; release artifacts from the vendor cannot be tied to this source. | `.github/`, `build.py` |

**D. Things checked and found clean**

* No Sentry/Crashlytics/Firebase/Mixpanel/Umeng/Baidu/Tencent SDK in the source.
  Firebase appears only commented out in `flutter/lib/main.dart` and stripped by `flutter/build_fdroid.sh`.
* No bundled `.dll/.so/.exe/.jar/.aar` files are committed (only icon fonts).
* Existing opt-outs that should be forced on rather than relied on:
  `OPTION_ENABLE_CHECK_UPDATE`, `OPTION_ALLOW_AUTO_UPDATE`, `Config::no_register_device()`
  (empties the API server, see `get_api_server`), `OPTION_WHITELIST`, `OPTION_APPROVE_MODE`,
  `OPTION_DISABLE_UDP`, `OPTION_ALLOW_WEBSOCKET`.

**E. Honest caveat on the "China connections" claim**

Nothing in this tree contains China-specific telemetry or a backdoor. The concern is
structural: the company operates the default servers. Correction from the first draft of
this table: `hbb_common` contains **no** `rs-cn` default, only `rs-ny.rustdesk.com`. Treat it as a
*default-trust* problem, fixed by A1-A7 and B/C below, not as evidence of malicious code.
The 35 git-sourced crates were also pattern-audited and showed no backdoor or telemetry
(plan §2a); transitive crates.io dependencies are covered by `cargo audit` (plan U7).

### Fix status (branch `handover/trust-hardening`, 2026-10-05)

Epic: issue #32. "Measured" = observed in an offline network namespace or on the Windows test machine (plan sections 2a-2d).

| # | Status | Commit / issue |
|---|--------|----------------|
| A1 | fixed, measured | `ad6184e0f` (own server and key baked in from env/`.env`, `f476314e8`; fails closed) |
| A2 | fixed, measured | `a84caab62` |
| A3 | fixed, measured | `a416f0c4a` (API server empty, sync/audit/upload stubbed); account/address-book UI hidden in `80bf992ff` |
| A4 | fixed | `is_public()` is a constant `false` (`b0270ad1e`); the update/API paths it guarded are removed |
| A5 | fixed | `a416f0c4a` (no server-pushed config writes; `ConfigureUpdate` ignored in `ad6184e0f`) |
| A6 | fixed (Windows) | `5e7c5ec28` (exe-name licence and `custom.txt` removed) |
| A7 | fixed | `a416f0c4a` |
| A8 | fixed for the built targets | desktop links `2040fe9c2`, `4fb73916b`, `abc2f016a`; `strings` scan of the Linux bundle and the Windows library finds no vendor host (plan section 2o). Mobile-only Dart pages still carry `rustdesk.com` links but are not built in this fork |
| B1, B2 | removed from the supported builds | `5e7c5ec28`, `4fb73916b` (virtual display, printer driver) |
| B3, B5 | not used | `tools/build-*.{sh,ps1}` use the stock Flutter 3.24.5 engine and fetch no vendor binaries |
| B4 | fixed | `7f143873a` |
| B6 | not enabled | the builds use only `--features flutter`; no hwcodec/vram/mediacodec/drm |
| C1 | fixed | `bf4b97f5f`, `6b4ee6c86` (cargo-deny source policy); every git dependency vendored in `third_party/` `d8e898b5e` (#20); dependencies made dead removed `e7a08c118`, `74422d24d` (#22) |
| C2 | fixed | `394d3e631` |
| C3 | open: #34 | plugins are pinned by commit `aa232a9df` and the lock is regenerated under the pinned SDK `9b0a30e7c`, but their source is unreviewed and still fetched from GitHub |
| C4 | avoided, builds reproducible | `build.py` is not used; `tools/build-linux.sh` (`7282214c9`, `5ddc3f69b`) and `tools/build-windows.ps1` (`3ce578eb7`) give bit-identical results across directories (#23, plan sections 2k and 2n) |
| C5 | pipeline done; certificate is the maintainer's | own signing scripts `e22f98704`, `746ff5083` (tested with a throwaway certificate); the real certificate, and machines with Smart App Control: #18 |

New findings since the table above was written (all fixed unless linked): plaintext-downgrade branches in the handshake and the
controlled side (`ad6184e0f`); `id@host` and direct dialling (`ad6184e0f`); peer-supplied avatar URLs (`73a9e3703`); LAN discovery and
direct server (`73a9e3703`); the pinned peer key was never persisted (`6d10ca551`); peer clipboard defaults (`3c598ec29`, `c030b3f2b`);
no record of who connected (`8d2e48606`).
Later findings: the egress analyzer ignored UDP `sendto()`/`sendmsg()` targets (`2afbc17db`); Windows installer and library were not reproducible because of a packer timestamp and random resource-field order (`3ce578eb7`); the Linux release archive carried file times and owners (`deea33505`); `-k _` was no access control on `hbbs`/`hbbr` (it checked a shared string on two messages only; registration and several others were open) and any build could log in to a controlled side, fixed by signed admission (plan section 2q); the controlled side never checked a password (any holder of the server key could raise Accept prompts), fixed by `926d93a04`: the one-time password now gates the prompt and the click authorises (plan section 2p).

### Work plan (do in this order; one PR-sized change each)

1. **Vendor `hbb_common`.** Initialise and audit it, then decide: fork it under the
   user's own account and repoint `.gitmodules`, or inline it. Confirm the real values
   of A1 before any other change. Record the audited commit here.
2. **Remove default vendor endpoints (A1-A4, A8).** Empty `RENDEZVOUS_SERVERS`, `RS_PUB_KEY`
   and `PROD_RENDEZVOUS_SERVER`; require the user's own server + key. Delete the update check
   and the `admin.rustdesk.com` fallback rather than defaulting them off. Make `is_public()`
   return `false` and drop the branches that depend on it. Remove vendor links from the UI.
3. **Cut the Pro/API surface (A3, A5-A7).** The deployment is self-hosted with the open-source
   `hbbs`/`hbbr`, which provide only rendezvous and relay. The HTTP API on port 21114
   (accounts, address book, strategy, devices, audit, heartbeat/sysinfo) belongs to the closed
   Pro server and has no counterpart in the OSS server. Delete the `src/hbbs_http/{sync,account,record_upload}.rs`
   call paths, the address-book/strategy/device/login UI, and the exe-name licence parsing
   outright, rather than defaulting them off.
4. **Egress test.** Add a single regression test or script that runs the client against a
   local `hbbs` and asserts no connection to any host other than that server and the peer
   (`strace -f -e trace=connect`, or a network namespace with default-deny). Run before every release: `tools/egress-all.sh` (Linux, all scenarios plus a self-test of the checker) and `tools/egress-windows.ps1` (Windows).
5. **Pin the supply chain (C1-C4).** Convert branch pins to full `rev =`, run `cargo vendor`
   or fork the critical crates under the user's account, `cargo deny` / `cargo audit` in CI,
   pin the Flutter SDK and `vcpkg` baseline, replace unpinned `wget`/`git clone` in `build.py`.
6. **Replace or drop binary blobs (B1-B6).** Linux-first: ship no Windows driver at all.
   Drop Sciter and the `inline` feature. Do not enable `hwcodec`/`vram` in release builds.
   If Windows is needed later, build the IDD driver from source or omit virtual display and printing.
7. **Build and sign your own.** Reproducible build from a clean checkout, own signing key,
   published checksums, own package names and app ID so it cannot be confused with or
   auto-updated by upstream.
8. **Rebrand to Handover** (`me.heimbs.Handover`), personal use. Windows controlled side (installed
   mode + service, attended-only) and Linux Wayland controller (outgoing-only). Keep the AGPL notice
   and source-offer. See `docs/TRUST_HARDENING_PLAN.md` Phases 7, W and L.

### Documentation rules (tickets are the memory)

A new session may start with an empty context. Everything needed to continue must therefore already be written down, in the right place:

1. **GitHub issues are the system of record.** The epic (#32) holds the status and the resume pointers; each story issue holds what was decided, found, measured and
   changed, with the commit hash. The runbook issue (#33) holds the generic build/test procedures and gotchas. In the *same turn* you do any of: finish or change work,
   make or learn a decision, measure something, hit a gotcha, find a bug, or change a procedure - add it to the right issue (comment, or edit the runbook/epic body) and
   keep the `status:` label true. Evidence tables and long write-ups go into `docs/TRUST_HARDENING_PLAN.md` (sections 2a-2h, the phase table in section 4). Do not rely on
   chat history or on scratch directories: they are gone next session.
2. **No personal information in anything that is pushed or posted**: code, docs, commit messages, issue bodies and comments, labels. Personal means anything specific to the
   maintainer's setup: host names and overlay-network names, private/overlay IP addresses, user names, e-mail addresses (except the git author identity and the public app id/organisation
   name), machine models, home-directory paths, tokens and keys, screenshots of private desktops. Write procedures with placeholders (`<test-laptop>`, `<server-ip>`, `<user>`) and say
   "see the local knowledge base" when the real values matter.
3. **Local knowledge base in the git-ignored `kb/` folder** for everything that needs those details: how to reach and drive the test machines, working scripts, environment quirks,
   decisions the owner made that are not in the repo. Start with `kb/README.md` (index). Write or update an article in the same turn you learn something personal-specific; keep
   reusable scripts in `kb/scripts/` (they load `kb/scripts/env.sh`) so they survive the ephemeral scratch directory. `kb/` is never committed, never copied into tickets.
   If `kb/` does not exist (fresh clone), do not guess: ask the maintainer for the environment details and then recreate it.
4. **Scrub before you publish.** Run `kb/scripts/scrub-check.sh` before every push and after writing ticket text (it checks the branch diff, commit messages and all issue text for
   the personal patterns in `kb/scrub-patterns.txt` and for generic ones). Without `kb/`, at least grep the diff for private IP ranges (`10.`, `172.16-31.`, `192.168.`, `100.64-127.`),
   `/home/<name>/`, e-mail addresses, `github_pat_`/`ghp_` tokens and private keys. If something leaked: remove it from the tree **and** from history (the branch is unreviewed and
   single-author, so rewriting it is acceptable; back up first, rewrite, verify every commit, update the issue text, delete the backup) - never leave it "fixed in a later commit".
5. **Start and end of every session**: start by reading AGENTS.md, the epic, the open stories and `kb/README.md`; end by making sure the tickets, the plan and the kb reflect the
   final state, the work is committed and pushed (token via `kb/scripts/github/gh-push.sh`), and every test machine and process you touched is back to its original state.
6. Secrets: the GitHub token lives only in `.env` (git-ignored). Never print it, put it on a command line, store it in git config, or write it into the kb.

### Rules for agents working in this fork

* **No new outbound endpoints.** Any new URL, hostname or IP literal in code needs an explicit
  justification in the PR. Never add telemetry, crash reporting, analytics or auto-update.
* **No new binary artifacts.** Do not commit or download prebuilt binaries, drivers or
  archives. Anything fetched at build time must be pinned by hash and listed in the audit table above.
* **Dependencies:** pin by `rev`/exact version; prefer removing a dependency to adding one.
  New git dependencies require the user's approval.
  Every git-sourced dependency is vendored in `third_party/` (via `.cargo/config.toml` source replacement);
  never edit it by hand: change the rev, `cargo update -p <name>`, run `tools/vendor-forks.sh`, review the diff.
  crates.io dependencies are not vendored; `Cargo.lock` checksums pin them.
* **Fail closed.** Missing server/key configuration is an error shown to the user, never a
  silent fallback to a vendor default.
* **Never trust the server with local config.** Remote peers and servers must not be able to
  change client settings, install software or run commands without a local approval prompt.
* **Keep the AGPL intact.** Do not strip licence headers or copyright notices; add a clear
  fork notice in the README.
* **Update this section.** When a finding is fixed, mark it fixed here with the commit hash;
  when a new concern is found, add a row. Keep claims verifiable: cite file and line, and say
  "not verified" when you could not check.
* Hardening commits go in separate commits from feature work, and the PR description lists
  the egress/regression surface touched (see the upstream "regression-surface" rule below).

## Project Layout

### Directory Structure
* `src/` Rust app
* `src/server/` audio / clipboard / input / video / network
* `src/platform/` platform-specific code
* `src/ui/` legacy Sciter UI (deprecated)
* `flutter/` current UI
* `libs/hbb_common/` shared with the server: rendezvous proto, sockets, `Config` core
* `libs/base/` (crate `base`) client-only: option keys, message proto, file transfer, platform code
* `libs/scrap/` screen capture
* `libs/enigo/` input control
* `libs/clipboard/` clipboard
* `libs/base/src/config/keys.rs` the single import path for all options

### Key Components
- **Remote Desktop Protocol**: Custom protocol implemented in `src/rendezvous_mediator.rs` for communicating with rustdesk-server
- **Screen Capture**: Platform-specific screen capture in `libs/scrap/`
- **Input Handling**: Cross-platform input simulation in `libs/enigo/`
- **Audio/Video Services**: Real-time audio/video streaming in `src/server/`
- **File Transfer**: Secure file transfer implementation in `libs/base/src/fs.rs`

`hbb_common` is a git submodule shared with the server, so changing it costs a
round-trip. Put client-only code in `libs/base` instead; it is a normal
workspace member. `base::config::keys` re-exports the handful of keys
`hbb_common` still reads, so callers get the whole set from that one path.

### UI Architecture
- **Legacy UI**: Sciter-based (deprecated) - files in `src/ui/`
- **Modern UI**: Flutter-based - files in `flutter/`
  - Desktop: `flutter/lib/desktop/`
  - Mobile: `flutter/lib/mobile/`
  - Shared: `flutter/lib/common/` and `flutter/lib/models/`

## Rust Rules

* Avoid `unwrap()` / `expect()` in production code.
* Exceptions:

  * tests;
  * lock acquisition where failure means poisoning, not normal control flow.
* Otherwise prefer `Result` + `?` or explicit handling.
* Do not ignore errors silently.
* Avoid unnecessary `.clone()`.
* Prefer borrowing when practical.
* Do not add dependencies unless needed.
* Keep code simple and idiomatic.

### Logging

* `debug` and above are written to the log file. A log call that can fire
  repeatedly (per packet, frame, input event, or loop iteration, or at a rate a
  peer controls) must not use `debug` or higher unthrottled.
* For such a site, pick one:

  * `log::trace!` when the event is expected and the line only helps while
    actively debugging;
  * `hbb_common::throttled_log!(interval, level, ...)` when it signals a fault
    that should still show up in a user's log. It keeps one line per interval
    with a count of the rest. Use `hbb_common::log_throttle::LogThrottle`
    directly only when the decision drives more than one log call.

## Tokio Rules

* Assume a Tokio runtime already exists.
* Never create nested runtimes.
* Never call `Runtime::block_on()` inside Tokio / async code.
* Do not hide runtime creation inside helpers or libraries.
* Do not hold locks across `.await`.
* Prefer `.await`, `tokio::spawn`, channels.
* Use `spawn_blocking` or dedicated threads for blocking work.
* Do not use `std::thread::sleep()` in async code.

## Editing Hygiene

* Change only what is required.
* Prefer the smallest valid diff.
* Do not refactor unrelated code.
* Do not make formatting-only changes.
* Keep naming/style consistent with nearby code.

### Imports

* One `use` per crate. Everything a file takes from the same crate goes in a
  single braced block, not one statement per item:

  ```rust
  // no
  use base::fs;
  use base::message_proto::*;

  // yes
  use base::{fs, message_proto::*};
  ```

* The only reason to split is a `#[cfg(...)]` that does not apply to the whole
  block -- an attribute binds to one item, so a differently-gated import has to
  stand on its own. A `pub use` re-export likewise cannot join a plain `use`.

  ```rust
  #[cfg(not(feature = "flutter"))]
  use base::fs;
  use base::message_proto::*;
  ```

* When splitting an existing `use` because some of its items moved to another
  crate, fold each side into that crate's existing block rather than leaving a
  second statement behind.

### Comments

* Avoid comments unless they explain a non-obvious reason, constraint, or workaround.
* Never restate what the code does; prefer clearer code instead.
* If the code is self-explanatory, add no comment.

### Be minimally invasive

* Prefer purely additive changes: layer new (`#[cfg]`-gated) blocks or new functions around existing code instead of restructuring it. The ideal diff for a fix adds lines and modifies/deletes none.
* Do not extract or reshape existing code just to enable your new code; look for a mechanism that leaves existing lines untouched (e.g. hide/show an existing object instead of refactoring its construction into a helper for rebuilding).
* Accept a little duplication over a restructure. A new function that repeats a few lines of an existing one is a better diff than reshaping the original so both can share it.
* Put new logic in self-contained functions in the module it belongs to (platform-specific logic in `src/platform/`, with `use` inside the function body to avoid churning shared import blocks). Call sites in shared files (`src/tray.rs`, `src/core_main.rs`, `src/server/connection.rs`, …) should be thin one-line hooks.

### Scope check before touching shared code

* Before changing a shared trait, a shared struct, or the signature of a widely used function, check whether the bug or feature is specific to one path. If it is, keep the change inside that path unless that is impossible, and say in the PR why it was.
* If an unrelated caller needs `Default::default()`, `None`, or another placeholder solely to satisfy a signature you changed, the diff is too broad: stop and redesign.
* The expected shape of a fix is a new function in the feature's own module, plus at most a new field or a thin hook in the shared code it needs. Feature-specific state belongs beside the feature's existing state, not in a new abstraction every caller has to learn.

### Mandatory regression-surface check

Before considering any implementation complete, perform a minimization pass over the final diff.

* Inspect every modified existing file and every modified existing code path. Each must be strictly necessary for the requested change. Revert changes that are merely cleanup, refactoring, consistency improvements, or fixes for pre-existing issues.
* For new features, preserve the existing implementation path when the feature is disabled or unsupported whenever practical. `feature off` should run the old code, not a rewritten equivalent.
* Do not route existing behavior through a new abstraction merely to share code with the new feature. Prefer a parallel new function or a small amount of duplication over changing a proven existing path.
* Keep new implementation logic in new or feature-specific modules. Changes to shared/core files should normally be thin hooks, capability checks, or protocol plumbing.
* Do not fix unrelated pre-existing bugs in the same PR. Put them in a separate change unless they directly block correctness or security of the requested work.
* For submodule bumps, inspect the exact commit range and ensure unrelated changes are not being pulled into the parent PR.
* Before finalizing, explicitly report the regression surface: list the existing files and existing runtime paths whose behavior changed, and explain why each change is unavoidable.
* During review, treat an unnecessarily modified legacy path as a review finding even if tests pass and the rewritten behavior appears equivalent.

### Corner cases raised in review

A refactor added to cover a corner case rarely converges. Each new counter, timestamp, cache or eviction/expiry rule interacts with state that existing code relies on, and the next review round finds the problems it introduced.

* A corner case is still worth fixing when the fix is easy and low-risk: a local change of a few lines that adds no state and changes no existing lookup, such as moving a check or refusing bad input earlier.
* When the only fix needs new state, a new lifecycle rule or a restructure, and the code already fails cleanly there or behaves as master does, document it as a known limit in the PR instead. Anything beyond the easy fix needs the maintainer's explicit go-ahead first.
* Before adding state that reorders, expires or reuses existing data, list every lookup that reads that data and check each one still holds.
* Prefer a clean failure, where the operation reports an error, over machinery that tries to make a rare case succeed.
* A severity label from any reviewer (P1, Critical, Major) is not a triage result. Apply the next rule by consequence, not by label.
* A corner case whose fix needs new state is fixed only when it crashes, loses data, weakens security, or a user has reported it. A rare cosmetic or layout glitch (e.g. rotation during an active drag, a feature that is off by default) is a known limit: reply once, list it under "Known limits" in the PR body, and leave the code alone.
* When a finding is about behavior an earlier commit of this same PR introduced, fix it by removing or simplifying that commit, not by adding a layer on top.
* Judge growth across all rounds, not per round. If review follow-ups have grown the non-test diff by more than half of the first fix, or added a new kind of state (handles into another component, cross-component references, deferred / post-frame callbacks, timers, caches, flags), stop and ask the maintainer before pushing.
* When keeping the user's preferred state is hard in a rare case, fall back to a deterministic default computed from the current inputs. Do not coordinate mutable state across components or frames to preserve the preference.

## Tests

* A fix gets regression tests for the reported behavior only: they fail on master and pass with the fix. One to three tests is normal.
* Assert what the user sees or what the API returns. Do not test private state, the order an algorithm runs its steps in, or each corner case raised in review.
* Do not add test infrastructure (browser runners, golden/screenshot harnesses, new mock layers, test-only hooks in production code) for a bug fix unless the maintainer asks.
* If the test diff is more than twice the fix, cut it back to the tests that pin the reported behavior. A state that needs long setup to reach is usually too rare to fix.
* When the number of tests needed to describe the behavior keeps growing, the implementation is too complex: simplify it instead of adding tests.

## Reviewing a PR

* Review only what the diff introduces. Verify ownership with `gh pr diff` before reporting a finding — if the offending lines are untouched context, it is a pre-existing problem, not this PR's.
* List pre-existing problems in a separate section at the end, or leave out the ones that are not fatal. Never mix them into the findings the author has to fix.
* Before re-reviewing, read the author's reply comments. Do not re-raise items they declined on scope grounds.
* State a finding's consequence exactly: distinguish "the value is lost" from "the shortcut is inert but the value still saves".
* Do not report a rare corner case as blocking when fixing it needs new state; mark it as a known limit the author may leave unfixed.
* Treat growth across review rounds as a finding: if the latest commits add more state than the original fix, say so instead of asking for more handling.

## Localization (`src/lang/*.rs`)

Each file is a `HashMap<key, translation>`. Layout:

* `template.rs` is the master list of every key. **Never edit it** as part of translation work.
* `en.rs` holds only the keys whose English display text differs from the key itself.
* Every other file (`de.rs`, `fr.rs`, …) carries the full key set; an untranslated entry has an empty value: `("key", "")`.
* `it.rs` is maintained by hand by its translator. Never fill or change its entries; when adding new keys, append them to it with `""` and leave the translation to the maintainer.

### Finding the English source for a key

When filling an empty entry, determine the source English text with this rule:

* If `key` exists in `en.rs` **with a non-empty value**, that value is the source text (look it up in `en.rs`).
* Otherwise the **key string itself is the source text** (the key is already plain English).

Then translate that source into the file's target language (infer the language from the file's existing non-empty entries / filename).

### Translation hygiene

* Only fill empty values. Never change keys, and never touch existing non-empty translations.
* Preserve placeholders (`{}`) and escape sequences (`\n`, `\"`) exactly as in the source.
* Do not translate brand or technical tokens: `RustDesk`, `Socks5`, `TLS`, `UAC`, `Wayland`, `X11`, `TCP`, `UDP`, `2FA`, `RDP`, `D3D`, etc.
* Copy URL values (e.g. `doc_*` keys) verbatim from `en.rs`.

### Adding new keys (feature work)

* New English-text keys use sentence case, not Title Case: `Use ID whitelisting`, **not** `Use ID Whitelisting`. Acronyms (ID, IP, 2FA…) stay uppercase. Legacy Title-Case keys (e.g. `Use IP Whitelisting`) stay as-is — do not rename them.
* Since the key itself is the English display text, a sentence-case key usually needs **no** `en.rs` entry; add one only when the display text must differ from the key (e.g. `*_tip` keys).
* Append each new key to `template.rs` (with `""`) and to every `src/lang/*.rs` file (translated, or `""` if unsure; always `""` for `it.rs`), at the end of the list.
