# Trust-hardening plan (self-hosted hbbs/hbbr only)

Status: **v5**, 2026-10-04 (three adversarial review passes + Phase 0 measurements + Windows/Wayland scope change folded in). Base `master @ e5bc204fe`,
hbb_common `229b904` (checked out from the vendor repo; its diff vs. what the client expects was not audited),
server `rustdesk-server @ a7736be` (1.1.17-dev, its hbb_common `69cea8d`).

**Nothing here has been built or run.** `cargo`, `rustc`, `flutter`, `cargo-audit`, `cargo-deny` are not
installed on this machine. Evidence tags: **[V]** read in code by the lead or re-read by the fact-checker,
**[A]** reported by an audit agent from code, **[U]** unverified. Phase 0 exists to turn [A]/[U] into measured facts.
"100% verified" is therefore not claimable for runtime behaviour; it is claimable for the code references
tagged [V], and the egress test (D4) is the final arbiter.

## 1. Goal and scope

End state: after start-up the client opens connections **only** to (a) the user's own hbbs/hbbr, (b) the chosen peer, (c) a proxy/DNS resolver the user configured. No vendor hostname is reachable from any code path; wrong or missing server/key settings are visible errors, never silent fallbacks; the controlled side is safe by default.

**Product: "Handover" (`me.heimbs.Handover`), personal use.** Roles (user decision 2026-10-04):
- **Controlled / screen-sharing machines: Windows 10/11 x64, installed mode, Windows service kept** (so the app is available across reboots, user switches, UAC and the lock/login screen), **attended-only**: every session needs a click on the machine (D7). Flutter UI.
- **Controller: Linux Wayland (Hyprland, Arch/Omarchy), Flutter UI**, outgoing-only (no local server process).
- Out of scope, left unreachable in the tree: Linux/macOS/Android/iOS as *controlled* side, macOS, mobile, web, Sciter, MSI, portable-service, privacy mode, virtual display, printing, hardware codecs.

## 2. Verified facts

| ID | Fact | Tag / evidence |
|----|------|----------------|
| F1 | Vendor fallbacks `RENDEZVOUS_SERVERS=["rs-ny.rustdesk.com"]`, `RS_PUB_KEY="OeVuKk5n…"`. Only readers: `config.rs:957` and `client.rs:466-472` (servers); `common.rs:2026`, `client.rs:1650`, `client.rs:2946` (key) | [V] |
| F2 | `get_rendezvous_server()` returns the vendor host unconfigured; with an empty list it returns `":21116"`. The mediator then spawns zero tasks and sleeps ≈18 s per loop (slow retry, no tight spin, no panic) | [V] `config.rs:908-926`, `rendezvous_mediator.rs:314-350` |
| F3 | `get_key()` falls back to `RS_PUB_KEY` when option `key` is empty | [V] `common.rs:2026` |
| F4 | Only `client.rs:466-472` indexes `RENDEZVOUS_SERVERS[0]` (`id@public`). `client.rs:2945` uses `PUBLIC_SERVER` + `RS_PUB_KEY` (no index). `PUBLIC_SERVER` also at `client.rs:3718` | [V] |
| F5 | **An empty/invalid server key does NOT fail closed.** `get_rs_pk("")` is `None` (`common.rs:2251-2265`), which fails the *rendezvous* handshake (`common.rs:2158-2161`), but the *peer* path `secure_connection` (`client.rs:1649-1688`) treats `rs_pk == None` as a "key-less deployment": logs, sends an empty message, returns `Ok(None)` = **peer identity unverified**. `use_ws()` skips `key_exchange` (`common.rs:2143`) | [V] (fact-checker) |
| F6 | Update check POSTs os/os_version/arch/device-fingerprint to `https://api.rustdesk.com/version/latest` (`hbb_common/src/lib.rs:510-530`); on by default (`enable-*` = on unless "N", `config.rs:2826`); runs on Linux via `main_get_software_update_url` (`flutter_ffi.rs:1789`) and `ui.rs:105`; `is_custom_client()` (`common.rs:2560`) skips it | [V] |
| F7 | `get_api_server()` falls back to `http://<custom-rendezvous-host>:21114`, then `https://admin.rustdesk.com`; returns `""` when BUILTIN `register-device=N` | [V] `common.rs:1126-1163` |
| F8 | `hbbs_http::sync` thread is a `lazy_static SENDER` started on first use of `signal_receiver()` (`server/connection.rs:556,1333`) **and** by `start()` at `rendezvous_mediator.rs:281`; so stubbing `start()` alone does nothing. `heartbeat_url` at `sync.rs:281-290`; response can write options via `handle_config_options` (`sync.rs:292-309`). `sync::is_pro()` read at `ipc.rs:973`, `connection.rs:2828` | [V] |
| F9 | `allow-remote-config-modification` has no Rust consumer (UI toggles only) | [V] |
| F10 | WebRTC answerer deliberately skips the `enable-webrtc` check; ICE falls back to 4 public STUN servers (Cloudflare, Google, antisip, Nextcloud; `webrtc.rs:164` `DEFAULT_ICE_SERVERS`) | [V] `rendezvous_mediator.rs:1066-1092` |
| F11 | [measured, §2a] The IPv6 STUN probe (`stun_ipv6_test`, `common.rs:2717-2722`) runs inside `test_ipv6`, called at startup (`test_ipv6_sync`, `common.rs:663`), per connection (`client.rs:483`) and at `rendezvous_mediator.rs:1454`; ungated by WebRTC | [V] |
| F12 | Client persists hbbs `ConfigUpdate.rendezvous_servers` into option `rendezvous-servers` (`rendezvous_mediator.rs:584-593`, also NAT-test `cu` `common.rs:740-745`); open-source hbbs does send it (`rendezvous_server.rs:362,569`). Inert while `custom-rendezvous-server` (or PROD/EXE server) is set (`config.rs:933-957`) | [V] |
| F13 | `custom.txt` must verify against a hard-coded **vendor** public key (`common.rs:2463`); anyone holding that private key can override settings if the file can be placed | [V] |
| F14 | Windows exe-name licence: `get_license_from_exe_name` (`windows.rs:2103`; call sites `common.rs:771,1111,1145,2011`, `ui_interface.rs:142`); `cfg(windows)` | [V] |
| F15 | `hbbs` makes exactly one outbound call (daily POST to `api.rustdesk.com`, `src/main.rs:36`, `common.rs:282-306`); `hbbr` none | [A] |
| F16 | `hbbs -k _`/`-k -` generate+enforce a key (`id_ed25519(.pub)` in CWD); hbbr mirrors; mismatch → `LICENSE_MISMATCH`/"invalid key" | [A] |
| F17 | Server hbb_common (`69cea8d`) lacks `kx_version`, `signed_params`, `webrtc_sdp_*`; has basic `KeyExchange`. Basic kx/punch/relay should negotiate; WebRTC/kx-v2 will not. Never run | [A], **[U]** |
| F18 | Telegram 2FA calls `api.telegram.org` only if configured | [A] `auth_2fa.rs:159,166` |
| F19 | Auto-updaters (download + run installer as root/SYSTEM) exist only for Windows/macOS (`rendezvous_mediator.rs:284`, `macos.rs:797`); `flutter_ffi.rs:2811` is `cfg(windows,macos)`; `manually_check_update` has no callers | [V] |
| F20 | ~25 deps float on branch/HEAD in manifests, pinned only by `Cargo.lock` (60 `git+` lines) | [A] |
| F21 | No analytics/crash SDKs; no committed binaries | [V]/[A] |
| F22 | **`id@host` redirection**: `client.rs:476` `check_port(other_server, RENDEZVOUS_PORT)` lets any `id@evil.com[?key=…]` (typed, `rustdesk://<id>/r@<server>` `common.dart:2464`, or `--connect`) register/punch/relay via an arbitrary server. A typed `host:port` also skips rendezvous and dials a DNS name (`client.rs:446` `is_domain_port_str`) | [V] line 476; [A] rest |
| F23 | Controlled-side Connection Manager renders the controller-supplied avatar; Dart does `NetworkImage(<http(s) url>)` (`common.dart:4271-4272`); `connection.rs:2351` forwards `lr.avatar`. Malicious controller ⇒ victim fetches arbitrary URL | [V] |
| F24 | `res/DEBIAN/postinst:23-25` does `systemctl enable` + `start rustdesk`; unit runs `rustdesk --service` as root, unhardened (`res/rustdesk.service`) | [V] postinst; [A] unit |
| F25 | LAN discovery listener binds UDP 0.0.0.0:21119, replies with hostname/username/MAC/ID unless `enable-lan-discovery`="N" (default on); started whenever `is_installed()` (`rendezvous_mediator.rs:296-303`, `lan.rs`); active discovery broadcasts to 255.255.255.255; WoL sender exists | [V] start; [A] contents |
| F26 | Default-on controlled-side features: every `enable-*` option is on unless "N" (file transfer, clipboard, terminal, tunnel, remote-restart, record-session, keyboard, audio, camera); `approve_mode` defaults `Both`; `direct_server` (0.0.0.0:21118) off by default | [A] `config.rs:2826`, `password_security.rs:77`, `rendezvous_mediator.rs:1354` |
| F27 | Dart calls `package:http` directly (not only via `http_service.dart`) in `user_model.dart`, `ab_model.dart` (~20), `group_model.dart`, `model.dart:1298`, `address_book.dart:437`; with an empty API URL these build relative URLs and throw locally (no egress, but error toasts / retry loops). FFI also exposes arbitrary-URL fetchers (`main_get_http_status` `flutter_ffi.rs:991`, `main_http_request`) | [V]/[A] |
| F28 | Deb depends on `curl` (`build.py:367`) though nothing in `src/` shells out to it; `google_fonts` (mobile-only use), `stunclient`, `http` packages are in the dependency trees | [A] |
| F29 | `websocket.rs:425` reads raw option `api-server` only to choose `ws` vs `wss`; dropping `ServerConfig.api` would silently downgrade TLS-fronted domain servers to plain `ws` | [A] |

### 2a. Measured baseline (Phase 0, unmodified master, 2026-10-04)

Method: offline network namespace (`unshare -rn`), `strace -f -e trace=connect,sendto,sendmsg` with long strings so resolver
queries show names, throwaway `$HOME`, client `--server` process (no display), debug build, 70-75 s runs. Scripts and raw logs:
`target/trust/` (git-ignored). Build workarounds needed on this Arch box (not repo changes): `CXXFLAGS="-include cstdint"` for the
bundled libwebm, a `libyuv.pc` shim in `PKG_CONFIG_PATH`.

| Scenario | Measured outbound attempts | Confirms |
|---|---|---|
| `hbbs -k _` + `hbbr -k _` (server 1.1.17-dev @ a7736be, release build, 20 s) | hbbs: connect to a Hetzner IPv4 :443 (api.rustdesk.com range) within seconds; hbbr: none | F15 **[measured]** |
| Client, **no config** | resolves and dials `rs-ny.rustdesk.com:21116` (209.250.254.15) repeatedly; resolves + sends to `stun.l.google.com:19302`, `stun.cloudflare.com:3478`, `stun.antisip.com:3478`, `stun.nextcloud.com:3478/443` | F1, F11 **[measured]**; STUN fires with WebRTC unused |
| Client, **own hbbs/hbbr**, `custom-rendezvous-server=127.0.0.1` + hbbs key | `POST /api/sysinfo` (cpu model, hostname, OS username, memory, OS, uuid, id, version) and repeated `POST /api/heartbeat` (id, uuid, ver) to **`http://<your-hbbs-host>:21114`**; the 4 STUN lookups again; hbbs ports 21115/21116 | F7, F8, F11 **[measured]**: a self-hosted client leaks host identity to whatever listens on :21114 of your server (OSS hbbs does not listen there, so today it is a refused connection, but any service you later put on that port receives it) |
| Update check (`api.rustdesk.com/version/latest`) | not observed in the `--server` process | consistent with F6: triggered from the Flutter UI (`main_get_software_update_url`), so must be measured in Phase 0 with the Flutter build |
| `admin.rustdesk.com` heartbeat | not observed | consistent with the `is_public()` guard (F8) |

Build findings (Phase 0): (1) unmodified master builds: `cargo check`/`cargo build` (default and `--features flutter,linux-pkg-config --lib`) and
`flutter build linux --debug` all succeed with Rust 1.75.0 + Flutter 3.24.5 (bridge generated with 3.22.3, as CI does). (2) Local-only workarounds were
needed on current Arch (none touch the repo): `CXXFLAGS="-include cstdint"` (bundled libwebm vs. new GCC), a `libyuv.pc` shim, and a hand patch of the
generated `flutter/lib/generated_bridge.dart` because the pinned `flutter_rust_bridge_codegen` 1.80.1 mis-parses `bool` with libclang 22 (emits
`typedef bool = ffi.NativeFunction<..>`, `Pointer<bool>` params, wrong `store_dart_post_cobject` type). The patch is reproducible in `target/trust/build_flutter.sh`
and `target/trust/generated_bridge.dart.patched`. **Consequence for Phase 9:** a reproducible build must pin the toolchain image (libclang version), not rely on the host.
(3) The committed `flutter/pubspec.lock` is not what Flutter 3.24.5 resolves (SDK-bundled packages such as `collection`, `meta`, `path` and others differ; `flutter pub get`
rewrote it): the lock was produced with another SDK and is not enforced by CI, so it is not a pin today. Phase 8 must regenerate it under the pinned SDK and use `--enforce-lockfile`.

Flutter UI + interop measurements (Xvfb, offline netns, own hbbs/hbbr, `RUST_LOG=debug`):

| Scenario | Result | Confirms |
|---|---|---|
| Flutter UI (main window + its `--server`/`--tray` children), own hbbs, 90 s | resolves **`api.rustdesk.com`** and connects (49.12.46.241:443, same address `hbbs` dialled earlier, so that address is `api.rustdesk.com`); the 4 STUN lookups; `POST /api/sysinfo` + 6x `/api/heartbeat` to your hbbs host :21114; hbbs ports | F6 **[measured]**: the update check fires from the UI process; F8, F11 again |
| Controlled side receives a connection | `POST /api/audit/conn` (peer id, uuid, ip, session) to `http://<your-hbbs-host>:21114`, retried 3x | R4 **[measured]**: audit leak to your own host on every incoming connection |
| Two clients, **good key**, direct (TCP punch) | `TCP punch secure_connection ok`; controlled side logs `Connection opened` | F17/U1 **[measured]**: classic punch interoperates with `rustdesk-server` a7736be |
| Two clients, good key, **forced relay** (`--relay`) | hbbr: `New relay request … got paired`, `Both are raw`; controller `secure_connection ok`; controlled side `Connection opened` | F17/U1 **[measured]**: relay interoperates. (Controller then closes: its Flutter window dies on a missing `org.freedesktop.ScreenSaver` D-Bus service in this headless env, not a protocol fault) |
| Controller with a **wrong key** (isolated instance) | `Connection closed: Key mismatch(2)`; no relay request reaches hbbr | F16 **[measured]**: `hbbs -k _` rejects a wrong-key client before any session. The F5 plaintext-downgrade branches in `client.rs`/`server.rs` were **not reproduced end to end** (they need a hostile rendezvous/relay or on-path peer); the code finding stands as a should-fix, server-side `-k _` is the first line of defence |

Still not measured: `--cm`/`--tray` processes in isolation, file transfer/clipboard, a 24 h server soak, a successful authenticated session (needs the Phase 6 profile/permanent-password work), Windows/macOS/Android.

Test-harness lessons (must carry into the Phase 0/11 egress test): (a) `hbbr` treats **any plain TCP connection from a loopback address as an admin-console command**
(`relay_server.rs:394-406`), so relay over 127.0.0.1 can never work: give the server a non-loopback address (`ip addr add 10.77.0.1/32 dev lo`);
(b) two client instances **share their IPC socket under `/tmp/RustDesk`** and the controller reads its `key` option from the *other* instance's server process over IPC
(`get_key(false)`, `common.rs:2010-2028`), so a second instance needs a private `/tmp` (`unshare -m` + tmpfs) or its config is silently overridden; this also means IPC is a
cross-process, cross-HOME trust boundary (see Phase 6 IPC read-through); (c) `pkill -f` patterns can match the harness's own command line: use `pkill -x`.
Also seen: `fuse init failed: Can't mount path /run/user/1000/doc` (portal FUSE) in the UI; benign here.
Third-party git crates (35, `~/.cargo/git/checkouts`) were read by an agent (patterns + fork commits, not line-by-line): no backdoor, telemetry or hidden egress found; the only
network-capable ones are the expected `webrtc`, `tokio-tungstenite`, `tungstenite`, `tokio-socks` (+ local IPC `parity-tokio-ipc`); `cpal/asio-sys` downloads the ASIO SDK at build time (Windows feature only);
`hwcodec`, `rust-sciter`, and the Apple/Android crates were not fully read (off/unreachable). Transitive crates.io dependencies remain for `cargo audit`/`cargo deny` (Phase 8).

## 3. Design decisions

**D1. Inline `hbb_common`** (delete the submodule, commit its files as a workspace member). Needed because the
vendor constants and `Config` live there (§[V] F1). **Confirmed by the user 2026-10-04.** This overrides AGENTS.md's
"hbb_common is a submodule / put client-only code in libs/base"; add that sentence to the Fork Mission section.

**D2. Bake server + key at build time without breaking other crates.** *(v1's `env!`+`compile_error!` in hbb_common rejected: 8 workspace crates depend on it and `cargo check/test -p scrap|base|…` would fail.)*
1. In `hbb_common/src/config.rs`: `option_env!("RD_RENDEZVOUS_SERVER").unwrap_or("")`, `option_env!("RD_SERVER_KEY").unwrap_or("")`
   (list form for servers via a small const slice). Library crates and tests build with empty defaults.
2. In the **root crate only** (`build.rs`, which exists): fail the build if either is empty or the key is not valid
   base64 of 32 bytes. rustc tracks `option_env!`, so changing the value rebuilds.
3. Runtime still honours `custom-rendezvous-server`/`key` (outrank baked values).
4. **Fail closed on key (F5):** in `client.rs:1668-1681` the `None` arm (no key, **or a signed blob that fails to verify
   under the configured key**) sends an empty message and continues with `is_secured()==false`, i.e. a session that can
   run **unencrypted**. Replace it with `bail!` (also for an empty `signed_id_pk` from a non-`use_ws` peer, and require a
   key in the `use_ws()` path). Hbbs always runs `-k _`, so every legitimate peer has a key and a valid signature.
   **All** downgrade branches must bail, not just `None` [V by lead]: client `secure_connection` `client.rs:1668-1681` (None arm) and
   `:1749-1780` (empty `PublicKey` "pk mismatch, fall back to non-secure", invalid message type, malformed message; WebRTC already bails);
   and the controlled side `server.rs:332-335`, which accepts an empty `asymmetric_value` from the controller and proceeds with no stream key
   (`Config::set_key_confirmed(false)`) = plaintext session. Result today: a hostile relay/on-path attacker can strip encryption on
   both ends. Also audit `secure_tcp` / `secure_tcp_required` used by the mediator (`rendezvous_mediator.rs:605,729,961,1172`) [U: not read].
   Whether later layers (login) refuse an unsecured stream is [U]; the fix is to refuse at handshake regardless.

**D3. Delete or hard-stub, never runtime-gate.** A stub returns the "disabled" result at the lowest function that all
callers share (keeps FFI/Dart signatures, small diff). Regression of upstream "feature off keeps old path" is intentional (Fork Mission).

**D4. The egress test is the arbiter.** A claim of "no vendor traffic" is accepted only when it passes (Phase 0 harness, §7).

**D5. Safe-by-default controlled side** is a compile-time default the UI cannot flip back (§Phase 6, D7 profiles).

**D6. Per-peer key pinning (TOFU).** Today the only trust anchor is the hbbs key and hbbs signs `id→pk` (`client.rs:1649`), so a compromised hbbs can impersonate any ID. Store the first-seen peer pk in the peer config and hard-fail on change (hook after `decode_id_pk`, `client.rs:1667`). Phase 2.

**D9. Name: Handover, app id `me.heimbs.Handover` (user decision 2026-10-04, supersedes the earlier "keep RustDesk").** Rename is now in scope (Phase 7). Effects verified by the Windows audit: most Windows names derive from `APP_NAME` at runtime (service, install dir, pipe, mutex, registry keys, config dirs), so changing `libs/hbb_common/src/config.rs:72` renames most state; the rest is a finite inventory (Phase 7). The exe file must be named `handover.exe` (process lookups use `app_name.to_lowercase()`). `is_custom_client()` becomes true (see Phase 7 caller list): set security-relevant defaults explicitly, do not rely on the "custom client" defaults.

**D10. Service policy (user decision 2026-10-04): keep the root/SYSTEM service on Windows only for availability** (reboot, user switch, UAC/secure desktop, session changes). It never auto-approves: every session still needs a click, and no click is possible at the lock/login screen (CM start is blocked while `is_prelogin()`, `connection.rs:6315-6318` [A]), so there is no login-screen assistance. The Linux controller runs **no service and no local server**.

**D7. Attended-only (user decision 2026-10-04): no unattended access, no camera, no recording.** Every session needs a local click on the controlled machine, so the helped person is always present and consenting. Consequences (all deletions/hard-offs, Phase 6): permanent password (UI, `--password`, `permanent_password.rs` storage), `hide_cm`, `allow-hide-cm`, auto-approve and the `approve-mode` choice (hard `click`), IP whitelist-as-auth, remote restart (`enable-remote-restart`: a restart ends the session and nothing can reconnect without a person), the Linux root service (D10: kept only on Windows), camera (`ViewCamera`, `nokhwa` dep) and session recording (local `record_*`, `scrap` webm/record paths, `rust-webm` dep, `record_upload`). Temporary one-time password stays as a second factor together with the click [recommended, §10].

## 4. Phases

### Phase 0: Prerequisites and baseline (no code changes) 
**Status: DONE 2026-10-04** (toolchain installed with your approval; results in §2a and §9: baseline builds, baseline egress measured, interop answered, audit run). Remaining Phase 0 leftovers moved to Phase 11: `--cm`/`--tray` isolation, 24 h server soak.
1. **User approval needed to install**: Rust at CI's version [A: 1.75; confirm in `flutter-build.yml`], `cargo-audit`, `cargo-deny`, Flutter 3.24.5, system build deps.
2. Build **unmodified** master with `--locked --features flutter` (no hwcodec/vram/mediacodec/drm), `cargo test` for crates we touch; record pre-existing failures. The submodule is already checked out at vendor commit `229b904` (trusted as the baseline only).
3. **Spike U4:** does `src/` build with `hbb_common` `webrtc` feature off? (Decides Phase 5 shape.) 
4. Build `rustdesk-server` at pinned `a7736be` (or tag 1.1.16); run `hbbs -k _` and `hbbr`.
5. `tools/egress-check.sh` (see §7), run on the **unmodified** build to capture baseline leaks.
6. Interop smoke test client↔server over loopback: direct punch, relay, wrong key, server down (answers F17, F5 behaviour).
Exit: baseline build green, baseline leak list recorded, U1/U4 answered.

### Phase 1: Own the sources
Inline `hbb_common`; remove the submodule; add `rust-toolchain.toml`; **remove Sciter first**: delete `src/ui/`, `src/ui.rs`, the `inline` feature (`Cargo.toml:24`) and `sciter-rs` (`Cargo.toml:100`); clean the leftover `cfg(feature="inline")` at `ui_session_interface.rs:692-694`, `main.rs:25` and the `inline`+windows blocks in `build.rs`. A `--features flutter` build already excludes `ui` (`lib.rs:28-31`, flutter `main` in `main.rs:7-37`) [A], so this is dead-code removal. **Keep `src/ui_interface.rs`**: it is shared with Flutter (`flutter_ffi.rs`) and holds `post_request`, `get_async_http_status`, `discover`. Pin the toolchain (`rust-toolchain.toml`) *before* any build. Exit: build+tests identical to baseline.

### Phase 2: Remove vendor defaults, fail closed (F1-F5, F12, F13, F22)
- D2 (baked server/key, root-build.rs validation). `client.rs:466-472` and `:2945`: drop `id@public`/`PUBLIC_SERVER` special-casing.
- Fail closed on missing peer key (D2.4).
- **`id@host` override (F22):** reject any server override that isn't the configured server (`client.rs:2945-2965`, `:476`, URI form `common.dart:2464`, `--connect`). Direct `host:port` dialling: keep only if user wants it (§10), otherwise reject.
- Ignore server-pushed config: remove `ConfigureUpdate` handling (`rendezvous_mediator.rs:584-593`) and NAT-test `cu` (`common.rs:740-745`).
- `get_rendezvous_server()` returning `""` instead of `":21116"` is *optional* once the baked list is non-empty (skip per minimal-diff).
- `custom.txt`: delete `load_custom_client`/`read_custom_client` path (`common.rs:2360,2458`) rather than leave the vendor key (F13); then `OVERWRITE/DEFAULT/BUILTIN` maps only keep compiled-in values.
- Lang keys: any new user-visible error string needs `template.rs` + every `src/lang/*.rs` (`""`, always `""` for `it.rs`), per AGENTS.md.
- Implement D6 (peer pinning) in the same change as the fail-closed handshake. Phases 2 and 5 both touch `client.rs:483`: do those edits together.
- Tests (≤3): peer signature fails to verify (wrong/absent key) ⇒ connection errors, never an unsecured session; `id@other` rejected; ConfigureUpdate ignored.

### Phase 3: Kill the API/Pro surface (F7, F8, F9, F27, F29)
- `get_api_server()` returns `""` (one-line early return) **and** stubs below, because the guard only covers some callers.
- Rust: stub the sync thread in `start_hbbs_sync`/`start_hbbs_sync_async` (not only `start()`), delete `handle_config_options`, make `sync::is_pro()` return false; stub `post_conn_audit`, `record_upload::run`, `register_switch_grant`, OIDC `account_auth`/`ensure_client`, `--assign`/`--deploy`, `send_note`, `post_request*`, `get_async_http_status`, `main_http_request`, `main_get_http_status` (all return `Err`). 
- Dart: **remove the `http` package** and delete login/ab/group/audit/avatar code paths (`user_model`, `ab_model` (19 sites), `group_model` (4), `model.dart` (2), `address_book.dart`, `common/widgets/dialog.dart` (2), `common.dart` (1), `utils/http_service.dart` which re-exports `Response`); hide the account UI; `flutter analyze` is the completeness check. Nothing essential (connect, file transfer) uses `http`. Rust `post_request*`/`create_http_client*` stubs are safe for the core (file transfer and the hbbs TCP/WS path use `hbb_common::websocket`/tokio-tungstenite, not reqwest) [A]; check what `common.rs:1714` fetches before touching it.
- `ServerConfig.decode`/`setServerConfig`: drop `api`; keep the `ws`/`wss` decision independent of `api-server` (F29): choose `wss` via an explicit build-time/option flag.
- Remove `allow-remote-config-modification` toggle, `rustdesk://config/` and `rustdesk://password` deep links (not just gated).
- Tests: with `api-server` pointed at a local listener, no request arrives.

### Phase 4: Updates (F6, F19)
`check_software_update`/`do_check_software_update`: `return Ok(())`; delete `version_check_request` use; Dart update banner (`desktop_home_page.dart:438-460`) and `update_progress.dart`; `updater.rs` is Windows/macOS only: leave (§8). Test: idle client makes no connection to anything but loopback server.

### Phase 5: Third-party hosts (F10, F11, F18)
- Neutralise WebRTC (recommended). U4 is resolved: `src/` references `hbb_common::webrtc` ~52 times without a feature gate, so keep it compiled but inert: `webrtc_viable=false` at `rendezvous_mediator.rs:1074-1081`, no offers (`client.rs:520,915`). Empty `DEFAULT_ICE_SERVERS`, remove prepend branch (`webrtc.rs:526-549`). Remove `stunclient`.
- Delete `stun_ipv6_test` spawn (`common.rs:2717`) and its callers (`:663`, `client.rs:483`, `rendezvous_mediator.rs:1454`).
- nip.io: `socket_client.rs:164-170,189-203` return `Err`.
- Telegram: stub `auth_2fa.rs:159,166`.
- Remove `google_fonts` package; ensure no runtime font fetch on desktop.

### Phase 6: Safe defaults and local attack surface (F23-F26) — new in v2
- **Avatar:** remove the `http(s)` `NetworkImage` branch (`common.dart:4271-4272`); in `connection.rs` forward only `data:image/` avatars with an explicit length limit (e.g. ≤64 KiB; `connection.rs:94-99` is the pre-auth message-size cap, not an avatar cap [V by reviewer]) else blank it.
- **LAN discovery:** delete the `lan::start_listening` call (`rendezvous_mediator.rs:296-303`; it binds 0.0.0.0:21119 whenever installed and replies hostname/username/platform/MAC/ID to any LAN host unless `enable-lan-discovery`="N", `lan.rs:35-52`; the socket stays bound even when replies are off), `lan::discover` and `send_wol` (`lan.rs:86-104`); stub their callers `ui_interface.rs:781` and `flutter_ffi.rs:2213-2215`. Unattended access does not depend on LAN discovery (connections go via hbbs).
- **Direct server:** keep off; remove `direct_server` listener or require explicit opt-in; no UI toggle by default.
- **Attended-only hard defaults (D7):** `approve-mode` fixed to `click` (UI cannot change it), temporary one-time password required in addition, no permanent password, no `hide_cm`. Controlled-side features: clipboard + file transfer on (core support tasks); terminal, tunnel/port-forward/RDP, remote restart, camera, recording **removed or hard-off**. Build without `unix-file-copy-paste` (`Cargo.toml:41-47`) unless file copy/paste of files is needed. (Today: `enable-*` on unless "N"; `approve_mode` default `Both`, `password_security.rs:77-86` [V].) Remove `rust-webm` and `nokhwa` deps once camera/recording code is gone.
- **Consent and traceability:** always show the Connection Manager or a tray notice (disable `allow-hide-cm`); add a **local append-only connection log** (peer id, IP, time, permissions used) at login success in `connection.rs`, since `post_conn_audit` is stubbed in Phase 3.
- **Brute force:** per-IP limits exist (`LOGIN_FAILURES`, `connection.rs:192,4397-4450`; temp-password rotation after 10 failures `:2508-2546`) but via hbbr the source IP is the relay's, collapsing the bucket [U]: verify `self.ip` for relayed sessions and add a global per-ID cap; temporary password is one-time per session; TOTP 2FA (`auth_2fa.rs`) is optional and can be deleted with the Telegram path since the human click is the consent gate.
- **Services:** Windows service kept (D10) and hardened in Phase W. Linux: no service, no `postinst` enable/start, no `res/rustdesk.service` in the package (controller is outgoing-only).
- **Read-through** (no change unless defects found): `src/ipc/auth.rs`, `src/ipc/fs.rs:36-40`, uinput listener (`server.rs:705`, `server/uinput.rs`), `platform/linux.rs:1777` `pkexec`, root CLI handlers `--password/--set-id/--config/--option/--import-config` (`core_main.rs:423-545`). `drm` feature stays off (its socket is 0o666, `ipc/drm.rs:97`).
- Drop `curl` from `.deb` Depends (`build.py:367`) after confirming no shell-out.

### Phase 7: UI links and rename to Handover (A8, D9)
- Links: replace every vendor `launchUrl*` site with one wrapper that blocks all hosts (`common.dart:1160,1248,3741`; `desktop_home_page.dart:438,531,542,548,666`; `desktop_setting_page.dart:2557,2565`; `desktop/pages/connection_page.dart:44`; `toolbar.dart:25`; `install_page.dart:189`; `login.dart:311`; `update_progress.dart:148`); docs links `client.rs:130,4485`, `config.rs:100-101` replaced with local text.
- Rename inventory ([A] from the Windows audit, to be re-grepped when implementing): `config.rs:72` `APP_NAME="Handover"`, `config.rs:57` `ORG="me.heimbs"`; flutter windows `CMakeLists.txt:3,7` (`project`/`BINARY_NAME handover`; keep `librustdesk.dll` name to limit the diff, `main.cpp:26` loads it), `Runner.rc:92-98`, `main.cpp:83` title, channel names `org.rustdesk.rustdesk/*` (Dart-matched, rename together); flutter linux `CMakeLists.txt:7,10`, `my_application.cc` (`APPLICATION_ID com.carriez.flutter_hbb` -> `me.heimbs.Handover`, titles, channels); `libs/portable` (`generate.py` prefix `rustdesk`, `RUSTDESK_APPNAME` env must stay in step with `PORTABLE_APPNAME_RUNTIME_ENV_KEY`); Linux packaging names must equal `get_app_name().to_lowercase()` (`res/rustdesk.desktop`, `rustdesk-link.desktop`, `rpm/PKGBUILD/flatpak/appimage`, `build.py:26,360-365,719-790`); `src/clipboard.rs:128` `/tmp/.rustdesk_` prefix; `libs/base/src/platform/mod.rs:58`; `auth_2fa.rs:17` (removed with 2FA); installer temp names (`rustdesk_install_*.bat`, `RUSTDESK_OUTPUT_DIR`) internal, rename consistently (tests assert some).
- **Delete the `rustdesk://` URI scheme handler** (Windows `HKCR\{app}` URL protocol + `--play` association, `windows.rs:1523-1583`; Linux `rustdesk-link.desktop`; Dart `handleUriLink` `common.dart:2256-2470`) rather than renaming it to `handover://`: deep links are an attack surface and unneeded.
- `is_custom_client()` becomes true. Callers and effects [A, Windows audit]: `common.rs:1021` (update check returns early; we delete it anyway), `updater.rs:184,291,543`, `flutter_ffi.rs:2515,2735`, `ipc.rs:973` (exposes `hide_cm`; we delete it), `windows.rs:1512,2083,2216,3765,3879`, Dart `bind.isCustomClient()` (`common.dart:3981-3993`: **changes defaults** for approve-mode, whitelist, access-mode to `password-click`/`custom`/...; `checkUpdate` skipped; "powered by" widget). Mitigation: after the Phase 6 hard defaults land, the custom-client default table is dead code; verify with a settings-screen walk (Phase 11).
- Existing state is not migrated (new config dirs, new service name): intended; an official RustDesk can coexist after the rename.

### Phase W: Windows controlled side (installed mode + service; attended)
Facts [A] from the Windows audit unless tagged; `custom_server.rs:30-32` and the IPC handler `ipc.rs:1029-1061` are [V by lead].
**Delete** (the Phase 3-5 deletions also apply on Windows):
- Updater: all of `src/updater.rs` (downloads a GitHub exe/msi, HTTPS only, no signature/hash, runs it as SYSTEM via `launch_privileged_process` `windows.rs:832`; `update_new_version` `updater.rs:269`; `update_me_msi` `windows.rs:3912`; `update_to` `:3876`) and `rendezvous_mediator.rs:283-285`.
- Vendor-keyed / unsigned config channels: `custom.txt` (`load_custom_client` `common.rs:2360-2379`, `read_custom_client` `:2458-2463`, staging dir `windows.rs:1967,2018+`), **exe-name licence** (`get_license_from_exe_name` `windows.rs:2103`, `get_license` `:4066`, registry fallback `:4072-4074`, `install_me` applying it `:1696-1699`) and `custom_server.rs`, **which accepts an unsigned `CustomServer` JSON before checking the signature (`custom_server.rs:30-32` [V])**, so an installer file name like `handover-host=evil,key=....exe` or the `RUSTDESK_APPNAME` env set by the portable packer redirects the server at install time; the `--config <blob>` command (`core_main.rs:501`).
- Virtual display (closed `usbmmidd_v2`, `virtual_display_manager.rs:8,399-503`, `display_service.rs:907-909,986-1020`), `libs/virtual_display` + `dylib_virtual_display.dll`, **privacy mode** entirely (`privacy_mode.rs`, `win_topmost_window.rs` which injects (`QueueUserAPC`, `VirtualAllocEx`) into a copied `RuntimeBroker_rustdesk.exe`, `win_mag.rs`/`scrap/dxgi/mag.rs:702`, `WindowInjection.dll`, the RuntimeBroker copy at install `windows.rs:1479-1488` and `check_update_broker_process` `:1407`), `libs/remote_printer` + printer driver zips + `--install-remote-printer` at every install (`windows.rs:1699-1710`), `res/msi` (WiX, CustomActions, NuGet), `server/portable_service.rs` and `--quick_support`/`-qs-` portable modes, terminal OS-login token code (`create_process_with_logon`, `get_logon_user_token` `windows.rs:2785-3010`), peer shortcut creation via `cscript` (`windows.rs:2287`), `--install-idd`/`--uninstall-amyuni-idd`/`--uninstall-cert` (`core_main.rs:288-312`) and `windows_delete_test_cert.cc`, `C:\Windows\temp\test_rustdesk.log` (`windows.cc:22`), the IS1 Inno Setup fallbacks (`windows.rs:1300,1320-1326`).
**Harden** (the service and installer stay):
- Installer: force `%ProgramFiles%\Handover`; reject any UI/CLI-supplied install path (`install_me(path)` takes it from the UI `install_page.dart:79,261`; the audit says only characters are validated, so a user-writable path would place a SYSTEM-service exe in a user-writable directory, an LPE [A, validator not located by the lead]); `install_me` keeps: copy to Program Files, service create/start (`sc create ... binpath= "\"{exe}\" --service" start= auto`, LocalSystem, `windows.rs:3951,3930`), tray autostart, uninstall key, **outbound-only firewall rule** (drop the inbound rule, `windows.rs:1578-1579`; relay-only needs none).
- Registry: review `HKLM\...\Policies\System SoftwareSASGeneration=1` (`windows.rs:1581`, toggled at runtime in `send_sas` `:957-990`): needed only for remote Ctrl+Alt+Del; decide keep/drop in the Phase W review; if kept, temporary and restored.
- IPC (named pipe `\\.\pipe\{APP}\query`, `""` and `_service` created allow-everyone then authorised at accept time: peer SYSTEM or same session or elevated admin **and** peer exe path == own exe path, `auth.rs:472-495,622,749-820`): the SYSTEM server's `handle()` applies **any** `Data::Options(Some)` (arbitrary keys, `ipc.rs:1029-1041`), `Data::Config` (permanent password/salt/pin, `:1000-1022`; removed with D7) and **`Data::SyncConfig(Some)`, which replaces the whole `Config`/`Config2` including the key pair (`ipc.rs:1048-1053` [V])**, from any same-session same-exe process. Fix: allow-list the option keys a GUI process may set (a tiny set, none of server/key/approve-mode/relay/api), drop `SyncConfig(Some)` from the pipe, hard-code security options in the SYSTEM process. Any same-session process of the same exe can also stop the service (`Close`), send SAS, or make it launch `--server` in another session (`UserSid`, `windows.rs:725-755`): document as the user-to-service trust boundary and test that a *different* exe cannot.
- Process model: `--server` runs as SYSTEM with a winlogon token (`launch_server` `windows.rs:820`, `LaunchProcessWin` `windows.cc:233`); `--cm`/`--tray` run as the user via the explorer.exe token. Keep; hard-fail if the service pipe peer check fails.
- `OPTION_ALLOW_LOGON_SCREEN_PASSWORD` stays off (`connection.rs:2967-2988`); permanent password and `approve-mode` both/password removed in code (D7).
- Shell-outs to review/minimise (`netsh`, `sc`, `taskkill`, `wmic.exe` `windows.rs:4653,4728`, `cmd /C tasklist | findstr consent.exe` `:3181`, `chcp`, `certutil`, `findstr` in `installer_handoff.rs`): replace with API calls where trivial, otherwise keep with fixed absolute paths and no user-controlled arguments.
**Build (Windows host, MSVC)** [A, flutter-build.yml/vcpkg]: Rust 1.75 `x86_64-pc-windows-msvc`; VS 2022 Build Tools (MSVC v143 x64, Windows 10/11 SDK, CMake); LLVM/libclang 15.0.6; Flutter 3.24.5 + `.github/patches/flutter_3.24.4_dropdown_menu_enableFilter.diff`; vcpkg `9e593bb18ea69cc5095e012465dcd675a822ed0d` triplet `x64-windows-static` with only aom, libjpeg-turbo, opus, libvpx, libyuv (no ffmpeg/mfx/nvcodec/amf/qsv, no `--hwcodec`); Python 3 (`build.py`, `libs/portable/generate.py`); git; nasm (fetched by vcpkg); bridge files generated on Linux and copied (git-ignored; see §2a for the local libclang workaround). Drop: MSI/WiX/NuGet, Sciter, arm64, drivers, WindowInjection build, vendor signer, sbom/release actions. Commands: `python build.py --portable --flutter --skip-portable-pack`, then `python libs/portable/generate.py -f <release dir> -o . -e <release dir>/handover.exe`, output renamed `handover-install.exe` (running it starts `--install`). Open: test the stock Flutter 3.24.5 engine instead of `rustdesk/engine` `windows-x64-release.zip` (unpinned, purpose unknown) [U11]; vcpkg's own tool downloads (nasm, msys2, perl) are unpinned in this repo [U12].
**Signing** (user decision pending, §10): unsigned works functionally (`sc create` accepts it) but gives SmartScreen (only with Mark-of-the-Web), UAC "Unknown publisher" and typical AV flags; Windows 11 **Smart App Control** in enforcement mode blocks unsigned/unreputed binaries and a self-signed cert does not satisfy it. Self-signed option: `New-SelfSignedCertificate -Type CodeSigningCert`, `signtool sign /fd SHA256` on exe/dll/installer, import the cert into `LocalMachine\Root` and `TrustedPublisher` on each machine; keep the private key off the build host; copy the installer by scp/USB to avoid Mark-of-the-Web. The build signs nothing on the Flutter path today (`build.py:1051-1056` is the Sciter branch and contacts DigiCert) and CI uses a vendor remote signer: both unusable.
**Test/egress on Windows** (the physical laptop `<test-laptop>` over SSH, see §10): per-process egress via Windows Firewall rules scoped to `handover.exe` with default-block outbound except the test hbbs/hbbr, plus audit policy *Filtering Platform Connection* failure events (Security log **5157** records process path and destination), DNS through a logging resolver on the Linux host; interactive session via a scheduled task `/IT` for GUI and screen-capture tests.

### Phase L: Linux Wayland controller (outgoing-only)
Facts [V] by the Wayland audit unless tagged.
- **No local server on the controller.** On Flutter launch with empty args the UI process spawns `start_server`, which registers your ID/IP with hbbs, NAT-tests, opens `lan::start_listening` (UDP 0.0.0.0 if installed under /usr), `hbbs_http::sync::start()` and `test_av1` (`core_main.rs:205`, `server.rs:742-745`, `rendezvous_mediator.rs:274-406`). The initiator needs none of it (`PunchHoleRequest` goes straight to hbbs, `client.rs:943-950`). Compile outgoing-only: either `--no-server` baked into the launcher (`core_main.rs:105-106`) or HARD `conn-type=outgoing` (`is_outgoing_only`, `rendezvous_mediator.rs:276-279`), then delete the dead paths. [U: hbbs handling of an unregistered initiator, to confirm in the interop test.]
- **File transfer, Windows peer -> Linux controller (HIGH, [V by lead])**: `file_model.dart:639` builds `to: PathUtil.join(toPath, from.name, isWindows)` from the peer-supplied listing name with no validation (`p.posix.join(dir, '/etc/x')` returns `/etc/x`, `..` is not blocked); `io_loop.rs:889-893` passes it to `DataSource::FilePath(PathBuf::from(&to))`; `fs.rs:488-497` even exempts the empty single-file name. A hostile peer (a machine you are supporting may be compromised) can make a download land anywhere user-writable (`~/.config/autostart/*.desktop`, `~/.bashrc`); only the overwrite prompt (`is_write_need_confirmation`, `fs.rs:1455`) intervenes. Fix in Rust (authoritative) and Dart: reject entry names that are empty, `.`, `..`, absolute, or contain separators; join onto the chosen directory with canonicalisation and a `starts_with` check; open final files with `O_NOFOLLOW|O_EXCL` (`fs.rs:795` follows symlinks); reject `\` in names regardless of the reported peer platform. Present checks: `validate_file_name_no_traversal` (`fs.rs:463-491`), `validate_no_symlink_components` (`fs.rs:519`, TOCTOU noted), `transform_windows_path` (`fs.rs:1442`), `.download` + rename.
- **Clipboard**: peer text/images are written to the local clipboard with no prompt (`clipboard.rs:306`); a hostile peer can plant a shell command. Default `disable-clipboard` on for the controller, explicit per-session enable (or a visible indicator).
- **Build without `unix-file-copy-paste`** (`Cargo.toml:41-47`; pulls `fuser`, `x11-clipboard`, `x11rb`, a FUSE mount 0o777 `libs/clipboard/.../fuse/mod.rs:254`); the UI hides file clipboard automatically (`flutter_ffi.rs:2469`).
- **Keyboard/mouse**: on Wayland the rdev grab is unused; Flutter key events arrive only while the window is focused; Super/Meta is dropped (`input_model.dart:833`, win-key combos need the toolbar); shortcut inhibit applies to remote windows (`wayland_shortcuts_inhibit.cc`, compiled if wayland-protocols is found) so Hyprland binds stop working while a remote window is focused: provide an escape bind that bypasses inhibit (Hyprland `bindp`) [I, untested]. Relative mouse is hidden on Wayland (`relative_mouse_model.dart:191-193`); `bump_mouse` is X11-only. `RUSTDESK_FORCED_DISPLAY_SERVER=wayland` (`libs/base/src/platform/linux.rs:96`) must be set under nested/headless compositors (`loginctl` misreads them); rename this env var consistently with D9.
- **Startup noise to remove**: `main_get_main_display` on Wayland shells out to `xrandr`/`kscreen-doctor`/`gdbus` (`scrap/wayland/display.rs:180-184`); `tray-icon` runs in a separate `--tray` process (hide on the controller); the Flutter texture renderer is a CPU pixel buffer (no GL/X11 dependency), so the controller needs no portal/PipeWire.
- **Headless test**: Hyprland is installed; run `AQ_BACKENDS=headless Hyprland` (private `XDG_RUNTIME_DIR`), `hyprctl output create headless`, screenshots with `grim`; fallbacks `sway` (`WLR_BACKENDS=headless`), `weston --backend=headless` (no grim), `cage` (single window; remote windows are separate GTK windows, so prefer a tiling/floating compositor). Needs `dbus-run-session`, `--no-server`, `LIBGL_ALWAYS_SOFTWARE=1` if no GPU; do **not** start xdg-desktop-portal in the controller test, to prove no portal request happens. Missing here (all in `extra`): weston, sway, cage, labwc.

### Phase 8: Supply chain (F20, F28)
Decision D8 (user, 2026-10-04): **hybrid, not "vendor everything".**
- **Every git dependency**: replace branch/HEAD with `rev = <locked commit>` in all manifests (root + `libs/*`); `cargo build --locked` proves `Cargo.lock` did not move; `deny.toml` `[sources]` allow-lists exactly those git URLs.
- **Vendor** (`cargo vendor` of just these packages into `third_party/`, committed) only the git deps that are **small, vendor-controlled forks** whose code runs in the app and whose contents have no independent review: the `rustdesk-org` / personal-account forks (`rdev`, `magnum-opus`, `kcp-sys`, `arboard`, `clipboard-master`, `parity-tokio-ipc`, `evdev`, `keepawake`, `wallpaper`, `cpal`, `tao`, `tungstenite-rs`, `tokio-tungstenite`, `tokio-socks`, `confy`, `machine-uid`, `default_net`, `sysinfo`, `x11-clipboard`, `cacao`-class ones only if built on Linux, `webrtc` fork while it stays compiled), and the `clslaid`/`21pages`/`bjornsnoen` ones. Exclude from vendoring (pin by rev only): **well-established upstream projects** such as `wezterm`'s `portable-pty` (273 MB monorepo; the fork's only delta is a Windows user-token pty patch, not compiled on Linux, read by the crate audit), `tray-icon` (tauri-apps, no fork patches), and `fuser`/`x11-rs` (upstream-equivalent). Each exclusion is recorded with its rev and the reason in `deny.toml` comments.
- crates.io dependencies stay pinned by `Cargo.lock` checksums; `cargo deny check` (sources/licences/advisories) and `cargo audit` run before each release; the 20 client advisories (U7) are triaged for reachability and fixed where a semver-compatible bump exists, and the rest documented as unreachable or accepted. Keep a checksummed full `cargo vendor` tarball outside the git tree for offline rebuilds.
- Flutter: regenerate `pubspec.lock` under the pinned SDK (the committed lock is not what 3.24.5 resolves, §2a) and build with `--enforce-lockfile`; git plugins already pinned by commit. Pin Flutter 3.24.5 (+3.22.3 for bridge generation).
- Removed along the way: `sciter-rs`, `rust-webm` and `nokhwa` (D7), `stunclient`, the Dart `http` and `google_fonts` packages. Optional: `reqwest`/`hbbs_http` once unreferenced.

### Phase 9: Build, package, release (Linux controller + Windows installer)
`tools/build-linux.sh`: pinned toolchain, vendored deps, `--locked`, baked env, vcpkg libs only (libvpx, aom, libyuv, opus; hashed [A]). Own signing of checksums. Ignore vendor CI workflows.

### Phase 10: Server side (F15, F16)
Build pinned commit `--locked`, `cargo audit`; remove `check_software_update` (`src/main.rs:36`); run `-k _`; hardened systemd units (`User=`, `NoNewPrivileges`, `ProtectSystem=strict`, `ReadWritePaths`, `RestrictAddressFamilies`, `IPAddressDeny`); inbound only 21115-21119/tcp + 21116/udp from needed nets; outbound deny; key mode 0600 + backup; confirm console on :21115 bind scope (`ss -ltnp`) [U5].

### Phase 11: Acceptance
- Egress test (§7) green for **each process mode** (`--server`, `--service`, `--tray`, `--cm`, Flutter UI), idle, connect (direct+relay), file transfer, clipboard, wrong key, server down, peer offline, and a UI crawl clicking every menu/settings link.
- Binary scan: `strings` for `rustdesk.com|rustdesk.cn|rs-ny|api.rustdesk|admin.rustdesk|stun\.|nip.io|telegram|jitpack|googleapis` ⇒ only allow-listed strings. Constructed URLs (`common.rs:1157` format, `wss://…/ws/relay`) can evade grep ⇒ egress test is authoritative.
- Update AGENTS.md audit table with fixed-in hashes.

## 5. Phase order rationale
0 (measure, done) -> 1 (own code, remove dead UI) -> 2 (defaults/key/handshake) -> 3 (API) -> 4 (updates) -> 5 (third parties) -> 6 (defaults/attack surface) -> 7 (links, rename to Handover) -> L (Linux Wayland controller) and W (Windows controlled side; W needs the VM for its tests) -> 8 (supply chain) -> 9 (build/package: Linux controller package + Windows `handover-install.exe`) -> 10 (server) -> 11 (acceptance on both platforms). Egress test re-run after every phase 2-7, W and L.

## 6. Regression surface (existing files/paths that change)

`libs/hbb_common/src/{config,lib,webrtc,socket_client,websocket}.rs` · `src/common.rs` · `src/client.rs` ·
`src/rendezvous_mediator.rs` · `src/lan.rs` · `src/hbbs_http/*` · `src/server/connection.rs` · `src/updater.rs` ·
`src/flutter_ffi.rs`, `ui_interface.rs`, `core_main.rs`, `ipc.rs`, `auth_2fa.rs` · Flutter: `utils/http_service.dart`,
`models/{user,ab,group,model}_model.dart`, `common.dart`, `desktop_home_page.dart`, settings/login/toolbar/install pages, `pubspec.yaml` ·
`Cargo.toml` (all, incl. rev pins), `.gitmodules`, new `rust-toolchain.toml`, `deny.toml`, `build.py`, `res/DEBIAN/*`, `res/rustdesk.service`, `res/*.spec` · AGENTS.md.
Behaviour intentionally lost: accounts, address book, groups, audit, session upload, update checks, WebRTC, Telegram 2FA, `id@public`/`id@host`, server-pushed server lists, `custom.txt`, LAN discovery/WoL, deep-link config/password, avatar images from URLs.

## 7. Egress test design (D4)
Network namespace with only a veth to a stub hbbs/hbbr/peer; default-deny nftables; stub DNS inside the netns logging **every** query name (catches resolutions even when connections are refused); `tcpdump` on the veth (IPv4 **and IPv6**, including broadcast/multicast/mDNS/ARP-visible traffic) **and** `strace -f -e trace=network`; fail on any packet or query not to/for the allow-list (hbbs/hbbr/peer ports). Loopback is allowed but loopback listeners are enumerated (`ss`) and reviewed so a local forwarder can't hide egress. `/etc/hosts`/nscd resolution does not touch the network: note it. Timers: daily/hourly paths are exercised by direct invocation or fake clock; the server soak runs ≥24 h once.

## 8. Out of scope / residual (documented)
Windows is **in scope** as the controlled side (Phase W): its exe-name licence, updater, IDD/printer drivers, privacy mode and MSI are deleted there. macOS, Android/iOS, web, Flatpak/AppImage, Linux as a *controlled* side and the Sciter UI (removed in Phase 1) remain in the tree unreachable from the two supported builds and must be re-audited before anyone builds them. Hardware codecs disabled not removed. **Relay trust:** hbbr is an opaque pipe and traffic is end-to-end encrypted after `set_negotiated_key` (`client.rs:1717`, `server.rs:313-326`) *only once all downgrade branches are closed* (Phase 2); hbbs/hbbr still see IDs, IPs and timing, and session security is only as good as the hbbs-signed key plus D6 pinning. **ID enumeration:** hbbs answers online/offline/not-exist [U: not read]; mitigate with random non-default IDs (`--set-id`), `-k _`, IP allow-lists on 21116. The Flutter engine, vcpkg libs, kernel and remote crates are trusted as built from pinned sources; remote crates are read in Phase 8 only to the extent time allows. A compromised **own** hbbs is trusted.

## 9. Risks / unverified

| # | Item | Resolution |
|---|------|-----------|
| U1 | Client 1.5.0 ↔ server 1.1.17-dev interop | **Resolved [measured]**: direct punch and forced relay both interoperate (§2a); WebRTC/kx-v2 still unavailable (F17) |
| U2 | Dart account/ab UI visibility with empty API | Phase 3 run app |
| U4 | `src/` without `webrtc` feature | **Resolved [V, grep]**: `hbb_common::webrtc` is behind `#[cfg(feature="webrtc")]` (`lib.rs:62-63`) but `src/` uses it unconditionally (~52 references: `client.rs` 31, `rendezvous_mediator.rs` 18, `server.rs` 2, `common.rs` 1), so removing the feature = gating all of those. Phase 5 therefore keeps WebRTC **compiled but inert** (not viable, empty ICE list, no offers/answers, no STUN probe); removing the crate is optional and later |
| U5 | hbbs console :21115 bind scope | **Resolved [V, source]**: hbbs (:21115) and hbbr (:21117) listen on all interfaces and treat any plain TCP connection whose *source address is loopback* as an admin-console command (`rendezvous_server.rs:1123-1137`, `relay_server.rs:394-406`; also `rendezvous_server.rs:467` accepts a config serial update from loopback). Consequence: a local TCP reverse proxy/forwarder in front of hbbs/hbbr makes every remote connection look like loopback, i.e. remote admin. Phase 10: never proxy hbbs/hbbr over local TCP (the ws ports 21118/21119 are exempt from the check but trust `X-Real-IP`), firewall 21115/21117 from the Internet only where relay/NAT-test are needed, keep them off a shared host |
| U6 | Contents of remote git crates | **Largely resolved**: 35 cached crates pattern-audited, clean (§2a); transitive crates.io deps still open (Phase 8) |
| U7 | cargo-audit/deny results | **Triaged 2026-10-05** (cargo-deny, Linux+Windows graph, Rust 1.75 constraint). Fixed by lockfile bumps: crossbeam-channel 0.5.15 (RUSTSEC-2025-0024), openssl 0.10.72 + openssl-sys 0.9.108 (2025-0004, 2025-0022), rustls 0.23.45 + rustls-webpki 0.103.15 + rustls-pki-types (2026-0285, -0049, -0098, -0099, -0104), anyhow 1.0.104 (2026-0190). **Not fixable on 1.75** (need edition 2024 / newer rustc): time 0.3.47 (2026-0009) and url->idna 1.x (2024-0421). Remaining, with reachability: `quick-xml` 0.30/0.39 (2026-0194/-0195) and `libgit2-sys`/`git2` (2024-0013, 2026-0008/-0183/-0184): **build-dependencies only**, not in the shipped binary; `time` 0.3.36 via asn1-rs/webrtc-dtls (2026-0009): certificate parsing in WebRTC, which is inert; `time` 0.1.45 via fruitbasket: macOS only; `idna` 0.5.0 via `url` in hbb_common: parses only user-configured server addresses; `ringbuf` 0.3.3 (2026-0293): element type is `f32` (no Drop, so the panic-in-drop precondition cannot occur); `rand` 0.8.5 (2026-0097): needs a custom logger calling `rand::rng()`, not present; `users` 0.11.0 (2025-0040, 2023-0059/-0040): no fix exists, used for local user names only; `glib` 0.18.5, `memmap2` 0.9.8: local UI libraries (tray icon, winit), no network input. Unmaintained crates (adler, ansi_term, atty, bincode, derivative, dlopen_derive, instant, paste, proc-macro-error, rand_os, serial, sodiumoxide, ttf-parser, unic-*) are listed, not fixed. `cargo deny check sources` passes. The **server** lockfile is a separate item (Phase 10). |
| U8 | Hidden runtime egress | Phase 11 egress test |
| U9 | Effects of `is_custom_client()` flip | Phase 7 |
| U10 | Whether root service can drop root / be sandboxed and still capture+inject input | Phase 6 test |
| R1 | Upstream merge conflicts grow | Accepted; permanent fork; keep stubs signature-compatible |

## 10. Decisions

Resolved by the user 2026-10-04:
1. **Inline `hbb_common`.**
2. **Toolchain install: done.**
3. **Hybrid vendoring (D8).**
4. **WebRTC: neutralise.**
5. **Direct `host:port` dialling and the direct-server listener: rejected.**
6. **Attended-only (D7)**: no unattended, no camera, no recording.
7. **Name: Handover, `me.heimbs.Handover` (D9)**, replacing the earlier "keep RustDesk".
8. **Service kept for availability (D10)**: Windows service stays; Linux controller has none.
9. **Roles**: controlled = Windows 10/11 x64 (installed mode); controller = Linux Wayland (Hyprland).
10. **Windows test VM on another host** (details below).

Adopted defaults, not yet explicitly answered: one-time temporary password **plus** local click; terminal, tunnel/RDP and remote restart removed; clipboard and file transfer on the controlled side (clipboard off-by-default on the controller, Phase L); TOTP/Telegram 2FA removed.

11. **Windows signing: self-signed** (cert trusted on the user's machines; installer copied by scp/USB, no Mark-of-the-Web).
12. **Windows targets: Windows 11 Home and Pro, up to 5 machines.** Check Smart App Control on each (`(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy').VerifiedAndReputablePolicyState`: 0 off, 1 enforcing, 2 evaluation); Home has no Group Policy editor or Windows Sandbox/Hyper-V guest features, so nothing in the install flow may depend on them.
13. **Controller tests run in the user's existing Hyprland session** (`wayland-1`), not a headless compositor, so no `sway`/`weston` install is needed. Keep the user's desktop undisturbed with a window rule that sends the Handover class to a dedicated workspace silently; remember Hyprland shortcut-inhibit applies while a remote window is focused.

**Windows build/test host (verified 2026-10-04 over SSH, `<user>@<test-laptop>`, key `~/.ssh/id_ed25519`):** a **physical** laptop (not a VM): Windows 11 Home 10.0.22621 (22H2), de-DE, 12 logical CPUs, 15.7 GB RAM, 879 GB free on C:, user `<user>` is a local administrator and the auto-logged-in interactive console user (`AutoAdminLogon=1`), OpenSSH Server running with PowerShell as default shell, Smart App Control state 0 (off), UAC on, Defender real-time protection on, firewall enabled (outbound default NotConfigured), `winget` present, no git/Rust/VS/LLVM/Flutter/Python (only the Store alias) installed. Network: reachable from this Linux host over the overlay network mesh (`the overlay interface` <overlay-ip>, resolves `<test-laptop>`); the laptop reaches this host's `the overlay interface` address <overlay-ip> (TCP test on :21115 succeeded) but **not** its LAN address <lan-ip>. So hbbs/hbbr for Windows tests listen on / are addressed by `<overlay-ip>` (`<linux-host>`); the overlay network overlay is the user's own and counts as the trusted test network. Helper scripts: `target/trust/vm/vmssh.sh <script.ps1>` (scp + `-File`; piping scripts via stdin is unreliable on this shell).
Constraints that follow from it being a real, snapshot-less machine: toolchains go under the `<user>` account via `winget`/user-scope installs where possible; any test that installs the Handover **service**, firewall rules or registry policy must be fully reversible (`--uninstall`, `netsh advfirewall` rule removal, registry restore) and is run only with the user's go-ahead; Hyper-V is present (`HypervisorPresent=True`) but Home lacks Windows Sandbox, so there is no throw-away guest; consider a second Windows account or a overlay network-reachable throwaway VM later if clean-room installs matter.

Open, needed from the user:
- **Permission to install the Windows toolchain on `<test-laptop>`** (Visual Studio 2022 Build Tools C++ workload ~6-10 GB, Windows SDK, Git, Rust 1.75 MSVC, LLVM 15.0.6, Python 3, nasm, Flutter 3.24.5, vcpkg libs) via `winget`/direct downloads, and **permission to install/uninstall the Handover service on this laptop for tests** (reversible, see above).

Plan is complete for implementation to start at Phase 1; Phases W and L need the Windows host for their tests, not for their code changes.
