# Handover server (hbbs + hbbr)

Handover uses the open-source `rustdesk-server` (AGPL-3.0): `hbbs` (rendezvous) and `hbbr` (relay).
Nothing here uses the closed Pro server or its API.

## Build

```
server/build.sh            # clones upstream at a pinned commit, verifies the hbb_common submodule,
                           # applies server/patches/*.patch (0001-0005), copies libs/handover_cred, builds with --locked, prints SHA256SUMS
```

Pinned: `rustdesk/rustdesk-server@a7736be5e40f85bfc141120dce587e836e5d4b80` (hbb_common
`69cea8dafee147848ae88702029f4bf7df7224c3`), built with rustc 1.99.0.

What the patches change (and why):

| Patch | Change |
|---|---|
| `0001-hardening.patch` | `hbbs` no longer makes its only outbound connection (a daily update check to the vendor, measured in an offline netns); unused `reqwest`, `axum` and `minreq` dependencies are removed (drops `h2`, `hyper`, `axum-core`, `native-tls` from the tree); lock bumps for `anyhow`, `crossbeam-epoch`, `openssl`; WebSocket connections on 21118/21119 are refused before any HTTP parsing (the browser client is not used and the WebSocket stack, `tungstenite` 0.17, has a remote DoS advisory). |
| `0002-hbb_common-no-version-check.patch` | removes the hard-coded vendor version-check URL and request builder from the shared library. |
| `0003-bump-rustls.patch` | lockfile only: `rustls` 0.23.42 -> 0.23.45 and `rustls-webpki` 0.103.13 -> 0.103.15 (RUSTSEC-2026-0285). Re-resolving also moved one Windows-only `windows-targets` entry, irrelevant on Linux. |
| `0004-handover-admission.patch` | Admission (see "Admission" below): `hbbs` and `hbbr` check a signed token on registration, public-key registration, connection and relay requests and the responses machines send; refuse to start without `HANDOVER_CA_PUB`; `HANDOVER_REVOKED` revocation file; `hbbs`'s own loopback self-test registration is exempt. Uses the credential crate `libs/handover_cred`, which `build.sh` copies into the tree (it is not part of the patch). |
| `0005-hbb_common-admission-fields.patch` | `string licence_key = 20` on `RegisterPeer`, `RegisterPk`, `PunchHoleSent`, `LocalAddr` and `RelayResponse` (the admission token), matching the client's `rendezvous.proto`. |

## Run

Use the hardened units in `server/systemd/` (sandboxing, no capabilities, `IPAddressDeny=any` with an
allow-list). They are templates: addresses come from your git-ignored `.env` (copy `.env.example`):

```
cp .env.example .env     # set HANDOVER_RELAY_HOST, HANDOVER_ALLOWED_NETS and HANDOVER_CONTROLLER_CA (issuer public key, see docs/ADMISSION.md) and the client settings
server/render-units.sh   # writes server/build/systemd/*.service with your values (git-ignored)

useradd --system --home /var/lib/handover-server --shell /usr/sbin/nologin handover
install -d -o handover -g handover -m 0700 /var/lib/handover-server
install -m 0755 server/build/bin/hbbs server/build/bin/hbbr /usr/local/bin/
cp server/build/systemd/*.service /etc/systemd/system/
systemctl enable --now handover-hbbs handover-hbbr
cat /var/lib/handover-server/id_ed25519.pub         # put this in .env as HANDOVER_SERVER_KEY, then build the clients
```

Both units score 1.5 (OK) on `systemd-analyze security`. Their sandbox directives were also run for real as transient services
in a user manager (20 properties each: syscall filter `@system-service`, `MemoryDenyWriteExecute`, dropped capabilities, address-family and
namespace restrictions, kernel/clock/hostname protections, `UMask=0077`): both stayed up, listened on 21115-21119, created their key and database
files, and `hbbs` answered a real controller (key exchange + database lookup) with no seccomp kills. The parts that need a system manager and root (`User=`/`Group=`, `ProtectHome`, `PrivateTmp`, `ReadWritePaths`, `IPAddressDeny`/`IPAddressAllow`) are covered by the script below. Check `journalctl -u handover-hbbs` after the first real start.

**Result of the run on 2026-10-07 (systemd, a dedicated user): 16 of 16 checks PASS** - units active, `hbbs` runs as the dedicated user, key created with mode 600 and owned by it, loopback allowed, a connection from a non-allowed source address dropped by the IP filter, `ProtectHome` and `ProtectSystem=strict` effective, own mount namespace, no effective capabilities, no seccomp kills in the journal; everything was removed again.

`sudo server/test-system-units.sh <dir with hbbs and hbbr>` runs exactly these missing parts for real under test names (own user, `/var/lib/handover-server-test`,
units `handover-test-*`), checks the user, key permissions, `ProtectHome`/`ProtectSystem`, empty capabilities and that a connection from a non-allowed
source address is dropped by the IP filter, and removes everything again on exit.

## Ports

| Port | Service | Notes |
|---|---|---|
| 21116 tcp+udp | hbbs | rendezvous: clients and controlled machines |
| 21115 tcp | hbbs | NAT test **and the admin console, see below** |
| 21117 tcp | hbbr | relay |
| 21118, 21119 tcp | hbbs, hbbr | WebSocket: closed by the patch, block them at the firewall too |

Only your own networks should reach these ports; nothing needs the Internet. Allow outbound DNS only if
you resolve hostnames; the servers themselves make no outbound connections.

## Admission: only clients you signed

`-k _` on the stock servers is **not** an access control. It only compares a shared string, the server's own public key
(printed in the clients' settings), and only on two messages: the connection request to `hbbs` and the relay request to
`hbbr`. Registration (UDP `RegisterPeer`/`RegisterPk`), the relay request forwarded by `hbbs`, and the responses machines
send (`PunchHoleSent`, `LocalAddr`, `RelayResponse`) are not checked at all, so anyone can register IDs and anyone who
reads the key out of a client can start connections.

Patches 0004/0005 replace that with signed admission. You hold an issuer key (`handover-ca init <dir>`, kept offline,
encrypted with a passphrase) and sign credentials for the machines and controllers you trust (`handover-ca issue`).
Every message to `hbbs`/`hbbr` carries a token: the credential plus a proof bound to that message, a timestamp (ten-minute
window) and a nonce. The servers check the issuer's signature, the validity window, the role, the proof, the revocation
list and that the token was not used before:

| Message | Needs |
|---|---|
| connection request, relay request to `hbbs` | a **controller** credential |
| registration, public-key registration, `PunchHoleSent`, `LocalAddr`, `RelayResponse`, relay request to `hbbr` | a **device** or a controller credential |

Configuration (units: `Environment=` lines, rendered by `render-units.sh` from `HANDOVER_CONTROLLER_CA` in `.env`):
`HANDOVER_CA_PUB` is the issuer's public key; **without it the servers refuse to start**. `HANDOVER_REVOKED` names a file
with one serial per line (`#` comments), re-read within seconds, no restart. Refusals are logged with the reason, one line
per second at most. Revoking stops new registrations and connection requests; a session that is already running is not ended.

## Warnings

* **Admin console:** `hbbs` (21115) and `hbbr` (21117) treat any plain TCP connection whose *source
  address is loopback* as an administrative command (relay list, IP blocker, always-use-relay, ...).
  Do **not** put a local TCP proxy or forwarder in front of them: every proxied connection would look
  like loopback and become a remote admin. Do not run them on a shared host.
* **Key:** `id_ed25519` (mode 0600, in the working directory) is the server identity. Back it up: losing
  it forces every client to be rebuilt with the new public key. Clients refuse a server whose key does
  not match the one baked into their build (`Key mismatch`).
* **Rendezvous channel:** the open-source `hbbs` does not implement the newer signed key exchange, so
  the client-to-`hbbs` signalling is not encrypted at the application layer (peer IDs, addresses). The
  session to the peer is end-to-end encrypted. Run the servers on a private overlay network or add
  network-level encryption.
* **Known server advisories** (`cargo deny check advisories`, Phase 10): remaining items are
  `libsqlite3-sys`/`sqlx` 0.6 (CVE-2022-35737 needs multi-gigabyte `printf` strings; judged unreachable
  through the parameterised queries, not tested), `rustls`/`webpki`/`ring` (TLS code pulled in by the shared library; the servers start no TLS listener,
  inferred from the code, not tested), `tungstenite` 0.17 (WebSocket refused before parsing), `quick-xml`
  (wayland build tooling, not in the binary), `rand`, `users`, `remove_dir_all` (not reachable from the
  network). Updating sqlx/tungstenite needs upstream API changes and is not done.

## Known dependency advisories (cargo audit, 2026-10-05)

After the patches, `cargo audit` still lists 10 advisories. None is reachable in `hbbs`/`hbbr`; they are left in place because fixing them means
rewriting the database layer (sqlx 0.6 -> 0.8) for no runtime benefit:

| Advisory | Crate | Why it is not reachable |
|---|---|---|
| RUSTSEC-2026-0194, -0195 | `quick-xml` 0.39 | only a `wayland-scanner` proc-macro (build time) pulled in through `hbb_common` |
| RUSTSEC-2023-0018 | `remove_dir_all` 0.5 | only via `tempfile` in `protobuf-codegen` (build time) |
| RUSTSEC-2025-0009, 2024-0336, 2023-0052 | `ring` 0.16, `rustls` 0.20, `webpki` 0.22 | only through `sqlx`'s optional TLS for network databases and `jsonwebtoken`; the server uses a local SQLite file, no TLS handshake happens; the AES overflow panic needs overflow checks (off in release) |
| RUSTSEC-2022-0090 | `libsqlite3-sys` 0.24 (SQLite 3.39) | needs attacker-controlled data in `sqlite3_snprintf` format strings; the server only uses bound parameters |
| RUSTSEC-2024-0363 | `sqlx` 0.6 | Postgres/MySQL wire-protocol length bug; not used with SQLite |
| RUSTSEC-2023-0065 | `tungstenite` 0.17 | WebSocket DoS; WebSocket connections are refused before any HTTP parsing (patch 0001) |
| RUSTSEC-2025-0040 | `users` 0.11 | no fix exists; local user/group lookups only |

Unmaintained/yanked crates (`ahash`, `crossbeam-channel`, `ed25519` 1.5, `spin`) are listed by `cargo audit` as warnings only.
