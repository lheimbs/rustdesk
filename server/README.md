# Handover server (hbbs + hbbr)

Handover uses the open-source `rustdesk-server` (AGPL-3.0): `hbbs` (rendezvous) and `hbbr` (relay).
Nothing here uses the closed Pro server or its API.

## Build

```
server/build.sh            # clones upstream at a pinned commit, verifies the hbb_common submodule,
                           # applies server/patches/*.patch, builds with --locked, prints SHA256SUMS
```

Pinned: `rustdesk/rustdesk-server@a7736be5e40f85bfc141120dce587e836e5d4b80` (hbb_common
`69cea8dafee147848ae88702029f4bf7df7224c3`), built with rustc 1.99.0.

What the patches change (and why):

| Patch | Change |
|---|---|
| `0001-hardening.patch` | `hbbs` no longer makes its only outbound connection (a daily update check to the vendor, measured in an offline netns); unused `reqwest`, `axum` and `minreq` dependencies are removed (drops `h2`, `hyper`, `axum-core`, `native-tls` from the tree); lock bumps for `anyhow`, `crossbeam-epoch`, `openssl`; WebSocket connections on 21118/21119 are refused before any HTTP parsing (the browser client is not used and the WebSocket stack, `tungstenite` 0.17, has a remote DoS advisory). |
| `0002-hbb_common-no-version-check.patch` | removes the hard-coded vendor version-check URL and request builder from the shared library. |
| `0003-bump-rustls.patch` | lockfile only: `rustls` 0.23.42 -> 0.23.45 and `rustls-webpki` 0.103.13 -> 0.103.15 (RUSTSEC-2026-0285). Re-resolving also moved one Windows-only `windows-targets` entry, irrelevant on Linux. |

## Run

Use the hardened units in `server/systemd/` (sandboxing, no capabilities, `IPAddressDeny=any` with an
allow-list). They are templates: addresses come from your git-ignored `.env` (copy `.env.example`):

```
cp .env.example .env     # set HANDOVER_RELAY_HOST and HANDOVER_ALLOWED_NETS (and the client settings)
server/render-units.sh   # writes server/build/systemd/*.service with your values (git-ignored)

useradd --system --home /var/lib/handover-server --shell /usr/sbin/nologin handover
install -d -o handover -g handover -m 0700 /var/lib/handover-server
install -m 0755 server/build/bin/hbbs server/build/bin/hbbr /usr/local/bin/
cp server/build/systemd/*.service /etc/systemd/system/
systemctl enable --now handover-hbbs handover-hbbr
cat /var/lib/handover-server/id_ed25519.pub         # put this in .env as HANDOVER_SERVER_KEY, then build the clients
```

Both units are verified with `systemd-analyze` only (exposure 1.6); they have not been run under
systemd in the test lab, so check `journalctl -u handover-hbbs` after the first start.

## Ports

| Port | Service | Notes |
|---|---|---|
| 21116 tcp+udp | hbbs | rendezvous: clients and controlled machines |
| 21115 tcp | hbbs | NAT test **and the admin console, see below** |
| 21117 tcp | hbbr | relay |
| 21118, 21119 tcp | hbbs, hbbr | WebSocket: closed by the patch, block them at the firewall too |

Only your own networks should reach these ports; nothing needs the Internet. Allow outbound DNS only if
you resolve hostnames; the servers themselves make no outbound connections.

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
