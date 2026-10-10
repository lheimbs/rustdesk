# Operating admission (signed controllers and machines)

Design and measurements: `docs/TRUST_HARDENING_PLAN.md` section 2q and decision D16. This file is the operator's guide: what
to create, where each file goes, how to renew and revoke, and what the error messages mean. No secret ever goes into the
repository, `.env`, a ticket or a chat message.

## What exists

| Thing | What it is | Where it lives |
|---|---|---|
| Issuer key | Ed25519 secret key that signs every credential; the crown jewel | `<issuer dir>/ca.key` (encrypted with a passphrase) on a machine that is **not** a controller; keep an offline backup |
| Issuer public key | 44-character base64, printed by `handover-ca init`, also in `<issuer dir>/ca.pub` | `.env` as `HANDOVER_CONTROLLER_CA` (clients, server units); servers read it as `HANDOVER_CA_PUB` |
| Controller credential | role `controller`, default 90 days | `controller.cred` in the controller's Handover config directory (mode 0600) |
| Device credential | role `device`, default 365 days | baked into a build (`HANDOVER_DEVICE_CRED`, shared by all machines of that build) or a `device.cred` file in a machine's config directory (wins over the baked one) |
| Revocation list | one serial per line, `#` comments | the file named by `HANDOVER_REVOKED` on the server (units: `/var/lib/handover-server/revoked.txt`) |

Credentials and their files contain the holder's **secret** key: treat them like passwords.

## One-time setup

1. Build the tool: `cargo build --release -p handover-cred` (binary `target/release/handover-ca`).
2. On the issuer machine: `handover-ca init <issuer dir>` (asks for a passphrase of at least 12 characters twice). It prints
   `HANDOVER_CONTROLLER_CA=<public key>`: put that line in `.env` (see `.env.example`).
3. Build the servers (`server/build.sh`) and render the units (`server/render-units.sh`); the units carry the public key. Without
   `HANDOVER_CA_PUB` the servers refuse to start, by design. Create an empty revocation file in the state directory.
4. Build the clients with `HANDOVER_CONTROLLER_CA` set (release builds refuse to build without it), optionally with
   `HANDOVER_DEVICE_CRED` set to the output of `handover-ca compact device.cred`.

## Issuing

```
handover-ca issue <issuer dir> --role controller --label "my laptop" --out controller.cred          # 90 days
handover-ca issue <issuer dir> --role device     --label "customer a" --days 365 --out device.cred
handover-ca inspect controller.cred --ca-pub <issuer dir>/ca.pub     # role, label, serial, validity, key matches
handover-ca compact device.cred                                      # one-line form for HANDOVER_DEVICE_CRED
```

Copy the controller credential to the controller machine (`controller.cred` in the config directory, for example
`~/.config/handover/` on Linux) over a channel you trust, then delete the copy on the issuer machine. Give each customer a
device credential only if you want to revoke that customer separately (file in their config directory); otherwise the baked
one is enough. The label is what appears in the controlled machine's `connections.log` next to the serial.

## Renewing, revoking, rotating

* **Renew** before expiry: issue a new credential with the same label and replace the file. A machine's clock may be off by up
  to a day without trouble (credentials) and ten minutes (tokens).
* **Revoke**: add the serial (from `handover-ca inspect`) to the revocation file on the server. Effective within about 5 seconds, no
  restart. A revoked controller can no longer start connections; a revoked device can no longer register or relay and its machine
  appears offline. A running session is not ended. A serial from another credential revokes nothing: check with `inspect`.
* **Rotate the issuer key** (suspected leak): make a new issuer, set the new public key in `.env`, rebuild and redistribute every
  client and server, issue new credentials. The old credentials stop working everywhere at once.
* Never put `ca.key` on a server or a controller.

## Reading the messages

| You see | It means |
|---|---|
| controller: "Not a trusted controller" | the controlled machine did not accept the controller credential (missing, other issuer, wrong role, expired, wrong key); the machine's `connections.log` has `controller-refused ... <reason>` |
| controller: "Key mismatch" at connect | `hbbs` refused the connection request token; the server log has `admission refused (punch) ...: <reason>` |
| controller: "Remote desktop is offline" although the machine runs | the machine's registrations are refused (revoked or missing device credential, or a clock off by more than ten minutes); look for `admission refused (register)` in the `hbbs` log |
| server log `admission refused (<kind>) ...: <reason>` | reasons: malformed token (no credential), not signed by the trusted issuer, wrong role, expired, not yet valid, token timestamp outside the window, token already used, revoked, proof failed |
| a server exits about 12 seconds after start | its own start-up self-test was refused: the admission patch must exempt the loopback self-test registration (it does; check the patches were applied) |
| "Password required" / "Wrong password" | the credential was accepted; now the one-time password shown on the controlled machine is needed, then its owner clicks Accept |

## Checking a deployment

`docs` runbook (issue #33, "Admission test") lists the test matrix; `tools/egress-check.sh offline 40` with `CRED=<file>` and
`KEEP=1` against the admission binaries shows the server's view in an offline namespace.
