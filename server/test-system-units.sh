#!/bin/bash
# Run the hardened systemd units for real (system manager, root) and check what a user manager cannot:
# User=/Group=, ProtectHome, PrivateTmp, ReadWritePaths and the IPAddressDeny/IPAddressAllow filter.
# Everything is created under test names and removed again (trap), nothing of a real installation is touched.
#
#   sudo server/test-system-units.sh <dir with the built hbbs and hbbr>        e.g. target/trust/bin
#
# Needs: systemd, root, an IPv4 address on a non-loopback interface (used as the "denied" source), bash, ss.
set -u
[ "$(id -u)" = 0 ] || { echo "run as root (sudo)" >&2; exit 2; }
BIN=${1:?usage: $0 <dir with hbbs and hbbr>}
[ -x "$BIN/hbbs" ] && [ -x "$BIN/hbbr" ] || { echo "hbbs/hbbr not found in $BIN" >&2; exit 2; }
HERE=$(cd "$(dirname "$0")" && pwd)
U=handover-test; STATE=/var/lib/handover-server-test; LIB=/usr/local/lib/handover-test; DST=/etc/systemd/system
HOSTIP=$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -n1)
[ -n "$HOSTIP" ] || { echo "no non-loopback IPv4 address found" >&2; exit 2; }
FAIL=0
ok()  { echo "PASS  $*"; }
bad() { echo "FAIL  $*"; FAIL=1; }

cleanup() {
  systemctl stop handover-test-hbbs handover-test-hbbr 2>/dev/null
  rm -f "$DST/handover-test-hbbs.service" "$DST/handover-test-hbbr.service"
  systemctl daemon-reload
  userdel "$U" 2>/dev/null; rm -rf "$STATE" "$LIB"
  echo "cleaned up (units, user, $STATE, $LIB)"
}
trap cleanup EXIT

useradd --system --home "$STATE" --shell /usr/sbin/nologin "$U" || { echo "cannot create user $U (left over from a failed run? userdel $U)" >&2; trap - EXIT; exit 2; }
install -d -o "$U" -g "$U" -m 0700 "$STATE"
install -d -m 0755 "$LIB"; install -m 0755 "$BIN/hbbs" "$BIN/hbbr" "$LIB/"

# Render the shipped templates: test names, test paths, the allow-list reduced to loopback so that a connection
# from the host's own non-loopback address must be dropped by the IP filter.
for n in hbbs hbbr; do
  sed -e "s#^User=handover#User=$U#; s#^Group=handover#Group=$U#" \
      -e "s#/var/lib/handover-server#$STATE#g; s#/usr/local/bin/#$LIB/#" \
      -e "s#@CA_PUB@#$(head -c 32 /dev/urandom | base64)#g" \
      -e "s#@RELAY_HOST@#127.0.0.1#g; s#^IPAddressAllow=.*#IPAddressAllow=127.0.0.0/8#; s#@ALLOWED_NETS@#127.0.0.0/8#g" \
      "$HERE/systemd/handover-$n.service" > "$DST/handover-test-$n.service"
done
grep -q '@RELAY_HOST@\|@ALLOWED_NETS@\|@CA_PUB@' "$DST/handover-test-hbbs.service" && { echo "unrendered placeholder left in the unit" >&2; exit 2; }
systemctl daemon-reload
systemctl start handover-test-hbbr handover-test-hbbs
sleep 4

for n in hbbs hbbr; do
  systemctl is-active --quiet handover-test-$n && ok "$n is active" || bad "$n is not active (journalctl -u handover-test-$n)"
done
ps -o user= -C hbbs | grep -qx "$U" && ok "hbbs runs as $U, not root" || bad "hbbs does not run as $U"
[ -f "$STATE/id_ed25519" ] && [ "$(stat -c %a "$STATE/id_ed25519")" = 600 ] && ok "key created in the state dir, mode 600" || bad "key missing or not mode 600 in $STATE"
[ -z "$(find "$STATE" ! -user "$U" 2>/dev/null)" ] && ok "state dir contents belong to $U" || bad "files in $STATE not owned by $U"
ss -ltn | grep -q ':21116 ' && ok "hbbs listens on 21116" || bad "hbbs does not listen on 21116"

timeout 4 bash -c 'exec 3<>/dev/tcp/127.0.0.1/21116' && ok "loopback source is allowed by IPAddressAllow" || bad "loopback source was refused"
if timeout 4 bash -c "exec 3<>/dev/tcp/$HOSTIP/21116" 2>/dev/null; then
  bad "connection from a non-allowed source ($HOSTIP -> $HOSTIP) went through: IPAddressDeny is not effective"
else
  ok "connection from a non-allowed source is dropped (IPAddressDeny=any + IPAddressAllow)"
fi

for n in hbbs hbbr; do
  P=$(systemctl show -p MainPID --value handover-test-$n)
  [ "$P" != 0 ] || continue
  [ -z "$(nsenter -t "$P" -m ls -A /home 2>/dev/null)" ] && ok "$n sees an empty or inaccessible /home (ProtectHome)" || bad "$n can list /home (ProtectHome)"
  nsenter -t "$P" -m sh -c 'touch /usr/local/lib/handover-test/x 2>&1' 2>/dev/null | grep -qi "read-only\|denied" && ok "$n cannot write outside ReadWritePaths (ProtectSystem=strict)" || bad "$n could write to the program directory"
  [ "$(readlink /proc/$P/ns/mnt)" != "$(readlink /proc/1/ns/mnt)" ] && ok "$n has its own mount namespace (PrivateTmp/ProtectSystem)" || bad "$n shares the host mount namespace"
  [ "$(awk '/^CapEff/ {print $2}' /proc/$P/status)" = 0000000000000000 ] && ok "$n has no effective capabilities" || bad "$n has capabilities"
done
echo "journal (last lines, check for seccomp kills / permission errors):"
journalctl -u handover-test-hbbs -u handover-test-hbbr --no-pager -n 6 2>/dev/null | cut -c1-160
[ "$FAIL" = 0 ] && echo "RESULT: PASS" || echo "RESULT: FAIL"
exit "$FAIL"
