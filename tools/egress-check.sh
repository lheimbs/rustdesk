#!/bin/bash
# Run the Handover controller UI (and/or the servers) in an isolated, offline network namespace and fail
# if anything connects or resolves a name outside the allow-list (loopback + the throwaway server address).
#
#   tools/egress-check.sh ui     [seconds]   idle Flutter UI of the Linux controller, own hbbs/hbbr present
#   tools/egress-check.sh server [seconds]   hbbs + hbbr alone (they must make no outbound connection)
#   tools/egress-check.sh down   [seconds]   controller tries to connect while the servers are down (retry loops)
#   tools/egress-check.sh selftest [seconds] a deliberately leaking process: must FAIL (checks the checker itself)
#   tools/egress-check.sh offline [seconds]  servers up, controller connects to an ID nobody registered (peer offline)
#   tools/egress-check.sh wrongkey [seconds] controller carries a different server key than the running hbbs
#
# Needs: unshare (user namespaces), strace, Xvfb, dbus-run-session (ui mode), python3.
# Env:   SERVER_BIN  dir with hbbs and hbbr (default server/build/bin, built by server/build.sh)
#        BUNDLE      Flutter bundle executable (default flutter/build/linux/x64/debug/bundle/handover)
#        KEEP=1      keep the work directory (logs) instead of deleting it
#        PCAP=0      skip the packet capture (default: needs tcpdump)
# The namespace has a fake uplink (a dummy interface with default routes), so connect() succeeds and every packet that
# would have left the machine (IPv4/IPv6, multicast, broadcast, whatever syscall sent it) is recorded and must be empty.
set -euo pipefail

MODE=${1:-ui}
DUR=${2:-60}
HERE=$(cd "$(dirname "$0")/.." && pwd)
SERVER_BIN=${SERVER_BIN:-$HERE/server/build/bin}
BUNDLE=${BUNDLE:-$HERE/flutter/build/linux/x64/debug/bundle/handover}
SRV_IP=10.77.0.1   # not loopback: hbbs/hbbr treat any loopback TCP peer as an admin console

PCAP=${PCAP:-1}
[ "$PCAP" = 0 ] || command -v tcpdump >/dev/null || { echo "missing tool: tcpdump (or PCAP=0)" >&2; exit 2; }
for t in unshare strace python3; do command -v "$t" >/dev/null || { echo "missing tool: $t" >&2; exit 2; }; done
[ -x "$SERVER_BIN/hbbs" ] && [ -x "$SERVER_BIN/hbbr" ] || { echo "hbbs/hbbr not found in $SERVER_BIN (run server/build.sh)" >&2; exit 2; }
if [ "$MODE" != server ] && [ "$MODE" != selftest ]; then
  for t in Xvfb dbus-run-session; do command -v "$t" >/dev/null || { echo "missing tool: $t" >&2; exit 2; }; done
  [ -x "$BUNDLE" ] || { echo "controller bundle not found: $BUNDLE" >&2; exit 2; }
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/handover-egress.XXXXXX")
[ "${KEEP:-0}" = 1 ] || trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/srv" "$WORK/home/.config/handover"

cat > "$WORK/inner.sh" <<INNER
#!/bin/bash
set -u
ip link set lo up
ip addr add $SRV_IP/32 dev lo
TCPD=0
if [ "$PCAP" != 0 ]; then
  ip link add up0 type dummy && ip link set up0 up && ip addr add 192.0.2.2/24 dev up0 \\
    && ip -6 addr add 2001:db8::2/64 dev up0 nodad && ip route add default via 192.0.2.1 dev up0 \\
    && ip -6 route add default via 2001:db8::1 dev up0 \\
    && ip neigh add 192.0.2.1 lladdr 02:00:00:00:00:01 dev up0 nud permanent \\
    && ip -6 neigh add 2001:db8::1 lladdr 02:00:00:00:00:01 dev up0 nud permanent \\
    || { echo "could not create the fake uplink" >&2; echo 1 > "$WORK/nouplink"; exit 0; }
  tcpdump -i up0 -nn -e -U -w "$WORK/uplink.pcap" >/dev/null 2>&1 &
  TCPD=\$!
  sleep 1
fi
cd "$WORK/srv"
HBBS=0; HBBR=0
if [ "$MODE" != down ]; then
  $SERVER_BIN/hbbs -k _ -r $SRV_IP:21117 >"$WORK/hbbs.log" 2>&1 &
  HBBS=\$!
  $SERVER_BIN/hbbr -k _ >"$WORK/hbbr.log" 2>&1 &
  HBBR=\$!
fi
sleep 3
if [ "$MODE" = selftest ]; then
  # positive control: a process that does leak must make this run FAIL on both the syscall trace and the capture
  strace -f -qq -s 300 -e trace=connect,sendto,sendmsg -o "$WORK/strace.txt" \\
    timeout $DUR python3 -c "
import socket,time
s=socket.socket(); s.settimeout(1)
try: s.connect(('203.0.113.9',443))
except OSError: pass
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); u.sendto(b'x',('224.0.0.251',5353))
u.sendto(b'x',('203.0.113.9',3478))
time.sleep(60)"
  echo \$? > "$WORK/rc"
elif [ "$MODE" = server ]; then
  # the servers were started before strace could attach: restart them under strace
  kill \$HBBS \$HBBR 2>/dev/null; wait \$HBBS \$HBBR 2>/dev/null
  strace -f -qq -s 300 -e trace=connect,sendto,sendmsg -o "$WORK/strace.txt" \
    timeout $DUR bash -c "$SERVER_BIN/hbbs -k _ -r $SRV_IP:21117 >/dev/null 2>&1 & $SERVER_BIN/hbbr -k _ >/dev/null 2>&1 & wait"
  echo \$? > "$WORK/rc"
else
  KEY=\$(cat "$WORK/srv/id_ed25519.pub" 2>/dev/null || echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=)
  [ "$MODE" = wrongkey ] && KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
  ARGS=""
  [ "$MODE" = down ] || [ "$MODE" = wrongkey ] || [ "$MODE" = offline ] && ARGS="--no-server --connect 123456789 --password wrongpassword1"
  printf "[options]\ncustom-rendezvous-server = '$SRV_IP'\nkey = '%s'\n" "\$KEY" > "$WORK/home/.config/handover/Handover2.toml"
  Xvfb :88 -screen 0 1280x800x24 >/dev/null 2>&1 &
  XVFB=\$!
  sleep 2
  export DISPLAY=:88 HOME="$WORK/home" XDG_CONFIG_HOME="$WORK/home/.config" XDG_DATA_HOME="$WORK/home/.local/share" XDG_CACHE_HOME="$WORK/home/.cache" NO_AT_BRIDGE=1 GDK_BACKEND=x11
  strace -f -qq -s 300 -e trace=connect,sendto,sendmsg -o "$WORK/strace.txt" \
    timeout $DUR dbus-run-session -- "$BUNDLE" \$ARGS >"$WORK/app.log" 2>&1
  echo \$? > "$WORK/rc"
  kill \$XVFB 2>/dev/null
fi
[ \$TCPD != 0 ] && { sleep 1; kill \$TCPD 2>/dev/null; }
[ \$HBBS != 0 ] && kill \$HBBS 2>/dev/null
[ \$HBBR != 0 ] && kill \$HBBR 2>/dev/null
exit 0
INNER
chmod +x "$WORK/inner.sh"

echo "== egress check: mode=$MODE duration=${DUR}s (offline namespace, allow-list: loopback + $SRV_IP)"
unshare -rn "$WORK/inner.sh"
[ ! -e "$WORK/nouplink" ] || { echo "the fake uplink could not be created (PCAP=0 to skip the capture)" >&2; KEEP=1; trap - EXIT; exit 2; }
[ -s "$WORK/strace.txt" ] || { echo "no trace was produced (see $WORK)" >&2; KEEP=1; trap - EXIT; exit 2; }
# `timeout` exits 124 when the process was still running at the end; anything else means it died early.
if [ "$(cat "$WORK/rc" 2>/dev/null)" != 124 ]; then
  echo "the process under test ended early (exit status $(cat "$WORK/rc" 2>/dev/null || echo unknown)), so this run is inconclusive (see $WORK)" >&2
  KEEP=1; trap - EXIT; exit 2
fi
if [ "$MODE" != server ] && [ "$MODE" != selftest ] && ! grep -q 'X11-unix/X88' "$WORK/strace.txt"; then
  echo "the app never connected to the test display, so this run proves nothing (see $WORK/app.log)" >&2
  KEEP=1; trap - EXIT; exit 2
fi
set +e
python3 "$HERE/tools/egress-analyze.py" "$WORK/strace.txt" --allow "$SRV_IP"
RC=$?
if [ "$PCAP" != 0 ]; then
  # anything the kernel itself sends for an interface that came up (IPv6 neighbour/router/MLD from fe80::/::) is not the app
  tcpdump -nn -e -r "$WORK/uplink.pcap" 2>/dev/null | grep -v -E 'ICMP6, (neighbor solicitation|router solicitation|multicast listener)' > "$WORK/uplink.txt" || true
  if [ -s "$WORK/uplink.txt" ]; then
    echo "PCAP: FAIL, $(wc -l < "$WORK/uplink.txt") packet(s) reached the uplink:"; head -20 "$WORK/uplink.txt"; RC=1; KEEP=1; trap - EXIT
  else
    echo "PCAP: PASS, no packet reached the uplink"
  fi
fi
[ "${KEEP:-0}" = 1 ] && echo "logs kept in $WORK"
exit $RC
