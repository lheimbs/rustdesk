#!/bin/bash
# Install the Handover lite build (the Linux controlled side) as a system service, or remove it again.
#
#   sudo tools/install-linux.sh install <handover-linux-x64-lite.tar.gz>
#   sudo tools/install-linux.sh uninstall
#   tools/install-linux.sh status
#
# install : bundle to /usr/lib/handover (the app counts as installed only under /usr), unit
#           /etc/systemd/system/handover.service (res/handover.service), enabled and started. The root service
#           starts the --server of the active seat0 user and answers the approval checks (docs/APPROVAL_SPEC.md).
# uninstall: stops and removes the unit, the bundle, the service's own config, logs and IPC sockets (under /root and /tmp/Handover-*);
#           the per-user config folders (~/.config/handover, holding the connection log) are listed, not deleted.
# Needs  : systemd; for the tray icon libayatana-appindicator (without it the --tray process panics, measured; the
#          service and the connection still work).
# Only the lite build is accepted: the full Linux build is the controller and must not run as a service.
set -euo pipefail
cd "$(dirname "$0")/.."
DEST=/usr/lib/handover UNIT=/etc/systemd/system/handover.service
need_root() { [ "$(id -u)" = 0 ] || { echo "run as root (sudo)" >&2; exit 2; }; }

case "${1:-status}" in
  install)
    need_root
    TAR=${2:?usage: install <handover-linux-x64-lite.tar.gz>}
    case "$TAR" in *-lite.tar.gz) ;; *) echo "not a lite archive: $TAR (build with HANDOVER_LITE=1)" >&2; exit 2;; esac
    TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
    tar -xzf "$TAR" -C "$TMP"
    [ -x "$TMP/bundle/handover" ] || { echo "archive has no bundle/handover" >&2; exit 1; }
    systemctl stop handover.service 2>/dev/null || true
    rm -rf "$DEST"; mkdir -p "$DEST"
    cp -a "$TMP/bundle/." "$DEST/"
    chown -R root:root "$DEST"; chmod -R go-w "$DEST"
    install -m 644 res/handover.service "$UNIT"
    systemctl daemon-reload
    systemctl enable --now handover.service
    echo "installed: $DEST, $UNIT (enabled, started)";;
  uninstall)
    need_root
    systemctl disable --now handover.service 2>/dev/null || true
    rm -f "$UNIT"; systemctl daemon-reload
    rm -rf "$DEST" /root/.config/handover /root/.local/share/logs/Handover /tmp/Handover-service /tmp/Handover-[0-9]*
    left=$(pgrep -f "^$DEST/" || true)
    [ -z "$left" ] || { echo "still running (pids): $left" >&2; exit 1; }
    for h in /home/*; do [ -d "$h/.config/handover" ] && echo "kept user config: $h/.config/handover"; done
    echo "uninstalled";;
  status)
    systemctl is-enabled handover.service 2>/dev/null || echo "unit: not installed"
    systemctl is-active handover.service 2>/dev/null || true
    [ -d "$DEST" ] && echo "bundle: $DEST" || echo "bundle: absent"
    pgrep -a -f "^$DEST/" || echo "processes: none";;
  *) echo "usage: $0 install <tarball> | uninstall | status" >&2; exit 2;;
esac
