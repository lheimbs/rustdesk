#!/bin/bash
# Render the hardened systemd units from the templates in server/systemd using the settings in .env
# (HANDOVER_RELAY_HOST, HANDOVER_ALLOWED_NETS, HANDOVER_CONTROLLER_CA; see .env.example).
#
# usage: server/render-units.sh [output dir]      default: server/build/systemd
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ENV_FILE=${ENV_FILE:-$HERE/../.env}
OUT=${1:-$HERE/build/systemd}

get() {
  local v=${!1:-}
  if [ -z "$v" ] && [ -f "$ENV_FILE" ]; then
    v=$(sed -n "s/^$1=//p" "$ENV_FILE" | head -n1 | sed -e 's/^["'\'']//' -e 's/["'\'']$//')
  fi
  printf '%s' "$v"
}
RELAY_HOST=$(get HANDOVER_RELAY_HOST)
ALLOWED_NETS=$(get HANDOVER_ALLOWED_NETS)
CA_PUB=$(get HANDOVER_CONTROLLER_CA)
[ -n "$RELAY_HOST" ] || { echo "HANDOVER_RELAY_HOST is not set (environment or .env)" >&2; exit 1; }
[ -n "$CA_PUB" ] || { echo "HANDOVER_CONTROLLER_CA (public key printed by handover-ca init) is not set (environment or .env)" >&2; exit 1; }
[ -n "$ALLOWED_NETS" ] || { echo "HANDOVER_ALLOWED_NETS is not set (environment or .env)" >&2; exit 1; }
case "$RELAY_HOST" in *:*) ;; *) RELAY_HOST="$RELAY_HOST:21117" ;; esac

mkdir -p "$OUT"
for t in "$HERE"/systemd/*.service; do
  sed -e "s|@RELAY_HOST@|$RELAY_HOST|g" -e "s|@ALLOWED_NETS@|$ALLOWED_NETS|g" -e "s|@CA_PUB@|$CA_PUB|g" "$t" > "$OUT/$(basename "$t")"
done
echo "rendered to $OUT (not committed; contains your addresses)"
