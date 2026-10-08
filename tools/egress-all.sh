#!/bin/bash
# Run every egress scenario; exit non-zero if any fails. Run before every release (see AGENTS.md).
#   tools/egress-all.sh [seconds per scenario, default 60]
# The self-test (a deliberately leaking process) must FAIL for the checker to be trusted; the others must PASS.
# Env: SERVER_BIN, BUNDLE as for tools/egress-check.sh. Takes about (modes x seconds) plus start-up time.
HERE=$(cd "$(dirname "$0")" && pwd)
DUR=${1:-60}
rc=0
if "$HERE/egress-check.sh" selftest 4 >/dev/null 2>&1; then echo "selftest: the checker did NOT detect a deliberate leak"; rc=1; else echo "selftest: leak detected (expected)"; fi
for m in server ui down offline wrongkey; do
  if "$HERE/egress-check.sh" $m "$DUR" >/tmp/egress-all.$$.log 2>&1; then echo "$m: PASS"; else echo "$m: FAIL"; tail -15 /tmp/egress-all.$$.log; rc=1; fi
done
rm -f /tmp/egress-all.$$.log
[ $rc = 0 ] && echo "ALL EGRESS SCENARIOS PASS" || echo "EGRESS CHECK FAILED"
exit $rc
