#!/bin/bash
# Deploy app.py and restart the controller -- but refuse while a job is running.
#
# History of this script, because it matters for trusting it:
#
#   1. I twice checked for in-flight jobs and restarted in the same command, so
#      the check printed its warning after the restart had already orphaned
#      someone's provision. Printing a warning is not a guard.
#   2. The first version of this script read /api/jobs, which returns only the
#      20 most recent jobs -- so it reported nothing running while an older job
#      still was, and it let me interrupt a stress run anyway.
#
# So it now asks /api/capacity, where jobs_running is counted from the job table
# itself rather than inferred from a truncated list. It also fails closed: if
# the number cannot be read at all, it refuses rather than assuming zero.
set -euo pipefail

HOST=root@192.168.6.58
CTL=http://sandbox.winetown.wirehavok.net
SRC="C:/Users/crimson/source/repos/SandboxMCP/sandboxctl/app.py"

running=$(curl -s -m 20 "$CTL/api/capacity" | python -c "
import sys, json
try:
    d = json.load(sys.stdin)
except Exception:
    print('unreadable'); raise SystemExit
n = d.get('jobs_running')
if n is None:
    print('unreported')            # an older controller: do not guess
else:
    print(n)
" 2>/dev/null || echo unreachable)

if [ "$running" != "0" ]; then
  if [ "$running" = "unreadable" ] || [ "$running" = "unreachable" ] || [ "$running" = "unreported" ]; then
    echo "REFUSING: could not read jobs_running ($running)." >&2
    echo "Failing closed: a restart during a provision orphans it." >&2
  else
    echo "REFUSING: $running job(s) in flight." >&2
    curl -s -m 20 "$CTL/api/jobs" | python -c "
import sys, json
for j in json.load(sys.stdin):
    if not j['done']:
        print('  %s  %s  |  %s' % (j['id'], j['title'], j['last']), file=sys.stderr)
" 2>&1 >/dev/null || true
    echo "A restart orphans them mid-provision. Wait, then run this again." >&2
  fi
  exit 1
fi

python -m py_compile "$SRC"
scp -q -o ConnectTimeout=10 -o StrictHostKeyChecking=no "$SRC" "$HOST:/opt/sandboxctl/app.py"
ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no "$HOST" \
    "systemctl restart sandboxctl; sleep 4; systemctl is-active sandboxctl"
echo "deployed"
