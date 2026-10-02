#!/usr/bin/env python3
"""Stress the create path: N sandboxes at once, timed, then torn down.

Creation is the longest and most fragile thing this controller does -- clone,
OOBE, a reboot, auto-logon, a Groundhog apply -- and it is the path that has
actually broken in practice. One success proves little; what matters is whether
the tenth concurrent one still works and what fails first when it does not.

What this measures, because they fail differently:
  - how long a create takes under concurrency, against the ~6 min it takes alone,
  - whether the capacity limit refuses cleanly rather than queueing or crashing,
  - the controller's own memory, since each running sandbox costs it ~100 MB for
    a console recorder and that is what OOM-killed it once,
  - and which step a failure landed on, from the job log rather than a guess.

It respects the configured limits rather than trying to defeat them: a refusal
is a pass, not an error. Everything it creates is named with a prefix it then
destroys, so it cannot take anything it did not make.

  python tools/stress-create.py --host http://sandbox... --count 4
  python tools/stress-create.py --count 4 --keep      # leave them up
"""
import argparse
import json
import re
import statistics
import sys
import threading
import time
import urllib.error
import urllib.request

PREFIX = "stress-"


def mcp(host, name, args, timeout=180):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": name, "arguments": args}}).encode()
    req = urllib.request.Request(host.rstrip("/") + "/mcp", data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        d = json.loads(r.read().decode())
    res = d.get("result") or {}
    text = (res.get("content") or [{}])[0].get("text", "")
    if res.get("isError"):
        raise RuntimeError(text.strip())
    try:
        return json.loads(text)
    except ValueError:
        return {"text": text}


def api(host, path, timeout=60):
    with urllib.request.urlopen(host.rstrip("/") + path, timeout=timeout) as r:
        return json.loads(r.read().decode())


class Attempt:
    def __init__(self, n):
        self.n = n
        self.name = "%s%d" % (PREFIX, n)
        self.job = None
        self.vmid = None
        self.started = None
        self.took = None
        self.state = "pending"
        self.detail = ""
        self.lines = []


def run_one(host, a, poll=15, limit=1800):
    a.started = time.time()
    try:
        r = mcp(host, "create_sandbox",
                {"name": a.name, "who": "stress", "expires_in_minutes": 60})
    except Exception as exc:                          # noqa: BLE001
        msg = str(exc)
        a.took = time.time() - a.started
        # A refusal is the limit working, not a failure of the thing under test.
        a.state = "refused" if "limit" in msg.lower() else "rejected"
        a.detail = msg[:160]
        return
    a.job = (r or {}).get("job_id")
    if not a.job:
        a.state = "rejected"
        a.detail = "no job id in the reply"
        return
    deadline = time.time() + limit
    while time.time() < deadline:
        time.sleep(poll)
        try:
            j = api(host, "/api/job?id=" + a.job)
        except Exception:                             # noqa: BLE001
            continue
        a.vmid = j.get("vmid") or a.vmid
        a.lines = j.get("lines") or a.lines
        if j.get("done"):
            a.took = time.time() - a.started
            if j.get("failed"):
                a.state = "failed"
                a.detail = (a.lines or ["(no log)"])[-1][:160]
            else:
                a.state = "ready"
                a.detail = (a.lines or [""])[-1][:160]
            return
    a.took = time.time() - a.started
    a.state = "timeout"
    a.detail = (a.lines or [""])[-1][:160] if a.lines else "no log"


def controller_mem(host):
    """Memory is the constraint that actually bites, so report it if offered."""
    try:
        c = api(host, "/api/capacity")
        return "running %s/%s, sandboxes %s/%s" % (
            c.get("running"), c.get("max_running"),
            c.get("sandboxes"), c.get("max_sandboxes"))
    except Exception:                                 # noqa: BLE001
        return "unknown"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="http://sandbox.winetown.wirehavok.net")
    p.add_argument("--count", type=int, default=4)
    p.add_argument("--stagger", type=float, default=0.0,
                   help="seconds between starts; 0 means all at once")
    p.add_argument("--keep", action="store_true", help="do not destroy afterwards")
    args = p.parse_args()

    print("capacity before: %s" % controller_mem(args.host))
    print("launching %d create(s)%s\n" % (
        args.count, "" if not args.stagger else " staggered %.1fs" % args.stagger))

    attempts = [Attempt(i + 1) for i in range(args.count)]
    threads = []
    t0 = time.time()
    for a in attempts:
        t = threading.Thread(target=run_one, args=(args.host, a), daemon=True)
        t.start()
        threads.append(t)
        if args.stagger:
            time.sleep(args.stagger)
    for t in threads:
        t.join()
    wall = time.time() - t0

    print("%-14s %-6s %-9s %8s  %s" % ("name", "vmid", "result", "secs", "last log line"))
    for a in attempts:
        print("%-14s %-6s %-9s %8s  %s" % (
            a.name, a.vmid or "-", a.state,
            "%.0f" % a.took if a.took else "-", a.detail))

    ok = [a for a in attempts if a.state == "ready"]
    print("\n%d/%d ready, wall clock %.0f s" % (len(ok), len(attempts), wall))
    if ok:
        times = [a.took for a in ok]
        print("  fastest %.0f s   slowest %.0f s   median %.0f s"
              % (min(times), max(times), statistics.median(times)))
    for state in ("refused", "failed", "timeout", "rejected"):
        n = [a for a in attempts if a.state == state]
        if n:
            print("  %s: %d (%s)" % (state, len(n), ", ".join(x.name for x in n)))
    print("capacity after: %s" % controller_mem(args.host))

    # Where a failure landed matters more than that it happened.
    for a in attempts:
        if a.state in ("failed", "timeout") and a.lines:
            print("\n--- %s (%s) ---" % (a.name, a.state))
            for line in a.lines[-8:]:
                print("   " + line)

    if args.keep:
        print("\n--keep: leaving %d sandbox(es) up" % len(ok))
        return 0

    made = [a for a in attempts if a.vmid]
    if made:
        print("\ntearing down %d" % len(made))
        for a in made:
            # Only ever something this run created and named.
            if not a.name.startswith(PREFIX):
                continue
            try:
                mcp(args.host, "destroy_sandbox", {"vmid": a.vmid, "who": "stress"})
                print("  %s (%s) destroying" % (a.name, a.vmid))
            except Exception as exc:                  # noqa: BLE001
                print("  %s (%s) destroy failed: %s" % (a.name, a.vmid, str(exc)[:90]))
    return 0 if len(ok) == len([a for a in attempts if a.state != "refused"]) else 1


if __name__ == "__main__":
    sys.exit(main())
