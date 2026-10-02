#!/usr/bin/env python3
"""
Sandbox controller: a small web UI that creates and destroys disposable Windows
sandboxes on Proxmox, and installs Deskhand into each one.

Design notes worth knowing before changing anything:

* The Windows template deliberately contains NO Deskhand and no baked config.
  Deskhand moves fast; baking it in meant a ~15 minute template rebuild per
  release. Instead this service hosts the build and installs it per sandbox, so
  a new Deskhand version is a file drop here, not a template rebuild.

* Config (TLS / shell / port / token) is therefore a CREATION-TIME choice, not
  an image property. Each sandbox gets its own generated token.

* Sandboxes live on an isolated SDN network and are firewalled away from the
  LAN. The single exception is this host on one port, which is how they fetch
  the payload. Nothing here should widen that.

* Proxmox credentials are a scoped token (sandboxctl@pve!ui): it may create
  VMs, clone the template, and fully manage members of the 'sandboxes' pool --
  and nothing else. It is not a cluster admin and must not become one.

Stdlib only, on purpose: no pip, nothing to keep patched.
"""
import base64
import gzip
import concurrent.futures
import hashlib
import html
import json
import os
import queue
import re
import secrets
import ssl
import string
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import live
import recorder

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG = json.load(open(os.path.join(HERE, "config.json")))

NODE = CONFIG["node"]
HOST = CONFIG["pve_host"]
TOKENID = CONFIG["token_id"]
SECRET = CONFIG["token_secret"]
TEMPLATE = int(CONFIG["template"])
POOL = CONFIG.get("pool", "sandboxes")
BRIDGE = CONFIG.get("bridge", "sbx0")
ID_LO, ID_HI = CONFIG.get("id_range", [900, 949])
# Default to the whole range, so these are inert until deliberately set.
MAX_SANDBOXES = int(CONFIG.get("max_sandboxes") or (ID_HI - ID_LO + 1))
MAX_RUNNING = int(CONFIG.get("max_running") or (ID_HI - ID_LO + 1))
LISTEN = CONFIG.get("listen", ["0.0.0.0", 8080])
# The payload is served on its OWN port, and that is the only port the
# sandbox firewall rule allows. Sandboxes are the untrusted thing here; if
# they could reach the control port they could enumerate every sandbox,
# read its Deskhand token, and create or destroy VMs. Separating the ports
# means a compromised sandbox can fetch a zip and nothing else.
PAYLOAD_LISTEN = CONFIG.get("payload_listen", ["0.0.0.0", 8081])
SELF_URL = CONFIG["self_url"]                 # what the guest fetches from
WIN_USER = CONFIG.get("windows_user", "sandbox")
WIN_PASS = CONFIG["windows_password"]
# Optional. What to seed an in-sandbox agent with: provider keys, a model per
# agent, and any extra MCP servers. Absent or empty just means the agent is
# installed unconfigured.
AGENTS_CFG = CONFIG.get("agents") or {}
# Matches the default agent-side MCP cap, so Deskhand spills to its OutputStore
# at the same point the client would otherwise start discarding.
DESKHAND_TOOL_CHARS = int(CONFIG.get("deskhand_max_tool_chars") or 150000)

# Console recording. Off unless a directory is configured, because it needs
# somewhere with room -- a chunk is tens of MB and they accumulate per sandbox.
REC_DIR = CONFIG.get("recordings_dir") or ""
REC_RETENTION_DAYS = int(CONFIG.get("recordings_retention_days") or 14)

_SSL = ssl.create_default_context()
_SSL.check_hostname = False
_SSL.verify_mode = ssl.CERT_NONE


# --------------------------------------------------------------------------
# Proxmox API
# --------------------------------------------------------------------------
def api(path, method="GET", data=None, timeout=60):
    body = urllib.parse.urlencode(data, doseq=True).encode() if data else None
    req = urllib.request.Request(
        f"https://{HOST}:8006/api2/json{path}", data=body, method=method,
        headers={"Authorization": f"PVEAPIToken={TOKENID}={SECRET}",
                 "Accept-Encoding": "identity"})
    with urllib.request.urlopen(req, timeout=timeout, context=_SSL) as r:
        return json.load(r).get("data")


def vm(path, method="GET", data=None, vmid=None, timeout=60):
    return api(f"/nodes/{NODE}/qemu/{vmid}{path}", method, data, timeout)


# --------------------------------------------------------------------------
# Guest agent helpers
# --------------------------------------------------------------------------
def agent_ping(vmid):
    try:
        vm("/agent/ping", "POST", vmid=vmid, timeout=20)
        return True
    except Exception:
        return False


def agent_run_ps(vmid, script, wait=True, timeout=180):
    """Run PowerShell in the guest via -EncodedCommand.

    Encoded rather than inline because the scripts carry tokens and passwords;
    base64 removes every quoting question between here and PowerShell at once.
    """
    enc = base64.b64encode(script.encode("utf-16-le")).decode()
    # The agent vanishes across the reboots Windows setup performs, so failing
    # to even start the command is a "not yet", not an error. Callers treat None
    # as "retry" rather than aborting a five-minute build over one lost poll.
    try:
        res = vm("/agent/exec", "POST", vmid=vmid, data=[
            ("command", "powershell.exe"), ("command", "-NoProfile"),
            ("command", "-EncodedCommand"), ("command", enc)])
    except Exception:
        return None
    if not res or "pid" not in res:
        return None
    pid = res["pid"]
    if not wait:
        return None
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(3)
        try:
            st = vm(f"/agent/exec-status?pid={pid}", vmid=vmid, timeout=30)
        except Exception:
            continue
        if st and st.get("exited"):
            return (st.get("out-data") or "") + (st.get("err-data") or "")
    return None


def guest_ip(vmid):
    try:
        res = vm("/agent/network-get-interfaces", vmid=vmid, timeout=30)
        for iface in res["result"]:
            for a in iface.get("ip-addresses", []):
                ip = a.get("ip-address", "")
                if a.get("ip-address-type") == "ipv4" and not ip.startswith(("127.", "169.254.")):
                    return ip
    except Exception:
        pass
    return None


# --------------------------------------------------------------------------
# Jobs
# --------------------------------------------------------------------------
# Creating a sandbox takes minutes (OOBE, a reboot for auto-logon, the install),
# so the HTTP request returns immediately and the browser polls this instead.
JOBS = {}
JOBS_LOCK = threading.Lock()


class Job:
    def __init__(self, title):
        self.id = secrets.token_hex(6)
        self.title = title
        self.lines = []
        self.done = False
        self.failed = False
        self.result = {}
        self.started = time.time()
        self.vmid = None            # set once a create knows which VM it took

    def log(self, msg):
        self.lines.append(f"{time.strftime('%H:%M:%S')}  {msg}")
        _jobs_save()

    def as_dict(self):
        return {"id": self.id, "title": self.title, "lines": self.lines,
                "done": self.done, "failed": self.failed, "result": self.result,
                "vmid": self.vmid,
                "elapsed": int(time.time() - self.started)}

    @classmethod
    def from_dict(cls, d):
        job = cls.__new__(cls)
        job.id = d.get("id") or secrets.token_hex(6)
        job.title = d.get("title") or ""
        job.lines = list(d.get("lines") or [])
        job.done = bool(d.get("done"))
        job.failed = bool(d.get("failed"))
        job.result = d.get("result") or {}
        job.vmid = d.get("vmid")
        job.started = time.time() - int(d.get("elapsed") or 0)
        return job


JOBS_PATH = os.path.join(HERE, "jobs.json")


def _jobs_save():
    """Called on every log line. Jobs are low-volume -- a create writes about
    eight lines in six minutes -- so this costs nothing and means the record
    survives whatever happens to the process."""
    try:
        with JOBS_LOCK:
            snapshot = [j.as_dict() for j in JOBS.values()]
        tmp = JOBS_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(snapshot, fh, indent=2, default=str)
        os.replace(tmp, JOBS_PATH)
    except Exception:                                 # noqa: BLE001
        pass                                          # never fail work over bookkeeping


def _jobs_load():
    """Restore the record at startup and close out anything left mid-flight.

    A job that was not done when we stopped has no thread any more, so it can
    never finish. Saying so -- and naming repair_sandbox -- turns a silently
    half-built VM into a one-line explanation.
    """
    try:
        with open(JOBS_PATH, encoding="utf-8") as fh:
            saved = json.load(fh)
    except Exception:                                 # noqa: BLE001
        return
    for d in saved:
        job = Job.from_dict(d)
        if not job.done:
            job.done = True
            job.failed = True
            job.log("INTERRUPTED: the controller restarted while this job was "
                    "running, so its worker is gone.")
            if job.vmid:
                job.log(f"  VM {job.vmid} may be half-provisioned -- "
                        f"repair_sandbox({job.vmid}) finishes it.")
        JOBS[job.id] = job


MAX_JOBS = 50

# --------------------------------------------------------------------------
# Template building
# --------------------------------------------------------------------------
SYSPREP_EXE = r"C:\Windows\System32\Sysprep\sysprep.exe"
SYSPREP_ANSWER = r"C:\Windows\System32\Sysprep\unattend.xml"


def wait_oobe_settled(job, vmid, timeout=1200):
    """Block until Windows setup is finished in every sense that matters.

    SystemSetupInProgress dropping to 0 is not enough on its own: OOBE may still
    have a process running, or owe itself a reboot from a zero-day patch. A
    machine inspected before all three are clear looks finished and is not.
    """
    deadline = time.time() + timeout
    soft_deadline = time.time() + 240   # how long to insist on a quiet OOBE
    last = ""
    while time.time() < deadline:
        out = agent_run_ps(vmid,
                           "$ProgressPreference='SilentlyContinue'\n"
                           "$sip = (Get-ItemProperty 'HKLM:\\SYSTEM\\Setup').SystemSetupInProgress\n"
                           "$p = @(Get-Process msoobe,CloudExperienceHostBroker "
                           "-ErrorAction SilentlyContinue).Count\n"
                           "$rb = Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
                           "Component Based Servicing\\RebootPending'\n"
                           "Write-Output ('OOBE|' + $sip + '|' + $p + '|' + $rb)", timeout=90)
        for line in (out or "").splitlines():
            if line.strip().startswith("OOBE|"):
                _, sip, procs, reboot = line.strip().split("|", 3)
                state = f"setup={sip} oobeProcs={procs} rebootPending={reboot}"
                if state != last:
                    job.log("  " + state)
                    last = state
                ready = sip.strip() in ("0", "") and reboot.strip().lower() == "false"
                if ready and procs.strip() == "0":
                    time.sleep(45)          # account cleanup lands just after
                    return
                if ready and time.time() > soft_deadline:
                    # A build VM has nobody to log on, so an OOBE process can sit
                    # at a screen indefinitely. Setup itself is finished and
                    # nothing is pending, which is what matters before sealing.
                    job.log(f"  proceeding with {procs.strip()} OOBE process(es) still up; "
                            "setup is complete and no reboot is pending")
                    time.sleep(30)
                    return
        time.sleep(15)
    raise RuntimeError("OOBE did not settle in time")


def do_make_template(job, opts):
    global TEMPLATE
    base = int(opts.get("base") or TEMPLATE)
    name = re.sub(r"[^A-Za-z0-9-]", "-", (opts.get("name") or f"tmpl-{int(time.time()) % 100000}"))[:15]
    vmid = free_vmid()
    job.vmid = vmid
    job.log(f"building template {name} as VMID {vmid}, from {base}")

    # Full clone: a template that depends on the one it came from cannot outlive
    # it, and the whole point of a new template is to retire the old one.
    try:
        api(f"/nodes/{NODE}/qemu/{base}/clone", "POST",
            {"newid": vmid, "name": name, "full": 1, "pool": POOL,
             "storage": opts.get("storage") or "local-lvm"}, timeout=120)
        wait_unlocked(vmid, timeout=1800)
    finally:
        release_vmid(vmid)
    job.log("cloned")

    vm("/status/start", "POST", vmid=vmid)
    job.log("started; waiting for the guest agent")
    wait_agent(vmid)
    wait_oobe_settled(job, vmid)
    job.log("OOBE settled")

    if opts.get("groundhog"):
        # Written the same way, but run directly rather than through the logon
        # task. A template build has nobody logged on and that task is
        # ONLOGON /IT, so it reports 267011 and never fires. Running as SYSTEM
        # is also the right scope here: per-user state in an image that is about
        # to be generalized belongs in the default profile, not in whoever
        # happened to build it.
        apply_groundhog(vmid, opts["groundhog"], opts.get("groundhog_sha256"),
                        None, True, job, trigger=False)
        job.log("groundhog: applying directly (a template build has no session)")
        out = agent_run_ps(vmid,
                           "$ProgressPreference='SilentlyContinue'\n"
                           "& (Join-Path $env:ProgramData 'groundhog\\bin\\groundhog-agent.exe') "
                           "run-pending 2>&1 | Out-String",
                           timeout=int(opts.get("groundhog_timeout") or 7200))
        for line in (out or "").splitlines():
            if line.strip():
                job.log("  " + line.strip()[:140])
        st = groundhog_status(vmid)
        job.log(f"  groundhog: {st['outcome']} -- {st['status'][:140]}")
        # Anything but an explicit success is a refusal to seal. "none" means it
        # never ran at all, which is how an unconfigured image got sealed once
        # already, and is just as disqualifying as a failure.
        if st["outcome"] != "succeeded":
            raise RuntimeError("groundhog did not succeed (%s: %s); not sealing a broken image"
                               % (st["outcome"], st["status"][:120]))

    for i, step in enumerate(opts.get("steps") or [], 1):
        job.log(f"step {i}/{len(opts['steps'])}")
        out = agent_run_ps(vmid, "$ProgressPreference='SilentlyContinue'\n" + step, timeout=900)
        for line in (out or "").splitlines()[:6]:
            if line.strip():
                job.log("  " + line.strip()[:120])

    checks = agent_run_ps(vmid,
                          "$ProgressPreference='SilentlyContinue'\n"
                          "$u = (Get-LocalUser | Where-Object Enabled | "
                          "Select-Object -ExpandProperty Name) -join ','\n"
                          "$rb = Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
                          "Component Based Servicing\\RebootPending'\n"
                          f"$ans = Test-Path '{SYSPREP_ANSWER}'\n"
                          "Write-Output ('CHK|' + $u + '|' + $rb + '|' + $ans)", timeout=120)
    for line in (checks or "").splitlines():
        if line.strip().startswith("CHK|"):
            _, users, reboot, answer = line.strip().split("|", 3)
            job.log(f"  accounts: {users}")
            job.log(f"  rebootPending={reboot} answerFile={answer}")
            if reboot.strip().lower() == "true":
                raise RuntimeError("a reboot is pending; sealing now would bake it into "
                                   "every clone")

    # Forget this build's Groundhog state before sealing. Without it every clone
    # inherits pending.done.json (so groundhog_status reports a success nothing
    # asked for), the download cache, and -- worse -- one shared per-machine
    # secret salt. Unconditional: the state may have come from an earlier
    # template in the chain rather than from this build.
    gh_clean = agent_run_ps(vmid,
                            "$ProgressPreference='SilentlyContinue'\n"
                            "$exe = Join-Path $env:ProgramData "
                            "'groundhog\\bin\\groundhog-agent.exe'\n"
                            "if (-not (Test-Path $exe)) { Write-Output 'CLEAN|absent'; exit }\n"
                            "& $exe update 2>&1 | Out-String | Out-Null\n"
                            "$o = (& $exe clean 2>&1 | Out-String).Trim()\n"
                            "Write-Output ('CLEAN|' + $LASTEXITCODE + '|' + "
                            "($o -replace '\r?\n', ' ~ '))", timeout=600)
    line = ""
    for l in (gh_clean or "").splitlines():
        if l.strip().startswith("CLEAN|"):
            line = l.strip()
    if line.startswith("CLEAN|absent"):
        job.log("groundhog: agent not in this image, nothing to clean")
    elif line.startswith("CLEAN|0"):
        job.log("groundhog: state cleaned (needs agent >=0.13.0); clones start fresh")
    else:
        # Not fatal: a sealed template with leftover state is wrong but usable,
        # and failing the whole build over it would be worse.
        job.log(f"WARNING: groundhog clean did not report success: {line[:160]}")
        job.log("  clones will inherit this build's groundhog state and secret salt")

    job.log("sysprep /generalize /oobe /shutdown")
    agent_run_ps(vmid,
                 "$ProgressPreference='SilentlyContinue'\n"
                 f"Start-Process -FilePath '{SYSPREP_EXE}' -ArgumentList "
                 f"'/generalize','/oobe','/shutdown','/quiet','/unattend:{SYSPREP_ANSWER}'",
                 wait=False, timeout=60)
    deadline = time.time() + 1800
    while time.time() < deadline:
        time.sleep(20)
        if (vm("/status/current", vmid=vmid) or {}).get("status") == "stopped":
            break
    else:
        raise RuntimeError("the guest did not shut down after sysprep")
    job.log("sysprep finished; guest is down")

    vm("/template", "POST", vmid=vmid, timeout=180)
    job.log(f"converted {vmid} to a template")

    result = {"vmid": vmid, "name": name, "base": base, "active": False}
    if opts.get("activate"):
        # Written straight to the config file: this is the one setting that
        # decides what every future sandbox is cloned from.
        cfg_path = os.path.join(HERE, "config.json")
        with open(cfg_path, encoding="utf-8") as fh:
            cfg = json.load(fh)
        cfg["template"] = vmid
        tmp = cfg_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, indent=2)
        os.replace(tmp, cfg_path)
        TEMPLATE = vmid
        result["active"] = True
        job.log(f"activated: new sandboxes now clone from {vmid} "
                "(restart the service to persist across a reload)")
    else:
        job.log(f"not activated; set template={vmid} in config.json when you are ready")

    job.result = result
    return result


# --------------------------------------------------------------------------
# Groundhog
# --------------------------------------------------------------------------
GROUNDHOG_HOME = r"C:\ProgramData\groundhog"
GROUNDHOG_TASK = r"Groundhog\RunPending"
# Written by the agent's own built-in reporter on every run, so there is nothing
# to configure and it is there for applies this controller did not start.
# vmid -> the last outcome we saw, for the fleet list's badge. A hint, not a
# record: the panel reads the guest. Not persisted on purpose -- a stale badge
# that survived a restart would be worse than no badge.
# The dashboard's favicon, base64 of a small SVG. Defined once and used both
# by the page tag and the /favicon.svg route.
FAVICON_B64 = "PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAzMiAzMiI+PHJlY3Qgd2lkdGg9IjMyIiBoZWlnaHQ9IjMyIiByeD0iNyIgZmlsbD0iIzE1MTkyMiIvPjxyZWN0IHg9IjUiIHk9IjgiIHdpZHRoPSIyMiIgaGVpZ2h0PSIxNSIgcng9IjIuNSIgZmlsbD0iIzRhOWVmZiIvPjxyZWN0IHg9IjkiIHk9IjI1IiB3aWR0aD0iMTQiIGhlaWdodD0iMi41IiByeD0iMS4yNSIgZmlsbD0iIzJhMzI0MiIvPjxjaXJjbGUgY3g9IjIyLjUiIGN5PSIxMi41IiByPSIyLjYiIGZpbGw9IiMzZmI5NTAiLz48L3N2Zz4="
GH_LAST = {}
GROUNDHOG_LAST_RUN = GROUNDHOG_HOME + r"\last-run"


def _payload_sha256(url):
    """The hash of a payload file we serve ourselves, or None if it is not ours."""
    try:
        name = os.path.basename(urllib.parse.urlparse(url).path)
        full = os.path.join(HERE, "payload", name)
        if not name or not os.path.isfile(full):
            return None
        h = hashlib.sha256()
        with open(full, "rb") as fh:
            for block in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(block)
        return h.hexdigest()
    except Exception:                                 # noqa: BLE001
        return None


def _header_rules(headers):
    """Accept Groundhog's own --header spelling as well as objects.

    The documented form is "host=Name: value", which is what someone reading
    Groundhog's docs will reach for; the wire format is {host, name, value}.
    Taking both costs a few lines and saves a caller translating by hand.
    """
    out = []
    for h in headers or []:
        if isinstance(h, dict):
            if not all(k in h for k in ("host", "name", "value")):
                raise ValueError("a header object needs host, name and value")
            out.append({"host": str(h["host"]), "name": str(h["name"]),
                        "value": str(h["value"])})
            continue
        text = str(h)
        left, sep, value = text.partition(":")
        if not sep:
            raise ValueError(f"header {text!r} must look like 'host=Name: value'")
        host, eq, name = left.partition("=")
        if not eq:
            raise ValueError(f"header {text!r} needs 'host=' so the agent knows "
                             "which host to send it to")
        out.append({"host": host.strip(), "name": name.strip(), "value": value.strip()})
    return out


def apply_groundhog(vmid, source, sha256=None, allow_http=None, allow_reboot=False,
                    job=None, trigger=True, secrets=None, headers=None):
    """Point a sandbox at a Groundhogfile and start the apply.

    Returns once the task has been kicked; the agent keeps going on its own.
    Poll groundhog_status for the outcome.
    """
    source = (source or "").strip()
    if not source:
        raise ValueError("source is required: a path, URL or zip the agent can fetch")
    if allow_http is None:
        # The payload port is plain HTTP and is the only controller port a
        # sandbox may reach, so http sources are normal here rather than a
        # mistake to be defended against.
        allow_http = source.lower().startswith("http://")

    pending = {"source": source, "allowReboot": bool(allow_reboot),
               "allowHttp": bool(allow_http),
               }
    if not sha256 and source.lower().startswith("http://"):
        # allow_http applies to every download in the run, not only this source,
        # so pin what we can. Ours is on local disk; hashing it costs nothing and
        # the caller does not have to care.
        sha256 = _payload_sha256(source)
        if sha256 and job:
            job.log("groundhog: pinned the Groundhogfile to sha256 "
                    f"{sha256[:12]}...")
    if sha256:
        pending["sha256"] = sha256
    if secrets:
        # Values for ${secret:NAME} references. The agent strips them from this
        # file as soon as it reads it, and never logs them. Deliberately not
        # logged here either -- not the names, which are harmless, and certainly
        # not the values.
        pending["secrets"] = {str(k): str(v) for k, v in dict(secrets).items()}
    if headers:
        pending["headers"] = _header_rules(headers)

    # Clear what the last run left, which in a fresh sandbox is the TEMPLATE's:
    # generate_template applies a Groundhogfile before sealing, so every clone
    # inherits a pending.done.json and a last-run folder, and would otherwise
    # report that build's success -- and its steps -- as its own. last-run goes
    # too, or a status check taken before the agent's first write describes the
    # previous run as though it were this one.
    _guest_ps(vmid,
              "$ErrorActionPreference='SilentlyContinue'\n"
              f"$h = '{GROUNDHOG_HOME}'\n"
              "Remove-Item -LiteralPath ($h + '\\pending.done.json'), "
              "($h + '\\pending.failed.json') -Force -ErrorAction SilentlyContinue\n"
              "Remove-Item -LiteralPath ($h + '\\last-run') -Recurse -Force "
              "-ErrorAction SilentlyContinue\n"
              "Write-Output 'OK'", timeout=90)

    # Written as bytes: a BOM makes the agent fail with "expected value at
    # line 1 column 1", which reads like a corrupt file rather than an encoding.
    guest_write(vmid, GROUNDHOG_HOME + r"\pending.json",
                content_base64=base64.b64encode(
                    json.dumps(pending, indent=2).encode("utf-8")).decode())
    if job:
        job.log(f"groundhog: pending.json written ({source})")

    if not trigger:
        record_event(vmid, "groundhog pending", source[:80])
        return {"vmid": int(vmid), "source": source, "started": False,
                "note": "pending.json written; the caller runs the agent itself"}

    out = _guest_ps(vmid,
                    "$ErrorActionPreference='SilentlyContinue'\n"
                    f"schtasks.exe /Run /TN '{GROUNDHOG_TASK}' 2>&1 | Out-String\n"
                    "Write-Output 'OK|started'", timeout=120)
    if "OK|started" not in (out or ""):
        raise RuntimeError("could not start " + GROUNDHOG_TASK + ": " + (out or "")[:160])
    GH_LAST[int(vmid)] = "running"
    record_event(vmid, "groundhog apply", source[:80])
    if job:
        job.log("groundhog: apply started; it continues in the guest")
    return {"vmid": int(vmid), "source": source, "started": True,
            "note": "the agent runs in the sandbox user's session; poll groundhog_status"}


def _plan_clean(text):
    """Keep the agent's own words; drop PowerShell's error furniture.

    A native program's stderr comes back wrapped in the command echoed again, a
    squiggle underline, CategoryInfo and FullyQualifiedErrorId. None of that
    says anything about the file somebody is trying to write.
    """
    out = []
    for line in (text or "").splitlines():
        s = line.strip()
        if not s:
            if out and out[-1] != "":
                out.append("")           # keep paragraph breaks, drop runs
            continue
        if s.startswith(("At line:", "+ ", "+~", "~")) or s.startswith("+"):
            continue
        if s.startswith(("CategoryInfo", "FullyQualifiedErrorId")):
            continue
        if set(s) <= {"~", "+", " "}:
            continue
        # "groundhog-agent.exe : error: ..." -> "error: ..."
        if ".exe : " in s:
            s = s.split(".exe : ", 1)[1]
        out.append(s)
    return "\n".join(out).strip()


# Short descriptions for the editor. Keyed by the file's stem; anything in the
# directory without an entry still shows up, just without the blurb.
GH_LIBRARY_NOTES = {
    "heisenberg": "Heisenberg debugging MCP server, plus the toolchain it drives "
                  "(Sysinternals, WinDbg, TTD, symbols). Slow: Windows features "
                  "come from Windows Update.",
    "opencode": "opencode from its own release zip, on the machine PATH.",
    "hermes": "Hermes via the vendor installer. ~2 GB; brings its own git, "
              "python and node.",
    "debug-kit": "Heisenberg and opencode together: drive native debugging from "
                 "an agent.",
    "everything": "Every agent and tool here in one apply. Bake this into a "
                  "template rather than waiting on it per sandbox.",
}


def groundhog_library():
    """The profiles shipped alongside this service, newest content each time.

    Read from disk rather than cached: these are small, and editing one and
    reloading the page is how you iterate on them.
    """
    d = os.path.join(HERE, "groundhog")
    out = []
    for name in sorted(os.listdir(d)) if os.path.isdir(d) else []:
        if not name.endswith(".groundhog.yaml"):
            continue
        stem = name[: -len(".groundhog.yaml")]
        try:
            with open(os.path.join(d, name), encoding="utf-8") as fh:
                body = fh.read()
        except OSError:
            continue
        out.append({"name": stem,
                    "note": GH_LIBRARY_NOTES.get(stem, ""),
                    "url": f"{SELF_URL}/payload/lib-{name}",
                    "content": body.replace("@@SELF@@", SELF_URL.split("//", 1)[-1])})
    return out


def publish_groundhog_library():
    """Copy the library into the payload directory, where a guest can fetch it.

    Done at startup so an edited profile is picked up by a restart, and because
    the combinations reference each other by URL -- they have to be fetchable,
    not just readable here.
    """
    pdir = os.path.join(HERE, "payload")
    try:
        os.makedirs(pdir, exist_ok=True)
        for item in groundhog_library():
            dest = os.path.join(pdir, "lib-" + item["name"] + ".groundhog.yaml")
            tmp = dest + ".tmp"
            with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(item["content"])
            os.replace(tmp, dest)
        return len(groundhog_library())
    except Exception as exc:                          # noqa: BLE001
        print(f"groundhog library: not published ({exc})", flush=True)
        return 0


def groundhog_plan(vmid, source):
    """Run `groundhog-agent plan` in the guest. Loads everything, changes nothing.

    Groundhog's own answer to "is this file valid", which beats anything this
    controller could reimplement: it resolves extends, fetches what it must to
    know what "latest" is, and prints the steps it would take.
    """
    # Only for http, so an https source keeps the protection. Our own payload
    # port is plain http and is the only port a sandbox may reach, so a file
    # served from here cannot be validated without this.
    flag = " --allow-http" if source.lower().startswith("http://") else ""
    out = _guest_ps(vmid,
                    # Continue, not SilentlyContinue: a native program's stderr
                    # arrives as error records, and silencing those throws away
                    # the one line that says what is wrong with the file.
                    "$ErrorActionPreference='Continue'\n"
                    f"$exe = '{GROUNDHOG_HOME}' + '\\bin\\groundhog-agent.exe'\n"
                    "if (-not (Test-Path $exe)) { Write-Output 'ERR|agent not installed'; exit }\n"
                    f"$o = (& $exe plan {_ps_literal(source)}{flag} 2>&1 | Out-String).Trim()\n"
                    # No delimiter: base64 cannot collide with the output the way
                    # a '~~' sentinel collided with PowerShell's own squiggle
                    # underline, which decoded back into a page of blank lines.
                    "$b = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($o))\n"
                    "Write-Output ('OK|' + $LASTEXITCODE + '|' + $b)",
                    timeout=300)
    line = _marked_line(out)
    if line.startswith("ERR|"):
        raise RuntimeError(line.split("|", 1)[1])
    _, code, blob = line.split("|", 2)
    text = base64.b64decode(blob.strip(), validate=True).decode("utf-8", "replace")
    return {"vmid": int(vmid), "ok": code.strip() in ("0", ""),
            "output": _plan_clean(text)}


def groundhog_write_adhoc(vmid, content):
    """Stage a typed Groundhogfile where the guest can fetch it.

    The payload port is the only one a sandbox may reach, so this is the same
    route the Deskhand install uses. The file names its secrets rather than
    carrying them, so serving it is not a disclosure.
    """
    if not (content or "").strip():
        raise ValueError("nothing to apply: the Groundhogfile is empty")
    name = f"adhoc-{int(vmid)}.groundhog.yaml"
    pdir = os.path.join(HERE, "payload")
    os.makedirs(pdir, exist_ok=True)
    tmp = os.path.join(pdir, name + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)
    os.replace(tmp, os.path.join(pdir, name))
    return f"{SELF_URL}/payload/{name}"


def groundhog_status(vmid):
    """What the last apply did, from the agent and from the pending file's fate.

    The agent renames pending.json rather than deleting it -- pending.done.json
    on success, pending.failed.json on failure -- so which one is there is the
    outcome, and it is still there after a reboot the agent did not survive.
    """
    out = _guest_ps(vmid,
                    "$ErrorActionPreference='SilentlyContinue'\n"
                    f"$h = '{GROUNDHOG_HOME}'\n"
                    "$exe = $h + '\\bin\\groundhog-agent.exe'\n"
                    "if (-not (Test-Path $exe)) { Write-Output 'ERR|agent not installed in this image'; exit }\n"
                    "$p = Test-Path ($h + '\\pending.json')\n"
                    "$d = Test-Path ($h + '\\pending.done.json')\n"
                    "$f = Test-Path ($h + '\\pending.failed.json')\n"
                    "$s = (& $exe status 2>&1 | Out-String).Trim()\n"
                    "Write-Output ('OK|' + $p + '|' + $d + '|' + $f + '|' "
                    "+ ($s -replace '\r?\n', ' ~ '))",
                    timeout=120)
    line = _marked_line(out)
    if line.startswith("ERR|"):
        raise RuntimeError(line.split("|", 1)[1])
    _, pending, done, failed, status = line.split("|", 4)
    run = None
    try:
        raw = guest_read(vmid, GROUNDHOG_LAST_RUN + r"\status.json")
        run = json.loads(raw.get("text") or "{}") or None
    except Exception:                                 # noqa: BLE001
        run = None                  # never applied, or an agent older than 0.12
    pending = pending.strip().lower() == "true"
    done = done.strip().lower() == "true"
    failed = failed.strip().lower() == "true"
    # status.json is the authority when it exists: file names cannot distinguish a
    # run that is still going from one that is waiting for a restart, and both
    # leave pending.json in place.
    if run and run.get("status"):
        outcome = str(run["status"])
    elif pending:
        outcome = "running"
    elif failed:
        outcome = "failed"
    elif done:
        outcome = "succeeded"
    else:
        outcome = "none"              # nothing was ever asked of this sandbox

    GH_LAST[int(vmid)] = outcome
    out = {"vmid": int(vmid),
           "pending": pending,
           "outcome": outcome,
           "status": status.strip()}
    if run:
        steps = [{"title": s.get("title"), "status": s.get("status"),
                  "changed": bool(s.get("changed")), "message": s.get("message")}
                 for s in (run.get("steps") or [])]
        out["run"] = {"agent": run.get("agent"), "updated": run.get("updated"),
                      "reboots": run.get("reboots"), "message": run.get("message"),
                      "steps": steps}
        # Name the step that went wrong rather than making the caller scan.
        bad = next((s for s in steps if s.get("status") == "failed"), None)
        if bad:
            out["failed_step"] = bad.get("title")
            out["failed_message"] = bad.get("message")
        if outcome == "reboot-pending":
            out["note"] = ("the apply needs a restart to continue and allow_reboot was "
                           "false, so the agent is waiting: reboot the sandbox and it "
                           "resumes at the next logon. It is not stuck.")
    return out


# --------------------------------------------------------------------------
# Claims
# --------------------------------------------------------------------------
CLAIMS_PATH = os.path.join(HERE, "claims.json")
CLAIMS_LOCK = threading.Lock()
CLAIM_DEFAULT_MINUTES = 60
CLAIM_MAX_MINUTES = 24 * 60


def _claims_load():
    try:
        with open(CLAIMS_PATH, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:                                 # noqa: BLE001
        return {}


def _claims_save(d):
    tmp = CLAIMS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(d, fh, indent=2)
    os.replace(tmp, CLAIMS_PATH)


def get_claim(vmid):
    """The live claim on a sandbox, or None. Expiry is evaluated on read, so a
    forgotten claim stops mattering without anyone tidying up."""
    c = _claims_load().get(str(vmid))
    if not c:
        return None
    if c.get("until", 0) <= time.time():
        return None
    c = dict(c)
    c["minutes_left"] = max(0, int((c["until"] - time.time()) / 60))
    return c


def claim_sandbox(vmid, who, purpose="", minutes=CLAIM_DEFAULT_MINUTES):
    who = (who or "").strip()[:60]
    if not who:
        raise ValueError("who is required -- a claim nobody can be asked about is not a claim")
    minutes = max(1, min(int(minutes or CLAIM_DEFAULT_MINUTES), CLAIM_MAX_MINUTES))
    held = get_claim(vmid)
    if held and held["who"] != who:
        raise RuntimeError(
            f"{held['who']} holds this sandbox for another {held['minutes_left']} min"
            + (f" ({held['purpose']})" if held.get("purpose") else "")
            + ". Take it over with the same 'who', or pick another sandbox.")
    entry = {"who": who, "purpose": (purpose or "").strip()[:200],
             "since": int(time.time()), "until": int(time.time() + minutes * 60)}
    with CLAIMS_LOCK:
        d = _claims_load()
        d[str(vmid)] = entry
        _claims_save(d)
    record_event(vmid, "claimed", f"{who}: {entry['purpose']}"[:80] if entry["purpose"] else who)
    return entry


def release_sandbox(vmid, who=None):
    held = get_claim(vmid)
    if held and who and held["who"] != who.strip():
        raise RuntimeError(f"{held['who']} holds this claim, not {who}")
    with CLAIMS_LOCK:
        d = _claims_load()
        d.pop(str(vmid), None)
        _claims_save(d)
    record_event(vmid, "released", (held or {}).get("who", ""))
    return {"vmid": int(vmid), "released": bool(held)}


def _guard_claim(vmid, action, who=None, force=False):
    """Refuse a destructive action on someone else's live claim.

    Only destroy, repair and update come through here. Everything else stays
    advisory on purpose: a claim you cannot work around for ordinary use is a
    claim people route around entirely.
    """
    held = get_claim(vmid)
    if not held or force:
        return
    if who and held["who"] == who.strip():
        return
    raise RuntimeError(
        f"refusing to {action}: {held['who']} holds VM {vmid} "
        f"for another {held['minutes_left']} min"
        + (f" for {held['purpose']}" if held.get("purpose") else "")
        + ". Pass force=true if you are certain, or wait for the claim to lapse.")


# --------------------------------------------------------------------------
# Expiry
# --------------------------------------------------------------------------
EXPIRY_PATH = os.path.join(HERE, "expiry.json")
EXPIRY_LOCK = threading.Lock()
# 0 means never. Opt-in on purpose: the consequence of being wrong here is a
# destroyed VM, so a fresh install should not start reaping on its own.
TTL_DEFAULT_MINUTES = int(CONFIG.get("default_ttl_minutes") or 0)
TTL_MAX_MINUTES = int(CONFIG.get("max_ttl_minutes") or 60 * 24 * 30)
REAP_POLL_SECONDS = 60


def _expiry_load():
    try:
        with open(EXPIRY_PATH, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:                                 # noqa: BLE001
        return {}


def _expiry_save(d):
    tmp = EXPIRY_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(d, fh, indent=2)
    os.replace(tmp, EXPIRY_PATH)


def get_expiry(vmid):
    """The expiry for one sandbox, or None when it never expires."""
    e = _expiry_load().get(str(vmid))
    if not e:
        return None
    e = dict(e)
    left = e["until"] - time.time()
    e["minutes_left"] = int(left / 60)
    e["expired"] = left <= 0
    return e


def set_expiry(vmid, minutes, who=""):
    """Set, change or remove a sandbox's expiry.

    minutes <= 0 (or None) means never, which is a real choice rather than an
    absence -- it clears any existing timer.
    """
    vmid = int(vmid)
    who = (who or "").strip()[:60]
    if minutes in (None, "", "never", "infinite"):
        minutes = 0
    minutes = int(minutes)
    with EXPIRY_LOCK:
        d = _expiry_load()
        if minutes <= 0:
            was = d.pop(str(vmid), None)
            _expiry_save(d)
            if was:
                record_event(vmid, "expiry cleared", who)
            return {"vmid": vmid, "never": True,
                    "note": "this sandbox will not be destroyed automatically"}
        minutes = min(minutes, TTL_MAX_MINUTES)
        entry = {"who": who, "since": int(time.time()),
                 "until": int(time.time() + minutes * 60), "minutes": minutes}
        d[str(vmid)] = entry
        _expiry_save(d)
    record_event(vmid, "expiry set", f"{minutes} min" + (f" by {who}" if who else ""))
    out = dict(entry)
    out.update({"vmid": vmid, "never": False, "minutes_left": minutes})
    return out


def clear_expiry(vmid):
    """Drop the entry without logging a change -- for a sandbox that is gone."""
    with EXPIRY_LOCK:
        d = _expiry_load()
        if d.pop(str(vmid), None) is not None:
            _expiry_save(d)


def reaper_loop():
    """Destroy sandboxes whose time is up.

    Polls rather than scheduling a timer per sandbox: the set changes without
    this service being told, and a poll that reads the truth each time cannot
    drift out of step with it.
    """
    while True:
        time.sleep(REAP_POLL_SECONDS)
        try:
            live = {s["vmid"] for s in list_sandboxes()}
            for key in list(_expiry_load()):
                vmid = int(key)
                if vmid not in live:
                    clear_expiry(vmid)                # gone already
                    continue
                e = get_expiry(vmid)
                if not e or not e["expired"]:
                    continue
                held = get_claim(vmid)
                if held:
                    # A claim is the more specific statement: someone says they
                    # are using it. Reap once that lapses.
                    print(f"reaper: VM {vmid} is expired but {held['who']} holds a claim "
                          f"for another {held['minutes_left']} min; leaving it", flush=True)
                    continue
                print(f"reaper: VM {vmid} expired; destroying", flush=True)
                record_event(vmid, "expired", "destroyed by the reaper")
                clear_expiry(vmid)
                start_job(f"Destroying {vmid} (expired)", do_destroy, vmid)
        except Exception as exc:                      # noqa: BLE001
            print(f"reaper: {exc}", flush=True)


# --------------------------------------------------------------------------
# History
# --------------------------------------------------------------------------
EVENTS_PATH = os.path.join(HERE, "events.json")
EVENTS_LOCK = threading.Lock()
MAX_EVENTS = 500              # per sandbox

# Proxmox task types worth showing, mapped to something a person can read.
_PVE_TASKS = {
    "qmclone": "cloned from template",
    "qmstart": "powered on",
    "qmstop": "powered off",
    "qmshutdown": "shut down",
    "qmreboot": "rebooted",
    "qmreset": "reset",
    "qmdestroy": "destroyed",
    "vncproxy": "screen viewed",
    "qmsnapshot": "snapshot taken",
    "qmrollback": "rolled back",
}


def _events_load():
    try:
        with open(EVENTS_PATH, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:                                 # noqa: BLE001
        return {}


def _events_save(d):
    tmp = EVENTS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(d, fh, indent=2, default=str)
    os.replace(tmp, EVENTS_PATH)


def record_event(vmid, what, detail=""):
    """Note something the controller did to a sandbox.

    Repeats of the same thing collapse into one entry with a count: an agent
    driving a desktop can call the same tool hundreds of times, and a timeline
    that lists each one is not a timeline.
    """
    if vmid is None:
        return
    try:
        now = int(time.time())
        with EVENTS_LOCK:
            d = _events_load()
            thread = d.setdefault(str(vmid), [])
            if thread and thread[-1]["what"] == what and thread[-1].get("detail") == detail:
                thread[-1]["count"] = thread[-1].get("count", 1) + 1
                thread[-1]["last"] = now
            else:
                thread.append({"ts": now, "what": what, "detail": detail, "count": 1})
            del thread[:-MAX_EVENTS]
            _events_save(d)
    except Exception:                                 # noqa: BLE001
        pass                                          # bookkeeping never breaks work


def _pve_events(vmid, limit=200):
    try:
        tasks = api(f"/nodes/{NODE}/tasks?vmid={int(vmid)}&limit={limit}") or []
    except Exception:                                 # noqa: BLE001
        return []
    out = []
    for t in tasks:
        label = _PVE_TASKS.get(t.get("type"))
        if not label:
            continue
        ok = (t.get("status") or "OK") in ("OK", "")
        out.append({"ts": int(t.get("starttime") or 0), "what": label,
                    "detail": "" if ok else str(t.get("status"))[:80],
                    "source": "proxmox", "ok": ok})
    return out


def _guest_boot(vmid):
    """Ask the guest when it last booted. Best effort: a wedged or powered-off
    guest simply contributes nothing."""
    try:
        out = agent_run_ps(vmid, "$ProgressPreference='SilentlyContinue'\n"
                                 "Write-Output ('BOOT|' + (Get-CimInstance Win32_OperatingSystem)"
                                 ".LastBootUpTime.ToUniversalTime().ToString('s'))", timeout=45)
        for line in (out or "").splitlines():
            if line.strip().startswith("BOOT|"):
                stamp = line.strip().split("|", 1)[1]
                ts = int(time.mktime(time.strptime(stamp, "%Y-%m-%dT%H:%M:%S")))
                return [{"ts": ts, "what": "windows booted", "detail": stamp,
                         "source": "guest", "ok": True}]
    except Exception:                                 # noqa: BLE001
        pass
    return []


def sandbox_history(vmid, include_guest=True):
    vmid = int(vmid)
    events = [{"ts": e["ts"], "what": e["what"], "detail": e.get("detail", ""),
               "count": e.get("count", 1), "last": e.get("last"),
               "source": "controller", "ok": True}
              for e in _events_load().get(str(vmid), [])]
    events += _pve_events(vmid)
    if include_guest:
        events += _guest_boot(vmid)
    events.sort(key=lambda e: e["ts"])
    for e in events:
        e["when"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e["ts"]))
    return {
        "vmid": vmid,
        "events": events,
        "note": ("Proxmox supplies the lifecycle and screen views; the controller "
                 "supplies what it did itself. An agent using a sandbox's Deskhand "
                 "token talks to it directly and never passes through here, so that "
                 "traffic cannot appear in this list."),
    }


# --------------------------------------------------------------------------
# Comments
# --------------------------------------------------------------------------
COMMENTS_PATH = os.path.join(HERE, "comments.json")
COMMENTS_LOCK = threading.Lock()
MAX_COMMENTS = 200            # per sandbox; a thread is a note, not a log


def _comments_load():
    try:
        with open(COMMENTS_PATH, encoding="utf-8") as fh:
            d = json.load(fh)
    except Exception:
        d = {}
    d.setdefault("active", {})
    d.setdefault("archive", [])
    return d


def _comments_save(d):
    # Write-then-swap: a reader never sees a half-written file.
    tmp = COMMENTS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(d, fh, indent=2)
    os.replace(tmp, COMMENTS_PATH)


def add_comment(vmid, text, author=None, via="web", addr=None):
    text = (text or "").strip()
    if not text:
        raise ValueError("comment text is required")
    if len(text) > 4000:
        raise ValueError("comment too long (4000 chars max)")
    entry = {
        "ts": int(time.time()),
        "author": (author or "").strip()[:60] or "anonymous",
        "text": text,
        "via": via,
        "addr": addr or "",
    }
    with COMMENTS_LOCK:
        d = _comments_load()
        thread = d["active"].setdefault(str(vmid), [])
        thread.append(entry)
        del thread[:-MAX_COMMENTS]
        _comments_save(d)
    return entry


def get_comments(vmid):
    return _comments_load()["active"].get(str(vmid), [])


def archive_comments(vmid, name=""):
    """Called when a sandbox is destroyed. VMIDs are reused, so the thread must
    not carry over to whatever lands on this vmid next."""
    with COMMENTS_LOCK:
        d = _comments_load()
        thread = d["active"].pop(str(vmid), None)
        if thread:
            d["archive"].append({"vmid": int(vmid), "name": name,
                                 "closed": int(time.time()), "comments": thread})
            del d["archive"][:-200]
            _comments_save(d)


def get_archive(vmid=None):
    arc = _comments_load()["archive"]
    return [a for a in arc if vmid is None or a.get("vmid") == int(vmid)]


def start_job(title, fn, *args):
    job = Job(title)
    with JOBS_LOCK:
        JOBS[job.id] = job
        # Jobs are the only way to see what happened, so keep a decent history,
        # but do not let a long-lived service accumulate them forever.
        if len(JOBS) > MAX_JOBS:
            for old_id in sorted(JOBS, key=lambda k: JOBS[k].started)[:len(JOBS) - MAX_JOBS]:
                JOBS.pop(old_id, None)

    def run():
        try:
            fn(job, *args)
        except Exception as exc:                      # noqa: BLE001
            job.failed = True
            job.log(f"FAILED: {exc}")
        finally:
            job.done = True
            _jobs_save()
    threading.Thread(target=run, daemon=True).start()
    return job


# --------------------------------------------------------------------------
# Sandbox lifecycle
# --------------------------------------------------------------------------
def list_sandboxes():
    out = []
    try:
        members = api(f"/pools/{POOL}").get("members", [])
    except Exception:
        members = []
    state = load_agent_state()
    # Warm the token cache for every running sandbox at once. Each miss is a
    # guest round trip of about three seconds, and in series that was the sum
    # rather than the longest of them.
    cold = [m["vmid"] for m in members
            if m.get("type") == "qemu" and not m.get("template")
            and m.get("status") == "running" and m["vmid"] not in _TOKEN_CACHE]
    if len(cold) > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            # Bounded: enough to overlap the whole id range, few enough that the
            # Proxmox API does not see a stampede. Failures are left to the
            # per-sandbox path below, which already tolerates a missing token.
            list(pool.map(lambda v: read_token(v), cold))
    for m in members:
        if m.get("type") != "qemu":
            continue
        vmid = m["vmid"]
        if m.get("template"):
            continue          # templates live in the pool to inherit clone rights
        entry = {"vmid": vmid, "name": m.get("name", ""),
                 "status": m.get("status", "?"), "ip": None, "token": None, "port": 8791}
        entry["agents"] = state.get(str(vmid)) or {}
        if entry["status"] == "running":
            entry["ip"] = guest_ip(vmid)
            entry["token"] = read_token(vmid)
        out.append(entry)
    return sorted(out, key=lambda e: e["vmid"])


# Tokens are cached per sandbox. Reading one costs a PowerShell round-trip (see
# read_launcher), and list_sandboxes reads every running sandbox's token on every
# UI poll, so an uncached read there would put seconds of latency on each refresh.
_TOKEN_CACHE = {}


# What was installed where. Kept on disk so the UI can still offer a link after
# a service restart, and so nothing has to be probed inside the guest on every
# poll of the sandbox list.
AGENT_STATE_PATH = os.path.join(HERE, "agents-state.json")
AGENT_STATE_LOCK = threading.Lock()


def load_agent_state():
    try:
        with open(AGENT_STATE_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def set_agent_state(vmid, data):
    with AGENT_STATE_LOCK:
        st = load_agent_state()
        st[str(vmid)] = data
        tmp = AGENT_STATE_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump(st, f, indent=2)
        os.replace(tmp, AGENT_STATE_PATH)


def clear_agent_state(vmid):
    with AGENT_STATE_LOCK:
        st = load_agent_state()
        if st.pop(str(vmid), None) is not None:
            tmp = AGENT_STATE_PATH + ".tmp"
            with open(tmp, "w") as f:
                json.dump(st, f, indent=2)
            os.replace(tmp, AGENT_STATE_PATH)


def read_launcher(vmid, timeout=90):
    r"""Return the text of a sandbox's run-deskhand.ps1, or '' if unreadable.

    Deliberately NOT /agent/file-read. The Windows guest agent leaks the handle
    that call opens: qemu-ga.exe keeps run-deskhand.ps1 open for the rest of its
    life. Because list_sandboxes read the token on every UI poll, the file was
    permanently locked within seconds of the page being opened -- and the lock
    belongs to qemu-ga, which no install script may kill, since it is the channel
    the script itself arrives over.

    The damage that caused was not a clean failure. Remove-Item deletes in
    alphabetical order, so an update wiped C:\Deskhand as far as
    run-deskhand.ps1 -- deskhand-http.exe included -- then hit the lock and threw,
    leaving the sandbox with no Deskhand at all and a logon task pointing at a
    missing exe. Reading through a PowerShell exec opens and closes the file
    inside the guest instead, so no handle outlives the call.
    """
    out = agent_run_ps(
        vmid, "Get-Content -Raw -LiteralPath 'C:\\Deskhand\\run-deskhand.ps1'",
        timeout=timeout)
    return out or ""


def read_config_token(vmid, timeout=90):
    """The token out of deskhand.json, where the declarative install puts it.

    Read through exec rather than /agent/file-read for the same reason
    read_launcher does: that call leaks the handle for the life of qemu-ga.
    """
    out = agent_run_ps(
        vmid,
        "$ErrorActionPreference='SilentlyContinue'\n"
        "$p = Join-Path $env:ProgramData 'Deskhand\\deskhand.json'\n"
        "if (Test-Path $p) { Get-Content -Raw -LiteralPath $p }",
        timeout=timeout)
    if not out:
        return None
    try:
        return (json.loads(out.strip()) or {}).get("token") or None
    except Exception:                                 # noqa: BLE001
        # Not JSON yet, or half-written mid-install. The regex is a last resort
        # rather than the plan, so a malformed file does not become a crash.
        m = re.search(r'"token"\s*:\s*"([^"]+)"', out)
        return m.group(1) if m else None


def read_token(vmid, refresh=False):
    """Recover a sandbox's Deskhand token, so the UI can always show it.

    deskhand.json first, because that is where the declarative install puts it;
    run-deskhand.ps1 second, because sandboxes built before that have only the
    launcher. Without either, the token exists only in the creation log and does
    not survive a restart of this service.
    """
    if not refresh and vmid in _TOKEN_CACHE:
        return _TOKEN_CACHE[vmid]
    tok = read_config_token(vmid)
    if not tok:
        m = re.search(r"DESKHAND_TOKEN\s*=\s*'([^']+)'", read_launcher(vmid))
        tok = m.group(1) if m else None
    if tok:
        _TOKEN_CACHE[vmid] = tok
    return tok


# Ids handed out but whose VM does not exist yet. Pool membership cannot see
# these -- that is the whole problem -- so they are tracked here and counted as
# taken until the clone has either succeeded or failed.
_VMID_LOCK = threading.Lock()
_VMID_INFLIGHT = set()


def free_vmid(skip=()):
    """Reserve the lowest free id in the sandbox range.

    Deliberately NOT from /cluster/resources: this service's token can only see
    its own pool, so that call would need read access to every guest on the
    cluster. The range is reserved for sandboxes, so pool membership is the
    right source -- and if something outside the pool has squatted an id, the
    clone fails and do_create simply tries the next one.

    The reservation is the important part. Membership does not list a VM that is
    still being cloned, so without it two overlapping creates are told the same
    id and then fight over one guest. Release it with release_vmid once the VM
    exists, or once it is certain it never will.
    """
    with _VMID_LOCK:
        used = {m["vmid"] for m in (api(f"/pools/{POOL}").get("members") or [])}
        used |= set(skip) | _VMID_INFLIGHT
        for i in range(ID_LO, ID_HI + 1):
            if i not in used:
                _VMID_INFLIGHT.add(i)
                return i
    raise RuntimeError(f"no free VMID in {ID_LO}-{ID_HI}")


def release_vmid(vmid):
    """Give a reservation back. Safe to call for an id that was never reserved."""
    with _VMID_LOCK:
        _VMID_INFLIGHT.discard(int(vmid))


def wait_unlocked(vmid, timeout=600):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if not (vm("/config", vmid=vmid) or {}).get("lock"):
                return
        except Exception:
            pass
        time.sleep(3)
    raise RuntimeError("clone did not finish")


def wait_agent(vmid, timeout=900):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if agent_ping(vmid):
            return
        time.sleep(5)
    raise RuntimeError("guest agent never responded")


def _reboot_pending(vmid):
    """True while Windows still owes itself a reboot.

    Set by the zero-day patch OOBE installs. Templates built with the current
    provision.ps1 never see it; older ones do, and this is what stops them
    failing fifteen minutes later inside the Deskhand install.
    """
    try:
        out = agent_run_ps(
            vmid,
            "Write-Output (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\"
            "CurrentVersion\\Component Based Servicing\\RebootPending')",
            timeout=60)
    except Exception:
        return False                # agent gone mid-reboot; the caller re-checks
    return bool(out) and out.strip().lower().startswith("true")


def wait_oobe(job, vmid, timeout=900):
    """Block until Windows setup is genuinely finished.

    This matters more than it looks. OOBE creates a temporary 'defaultuser0',
    points auto-logon at it, and during cleanup deletes AutoAdminLogon and
    DefaultUserName -- so anything written before that finishes is silently
    erased, and the sandbox comes up at a lock screen with no session for
    Deskhand to drive.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            out = agent_run_ps(vmid, "Write-Output (Get-ItemProperty 'HKLM:\\SYSTEM\\Setup').SystemSetupInProgress",
                               timeout=60)
        except Exception:
            out = None      # agent gone mid-reboot; keep waiting
        if out and out.strip().startswith("0"):
            # SystemSetupInProgress drops to 0 before OOBE has necessarily
            # stopped working. If OOBE installed a zero-day patch it still owes
            # us a reboot, and the pass after that reboot clears auto-logon --
            # so writing it now would be writing into a file about to be wiped.
            if _reboot_pending(vmid):
                job.log("  setup reports done but a reboot is pending; waiting it out")
                time.sleep(20)
                continue
            job.log("OOBE finished; letting its cleanup settle")
            time.sleep(60)
            return
        time.sleep(10)
    raise RuntimeError("OOBE did not finish")


AUTOLOGON_PS = r"""
$wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
for ($i = 1; $i -le 5; $i++) {{
    Set-ItemProperty $wl -Name AutoAdminLogon    -Value '1' -Type String
    Set-ItemProperty $wl -Name DefaultUserName   -Value '{user}' -Type String
    Set-ItemProperty $wl -Name DefaultPassword   -Value '{password}' -Type String
    Set-ItemProperty $wl -Name DefaultDomainName -Value $env:COMPUTERNAME -Type String
    Start-Sleep -Seconds 15
    $p = Get-ItemProperty $wl
    if ($p.AutoAdminLogon -eq '1' -and $p.DefaultUserName -eq '{user}') {{ Write-Output 'STABLE'; break }}
}}
"""

# Deskhand as a Groundhogfile. Everything here is public: the token is a secret
# reference the agent fills in from pending.json, so this can be served to the
# guest over the payload port like any other artifact.
DESKHAND_GROUNDHOG = """\
version: 1
agent: ">=0.12.0"

files:
  - from: @@PAYLOAD@@
    sha256: @@SHA256@@
    to: C:\\Deskhand
    extract: true

  # Not inside C:\\Deskhand: `extract: true` replaces that folder wholesale, so a
  # config kept there would not survive the next update. Deskhand searches
  # ProgramData, so this is found whatever the working directory is.
  - to: C:\\ProgramData\\Deskhand\\deskhand.json
    content: |
      {
        "token": "${secret:DESKHAND_TOKEN}",
        "port": @@PORT@@,
        "bind": "any",
        "maxToolChars": @@TOOLCHARS@@,
        "enableShell": @@SHELL@@,
        "enableSessionLaunch": @@SHELL@@@@TLS_LINE@@
      }

run:
  - command: |
      # Open the port and register Deskhand's logon task
      $ErrorActionPreference = 'Stop'
      Remove-NetFirewallRule -DisplayName 'Deskhand HTTP' -ErrorAction SilentlyContinue
      New-NetFirewallRule -DisplayName 'Deskhand HTTP' -Direction Inbound -Action Allow -Protocol TCP -LocalPort @@PORT@@ -Profile Any | Out-Null
      $exe = Join-Path 'C:\\Deskhand' 'deskhand-http.exe'
      if (-not (Test-Path $exe)) { throw ('deskhand-http.exe missing from the zip at ' + $exe) }
      $action = New-ScheduledTaskAction -Execute $exe
      $trigger = New-ScheduledTaskTrigger -AtLogOn -User '@@USER@@'
      $principal = New-ScheduledTaskPrincipal -UserId '@@USER@@' -LogonType Interactive -RunLevel Highest
      $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
      Register-ScheduledTask -TaskName 'Deskhand' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
      Stop-Process -Name deskhand-http -Force -ErrorAction SilentlyContinue
      Start-ScheduledTask -TaskName 'Deskhand'

verify:
  - port: @@PORT@@
    within: 3m
"""


INSTALL_PS = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Stop any running instance FIRST. This script is used for updates as well as
# first installs, and the wipe below fails partway otherwise, leaving a
# half-deleted install. Two things hold files open, not one:
#   * deskhand-http.exe          -> its DLLs
#   * the scheduled task's powershell running run-deskhand.ps1 -> that script
# Ending the task kills the launcher; killing only the exe leaves the launcher
# holding run-deskhand.ps1 and the wipe still fails.
# The ScheduledTasks cmdlet, NOT schtasks.exe. Piping a native command's
# stderr under $ErrorActionPreference='Stop' throws NativeCommandError, and
# on a fresh sandbox this task does not exist yet -- so every first install
# died here with 'the system cannot find the file specified'. Updates passed
# because by then the task did exist.
Stop-ScheduledTask -TaskName 'Deskhand' -ErrorAction SilentlyContinue
Stop-Process -Name deskhand-http -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 5

if ('@@KIND@@' -eq 'msi') {
    # The project's CI publishes an MSI on tags, so support installing from one.
    # It lands machine-wide under Program Files rather than C:\Deskhand, so the
    # exe is located rather than assumed.
    $msi = 'C:\Windows\Temp\Deskhand.msi'
    Invoke-WebRequest -Uri '@@PAYLOAD@@' -OutFile $msi -UseBasicParsing
    $pr = Start-Process msiexec.exe -Wait -PassThru -ArgumentList @('/i', ('"' + $msi + '"'), '/qn', '/norestart')
    if ($pr.ExitCode -notin 0, 3010) { throw ("msiexec exit " + $pr.ExitCode) }
    Remove-Item $msi -Force -ErrorAction SilentlyContinue
    $found = Get-ChildItem 'C:\Program Files' -Recurse -Filter deskhand-http.exe -ErrorAction SilentlyContinue |
             Select-Object -First 1
    if (-not $found) { throw 'deskhand-http.exe not found after the MSI install' }
    $exe = $found.FullName
    $dir = Split-Path $exe
} else {
    $dir = 'C:\Deskhand'
    $zip = 'C:\Windows\Temp\deskhand.zip'
    Invoke-WebRequest -Uri '@@PAYLOAD@@' -OutFile $zip -UseBasicParsing
    if (Test-Path $dir) {
        $ok = $false
        foreach ($try in 1..5) {
            try { Remove-Item $dir -Recurse -Force -ErrorAction Stop; $ok = $true; break }
            catch { Start-Sleep -Seconds 3 }
        }
        if (-not $ok) { throw ('could not clear ' + $dir + ' - something still holds a file open') }
    }
    Expand-Archive -Path $zip -DestinationPath $dir -Force
    Remove-Item $zip -Force -ErrorAction SilentlyContinue
    $exe = Join-Path $dir 'deskhand-http.exe'
    if (-not (Test-Path $exe)) { throw 'deskhand-http.exe missing from the zip' }
}

# The launcher always lives at a fixed path regardless of install shape, because
# the controller reads the token back out of it.
$cfgdir = 'C:\Deskhand'
if (-not (Test-Path $cfgdir)) { New-Item -ItemType Directory -Path $cfgdir | Out-Null }
$runner = Join-Path $cfgdir 'run-deskhand.ps1'
@"
`$ip = (Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { `$_.IPAddress -notlike '127.*' -and `$_.IPAddress -notlike '169.254.*' } |
        Select-Object -First 1).IPAddress
if (-not `$ip) { `$ip = 'any' }
`$env:DESKHAND_BIND  = `$ip
`$env:DESKHAND_TOKEN = '@@TOKEN@@'
`$env:DESKHAND_PORT  = '@@PORT@@'
# Cap a single tool result. Deskhand 0.2.7+ does not truncate: past this it
# stores the full text and returns a small valid envelope instead. Worth setting
# to whatever the CLIENT will accept -- Hermes trims an MCP result above its own
# cap to a 1.5k preview, so a Deskhand budget larger than that just guarantees
# the client throws the difference away.
`$env:DESKHAND_MAX_TOOL_CHARS = '@@TOOLCHARS@@'
@@SHELL_LINE@@
@@TLS_LINE@@
Set-Location '$dir'
& '$exe'
"@ | Set-Content $runner -Encoding UTF8

Remove-NetFirewallRule -DisplayName 'Deskhand HTTP' -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName 'Deskhand HTTP' -Direction Inbound -Action Allow `
    -Protocol TCP -LocalPort @@PORT@@ -Profile Any | Out-Null

# A logon task, not a service: Deskhand drives the desktop through UI Automation,
# which only works inside an interactive session. Session 0 has no desktop.
#
# RunLevel Highest, not Limited. A scheduled task started this way is elevated
# with no consent prompt, which is the only way Deskhand's system-control and
# UAC tools can work at all -- writing HKLM policy needs admin, and an
# unelevated process cannot obtain it without a prompt on the secure desktop
# that nothing is able to click. It also means installers Deskhand launches
# inherit elevation and never raise a prompt in the first place.
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument ('-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $runner + '"')
$trigger = New-ScheduledTaskTrigger -AtLogOn -User '@@USER@@'
$principal = New-ScheduledTaskPrincipal -UserId '@@USER@@' -LogonType Interactive -RunLevel Highest
Register-ScheduledTask -TaskName 'Deskhand' -Action $action -Trigger $trigger `
    -Principal $principal -Force | Out-Null

Stop-Process -Name deskhand-http -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Start-ScheduledTask -TaskName 'Deskhand' -ErrorAction SilentlyContinue
Write-Output 'INSTALLED'
"""


def do_create(job, opts):
    name = opts["name"]
    # An id can be taken by something outside the pool, which this token cannot
    # see. Rather than demand cluster-wide read access, just try the next one.
    tried = []
    for _ in range(6):
        vmid = free_vmid(skip=tried)
        job.vmid = vmid
        job.log(f"allocating VMID {vmid} ({name})")
        try:
            api(f"/nodes/{NODE}/qemu/{TEMPLATE}/clone", "POST", {
                "newid": vmid, "name": name, "full": 0, "pool": POOL}, timeout=120)
            break
        except Exception as exc:                      # noqa: BLE001
            if "already exists" not in str(exc).lower() and "config file" not in str(exc).lower():
                raise
            job.log(f"  {vmid} is taken by something outside the pool; trying the next")
            release_vmid(vmid)        # it is not ours; do not hold the slot
            tried.append(vmid)
    else:
        raise RuntimeError("could not find a free VMID")
    wait_unlocked(vmid)
    job.log("cloned from template")

    # The reservation is held until the whole create finishes, not just until the
    # clone exists. Allocation stops needing it the moment the VM joins the pool,
    # but capacity does not: for the next five minutes the VM is in the pool and
    # stopped, so counting only running sandboxes would let four more creates
    # through while four were already on their way up.
    try:
        # Set before provisioning, not after: a build that dies half way is
        # exactly the case worth cleaning up on its own.
        ttl = opts.get("expires_in_minutes")
        if ttl is None:
            ttl = TTL_DEFAULT_MINUTES
        if int(ttl or 0) > 0:
            exp = set_expiry(vmid, ttl, opts.get("who") or "create")
            job.log(f"expires in {exp['minutes']} min unless extended")
        else:
            job.log("no expiry: this sandbox stays until destroyed")

        provision(job, vmid, opts)
    finally:
        release_vmid(vmid)

def provision(job, vmid, opts, configure_hw=True):
    """Bring a cloned-but-unfinished sandbox all the way up.

    Split out of do_create so an interrupted build can be resumed. Jobs live
    in memory, so restarting this service mid-create abandons the job and
    leaves a VM with no auto-logon and no Deskhand; repair_sandbox re-runs
    exactly these steps against it. Every step is idempotent.
    """
    # Reuse the MAC the clone was given. Passing net0 without one mints a fresh
    # MAC, which releases this guest's SDN IPAM reservation and can move its IP.
    if configure_hw:
        cfg = vm("/config", vmid=vmid)
        mac = cfg["net0"].split("=")[1].split(",")[0]
        vm("/config", "PUT", vmid=vmid, data={
            "net0": f"virtio={mac},bridge={BRIDGE},firewall=1",
            "cores": opts["cores"], "memory": opts["memory"],
            # base=utc, not the localtime default Proxmox picks for win11: the
            # guest's timezone is UTC, so a local-time RTC reads as exactly the
            # host's UTC offset behind -- seven hours here. Takes effect on a
            # cold boot, since the RTC base is a QEMU argument.
            "localtime": 0,
            "description": "SANDBOX - disposable, not backed up. Created by sandboxctl."})

    if (vm("/status/current", vmid=vmid) or {}).get("status") != "running":
        vm("/status/start", "POST", vmid=vmid)
    job.log("started; waiting for the guest agent")
    wait_agent(vmid)

    wait_oobe(job, vmid)

    # Sysprep's answer file survives into the image with the local admin
    # password in plaintext, readable by BUILTIN\\Users. Windows scrubs its
    # own copy under Panther and leaves this one alone.
    scrub = agent_run_ps(vmid,
                         "$ProgressPreference='SilentlyContinue'\n"
                         "$gone = 0\n"
                         "Get-ChildItem 'C:\\Windows\\Panther','C:\\Windows\\System32\\Sysprep' "
                         "-Filter *.xml -Recurse -ErrorAction SilentlyContinue |\n"
                         "  Where-Object { Select-String -Path $_.FullName -Pattern 'PlainText>true' "
                         "-Quiet -ErrorAction SilentlyContinue } |\n"
                         "  ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force "
                         "-ErrorAction SilentlyContinue; $gone++ }\n"
                         "Write-Output ('SCRUBBED|' + $gone)",
                         timeout=120)
    removed = "?"
    for line in (scrub or "").splitlines():
        if line.strip().startswith("SCRUBBED|"):
            removed = line.strip().split("|", 1)[1]
    job.log(f"removed {removed} answer file(s) holding the password in plaintext")

    # Two copies of one secret: the value baked into the template account, and
    # the config value auto-logon is written from. Sync them here -- the agent
    # runs as SYSTEM, so this needs no knowledge of the previous value -- so
    # that rotating the secret is a config edit, not a template rebuild.
    setpw = agent_run_ps(
        vmid,
        "$ProgressPreference='SilentlyContinue'\n"
        f"$u = Get-LocalUser -Name {_ps_literal(WIN_USER)} -ErrorAction SilentlyContinue\n"
        "if (-not $u) { Write-Output 'PWSET|missing'; exit }\n"
        f"Set-LocalUser -Name {_ps_literal(WIN_USER)} "
        f"-Password (ConvertTo-SecureString {_ps_literal(WIN_PASS)} -AsPlainText -Force) "
        "-PasswordNeverExpires $true\n"
        "Write-Output 'PWSET|ok'",
        timeout=120)
    if "PWSET|ok" not in (setpw or ""):
        raise RuntimeError(
            f"could not set the {WIN_USER} account credential in the image. Auto-logon "
            "would then be written with a value the account does not have, so this stops "
            "here rather than handing back a sandbox with no session.")
    job.log(f"account {WIN_USER}: credential synced from config")

    job.log("applying auto-logon")
    out = None
    for _ in range(6):
        out = agent_run_ps(vmid, AUTOLOGON_PS.format(user=WIN_USER, password=WIN_PASS), timeout=200)
        if out and "STABLE" in out:
            break
        job.log("  auto-logon not stable yet; retrying")
        time.sleep(20)
    if not out or "STABLE" not in out:
        raise RuntimeError("auto-logon did not stick")
    job.log("auto-logon set; rebooting into a desktop session")
    vm("/status/reboot", "POST", vmid=vmid)
    time.sleep(45)
    wait_agent(vmid)

    token = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(40))
    shell_line = "`$env:DESKHAND_ENABLE_SHELL = '1'" if opts["shell"] else ""
    tls_line = "`$env:DESKHAND_TLS = 'self-signed'" if opts["tls"] else ""
    kind = artifact_kind()
    if kind is None:
        raise RuntimeError("no Deskhand payload staged on the controller; "
                           "run fetch_deskhand or copy one into payload/")
    asset = "deskhand.zip" if kind == "zip" else "Deskhand.msi"
    script = (INSTALL_PS
              .replace("@@KIND@@", kind)
              .replace("@@PAYLOAD@@", f"{SELF_URL}/payload/{asset}")
              .replace("@@TOKEN@@", token)
              .replace("@@PORT@@", str(opts["port"]))
              .replace("@@SHELL_LINE@@", shell_line)
              .replace("@@TLS_LINE@@", tls_line)
              .replace("@@USER@@", WIN_USER)
              .replace("@@TOOLCHARS@@", str(DESKHAND_TOOL_CHARS)))
    # Default: let Groundhog do it. The Groundhogfile fetches the zip, so an
    # installation staged with the MSI keeps the scripted path rather than
    # failing where it used to work.
    via_gh = opts.get("deskhand_via_groundhog")
    if via_gh is None:
        via_gh = True
    if via_gh and kind != "zip":
        job.log(f"installing Deskhand with the scripted path ({asset}): "
                "the Groundhog route needs the zip artifact")
        via_gh = False
    if via_gh:
        install_deskhand_groundhog(job, vmid, opts, token)
    else:
        job.log(f"installing Deskhand from the controller ({asset})")
        out = agent_run_ps(vmid, script, timeout=900)
        if not out or "INSTALLED" not in out:
            raise RuntimeError(f"Deskhand install failed: {(out or '')[:400]}")

    time.sleep(15)
    ip = guest_ip(vmid)
    scheme = "https" if opts["tls"] else "http"
    # Read the name back from the VM rather than a caller local: provision() is
    # also reached from repair, where no name was ever passed in.
    vm_name = (vm("/config", vmid=vmid) or {}).get("name") or opts.get("name") or str(vmid)
    job.result = {"vmid": vmid, "name": vm_name, "ip": ip, "token": token,
                  "url": f"{scheme}://{ip}:{opts['port']}/?token={token}" if ip else None}
    _TOKEN_CACHE[vmid] = token
    job.log(f"ready: {ip}  token {token}")

    if opts.get("groundhog"):
        try:
            apply_groundhog(vmid, opts["groundhog"], opts.get("groundhog_sha256"),
                            None, opts.get("groundhog_allow_reboot", False), job,
                            secrets=opts.get("groundhog_secrets"),
                            headers=opts.get("groundhog_headers"))
        except Exception as exc:                      # noqa: BLE001
            job.log(f"groundhog: could not start the apply: {exc}")


def install_deskhand_groundhog(job, vmid, opts, token):
    """Install Deskhand by applying a rendered Groundhogfile, and wait for it.

    Returns nothing; raises if the apply did not succeed. The caller already
    knows the token -- it generated it -- so nothing has to be read back.
    """
    asset = "deskhand.zip"
    sha = _payload_sha256(f"{SELF_URL}/payload/{asset}")
    if not sha:
        raise RuntimeError("could not hash the staged deskhand.zip to pin it")

    tls = ',\n        "tls": "self-signed"' if opts.get("tls") else ""
    body = (DESKHAND_GROUNDHOG
            .replace("@@PAYLOAD@@", f"{SELF_URL}/payload/{asset}")
            .replace("@@SHA256@@", sha)
            .replace("@@PORT@@", str(opts["port"]))
            .replace("@@TOOLCHARS@@", str(DESKHAND_TOOL_CHARS))
            .replace("@@SHELL@@", "true" if opts.get("shell") else "false")
            .replace("@@TLS_LINE@@", tls)
            .replace("@@USER@@", WIN_USER))

    # Per sandbox, because the port and flags differ. It carries no secret, only
    # a reference to one, so serving it from the payload port is safe.
    name = f"deskhand-{vmid}.groundhog.yaml"
    pdir = os.path.join(HERE, "payload")
    os.makedirs(pdir, exist_ok=True)
    tmp = os.path.join(pdir, name + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(body)
    os.replace(tmp, os.path.join(pdir, name))

    job.log(f"installing Deskhand via Groundhog; {asset} pinned to {sha[:12]}...")
    # The agent is often still coming back from the auto-logon reboot, and under
    # concurrency that window is longer. Only the agent-unavailable case is
    # retried: a bad Groundhogfile or a missing artifact should fail at once.
    for attempt in range(1, 7):
        try:
            apply_groundhog(vmid, f"{SELF_URL}/payload/{name}", None, True, False, job,
                            secrets={"DESKHAND_TOKEN": token})
            break
        except Exception as exc:                      # noqa: BLE001
            if "did not answer" not in str(exc) or attempt == 6:
                raise
            job.log(f"  the guest agent is not back yet; retrying ({attempt}/6)")
            time.sleep(20)
            wait_agent(vmid, timeout=180)

    deadline = time.time() + 900
    last = ""
    while time.time() < deadline:
        time.sleep(15)
        try:
            st = groundhog_status(vmid)
        except Exception:                             # noqa: BLE001
            continue                                  # agent busy or mid-restart
        if st["outcome"] != last:
            job.log(f"  groundhog: {st['outcome']}")
            last = st["outcome"]
        if st["outcome"] == "succeeded":
            steps = (st.get("run") or {}).get("steps") or []
            if not steps:
                # The outcome can land from the done marker a moment before the
                # agent finishes writing status.json. The job log is the audit
                # trail, so ask once more rather than recording nothing.
                time.sleep(5)
                try:
                    steps = (groundhog_status(vmid).get("run") or {}).get("steps") or []
                except Exception:                     # noqa: BLE001
                    steps = []
            for s in steps:
                job.log(f"    {s['status']}: {str(s['title'])[:90]}")
            return
        if st["outcome"] == "failed":
            raise RuntimeError("Deskhand install failed at step %r: %s"
                               % (st.get("failed_step"), st.get("failed_message")))
        if st["outcome"] == "reboot-pending":
            raise RuntimeError("the Deskhand install wants a restart, which this "
                               "path does not expect; investigate before retrying")
    raise RuntimeError("the Deskhand Groundhog apply did not finish in 15 minutes")


def do_destroy(job, vmid):
    vmid = _check_managed(vmid)
    if (vm("/status/current", vmid=vmid) or {}).get("status") == "running":
        job.log("stopping")
        vm("/status/stop", "POST", vmid=vmid)
        for _ in range(60):
            time.sleep(3)
            if (vm("/status/current", vmid=vmid) or {}).get("status") == "stopped":
                break
    try:
        release_sandbox(vmid)
    except Exception:                                 # noqa: BLE001
        pass
    clear_expiry(vmid)
    GH_LAST.pop(int(vmid), None)
    # The per-sandbox Groundhogfile the install rendered. Harmless to serve,
    # but it would otherwise leave one file per sandbox ever created.
    try:
        os.remove(os.path.join(HERE, "payload",
                               f"deskhand-{int(vmid)}.groundhog.yaml"))
    except OSError:
        pass
    try:                    # and anything typed into the editor for it
        os.remove(os.path.join(HERE, "payload",
                               f"adhoc-{int(vmid)}.groundhog.yaml"))
    except OSError:
        pass
    try:
        archive_comments(vmid, (vm("/config", vmid=vmid) or {}).get("name") or "")
    except Exception:                                 # noqa: BLE001
        pass                                          # a note must never block a destroy
    _TOKEN_CACHE.pop(vmid, None)
    clear_agent_state(vmid)
    if RECORDER:
        RECORDER.stop(vmid)
    job.log("destroying")
    api(f"/nodes/{NODE}/qemu/{vmid}?purge=1&destroy-unreferenced-disks=1", "DELETE", timeout=180)
    job.log("gone")



# --------------------------------------------------------------------------
# MCP server (Streamable HTTP, stateless)
# --------------------------------------------------------------------------
# So an AI can run the whole loop itself: create a sandbox, get its Deskhand
# endpoint + token, drive the desktop through that, then throw it away.
#
# Creating takes minutes, so create/destroy return a job id immediately and
# `job_status` polls it. Blocking a tool call for five minutes would just hit
# the client's timeout and leave the caller unsure whether it worked.
MCP_PROTOCOL = "2024-11-05"

MCP_TOOLS = [
    {
        "name": "list_sandboxes",
            "description": ("List every sandbox: vmid, name, status, IP, Deskhand URL, "
                        "bearer token, and a ready-to-use MCP endpoint for each one. "
                        "Use this to find a sandbox to drive."),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "generate_template",
        "description": ("Build a new sandbox template: clone an existing one, let OOBE settle, "
                        "optionally apply a Groundhogfile and run extra steps, then sysprep and "
                        "seal it. Returns a job id; expect 15-30 minutes. The new template is "
                        "created inside the sandbox pool so it inherits clone rights. Pass "
                        "activate=true to point new sandboxes at it."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Name for the template. Max 15 chars."},
                "base": {"type": "integer", "description": "Template to clone from. "
                                                           "Defaults to the active one."},
                "groundhog": {"type": "string", "description": "Groundhogfile to bake in -- a "
                                                               "path, URL or zip. Reboots are "
                                                               "allowed during a template build."},
                "groundhog_sha256": {"type": "string"},
                "groundhog_timeout": {"type": "integer",
                                      "description": ("Seconds to allow the apply. Default "
                                                      "7200. Windows features and "
                                                      "capabilities are serviced from Windows "
                                                      "Update unless the Groundhogfile gives a "
                                                      "`source:`, and NetFx3 or OpenSSH.Server "
                                                      "is roughly 30 minutes each on a fresh "
                                                      "Windows 11 VM -- which is exactly what "
                                                      "baking a base layer is for, so allow "
                                                      "for it.")},
                "steps": {"type": "array", "items": {"type": "string"},
                          "description": "PowerShell run in the image before sealing, in order. "
                                         "For things a Groundhogfile cannot express."},
                "activate": {"type": "boolean", "description": "Point new sandboxes at it once "
                                                               "sealed. Default false."},
                "storage": {"type": "string", "description": "Proxmox storage. Default local-lvm."},
            },
        },
    },
    {
        "name": "apply_groundhog",
        "description": ("Configure a sandbox from a Groundhogfile -- apps via winget, files, "
                        "registry, environment, commands, verification. Takes a path, URL or "
                        "zip. Serve one from the controller's payload directory and use "
                        "http://<controller>:8081/payload/<name>, the only controller port a "
                        "sandbox can reach. Returns once started; poll groundhog_status."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "vmid": {"type": "integer"},
                "source": {"type": "string", "description": "Path, URL or zip bundle."},
                "sha256": {"type": "string", "description": "Optional, pins the source."},
                "allow_reboot": {"type": "boolean", "description": "Let it reboot mid-apply. "
                                                                   "Default false."},
                "allow_http": {"type": "boolean", "description": "Defaults to true for http:// "
                                                                 "sources, which the payload "
                                                                 "port requires."},
                "secrets": {"type": "object", "additionalProperties": {"type": "string"},
                            "description": ("Values for ${secret:NAME} references in the "
                                            "Groundhogfile -- a token, an API key. REQUIRED if "
                                            "the file references any: a missing one stops the "
                                            "run before it changes anything. The agent removes "
                                            "them from pending.json as it reads it and never "
                                            "logs them. Needs agent >=0.12.0, which a template "
                                            "agent self-updates to. A per-VM value is the right "
                                            "use: it is born and dies with the sandbox. A "
                                            "long-lived API key is NOT -- anything in a sandbox "
                                            "can read it once written, and it outlives the VM.")},
                "headers": {"type": "array", "items": {"type": "string"},
                            "description": ("Headers for private sources, as "
                                            "\"host=Name: value\". A value may itself be "
                                            "${secret:NAME}.")},
            },
            "required": ["vmid", "source"],
        },
    },
    {
        "name": "groundhog_status",
        "description": ("How the last Groundhog apply went on a sandbox. `outcome` is "
                        "running, succeeded, failed, reboot-pending or none, with `run.steps` "
                        "giving each step's title and state and `failed_step` naming the one "
                        "that broke. reboot-pending means the apply needs a restart to "
                        "continue and allow_reboot was false: reboot the sandbox and it "
                        "resumes at the next logon -- it is not stuck."),
        "inputSchema": {
            "type": "object",
            "properties": {"vmid": {"type": "integer"}},
            "required": ["vmid"],
        },
    },
    {
        "name": "set_expiry",
        "description": ("Set when a sandbox is destroyed automatically, or stop it expiring. "
                        "minutes=0 (or omit it) means never, which is a real choice rather "
                        "than an absence -- it clears any existing timer. Call it again to "
                        "extend. A sandbox under an active claim is left alone until the "
                        "claim lapses."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "vmid": {"type": "integer"},
                "minutes": {"type": "integer",
                            "description": "Minutes from now. 0 means never expire."},
                "who": {"type": "string", "description": "Who set it, for the history."},
            },
            "required": ["vmid"],
        },
    },
    {
        "name": "claim_sandbox",
        "description": ("Say you are using a sandbox, so nobody destroys it under you. "
                        "Advisory: it does not stop anyone driving the machine, but "
                        "destroy_sandbox, repair_sandbox and update_sandbox will refuse "
                        "while someone else holds it. Claims expire on their own, so a "
                        "forgotten one is not a problem for the next person."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "vmid": {"type": "integer"},
                "who": {"type": "string", "description": "You. Required -- a claim nobody "
                                                         "can be asked about is not a claim."},
                "purpose": {"type": "string", "description": "What you are doing, so someone "
                                                             "deciding whether to wait can tell."},
                "minutes": {"type": "integer", "description": "How long you need it. "
                                                              "Default 60, max 1440."},
            },
            "required": ["vmid", "who"],
        },
    },
    {
        "name": "release_sandbox",
        "description": "Give up a claim early, once you have finished with the sandbox.",
        "inputSchema": {
            "type": "object",
            "properties": {"vmid": {"type": "integer"}, "who": {"type": "string"}},
            "required": ["vmid"],
        },
    },
    {
        "name": "sandbox_history",
        "description": ("What has happened to a sandbox, oldest first: cloned, powered on, "
                        "rebooted, screen viewed, agents installed, Deskhand updated, files "
                        "read or written, notes left. Lifecycle and screen views come from "
                        "Proxmox; the rest is what the controller did. Calls an agent makes "
                        "directly to a sandbox's Deskhand do not pass through the controller "
                        "and so cannot appear."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "vmid": {"type": "integer"},
                "include_guest": {"type": "boolean",
                                  "description": "Also ask the guest when it last booted. "
                                                 "Default true; skipped silently if it cannot answer."},
            },
            "required": ["vmid"],
        },
    },
    {
        "name": "browse_guest_file",
        "description": ("List a directory inside a sandbox THROUGH THE GUEST AGENT, which "
                        "works when Deskhand is not running -- a guest stuck in setup, at a "
                        "lock screen, or not yet provisioned. If Deskhand is up, prefer "
                        "<sandbox>__deskhand_browse_files: it is faster and not capped."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "vmid": {"type": "integer"},
                "path": {"type": "string", "description": "Directory, e.g. C:\\Windows\\Panther"},
            },
            "required": ["vmid"],
        },
    },
    {
        "name": "read_guest_file",
        "description": ("Read a file inside a sandbox through the guest agent, for when "
                        "Deskhand cannot answer. Good for setup logs: "
                        "C:\\Windows\\Panther\\setuperr.log and "
                        "C:\\Windows\\Panther\\UnattendGC\\setupact.log explain most "
                        "failed provisions. 4 MiB limit; binary returns base64."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "vmid": {"type": "integer"},
                "path": {"type": "string", "description": "Full path to the file."},
            },
            "required": ["vmid", "path"],
        },
    },
    {
        "name": "write_guest_file",
        "description": ("Write a file inside a sandbox through the guest agent. Works before "
                        "Deskhand exists and while Windows setup is still running, so it is "
                        "also how you fix a guest nothing else can reach. Written to a "
                        "temporary file and moved into place only once it is all there, so a "
                        "failure part-way leaves the original untouched. "
                        "THERE IS NO SIZE LIMIT: it splits the content up for you. Measured "
                        "~13 s for 4 MiB, so a few MB is routine and tens of MB is fine if "
                        "you are willing to wait. For something large AND publicly "
                        "downloadable, prefer having the guest fetch it -- a sandbox can "
                        "reach the internet directly, which is faster than pushing it "
                        "through here and costs the controller nothing."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "vmid": {"type": "integer"},
                "path": {"type": "string"},
                "text": {"type": "string", "description": "UTF-8 content."},
                "content_base64": {"type": "string", "description": "Binary content instead."},
                "append": {"type": "boolean", "description": "Append rather than replace."},
            },
            "required": ["vmid", "path"],
        },
    },
    {
        "name": "comment_sandbox",
        "description": ("Leave a note on a sandbox, so the next person or agent knows what "
                        "it is for and what you did to it. Notes are append-only and survive "
                        "restarts; they are archived when the sandbox is destroyed. Say who "
                        "you are in 'author' -- it is not verified, it is a signature."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "vmid": {"type": "integer", "description": "Which sandbox to comment on."},
                "text": {"type": "string", "description": "The note. 4000 chars max."},
                "author": {"type": "string", "description": "Who is writing. Self-declared."},
            },
            "required": ["vmid", "text"],
        },
    },
    {
        "name": "read_comments",
        "description": ("Read the notes left on a sandbox, oldest first. Worth doing before "
                        "you change one you did not create. Pass archived=true to read the "
                        "threads of sandboxes that no longer exist."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "vmid": {"type": "integer", "description": "Which sandbox."},
                "archived": {"type": "boolean", "description": "Read archived threads instead."},
            },
            "required": ["vmid"],
        },
    },
    {
        "name": "capacity",
        "description": ("How many sandboxes exist and how many are running, against the "
                        "configured limits. Check this before creating one in bulk: "
                        "create_sandbox refuses at the limit."),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "create_sandbox",
            "description": ("Create a new disposable Windows 11 sandbox with Deskhand installed. "
                        "Returns a job id immediately; poll job_status until done (about 5 "
                        "minutes). The finished job carries the IP, token and MCP URL."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Optional. Max 15 chars, letters/digits/hyphen."},
                    "cores": {"type": "integer", "description": "vCPUs (default 4)"},
                "memory": {"type": "integer", "description": "MiB of RAM (default 8192)"},
                "port": {"type": "integer", "description": "Deskhand port (default 8791)"},
                "shell": {"type": "boolean", "description": "Enable Deskhand's command runner (default true)"},
                "tls": {"type": "boolean", "description": ("Self-signed HTTPS. Default false, and "
                                                           "leave it false for MCP: the certificate is "
                                                           "ephemeral so verifying clients reject it.")},
                "who": {"type": "string", "description": "You, for the history and for claims."},
                "deskhand_via_groundhog": {"type": "boolean",
                                           "description": ("How Deskhand gets installed. Default "
                                                           "true: a Groundhogfile, which is "
                                                           "declarative, reruns only what "
                                                           "changed, and is verified by its own "
                                                           "port check. Set false for the older "
                                                           "scripted install. Ignored when the "
                                                           "staged artifact is the MSI, which "
                                                           "always uses the scripted path.")},
                "expires_in_minutes": {"type": "integer",
                                       "description": ("Destroy it automatically after this long. "
                                                       "0 or omitted means never. A sandbox under "
                                                       "an active claim is left alone until the "
                                                       "claim lapses.")},
                "groundhog": {"type": "string",
                              "description": ("Optional Groundhogfile to apply once the sandbox is "
                                              "up -- apps, files, registry, env, verification. A "
                                              "path, URL or zip. Applied last, so a config that "
                                              "fails still leaves a working sandbox. Serve one "
                                              "from the payload port, the only controller port a "
                                              "sandbox can reach.")},
                "groundhog_sha256": {"type": "string", "description": "Optional, pins the source."},
                "groundhog_allow_reboot": {"type": "boolean",
                                           "description": "Let it reboot mid-apply. Default false."},
                "groundhog_secrets": {"type": "object",
                                      "additionalProperties": {"type": "string"},
                                      "description": ("Values for ${secret:NAME} references in "
                                                      "your Groundhogfile. REQUIRED if it uses "
                                                      "any: a missing one stops the run before it "
                                                      "changes anything. Never logged, and the "
                                                      "agent strips them from pending.json as it "
                                                      "reads it. A per-VM value is the right use: "
                                                      "it is born and dies with the sandbox. A "
                                                      "long-lived API key is NOT -- anything in a "
                                                      "sandbox can read it once written, and it "
                                                      "outlives the VM.")},
                "groundhog_headers": {"type": "array", "items": {"type": "string"},
                                      "description": ("Headers for a private source, as "
                                                      "\"host=Name: value\".")},
            },
        },
    },
    {
        "name": "destroy_sandbox",
            "description": ("Permanently destroy a sandbox and its disk. Only works on sandboxes in the "
                        "managed pool. Returns a job id; poll job_status."),
        "inputSchema": {
            "type": "object",
            "properties": {"vmid": {"type": "integer", "description": "The sandbox VMID"}},
            "required": ["vmid"],
        },
    },
    {
        "name": "update_sandbox",
            "description": ("Update a running sandbox to the Deskhand build currently on the "
                        "controller, in place. Keeps the sandbox's existing token and settings, "
                        "so MCP clients pointed at it keep working. Returns a job id."),
        "inputSchema": {
            "type": "object",
            "properties": {"vmid": {"type": "integer"}},
            "required": ["vmid"],
        },
    },
    {
        "name": "install_agents",
        "description": ("Install an AI agent INSIDE a sandbox (hermes, opencode, or both) and "
                        "configure it with the controller's API keys and that sandbox's own "
                        "Deskhand as an MCP server, so it can drive the desktop it runs on. "
                        "On demand: Hermes alone is a ~2 GB install. Returns a job id. "
                        "NOTE: this writes the controller's API keys into an untrusted VM, "
                        "where anything running can read them, and they outlive the sandbox. "
                        "Use scoped or short-lived keys, not your main ones."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "vmid": {"type": "integer", "description": "The sandbox VMID"},
                "agents": {"type": "array", "items": {"type": "string", "enum": ["hermes", "opencode"]},
                           "description": "Which agents to install"},
                "base_url": {"type": "string", "description": (
                    "OpenAI-compatible inference endpoint the agent should call, e.g. "
                    "http://10.0.0.5:11444/v1. Defaults to agents.base_url in the "
                    "controller config. Leave the key empty if the server needs none.")},
                "api_key": {"type": "string", "description": "Optional key for that endpoint"},
                "model": {"type": "string", "description": "Model name to select, e.g. qwen3-30b"},
                "context_length": {"type": "integer", "description": (
                    "The context window the server actually serves this model with. Worth "
                    "setting for a local server whose tag pins a custom num_ctx, since "
                    "/v1/models advertises the model ceiling instead.")},
            },
            "required": ["vmid", "agents"],
        },
    },
    {
        "name": "repair_sandbox",
        "description": ("Finish a sandbox whose creation was interrupted (it sits at a lock "
                        "screen with no Deskhand). Re-runs auto-logon and the Deskhand "
                        "install. Also usable to reinstall Deskhand with a fresh token."),
        "inputSchema": {
            "type": "object",
            "properties": {"vmid": {"type": "integer"}},
            "required": ["vmid"],
        },
    },
    {
        "name": "fetch_deskhand",
        "description": ("Download a Deskhand build from the project's GitHub releases onto the "
                        "controller, so new and updated sandboxes get it. Omit tag for the "
                        "latest release. Fails clearly if the repo has no releases yet."),
        "inputSchema": {
            "type": "object",
            "properties": {"tag": {"type": "string", "description": "e.g. v0.1.0; omit for latest"}},
        },
    },
    {
        "name": "job_status",
        "description": ("Check a create_sandbox or destroy_sandbox job. Returns its log, "
                        "completion state and result. Jobs survive a restart; one left "
                        "unfinished by one is marked INTERRUPTED."),
        "inputSchema": {
            "type": "object",
            "properties": {"id": {"type": "string",
                                  "description": "The job_id returned by create_sandbox "
                                                 "or destroy_sandbox."}},
            "required": ["id"],
        },
    },
]




# Updating an existing sandbox in place. The launcher (run-deskhand.ps1) is NOT
# in the zip -- it is generated at install time and holds the token, port and
# feature flags -- so extracting over the directory leaves it untouched and the
# sandbox keeps the same token. That matters: a changed token would silently
# break whatever MCP client is already pointed at this box.



# --------------------------------------------------------------------------
# Guest filesystem, over the agent channel
# --------------------------------------------------------------------------
# PowerShell's -EncodedCommand goes on a command line, so the whole script must
# fit in it. Writes are therefore chunked; reads are capped because the result
# comes back through the same place.
GUEST_READ_MAX = 4 * 1024 * 1024        # 4 MiB, base64'd on the way out
# Bytes of payload per exec call. This is a throughput setting, not a size
# limit -- guest_write chunks and loops, so there is no cap on the file.
#
# The ceiling is the Windows command line, 32767 characters, and the payload is
# nowhere near its own size by the time it gets there: agent_run_ps sends the
# script as -EncodedCommand, so it is UTF-16'd (x2) then base64'd (x4/3). That
# is 2.667x on the whole script, which is this payload's base64 plus about 200
# characters of wrapper, so the real budget is roughly 32767 / 2.667 = 12280
# script characters: about 9 KiB of payload.
#
# Measured through write_guest_file on a live guest: 8192 bytes works, 12288
# fails. Going over does not fail usefully either -- the oversized exec is
# refused, agent_run_ps returns None, and the caller is told "the guest agent
# did not answer", which reads like a rebooting VM.
GUEST_WRITE_CHUNK = 8 * 1024
# Payload per agent file-write call. PVE caps the content parameter at 61440
# characters; with encode=0 that is our own base64, so 61440 * 3/4 of payload.
GUEST_FW_CHUNK = 45 * 1024              # = 46080, exactly the 61440-char cap


def _guest_ps(vmid, script, timeout=180):
    """Run PowerShell in a managed sandbox and insist on an answer.

    ProgressPreference is silenced because the agent hands back PowerShell's
    CLIXML progress stream alongside stdout, and that stream is full of
    base64-alphabet characters -- which a lenient b64decode will happily
    absorb into the payload.
    """
    _check_managed(vmid)
    out = agent_run_ps(vmid, "$ProgressPreference='SilentlyContinue'\n" + script,
                       timeout=timeout)
    if out is None:
        raise RuntimeError(
            "the guest agent did not answer. The VM may be rebooting, or off. "
            "This channel needs qemu-guest-agent, which is the one thing that "
            "survives when Deskhand does not.")
    return out


def guest_browse(vmid, path="C:\\"):
    """List a directory. Directories first, then files, both by name."""
    script = (
        "$ErrorActionPreference='Stop'\n"
        "$p = %s\n"
        "if (-not (Test-Path -LiteralPath $p)) { Write-Output 'ERR|not found'; exit }\n"
        "$items = Get-ChildItem -LiteralPath $p -Force -ErrorAction SilentlyContinue |\n"
        "  Sort-Object @{e={-not $_.PSIsContainer}}, Name |\n"
        "  Select-Object -First 2000\n"
        "foreach ($i in $items) {\n"
        "  $kind = if ($i.PSIsContainer) { 'dir' } else { 'file' }\n"
        "  $size = if ($i.PSIsContainer) { 0 } else { $i.Length }\n"
        "  Write-Output ($kind + '|' + $size + '|' + $i.LastWriteTimeUtc.ToString('s') + '|' + $i.Name)\n"
        "}\n" % _ps_literal(path))
    out = _guest_ps(vmid, script)
    if out.strip().startswith("ERR|"):
        raise RuntimeError("path not found: " + path)
    entries = []
    for line in out.splitlines():
        bits = line.strip().split("|", 3)
        if len(bits) == 4 and bits[0] in ("dir", "file"):
            entries.append({"kind": bits[0], "size": int(bits[1] or 0),
                            "modified": bits[2], "name": bits[3]})
    return {"path": path, "entries": entries, "count": len(entries)}


def guest_read(vmid, path):
    """Read a file as text. Binary comes back base64 with a flag."""
    script = (
        "$ErrorActionPreference='Stop'\n"
        "$p = %s\n"
        "if (-not (Test-Path -LiteralPath $p)) { Write-Output 'ERR|not found'; exit }\n"
        "$len = (Get-Item -LiteralPath $p).Length\n"
        "if ($len -gt %d) { Write-Output ('ERR|too large: ' + $len + ' bytes'); exit }\n"
        "$b = [IO.File]::ReadAllBytes($p)\n"
        "Write-Output ('OK|' + $len + '|' + [Convert]::ToBase64String($b))\n"
        % (_ps_literal(path), GUEST_READ_MAX))
    out = _guest_ps(vmid, script, timeout=300)
    line = _marked_line(out)
    if line.startswith("ERR|"):
        raise RuntimeError(line.split("|", 1)[1] + " (" + path + ")")
    _, size, b64 = line.split("|", 2)
    # validate=True: anything that is not base64 is a bug to surface, not
    # noise to quietly absorb.
    raw = base64.b64decode(b64.strip(), validate=True)
    try:
        return {"path": path, "size": int(size), "text": raw.decode("utf-8")}
    except UnicodeDecodeError:
        return {"path": path, "size": int(size), "binary": True,
                "base64": base64.b64encode(raw).decode()}


def _fw(vmid, path, blob):
    """One agent file-write. encode=0 so the agent writes our base64 verbatim.

    Raises on anything at all, so the caller can fall back to the exec path
    rather than this becoming the only way to write a file.
    """
    vm("/agent/file-write", "POST", vmid=vmid, timeout=120, data=[
        ("file", path), ("encode", 0),
        ("content", base64.b64encode(blob).decode())])


def _guest_write_fast(vmid, path, blob, append):
    """Write via the guest agent's file-write, or raise so the caller falls back.

    Parts are zero-padded because they are joined in name order, and 'p-10'
    sorts before 'p-2'.
    """
    tmp = path + ".sbxpart"
    if len(blob) <= GUEST_FW_CHUNK:
        _fw(vmid, tmp, blob)
    else:
        part_dir = path + ".sbxparts"
        _guest_ps(vmid,
                  "$ErrorActionPreference='Stop'\n"
                  "$d = %s\n"
                  "if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force }\n"
                  "New-Item -ItemType Directory -Path $d | Out-Null\n"
                  "Write-Output 'OK'" % _ps_literal(part_dir), timeout=120)
        n = 0
        for off in range(0, len(blob), GUEST_FW_CHUNK):
            _fw(vmid, "%s\\p-%06d" % (part_dir, n), blob[off:off + GUEST_FW_CHUNK])
            n += 1
        # One exec to join them, whatever the file's size.
        out = _guest_ps(vmid,
                        "$ErrorActionPreference='Stop'\n"
                        "$d = %s; $t = %s\n"
                        "$fs = [IO.File]::Open($t, 'Create', 'Write')\n"
                        "Get-ChildItem -LiteralPath $d -Filter 'p-*' | Sort-Object Name | "
                        "ForEach-Object { $b = [IO.File]::ReadAllBytes($_.FullName); "
                        "$fs.Write($b, 0, $b.Length) }\n"
                        "$fs.Close()\n"
                        "Remove-Item -LiteralPath $d -Recurse -Force\n"
                        "Write-Output ('OK|' + (Get-Item -LiteralPath $t).Length)"
                        % (_ps_literal(part_dir), _ps_literal(tmp)), timeout=300)
        line = _marked_line(out)
        if int(line.split("|")[1]) != len(blob):
            raise RuntimeError("joined parts came to the wrong length")
    return _guest_place(vmid, path, tmp, append, len(blob))


def _guest_place(vmid, path, tmp, append, written):
    """Move the staged file into place, so a failure leaves the original alone."""
    script = (
        "$ErrorActionPreference='Stop'\n"
        "$t = %s; $p = %s\n"
        "if (%s) { Get-Content -LiteralPath $t -Raw | Add-Content -LiteralPath $p -NoNewline; "
        "Remove-Item -LiteralPath $t }\n"
        "else { Move-Item -LiteralPath $t -Destination $p -Force }\n"
        "Write-Output ('OK|' + (Get-Item -LiteralPath $p).Length)\n"
        % (_ps_literal(tmp), _ps_literal(path), "$true" if append else "$false"))
    line = _marked_line(_guest_ps(vmid, script, timeout=180))
    if not line.startswith("OK|"):
        raise RuntimeError("could not place the file: " + line[:120])
    return {"path": path, "written": written, "size_on_disk": int(line.split("|")[1])}


def guest_write(vmid, path, text=None, content_base64=None, append=False):
    """Write a file, in chunks, and verify the length afterwards."""
    if content_base64:
        blob = base64.b64decode(content_base64)
    elif text is not None:
        blob = text.encode("utf-8")
    else:
        raise ValueError("pass text or content_base64")

    # Preferred path: content in the request body rather than a command line.
    # Falls back rather than failing, because an old PVE or a tightened token
    # should cost throughput, not the ability to write a file at all.
    try:
        return _guest_write_fast(vmid, path, blob, append)
    except Exception as exc:                          # noqa: BLE001
        print(f"guest_write: file-write path unavailable on {vmid} ({exc}); "
              "falling back to exec chunks", flush=True)

    tmp = path + ".sbxpart"
    first = True
    for off in range(0, len(blob) or 1, GUEST_WRITE_CHUNK):
        part = base64.b64encode(blob[off:off + GUEST_WRITE_CHUNK]).decode()
        mode = "Create" if first else "Append"
        script = (
            "$ErrorActionPreference='Stop'\n"
            "$d = [Convert]::FromBase64String('%s')\n"
            "$fs = [IO.File]::Open(%s, [IO.FileMode]::%s, [IO.FileAccess]::Write)\n"
            "$fs.Write($d, 0, $d.Length); $fs.Close()\n"
            "Write-Output 'OK'\n" % (part, _ps_literal(tmp), mode))
        if _marked_line(_guest_ps(vmid, script, timeout=120), ("OK",)) != "OK":
            raise RuntimeError("chunk write failed at offset %d" % off)
        first = False

    # Swap into place only once every chunk landed, so a failure part-way
    # through leaves the original file untouched.
    script = (
        "$ErrorActionPreference='Stop'\n"
        "$t = %s; $p = %s\n"
        "$n = (Get-Item -LiteralPath $t).Length\n"
        "if (%s) { Get-Content -LiteralPath $t -Raw | Add-Content -LiteralPath $p -NoNewline; Remove-Item -LiteralPath $t }\n"
        "else { Move-Item -LiteralPath $t -Destination $p -Force }\n"
        "Write-Output ('OK|' + (Get-Item -LiteralPath $p).Length)\n"
        % (_ps_literal(tmp), _ps_literal(path), "$true" if append else "$false"))
    line = _marked_line(_guest_ps(vmid, script, timeout=120))
    if not line.startswith("OK|"):
        raise RuntimeError("could not place the file: " + line[:120])
    return {"path": path, "written": len(blob), "size_on_disk": int(line.split("|")[1])}


def _marked_line(out, prefixes=("OK|", "ERR|")):
    """Pull our own marked line out of whatever else the channel returned.

    The guest agent merges PowerShell's other streams into the reply, so the
    payload has to identify itself rather than be assumed to be the whole of
    stdout.
    """
    for line in (out or "").splitlines():
        line = line.strip()
        if any(line.startswith(p) for p in prefixes) or line in prefixes:
            return line
    raise RuntimeError("no result line in the guest reply: " + (out or "")[:160])


def _ps_literal(s):
    """A PowerShell single-quoted string. Doubling the quote is the whole escape
    rule there, which is why nothing else needs encoding."""
    return "'" + str(s).replace("'", "''") + "'"


def _vmid_for_name(name):
    """Map a proxied tool's sandbox prefix back to its vmid, quietly."""
    try:
        for s in list_sandboxes():
            if s.get("name") == name:
                return s.get("vmid")
    except Exception:                                 # noqa: BLE001
        pass
    return None


def _check_managed(vmid):
    """Two independent gates before any destructive call.

    The Proxmox token already cannot touch a guest outside the pool, but the app
    refuses too: defence in depth, and it produces a clear error instead of a 403
    from somewhere deeper.
    """
    vmid = int(vmid)
    if not (ID_LO <= vmid <= ID_HI):
        raise RuntimeError(f"VM {vmid} is outside the sandbox range {ID_LO}-{ID_HI}; refusing")
    members = {m["vmid"] for m in (api(f"/pools/{POOL}").get("members") or []) if m.get("type") == "qemu"}
    if vmid not in members:
        raise RuntimeError(f"VM {vmid} is not in the '{POOL}' pool; refusing")
    return vmid


def do_repair(job, vmid, opts=None):
    """Finish a sandbox whose build was interrupted.

    Re-runs the post-clone provisioning: wait for OOBE, apply auto-logon, reboot,
    install Deskhand. Safe to run on an already-complete sandbox -- it just
    reinstalls Deskhand with a fresh token.
    """
    vmid = _check_managed(vmid)
    opts = opts or {}
    opts.setdefault("cores", 4)
    opts.setdefault("memory", 8192)
    opts.setdefault("port", 8791)
    opts.setdefault("shell", True)
    opts.setdefault("tls", False)
    job.log(f"repairing sandbox {vmid}")
    provision(job, vmid, opts, configure_hw=False)



# The agent runs INSIDE the sandbox, so it needs no route back to the
# controller -- and could not reach it anyway, since the control port is
# firewalled off from the sandbox subnet. What it does get is the sandbox's own
# Deskhand as an MCP server, which lets it drive the desktop it is sitting on.
AGENTS_PS = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# C:\Users\Public, not %LOCALAPPDATA%: this script runs unelevated as the
# sandbox user, while the controller reads the log back through the guest
# agent, which is SYSTEM. The drive root is not writable by either.
$log = 'C:\Users\Public\sandboxctl-agents.log'
try { Start-Transcript -Path $log -Force | Out-Null } catch { }
try {

$want = '@@AGENTS@@'.Split(',') | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ }
$cfg  = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('@@CFG@@')) | ConvertFrom-Json

function Set-UserEnv($n, $v) {
    [Environment]::SetEnvironmentVariable($n, $v, 'User')
    Set-Item -Path ('Env:' + $n) -Value $v
}

# Both agents read provider credentials from the environment, under the same
# names, so this is set once rather than per agent. A local inference server
# often needs no key at all, hence the emptiness check rather than a default.
if ($cfg.api_keys) {
    foreach ($k in $cfg.api_keys.PSObject.Properties) {
        if ($k.Value) { Set-UserEnv $k.Name $k.Value }
    }
}
if ($cfg.base_url) {
    # The OpenAI-compatible convention, understood by both agents and by most
    # tools that speak to a local llama.cpp / vLLM / Ollama / LM Studio server.
    Set-UserEnv 'OPENAI_BASE_URL' $cfg.base_url
    if (-not $cfg.api_key) { Set-UserEnv 'OPENAI_API_KEY' 'not-needed' }
}
if ($cfg.api_key) { Set-UserEnv 'OPENAI_API_KEY' $cfg.api_key }

# Deskhand binds to the machine's own IPv4 and never to loopback -- see its
# launcher -- so a 127.0.0.1 URL is refused outright. Resolve the same address
# its launcher picks, here rather than on the controller, so the entry stays
# correct whatever address this clone was leased.
if ($cfg.deskhand -and $cfg.deskhand.token) {
    $dip = (Get-NetIPAddress -AddressFamily IPv4 |
            Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
            Select-Object -First 1).IPAddress
    if ($dip) {
        $durl = 'http://' + $dip + ':' + $cfg.deskhand.port + '/mcp?token=' + $cfg.deskhand.token
        if (-not $cfg.mcp) {
            $cfg | Add-Member -NotePropertyName mcp -NotePropertyValue ([pscustomobject]@{}) -Force
        }
        $cfg.mcp | Add-Member -NotePropertyName deskhand `
                   -NotePropertyValue ([pscustomobject]@{ url = $durl }) -Force
        Write-Output ('  deskhand mcp -> http://' + $dip + ':' + $cfg.deskhand.port + '/mcp')
    } else {
        Write-Output '  no usable IPv4; skipping the deskhand mcp entry'
    }
}

# ---------------------------------------------------------------- Hermes ---
if ($want -contains 'hermes') {
    $hh  = Join-Path $env:LOCALAPPDATA 'hermes'
    $exe = Join-Path $hh 'bin\hermes.exe'
    $freshInstall = -not (Test-Path $exe)
    if (-not (Test-Path $exe)) {
        # Brings its own git, python and node; user-scoped, so no elevation.
        $src = Invoke-RestMethod 'https://hermes-agent.nousresearch.com/install.ps1'
        & ([scriptblock]::Create($src)) -SkipSetup -SkipComputerUse
    }
    if (-not (Test-Path $exe)) { throw 'hermes.exe missing after install' }

    # Secrets go in .env, which is the documented precedence path; config.yaml
    # is for behaviour, not credentials.
    $envLines = @()
    if ($cfg.api_keys) {
        foreach ($k in $cfg.api_keys.PSObject.Properties) {
            if ($k.Value) { $envLines += ($k.Name + '=' + $k.Value) }
        }
    }
    if ($cfg.api_key) { $envLines += ('OPENAI_API_KEY=' + $cfg.api_key) }
    if ($envLines.Count) { Set-Content (Join-Path $hh '.env') -Value $envLines -Encoding UTF8 }

    # 'custom' is Hermes's own name for any OpenAI-compatible endpoint;
    # ollama/vllm/llamacpp are documented aliases for the same thing.
    if ($cfg.base_url) {
        & $exe config set model.provider 'custom' 2>&1 | Out-Null
        & $exe config set model.base_url $cfg.base_url 2>&1 | Out-Null
        if ($cfg.api_key) { & $exe config set model.api_key $cfg.api_key 2>&1 | Out-Null }
        Write-Output ('  hermes -> ' + $cfg.base_url)
    }
    # 'model.default', not 'model.name'.
    if ($cfg.hermes -and $cfg.hermes.model) {
        & $exe config set model.default $cfg.hermes.model 2>&1 | Out-Null
        Write-Output ('  hermes model ' + $cfg.hermes.model)
    }
    if ($cfg.hermes -and $cfg.hermes.context_length) {
        & $exe config set model.context_length ([string]$cfg.hermes.context_length) 2>&1 | Out-Null
        Write-Output ('  context_length ' + $cfg.hermes.context_length)
    }
    if ($cfg.hermes -and $cfg.hermes.mcp_result_size_chars) {
        & $exe config set tool_budget.mcp_result_size_chars ([string]$cfg.hermes.mcp_result_size_chars) 2>&1 | Out-Null
        Write-Output ('  mcp result cap ' + $cfg.hermes.mcp_result_size_chars + ' chars')
    }

    # Half of Deskhand is screenshots -- capture_screen, capture_window,
    # capture_region, the OCR tools. Hermes will not hand a tool-returned image
    # to the model unless it believes the model takes images AND is told to pass
    # them through natively; without both, those calls fail rather than degrade.
    # Auto-detection cannot see this for a custom OpenAI-compatible endpoint,
    # so it is stated explicitly.
    if ($cfg.hermes -and $cfg.hermes.supports_vision) {
        & $exe config set model.supports_vision 'true' 2>&1 | Out-Null
        & $exe config set agent.image_input_mode ($cfg.hermes.image_input_mode) 2>&1 | Out-Null
        Write-Output ('  vision on, image_input_mode ' + $cfg.hermes.image_input_mode)
    }

    if ($cfg.mcp) {
        # Deliberately NOT 'hermes mcp add': it asks whether the server needs
        # authentication and blocks forever with no console attached. 'config
        # set' writes the same entry and never prompts.
        foreach ($m in $cfg.mcp.PSObject.Properties) {
            $k = 'mcp_servers.' + $m.Name
            try {
                & $exe config set ($k + '.url') $m.Value.url 2>&1 | Out-Null
                & $exe config set ($k + '.enabled') 'true' 2>&1 | Out-Null
                & $exe config set ($k + '.connect_timeout') '180' 2>&1 | Out-Null
                Write-Output ('  mcp ' + $m.Name + ' configured')
            } catch {
                Write-Output ('  mcp ' + $m.Name + ' failed: ' + $_.Exception.Message)
            }
        }
    }

    # Hermes ships 16 toolsets on by default, 36 KB of schema before Deskhand
    # adds its own. Inside a sandbox most of them are noise -- and on a small
    # local model the schemas alone can exceed the whole context window. file,
    # terminal and code_execution are kept: here they act on the sandbox, which
    # is the point.
    # Enable BEFORE disabling, and state both lists. 'tools disable' only ever
    # removes, so dropping a name from the off-list does not switch it back on --
    # the toolset stays however a previous run left it. Declaring the keep-list
    # makes the result the same whatever state the sandbox was already in.
    if ($cfg.hermes -and $cfg.hermes.enable_toolsets) {
        try {
            & $exe tools enable @($cfg.hermes.enable_toolsets) 2>&1 | Out-Null
            Write-Output ('  toolsets on: ' + ((@($cfg.hermes.enable_toolsets)) -join ' '))
        } catch { Write-Output ('  could not enable toolsets: ' + $_.Exception.Message) }
    }
    if ($cfg.hermes -and $cfg.hermes.disable_toolsets) {
        $off = @($cfg.hermes.disable_toolsets) -join ' '
        if ($off) {
            try {
                & $exe tools disable @($cfg.hermes.disable_toolsets) 2>&1 | Out-Null
                Write-Output ('  toolsets off: ' + $off)
            } catch { Write-Output ('  could not disable toolsets: ' + $_.Exception.Message) }
        }
    }

    # The dashboard as a logon task, so it survives reboots. A non-loopback
    # bind always demands an auth provider, so basic auth is not optional.
    if ($cfg.dashboard_password) {
        $runner = Join-Path $hh 'run-dashboard.ps1'
        $dash = @'
$ip = (Get-NetIPAddress -AddressFamily IPv4 |
       Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
       Select-Object -First 1).IPAddress
$env:HERMES_DASHBOARD_BASIC_AUTH_USERNAME = '__USER__'
$env:HERMES_DASHBOARD_BASIC_AUTH_PASSWORD = '__PASS__'
& "$env:LOCALAPPDATA\hermes\bin\hermes.exe" dashboard --host $ip --port __PORT__ --no-open
'@
        $dash = $dash.Replace('__USER__', '@@WINUSER@@').Replace('__PASS__', $cfg.dashboard_password).Replace('__PORT__', '@@DASHPORT@@')
        $prev = if (Test-Path $runner) { (Get-Content $runner -Raw) } else { '' }
        $runnerChanged = ($prev.Trim() -ne $dash.Trim())
        Set-Content $runner -Value $dash -Encoding UTF8
        $da = New-ScheduledTaskAction -Execute 'powershell.exe' `
              -Argument ('-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $runner + '"')
        $dt = New-ScheduledTaskTrigger -AtLogOn -User '@@WINUSER@@'
        # A keepalive trigger, not just a restart-on-failure policy. The
        # dashboard has been observed dying with STATUS_CONTROL_C_EXIT -- a
        # console-control kill rather than a fault -- and the failure policy did
        # not bring it back. A trigger that simply fires every five minutes does,
        # because MultipleInstances=IgnoreNew makes the firing a no-op whenever
        # the dashboard is already running. Cheap, and it cannot get stuck.
        # Ten years rather than TimeSpan::MaxValue -- the scheduler rejects the
        # latter outright with "task XML contains a value which is incorrectly
        # formatted or out of range".
        $rep = New-ScheduledTaskTrigger -Once -At (Get-Date) `
               -RepetitionInterval (New-TimeSpan -Minutes 5) `
               -RepetitionDuration (New-TimeSpan -Days 3650)
        $dp = New-ScheduledTaskPrincipal -UserId '@@WINUSER@@' -LogonType Interactive -RunLevel Limited
        # It is a server, so no execution time limit.
        $ds = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
              -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew `
              -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
        Register-ScheduledTask -TaskName 'HermesDashboard' -Action $da -Trigger @($dt, $rep) `
              -Principal $dp -Settings $ds -Force | Out-Null

        # Restarting the dashboard drops whatever browser session is attached
        # to it: the websocket closes 1006 and the server reaps the client,
        # INTERRUPTING any turn in flight. So only restart when there is a
        # reason to -- a fresh install, changed launcher contents, or nothing
        # listening. Reconfiguring an already-running sandbox now leaves the
        # open session alone; the new settings apply to sessions started after.
        $listening = [bool](Get-NetTCPConnection -State Listen -LocalPort @@DASHPORT@@ -ErrorAction SilentlyContinue)
        $needsRestart = ($freshInstall -or $runnerChanged -or -not $listening)

        if (-not $needsRestart) {
            Write-Output '  dashboard already running and unchanged; left alone'
        } else {
        # Stop the previous instance and WAIT for the scheduler to agree it has
        # stopped. Start-ScheduledTask against a task the scheduler still counts
        # as Running is silently ignored -- so killing the process and starting
        # in the same breath took the dashboard down and never brought it back.
        Stop-ScheduledTask -TaskName 'HermesDashboard' -ErrorAction SilentlyContinue
        # Only the dashboard's own process. 'Get-Process hermes | Stop-Process'
        # also killed any agent run in flight, which is how an install could
        # terminate the very turn that requested it.
        Get-CimInstance Win32_Process -Filter "Name='hermes.exe'" -ErrorAction SilentlyContinue |
            Where-Object { $_.CommandLine -like '*dashboard*' } |
            ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        $stopBy = (Get-Date).AddSeconds(30)
        while ((Get-ScheduledTask -TaskName 'HermesDashboard').State -eq 'Running' -and (Get-Date) -lt $stopBy) {
            Start-Sleep -Seconds 2
        }
        # The dashboard spawns a backend child whose command line does NOT say
        # 'dashboard', so killing by name orphans it still holding the port.
        # Hermes then refuses every later start with BACKEND_PORT_IN_USE while
        # nothing actually serves -- a dead dashboard that looks like a running
        # one. Kill whoever owns the port, and wait for it to be free.
        Get-NetTCPConnection -State Listen -LocalPort @@DASHPORT@@ -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty OwningProcess -Unique |
            ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }
        $freeBy = (Get-Date).AddSeconds(30)
        while ((Get-NetTCPConnection -State Listen -LocalPort @@DASHPORT@@ -ErrorAction SilentlyContinue) `
               -and (Get-Date) -lt $freeBy) {
            Start-Sleep -Seconds 2
        }
        Start-ScheduledTask -TaskName 'HermesDashboard'

        # Report what happened, not that a start was requested. The first run
        # builds the web UI, so allow a couple of minutes.
        $up = $false
        for ($i = 0; $i -lt 24; $i++) {
            Start-Sleep -Seconds 5
            if (Get-NetTCPConnection -State Listen -LocalPort @@DASHPORT@@ -ErrorAction SilentlyContinue) {
                $up = $true; break
            }
        }
        if ($up) { Write-Output '  dashboard listening on @@DASHPORT@@' }
        else { Write-Output '  WARNING: dashboard did not bind @@DASHPORT@@ within two minutes' }
        }
    }
    Write-Output 'HERMES-OK'
}

# -------------------------------------------------------------- opencode ---
if ($want -contains 'opencode') {
    # The published installer is a bash script, so it is no use here. The
    # release ships a plain Windows zip: extract it and there is nothing to
    # build and no node to install.
    $dir = Join-Path $env:LOCALAPPDATA 'opencode'
    $zip = Join-Path $env:TEMP 'opencode.zip'
    $rel = Invoke-RestMethod 'https://api.github.com/repos/sst/opencode/releases/latest' `
             -Headers @{ 'User-Agent' = 'sandboxctl' }
    $asset = $rel.assets | Where-Object { $_.name -eq 'opencode-windows-x64.zip' } | Select-Object -First 1
    if (-not $asset) {
        $asset = $rel.assets | Where-Object { $_.name -like 'opencode-windows-x64*.zip' } | Select-Object -First 1
    }
    if (-not $asset) { throw 'no opencode windows x64 zip in the latest release' }
    Invoke-WebRequest $asset.browser_download_url -OutFile $zip -UseBasicParsing
    if (Test-Path $dir) { Remove-Item $dir -Recurse -Force }
    Expand-Archive -Path $zip -DestinationPath $dir -Force
    Remove-Item $zip -Force -ErrorAction SilentlyContinue
    $oc = Get-ChildItem $dir -Recurse -Filter opencode.exe | Select-Object -First 1
    if (-not $oc) { throw 'opencode.exe missing from the zip' }

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not $userPath) { $userPath = '' }
    if ($userPath -notlike ('*' + $oc.DirectoryName + '*')) {
        [Environment]::SetEnvironmentVariable(
            'Path', ($userPath.TrimEnd(';') + ';' + $oc.DirectoryName).TrimStart(';'), 'User')
    }

    $ocDir = Join-Path $env:USERPROFILE '.config\opencode'
    New-Item -ItemType Directory -Path $ocDir -Force | Out-Null
    $conf = [ordered]@{ '$schema' = 'https://opencode.ai/config.json' }
    if ($cfg.base_url) {
        # An OpenAI-compatible endpoint is expressed as a provider whose SDK
        # package is the openai-compatible one, with the URL in options.
        $opts = [ordered]@{ baseURL = $cfg.base_url }
        if ($cfg.api_key) { $opts['apiKey'] = $cfg.api_key } else { $opts['apiKey'] = 'not-needed' }
        $models = [ordered]@{}
        if ($cfg.opencode -and $cfg.opencode.model) { $models[$cfg.opencode.model] = [ordered]@{} }
        $conf['provider'] = [ordered]@{
            local = [ordered]@{
                npm     = '@ai-sdk/openai-compatible'
                name    = 'local'
                options = $opts
                models  = $models
            }
        }
        if ($cfg.opencode -and $cfg.opencode.model) { $conf['model'] = 'local/' + $cfg.opencode.model }
    } elseif ($cfg.opencode -and $cfg.opencode.model) {
        $conf['model'] = $cfg.opencode.model
    }
    if ($cfg.mcp) {
        $servers = [ordered]@{}
        foreach ($m in $cfg.mcp.PSObject.Properties) {
            $servers[$m.Name] = [ordered]@{ type = 'remote'; url = $m.Value.url; enabled = $true }
        }
        if ($servers.Count) { $conf['mcp'] = $servers }
    }
    ($conf | ConvertTo-Json -Depth 8) | Set-Content (Join-Path $ocDir 'opencode.json') -Encoding UTF8
    Write-Output 'OPENCODE-OK'
}

Write-Output 'AGENTS-INSTALLED'
} catch {
    Write-Output ('AGENTS-FAILED: ' + $_.Exception.Message)
}
try { Stop-Transcript | Out-Null } catch { }
"""

def run_install(job, vmid, script, _retried=False):
    r"""Run the install script, rebooting once if C:\Deskhand is held open.

    A stale handle can outlive everything the script is able to kill: a leaked
    guest-agent handle belongs to qemu-ga.exe, and the script cannot stop that
    without cutting the channel it is running over. A reboot is the only thing
    that clears one, and on a disposable sandbox it is cheap. Once, not in a
    loop -- if it is still locked after a fresh boot then something real is
    wrong, and the error should surface rather than spin.
    """
    out = agent_run_ps(vmid, script, timeout=900) or ""
    if "INSTALLED" in out:
        return
    if not _retried and "still holds a file open" in out:
        job.log("C:\\Deskhand is locked by a stale handle; rebooting once, then retrying")
        vm("/status/reboot", "POST", vmid=vmid)
        time.sleep(25)
        wait_agent(vmid)
        time.sleep(30)          # let auto-logon land: the logon task needs a session
        job.log("back up; reinstalling")
        return run_install(job, vmid, script, _retried=True)
    raise RuntimeError(f"update failed: {out[:300]}")


def do_update(job, vmid):
    """Reinstall Deskhand on a running sandbox, keeping its existing settings.

    Reuses the install path rather than a separate update script, so zip and MSI
    installs cannot drift apart. The token is read back out of the launcher and
    reapplied -- changing it would silently break any MCP client already pointed
    at this sandbox.
    """
    vmid = _check_managed(vmid)
    if (vm("/status/current", vmid=vmid) or {}).get("status") != "running":
        raise RuntimeError("sandbox must be running to update it")

    cur = read_launcher(vmid, timeout=120)
    if "DESKHAND_TOKEN" not in cur:
        raise RuntimeError("Deskhand is not installed on this sandbox; use repair_sandbox instead")

    m = re.search(r"DESKHAND_TOKEN\s*=\s*'([^']+)'", cur)
    if not m:
        raise RuntimeError("could not read the existing token; use repair_sandbox instead")
    token = m.group(1)
    pm = re.search(r"DESKHAND_PORT\s*=\s*'(\d+)'", cur)
    port = int(pm.group(1)) if pm else 8791
    shell = "DESKHAND_ENABLE_SHELL" in cur
    tls = "DESKHAND_TLS" in cur
    job.log(f"preserving token/port {port} shell={shell} tls={tls}")

    kind = artifact_kind()
    if kind is None:
        raise RuntimeError("no Deskhand payload staged on the controller")
    asset = "deskhand.zip" if kind == "zip" else "Deskhand.msi"
    script = (INSTALL_PS
              .replace("@@KIND@@", kind)
              .replace("@@PAYLOAD@@", f"{SELF_URL}/payload/{asset}")
              .replace("@@TOKEN@@", token)
              .replace("@@PORT@@", str(port))
              .replace("@@SHELL_LINE@@", "`$env:DESKHAND_ENABLE_SHELL = '1'" if shell else "")
              .replace("@@TLS_LINE@@", "`$env:DESKHAND_TLS = 'self-signed'" if tls else "")
              .replace("@@USER@@", WIN_USER)
              .replace("@@TOOLCHARS@@", str(DESKHAND_TOOL_CHARS)))
    job.log(f"installing {asset}")
    run_install(job, vmid, script)
    after = read_token(vmid, refresh=True)
    job.result = {"vmid": vmid, "token_preserved": after == token}
    job.log("done" + ("" if after == token else "  WARNING: token changed"))



DASH_PORT = 9119


def prepare_guest_firewall(vmid):
    """Open the dashboard port before anything tries to listen on it.

    Windows pops a "do you want to allow this app" dialog the first time an
    unknown binary binds a socket. Nobody is there to answer it, so it sits
    modal on the desktop forever -- and dismissing it writes a BLOCK rule for
    that executable, which then beats any allow rule you add afterwards. So:
    create the allow rule first, and clear any block rule a previous prompt
    left behind. Requires elevation, which is why it runs through the guest
    agent (SYSTEM) rather than in the user-context script.
    """
    ps = (
        "Remove-NetFirewallRule -DisplayName 'Hermes Dashboard' -ErrorAction SilentlyContinue\n"
        "New-NetFirewallRule -DisplayName 'Hermes Dashboard' -Direction Inbound -Action Allow "
        "-Protocol TCP -LocalPort " + str(DASH_PORT) + " -Profile Any | Out-Null\n"
        "Get-NetFirewallRule -Direction Inbound -Action Block -EA SilentlyContinue | ForEach-Object {\n"
        "  $af = $_ | Get-NetFirewallApplicationFilter -EA SilentlyContinue\n"
        "  if ($af.Program -like '*uv*python*' -or $af.Program -like '*hermes*' -or $af.Program -like '*opencode*') {\n"
        "    Remove-NetFirewallRule -Name $_.Name -EA SilentlyContinue }\n"
        "}\n"
        "Write-Output 'FW-OK'\n"
    )
    return "FW-OK" in (agent_run_ps(vmid, ps, timeout=180) or "")


GUEST_PUBLIC = "C:" + chr(92) + "Users" + chr(92) + "Public"


def run_in_guest_as_user(job, vmid, script, timeout=2400):
    """Run a PowerShell script inside the guest as the interactive user.

    The guest agent runs as SYSTEM, so anything launched straight through it
    installs into SYSTEM's profile -- the wrong place for a per-user tool like
    Hermes, and not the session the desktop is logged into. Windows offers no
    "run as that user" verb over the agent channel, so the script is staged to
    disk and driven by a scheduled task whose principal is the sandbox account.

    The task is fire-and-forget, so completion is observed by polling a log the
    script writes to a world-readable path rather than by an exit code.
    """
    ps1 = GUEST_PUBLIC + chr(92) + "sandboxctl-agents.ps1"
    log = GUEST_PUBLIC + chr(92) + "sandboxctl-agents.log"
    # Gzipped, not plain base64. The staging script is itself delivered as a
    # -EncodedCommand, so a plain base64 payload gets encoded a second time --
    # and Windows caps a command line at 32767 characters, which this script
    # quietly exceeded once it grew. Compressing first cuts it by roughly 4x.
    blob = base64.b64encode(gzip.compress(script.encode("utf-8"))).decode()

    stage = (
        "$gz = [Convert]::FromBase64String('" + blob + "')\n"
        "$ms = New-Object IO.MemoryStream(,$gz)\n"
        "$gs = New-Object IO.Compression.GzipStream($ms, [IO.Compression.CompressionMode]::Decompress)\n"
        "$b = (New-Object IO.StreamReader($gs)).ReadToEnd()\n"
        "Set-Content -LiteralPath '" + ps1 + "' -Value $b -Encoding UTF8\n"
        "Remove-Item -LiteralPath '" + log + "' -Force -ErrorAction SilentlyContinue\n"
        # -WindowStyle Hidden matters more than it looks: this console is a
        # window on the very desktop the agent automates, and Deskhand's
        # send_keys goes to whatever currently has focus. An agent reaching for
        # alt+F4 to dismiss a dialog will close its own console and kill its own
        # run -- observed. A hidden console cannot take focus, so it cannot be
        # the thing that closes.
        "$a = New-ScheduledTaskAction -Execute 'powershell.exe' "
        "-Argument '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File \"" + ps1 + "\"'\n"
        "$p = New-ScheduledTaskPrincipal -UserId '" + WIN_USER + "' "
        "-LogonType Interactive -RunLevel Limited\n"
        "Register-ScheduledTask -TaskName 'SandboxctlAgents' -Action $a -Principal $p -Force | Out-Null\n"
        "Start-ScheduledTask -TaskName 'SandboxctlAgents'\n"
        "Write-Output 'STARTED'\n"
    )
    # -EncodedCommand is UTF-16 then base64, so the wire cost is ~2.7x this.
    if len(stage) * 2.8 > 30000:
        raise RuntimeError(f"staging script too large for a Windows command line ({len(stage)} chars)")
    out = agent_run_ps(vmid, stage, timeout=180) or ""
    if "STARTED" not in out:
        raise RuntimeError("could not start the in-guest task: " + (out[-300:] or "no output"))

    read = "if (Test-Path '" + log + "') { Get-Content -LiteralPath '" + log + "' -Raw } else { '' }"
    deadline = time.time() + timeout
    seen = 0
    while time.time() < deadline:
        time.sleep(20)
        text = agent_run_ps(vmid, read, timeout=120) or ""
        # Surface progress rather than sitting silent for ten minutes.
        # PowerShell writes a CLIXML progress envelope to stderr, which
        # agent_run_ps concatenates onto the output; none of it is progress.
        lines = [l.strip() for l in text.splitlines()
                 if l.strip() and not l.lstrip().startswith(("<", "#< CLIXML"))]
        if len(lines) > seen:
            seen = len(lines)
            job.log(lines[-1][:160])
        if "AGENTS-FAILED" in text:
            msg = [l for l in lines if "AGENTS-FAILED" in l]
            raise RuntimeError(msg[-1] if msg else "agent install failed")
        if "AGENTS-INSTALLED" in text:
            return text
    raise RuntimeError("agent install timed out")


AGENT_NAMES = ("hermes", "opencode")


def do_install_agents(job, vmid, agents, opts=None):
    """Install one or more AI agents inside a sandbox and configure them.

    On demand rather than at creation: Hermes alone is a ~2 GB install and most
    sandboxes never need one. Baking them into the template would make this
    instant, at the cost of a much larger image for every sandbox.
    """
    opts = opts or {}
    vmid = _check_managed(vmid)
    if (vm("/status/current", vmid=vmid) or {}).get("status") != "running":
        raise RuntimeError("sandbox must be running to install agents")

    wanted = [a.strip().lower() for a in (agents or []) if str(a).strip()]
    unknown = [a for a in wanted if a not in AGENT_NAMES]
    if unknown:
        raise RuntimeError(f"unknown agent(s): {', '.join(unknown)}")
    if not wanted:
        raise RuntimeError("pick at least one agent")

    defaults = AGENTS_CFG
    base_url = (opts.get("base_url") or defaults.get("base_url") or "").strip()
    api_key = (opts.get("api_key") or defaults.get("api_key") or "").strip()
    # Overridable: set agents.hermes.disable_toolsets to [] to keep them all.
    DEFAULT_OFF = ["web", "browser", "image_gen", "tts", "video", "video_gen",
                   "x_search", "stt", "homeassistant", "spotify", "yuanbao",
                   "delegation", "cronjob", "session_search", "skills", "memory",
                   "todo", "clarify"]
    # 'vision' stays ON: Deskhand is a screenshot-heavy toolset, and at ~845
    # bytes of schema it is the cheapest entry on the list to keep.
    cfg = {
        "api_keys": dict(defaults.get("api_keys") or {}),
        "hermes": dict(defaults.get("hermes") or {}),
        "opencode": dict(defaults.get("opencode") or {}),
        "mcp": dict(defaults.get("mcp") or {}),
        "base_url": base_url,
        "api_key": api_key,
    }
    if opts.get("model"):
        cfg["hermes"]["model"] = opts["model"]
        cfg["opencode"]["model"] = opts["model"]
    # Hermes auto-detects the window, and gets it wrong against a local server
    # whose tag pins a custom num_ctx: /v1/models advertises the model ceiling,
    # not the size it was actually loaded with. Telling it the served number
    # puts history compression at the right threshold instead of overflowing.
    ctx = 0
    if opts.get("context_length"):
        try:
            ctx = int(opts["context_length"])
            cfg["hermes"]["context_length"] = ctx
        except (TypeError, ValueError):
            ctx = 0

    # Hermes caps a single MCP tool result at 50k characters and, unlike its
    # built-in tools, does NOT scale that to the context window -- so on a 262k
    # model a large UI tree comes back truncated to a 1.5k preview while most of
    # the window sits unused. Deskhand IS the toolset here, so raise it, using
    # the same fraction Hermes applies to its own tools (0.15 of the window,
    # 4 chars per token) and the same 8k floor.
    override = (defaults.get("hermes") or {}).get("mcp_result_size_chars")
    if override:
        cfg["hermes"]["mcp_result_size_chars"] = int(override)
    elif ctx:
        cfg["hermes"]["mcp_result_size_chars"] = max(8_000, min(150_000, int(ctx * 4 * 0.15)))
    cfg["hermes"].setdefault("disable_toolsets", DEFAULT_OFF)
    # Deskhand is a screenshot-heavy toolset, so default this on. Set
    # agents.hermes.supports_vision to false for a text-only model.
    cfg["hermes"].setdefault("enable_toolsets",
                             ["file", "terminal", "code_execution", "vision"])
    cfg["hermes"].setdefault("supports_vision", True)
    cfg["hermes"].setdefault("image_input_mode", "native")

    if base_url:
        job.log(f"inference endpoint {base_url}" + ("" if api_key else " (no key)"))
    elif not any(cfg["api_keys"].values()):
        job.log("WARNING: no endpoint and no api_keys; the agent installs unconfigured")

    # Point the agent at the Deskhand on its own machine. Deskhand accepts the
    # token as a query parameter, so this needs no header support from either
    # agent -- and 127.0.0.1 keeps it off the wire entirely.
    launcher = read_launcher(vmid, timeout=120)
    m = re.search(r"DESKHAND_TOKEN\s*=\s*'([^']+)'", launcher)
    pm = re.search(r"DESKHAND_PORT\s*=\s*'(\d+)'", launcher)
    if m:
        # Only the port and token travel; the guest resolves the host, because
        # Deskhand listens on the machine's IPv4 rather than on loopback.
        cfg["deskhand"] = {"port": int(pm.group(1)) if pm else 8791, "token": m.group(1)}
        job.log("agents will get this sandbox's own Deskhand as an MCP server")
    else:
        job.log("no Deskhand token found; agents get no local desktop tools")

    dash_pw = ""
    if "hermes" in wanted:
        # A non-loopback bind always requires an auth provider, so every
        # sandbox gets its own dashboard password rather than a shared default.
        prev = (load_agent_state().get(str(vmid)) or {}).get("dashboard_password")
        dash_pw = prev or "".join(
            secrets.choice(string.ascii_letters + string.digits) for _ in range(20))
        cfg["dashboard_password"] = dash_pw
        if not prepare_guest_firewall(vmid):
            job.log("WARNING: could not pre-open the dashboard port")

    blob = base64.b64encode(json.dumps(cfg).encode()).decode()
    script = (AGENTS_PS.replace("@@AGENTS@@", ",".join(wanted))
                       .replace("@@CFG@@", blob)
                       .replace("@@WINUSER@@", WIN_USER)
                       .replace("@@DASHPORT@@", str(DASH_PORT)))
    job.log(f"installing {', '.join(wanted)} as {WIN_USER} (several minutes)")
    out = run_in_guest_as_user(job, vmid, script, timeout=2400)

    done = [a for a in wanted if f"{a.upper()}-OK" in out]
    prev = load_agent_state().get(str(vmid)) or {}
    state = {
        "installed": sorted(set((prev.get("installed") or []) + done)),
        "base_url": base_url,
        "model": opts.get("model") or "",
    }
    if dash_pw:
        state["dashboard_password"] = dash_pw
        state["dashboard_port"] = DASH_PORT
        state["dashboard_user"] = WIN_USER
    set_agent_state(vmid, state)

    job.result = {"vmid": vmid, "installed": done,
                  "log": GUEST_PUBLIC + chr(92) + "sandboxctl-agents.log"}
    if dash_pw and "hermes" in done:
        job.log(f"Hermes dashboard: user {WIN_USER} / password {dash_pw}")
    job.log("installed: " + (", ".join(done) or "none"))


# --------------------------------------------------------------------------
# Fetching a Deskhand build from GitHub releases
# --------------------------------------------------------------------------
# The alternative is somebody scp-ing a zip here by hand, which means a human in
# the loop for every Deskhand release. This pulls a published release instead.
#
# Note what the project's CI actually publishes on a tag: Deskhand.msi,
# Deskhand.msix and a dev cert -- NOT the self-contained zip. The raw build only
# reaches a CI artifact, which needs auth even on a public repo. So both shapes
# are supported: a .zip if one is ever published (simpler, no installer), and the
# .msi otherwise (machine-wide install under Program Files).
GH_REPO = CONFIG.get("github_repo", "guscatalano/Deskhand")


# --------------------------------------------------------------------------
# Console recording
# --------------------------------------------------------------------------
RECORDER = None
if REC_DIR:
    RECORDER = recorder.RecorderManager(
        REC_DIR, api, NODE, HOST, REC_RETENTION_DAYS,
        log=lambda m: print(m, flush=True))


_REC_WARNED = ""


def capacity():
    """How many sandboxes exist and run, against the limits.

    Read from the pool rather than from a counter this service keeps, because a
    sandbox can appear or disappear without this service doing it.
    """
    # Membership, not list_sandboxes(): counting needs a vmid and a status, and
    # the listing pays a guest round trip per uncached token to get things this
    # does not use. That made the "is there room" endpoint slowest exactly when
    # several creates were in flight.
    try:
        members = api(f"/pools/{POOL}").get("members") or []
    except Exception:                                 # noqa: BLE001
        members = []
    sb = [{"vmid": m["vmid"], "status": m.get("status")}
          for m in members
          if m.get("type") == "qemu" and not m.get("template")]
    running = [s for s in sb if s.get("status") == "running"]
    # A sandbox mid-create is neither running nor in the pool yet, so without
    # counting reservations four simultaneous creates all pass a limit that none
    # of them would pass a minute later. They are counted toward both totals
    # because each one is about to be a running sandbox.
    # Counted from JOBS itself, not from /api/jobs, which returns only the 20
    # most recent and so can report nothing running while an older job still is.
    # Anything deciding whether it is safe to restart needs the real number.
    with JOBS_LOCK:
        jobs_running = sum(1 for j in JOBS.values() if not j.done)
    with _VMID_LOCK:
        pending = set(_VMID_INFLIGHT)
    # A reserved id is in the pool once its clone lands, so count only the ones
    # the listing cannot see -- otherwise a sandbox being provisioned is counted
    # as both a member and a reservation.
    known = {s["vmid"] for s in sb}
    creating = len(pending - known)
    total = len(sb) + creating
    # Reserved-but-stopped is about to be running, so it counts toward the
    # running limit even though the listing says otherwise.
    live = len(running) + len(pending - {s["vmid"] for s in running})
    return {
        "creating": creating,
        "jobs_running": jobs_running,
        "sandboxes": total,
        "max_sandboxes": MAX_SANDBOXES,
        "sandboxes_left": max(0, MAX_SANDBOXES - total),
        "running": live,
        "max_running": MAX_RUNNING,
        "running_left": max(0, MAX_RUNNING - live),
        "id_range": [ID_LO, ID_HI],
        "note": ("Each running sandbox costs the controller roughly 180 MB for its "
                 "console recorder -- measured on warm ones, which settle higher "
                 "than the ~130 MB a freshly started one shows. That is what "
                 "max_running protects, and six of them OOM-killed a 1 GB "
                 "controller at a 1013 MB peak."),
    }


def _guard_capacity():
    """Refuse a new sandbox at the limit, before any work is started.

    Checked here rather than inside the job so the caller is told no
    immediately, instead of getting a job id that fails several seconds later.
    """
    cap = capacity()
    if cap["sandboxes"] >= MAX_SANDBOXES:
        raise RuntimeError(
            f"at the sandbox limit: {cap['sandboxes']} of {MAX_SANDBOXES} exist. "
            "Destroy one you are finished with, or raise max_sandboxes in "
            "config.json.")
    if cap["running"] >= MAX_RUNNING:
        raise RuntimeError(
            f"at the running limit: {cap['running']} of {MAX_RUNNING} are running. "
            "Each running sandbox costs the controller ~180 MB for its console "
            "recorder. Destroy or stop one, or raise max_running in config.json.")


def recorder_loop():
    """Keep recorders matched to running sandboxes, and sweep old chunks.

    Polls rather than hooking create/destroy: a sandbox can also start or stop
    outside this service (a reboot, a Proxmox-side action), and a poll notices
    that without every path having to remember to call in.
    """
    last_sweep = 0.0
    while True:
        try:
            sb = list_sandboxes()
            # The memory ceiling is per *recorder*, so it has to hold even when
            # a VM was started from the Proxmox UI rather than through here.
            # Lowest VMID first, so which ones get a recorder is stable and the
            # set does not thrash between polls.
            running = sorted((s for s in sb if s.get("status") == "running"),
                             key=lambda s: s["vmid"])
            if len(running) > MAX_RUNNING:
                dropped = running[MAX_RUNNING:]
                global _REC_WARNED
                names = ", ".join(str(s["vmid"]) for s in dropped)
                if names != _REC_WARNED:
                    print(f"recorder: {len(running)} sandboxes running but max_running is "
                          f"{MAX_RUNNING}; not recording {names}", flush=True)
                    _REC_WARNED = names
                keep = {s["vmid"] for s in running[:MAX_RUNNING]}
                sb = [s for s in sb if s.get("status") != "running" or s["vmid"] in keep]
            RECORDER.sync(sb)
            if time.time() - last_sweep > 3600:
                RECORDER.sweep()
                last_sweep = time.time()
        except Exception as exc:                          # noqa: BLE001
            print(f"recorder loop: {exc}", flush=True)
        time.sleep(60)


def fetch_models(base_url, timeout=12):
    """Ask an OpenAI-compatible endpoint what it can serve.

    Sorted loaded-first. On a box that swaps models in and out of VRAM, choosing
    one that is already resident is the difference between a reply now and a
    cold load of tens of gigabytes. Servers that do not report residency simply
    come back all-equal, which sorts alphabetically and costs nothing.
    """
    url = base_url.rstrip("/") + "/models"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = json.loads(r.read().decode("utf-8", "replace"))
    out = []
    for m in (data.get("data") or []):
        mid = m.get("id")
        if not mid:
            continue
        out.append({
            "id": mid,
            "loaded": bool(m.get("loaded")),
            "size_mb": m.get("size_mb"),
            "state": m.get("proxy_state") or "",
            # A vLLM-backed entry states its window right here; an Ollama-backed
            # one does not, and is filled in from /api/ps below.
            "ctx_loaded": m.get("context_length") or m.get("max_model_len"),
            "ctx_max": m.get("max_context_length") or m.get("max_model_len"),
        })
    # Context size is the thing that decides whether an agent works here at
    # all: ~83 Deskhand tools is roughly 8k tokens of schema before a word is
    # said. Ollama-style servers report the *served* window on /api/ps and the
    # model's ceiling on /api/tags, and the two differ -- a tag pinned to
    # num_ctx=8192 still advertises a 262144 maximum. Both are best-effort:
    # a server that offers neither simply shows no context.
    root = base_url.rstrip("/")
    if root.endswith("/v1"):
        root = root[:-3]
    loaded_ctx, max_ctx = {}, {}
    for path, sink, key in (("/api/ps", loaded_ctx, "context_length"),
                            ("/api/tags", max_ctx, None)):
        try:
            with urllib.request.urlopen(root + path, timeout=6) as r:
                for m in (json.loads(r.read().decode("utf-8", "replace")).get("models") or []):
                    n = m.get("name")
                    if not n:
                        continue
                    sink[n] = m.get(key) if key else (m.get("details") or {}).get("context_length")
        except Exception:
            pass

    for e in out:
        # Only fill what the entry did not already state.
        e["ctx_loaded"] = e.get("ctx_loaded") or loaded_ctx.get(e["id"])
        e["ctx_max"] = e.get("ctx_max") or max_ctx.get(e["id"])

    out.sort(key=lambda e: (not e["loaded"], e["id"].lower()))
    return out


def artifact_kind():
    """Which payload is currently staged: 'zip', 'msi', or None."""
    if os.path.isfile(os.path.join(HERE, "payload", "deskhand.zip")):
        return "zip"
    if os.path.isfile(os.path.join(HERE, "payload", "Deskhand.msi")):
        return "msi"
    return None


def do_fetch(job, tag=None):
    url = (f"https://api.github.com/repos/{GH_REPO}/releases/"
           + (f"tags/{tag}" if tag else "latest"))
    job.log(f"querying {url}")
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json",
                                               "User-Agent": "sandboxctl"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            rel = json.load(r)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            # By far the most common cause, and the bare 404 says nothing useful.
            raise RuntimeError(
                f"no such release in {GH_REPO}"
                + (f" (tag {tag})" if tag else " -- the repo has no published releases") +
                ". CI publishes one only on a v* tag, so:  git tag v0.1.0 && git push --tags"
            ) from None
        raise RuntimeError(f"GitHub API error {exc.code}: {exc.reason}") from None
    assets = rel.get("assets") or []
    if not assets:
        raise RuntimeError(
            f"release {rel.get('tag_name')} has no assets. "
            "If this repo has no releases yet, push a tag (git tag v0.1.0 && git push --tags) "
            "so CI publishes one.")
    job.log(f"release {rel.get('tag_name')}: " + ", ".join(a["name"] for a in assets))

    # Prefer a plain zip; fall back to the MSI the CI publishes today.
    pick = next((a for a in assets if a["name"].lower().endswith(".zip")
                 and "msix" not in a["name"].lower()), None)
    kind = "zip"
    if pick is None:
        pick = next((a for a in assets if a["name"].lower().endswith(".msi")), None)
        kind = "msi"
    if pick is None:
        raise RuntimeError("no .zip or .msi asset in that release")

    dest = os.path.join(HERE, "payload", "deskhand.zip" if kind == "zip" else "Deskhand.msi")
    tmp = dest + ".part"
    job.log(f"downloading {pick['name']} ({pick['size']/2**20:.1f} MiB)")
    dreq = urllib.request.Request(pick["browser_download_url"],
                                  headers={"User-Agent": "sandboxctl"})
    with urllib.request.urlopen(dreq, timeout=900) as r, open(tmp, "wb") as fh:
        while chunk := r.read(262144):
            fh.write(chunk)
    # Only swap in the new payload once it is fully downloaded, so an interrupted
    # fetch cannot leave sandboxes installing a truncated file.
    os.replace(tmp, dest)
    other = os.path.join(HERE, "payload", "Deskhand.msi" if kind == "zip" else "deskhand.zip")
    if os.path.isfile(other):
        os.remove(other)
    meta = {"tag": rel.get("tag_name"), "asset": pick["name"], "kind": kind,
            "size": os.path.getsize(dest), "fetched": time.strftime("%Y-%m-%d %H:%M")}
    json.dump(meta, open(os.path.join(HERE, "payload", "meta.json"), "w"))
    job.log(f"staged {os.path.basename(dest)} ({os.path.getsize(dest)/2**20:.1f} MiB)")
    job.result = meta


# --------------------------------------------------------------------------
# Proxying the sandboxes' own MCP servers
# --------------------------------------------------------------------------
# Each sandbox runs Deskhand, which is itself an MCP server with ~61 tools. So
# that only ONE server has to be registered in a client, this one re-exports
# them, namespaced per sandbox: "mybox__deskhand_click" routes to mybox.
#
# Deskhand's MCP is stateless -- no initialize handshake, no session id -- but it
# answers over SSE rather than plain JSON, so the reply arrives as a "data:" line
# that has to be unwrapped.
#
# Tool counts add up fast (61 each), so only running sandboxes are proxied and
# PROXY_MAX caps how many. Past that the dispatcher below is the escape hatch.
PROXY = CONFIG.get("proxy_sandboxes", True)
PROXY_MAX = int(CONFIG.get("proxy_max", 4))
SEP = "__"

_tools_cache = {}          # name -> (expires, tools)
_CACHE_TTL = 60


def deskhand_rpc(ip, port, token, method, params=None, timeout=120):
    payload = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        payload["params"] = params
    req = urllib.request.Request(
        f"http://{ip}:{port}/mcp", data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json",
                 "Accept": "application/json, text/event-stream",
                 "Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read().decode("utf-8", "replace")
    # SSE framing: the JSON-RPC message rides in a "data:" line.
    for line in raw.splitlines():
        if line.startswith("data:"):
            msg = json.loads(line[5:].strip())
            if "error" in msg:
                raise RuntimeError(msg["error"].get("message", str(msg["error"])))
            return msg.get("result")
    # A server that answered plain JSON is fine too.
    msg = json.loads(raw)
    if "error" in msg:
        raise RuntimeError(msg["error"].get("message"))
    return msg.get("result")


def proxied_targets():
    """Running sandboxes we can reach, newest-first, capped."""
    out = []
    for e in list_sandboxes():
        if e["status"] == "running" and e.get("ip") and e.get("token"):
            out.append(e)
        if len(out) >= PROXY_MAX:
            break
    return out


def proxied_tools():
    """Every proxied sandbox's tools, prefixed with the sandbox name."""
    tools = []
    for e in proxied_targets():
        name = e["name"]
        now = time.time()
        cached = _tools_cache.get(name)
        if cached and cached[0] > now:
            remote = cached[1]
        else:
            try:
                remote = (deskhand_rpc(e["ip"], e.get("port", 8791), e["token"],
                                       "tools/list", timeout=30) or {}).get("tools", [])
                _tools_cache[name] = (now + _CACHE_TTL, remote)
            except Exception:
                continue                               # sandbox busy or rebooting
        for t in remote:
            copy = dict(t)
            copy["name"] = f"{name}{SEP}{t['name']}"
            copy["description"] = f"[sandbox {name}] " + (t.get("description") or "")
            tools.append(copy)
    return tools


def proxy_call(full_name, args):
    sb_name, _, tool = full_name.partition(SEP)
    for e in proxied_targets():
        if e["name"] == sb_name:
            return deskhand_rpc(e["ip"], e.get("port", 8791), e["token"],
                                "tools/call", {"name": tool, "arguments": args})
    raise ValueError(f"no running sandbox named '{sb_name}'")


def _sandbox_view(e):
    """One sandbox, described so a caller can act on it without another lookup."""
    port = e.get("port", 8791)
    out = dict(e)
    # Native Proxmox console: full interactive noVNC, works even with no guest
    # agent. Requires a Proxmox login, so it is a link rather than an embed.
    out["console_url"] = (f"https://{HOST}:8006/?console=kvm&novnc=1"
                          f"&vmid={e['vmid']}&node={NODE}&resize=off")
    # A count, not the notes themselves: an undocumented sandbox and a
    # well-documented one looked identical in the list.
    try:
        out["notes"] = len(get_comments(e["vmid"]) or [])
    except Exception:                                 # noqa: BLE001
        out["notes"] = 0
    gh = GH_LAST.get(int(e["vmid"]))
    if gh and gh != "none":
        out["groundhog"] = gh
    exp = get_expiry(e["vmid"])
    out["expires"] = "never" if not exp else ("expired" if exp["expired"]
                                              else f"{exp['minutes_left']} min")
    if exp:
        out["expires_at"] = exp["until"]
        out["expires_minutes_left"] = exp["minutes_left"]
    claim = get_claim(e["vmid"])
    if claim:
        out["claimed_by"] = claim["who"]
        out["claim_purpose"] = claim.get("purpose") or ""
        out["claim_minutes_left"] = claim["minutes_left"]
    if e.get("ip") and e.get("token"):
        out["deskhand_url"] = f"http://{e['ip']}:{port}/?token={e['token']}"
        out["mcp_url"] = f"http://{e['ip']}:{port}/mcp"
        out["mcp_auth_header"] = f"Authorization: Bearer {e['token']}"
    return out


_QUIET_TOOLS = {"list_sandboxes", "job_status", "read_comments", "sandbox_history"}


def mcp_call(name, args):
    # Reads are not worth a timeline entry; everything that changes something,
    # or reaches into a guest, is.
    if name not in _QUIET_TOOLS:
        record_event(args.get("vmid"), name, str(args.get("path") or args.get("agents") or "")[:80])
    if name == "generate_template":
        opts = {k: args.get(k) for k in
                ("name", "base", "groundhog", "groundhog_sha256", "groundhog_timeout",
                 "steps", "activate", "storage")}
        job = start_job(f"Building template {opts.get('name') or ''}".strip(),
                        do_make_template, opts)
        return {"job_id": job.id,
                "note": "poll job_status; a template build takes 15-30 minutes"}
    if name == "apply_groundhog":
        vmid = args.get("vmid")
        if vmid is None:
            raise ValueError("vmid is required")
        return apply_groundhog(vmid, args.get("source"), args.get("sha256"),
                               args.get("allow_http"), args.get("allow_reboot", False),
                               secrets=args.get("secrets"), headers=args.get("headers"))
    if name == "groundhog_status":
        vmid = args.get("vmid")
        if vmid is None:
            raise ValueError("vmid is required")
        return groundhog_status(vmid)
    if name == "set_expiry":
        vmid = args.get("vmid")
        if vmid is None:
            raise ValueError("vmid is required")
        _check_managed(vmid)
        return set_expiry(vmid, args.get("minutes"), args.get("who"))
    if name == "claim_sandbox":
        return claim_sandbox(args.get("vmid"), args.get("who"),
                             args.get("purpose"), args.get("minutes"))
    if name == "release_sandbox":
        vmid = args.get("vmid")
        if vmid is None:
            raise ValueError("vmid is required")
        return release_sandbox(vmid, args.get("who"))
    if name == "sandbox_history":
        vmid = args.get("vmid")
        if vmid is None:
            raise ValueError("vmid is required")
        return sandbox_history(vmid, args.get("include_guest", True))
    if name in ("browse_guest_file", "read_guest_file", "write_guest_file"):
        vmid = args.get("vmid")
        if vmid is None:
            raise ValueError("vmid is required")
        if name == "browse_guest_file":
            return guest_browse(vmid, args.get("path") or "C:\\")
        if not args.get("path"):
            raise ValueError("path is required")
        if name == "read_guest_file":
            return guest_read(vmid, args["path"])
        return guest_write(vmid, args["path"], args.get("text"),
                           args.get("content_base64"), bool(args.get("append")))
    if name == "comment_sandbox":
        vmid = args.get("vmid")
        if vmid is None:
            raise ValueError("vmid is required")
        return add_comment(vmid, args.get("text"), args.get("author"), via="mcp")
    if name == "read_comments":
        vmid = args.get("vmid")
        if vmid is None:
            raise ValueError("vmid is required")
        if args.get("archived"):
            return get_archive(vmid)
        return get_comments(vmid)
    if name == "list_sandboxes":
        return [_sandbox_view(e) for e in list_sandboxes()]
    if name == "capacity":
        return capacity()
    if name == "create_sandbox":
        _guard_capacity()
        opts = {
            "name": (args.get("name") or "").strip() or f"sandbox-{int(time.time()) % 100000}",
            "cores": int(args.get("cores") or 4),
            "memory": int(args.get("memory") or 8192),
            "port": int(args.get("port") or 8791),
            "shell": bool(args.get("shell", True)),
            "tls": bool(args.get("tls", False)),
            "groundhog": (args.get("groundhog") or "").strip() or None,
            "groundhog_sha256": args.get("groundhog_sha256"),
            "groundhog_allow_reboot": bool(args.get("groundhog_allow_reboot", False)),
            "groundhog_secrets": args.get("groundhog_secrets"),
            "groundhog_headers": args.get("groundhog_headers"),
            # None means "decide in provision", which is how the default can be
            # true without a caller passing false being ignored.
            "deskhand_via_groundhog": args.get("deskhand_via_groundhog"),
            "expires_in_minutes": args.get("expires_in_minutes"),
            "who": (args.get("who") or "").strip()[:60],
        }
        opts["name"] = re.sub(r"[^A-Za-z0-9-]", "-", opts["name"])[:15]
        job = start_job(f"Creating {opts['name']}", do_create, opts)
        return {"job_id": job.id, "note": "poll job_status; expect roughly 5 minutes"}
    if name == "destroy_sandbox":
        vmid = args.get("vmid")
        if vmid is None:
            raise ValueError("vmid is required")
        _guard_claim(vmid, "destroy", args.get("who"), args.get("force"))
        job = start_job(f"Destroying {vmid}", do_destroy, vmid)
        return {"job_id": job.id}
    if name == "fetch_deskhand":
        job = start_job("Fetching Deskhand", do_fetch, args.get("tag"))
        return {"job_id": job.id}
    if name == "repair_sandbox":
        vmid = args.get("vmid")
        if vmid is None:
            raise ValueError("vmid is required")
        _guard_claim(vmid, "repair (it reissues the token, breaking connected clients)",
                     args.get("who"), args.get("force"))
        job = start_job(f"Repairing {vmid}", do_repair, vmid)
        return {"job_id": job.id}
    if name == "update_sandbox":
        vmid = args.get("vmid")
        if vmid is None:
            raise ValueError("vmid is required")
        _guard_claim(vmid, "update (it restarts Deskhand under whoever is driving)",
                     args.get("who"), args.get("force"))
        job = start_job(f"Updating {vmid}", do_update, vmid)
        return {"job_id": job.id}
    if name == "install_agents":
        vmid = args.get("vmid")
        if vmid is None:
            raise ValueError("vmid is required")
        agents = args.get("agents") or []
        opts = {k: args.get(k) for k in ("base_url", "api_key", "model", "context_length")
                if args.get(k)}
        job = start_job(f"Installing agents on {vmid}", do_install_agents, vmid, agents, opts)
        return {"job_id": job.id, "note": "poll job_status; several minutes"}
    if name == "sandbox_call":
        return proxy_call(f"{args['sandbox']}{SEP}{args['tool']}", args.get("arguments") or {})
    if name == "job_status":
        # create_sandbox hands back "job_id", so accept that name too rather
        # than making the caller notice the two do not match.
        with JOBS_LOCK:
            job = JOBS.get(args.get("id") or args.get("job_id"))
        if not job:
            raise ValueError("no such job")
        return job.as_dict()
    raise ValueError(f"unknown tool: {name}")


DISPATCH_TOOL = {
    "name": "sandbox_call",
    "description": ("Call any tool on a specific sandbox's Deskhand by name. Use this when a "
                    "sandbox's tools are not listed directly (more sandboxes are running than "
                    "are proxied). Get tool names from that sandbox's own MCP or the docs."),
    "inputSchema": {
        "type": "object",
        "properties": {
            "sandbox": {"type": "string", "description": "Sandbox name, as shown by list_sandboxes"},
            "tool": {"type": "string", "description": "Deskhand tool name, e.g. deskhand_machine_info"},
            "arguments": {"type": "object", "description": "Arguments for that tool"},
        },
        "required": ["sandbox", "tool"],
    },
}


# What an AI pointed at this controller needs to know. Served on MCP initialize
# (as `instructions`), at /llms.txt, at / for non-browser clients, and on the
# dashboard itself -- so it reaches the model whichever way it arrived.
AGENT_GUIDE = """\
sandboxctl -- disposable Windows 11 sandboxes for AI agents

You are talking to a controller that provisions isolated Windows 11 VMs on
Proxmox, each with Deskhand (a desktop-automation server) running in a
logged-in session. Through it you can see a Windows screen, move the mouse,
type, run PowerShell and install software -- on a machine you can throw away.

HOW TO USE IT
  Connect over MCP (Streamable HTTP). No auth is needed from this network:
      {mcp_url}
  Then:
  1. list_sandboxes      see what exists; each row carries a ready-made Deskhand endpoint
  2. create_sandbox      only if you need a fresh machine (~5 min); poll job_status until done
  3. drive it            every sandbox's Deskhand tools are listed as <name>__deskhand_*
                         (e.g. <name>__deskhand_capture_screen), or reach any of them with
                         sandbox_call
  4. destroy_sandbox     when you are finished -- they are disposable; that is the point

SHARING IT WITH OTHER AGENTS
  claim_sandbox / release_sandbox   an advisory, self-expiring hold. Claim one
      before you test on it: it guards destroy, repair and update, so another
      session cannot pull the machine out from under you. It never blocks reads
      or screens, and force=true overrides it.
  comment_sandbox / read_comments   say what a sandbox is for, so the next
      person does not have to guess or leave it alone.
  sandbox_history                   boots, reboots, screen views, agent
      installs, file access -- for "was it always like this".

HOW MANY YOU MAY HAVE
  capacity        how many sandboxes exist and run, against the limits.
  create_sandbox refuses at either limit rather than queueing, so check this
  before creating several. Each running sandbox costs the controller about
  180 MB for its console recorder, which is what the running limit protects.

WHEN THEY GO AWAY
  set_expiry      a sandbox can be destroyed automatically when its time is up.
  create_sandbox takes expires_in_minutes; minutes=0 means NEVER, which is a
  real choice and clears a timer already set. A sandbox under an active claim is
  left alone until the claim lapses. This does not replace destroying what you
  finish with -- it is the backstop for when you do not.

GETTING FILES IN AND OUT
  write_guest_file / read_guest_file / browse_guest_file work over the guest
  agent, so they work before Deskhand is installed and while Windows setup is
  still running. write_guest_file has NO SIZE LIMIT -- it splits the content up
  itself -- and runs at roughly 4 MiB in 13 seconds, so do not go looking for a
  way around it for a few megabytes.
  For something large that is publicly downloadable, it is still faster to let
  the guest fetch it: a sandbox can reach the internet, so run the download
  inside it (deskhand_run_command, or a Groundhogfile 'files:' entry) rather
  than pushing the bytes through this controller.

RULES
  - A sandbox is untrusted. Never put real credentials, keys or private data in
    one; assume anything inside it can be read.
  - A sandbox cannot reach this controller or the LAN, by design. It can reach
    the inference endpoint and the public internet.
  - Creating and destroying VMs is real work on real hardware. Prefer a running
    sandbox over creating one; destroy what you finish with.
  - Deskhand runs elevated inside the sandbox: its bearer token is administrator
    on that VM. Treat it accordingly.

ALSO HERE
  GET /api/sandboxes           the same list as JSON
  GET /api/screen?vmid=<id>    JPEG of a sandbox's console; works even when the guest is wedged
  GET /.well-known/agent.json  machine-readable card for this service
  Source and docs:             https://github.com/guscatalano/SandboxMCP
"""


def agent_guide(host):
    """The guide with the MCP URL filled in from the Host the client used --
    whatever name or port they reached us by is the one they should keep."""
    return AGENT_GUIDE.format(mcp_url="http://%s/mcp" % (host or "this-host"))


def agent_card(host):
    base = "http://%s" % (host or "this-host")
    return {
        "name": "sandboxctl",
        "description": "Provisions disposable, network-isolated Windows 11 sandboxes on "
                       "Proxmox, each with Deskhand for screen, mouse, keyboard and shell.",
        "url": base + "/mcp",
        "protocol": "mcp",
        "transport": "streamable-http",
        "documentationUrl": base + "/llms.txt",
        "source": "https://github.com/guscatalano/SandboxMCP",
        "skills": [
            {"id": "list_sandboxes", "description": "List sandboxes and their Deskhand endpoints."},
            {"id": "create_sandbox", "description": "Provision a fresh Windows 11 sandbox (~5 min)."},
            {"id": "drive_sandbox", "description": "Screen, mouse, keyboard, shell and file tools on a "
                                                   "sandbox, namespaced <name>__deskhand_*."},
            {"id": "destroy_sandbox", "description": "Tear a sandbox down."},
        ],
    }


def handle_mcp(msg, host=None):
    """Handle one JSON-RPC message. Returns a response dict, or None for notifications."""
    mid = msg.get("id")
    method = msg.get("method")

    if method == "initialize":
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": (msg.get("params") or {}).get("protocolVersion") or MCP_PROTOCOL,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "sandboxctl", "version": "1.0"},
            "instructions": agent_guide(host)}}
    if method in ("notifications/initialized", "initialized"):
        return None                                   # notification: no reply
    if method == "ping":
        return {"jsonrpc": "2.0", "id": mid, "result": {}}
    if method == "tools/list":
        tools = list(MCP_TOOLS) + [DISPATCH_TOOL]
        if PROXY:
            try:
                tools += proxied_tools()
            except Exception:
                pass                                   # never fail the listing over one bad sandbox
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": tools}}
    if method == "tools/call":
        params = msg.get("params") or {}
        try:
            tname = params.get("name") or ""
            targs = params.get("arguments") or {}
            if SEP in tname and not any(t["name"] == tname for t in MCP_TOOLS):
                # Namespaced: forward to that sandbox's Deskhand and return its
                # response untouched, so the caller sees exactly what it sent.
                record_event(_vmid_for_name(tname.split(SEP)[0]),
                             "deskhand tool", tname.split(SEP)[-1])
                inner = proxy_call(tname, targs)
                return {"jsonrpc": "2.0", "id": mid, "result": inner}
            result = mcp_call(tname, targs)
            text = json.dumps(result, indent=2, default=str)
            return {"jsonrpc": "2.0", "id": mid,
                    "result": {"content": [{"type": "text", "text": text}], "isError": False}}
        except Exception as exc:                      # noqa: BLE001
            # Reported as a tool error rather than a protocol error, so the model
            # sees the reason and can correct itself.
            return {"jsonrpc": "2.0", "id": mid,
                    "result": {"content": [{"type": "text", "text": f"error: {exc}"}], "isError": True}}
    return {"jsonrpc": "2.0", "id": mid,
            "error": {"code": -32601, "message": f"method not found: {method}"}}


# --------------------------------------------------------------------------
# Web
# --------------------------------------------------------------------------
PAGE = """<!doctype html><html><head><meta charset="utf-8">
<title>Sandboxes</title><meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAzMiAzMiI+PHJlY3Qgd2lkdGg9IjMyIiBoZWlnaHQ9IjMyIiByeD0iNyIgZmlsbD0iIzE1MTkyMiIvPjxyZWN0IHg9IjUiIHk9IjgiIHdpZHRoPSIyMiIgaGVpZ2h0PSIxNSIgcng9IjIuNSIgZmlsbD0iIzRhOWVmZiIvPjxyZWN0IHg9IjkiIHk9IjI1IiB3aWR0aD0iMTQiIGhlaWdodD0iMi41IiByeD0iMS4yNSIgZmlsbD0iIzJhMzI0MiIvPjxjaXJjbGUgY3g9IjIyLjUiIGN5PSIxMi41IiByPSIyLjYiIGZpbGw9IiMzZmI5NTAiLz48L3N2Zz4=">
<style>
:root{--bg:#0f1115;--fg:#e6e6e6;--mut:#8b93a1;--ln:#252a33;--acc:#4a9eff;--ok:#3fb950;--bad:#f85149}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 ui-sans-serif,system-ui,Segoe UI,sans-serif}
.wrap{max-width:1000px;margin:0 auto;padding:24px}
h1{font-size:20px;margin:0 0 4px}.sub{color:var(--mut);margin:0 0 24px}
.card{background:#151922;border:1px solid var(--ln);border-radius:8px;padding:16px;margin-bottom:20px}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--ln)}
th{color:var(--mut);font-weight:500;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
code{font:12px ui-monospace,Consolas,monospace;background:#0b0d11;padding:2px 6px;border-radius:4px;color:#c9d1d9}
a{color:var(--acc)}
.lnk{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.badge{font:11px ui-monospace,Consolas,monospace;border:1px solid var(--ln);border-radius:999px;padding:1px 8px;color:var(--mut)}
/* A flex row rather than inline margins: the badges can wrap under the name
   instead of widening the column, and each one stays on a single line. */
.namecell{display:flex;align-items:center;gap:6px;flex-wrap:wrap;min-width:0}
.nm{font-weight:500}
.claim,.exp{font:11px ui-monospace,Consolas,monospace;border-radius:999px;padding:1px 8px;
  /* Whoever claimed it chose the text, so cap it and keep the rest in title. */
  white-space:nowrap;max-width:22ch;overflow:hidden;text-overflow:ellipsis}
.claim{border:1px solid #d29922;color:#d29922}
.exp{border:1px solid #8b949e;color:#8b949e}
/* Groundhog outcome, as a variant of the expiry badge so it inherits the
   one-line-and-ellipsis behaviour rather than repeating it. */
.gh-ok{border-color:var(--ok);color:var(--ok)}
.gh-bad{border-color:var(--bad);color:var(--bad)}
textarea:focus-visible,select:focus-visible{outline:2px solid var(--acc);outline-offset:1px}
.notes-toggle{font-size:11px;color:var(--mut);text-decoration:none;border-bottom:1px dotted var(--ln)}
/* State is its own column now, so the badges wrap there instead of widening Name. */
.statecell{display:flex;align-items:center;gap:6px;flex-wrap:wrap;min-width:0}
/* Capacity, above the table: a limit should be visible before it refuses you. */
.cap{display:flex;align-items:center;gap:18px;flex-wrap:wrap;padding:0 2px 14px;
  font:12px ui-monospace,Consolas,monospace;color:var(--mut)}
.cap .m{display:flex;align-items:center;gap:8px}
.cap .bar{width:80px;height:5px;border-radius:3px;background:#222936;overflow:hidden}
.cap .bar>i{display:block;height:100%;background:var(--acc)}
.cap .bar>i.hot{background:#d29922}
.cap .warnmsg{color:#d29922}
tr.grouphead td{padding:14px 10px 4px;border-bottom:0;color:var(--mut);
  font:500 11px ui-monospace,Consolas,monospace;letter-spacing:.09em;text-transform:uppercase}
tr.dimmed td{opacity:.62}
.tick{font:12px ui-monospace,Consolas,monospace;font-variant-numeric:tabular-nums;color:#8b949e}
.tick.soon{color:var(--bad)}
.notes-toggle:hover{color:var(--acc)}
.notes-row>td{background:#0f131a;padding-top:12px}
.notes{max-height:260px;overflow:auto;margin-bottom:10px}
.note{border-left:2px solid var(--ln);padding:2px 0 6px 10px;margin-bottom:8px}
.note .who{font-weight:600;margin-right:8px}
.note .when{color:var(--mut);font-size:12px;margin-right:8px}
.note .via{color:var(--mut);font-size:11px;font-family:ui-monospace,Consolas,monospace}
.note .what{white-space:pre-wrap;margin-top:2px}
.muted{color:var(--mut)}
.notes-add{display:flex;gap:8px;flex-wrap:wrap}
.notes-add input{background:#0b0d11;border:1px solid var(--ln);border-radius:6px;padding:7px 9px;color:var(--fg);font:13px inherit}
.notes-add input:first-child{width:140px}
.notes-add input:nth-child(2){flex:1;min-width:240px}
details.menu{position:relative;display:inline-block}
details.menu>summary{list-style:none;cursor:pointer;border:1px solid #30363d;border-radius:6px;padding:7px 11px;color:var(--mut);background:#161b22;font-weight:700}
details.menu>summary::-webkit-details-marker{display:none}
.mi{display:flex;position:absolute;right:0;top:115%;z-index:30;flex-direction:column;gap:6px;background:#161b22;border:1px solid var(--ln);border-radius:8px;padding:8px;min-width:226px;text-align:left;box-shadow:0 10px 30px rgba(0,0,0,.6)}
/* .d with no inline colour is the destructive style; menu entries are not. */
.mi button.d{width:100%;text-align:left;color:#c9d1d9;border-color:#30363d}
.mi button.d.warnish{color:#d29922;border-color:#d29922}
.mi button.d.okish{color:#3fb950;border-color:#3fb950}
.mi button.d.badish{color:#f85149;border-color:#f85149}
label.opt{display:inline-flex;align-items:center;gap:7px;white-space:nowrap;color:var(--fg);font-size:14px;text-transform:none;letter-spacing:0}
label.opt input{width:auto;margin:0}
.cred{text-align:left;font:12px/1.6 ui-sans-serif,system-ui,sans-serif;color:var(--mut);padding:2px 4px 8px;border-bottom:1px solid var(--ln);margin-bottom:4px}
.cred code{font-size:11px}
button{background:var(--acc);color:#08111f;border:0;border-radius:6px;padding:8px 14px;font-weight:600;cursor:pointer}
button.d{background:transparent;color:var(--bad);border:1px solid var(--bad);padding:5px 10px;font-weight:500}
button:disabled{opacity:.5;cursor:not-allowed}
label{display:block;color:var(--mut);font-size:12px;margin-bottom:4px}
input,select{background:#0b0d11;border:1px solid var(--ln);color:var(--fg);border-radius:6px;padding:7px 9px;width:100%}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;margin-bottom:14px}
.row{display:flex;align-items:center;gap:8px}
pre{background:#0b0d11;border:1px solid var(--ln);border-radius:6px;padding:12px;overflow:auto;max-height:280px;font:12px ui-monospace,monospace;color:#9fb4c9;white-space:pre-wrap}
.st{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
.st.r{background:var(--ok)}.st.s{background:var(--mut)}
.warn{color:var(--mut);font-size:12px;margin-top:8px}
</style></head><body><div class="wrap">
<h1>Windows sandboxes</h1>
<p class="sub">Disposable VMs on an isolated network. Deskhand is installed per sandbox, so config is chosen here rather than baked into the image.</p>
<details class="card" style="padding:10px 16px"><summary style="cursor:pointer;color:var(--mut)">If you are an AI reading this page</summary>
<p>Connect over MCP at <code>/mcp</code> on this host, call <code>list_sandboxes</code>, then drive a sandbox through its <code>&lt;name&gt;__deskhand_*</code> tools. The full guide, as plain text, is at <a href="/llms.txt">/llms.txt</a>; a machine-readable card is at <a href="/.well-known/agent.json">/.well-known/agent.json</a>. Sandboxes are disposable and untrusted: never put real credentials in one, and destroy what you finish with.</p>
</details>

<div class="card">
  <div class="row" style="justify-content:space-between;flex-wrap:wrap;gap:10px">
    <div><b>Deskhand build</b><div class="warn" id="pay">checking&hellip;</div></div>
    <div class="row">
      <input id="tag" placeholder="latest" style="width:120px">
      <button onclick="fetchDh()">Fetch from GitHub</button>
    </div>
  </div>
  <div class="warn">This is what <b>Create</b> installs, and what <b>Update</b> rolls out to an existing sandbox.</div>
</div>

<div class="card">
  <div class="grid">
    <div><label>Name</label><input id="name" placeholder="auto"></div>
    <div><label>Cores</label><input id="cores" type="number" value="4" min="1" max="16"></div>
    <div><label>Memory (MiB)</label><input id="memory" type="number" value="8192" step="1024" min="4096"></div>
    <div><label>Deskhand port</label><input id="port" type="number" value="8791"></div>
    <div><label>Shell (/shell/run)</label><select id="shell"><option value="1" selected>enabled</option><option value="0">disabled</option></select></div>
    <div><label>TLS (self-signed)</label><select id="tls"><option value="0" selected>off</option><option value="1">on</option></select></div>
  </div>
  <div class="row"><button id="go" onclick="create()">Create sandbox</button>
  <span class="warn" id="hint">Takes about 5 minutes: clone, Windows OOBE, a reboot for auto-logon, then the Deskhand install.</span></div>
  <div class="warn">TLS uses an ephemeral self-signed certificate. It changes on every boot, so MCP clients that verify certificates will reject it &mdash; leave it off unless you know you want it.</div>
</div>

<div class="card">
<div class="cap" id="cap"></div>
<table id="tbl"><thead><tr>
<th>VMID</th><th>Name</th><th>State</th><th>Address</th><th>Open</th><th></th>
</tr></thead><tbody id="rows"><tr><td colspan="6" style="color:#8b93a1">loading&hellip;</td></tr></tbody></table></div>

<div class="card"><div class="warn">
<b>Open</b> lists what is reachable on a sandbox. <b>Watch</b> is a live view of its screen,
  <b>Agents</b> installs Hermes or opencode inside it, and <b>&#8943;</b> holds the rest:<br>
  <b>Update Deskhand</b> &mdash; reinstall the staged build; keeps the token (~25s).<br>
  <b>Repair / Finish setup</b> &mdash; for a sandbox stuck at a lock screen or with no Deskhand. <b>Issues a new token</b> (~3min).<br>
  <b>Destroy</b> &mdash; permanent; the disk goes too.
</div></div>

<div class="card">
  <b>Connect an AI agent</b>
  <div class="warn" style="margin:6px 0 12px">One endpoint covers every sandbox.
  This controller proxies each sandbox&rsquo;s Deskhand, so you configure it once and
  sandboxes you create later show up as tools automatically &mdash; no per-sandbox setup,
  no tokens to copy.</div>
  <div class="row" style="gap:8px;flex-wrap:wrap">
    <button class="d" style="color:#4a9eff;border-color:#4a9eff" onclick="copyHub('claude')">Copy for Claude Code</button>
    <button class="d" style="color:#3fb950;border-color:#3fb950" onclick="copyHub('hermes')">Copy for Hermes</button>
  </div>
  <pre id="hubcmd" style="margin-top:12px;white-space:pre-wrap"></pre>
  <div class="warn"><b>Sandbox-only mode.</b> Hermes keeps its own file, terminal, browser and
  code-execution tools switched on, and those act on <i>your</i> machine, not the sandbox.
  To let it touch only the sandboxes, scope a run with
  <code>hermes -t sandboxctl -z "&hellip;"</code> (also works with <code>--tui</code>).
  To make that permanent instead, <code>hermes tools disable web browser terminal file code_execution</code>
  &mdash; but note that setting is shared with Telegram and Discord.</div>
</div>

<div class="card" id="reccard" style="display:none">
  <div class="row" style="justify-content:space-between;flex-wrap:wrap;gap:8px">
    <b id="rectitle"></b>
    <button class="d" onclick="document.getElementById('reccard').style.display='none';document.getElementById('recplayer').src=''">Close</button>
  </div>
  <div class="warn" id="recnote" style="margin:6px 0 10px"></div>
  <video id="recplayer" controls preload="metadata"
         style="width:100%;max-height:520px;background:#000;border:1px solid var(--ln);border-radius:6px;display:none"></video>
  <table style="margin-top:10px"><thead><tr>
    <th>Started</th><th>Size</th><th></th>
  </tr></thead><tbody id="recrows"></tbody></table>
</div>

<div class="card" id="ghcard" style="display:none">
  <b id="ghtitle"></b>
  <div class="warn" style="margin:6px 0 10px">Groundhog brings a sandbox to a declared state from
  one file &mdash; apps, files, registry, environment, and its own health checks. It is how Deskhand
  itself gets installed. <b>Validate</b> runs Groundhog&rsquo;s own <code>plan</code> in the guest and
  changes nothing; <b>Apply</b> runs it for real. Name secrets in the file as
  <code>${secret:NAME}</code> and give the values below &mdash; they are stripped from the guest as the
  agent reads them, and never logged.</div>
  <div id="ghstate" class="warn" style="margin:-4px 0 12px">&nbsp;</div>
  <div class="grid" style="margin-bottom:10px">
    <div><label>Start from</label>
      <select id="gh_tpl" onchange="ghStarter()">
        <option value="">(keep what is in the editor)</option>
        <option value="internals">groundhog:windows-internals &mdash; Sysinternals, WinDbg, symbols</option>
        <option value="sysinternals">groundhog:sysinternals only</option>
        <option value="apps">a couple of winget apps</option>
        <option value="secret">pass a secret into the environment</option>
      </select></div>
    <div style="grid-column:span 2"><label>Or one of the profiles shipped with this controller</label>
      <select id="gh_lib" onchange="ghLib()"><option value="">loading&hellip;</option></select>
      <div class="warn" id="gh_libnote" style="margin:6px 0 0">&nbsp;</div></div>
    <div><label>Secrets (NAME=value, one per line)</label>
      <input id="gh_secrets" placeholder="API_TOKEN=..."></div>
  </div>
  <label for="gh_body">Groundhogfile</label>
  <textarea id="gh_body" spellcheck="false" rows="14"
    style="width:100%;font:13px/1.5 ui-monospace,Consolas,monospace;background:#0f1115;
           color:var(--fg);border:1px solid var(--ln);border-radius:6px;padding:10px"></textarea>
  <div style="display:flex;gap:8px;align-items:center;margin-top:10px;flex-wrap:wrap">
    <button class="d" onclick="ghPlan()">Validate</button>
    <button class="d" style="color:#58a6ff;border-color:#58a6ff" onclick="ghApply()">Apply</button>
    <label style="display:flex;align-items:center;gap:6px;color:var(--mut);font-size:12px">
      <input type="checkbox" id="gh_reboot"> allow it to reboot mid-apply</label>
    <button class="d" onclick="document.getElementById('ghcard').style.display='none'">Close</button>
  </div>
  <pre id="gh_out" style="margin:12px 0 0;padding:10px;background:#0f1115;border:1px solid var(--ln);
       border-radius:6px;font:12px/1.5 ui-monospace,Consolas,monospace;color:var(--mut);
       white-space:pre-wrap;max-height:260px;overflow:auto">No run recorded for this sandbox yet.</pre>
</div>

<div class="card" id="agentcard" style="display:none">
  <b id="agenttitle"></b>
  <div class="warn" style="margin:6px 0 10px">Installs into the sandbox itself and configures it with
  the API keys from the controller&rsquo;s config, plus this sandbox&rsquo;s own Deskhand as an MCP server
  &mdash; so the agent can drive the desktop it is running on. Several minutes; Hermes is a ~2&nbsp;GB install
  that brings its own git, python and node. Leave the endpoint blank to use the keys in the
  controller config instead; leave the key blank for a local server that needs none.</div>
  <div class="grid" style="margin-bottom:12px">
    <div style="grid-column:span 2"><label>Inference endpoint (OpenAI-compatible)</label>
      <input id="ag_url" value="@@AGENT_BASEURL@@" placeholder="http://host:11444/v1"
             onchange="document.getElementById('ag_model').value='';loadModels()"></div>
    <div><label>API key</label><input id="ag_key" placeholder="blank if none"></div>
    <div><label>Model</label>
      <input id="ag_model" list="ag_models" value="@@AGENT_MODEL@@" placeholder="pick or type">
      <datalist id="ag_models"></datalist></div>
  </div>
  <div class="warn" id="ag_models_note" style="margin:-4px 0 12px">&nbsp;</div>
  <div class="row" style="gap:16px;flex-wrap:wrap;align-items:center">
    <label class="opt"><input type="checkbox" id="ag_hermes" checked> Hermes</label>
    <label class="opt"><input type="checkbox" id="ag_opencode" checked> opencode</label>
    <button onclick="installAgents()">Install</button>
    <button class="d" onclick="document.getElementById('agentcard').style.display='none'">Cancel</button>
  </div>
</div>

<div class="card" id="watchcard" style="display:none">
  <div class="row" style="justify-content:space-between;flex-wrap:wrap;gap:8px">
    <b id="watchtitle"></b>
    <div class="row">
      <select id="wsrc" onchange="rewatch()">
        <option value="vnc">Proxmox VNC (works even at a lock screen)</option>
        <option value="deskhand">Deskhand capture (needs a session)</option>
      </select>
      <select id="wfps" onchange="rewatch()">
        <option value="1">1 fps</option><option value="2" selected>2 fps</option>
        <option value="4">4 fps</option><option value="8">8 fps</option>
      </select>
      <a id="wconsole" href="#" target="_blank"><button class="d" style="color:#4a9eff;border-color:#4a9eff">Proxmox console</button></a>
      <button class="d" onclick="stopWatch()">Close</button>
    </div>
  </div>
  <img id="wimg" style="width:100%;margin-top:12px;border:1px solid var(--ln);border-radius:6px;background:#000">
  <div class="warn" id="werr"></div>
</div>

<div class="card" id="jobcard" style="display:none"><b id="jobtitle"></b><pre id="joblog"></pre></div>
</div>
<script>
let jobId=null;
// One row is: what it is, what you can open on it, and what you can do to it.
// Everything destructive or rarely used lives behind the menu so the common
// actions stay one click away.
function links(s){
  if(!s.ip) return '&mdash;';
  var a=s.agents||{}, inst=a.installed||[], out=[];
  if(s.token) out.push(`<a href="http://${s.ip}:${s.port||8791}/?token=${s.token}" target="_blank">Deskhand</a>`);
  if(inst.indexOf('hermes')>=0 && a.dashboard_port)
    out.push(`<a href="http://${s.ip}:${a.dashboard_port}/" target="_blank" title="Hermes dashboard - sign in as ${a.dashboard_user}; the password is in the menu">Hermes</a>`);
  if(inst.indexOf('opencode')>=0)
    out.push('<span class="badge" title="Installed. opencode is a terminal app with no web UI - run it on the desktop (Watch), or point a client at opencode serve.">opencode</span>');
  return out.length ? out.join('') : '&mdash;';
}
function actions(s){
  var a=s.agents||{}, m=[];
  if(s.token){
    m.push(`<button class="d" onclick="copyMcp('claude','${s.name}','${s.ip}',${s.port||8791},'${s.token}')">Copy MCP for Claude</button>`);
    m.push(`<button class="d" onclick="copyMcp('hermes','${s.name}','${s.ip}',${s.port||8791},'${s.token}')">Copy MCP for Hermes</button>`);
    m.push(`<button class="d" onclick="copyText('${s.token}','Deskhand token')">Copy Deskhand token</button>`);
  }
  if(a.dashboard_password){
    // Readable, not just copyable: a password you can only copy is a password
    // you cannot check.
    m.push(`<div class="cred">Hermes dashboard sign-in<br>
      user <code>${a.dashboard_user||'sandbox'}</code><br>pass <code>${a.dashboard_password}</code></div>`);
    m.push(`<button class="d" onclick="copyText('${a.dashboard_password}','Dashboard password')">Copy dashboard password</button>`);
  }
  if(s.token)
    m.push(`<button class="d warnish" onclick="upd(${s.vmid})">Update Deskhand</button>`);
  m.push(`<button class="d okish" onclick="rep(${s.vmid})">${s.token?'Repair':'Finish setup'}</button>`);
  m.push(`<button class="d" onclick="recordings(${s.vmid},'${s.name}')">Recordings</button>`);
  m.push(`<button class="d badish" onclick="destroy(${s.vmid})">Destroy</button>`);
  // Claim where it can be claimed, Release only for the holder. A row that is
  // someone else's says so in the badge and offers neither.
  var hold = '';
  if (s.status === 'running') {
    if (!s.claimed_by) {
      hold = `<button class="d okish" onclick="claimRow(${s.vmid})"
                title="Hold it so nobody destroys or repairs it while you work">Claim</button>`;
    } else if (s.claimed_by === whoAmI(true)) {
      hold = `<button class="d warnish" onclick="releaseRow(${s.vmid})"
                title="Give it back">Release</button>`;
    }
  }
  return hold + `<button class="d" style="color:#a371f7;border-color:#a371f7" onclick="watch(${s.vmid},'${s.name}')">Watch</button>
    <button class="d" onclick="ghPanel(${s.vmid},'${esc(s.name)}')">Groundhog</button>
    <button class="d" style="color:#58a6ff;border-color:#58a6ff" onclick="agentPanel(${s.vmid},'${s.name}')">Agents</button>
    <details class="menu"><summary>&#8943;</summary><div class="mi">${m.join('')}</div></details>`;
}
function row(s){
  // esc() on all of it: these land in innerHTML, and who/purpose are whatever
  // the caller of claim_sandbox typed.
  var claim = s.claimed_by
    ? `<span class="claim" title="${esc('held by ' + s.claimed_by + (s.claim_purpose ? ' \u2014 ' + s.claim_purpose : ''))}">held by ${esc(s.claimed_by)} &middot; ${esc(s.claim_minutes_left)}m</span>`
    : '';
  // A sandbox counting down to destruction should not look like one that is
  // staying. "never" is the common case and says nothing.
  // A countdown, not a label: this used to be a server-rendered string, so a
  // row could read "33 min" with seconds left on it.
  var exp = '';
  if (s.expires === 'expired') {
    exp = '<span class="exp" title="Past its expiry; the reaper takes it on its next pass">expired</span>';
  } else if (s.expires_at) {
    exp = `<span class="exp tick" data-until="${s.expires_at}"
             title="Destroyed automatically when this runs out">&hellip;</span>`;
  }
  // Named outcomes, because "not applied" and "failed" are different facts and
  // the old badge-free row said neither.
  var gh = '';
  if (s.groundhog && s.groundhog !== 'none') {
    var cls = s.groundhog === 'failed' ? 'exp gh-bad'
            : s.groundhog === 'succeeded' ? 'exp gh-ok' : 'exp';
    var label = s.groundhog === 'reboot-pending' ? 'needs reboot' : 'gh ' + s.groundhog;
    gh = `<span class="${cls}" title="Groundhog: ${esc(s.groundhog)}">${esc(label)}</span>`;
  }
  var n = s.notes || 0;
  // Dim by bucket, not by claim: a claimed sandbox that is about to be reaped
  // belongs in "expiring soon" and must not be greyed out there.
  return `<tr class="${bucket(s) >= 2 ? 'dimmed' : ''}">
    <td><code>${s.vmid}</code></td>
    <td><div class="namecell"><span class="nm">${esc(s.name)}</span>
      <a href="#" class="notes-toggle" onclick="return toggleNotes(event,${s.vmid})"
         title="${n ? n+' note'+(n===1?'':'s')+' on this sandbox' : 'No notes yet'}"
         >notes${n ? ' ' + n : ''}</a></div></td>
    <td><div class="statecell"><span class="st ${s.status==='running'?'r':'s'}"></span>${s.status}${claim}${exp}${gh}</div></td>
    <td>${s.ip?`<code>${s.ip}</code>`:'&mdash;'}</td>
    <td><div class="lnk">${links(s)}</div></td>
    <td style="text-align:right">${actions(s)}</td></tr>
    <tr id="notes-${s.vmid}" class="notes-row" hidden><td colspan="6">
      <div class="notes" id="notes-body-${s.vmid}">loading&hellip;</div>
      <div class="notes-add">
        <input id="notes-who-${s.vmid}" placeholder="your name" maxlength="60">
        <input id="notes-txt-${s.vmid}" placeholder="What is this sandbox for? What did you change?"
               onkeydown="if(event.key==='Enter')addNote(${s.vmid})">
        <button class="d okish" onclick="addNote(${s.vmid})">Add note</button>
      </div>
    </td></tr>`;
}

// Notes are append-only and self-declared; the server records the channel and
// the client address next to whatever name is typed.
function toggleNotes(ev,vmid){
  ev.preventDefault();
  var tr=document.getElementById('notes-'+vmid);
  tr.hidden=!tr.hidden;
  if(!tr.hidden) loadNotes(vmid);
  return false;
}
function fmtWhen(ts){
  var d=new Date(ts*1000), n=Date.now()/1000, age=n-ts;
  if(age<60) return 'just now';
  if(age<3600) return Math.floor(age/60)+'m ago';
  if(age<86400) return Math.floor(age/3600)+'h ago';
  return d.toLocaleDateString()+' '+d.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
}
function esc(s){ return String(s).replace(/[&<>"]/g, function(c){
  return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'})[c]; }); }
function loadNotes(vmid){
  var el=document.getElementById('notes-body-'+vmid);
  fetch('api/comments?vmid='+vmid).then(function(r){return r.json();}).then(function(list){
    if(!list.length){ el.innerHTML='<p class="muted">No notes yet. The next person here will not know what this box is for.</p>'; return; }
    el.innerHTML=list.map(function(c){
      return '<div class="note"><span class="who">'+esc(c.author)+'</span>'
           + '<span class="when">'+fmtWhen(c.ts)+'</span>'
           + '<span class="via">'+esc(c.via)+(c.addr?' &middot; '+esc(c.addr):'')+'</span>'
           + '<div class="what">'+esc(c.text)+'</div></div>';
    }).join('');
  }).catch(function(){ el.textContent='could not load notes'; });
}
function addNote(vmid){
  var who=document.getElementById('notes-who-'+vmid), txt=document.getElementById('notes-txt-'+vmid);
  if(!txt.value.trim()) return;
  fetch('api/comment',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({vmid:vmid,text:txt.value,author:who.value})})
    .then(function(r){return r.json();})
    .then(function(d){ if(d.error){ alert(d.error); return; } txt.value=''; loadNotes(vmid); })
    .catch(function(){ alert('could not save the note'); });
}
// navigator.clipboard exists only in a SECURE context, and this UI is served
// over plain http. Touching it throws synchronously -- before any .then()
// handler can run -- which is why every copy button silently did nothing.
// So: feature-detect, fall back to a scratch textarea, and fall back again to
// a prompt, which at least puts the value on screen where it can be read.
function copyText(t,what,extra){
  var shown=(what||'Value')+' copied to clipboard:'+String.fromCharCode(10,10)+t+(extra||'');
  function viaTextarea(){
    try{
      var ta=document.createElement('textarea');
      ta.value=t; ta.setAttribute('readonly','');
      ta.style.position='fixed'; ta.style.top='-1000px'; ta.style.opacity='0';
      document.body.appendChild(ta);
      ta.select(); ta.setSelectionRange(0,t.length);
      var ok=document.execCommand('copy');
      document.body.removeChild(ta);
      if(ok){ alert(shown); return true; }
    }catch(e){}
    return false;
  }
  try{
    if(window.isSecureContext && navigator.clipboard && navigator.clipboard.writeText){
      navigator.clipboard.writeText(t).then(
        function(){ alert(shown); },
        function(){ if(!viaTextarea()) prompt((what||'Value')+' (copy it):',t); });
      return;
    }
  }catch(e){}
  if(!viaTextarea()) prompt((what||'Value')+' (copy it):',t);
}
// Which question a row answers: can I take this, is it about to vanish, is
// someone on it, or is it not even running. Imminent destruction outranks a
// claim, because it is the fact you have least time to act on.
function bucket(s){
  if(s.status!=='running') return 3;
  var left = s.expires_minutes_left;
  if(s.expires==='expired' || (typeof left==='number' && left<=15)) return 1;
  return s.claimed_by ? 2 : 0;
}
var GROUPS=['free to take','expiring soon','held','not running'];

function groupHead(i,n){
  return '<tr class="grouphead"><td colspan="6">'+GROUPS[i]+' &middot; '+n+'</td></tr>';
}

function ticks(){
  var now = Date.now()/1000;
  document.querySelectorAll('.tick[data-until]').forEach(function(el){
    var left = Math.round(parseInt(el.dataset.until,10) - now);
    if(left <= 0){ el.textContent='expired'; el.classList.add('soon'); return; }
    var h=Math.floor(left/3600), m=Math.floor((left%3600)/60), s=left%60;
    var p=function(v){ return v<10?'0'+v:''+v; };
    el.textContent = (h ? h+':'+p(m)+':'+p(s) : m+':'+p(s)) + ' left';
    el.classList.toggle('soon', left < 15*60);
  });
}

async function drawCapacity(){
  try{
    const r=await fetch('api/capacity');
    if(!r.ok) return;
    const c=await r.json();
    var pct=function(a,b){ return b ? Math.min(100, Math.round(a/b*100)) : 0; };
    var hot=function(a,b){ return b && a/b >= .8 ? ' hot' : ''; };
    var left=c.running_left;
    document.getElementById('cap').innerHTML =
      '<span class="m">sandboxes <span class="bar"><i style="width:'+pct(c.sandboxes,c.max_sandboxes)+'%"></i></span> '
        +c.sandboxes+' / '+c.max_sandboxes+'</span>'
      +'<span class="m">running <span class="bar"><i class="'+hot(c.running,c.max_running).trim()
        +'" style="width:'+pct(c.running,c.max_running)+'%"></i></span> '
        +c.running+' / '+c.max_running+'</span>'
      +(left<=1 ? '<span class="warnmsg">'+(left===0
          ? 'no room left \u2014 create will refuse until one is destroyed or stopped'
          : '1 slot left \u2014 each running sandbox costs the controller ~180 MB')+'</span>' : '');
  }catch(e){ /* the list is the point; capacity is a nicety */ }
}

async function refresh(){
 try{
  const r=await fetch('api/sandboxes');
  if(!r.ok) throw new Error('HTTP '+r.status);
  const d=await r.json();
  if(!d.length){
    document.getElementById('rows').innerHTML =
      '<tr><td colspan="6" style="color:#8b93a1">No sandboxes yet.</td></tr>';
  } else {
    var by=[[],[],[],[]];
    d.forEach(function(s){ by[bucket(s)].push(s); });
    var html='';
    by.forEach(function(list,i){
      if(!list.length) return;
      list.sort(function(a,b){ return a.vmid-b.vmid; });
      html += groupHead(i,list.length) + list.map(row).join('');
    });
    document.getElementById('rows').innerHTML = html;
    ticks();
  }
  drawCapacity();
 }catch(e){
  document.getElementById('rows').innerHTML =
    '<tr><td colspan="6" style="color:#f85149">Could not load: '+e.message+'</td></tr>';
 }
}
setInterval(ticks, 1000);
// The controller proxies every sandbox, so this endpoint is the one worth
// configuring; the per-sandbox commands below are for pointing a client at a
// single box directly.
function hubCmd(kind){
  const url=location.origin+'/mcp';
  return kind==='hermes'
    ? 'hermes mcp add sandboxctl --url '+url+' --connect-timeout 180'
    : 'claude mcp add --transport http sandboxctl '+url;
}
function showHub(){
  document.getElementById('hubcmd').textContent =
    '# Claude Code\\n'+hubCmd('claude')+'\\n\\n# Hermes\\n'+hubCmd('hermes');
}
function copyHub(kind){
  copyText(hubCmd(kind),'Command');
}
function copyMcp(kind,name,ip,port,token){
  const url=`http://${ip}:${port}/mcp`;
  // Hermes has no flag for a header value: --auth header makes it ask, so the
  // token goes in the note rather than the command line.
  const cmd = kind==='hermes'
    ? `hermes mcp add ${name} --url ${url} --auth header`
    : `claude mcp add --transport http ${name} ${url} --header "Authorization: Bearer ${token}"`;
  const note = kind==='hermes'
    ? `\\n\\nHermes will ask "Does this server require authentication?" - answer yes,\\nchoose a header, and give it:\\n\\n  Authorization: Bearer ${token}`
    : '';
  copyText(cmd,'MCP command',note);
}
var wvm=null, wname='';
function watch(vmid,name){
  wvm=vmid; wname=name;
  document.getElementById('watchcard').style.display='block';
  document.getElementById('watchtitle').textContent='Live: '+name+' (vmid '+vmid+')';
  document.getElementById('wconsole').href=
    'https://@@PVEHOST@@:8006/?console=kvm&novnc=1&vmid='+vmid+'&node=@@PVENODE@@&resize=off';
  rewatch();
  document.getElementById('watchcard').scrollIntoView({behavior:'smooth'});
}
function rewatch(){
  if(!wvm) return;
  var src=document.getElementById('wsrc').value, fps=document.getElementById('wfps').value;
  var img=document.getElementById('wimg');
  document.getElementById('werr').textContent='';
  // cache-buster so switching source actually reopens the stream
  img.onerror=function(){ document.getElementById('werr').textContent=
    'Stream failed. VNC needs the VM running; Deskhand needs a logged-in session.'; };
  img.src='api/stream?vmid='+wvm+'&src='+src+'&fps='+fps+'&t='+Date.now();
}
function stopWatch(){
  wvm=null;
  document.getElementById('wimg').src='';       // closes the MJPEG connection
  document.getElementById('watchcard').style.display='none';
}
async function payload(){
  try{
    const d=await (await fetch('api/payload')).json();
    const el=document.getElementById('pay');
    if(!d.kind){ el.innerHTML='<span style="color:#f85149">nothing staged &mdash; Create and Update will fail</span>'; return; }
    const mb=(d.size/1048576).toFixed(1);
    el.textContent=(d.tag?d.tag+'  ':'')+(d.asset||d.kind)+'  '+mb+' MB  ('+(d.fetched||d.mtime||'')+')';
  }catch(e){ document.getElementById('pay').textContent='could not read'; }
}
async function fetchDh(){
  const tag=document.getElementById('tag').value.trim();
  const r=await fetch('api/fetch',{method:'POST',body:JSON.stringify(tag?{tag}:{})});
  const d=await r.json(); jobId=d.id; document.getElementById('go').disabled=true; poll();
}
async function create(){
  const b=document.getElementById('go'); b.disabled=true;
  const body={name:document.getElementById('name').value,
    cores:+document.getElementById('cores').value, memory:+document.getElementById('memory').value,
    port:+document.getElementById('port').value,
    shell:document.getElementById('shell').value==='1', tls:document.getElementById('tls').value==='1'};
  const r=await fetch('api/create',{method:'POST',body:JSON.stringify(body)});
  const d=await r.json(); jobId=d.id; poll();
}
// Console recordings. The chunk being written right now is playable too --
// the recorder emits fragmented mp4 precisely so you can watch a sandbox's
// history without waiting eight hours for the file to close.
async function recordings(vmid,name){
  var card=document.getElementById('reccard');
  document.getElementById('rectitle').textContent='Console recordings: '+name+' (vmid '+vmid+')';
  document.getElementById('recrows').innerHTML='<tr><td colspan="3">loading&hellip;</td></tr>';
  card.style.display='block';
  card.scrollIntoView({behavior:'smooth'});
  try{
    const r=await fetch('api/recordings?vmid='+vmid);
    const d=await r.json();
    if(!d.enabled){
      document.getElementById('recnote').textContent='Recording is off: set recordings_dir in the controller config.';
      document.getElementById('recrows').innerHTML=''; return;
    }
    var st=(d.status||{})[String(vmid)];
    document.getElementById('recnote').textContent =
      (st&&st.recording ? ('recording now \u00b7 '+st.frames+' frames this chunk') : 'not currently recording')
      + ' \u00b7 8h chunks \u00b7 kept '+d.retention_days+' days'
      + (st&&st.error ? (' \u00b7 last error: '+st.error) : '');
    if(!d.items.length){ document.getElementById('recrows').innerHTML='<tr><td colspan="3" style="color:#8b93a1">Nothing recorded yet.</td></tr>'; return; }
    document.getElementById('recrows').innerHTML=d.items.map(function(it){
      var t=it.started, pretty=t.slice(0,4)+'-'+t.slice(4,6)+'-'+t.slice(6,8)+' '+t.slice(9,11)+':'+t.slice(11,13);
      var mb=(it.size/1048576).toFixed(1)+' MB';
      var live=(st&&st.file===it.file)?' <span class="badge">live</span>':'';
      // q, not a backslash-escaped quote: PAGE is a non-raw python string,
      // so a \' in this file never survives to the browser.
      var q=String.fromCharCode(39);
      return '<tr><td><code>'+pretty+'</code>'+live+'</td><td>'+mb+'</td>'
        +'<td style="text-align:right">'
        +'<button class="d" onclick="playrec('+q+it.file+q+')">Play</button> '
        +'<a href="api/recording?file='+it.file+'" download><button class="d">Download</button></a></td></tr>';
    }).join('');
  }catch(e){ document.getElementById('recrows').innerHTML='<tr><td colspan="3" style="color:#f85149">'+e.message+'</td></tr>'; }
}
function playrec(file){
  var v=document.getElementById('recplayer');
  v.style.display='block';
  v.src='api/recording?file='+file;
  v.play().catch(function(){});
  v.scrollIntoView({behavior:'smooth',block:'nearest'});
}
var agvm=null, MODEL_CTX={};
// Asked once and remembered: a claim nobody can be asked about is not a claim,
// and retyping your own name every time is how a feature gets skipped.
function whoAmI(quiet){
  var w='';
  try{ w=localStorage.getItem('sbx-who')||''; }catch(e){}
  if(w || quiet) return w;
  w=(prompt('Your name, so others know who holds a sandbox:')||'').trim().slice(0,60);
  if(w){ try{ localStorage.setItem('sbx-who',w); }catch(e){} }
  return w;
}
async function claimRow(vmid){
  var who=whoAmI();
  if(!who) return;
  var purpose=(prompt('What for? (optional, shown to whoever looks next)')||'').trim();
  try{
    const r=await fetch('api/claim',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({vmid:vmid,who:who,purpose:purpose,minutes:120})});
    const d=await r.json();
    if(d.error){ alert('Could not claim it: '+d.error); return; }
    refresh();
  }catch(e){ alert('Could not claim it: '+e.message); }
}
async function releaseRow(vmid){
  var who=whoAmI(true);
  try{
    const r=await fetch('api/claim',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({vmid:vmid,who:who,release:true})});
    const d=await r.json();
    if(d.error){ alert('Could not release it: '+d.error); return; }
    refresh();
  }catch(e){ alert('Could not release it: '+e.message); }
}
var ghvm=null;
// A newline with no escape anywhere: a template literal holding a real one.
// Every multi-line string below uses this or a backtick literal. Escape
// sequences are avoided on purpose here: PAGE is a non-raw Python string, so
// a backslash-n typed in this block is turned into a real line break before
// the browser ever sees it, which is a syntax error inside a quoted string.
var NL = `
`;
var GH_STARTERS={
  internals: `version: 1
extends: groundhog:windows-internals
`,
  sysinternals: `version: 1
extends: groundhog:sysinternals
`,
  apps: `version: 1
apps:
  - Git.Git
  - Microsoft.VisualStudioCode
verify:
  - command: git --version
`,
  // Single quotes, not a backtick literal: ${...} inside a template literal is
  // read as an interpolation, and this starter exists precisely to show a
  // secret reference. An array joined by NL needs no escape of any kind.
  secret: ['version: 1',
           'agent: ">=0.12.0"',
           'env:',
           '  EXAMPLE_TOKEN: "${secret:API_TOKEN}"',
           'verify:',
           '  - command: if (-not $env:EXAMPLE_TOKEN) { exit 1 }',
           ''].join(NL)
};
var GH_LIB=[];
async function ghLoadLibrary(){
  var sel=document.getElementById('gh_lib');
  try{
    const r=await fetch('api/groundhog/library');
    GH_LIB=await r.json();
    if(!GH_LIB.length){ sel.innerHTML='<option value="">(none shipped)</option>'; return; }
    sel.innerHTML='<option value="">(pick one)</option>'+GH_LIB.map(function(p,i){
      return '<option value="'+i+'">'+esc(p.name)+'</option>'; }).join('');
  }catch(e){ sel.innerHTML='<option value="">(could not load)</option>'; }
}
function ghLib(){
  var i=document.getElementById('gh_lib').value;
  var note=document.getElementById('gh_libnote');
  if(i===''){ note.innerHTML='&nbsp;'; return; }
  var p=GH_LIB[parseInt(i,10)];
  if(!p) return;
  document.getElementById('gh_body').value=p.content;
  document.getElementById('gh_tpl').value='';
  note.textContent=p.note||'';
}
function ghStarter(){
  var k=document.getElementById('gh_tpl').value;
  if(k && GH_STARTERS[k]) document.getElementById('gh_body').value=GH_STARTERS[k];
}
function ghPanel(vmid,name){
  ghvm=vmid;
  document.getElementById('ghtitle').textContent='Groundhog on '+name+' (vmid '+vmid+')';
  var c=document.getElementById('ghcard');
  c.style.display='block';
  c.scrollIntoView({behavior:'smooth'});
  if(!GH_LIB.length) ghLoadLibrary();
  if(!document.getElementById('gh_body').value.trim()){
    document.getElementById('gh_tpl').value='internals'; ghStarter();
  }
  ghRefresh();
}
async function ghRefresh(){
  var st=document.getElementById('ghstate'), out=document.getElementById('gh_out');
  st.textContent='reading the last run...';
  try{
    const r=await fetch('api/groundhog?vmid='+ghvm);
    const d=await r.json();
    if(d.error){ st.textContent='could not read it: '+d.error; return; }
    var bits=['last run: '+d.outcome];
    if(d.outcome==='reboot-pending')
      bits.push('waiting for a restart - reboot the sandbox and it continues at the next logon');
    if(d.failed_step) bits.push('failed at: '+d.failed_step+(d.failed_message?' - '+d.failed_message:''));
    st.textContent=bits.join(' - ');
    var run=d.run;
    if(run && run.steps && run.steps.length){
      var head = run.agent ? ('agent '+run.agent+'  '+(run.updated||'')+NL+NL) : '';
      out.textContent = head + run.steps.map(function(s){
        var mark = s.status==='done' ? '  ok  ' : s.status==='failed' ? ' FAIL ' : '  ..  ';
        return mark + s.title + (s.changed?'   (changed)':'')
               + (s.message ? NL+'        '+s.message : '');
      }).join(NL);
    } else if(d.status){ out.textContent=d.status; }
    else { out.textContent='No run recorded for this sandbox yet.'; }
  }catch(e){ st.textContent='could not read it: '+e.message; }
}
async function ghPost(extra){
  var body=Object.assign({
    vmid: ghvm,
    content: document.getElementById('gh_body').value,
    secrets: document.getElementById('gh_secrets').value,
    allow_reboot: document.getElementById('gh_reboot').checked
  }, extra||{});
  const r=await fetch('api/groundhog',{method:'POST',
    headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  return await r.json();
}
async function ghPlan(){
  var out=document.getElementById('gh_out');
  out.textContent='validating in the sandbox... plan resolves extends and downloads, so give it a moment.';
  try{
    const d=await ghPost({plan:true});
    if(d.error){ out.textContent='plan could not run: '+d.error; return; }
    out.textContent=(d.ok ? 'valid - these are the steps it would take:' : 'plan rejected it:')+NL+NL+d.output;
  }catch(e){ out.textContent='plan could not run: '+e.message; }
}
async function ghApply(){
  var out=document.getElementById('gh_out');
  out.textContent='applying... it runs in the sandbox, so this panel follows along.';
  try{
    const d=await ghPost({});
    if(d.error){ out.textContent='could not start the apply: '+d.error; return; }
    var n=0;
    var poll=setInterval(async function(){
      n++; await ghRefresh();
      var s=document.getElementById('ghstate').textContent||'';
      if(n>60 || /succeeded|failed|reboot-pending/.test(s)) clearInterval(poll);
    }, 5000);
    ghRefresh();
  }catch(e){ out.textContent='could not start the apply: '+e.message; }
}
function agentPanel(vmid,name){
  agvm=vmid;
  document.getElementById('agenttitle').textContent='Install agents in '+name+' (vmid '+vmid+')';
  var c=document.getElementById('agentcard');
  c.style.display='block';
  c.scrollIntoView({behavior:'smooth'});
  loadModels();
}
// Ask the endpoint what it has. Loaded models come back first, and one of those
// is pre-selected: picking a resident model is the difference between answering
// now and waiting for a cold load.
async function loadModels(){
  var note=document.getElementById('ag_models_note');
  var list=document.getElementById('ag_models');
  var url=document.getElementById('ag_url').value.trim();
  note.textContent='checking the endpoint\u2026';
  list.innerHTML='';
  try{
    const r=await fetch('api/models'+(url?('?base_url='+encodeURIComponent(url)):''));
    const d=await r.json();
    if(d.error){ note.textContent='could not reach '+(d.base_url||'the endpoint')+': '+d.error; return; }
    if(!d.models.length){ note.textContent=d.base_url?'no models reported by '+d.base_url:'no endpoint set'; return; }
    list.innerHTML=d.models.map(function(m){
      var gb=m.size_mb?(' \u00b7 '+(m.size_mb/1024).toFixed(1)+' GB'):'';
      var c=m.ctx_loaded||m.ctx_max;
      var ctx=c?(' \u00b7 '+(c>=1024?Math.round(c/1024)+'k':c)+' ctx'):'';
      return '<option value="'+m.id+'">'+(m.loaded?'loaded':'available')+ctx+gb+'</option>';
    }).join('');
    // Remember the served window so the install can tell Hermes where its
    // compression threshold really is.
    MODEL_CTX={}; d.models.forEach(function(m){ MODEL_CTX[m.id]=m.ctx_loaded||m.ctx_max||0; });
    var loaded=d.models.filter(function(m){return m.loaded;});
    var box=document.getElementById('ag_model');
    if(!box.value) box.value=(loaded[0]||d.models[0]).id;
    var pick=MODEL_CTX[box.value]||0;
    var warn=(pick&&pick<32768)?((pick>=1024?Math.round(pick/1024)+'k':pick)+
      ' context may be too small (Deskhand alone is ~83 tools)  \u00b7  '):'';
    note.textContent=warn+d.models.length+' model'+(d.models.length===1?'':'s')+' at '+d.base_url+
      (loaded.length?('  \u00b7  loaded: '+loaded.map(function(m){return m.id;}).join(', ')):'  \u00b7  none loaded');
  }catch(e){ note.textContent='could not list models: '+e.message; }
}
async function installAgents(){
  if(!agvm) return;
  var list=[];
  if(document.getElementById('ag_hermes').checked) list.push('hermes');
  if(document.getElementById('ag_opencode').checked) list.push('opencode');
  if(!list.length){ alert('Pick at least one agent.'); return; }
  document.getElementById('agentcard').style.display='none';
  const body={vmid:agvm,agents:list};
  var u=document.getElementById('ag_url').value.trim();
  var k=document.getElementById('ag_key').value.trim();
  var md=document.getElementById('ag_model').value.trim();
  if(u) body.base_url=u;
  if(k) body.api_key=k;
  if(md) body.model=md;
  if(MODEL_CTX[md]) body.context_length=MODEL_CTX[md];
  const r=await fetch('api/agents',{method:'POST',body:JSON.stringify(body)});
  const d=await r.json(); jobId=d.id; poll();
}
async function upd(vmid){
  const r=await fetch('api/update',{method:'POST',body:JSON.stringify({vmid})});
  const d=await r.json(); jobId=d.id; poll();
}
async function rep(vmid){
  const r=await fetch('api/repair',{method:'POST',body:JSON.stringify({vmid})});
  const d=await r.json(); jobId=d.id; document.getElementById('go').disabled=true; poll();
}
async function destroy(vmid){
  if(!confirm('Permanently destroy sandbox '+vmid+'? This cannot be undone.'))return;
  const r=await fetch('api/destroy',{method:'POST',body:JSON.stringify({vmid})});
  const d=await r.json(); jobId=d.id; poll();
}
async function poll(){
  if(!jobId)return;
  const r=await fetch('api/job?id='+jobId); const j=await r.json();
  document.getElementById('jobcard').style.display='block';
  document.getElementById('jobtitle').textContent=j.title+'  ('+j.elapsed+'s)';
  let t=j.lines.join('\\n');
  if(j.done&&j.result&&j.result.url)t+='\\n\\nOPEN: '+j.result.url+'\\nTOKEN: '+j.result.token;
  document.getElementById('joblog').textContent=t;
  if(j.done){document.getElementById('go').disabled=false; jobId=null; refresh(); payload(); return;}
  if(jobId) setTimeout(poll,2000);
}
async function resume(){
  // The job lives on the server, so a refresh -- or a different tab -- can pick
  // up work already in flight instead of losing sight of it.
  try{
    const r=await fetch('api/jobs'); const js=await r.json();
    if(!js.length) return;
    const running=js.find(j=>!j.done);
    const target=running||js[0];
    jobId=target.id;
    if(running) document.getElementById('go').disabled=true;
    poll();
    if(!running) jobId=null;
  }catch(e){}
}
showHub(); refresh(); payload(); resume(); setInterval(()=>{if(!jobId){refresh();payload();}},10000);
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} {fmt % args}", flush=True)

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        host = self.headers.get("Host")
        # Discovery surfaces for agents. An AI handed this URL will usually
        # fetch it with a non-browser Accept header, so the root serves the
        # plain-text guide to anything that did not ask for HTML.
        if p.path == "/llms.txt":
            return self._send(200, agent_guide(host), "text/plain; charset=utf-8")
        if p.path == "/.well-known/agent.json":
            return self._send(200, json.dumps(agent_card(host), indent=2))
        if p.path == "/.well-known/mcp.json":
            return self._send(200, json.dumps({"mcpServers": {"sandboxctl": {
                "type": "http", "url": "http://%s/mcp" % (host or "this-host")}}}, indent=2))
        if p.path in ("/", "/index.html") and "text/html" not in (self.headers.get("Accept") or ""):
            return self._send(200, agent_guide(host), "text/plain; charset=utf-8")
        if p.path in ("/", "/index.html"):
            return self._send(200, PAGE.replace("@@PVEHOST@@", HOST)
                              .replace("@@PVENODE@@", NODE)
                              .replace("@@AGENT_BASEURL@@",
                                       html.escape(AGENTS_CFG.get("base_url") or "", quote=True))
                              .replace("@@AGENT_MODEL@@",
                                       html.escape((AGENTS_CFG.get("hermes") or {}).get("model") or "",
                                                   quote=True)),
                              "text/html; charset=utf-8")
        if p.path == "/api/history":
            q = urllib.parse.parse_qs(p.query)
            vmid = (q.get("vmid") or [None])[0]
            if vmid is None:
                return self._send(400, json.dumps({"error": "vmid is required"}))
            guest = (q.get("guest") or ["1"])[0] not in ("0", "false")
            try:
                return self._send(200, json.dumps(sandbox_history(vmid, guest)))
            except Exception as exc:                  # noqa: BLE001
                return self._send(400, json.dumps({"error": str(exc)}))
        if p.path == "/api/comments":
            q = urllib.parse.parse_qs(p.query)
            vmid = (q.get("vmid") or [None])[0]
            if vmid is None:
                return self._send(400, json.dumps({"error": "vmid is required"}))
            if (q.get("archived") or ["0"])[0] in ("1", "true"):
                return self._send(200, json.dumps(get_archive(vmid)))
            return self._send(200, json.dumps(get_comments(vmid)))
        if p.path == "/api/expiry":
            try:
                return self._send(200, json.dumps(
                    {k: get_expiry(k) for k in _expiry_load()}))
            except Exception as exc:                  # noqa: BLE001
                return self._send(500, json.dumps({"error": str(exc)}))
        if p.path == "/api/groundhog/library":
            try:
                return self._send(200, json.dumps(groundhog_library()))
            except Exception as exc:                  # noqa: BLE001
                return self._send(500, json.dumps({"error": str(exc)}))
        if p.path == "/api/groundhog":
            try:
                vmid = urllib.parse.parse_qs(p.query).get("vmid", [""])[0]
                return self._send(200, json.dumps(groundhog_status(int(vmid))))
            except Exception as exc:                  # noqa: BLE001
                return self._send(400, json.dumps({"error": str(exc)}))
        if p.path in ("/favicon.svg", "/favicon.ico"):
            # The same icon the page embeds. .ico is answered with an
            # SVG on purpose: every browser that asks for it by that name
            # accepts one, and it saves carrying a second format.
            body = base64.b64decode(FAVICON_B64)
            self.send_response(200)
            self.send_header("Content-Type", "image/svg+xml")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "max-age=86400")
            self.end_headers()
            self.wfile.write(body)
            return
        if p.path == "/api/capacity":
            try:
                return self._send(200, json.dumps(capacity()))
            except Exception as exc:                  # noqa: BLE001
                return self._send(500, json.dumps({"error": str(exc)}))
        if p.path == "/api/sandboxes":
            try:
                return self._send(200, json.dumps([_sandbox_view(e) for e in list_sandboxes()]))
            except Exception as exc:                  # noqa: BLE001
                return self._send(500, json.dumps({"error": str(exc)}))
        if p.path == "/api/recordings":
            if not RECORDER:
                return self._send(200, json.dumps({"enabled": False, "items": []}))
            q = urllib.parse.parse_qs(p.query)
            vmid = q.get("vmid", [None])[0]
            return self._send(200, json.dumps({
                "enabled": True,
                "retention_days": REC_RETENTION_DAYS,
                "status": {str(k): v for k, v in RECORDER.status().items()},
                "items": RECORDER.listing(vmid)}))
        if p.path == "/api/recording":
            # Serve a chunk for playback/download. Name-checked, not path-joined
            # from user input: the filename pattern is the whole allowlist.
            q = urllib.parse.parse_qs(p.query)
            fn = (q.get("file", [""])[0] or "").strip()
            if not RECORDER or not recorder.NAME_RE.match(fn):
                return self._send(404, json.dumps({"error": "no such recording"}))
            path = os.path.join(REC_DIR, fn)
            if not os.path.isfile(path):
                return self._send(404, json.dumps({"error": "no such recording"}))
            size = os.path.getsize(path)
            self.send_response(200)
            self.send_header("Content-Type", "video/mp4")
            self.send_header("Content-Length", str(size))
            self.send_header("Content-Disposition", f'inline; filename="{fn}"')
            self.end_headers()
            with open(path, "rb") as fh:
                while True:
                    buf = fh.read(256 * 1024)
                    if not buf:
                        break
                    self.wfile.write(buf)
            return
        if p.path == "/api/models":
            q = urllib.parse.parse_qs(p.query)
            base = (q.get("base_url", [""])[0] or AGENTS_CFG.get("base_url") or "").strip()
            if not base:
                return self._send(200, json.dumps({"models": [], "base_url": ""}))
            try:
                return self._send(200, json.dumps(
                    {"models": fetch_models(base), "base_url": base}))
            except Exception as exc:                   # noqa: BLE001
                # A wrong or unreachable endpoint is a normal thing to type, so
                # it is reported in the panel rather than raised as an error.
                return self._send(200, json.dumps(
                    {"models": [], "base_url": base, "error": str(exc)[:200]}))
        if p.path in ("/api/stream", "/api/screen"):
            q = urllib.parse.parse_qs(p.query)
            record_event((q.get("vmid") or [None])[0],
                         "screenshot taken" if p.path == "/api/screen" else "screen streamed")
            try:
                vmid = _check_managed(q.get("vmid", [""])[0])
            except Exception as exc:                   # noqa: BLE001
                return self._send(400, json.dumps({"error": str(exc)}))
            src = (q.get("src", ["vnc"])[0] or "vnc").lower()
            fps = max(1, min(10, int(q.get("fps", ["2"])[0] or 2)))
            single = p.path == "/api/screen"

            def deskhand_target():
                for e in list_sandboxes():
                    if e["vmid"] == vmid and e.get("ip") and e.get("token"):
                        return e
                raise RuntimeError("Deskhand is not reachable on this sandbox; use src=vnc")

            try:
                if single:
                    if src == "deskhand":
                        e = deskhand_target()
                        jpg = live.deskhand_frame(e["ip"], e.get("port", 8791), e["token"])
                    else:
                        # Prefer the recorder's own frame. Proxmox serves one
                        # VNC session per VM well and a second one poorly: a
                        # screenshot opened alongside a running recorder gets
                        # starved of framebuffer updates and comes back black.
                        jpg = RECORDER.latest(vmid) if RECORDER else None
                        if jpg is None:
                            sess = live.open_vnc(api, NODE, vmid, HOST)
                            try:
                                jpg = sess.frame(incremental=False)
                            finally:
                                sess.close()
                    self.send_response(200)
                    self.send_header("Content-Type", "image/jpeg")
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("Content-Length", str(len(jpg)))
                    self.end_headers()
                    self.wfile.write(jpg)
                    return
            except Exception as exc:                   # noqa: BLE001
                return self._send(502, json.dumps({"error": str(exc)}))

            # MJPEG: every browser plays this in a plain <img>, no player needed.
            self.send_response(200)
            self.send_header("Content-Type", "multipart/x-mixed-replace; boundary=frame")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            sess = None
            try:
                if src == "vnc":
                    sess = live.open_vnc(api, NODE, vmid, HOST)
                deadline = time.time() + 900           # cap a forgotten tab
                while time.time() < deadline:
                    if src == "deskhand":
                        e = deskhand_target()
                        jpg = live.deskhand_frame(e["ip"], e.get("port", 8791), e["token"])
                    else:
                        # Poll for changes, then always emit the current canvas so
                        # the viewer keeps ticking on an idle desktop.
                        sess.pump(min(0.5, 1.0 / fps))
                        jpg = sess.jpeg()
                    self.wfile.write(b"--frame\r\nContent-Type: image/jpeg\r\n"
                                     + f"Content-Length: {len(jpg)}\r\n\r\n".encode())
                    self.wfile.write(jpg)
                    self.wfile.write(b"\r\n")
                    time.sleep(1.0 / fps)
            except (BrokenPipeError, ConnectionResetError):
                pass                                   # viewer closed the tab
            except Exception as exc:                   # noqa: BLE001
                print(f"stream {vmid} ended: {exc}", flush=True)
            finally:
                if sess:
                    sess.close()
            return
        if p.path == "/api/payload":
            kind = artifact_kind()
            info = {"kind": kind}
            mp = os.path.join(HERE, "payload", "meta.json")
            if os.path.isfile(mp):
                try:
                    info.update(json.load(open(mp)))
                except Exception:
                    pass
            if kind:
                f = os.path.join(HERE, "payload",
                                 "deskhand.zip" if kind == "zip" else "Deskhand.msi")
                info["size"] = os.path.getsize(f)
                info["mtime"] = time.strftime("%Y-%m-%d %H:%M",
                                              time.localtime(os.path.getmtime(f)))
            return self._send(200, json.dumps(info))
        if p.path == "/api/jobs":
            with JOBS_LOCK:
                jobs = sorted(JOBS.values(), key=lambda j: j.started, reverse=True)[:20]
            return self._send(200, json.dumps([
                {"id": j.id, "title": j.title, "done": j.done, "failed": j.failed,
                 "elapsed": int(time.time() - j.started),
                 "last": j.lines[-1] if j.lines else ""} for j in jobs]))
        if p.path == "/api/job":
            jid = urllib.parse.parse_qs(p.query).get("id", [""])[0]
            with JOBS_LOCK:
                job = JOBS.get(jid)
            return self._send(200 if job else 404,
                              json.dumps(job.as_dict() if job else {"error": "no such job"}))
        if p.path.startswith("/payload/"):
            # Served to the sandboxes themselves; this is the one thing they are
            # allowed to reach on the LAN.
            fn = os.path.basename(p.path)
            full = os.path.join(HERE, "payload", fn)
            if not os.path.isfile(full):
                return self._send(404, json.dumps({"error": "not found"}))
            size = os.path.getsize(full)
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(size))
            self.end_headers()
            with open(full, "rb") as fh:
                while chunk := fh.read(262144):
                    self.wfile.write(chunk)
            return
        return self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        p = urllib.parse.urlparse(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            body = {}
        if p.path == "/api/create":
            opts = {
                "name": (body.get("name") or "").strip() or None,
                "cores": int(body.get("cores") or 4),
                "memory": int(body.get("memory") or 8192),
                "port": int(body.get("port") or 8791),
                "shell": bool(body.get("shell", True)),
                "tls": bool(body.get("tls", False)),
            }
            if not opts["name"]:
                opts["name"] = f"sandbox-{int(time.time()) % 100000}"
            # Windows truncates hostnames past 15 chars, which leaves the Proxmox
            # name and the DNS name disagreeing.
            opts["name"] = re.sub(r"[^A-Za-z0-9-]", "-", opts["name"])[:15]
            job = start_job(f"Creating {opts['name']}", do_create, opts)
            return self._send(200, json.dumps({"id": job.id}))
        if p.path == "/mcp":
            # Streamable HTTP: a batch is a JSON array, a single call an object.
            msgs = body if isinstance(body, list) else [body]
            host = self.headers.get("Host")
            replies = [r for r in (handle_mcp(m, host) for m in msgs) if r is not None]
            if not replies:
                self.send_response(202)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            out = replies if isinstance(body, list) else replies[0]
            return self._send(200, json.dumps(out))
        if p.path == "/api/groundhog":
            # One route, two verbs of its own: validate, or apply. Validation is
            # separate because it is the cheap half and changes nothing.
            try:
                vmid = int(body.get("vmid"))
                content = body.get("content")
                source = (body.get("source") or "").strip()
                if content and not source:
                    source = groundhog_write_adhoc(vmid, content)
                if not source:
                    raise ValueError("pass a Groundhogfile or a source to fetch one from")
                if body.get("plan"):
                    return self._send(200, json.dumps(groundhog_plan(vmid, source)))
                secrets = {}
                for line in (body.get("secrets") or "").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    k, sep, v = line.partition("=")
                    if not sep:
                        raise ValueError(f"secrets want NAME=value, got {line[:40]!r}")
                    secrets[k.strip()] = v.strip()
                return self._send(200, json.dumps(apply_groundhog(
                    vmid, source, body.get("sha256"), None,
                    bool(body.get("allow_reboot")), None, secrets=secrets or None)))
            except Exception as exc:                  # noqa: BLE001
                return self._send(400, json.dumps({"error": str(exc)}))
        if p.path == "/api/claim":
            try:
                if body.get("release"):
                    return self._send(200, json.dumps(
                        release_sandbox(body.get("vmid"), body.get("who"))))
                return self._send(200, json.dumps(claim_sandbox(
                    body.get("vmid"), body.get("who"), body.get("purpose"),
                    body.get("minutes"))))
            except Exception as exc:                  # noqa: BLE001
                return self._send(400, json.dumps({"error": str(exc)}))
        if p.path == "/api/comment":
            try:
                entry = add_comment(body.get("vmid"), body.get("text"),
                                    body.get("author"), via="web",
                                    addr=self.client_address[0])
                record_event(body.get("vmid"), "note added", entry["author"])
                return self._send(200, json.dumps(entry))
            except Exception as exc:                  # noqa: BLE001
                return self._send(400, json.dumps({"error": str(exc)}))
        if p.path == "/api/fetch":
            job = start_job("Fetching Deskhand", do_fetch, (body.get("tag") or None))
            return self._send(200, json.dumps({"id": job.id}))
        if p.path == "/api/agents":
            opts = {k: body.get(k) for k in ("base_url", "api_key", "model", "context_length")
                    if body.get(k)}
            job = start_job(f"Installing agents on {body.get('vmid')}",
                            do_install_agents, body.get("vmid"), body.get("agents") or [], opts)
            return self._send(200, json.dumps({"id": job.id}))
        if p.path == "/api/repair":
            job = start_job(f"Repairing {body.get('vmid')}", do_repair, body.get("vmid"))
            return self._send(200, json.dumps({"id": job.id}))
        if p.path == "/api/update":
            job = start_job(f"Updating {body.get('vmid')}", do_update, body.get("vmid"))
            return self._send(200, json.dumps({"id": job.id}))
        if p.path == "/api/destroy":
            job = start_job(f"Destroying {body.get('vmid')}", do_destroy, body.get("vmid"))
            return self._send(200, json.dumps({"id": job.id}))
        return self._send(404, json.dumps({"error": "not found"}))


class PayloadHandler(BaseHTTPRequestHandler):
    """Read-only static file server for the Deskhand payload.

    Deliberately implements nothing else -- no control API, no MCP, no listing.
    This is the only surface a sandbox is allowed to reach.
    """
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print(f"payload {self.address_string()} {fmt % args}", flush=True)

    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        if not p.path.startswith("/payload/"):
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        fn = os.path.basename(p.path)
        full = os.path.join(HERE, "payload", fn)
        if not os.path.isfile(full):
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(os.path.getsize(full)))
        self.end_headers()
        with open(full, "rb") as fh:
            while chunk := fh.read(262144):
                self.wfile.write(chunk)

    def do_POST(self):
        self.send_response(405)
        self.send_header("Content-Length", "0")
        self.end_headers()


if __name__ == "__main__":
    pay = ThreadingHTTPServer((PAYLOAD_LISTEN[0], int(PAYLOAD_LISTEN[1])), PayloadHandler)
    threading.Thread(target=pay.serve_forever, daemon=True).start()
    print(f"payload  listening on {PAYLOAD_LISTEN[0]}:{PAYLOAD_LISTEN[1]} (sandbox-facing, read-only)", flush=True)

    n = publish_groundhog_library()
    if n:
        print(f"groundhog library: {n} profile(s) published to the payload port", flush=True)

    threading.Thread(target=reaper_loop, daemon=True).start()
    print("expiry reaper running (default "
          + (f"{TTL_DEFAULT_MINUTES} min" if TTL_DEFAULT_MINUTES else "never")
          + ")", flush=True)

    if RECORDER:
        threading.Thread(target=recorder_loop, daemon=True).start()
        print(f"recording consoles to {REC_DIR} "
              f"(8h chunks, {REC_RETENTION_DAYS}d retention)", flush=True)

    srv = ThreadingHTTPServer((LISTEN[0], int(LISTEN[1])), Handler)
    _jobs_load()
    stale = [j for j in JOBS.values() if j.failed and any("INTERRUPTED" in l for l in j.lines)]
    if stale:
        print(f"  {len(stale)} job(s) were interrupted by a restart; see the dashboard", flush=True)
    print(f"sandboxctl listening on {LISTEN[0]}:{LISTEN[1]}  template={TEMPLATE} pool={POOL}", flush=True)
    srv.serve_forever()
