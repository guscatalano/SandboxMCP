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

    def log(self, msg):
        self.lines.append(f"{time.strftime('%H:%M:%S')}  {msg}")

    def as_dict(self):
        return {"id": self.id, "title": self.title, "lines": self.lines,
                "done": self.done, "failed": self.failed, "result": self.result,
                "elapsed": int(time.time() - self.started)}


MAX_JOBS = 50


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
    for m in members:
        if m.get("type") != "qemu":
            continue
        vmid = m["vmid"]
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


def read_token(vmid, refresh=False):
    """Recover a sandbox's Deskhand token from its launcher, so the UI can always
    show it. Without this the token would exist only in the creation log."""
    if not refresh and vmid in _TOKEN_CACHE:
        return _TOKEN_CACHE[vmid]
    m = re.search(r"DESKHAND_TOKEN\s*=\s*'([^']+)'", read_launcher(vmid))
    tok = m.group(1) if m else None
    if tok:
        _TOKEN_CACHE[vmid] = tok
    return tok


def free_vmid(skip=()):
    """Lowest free id in the sandbox range, judged from pool membership.

    Deliberately NOT from /cluster/resources: this service's token can only see
    its own pool, so that call would need read access to every guest on the
    cluster. The range is reserved for sandboxes, so pool membership is the
    right source -- and if something outside the pool has squatted an id, the
    clone fails and do_create simply tries the next one.
    """
    used = {m["vmid"] for m in (api(f"/pools/{POOL}").get("members") or [])}
    used |= set(skip)
    for i in range(ID_LO, ID_HI + 1):
        if i not in used:
            return i
    raise RuntimeError(f"no free VMID in {ID_LO}-{ID_HI}")


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
schtasks /End /TN Deskhand 2>$null | Out-Null
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
schtasks /Run /TN Deskhand | Out-Null
Write-Output 'INSTALLED'
"""


def do_create(job, opts):
    name = opts["name"]
    # An id can be taken by something outside the pool, which this token cannot
    # see. Rather than demand cluster-wide read access, just try the next one.
    tried = []
    for _ in range(6):
        vmid = free_vmid(skip=tried)
        job.log(f"allocating VMID {vmid} ({name})")
        try:
            api(f"/nodes/{NODE}/qemu/{TEMPLATE}/clone", "POST", {
                "newid": vmid, "name": name, "full": 0, "pool": POOL}, timeout=120)
            break
        except Exception as exc:                      # noqa: BLE001
            if "already exists" not in str(exc).lower() and "config file" not in str(exc).lower():
                raise
            job.log(f"  {vmid} is taken by something outside the pool; trying the next")
            tried.append(vmid)
    else:
        raise RuntimeError("could not find a free VMID")
    wait_unlocked(vmid)
    job.log("cloned from template")

    provision(job, vmid, opts)

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
            "description": "SANDBOX - disposable, not backed up. Created by sandboxctl."})

    if (vm("/status/current", vmid=vmid) or {}).get("status") != "running":
        vm("/status/start", "POST", vmid=vmid)
    job.log("started; waiting for the guest agent")
    wait_agent(vmid)

    wait_oobe(job, vmid)

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
              .replace("@@USER@@", WIN_USER))
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


def do_destroy(job, vmid):
    vmid = _check_managed(vmid)
    if (vm("/status/current", vmid=vmid) or {}).get("status") == "running":
        job.log("stopping")
        vm("/status/stop", "POST", vmid=vmid)
        for _ in range(60):
            time.sleep(3)
            if (vm("/status/current", vmid=vmid) or {}).get("status") == "stopped":
                break
    _TOKEN_CACHE.pop(vmid, None)
    clear_agent_state(vmid)
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
                        "On demand: Hermes alone is a ~2 GB install. Returns a job id."),
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
            "description": "Check a create_sandbox or destroy_sandbox job. Returns its log, completion state and result.",
        "inputSchema": {
            "type": "object",
            "properties": {"id": {"type": "string"}},
            "required": ["id"],
        },
    },
]




# Updating an existing sandbox in place. The launcher (run-deskhand.ps1) is NOT
# in the zip -- it is generated at install time and holds the token, port and
# feature flags -- so extracting over the directory leaves it untouched and the
# sandbox keeps the same token. That matters: a changed token would silently
# break whatever MCP client is already pointed at this box.



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
        Set-Content $runner -Value $dash -Encoding UTF8
        $da = New-ScheduledTaskAction -Execute 'powershell.exe' `
              -Argument ('-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $runner + '"')
        $dt = New-ScheduledTaskTrigger -AtLogOn -User '@@WINUSER@@'
        $dp = New-ScheduledTaskPrincipal -UserId '@@WINUSER@@' -LogonType Interactive -RunLevel Limited
        # It is a server, so no execution time limit; and bring it back if it
        # exits on its own rather than leaving it down until the next logon.
        $ds = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
              -ExecutionTimeLimit ([TimeSpan]::Zero) `
              -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
        Register-ScheduledTask -TaskName 'HermesDashboard' -Action $da -Trigger $dt `
              -Principal $dp -Settings $ds -Force | Out-Null

        # Stop the previous instance and WAIT for the scheduler to agree it has
        # stopped. Start-ScheduledTask against a task the scheduler still counts
        # as Running is silently ignored -- so killing the process and starting
        # in the same breath took the dashboard down and never brought it back.
        Stop-ScheduledTask -TaskName 'HermesDashboard' -ErrorAction SilentlyContinue
        Get-Process hermes -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        $stopBy = (Get-Date).AddSeconds(30)
        while ((Get-ScheduledTask -TaskName 'HermesDashboard').State -eq 'Running' -and (Get-Date) -lt $stopBy) {
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
              .replace("@@USER@@", WIN_USER))
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
        "$a = New-ScheduledTaskAction -Execute 'powershell.exe' "
        "-Argument '-NoProfile -ExecutionPolicy Bypass -File \"" + ps1 + "\"'\n"
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
                   "todo", "clarify", "vision"]
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
    if opts.get("context_length"):
        try:
            cfg["hermes"]["context_length"] = int(opts["context_length"])
        except (TypeError, ValueError):
            pass
    cfg["hermes"].setdefault("disable_toolsets", DEFAULT_OFF)

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
    if e.get("ip") and e.get("token"):
        out["deskhand_url"] = f"http://{e['ip']}:{port}/?token={e['token']}"
        out["mcp_url"] = f"http://{e['ip']}:{port}/mcp"
        out["mcp_auth_header"] = f"Authorization: Bearer {e['token']}"
    return out


def mcp_call(name, args):
    if name == "list_sandboxes":
        return [_sandbox_view(e) for e in list_sandboxes()]
    if name == "create_sandbox":
        opts = {
            "name": (args.get("name") or "").strip() or f"sandbox-{int(time.time()) % 100000}",
            "cores": int(args.get("cores") or 4),
            "memory": int(args.get("memory") or 8192),
            "port": int(args.get("port") or 8791),
            "shell": bool(args.get("shell", True)),
            "tls": bool(args.get("tls", False)),
        }
        opts["name"] = re.sub(r"[^A-Za-z0-9-]", "-", opts["name"])[:15]
        job = start_job(f"Creating {opts['name']}", do_create, opts)
        return {"job_id": job.id, "note": "poll job_status; expect roughly 5 minutes"}
    if name == "destroy_sandbox":
        vmid = args.get("vmid")
        if vmid is None:
            raise ValueError("vmid is required")
        job = start_job(f"Destroying {vmid}", do_destroy, vmid)
        return {"job_id": job.id}
    if name == "fetch_deskhand":
        job = start_job("Fetching Deskhand", do_fetch, args.get("tag"))
        return {"job_id": job.id}
    if name == "repair_sandbox":
        vmid = args.get("vmid")
        if vmid is None:
            raise ValueError("vmid is required")
        job = start_job(f"Repairing {vmid}", do_repair, vmid)
        return {"job_id": job.id}
    if name == "update_sandbox":
        vmid = args.get("vmid")
        if vmid is None:
            raise ValueError("vmid is required")
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
        with JOBS_LOCK:
            job = JOBS.get(args.get("id"))
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


def handle_mcp(msg):
    """Handle one JSON-RPC message. Returns a response dict, or None for notifications."""
    mid = msg.get("id")
    method = msg.get("method")

    if method == "initialize":
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": (msg.get("params") or {}).get("protocolVersion") or MCP_PROTOCOL,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "sandboxctl", "version": "1.0"}}}
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

<div class="card"><table id="tbl"><thead><tr>
<th>VMID</th><th>Name</th><th>Status</th><th>Address</th><th>Open</th><th></th>
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
  m.push(`<button class="d badish" onclick="destroy(${s.vmid})">Destroy</button>`);
  return `<button class="d" style="color:#a371f7;border-color:#a371f7" onclick="watch(${s.vmid},'${s.name}')">Watch</button>
    <button class="d" style="color:#58a6ff;border-color:#58a6ff" onclick="agentPanel(${s.vmid},'${s.name}')">Agents</button>
    <details class="menu"><summary>&#8943;</summary><div class="mi">${m.join('')}</div></details>`;
}
function row(s){
  return `<tr><td><code>${s.vmid}</code></td><td>${s.name}</td>
    <td><span class="st ${s.status==='running'?'r':'s'}"></span>${s.status}</td>
    <td>${s.ip?`<code>${s.ip}</code>`:'&mdash;'}</td>
    <td><div class="lnk">${links(s)}</div></td>
    <td style="text-align:right">${actions(s)}</td></tr>`;
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
async function refresh(){
 try{
  const r=await fetch('api/sandboxes');
  if(!r.ok) throw new Error('HTTP '+r.status);
  const d=await r.json();
  document.getElementById('rows').innerHTML = d.length ? d.map(row).join('')
    : '<tr><td colspan="6" style="color:#8b93a1">No sandboxes yet.</td></tr>';
 }catch(e){
  document.getElementById('rows').innerHTML =
    '<tr><td colspan="7" style="color:#f85149">Could not load: '+e.message+'</td></tr>';
 }
}
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
var agvm=null, MODEL_CTX={};
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
        if p.path in ("/", "/index.html"):
            return self._send(200, PAGE.replace("@@PVEHOST@@", HOST)
                              .replace("@@PVENODE@@", NODE)
                              .replace("@@AGENT_BASEURL@@",
                                       html.escape(AGENTS_CFG.get("base_url") or "", quote=True))
                              .replace("@@AGENT_MODEL@@",
                                       html.escape((AGENTS_CFG.get("hermes") or {}).get("model") or "",
                                                   quote=True)),
                              "text/html; charset=utf-8")
        if p.path == "/api/sandboxes":
            try:
                return self._send(200, json.dumps(list_sandboxes()))
            except Exception as exc:                  # noqa: BLE001
                return self._send(500, json.dumps({"error": str(exc)}))
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
            replies = [r for r in (handle_mcp(m) for m in msgs) if r is not None]
            if not replies:
                self.send_response(202)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            out = replies if isinstance(body, list) else replies[0]
            return self._send(200, json.dumps(out))
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

    srv = ThreadingHTTPServer((LISTEN[0], int(LISTEN[1])), Handler)
    print(f"sandboxctl listening on {LISTEN[0]}:{LISTEN[1]}  template={TEMPLATE} pool={POOL}", flush=True)
    srv.serve_forever()
