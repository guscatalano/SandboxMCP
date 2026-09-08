"""A small WindowsAgentArena runner that scores agents on our own sandboxes.

WAA ships its tasks as JSON: a `config` block that sets the machine up, an
instruction for the agent, then a `postconfig` block and a *getter* that reads
the machine back to decide pass/fail. Upstream those getters call a Python
server baked into their golden image, which is the main reason running WAA
means adopting their whole VM stack -- Docker, QEMU-in-Docker, a 30 GB image.

We already have that server: Deskhand. It runs in the sandbox, speaks HTTP, and
exposes shell, filesystem and UI Automation. So this runner keeps WAA's task
files and validation semantics verbatim and swaps only the transport, which
means our sandboxes, our snapshots and our console recording come along for
free -- every failed task leaves a video behind, which upstream cannot do.

Scores from this are NOT leaderboard-comparable: it is a subset, and a getter
reimplemented against a different API is a reimplementation. It is meant to
answer "did my change help?", not "where do I rank?".

    python runner.py --agent null
    python runner.py --agent hermes --tasks tasks/clock__*.json
"""
import argparse
import base64
import fnmatch
import glob
import io
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))

# The sandbox is reachable on the SDN; the controller host is the natural place
# to run this from. Override for a different sandbox.
DESKHAND_URL = os.environ.get("DESKHAND_URL", "http://10.66.0.100:8791/mcp")
DESKHAND_TOKEN = os.environ.get("DESKHAND_TOKEN", "")


class TaskError(Exception):
    """Raised when a task cannot be run at all, as distinct from failing."""


# --------------------------------------------------------------------------
# Deskhand transport
# --------------------------------------------------------------------------
class Deskhand:
    """Minimal MCP client. Deskhand answers over Streamable HTTP, so a response
    arrives as SSE-style `data:` lines rather than a plain JSON body."""

    def __init__(self, url=DESKHAND_URL, token=DESKHAND_TOKEN, timeout=120):
        self.url = url + ("?token=" + token if token else "")
        self.timeout = timeout
        self._id = 0

    def call(self, tool, args=None):
        self._id += 1
        body = json.dumps({
            "jsonrpc": "2.0", "id": self._id, "method": "tools/call",
            "params": {"name": tool, "arguments": args or {}},
        }).encode("utf-8")
        req = urllib.request.Request(self.url, data=body, headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        })
        try:
            raw = urllib.request.urlopen(req, timeout=self.timeout).read().decode("utf-8", "replace")
        except urllib.error.URLError as exc:
            raise TaskError(f"deskhand unreachable at {self.url}: {exc}")

        payload = None
        for line in raw.splitlines():
            if line.startswith("data: "):
                payload = json.loads(line[6:])
                break
        if payload is None:                       # plain JSON response
            payload = json.loads(raw)
        if "error" in payload:
            raise TaskError(f"{tool}: {payload['error']}")

        content = (payload.get("result") or {}).get("content") or []
        if not content:
            return None
        text = content[0].get("text", "")
        try:
            return json.loads(text)
        except ValueError:
            return text

    # -- conveniences used by steps and getters ---------------------------
    def windows(self):
        """Win32 enumeration. Deliberately not list_windows: the UIA list misses
        owned pop-ups, which is exactly where dialogs and nags live."""
        return self.call("deskhand_list_windows_all") or []

    def shell(self, command, timeout_ms=60000):
        return self.call("deskhand_run_command",
                         {"command": command, "timeoutMs": timeout_ms}) or {}

    def read_file(self, path):
        """Returns file bytes, or None when the file does not exist."""
        r = self.call("deskhand_read_file", {"path": path}) or {}
        if r.get("error") or not r.get("base64"):
            return None
        return base64.b64decode(r["base64"])


# Anything larger than this stalls on the way to the sandbox and dies with a
# broken pipe after ~295 s. Measured by bisection: 32 KB succeeds instantly,
# 128 KB never arrives, and BOTH the MCP write_file tool and Deskhand's own
# multipart /fs/upload fail identically -- so this is the network path between
# the controller and the SDN, almost certainly a path-MTU black hole, not a
# limit in Deskhand. Chunking sidesteps it without touching the network.
CHUNK_BYTES = 32 * 1024


def put_file(path, blob):
    """Place bytes in the guest, in chunks small enough to survive the path.

    Parts go over as separate small writes and are joined guest-side, because
    a single large body never lands. Slower than one upload, but it is the
    difference between the download-heavy tasks running and not.
    """
    dh = Deskhand(timeout=120)
    if len(blob) <= CHUNK_BYTES:
        dh.call("deskhand_write_file", {
            "path": path, "contentBase64": base64.b64encode(blob).decode(),
            "overwrite": True})
        return len(blob)

    parts = [blob[i:i + CHUNK_BYTES] for i in range(0, len(blob), CHUNK_BYTES)]
    for n, chunk in enumerate(parts):
        dh.call("deskhand_write_file", {
            "path": "%s.part%03d" % (path, n),
            "contentBase64": base64.b64encode(chunk).decode(),
            "overwrite": True})

    lit = json.dumps(path)
    joined = dh.shell(
        "$out=[IO.File]::Create(%s); "
        "Get-ChildItem -LiteralPath (Split-Path %s -Parent) -Filter "
        "((Split-Path %s -Leaf) + '.part*') | Sort-Object Name | ForEach-Object { "
        "  $b=[IO.File]::ReadAllBytes($_.FullName); $out.Write($b,0,$b.Length); "
        "  Remove-Item -LiteralPath $_.FullName -Force }; "
        "$out.Close(); (Get-Item -LiteralPath %s).Length"
        % (lit, lit, lit, lit), timeout_ms=120000)
    size = str(joined.get("stdout", "")).strip()
    if not size.isdigit() or int(size) != len(blob):
        raise TaskError("chunked upload of %s reassembled to %r, expected %d"
                        % (path, size, len(blob)))
    return len(blob)


# --------------------------------------------------------------------------
# Sandbox reset
# --------------------------------------------------------------------------
class Proxmox:
    """Just enough of the PVE API to snapshot and roll back one sandbox.

    Snapshots are taken WITH vmstate, so a rollback restores a running desktop
    with Deskhand already listening instead of cold-booting Windows. That turns
    per-task reset from minutes into seconds, which is the difference between a
    benchmark you run and one you keep meaning to.
    """

    def __init__(self, cfg_path="/opt/sandboxctl/config.json"):
        cfg = json.load(io.open(cfg_path, encoding="utf-8"))
        self.host = cfg["pve_host"]
        self.node = cfg["node"]
        self.auth = "PVEAPIToken=%s=%s" % (cfg["token_id"], cfg["token_secret"])
        import ssl
        self._ctx = ssl._create_unverified_context()   # PVE ships a self-signed cert

    def _req(self, path, method="GET", data=None):
        url = "https://%s:8006/api2/json%s" % (self.host, path)
        body = urllib.parse.urlencode(data).encode() if data else None
        req = urllib.request.Request(url, data=body, method=method,
                                     headers={"Authorization": self.auth})
        with urllib.request.urlopen(req, timeout=60, context=self._ctx) as r:
            return json.loads(r.read().decode("utf-8")).get("data")

    def snapshots(self, vmid):
        return [s.get("name") for s in (self._req("/nodes/%s/qemu/%s/snapshot"
                                                  % (self.node, vmid)) or [])]

    def create_snapshot(self, vmid, name):
        upid = self._req("/nodes/%s/qemu/%s/snapshot" % (self.node, vmid), "POST",
                         {"snapname": name, "vmstate": 1,
                          "description": "waa-runner baseline"})
        return self.wait(upid)

    def rollback(self, vmid, name):
        upid = self._req("/nodes/%s/qemu/%s/snapshot/%s/rollback"
                         % (self.node, vmid, name), "POST")
        return self.wait(upid)

    def wait(self, upid, timeout=600):
        """Block until a PVE task finishes; raise on a non-OK exit status."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            st = self._req("/nodes/%s/tasks/%s/status" % (self.node, upid)) or {}
            if st.get("status") == "stopped":
                if st.get("exitstatus") != "OK":
                    raise TaskError("pve task %s: %s" % (upid, st.get("exitstatus")))
                return True
            time.sleep(2)
        raise TaskError("pve task %s timed out" % upid)

    def status(self, vmid):
        return (self._req("/nodes/%s/qemu/%s/status/current"
                          % (self.node, vmid)) or {}).get("status")

    def start(self, vmid):
        return self.wait(self._req("/nodes/%s/qemu/%s/status/start"
                                   % (self.node, vmid), "POST"))


def reset_sandbox(pve, dh, vmid, snapshot, wait_deskhand=180):
    """Roll the sandbox back, then wait until Deskhand answers again.

    Waiting on Deskhand rather than on the PVE task is deliberate: the rollback
    task completes before Windows has finished resuming, and a task that starts
    against a half-awake desktop fails for reasons that have nothing to do with
    the agent."""
    pve.rollback(vmid, snapshot)
    if pve.status(vmid) != "running":
        pve.start(vmid)
    deadline = time.time() + wait_deskhand
    while time.time() < deadline:
        try:
            dh.call("deskhand_arm")
            return True
        except TaskError:
            time.sleep(5)
    raise TaskError("deskhand did not come back within %ss of rollback" % wait_deskhand)


# --------------------------------------------------------------------------
# config / postconfig steps
# --------------------------------------------------------------------------
def step_launch(dh, p):
    # WAA passes an argv list; the first element may be a shell verb ("start").
    cmd = p.get("command")
    if isinstance(cmd, list):
        if cmd and cmd[0] == "start":
            target, args = (cmd[1] if len(cmd) > 1 else ""), cmd[2:]
        else:
            target, args = cmd[0], cmd[1:]
    else:
        target, args = str(cmd), []
    dh.call("deskhand_launch_process",
            {"path": target, "args": " ".join(args), "waitForWindowMs": 30000})


def step_sleep(dh, p):
    time.sleep(float(p.get("seconds", 1)))


def step_activate_window(dh, p):
    name, strict = p.get("window_name", ""), p.get("strict", False)
    for w in dh.windows():
        title = str(w.get("title") or "")
        if (title == name) if strict else (name.lower() in title.lower()):
            dh.call("deskhand_window", {"hwnd": w["hwnd"], "action": "activate"})
            return
    raise TaskError(f"activate_window: no window titled {name!r}")


def step_open(dh, p):
    dh.call("deskhand_launch_process", {"path": p.get("path", ""), "waitForWindowMs": 20000})


def step_execute(dh, p):
    cmd = p.get("command")
    dh.shell(" ".join(cmd) if isinstance(cmd, list) else str(cmd))


def step_download(dh, p):
    """Fetch task fixtures and place them in the guest.

    The controller does the fetching and pushes the bytes in over Deskhand,
    rather than having the guest curl the internet. Sandboxes are firewalled to
    one host on purpose, and widening that just to run a benchmark would be a
    bad trade -- this keeps the isolation intact and works unchanged on an
    air-gapped sandbox, as long as the controller can reach the fixtures.
    """
    for f in p.get("files", []):
        url, path = f.get("url"), f.get("path")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "waa-runner"})
            blob = urllib.request.urlopen(req, timeout=120).read()
        except Exception as exc:                   # noqa: BLE001
            raise TaskError(f"could not fetch fixture {url}: {exc}")
        put_file(path, blob)


def step_create_folder(dh, p):
    for path in (p.get("paths") or ([p["path"]] if p.get("path") else [])):
        dh.shell("New-Item -ItemType Directory -Force -Path %s | Out-Null"
                 % json.dumps(path))


def step_command(dh, p):
    """Tasks express these as ['cmd', '/c', '...']. Running that payload through
    PowerShell breaks it -- `>` and friends mean different things there -- so
    hand cmd's own syntax back to cmd."""
    cmd = p.get("command")
    shell = None
    if isinstance(cmd, list) and cmd and cmd[0] == "cmd":
        shell, cmd = "cmd", " ".join(cmd[2:]) if len(cmd) > 2 else ""
    elif isinstance(cmd, list):
        cmd = " ".join(cmd)
    r = dh.call("deskhand_run_command",
                {"command": str(cmd), "shell": shell, "timeoutMs": 120000}) or {}
    if r.get("exitCode") not in (0, None):
        raise TaskError("command step failed: %s" % str(r.get("stderr"))[:200])


def step_recycle_file(dh, p):
    """Send to the Recycle Bin rather than delete: tasks that ask the agent to
    restore a file need it recoverable, so a hard delete would make them
    impossible."""
    for path in (p.get("paths") or ([p["path"]] if p.get("path") else [])):
        dh.shell(
            "Add-Type -AssemblyName Microsoft.VisualBasic; "
            "[Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile(%s,'OnlyErrorDialogs','SendToRecycleBin')"
            % json.dumps(path))


STEPS = {
    "launch": step_launch, "sleep": step_sleep, "activate_window": step_activate_window,
    "open": step_open, "execute": step_execute, "download": step_download,
    "create_folder": step_create_folder, "command": step_command,
    "recycle_file": step_recycle_file,
}


# WAA's golden image runs as a user called "Docker"; ours is whatever the
# controller provisions. Every fixture path, and every getter that checks one,
# is written against their name -- so rewrite the whole task once at load time
# instead of remembering to do it at each call site.
WAA_USER = "Docker"
LOCAL_USER = os.environ.get("SANDBOX_USER", "sandbox")


def rewrite_paths(obj):
    if isinstance(obj, str):
        out = obj
        for sep in (chr(92), '/'):
            needle = sep + 'Users' + sep + WAA_USER
            repl = sep + 'Users' + sep + LOCAL_USER
            i = out.lower().find(needle.lower())
            while i != -1:
                out = out[:i] + repl + out[i + len(needle):]
                i = out.lower().find(needle.lower(), i + len(repl))
        return out
    if isinstance(obj, list):
        return [rewrite_paths(v) for v in obj]
    if isinstance(obj, dict):
        return {k: rewrite_paths(v) for k, v in obj.items()}
    return obj


def run_steps(dh, steps, label):
    for s in steps or []:
        fn = STEPS.get(s.get("type"))
        if fn is None:
            raise TaskError(f"{label}: unsupported step type {s.get('type')!r}")
        fn(dh, s.get("parameters", {}))


# --------------------------------------------------------------------------
# getters -- read the machine back
# --------------------------------------------------------------------------
def _walk(node, out):
    """Deskhand returns {"element": {...}, "children": [...]} recursively, so the
    payload we want sits one level below each node rather than on it."""
    if isinstance(node, dict):
        el = node.get("element")
        if isinstance(el, dict):
            out.append(el)
        for c in node.get("children") or []:
            _walk(c, out)
    elif isinstance(node, list):
        for c in node:
            _walk(c, out)
    return out


def _uia_names(dh, hwnd_title_contains, depth=12):
    """Every element name under the window whose title matches. WAA's clock
    getters are pure name matching, so names are all we need.

    Scoped in two hops on purpose: walking the desktop deep enough to reach a
    UWP app's content is enormous and slow, and most of it belongs to other
    windows. So find the window shallowly, then re-root the walk on it."""
    hwnd = None
    for w in dh.windows():
        if hwnd_title_contains.lower() in str(w.get("title") or "").lower():
            hwnd = w.get("hwnd")
            break
    if hwnd is None:
        return []

    top = dh.call("deskhand_get_tree", {"depth": 2, "maxChildren": 200})
    ref = None
    for el in _walk(top, []):
        if el.get("nativeWindowHandle") == hwnd:
            ref = el.get("ref")
            break
    if ref is None:
        return []

    tree = dh.call("deskhand_get_tree",
                   {"rootRef": ref, "depth": depth, "maxChildren": 400})
    return [str(el["name"]) for el in _walk(tree, []) if el.get("name")]


def _duration_seconds(text):
    """Pull "3 hours 0 minutes 0 seconds" (any component optional) out of a UIA
    name and return it in seconds, or None if there is no duration in there."""
    got = False
    total = 0
    for unit, mult in (("hour", 3600), ("minute", 60), ("second", 1)):
        m = re.search(r"(\d+)\s*%ss?\b" % unit, text, re.I)
        if m:
            total += int(m.group(1)) * mult
            got = True
    return total if got else None


def get_check_if_timer_started(dh, cfg):
    """Upstream formats "H hours M minutes S seconds" and requires that exact
    string on an element, plus a descendant named "Timer running, Pause".

    We keep the semantics -- a timer of this exact duration exists AND is
    running -- but compare durations numerically instead of by string. The
    fixed format is not portable across Clock builds: on this image a sub-hour
    timer is announced as "30 minutes 0 seconds", with no hours component, so
    upstream's string would never match a 0h30m task no matter what the agent
    did. Matching on seconds keeps the check honest on whatever build we run.
    """
    want = int(cfg.get("hours", 0)) * 3600 + int(cfg.get("minutes", 0)) * 60 \
        + int(cfg.get("seconds", 0))
    for name in _uia_names(dh, "Clock"):
        low = name.lower()
        if "edit timer" not in low:
            continue
        if "not started" in low:
            continue                              # exists but never started
        if "running" not in low:
            continue
        # A running entry reads "... Running, 59 seconds, Remaining Of, <total>",
        # so take the text after "of," to get the timer's length, not what is
        # left on the clock.
        tail = name.split("Of,", 1)[1] if "of," in low else name
        if _duration_seconds(tail) == want:
            EVIDENCE.append(name)
            return "True"
    return "False"


def get_check_if_world_clock_exists(dh, cfg):
    """Name-match, like upstream -- but record which name matched.

    A pass here is only as good as the element that produced it: the city name
    also appears in the add-city search suggestions, so a run that typed the
    city and never confirmed it could in principle score a point. Keeping the
    matching name in the result makes that auditable after the fact instead of
    a thing to argue about."""
    want = "%s, %s" % (cfg.get("city", ""), cfg.get("country", ""))
    hits = [n for n in _uia_names(dh, "Clock") if want.lower() in n.lower()]
    EVIDENCE.extend(hits[:5])
    return "True" if hits else "False"


def get_vm_file(dh, cfg):
    data = dh.read_file(cfg.get("path", ""))
    return None if data is None else data.decode("utf-8", "replace")


def get_vm_file_exists_in_vm_folder(dh, cfg):
    folder, name = cfg.get("folder", ""), cfg.get("file_name", cfg.get("name", ""))
    r = dh.shell("Test-Path -LiteralPath '%s'" % os.path.join(folder, name).replace("/", "\\"))
    return "True" if "true" in str(r.get("stdout", "")).strip().lower() else "False"


def _ps_bool(dh, expr):
    """Evaluate a PowerShell boolean and return WAA's "True"/"False" strings."""
    out = str(dh.shell("[bool](%s)" % expr).get("stdout", "")).strip().lower()
    return "True" if out == "true" else "False"


def _known_folder(dh, name):
    """Resolve Desktop/Documents properly rather than assuming C:\\Users\\<u>\\X.
    OneDrive redirection is on in this image, so the literal path is often wrong.
    Cached per process: it costs a round trip and never changes mid-run."""
    if name not in _FOLDER_CACHE:
        p = str(dh.shell("[Environment]::GetFolderPath('%s')" % name)
                .get("stdout", "")).strip()
        _FOLDER_CACHE[name] = p
    return _FOLDER_CACHE[name]


_FOLDER_CACHE = {}


def get_vm_folder_exists_in_documents(dh, cfg):
    path = os.path.join(_known_folder(dh, "MyDocuments"), cfg.get("folder_name", ""))
    EVIDENCE.append(path)
    return _ps_bool(dh, "Test-Path -LiteralPath %s -PathType Container" % json.dumps(path))


def _desktop_file(dh, cfg, key):
    return os.path.join(_known_folder(dh, "Desktop"), cfg.get(key, ""))


def get_vm_file_exists_in_desktop(dh, cfg):
    path = _desktop_file(dh, cfg, "file_name")
    EVIDENCE.append(path)
    return _ps_bool(dh, "Test-Path -LiteralPath %s" % json.dumps(path))


def get_is_file_desktop(dh, cfg):
    path = _desktop_file(dh, cfg, "filename")
    EVIDENCE.append(path)
    return _ps_bool(dh, "Test-Path -LiteralPath %s" % json.dumps(path))


def get_is_file_saved_desktop(dh, cfg):
    """Exists on the Desktop *and* contains the expected text -- a file of the
    right name with the wrong contents is not the task being done."""
    path = _desktop_file(dh, cfg, "filename")
    want = cfg.get("textcontent", "")
    data = dh.read_file(path)
    if data is None:
        EVIDENCE.append("missing: " + path)
        return "False"
    text = data.decode("utf-8", "replace")
    EVIDENCE.append("%s (%d bytes)" % (path, len(data)))
    return "True" if want.strip() in text else "False"


def get_is_files_moved_downloads(dh, cfg):
    dl = str(dh.shell("(New-Object -ComObject Shell.Application)."
                      "Namespace('shell:Downloads').Self.Path").get("stdout", "")).strip()
    path = os.path.join(dl, cfg.get("folder_name", ""), cfg.get("file_name", ""))
    EVIDENCE.append(path)
    return _ps_bool(dh, "Test-Path -LiteralPath %s" % json.dumps(path))


def get_is_file_hidden(dh, cfg):
    path = cfg.get("file_path", "")
    EVIDENCE.append(path)
    return _ps_bool(dh, "(Get-Item -LiteralPath %s -Force).Attributes -band "
                        "[IO.FileAttributes]::Hidden" % json.dumps(path))


def get_is_directory_read_only_for_user(dh, cfg):
    """Read-only for a named account: look for a deny-write ACE, or the absence
    of any write grant, on that identity."""
    d, user = cfg.get("directory", ""), cfg.get("user", "")
    r = dh.shell("icacls %s" % json.dumps(d))
    out = str(r.get("stdout", ""))
    EVIDENCE.append(out[:200])
    for line in out.splitlines():
        if user.lower() in line.lower():
            low = line.lower()
            if "(deny)" in low or ":(r)" in low.replace(" ", "") or ":(rx)" in low.replace(" ", ""):
                return "True"
            return "False"
    return "False"


def get_vm_command_line(dh, cfg):
    """Run the task's own command and hand back stdout for the metric to judge."""
    cmd = cfg.get("command")
    if isinstance(cmd, list):
        # tasks express these as ['cmd', '/c', '...'] -- drop the cmd wrapper and
        # let Deskhand's shell run the payload.
        cmd = cmd[2] if len(cmd) > 2 and cmd[0] == "cmd" else " ".join(cmd)
    r = dh.shell(str(cmd), timeout_ms=120000)
    out = str(r.get("stdout", ""))
    EVIDENCE.append(out[:200])
    return out


def get_vm_active_window_title(dh, cfg):
    fg = dh.call("deskhand_foreground_window") or {}
    title = str(fg.get("name") or "")
    EVIDENCE.append(title)
    return title


def get_all_png_file_names(dh, cfg):
    """The task asks for a listing of the .png files to be written to a file; we
    compare what was written against what is actually on disk."""
    folder, listing = cfg.get("folder_path", ""), cfg.get("file_path", "")
    data = dh.read_file(listing)
    if data is None:
        EVIDENCE.append("missing listing: " + listing)
        return "False"
    written = {l.strip().lower() for l in data.decode("utf-8", "replace").splitlines() if l.strip()}
    r = dh.shell("Get-ChildItem -LiteralPath %s -Filter *.png -Name" % json.dumps(folder))
    actual = {l.strip().lower() for l in str(r.get("stdout", "")).splitlines() if l.strip()}
    EVIDENCE.append("written=%d actual=%d" % (len(written), len(actual)))
    return "True" if written and written == actual else "False"


# Names/values a getter matched on, cleared per evaluation and copied into the
# result row. A score with no evidence behind it is an opinion.
EVIDENCE = []


GETTERS = {
    "check_if_timer_started": get_check_if_timer_started,
    "check_if_world_clock_exists": get_check_if_world_clock_exists,
    "vm_file": get_vm_file,
    "vm_file_exists_in_vm_folder": get_vm_file_exists_in_vm_folder,
    "vm_folder_exists_in_documents": get_vm_folder_exists_in_documents,
    "vm_file_exists_in_desktop": get_vm_file_exists_in_desktop,
    "is_file_desktop": get_is_file_desktop,
    "is_file_saved_desktop": get_is_file_saved_desktop,
    "is_files_moved_downloads": get_is_files_moved_downloads,
    "is_file_hidden": get_is_file_hidden,
    "is_directory_read_only_for_user": get_is_directory_read_only_for_user,
    "vm_command_line": get_vm_command_line,
    "vm_active_window_title": get_vm_active_window_title,
    "all_png_file_names": get_all_png_file_names,
}
# Deliberately absent, so they error rather than score a silent zero:
#   is_details_view, are_files_sorted_by_modified_time, are_all_images_tagged,
#   is_all_docx_in_archive, vm_library_folders, zipped_folder_in_desktop
# Each needs Explorer view state, EXIF tags, archive inspection or a password
# -- real work, and worth doing only if those tasks earn their keep.


# --------------------------------------------------------------------------
# metrics -- compare what we read against what the task expects
# --------------------------------------------------------------------------
def metric_exact_match(result, expected):
    return 1.0 if str(result).strip() == str(expected).strip() else 0.0


def metric_compare_text_file(result, expected):
    if result is None:
        return 0.0
    norm = lambda t: "\n".join(l.rstrip() for l in str(t).replace("\r\n", "\n").split("\n")).strip()
    return 1.0 if norm(result) == norm(expected) else 0.0


METRICS = {"exact_match": metric_exact_match, "compare_text_file": metric_compare_text_file}


def expected_value(expected):
    """WAA expresses expectations as {"type": "rule", "rules": {...}}."""
    if isinstance(expected, dict):
        if expected.get("type") == "rule":
            rules = expected.get("rules") or {}
            return rules.get("expected", rules)
        return expected.get("expected", expected)
    return expected


# --------------------------------------------------------------------------
# agents
# --------------------------------------------------------------------------
def agent_null(dh, instruction, timeout):
    """Does nothing. Any task this passes is passable by accident, and its score
    is the floor every real agent must clear to mean anything."""
    return {"agent": "null", "note": "no actions taken"}


def agent_hermes(dh, instruction, timeout):
    """Hermes headless, run inside the guest. Deskhand executes in the logged-in
    user's session, so the agent gets a real desktop rather than session 0.

    Uses its own client because the shared one's HTTP timeout is sized for
    quick tool calls -- an agent that thinks for ten minutes would otherwise
    look like an unreachable sandbox and score zero for the wrong reason."""
    exe = r"C:\Users\sandbox\AppData\Local\hermes\bin\hermes.exe"
    ps = ("$env:HERMES_HOME='C:\\Users\\sandbox\\AppData\\Local\\hermes'; "
          "& '%s' -z %s --yolo" % (exe, json.dumps(instruction)))
    slow = Deskhand(timeout=timeout + 120)
    r = slow.shell(ps, timeout_ms=int(timeout * 1000))
    out = str(r.get("stdout", "")) + str(r.get("stderr", ""))

    # An agent that never reached a model did not attempt the task, and scoring
    # that as a failure is how you end up reporting a confident 0% for an
    # afternoon when the inference server was simply down. Raise instead, so it
    # lands in `error` and is excluded from the score rather than counted as one.
    for probe in ("API call failed", "upstream unreachable", "HTTP 502",
                  "connection attempts failed", "no API key"):
        if probe.lower() in out.lower():
            raise TaskError("agent could not reach its model: %s"
                            % " ".join(out.split())[:180])
    return {"agent": "hermes", "exitCode": r.get("exitCode"), "tail": out[-600:]}


AGENTS = {"null": agent_null, "hermes": agent_hermes}


def preflight(dh, agent_name):
    """Confirm the agent can actually reach a model before spending an hour.

    Cheap insurance against the worst failure this harness can have: producing
    a plausible-looking score for an agent that was never able to think."""
    if agent_name == "null":
        return
    try:
        agent_hermes(dh, "Reply with the single word OK and nothing else.", 90)
    except TaskError as exc:
        raise TaskError("preflight failed -- %s" % exc)


# --------------------------------------------------------------------------
# the loop
# --------------------------------------------------------------------------
def evaluate(dh, task):
    ev = task.get("evaluator") or {}
    results = ev.get("result")
    funcs = ev.get("func")
    if not isinstance(results, list):
        results, funcs = [results], [funcs]
    if not isinstance(funcs, list):
        funcs = [funcs] * len(results)

    del EVIDENCE[:]
    scores, detail = [], []
    for res_cfg, func in zip(results, funcs):
        getter = GETTERS.get((res_cfg or {}).get("type"))
        metric = METRICS.get(func)
        if getter is None or metric is None:
            raise TaskError("unsupported getter/metric: %s / %s"
                            % ((res_cfg or {}).get("type"), func))
        got = getter(dh, res_cfg)
        want = expected_value(ev.get("expected"))
        score = metric(got, want)
        scores.append(score)
        detail.append({"getter": res_cfg.get("type"), "func": func,
                       "got": (got if isinstance(got, str) else repr(got))[:200],
                       "want": str(want)[:200], "score": score,
                       "evidence": list(EVIDENCE)})
    # All checks must pass -- WAA treats a task as binary.
    return (1.0 if scores and all(s == 1.0 for s in scores) else 0.0), detail


def run_task(dh, path, agent_name, timeout, reset=None):
    task = rewrite_paths(json.load(io.open(path, encoding="utf-8")))
    started = time.time()
    row = {"id": task.get("id"), "file": os.path.basename(path),
           "app": (task.get("related_apps") or ["?"])[0],
           "instruction": task.get("instruction", ""), "reset": bool(reset)}
    # Setup is the harness's job: if it breaks, the task never really ran and
    # calling that a zero would quietly understate every agent's score.
    try:
        if reset:
            reset()
        run_steps(dh, task.get("config"), "config")
        row["agent_result"] = AGENTS[agent_name](dh, task["instruction"], timeout)
    except Exception as exc:                       # noqa: BLE001
        row["score"] = 0.0
        row["error"] = "%s: %s" % (type(exc).__name__, exc) \
            if not isinstance(exc, TaskError) else str(exc)
        row["seconds"] = round(time.time() - started, 1)
        return row

    # Scoring is the agent's job. Several tasks activate a window the agent was
    # supposed to open -- when it did not, postconfig cannot run, and that is a
    # failed task, not a broken harness. Recording it as a note keeps the score
    # honest while still saying why.
    try:
        run_steps(dh, (task.get("evaluator") or {}).get("postconfig"), "postconfig")
        row["score"], row["detail"] = evaluate(dh, task)
    except TaskError as exc:
        row["score"], row["note"] = 0.0, str(exc)
    except Exception as exc:                       # noqa: BLE001
        row["score"], row["note"] = 0.0, "%s: %s" % (type(exc).__name__, exc)
    row["seconds"] = round(time.time() - started, 1)
    return row


def main():
    ap = argparse.ArgumentParser(description="Run WAA tasks against a sandbox via Deskhand.")
    ap.add_argument("--agent", default="null", choices=sorted(AGENTS))
    ap.add_argument("--tasks", default=os.path.join(HERE, "tasks", "*.json"),
                    help="glob of task JSON files")
    ap.add_argument("--timeout", type=float, default=600, help="per-task agent budget, seconds")
    ap.add_argument("--out", default=os.path.join(HERE, "results"))
    ap.add_argument("--vmid", type=int, default=900)
    ap.add_argument("--reset-snapshot", default=None, metavar="NAME",
                    help="roll back to this snapshot before every task "
                         "(created from the current state if absent). Without "
                         "it, tasks share state and scores are a smoke test only.")
    args = ap.parse_args()

    files = sorted(glob.glob(args.tasks))
    if not files:
        print("no task files matched %s" % args.tasks); return 2
    if not DESKHAND_TOKEN:
        print("warning: DESKHAND_TOKEN is unset; the sandbox will likely refuse the call",
              file=sys.stderr)

    dh = Deskhand()
    dh.call("deskhand_arm")     # every action below is gated on this

    try:
        preflight(dh, args.agent)
    except TaskError as exc:
        print("\n%s\n\nRefusing to run: a score produced now would measure the "
              "outage, not the agent." % exc, file=sys.stderr)
        return 3

    reset = None
    if args.reset_snapshot:
        pve = Proxmox()
        if args.reset_snapshot not in pve.snapshots(args.vmid):
            print("creating baseline snapshot %r from the sandbox's current state"
                  % args.reset_snapshot)
            pve.create_snapshot(args.vmid, args.reset_snapshot)
        reset = lambda: reset_sandbox(pve, dh, args.vmid, args.reset_snapshot)
    else:
        print("warning: no --reset-snapshot; tasks share state, so treat the "
              "score as a smoke test rather than a measurement\n", file=sys.stderr)

    os.makedirs(args.out, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    log_path = os.path.join(args.out, "%s-%s.jsonl" % (stamp, args.agent))

    rows = []
    print("running %d task(s) with agent=%s\n" % (len(files), args.agent))
    with io.open(log_path, "w", encoding="utf-8", newline="\n") as fh:
        for path in files:
            row = run_task(dh, path, args.agent, args.timeout, reset)
            rows.append(row)
            fh.write(json.dumps(row) + "\n"); fh.flush()
            print("  [%s] %-8s %-52s %5.1fs%s" % (
                "PASS" if row["score"] == 1.0 else "fail", row["app"],
                row["instruction"][:52], row["seconds"],
                ("  ERR " + row["error"][:56]) if row.get("error")
                else (("  " + row["note"][:58]) if row.get("note") else "")))

    passed = sum(1 for r in rows if r["score"] == 1.0)
    print("\n%d/%d passed (%.0f%%)  agent=%s" % (
        passed, len(rows), 100.0 * passed / len(rows), args.agent))
    print("results: %s" % log_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
