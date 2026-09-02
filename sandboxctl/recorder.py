"""Continuous recording of what Proxmox sees on each sandbox's console.

Deliberately the VNC framebuffer rather than Deskhand's own capture: this has to
keep working when the guest does not. A sandbox stuck in Windows setup, sitting
at a lock screen, or wedged behind a modal nothing can dismiss is exactly the
case you want footage of, and in all of those Deskhand is unreachable.

Frames go straight into ffmpeg as an image2pipe stream and come out H.264. A
desktop is almost entirely static, so at 1 fps a full 8-hour chunk is tens of
megabytes rather than the ~1.4 GB the same frames would cost as loose JPEGs.

Chunks rotate on a fixed wall-clock boundary so a file's name tells you which
part of the day it covers, and a sweep drops anything past the retention age.
"""
import os
import re
import subprocess
import threading
import time

import live

CHUNK_SECONDS = 8 * 60 * 60
FPS = 1
# Above ~30 the desktop text starts smearing; below ~24 the files stop shrinking
# much. 28 keeps a 1280x800 chunk in the tens of megabytes and still readable.
CRF = 28
NAME_RE = re.compile(r"^(\d+)-(\d{8}-\d{6})\.mp4$")


class SandboxRecorder:
    """One recorder for one sandbox. Reconnects until told to stop."""

    def __init__(self, vmid, name, out_dir, api, node, host, log=None):
        self.vmid = int(vmid)
        self.name = name
        self.out_dir = out_dir
        self.api = api
        self.node = node
        self.host = host
        self._log = log or (lambda m: None)
        self._stop = threading.Event()
        self._thread = None
        self.current = None
        self.started = None
        self.frames = 0
        self.error = None

    # -- lifecycle ---------------------------------------------------------
    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name=f"rec-{self.vmid}")
        self._thread.start()

    def stop(self, timeout=15):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout)

    @property
    def alive(self):
        return bool(self._thread and self._thread.is_alive())

    # -- the loop ----------------------------------------------------------
    def _run(self):
        backoff = 5
        while not self._stop.is_set():
            try:
                self._record_chunk()
                backoff = 5
            except Exception as exc:                      # noqa: BLE001
                # A sandbox that is rebooting, or a VNC ticket that expired, is
                # normal. Back off so a permanently broken VM does not spin.
                self.error = str(exc)[:200]
                self._log(f"recorder {self.vmid}: {self.error}")
                if self._stop.wait(backoff):
                    break
                backoff = min(backoff * 2, 120)

    def _chunk_path(self):
        stamp = time.strftime("%Y%m%d-%H%M%S")
        return os.path.join(self.out_dir, f"{self.vmid}-{stamp}.mp4")

    def _record_chunk(self):
        """Record until the chunk boundary, then return so a new file starts."""
        vnc = live.open_vnc(self.api, self.node, self.vmid, self.host)
        path = self._chunk_path()
        # -y so a retry cannot block on an overwrite prompt.
        #
        # FRAGMENTED mp4, not +faststart. faststart only writes the index when
        # the file closes, so an in-progress chunk is 48 bytes of nothing -- and
        # with 8-hour chunks that means the recording you actually want to watch
        # (the one happening right now) is the one you cannot open. Fragmented
        # output is playable while it is still being written, at the cost of
        # slightly larger files.
        proc = subprocess.Popen(
            ["ffmpeg", "-hide_banner", "-loglevel", "error", "-y",
             "-f", "image2pipe", "-framerate", str(FPS), "-i", "-",
             "-c:v", "libx264", "-preset", "veryfast", "-crf", str(CRF),
             "-pix_fmt", "yuv420p",
             "-movflags", "+frag_keyframe+empty_moov+default_base_moof",
             "-g", str(FPS * 60), path],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        self.current = path
        self.started = time.time()
        self.frames = 0
        self.error = None
        deadline = self.started + CHUNK_SECONDS
        interval = 1.0 / FPS
        try:
            while not self._stop.is_set() and time.time() < deadline:
                tick = time.time()
                # pump() returns False on an idle desktop; the canvas still holds
                # the last frame, and a constant frame rate is what keeps the
                # file's timeline honest against wall-clock time.
                vnc.pump(timeout=interval)
                proc.stdin.write(vnc.jpeg(quality=70))
                self.frames += 1
                slack = interval - (time.time() - tick)
                if slack > 0:
                    time.sleep(slack)
        finally:
            try:
                proc.stdin.close()
            except Exception:
                pass
            proc.wait(timeout=60)
            vnc.close()
            self.current = None


class RecorderManager:
    """Keeps one recorder running per sandbox that should have one."""

    def __init__(self, out_dir, api, node, host, retention_days=14, log=None):
        self.out_dir = out_dir
        self.api = api
        self.node = node
        self.host = host
        self.retention_days = retention_days
        self._log = log or (lambda m: None)
        self._recorders = {}
        self._lock = threading.Lock()
        os.makedirs(out_dir, exist_ok=True)

    def sync(self, sandboxes):
        """Start recorders for running sandboxes, stop them for the rest."""
        want = {int(s["vmid"]): s.get("name", "")
                for s in sandboxes if s.get("status") == "running"}
        with self._lock:
            for vmid, name in want.items():
                r = self._recorders.get(vmid)
                if r is None or not r.alive:
                    r = SandboxRecorder(vmid, name, self.out_dir, self.api,
                                        self.node, self.host, self._log)
                    self._recorders[vmid] = r
                    r.start()
            for vmid in list(self._recorders):
                if vmid not in want:
                    self._recorders.pop(vmid).stop(timeout=5)

    def stop(self, vmid):
        with self._lock:
            r = self._recorders.pop(int(vmid), None)
        if r:
            r.stop(timeout=5)

    def status(self):
        with self._lock:
            return {vmid: {"recording": r.alive, "file": os.path.basename(r.current or ""),
                           "frames": r.frames,
                           "since": int(r.started) if r.started else None,
                           "error": r.error}
                    for vmid, r in self._recorders.items()}

    # -- stored chunks -----------------------------------------------------
    def listing(self, vmid=None):
        out = []
        for fn in sorted(os.listdir(self.out_dir), reverse=True):
            m = NAME_RE.match(fn)
            if not m:
                continue
            if vmid is not None and int(m.group(1)) != int(vmid):
                continue
            p = os.path.join(self.out_dir, fn)
            try:
                st = os.stat(p)
            except OSError:
                continue
            out.append({"file": fn, "vmid": int(m.group(1)),
                        "started": m.group(2), "size": st.st_size,
                        "mtime": int(st.st_mtime)})
        return out

    def sweep(self):
        """Delete chunks past the retention age. Never touches a live file."""
        if not self.retention_days:
            return 0
        cutoff = time.time() - self.retention_days * 86400
        live_files = {r.current for r in self._recorders.values() if r.current}
        removed = 0
        for e in self.listing():
            p = os.path.join(self.out_dir, e["file"])
            if p in live_files or e["mtime"] > cutoff:
                continue
            try:
                os.remove(p)
                removed += 1
            except OSError:
                pass
        if removed:
            self._log(f"recordings: swept {removed} chunk(s) older than "
                      f"{self.retention_days} days")
        return removed
