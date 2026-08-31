"""
Live view of a sandbox's screen, from two independent sources.

Why two:

  * PROXMOX VNC  -- reads the VM's framebuffer through Proxmox, so it works when
    nothing is running inside the guest: during Windows setup, at a lock screen,
    on a boot loop, on a sandbox whose Deskhand install failed. It is the one to
    reach for when you want to see why something is stuck.

  * DESKHAND     -- asks the guest to screenshot itself. Needs Deskhand running
    and a logged-in session, but it is cheap, needs no VNC ticket, and reflects
    exactly what the automation sees.

Both are served to the browser as MJPEG (multipart/x-mixed-replace), which every
browser plays natively in an <img> with no player, no plugin and no JS.

The VNC path speaks just enough RFB to be useful: connect, authenticate, pin the
pixel format, then request *incremental* framebuffer updates so an idle desktop
costs almost nothing on the wire -- only changed rectangles are sent.
"""
import io
import json
import select
import socket
import ssl
import struct
import urllib.parse
import urllib.request

from PIL import Image

try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:                                    # older cryptography
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, modes


def _recvn(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("VNC connection closed")
        buf += chunk
    return buf


def _des(key8, data):
    """Single DES/ECB expressed as 3DES with equal subkeys.

    VNC also reverses the bit order within each key byte -- a quirk of the
    original implementation that every client has to reproduce.
    """
    rev = bytes(int(f"{b:08b}"[::-1], 2) for b in key8)
    enc = Cipher(TripleDES(rev * 3), modes.ECB()).encryptor()
    return enc.update(data) + enc.finalize()


class VncSession:
    """One live RFB connection to a VM's console."""

    def __init__(self, host, port, ticket, timeout=20):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        s = self.sock

        _recvn(s, 12)                                  # server version
        s.sendall(b"RFB 003.008\n")
        count = _recvn(s, 1)[0]
        if count == 0:
            reason = _recvn(s, struct.unpack(">I", _recvn(s, 4))[0])
            raise RuntimeError(f"VNC rejected: {reason.decode(errors='replace')}")
        types = _recvn(s, count)
        if 2 not in types:
            raise RuntimeError(f"no VNC auth offered: {list(types)}")
        s.sendall(bytes([2]))
        challenge = _recvn(s, 16)
        s.sendall(_des(ticket.encode()[:8].ljust(8, b"\0"), challenge))
        if struct.unpack(">I", _recvn(s, 4))[0] != 0:
            raise RuntimeError("VNC authentication failed")

        s.sendall(b"\x01")                             # ClientInit, shared
        self.w, self.h = struct.unpack(">HH", _recvn(s, 4))
        _recvn(s, 16)                                  # server pixel format
        namelen = struct.unpack(">I", _recvn(s, 4))[0]
        _recvn(s, namelen)

        # Pin 32-bit BGRX so no colour-map or endianness handling is needed.
        pf = struct.pack(">BBBB HHH BBB xxx", 32, 24, 0, 1, 255, 255, 255, 16, 8, 0)
        s.sendall(b"\x00\x00\x00\x00" + pf)            # SetPixelFormat
        s.sendall(struct.pack(">BxHi", 2, 1, 0))       # SetEncodings: raw only
        self.canvas = Image.new("RGB", (self.w, self.h), (0, 0, 0))
        self._pending = False
        self._got_first = False

    def _request(self, incremental):
        self.sock.sendall(struct.pack(">BBHHHH", 3, 1 if incremental else 0,
                                      0, 0, self.w, self.h))

    def pump(self, timeout):
        """Apply a framebuffer update if one is waiting. True if the screen changed.

        RFB only answers an *incremental* request when something actually changes,
        so a naive read blocks forever on an idle desktop and the stream appears
        frozen. Instead: keep exactly one request outstanding, poll with select,
        and let the caller re-send the last canvas when nothing arrived.
        """
        if not self._pending:
            self._request(incremental=not self._got_first)
            self._pending = True
        ready, _, _ = select.select([self.sock], [], [], timeout)
        if not ready:
            return False
        msg = _recvn(self.sock, 1)[0]
        self._pending = False
        if msg != 0:
            return False
        _recvn(self.sock, 1)
        nrects = struct.unpack(">H", _recvn(self.sock, 2))[0]
        changed = False
        for _ in range(nrects):
            rx, ry, rw, rh, enc = struct.unpack(">HHHHi", _recvn(self.sock, 12))
            if enc != 0 or rw == 0 or rh == 0:
                continue
            raw = _recvn(self.sock, rw * rh * 4)
            # BGRX on the wire; PIL's raw decoder converts it directly.
            tile = Image.frombytes("RGB", (rw, rh), raw, "raw", "BGRX")
            self.canvas.paste(tile, (rx, ry))
            changed = True
        self._got_first = True
        return changed

    def jpeg(self, quality=70):
        out = io.BytesIO()
        self.canvas.save(out, "JPEG", quality=quality)
        return out.getvalue()

    def frame(self, incremental=True, quality=70):
        """One-shot: block briefly for a full update, then encode."""
        self._got_first = bool(incremental)
        self.pump(5.0)
        return self.jpeg(quality)

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


def open_vnc(api, node, vmid, host):
    """Ask Proxmox for a console ticket and connect to it."""
    p = api(f"/nodes/{node}/qemu/{vmid}/vncproxy", "POST", {"websocket": 0})
    return VncSession(host, int(p["port"]), p["ticket"])


def deskhand_frame(ip, port, token, quality=70, timeout=20):
    """Single screenshot from the guest's own Deskhand. Returns JPEG bytes."""
    body = json.dumps({"format": "jpeg", "quality": quality}).encode()
    req = urllib.request.Request(
        f"http://{ip}:{port}/capture/screen", data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read()
        ctype = r.headers.get("Content-Type", "")
    if ctype.startswith("image/"):
        return data
    # Some builds answer JSON with a base64 payload instead of raw bytes.
    import base64
    obj = json.loads(data)
    for key in ("imageBase64", "image", "data", "base64", "bytes"):
        if isinstance(obj.get(key), str):
            return base64.b64decode(obj[key])
    raise RuntimeError(f"unexpected capture response: {str(obj)[:160]}")
