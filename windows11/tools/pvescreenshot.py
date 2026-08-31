#!/usr/bin/env python3
"""
Grab a PNG screenshot of a Proxmox VM's console over VNC.

The Proxmox REST API exposes no framebuffer endpoint, so this asks it to open a
VNC proxy (POST .../vncproxy), then speaks just enough RFB to pull one full
framebuffer update in raw encoding.

    python pvescreenshot.py <node-ip> <node-name> <vmid> <out.png>

Auth comes from proxmoxapi.txt via PVE_TOKEN / PVE_TOKENID env vars.
"""
import json, os, socket, ssl, struct, sys, urllib.request

HOST, NODE, VMID, OUT = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
TOKENID = os.environ.get("PVE_TOKENID", "root@pam!claude")
SECRET = os.environ["PVE_TOKEN"]


def api(path, method="GET", data=None):
    body = urllib.parse.urlencode(data).encode() if data else None
    req = urllib.request.Request(
        f"https://{HOST}:8006/api2/json{path}", data=body, method=method,
        headers={"Authorization": f"PVEAPIToken={TOKENID}={SECRET}",
                 "Accept-Encoding": "identity"})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
        return json.load(r)["data"]


import urllib.parse  # noqa: E402  (after the helper that uses it, for readability)


# --- RFB helpers -----------------------------------------------------------
def recvn(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError(f"connection closed with {n - len(buf)} bytes outstanding")
        buf += chunk
    return buf


def des_encrypt(key8, data):
    """Single DES/ECB, expressed as 3DES with all three subkeys equal.

    VNC also reverses the bit order within each key byte -- a quirk of the
    original implementation that every client must reproduce.
    """
    try:
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    except ImportError:
        from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
    from cryptography.hazmat.primitives.ciphers import Cipher, modes

    rev = bytes(int(f"{b:08b}"[::-1], 2) for b in key8)
    enc = Cipher(TripleDES(rev * 3), modes.ECB()).encryptor()
    return enc.update(data) + enc.finalize()


# --- open the proxy --------------------------------------------------------
proxy = api(f"/nodes/{NODE}/qemu/{VMID}/vncproxy", "POST", {"websocket": 0})
port, ticket = int(proxy["port"]), proxy["ticket"]
print(f"vncproxy: port {port}")

sock = socket.create_connection((HOST, port), timeout=30)
sock.settimeout(30)

version = recvn(sock, 12)
print(f"server version: {version.decode(errors='replace').strip()}")
sock.sendall(b"RFB 003.008\n")

count = recvn(sock, 1)[0]
if count == 0:
    reason = recvn(sock, struct.unpack(">I", recvn(sock, 4))[0])
    sys.exit(f"handshake rejected: {reason.decode(errors='replace')}")
sectypes = recvn(sock, count)
if 2 not in sectypes:
    sys.exit(f"server offers no VNC auth: {list(sectypes)}")
sock.sendall(bytes([2]))

challenge = recvn(sock, 16)
pw = ticket.encode()[:8].ljust(8, b"\0")
sock.sendall(des_encrypt(pw, challenge))
if struct.unpack(">I", recvn(sock, 4))[0] != 0:
    sys.exit("VNC authentication failed")
print("authenticated")

sock.sendall(b"\x01")                      # ClientInit, shared
w, h = struct.unpack(">HH", recvn(sock, 4))
recvn(sock, 16)                            # server pixel format (replaced below)
namelen = struct.unpack(">I", recvn(sock, 4))[0]
name = recvn(sock, namelen).decode(errors="replace")
print(f"framebuffer: {w}x{h}  desktop: {name}")

# Pin the format to plain 32-bit RGBX so no colour-map or endian handling is
# needed on this side.
pf = struct.pack(">BBBB HHH BBB xxx", 32, 24, 0, 1, 255, 255, 255, 16, 8, 0)
sock.sendall(b"\x00\x00\x00\x00" + pf)     # SetPixelFormat
sock.sendall(struct.pack(">BxHi", 2, 1, 0))  # SetEncodings: raw only
sock.sendall(struct.pack(">BBHHHH", 3, 0, 0, 0, w, h))  # full, non-incremental

msg = recvn(sock, 1)[0]
if msg != 0:
    sys.exit(f"unexpected server message type {msg}")
recvn(sock, 1)
nrects = struct.unpack(">H", recvn(sock, 2))[0]
print(f"receiving {nrects} rectangle(s)")

import numpy as np                          # noqa: E402
from PIL import Image                       # noqa: E402

canvas = np.zeros((h, w, 3), dtype=np.uint8)
for _ in range(nrects):
    rx, ry, rw, rh, enc = struct.unpack(">HHHHi", recvn(sock, 12))
    if enc != 0:
        print(f"  skipping non-raw rect encoding {enc}")
        continue
    raw = recvn(sock, rw * rh * 4)
    arr = np.frombuffer(raw, dtype=np.uint8).reshape(rh, rw, 4)
    canvas[ry:ry + rh, rx:rx + rw] = arr[:, :, 2::-1]   # BGRX -> RGB
    print(f"  rect {rw}x{rh} at ({rx},{ry})")

sock.close()
Image.fromarray(canvas).save(OUT)
print(f"saved {OUT}")
