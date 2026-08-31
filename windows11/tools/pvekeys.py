#!/usr/bin/env python3
"""
Type into a Proxmox VM's console via the API's sendkey endpoint.

    python pvekeys.py <host> <node> <vmid> --key shift-f10
    python pvekeys.py <host> <node> <vmid> --text 'dir X:\\' --enter

Useful when a guest has no network yet -- a WinPE command prompt reached with
Shift+F10, for instance. QEMU takes one key per call, so text is sent character
by character; that is slow but it is the only channel that exists before the
guest has an IP.
"""
import argparse, json, os, ssl, sys, time, urllib.parse, urllib.request

# QEMU key names for characters that are not simply their own name.
SPECIAL = {
    ' ': 'spc', '\\': 'backslash', '/': 'slash', '.': 'dot', ',': 'comma',
    '-': 'minus', '=': 'equal', ';': 'semicolon', "'": 'apostrophe',
    '[': 'bracket_left', ']': 'bracket_right', '`': 'grave_accent',
}
# Characters produced by holding shift over another key.
SHIFTED = {
    ':': 'semicolon', '"': 'apostrophe', '_': 'minus', '+': 'equal',
    '|': 'backslash', '?': 'slash', '>': 'dot', '<': 'comma', '~': 'grave_accent',
    '!': '1', '@': '2', '#': '3', '$': '4', '%': '5',
    '^': '6', '&': '7', '*': '8', '(': '9', ')': '0',
    '{': 'bracket_left', '}': 'bracket_right',
}


def key_for(ch):
    if ch in SPECIAL:
        return SPECIAL[ch]
    if ch in SHIFTED:
        return 'shift-' + SHIFTED[ch]
    if ch.isupper():
        return 'shift-' + ch.lower()
    if ch.isalnum():
        return ch
    raise ValueError(f"no key mapping for {ch!r}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument('host'); p.add_argument('node'); p.add_argument('vmid')
    p.add_argument('--key', action='append', default=[],
                   help='literal QEMU key name, may repeat')
    p.add_argument('--text', default=None)
    p.add_argument('--enter', action='store_true')
    p.add_argument('--delay', type=float, default=0.04)
    args = p.parse_args()

    tokenid = os.environ.get('PVE_TOKENID', 'root@pam!claude')
    secret = os.environ['PVE_TOKEN']
    url = (f"https://{args.host}:8006/api2/json"
           f"/nodes/{args.node}/qemu/{args.vmid}/sendkey")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def send(k):
        req = urllib.request.Request(
            url, data=urllib.parse.urlencode({'key': k}).encode(), method='PUT',
            headers={'Authorization': f'PVEAPIToken={tokenid}={secret}',
                     'Accept-Encoding': 'identity'})
        with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
            json.load(r)
        time.sleep(args.delay)

    n = 0
    for k in args.key:
        send(k); n += 1
    if args.text:
        for ch in args.text:
            send(key_for(ch)); n += 1
    if args.enter:
        send('ret'); n += 1
    print(f"sent {n} key event(s)")


if __name__ == '__main__':
    main()
