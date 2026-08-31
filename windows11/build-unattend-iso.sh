#!/usr/bin/env bash
#
# Build a small bootable-media companion ISO carrying autounattend.xml and
# provision.ps1, and place it on a Proxmox ISO storage.
#
# Run this ON a Proxmox node. Windows Setup scans the root of every attached
# volume for autounattend.xml, so a second CD is all it takes -- the Windows
# installation media is never modified, which means the same untouched ISO works
# for every build and can be replaced with a newer one at any time.
#
#   ./build-unattend-iso.sh                        # defaults, prompts for password
#   VM_NAME=devbox WINGET='Git.Git Microsoft.VisualStudioCode' ./build-unattend-iso.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
COMPUTER_NAME="${COMPUTER_NAME:-${VM_NAME:-win11}}"
USERNAME="${USERNAME:-sandbox}"
ORGANIZATION="${ORGANIZATION:-lab}"
TIMEZONE="${TIMEZONE:-Eastern Standard Time}"
LOCALE="${LOCALE:-en-US}"
KEYBOARD="${KEYBOARD:-0409:00000409}"

# Must match an edition name inside install.wim exactly. List them with:
#   dism /Get-WimInfo /WimFile:<mounted-iso>\sources\install.wim
IMAGE_NAME="${IMAGE_NAME:-Windows 11 Pro}"

# Generic KMS client setup key for Windows 11 Pro. Published by Microsoft; it
# selects the edition and gets Setup past the key prompt. It does NOT activate.
PRODUCT_KEY="${PRODUCT_KEY:-VK7JG-NPHTM-C97JM-9MPGT-3V66T}"

# Space-separated winget IDs, installed on first logon and allowed to fail.
WINGET="${WINGET:-}"

ISO_STORAGE="${ISO_STORAGE:-local}"
OUT_NAME="${OUT_NAME:-unattend-${COMPUTER_NAME}.iso}"

# --------------------------------------------------------------------------
die() { echo "error: $*" >&2; exit 1; }
note() { echo "==> $*"; }

[[ $EUID -eq 0 ]] || die "run as root on a Proxmox node"
[[ -f "$SCRIPT_DIR/autounattend.xml" ]] || die "autounattend.xml not found beside this script"
[[ -f "$SCRIPT_DIR/provision.ps1"    ]] || die "provision.ps1 not found beside this script"
[[ -f "$SCRIPT_DIR/sysprep-unattend.xml" ]] || die "sysprep-unattend.xml not found beside this script"

# --------------------------------------------------------------------------
# Password
# --------------------------------------------------------------------------
# Read from the environment or prompted -- never a default, and never a literal
# in this file. It is written into the ISO in clear text (Windows Setup requires
# a form it can read back), so the ISO is a secret: see the note at the end.
if [[ -z "${PASSWORD:-}" ]]; then
    read -rsp "Password for local admin '$USERNAME': " PASSWORD; echo
    read -rsp "Confirm: " PASSWORD2; echo
    [[ "$PASSWORD" == "$PASSWORD2" ]] || die "passwords do not match"
fi
[[ -n "$PASSWORD" ]] || die "password must not be empty"
# Windows refuses to create an account whose password fails complexity rules,
# and it fails at the very end of a 20-minute install. Check now instead.
(( ${#PASSWORD} >= 8 )) || die "password must be at least 8 characters"

# --------------------------------------------------------------------------
# Dependencies
# --------------------------------------------------------------------------
if ! command -v xorriso >/dev/null 2>&1; then
    note "installing xorriso"
    apt-get update -qq && apt-get install -y -qq xorriso
fi

# --------------------------------------------------------------------------
# Resolve the ISO storage to a directory on disk
# --------------------------------------------------------------------------
# Only file-backed storages (dir, nfs, cifs) can hold ISOs. Block storages such
# as lvmthin cannot, and saying so here is clearer than a confusing copy error.
storage_dir() {
    local want="$1"
    awk -v want="$want" '
        /^[a-z]+: / { type=$1; sub(":","",type); name=$2; inblk=(name==want); path="" }
        inblk && $1=="path" { path=$2 }
        inblk && /^$/ && path { print type" "path; exit }
        END { if (inblk && path) print type" "path }
    ' /etc/pve/storage.cfg
}

read -r st_type st_path <<<"$(storage_dir "$ISO_STORAGE")" || true
[[ -n "${st_path:-}" ]] || die "storage '$ISO_STORAGE' has no path in /etc/pve/storage.cfg (block storage cannot hold ISOs; try: local)"

ISO_DIR="$st_path/template/iso"
mkdir -p "$ISO_DIR"

# --------------------------------------------------------------------------
# Render the templates
# --------------------------------------------------------------------------
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# Turn "Git.Git Foo.Bar" into the PowerShell array body provision.ps1 expects.
winget_block() {
    local pkg
    for pkg in $WINGET; do printf "    '%s',\n" "$pkg"; done | sed '$ s/,$//'
}

# Substitution is done in Python rather than sed because passwords routinely
# contain the characters sed treats as delimiters or backreferences.
render() {
    WINGET_BLOCK="$(winget_block)" \
    P_COMPUTER_NAME="$COMPUTER_NAME" P_USERNAME="$USERNAME" P_PASSWORD="$PASSWORD" \
    P_ORGANIZATION="$ORGANIZATION" P_TIMEZONE="$TIMEZONE" P_LOCALE="$LOCALE" \
    P_KEYBOARD="$KEYBOARD" P_IMAGE_NAME="$IMAGE_NAME" P_PRODUCT_KEY="$PRODUCT_KEY" \
    python3 - "$1" "$2" <<'PY'
import os, re, sys, html
src, dst = sys.argv[1], sys.argv[2]
tokens = {
    "@@COMPUTER_NAME@@": os.environ["P_COMPUTER_NAME"],
    "@@USERNAME@@":      os.environ["P_USERNAME"],
    "@@PASSWORD@@":      os.environ["P_PASSWORD"],
    "@@ORGANIZATION@@":  os.environ["P_ORGANIZATION"],
    "@@TIMEZONE@@":      os.environ["P_TIMEZONE"],
    "@@LOCALE@@":        os.environ["P_LOCALE"],
    "@@KEYBOARD@@":      os.environ["P_KEYBOARD"],
    "@@IMAGE_NAME@@":    os.environ["P_IMAGE_NAME"],
    "@@PRODUCT_KEY@@":   os.environ["P_PRODUCT_KEY"],
    "@@WINGET_PACKAGES@@": os.environ["WINGET_BLOCK"],
}
text = open(src, encoding="utf-8").read()
# XML values must be escaped; a password containing & or < is otherwise a
# malformed answer file, which Setup reports only as "invalid unattend file".
esc = dst.endswith(".xml")
for k, v in tokens.items():
    text = text.replace(k, html.escape(v, quote=False) if esc else v)
left = [t for t in tokens if t in text]
if left:
    sys.exit(f"unsubstituted tokens remain in {dst}: {left}")
if esc:
    # Ship the answer file stripped of comments and pure ASCII. Windows
    # Setup's CSI parser is unforgiving and reports every complaint as one
    # opaque code; comments and non-ASCII punctuation buy nothing inside the
    # guest, and the documented originals stay in this repo. Removing them
    # removes a class of failure that is very tedious to diagnose from WinPE.
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    text = re.sub(r"\n\s*\n+", "\n", text)
    bad = sorted({c for c in text if ord(c) > 127})
    if bad:
        sys.exit(f"non-ASCII characters in {dst}: {bad}")
open(dst, "w", encoding="ascii" if esc else "utf-8", newline="\r\n").write(text)
PY
}

note "rendering answer file for '$COMPUTER_NAME' (user: $USERNAME, image: $IMAGE_NAME)"
render "$SCRIPT_DIR/autounattend.xml" "$STAGE/autounattend.xml"
render "$SCRIPT_DIR/provision.ps1"    "$STAGE/provision.ps1"
# Carried on the same disc so make-template.sh has it without a second build:
# sysprep replays only specialize and oobeSystem, and needs the computer name
# set to * so each clone gets its own.
render "$SCRIPT_DIR/sysprep-unattend.xml" "$STAGE/sysprep.xml"

# Windows Setup also honours an unattend.xml in the same place; providing both
# names costs nothing and covers the paths that look for the other one.
cp "$STAGE/autounattend.xml" "$STAGE/unattend.xml"

# --------------------------------------------------------------------------
# Burn
# --------------------------------------------------------------------------
# -J (Joliet) and -R (Rock Ridge) so the long filenames survive; without Joliet
# the file arrives as AUTOUNAT.XML and Setup never finds it.
note "building $ISO_DIR/$OUT_NAME"
xorriso -as mkisofs -quiet -J -R -V UNATTEND -o "$ISO_DIR/$OUT_NAME" "$STAGE"
chmod 600 "$ISO_DIR/$OUT_NAME"

cat <<EOF

Built: $ISO_STORAGE:iso/$OUT_NAME
       $(du -h "$ISO_DIR/$OUT_NAME" | cut -f1), on $st_type storage '$ISO_STORAGE'

This ISO contains the admin password in clear text -- Windows Setup has no way
to read it otherwise. It is chmod 600, but treat it as a credential:
  * detach it from the VM once installation finishes (create-vm.sh does this
    for you when you later run make-template.sh)
  * delete it when you are done building:  rm '$ISO_DIR/$OUT_NAME'

Next:
  ./create-vm.sh --vmid <id> --name $COMPUTER_NAME --unattend $ISO_STORAGE:iso/$OUT_NAME
EOF
