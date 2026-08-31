#!/usr/bin/env bash
#
# Spin a new Windows 11 VM off the template built by make-template.sh.
#
#   ./clone-vm.sh --template 120 --vmid 121 --name devbox
#   ./clone-vm.sh --template 120 --vmid 122 --name buildbox --cores 8 --memory 16384
#
# This is the step you run repeatedly. Everything slow already happened.
#
set -euo pipefail

TEMPLATE=""
VMID=""
NAME=""
CORES=""
MEMORY=""
STORAGE=""
FULL=1
START=1
RENAME=1
WAIT=600

die()  { echo "error: $*" >&2; exit 1; }
note() { echo "==> $*"; }

usage() {
    cat <<EOF
Usage: $0 --template ID --vmid ID --name NAME [options]

  --template ID    template VM to clone from (required)
  --vmid ID        new VM ID (required)
  --name NAME      new VM name (required)
  --cores N        override vCPUs
  --memory MB      override RAM
  --storage NAME   target storage for a full clone
  --linked         linked clone: instant and near-zero disk, but permanently
                   dependent on the template's disk. Full clone is the default
                   because an independent machine is worth the copy.
  --no-start       create but do not boot
  --no-rename      leave the random Windows hostname sysprep generated
EOF
    exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --template)  TEMPLATE="$2"; shift 2 ;;
        --vmid)      VMID="$2"; shift 2 ;;
        --name)      NAME="$2"; shift 2 ;;
        --cores)     CORES="$2"; shift 2 ;;
        --memory)    MEMORY="$2"; shift 2 ;;
        --storage)   STORAGE="$2"; shift 2 ;;
        --linked)    FULL=0; shift ;;
        --no-start)  START=0; shift ;;
        --no-rename) RENAME=0; shift ;;
        -h|--help)   usage 0 ;;
        *) echo "unknown option: $1" >&2; usage 1 ;;
    esac
done

[[ $EUID -eq 0 ]] || die "run as root on a Proxmox node"
[[ -n "$TEMPLATE" && -n "$VMID" && -n "$NAME" ]] || usage 1
qm config "$TEMPLATE" >/dev/null 2>&1 || die "template $TEMPLATE not found on this node"
qm config "$TEMPLATE" | grep -q '^template: 1' || die "VM $TEMPLATE is not a template (run make-template.sh first)"
! qm config "$VMID" >/dev/null 2>&1 || die "VMID $VMID already exists"

# Windows hostnames: 15 characters, letters/digits/hyphen. Longer names are
# silently truncated by Windows, which produces a machine whose Proxmox name and
# DNS name disagree -- a confusing thing to debug months later.
if (( RENAME )); then
    [[ ${#NAME} -le 15 ]] || die "--name must be 15 characters or fewer for a Windows hostname (or pass --no-rename)"
    [[ "$NAME" =~ ^[A-Za-z0-9-]+$ ]] || die "--name may contain only letters, digits and hyphens"
fi

# ---------------------------------------------------------------------------
# Clone
# ---------------------------------------------------------------------------
note "cloning $TEMPLATE -> $VMID ($NAME)"
clone_args=(--name "$NAME" --full "$FULL")
[[ -n "$STORAGE" ]] && clone_args+=(--storage "$STORAGE")
qm clone "$TEMPLATE" "$VMID" "${clone_args[@]}"

set_args=()
[[ -n "$CORES"  ]] && set_args+=(--cores "$CORES")
[[ -n "$MEMORY" ]] && set_args+=(--memory "$MEMORY")
if (( ${#set_args[@]} )); then
    qm set "$VMID" "${set_args[@]}" >/dev/null
    note "resources: ${set_args[*]}"
fi

if (( ! START )); then
    echo
    echo "VM $VMID created but not started. Boot it with: qm start $VMID"
    exit 0
fi

note "starting VM $VMID"
qm start "$VMID"

# ---------------------------------------------------------------------------
# Rename inside Windows
# ---------------------------------------------------------------------------
# sysprep set ComputerName to '*', so Windows generated something like
# DESKTOP-4K7B2QX. Renaming makes the guest agree with Proxmox and with DNS.
if (( RENAME )); then
    note "waiting for the guest agent (specialize pass takes a couple of minutes)"
    deadline=$(( SECONDS + WAIT ))
    until qm agent "$VMID" ping >/dev/null 2>&1; do
        if (( SECONDS >= deadline )); then
            echo "warning: guest agent did not respond within ${WAIT}s; VM is running but was not renamed." >&2
            echo "         rename it later:  qm guest exec $VMID -- powershell -Command \"Rename-Computer -NewName $NAME -Restart -Force\"" >&2
            exit 0
        fi
        sleep 10
    done

    note "renaming guest to $NAME and rebooting"
    qm guest exec "$VMID" --timeout 120 -- \
        powershell.exe -NoProfile -Command "Rename-Computer -NewName '$NAME' -Force -Restart" \
        >/dev/null 2>&1 || true
    # Same as sysprep: the reboot kills the agent channel, so a non-zero exit
    # here does not mean the rename failed.
fi

cat <<EOF

VM $VMID ($NAME) is up.
  Find its address:  qm guest cmd $VMID network-get-interfaces
  Then RDP to it with the admin account baked into the template.
EOF
