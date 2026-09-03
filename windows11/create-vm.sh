#!/usr/bin/env bash
#
# Create a Windows 11 VM on Proxmox with the settings Windows 11 actually
# requires, then boot it into a fully unattended installation.
#
# Run this ON the Proxmox node that will host the VM (`qm` is node-local).
#
#   ./create-vm.sh --vmid 120 --name win11-dev --unattend local:iso/unattend-win11-dev.iso
#
# What makes this Windows 11 rather than any other guest, and why each matters:
#
#   q35 + OVMF    Windows 11 requires UEFI. The i440fx/SeaBIOS default installs
#                 in legacy BIOS mode and Setup refuses outright.
#   TPM 2.0       A hard requirement. Proxmox provides it via swtpm as a small
#                 state disk; it is not emulated for free.
#   pre-enrolled  Secure Boot with Microsoft's keys already trusted, so the
#     -keys       signed Windows bootloader is accepted on the first boot.
#   cpu host      Windows 11 needs SSE4.2 and POPCNT. The kvm64 default lacks
#                 both and Setup fails the CPU check.
#   sata1 disk    The OS disk installs on AHCI, which Windows drives natively.
#                 Installing straight onto virtio-scsi does not work on 24H2+
#                 media: the answer-file mechanism that injects the driver into
#                 the installed image is rejected by the new setup engine, and
#                 drvload only covers WinPE -- Setup finishes and the result
#                 bluescreens INACCESSIBLE_BOOT_DEVICE on first boot. Install
#                 on SATA, let provision.ps1 install the VirtIO package into
#                 the OS, then run switch-to-virtio.sh.
#   audio0        Windows needs an audio RENDER endpoint to exist, even headless.
#                 Without one, anything touching the audio stack fails outright --
#                 FL Studio dies on GetDefaultAudioEndpoint before it can render a
#                 single sample. driver=none means no host backend; the guest just
#                 sees a device.
#   balloon 0     Memory ballooning before the VirtIO balloon driver exists just
#                 makes Windows report nonsense. Enable it after the first boot
#                 if you want it.
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
VMID=""
NAME="win11"
STORAGE="local-lvm"        # holds the OS disk, EFI vars and TPM state
CORES=4
MEMORY=8192                # Windows 11 minimum is 4096; 8192 is the usable floor
DISK=96                    # GiB. Minimum is 64; thin-provisioned, so this is a
                           # ceiling rather than an allocation.
BRIDGE=vmbr0
WIN_ISO=""
VIRTIO_ISO=""
UNATTEND_ISO=""
START=1
DOWNLOAD_VIRTIO=0

VIRTIO_URL="https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso"

die()  { echo "error: $*" >&2; exit 1; }
note() { echo "==> $*"; }

usage() {
    sed -n '2,30p' "$0" | sed 's/^#\s\?//'
    cat <<EOF

Options:
  --vmid N            VM ID (required)
  --name NAME         VM name                        [$NAME]
  --storage NAME      storage for disk/EFI/TPM       [$STORAGE]
  --cores N           vCPUs                          [$CORES]
  --memory MB         RAM in MiB                     [$MEMORY]
  --disk GB           OS disk size in GiB            [$DISK]
  --bridge NAME       network bridge                 [$BRIDGE]
  --iso VOLID         Windows 11 ISO      (auto-detected if omitted)
  --virtio VOLID      virtio-win ISO      (auto-detected if omitted)
  --unattend VOLID    answer-file ISO from build-unattend-iso.sh
  --download-virtio   fetch virtio-win.iso to 'local' if not present
  --no-start          create but do not boot
EOF
    exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --vmid)     VMID="$2"; shift 2 ;;
        --name)     NAME="$2"; shift 2 ;;
        --storage)  STORAGE="$2"; shift 2 ;;
        --cores)    CORES="$2"; shift 2 ;;
        --memory)   MEMORY="$2"; shift 2 ;;
        --disk)     DISK="$2"; shift 2 ;;
        --bridge)   BRIDGE="$2"; shift 2 ;;
        --iso)      WIN_ISO="$2"; shift 2 ;;
        --virtio)   VIRTIO_ISO="$2"; shift 2 ;;
        --unattend) UNATTEND_ISO="$2"; shift 2 ;;
        --download-virtio) DOWNLOAD_VIRTIO=1; shift ;;
        --no-start) START=0; shift ;;
        -h|--help)  usage 0 ;;
        *) echo "unknown option: $1" >&2; usage 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
[[ $EUID -eq 0 ]] || die "run as root on a Proxmox node"
command -v qm >/dev/null || die "qm not found -- run this on a Proxmox node, not a container"
[[ -n "$VMID" ]] || { echo "error: --vmid is required" >&2; usage 1; }
[[ "$VMID" =~ ^[0-9]+$ ]] || die "--vmid must be numeric"

# Refuse rather than clobber. A VM ID collision that silently reconfigures
# somebody else's machine is not a mistake you get to undo.
if qm config "$VMID" >/dev/null 2>&1; then
    die "VMID $VMID already exists: $(qm config "$VMID" | awk '/^name:/{print $2}')"
fi

pvesm status --storage "$STORAGE" >/dev/null 2>&1 || die "storage '$STORAGE' not found on this node"

# Windows 11's own floors. Better to stop here than 15 minutes into Setup.
(( MEMORY >= 4096 )) || die "Windows 11 requires at least 4096 MiB (got $MEMORY)"
(( DISK   >= 64   )) || die "Windows 11 requires at least 64 GiB (got $DISK)"

# swtpm provides the TPM. Without it, --tpmstate0 is accepted at create time and
# the VM then fails to start, which is a far more confusing failure.
command -v swtpm >/dev/null || die "swtpm not installed: apt install swtpm swtpm-tools"

# ---------------------------------------------------------------------------
# Locate ISOs
# ---------------------------------------------------------------------------
# Searches every ISO-capable storage visible from this node so it works whether
# media lives on 'local' or on the shared NAS.
find_iso() {
    local pattern="$1" store
    for store in $(pvesm status --content iso 2>/dev/null | awk 'NR>1 && $3=="active"{print $1}'); do
        pvesm list "$store" --content iso 2>/dev/null |
            awk 'NR>1{print $1}' |
            # The answer-file ISOs are named unattend-win11-*.iso and would
            # otherwise match the Windows pattern -- booting the wrong disc.
            grep -ivE 'unattend' |
            grep -iE "$pattern" || true
    done | head -1
}

if [[ -z "$WIN_ISO" ]]; then
    WIN_ISO="$(find_iso 'win.?(11|dows.?11)')"
    [[ -n "$WIN_ISO" ]] || die "no Windows 11 ISO found. Upload one, then pass --iso <storage>:iso/<file>"
    note "Windows ISO (auto): $WIN_ISO"
fi

if [[ -z "$VIRTIO_ISO" ]]; then
    VIRTIO_ISO="$(find_iso 'virtio-win')"
fi
if [[ -z "$VIRTIO_ISO" ]]; then
    if (( DOWNLOAD_VIRTIO )); then
        # Official Fedora-hosted build; this is where Proxmox's own docs point.
        note "downloading virtio-win.iso from fedorapeople.org"
        dest="/var/lib/vz/template/iso/virtio-win.iso"
        mkdir -p "$(dirname "$dest")"
        curl -fL --progress-bar -o "$dest" "$VIRTIO_URL"
        VIRTIO_ISO="local:iso/virtio-win.iso"
    else
        die "no virtio-win ISO found. Re-run with --download-virtio, or fetch it manually:
    curl -fLo /var/lib/vz/template/iso/virtio-win.iso $VIRTIO_URL"
    fi
fi
note "virtio ISO: $VIRTIO_ISO"

if [[ -z "$UNATTEND_ISO" ]]; then
    # Not fatal: a VM with correct hardware and no answer file is still useful,
    # it just means clicking through Setup by hand.
    echo "warning: no --unattend ISO given; Setup will run interactively." >&2
    echo "         build one first with ./build-unattend-iso.sh" >&2
fi

# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------
note "creating VM $VMID ($NAME) on storage $STORAGE"

qm create "$VMID" \
    --name        "$NAME" \
    --ostype      win11 \
    --machine     q35 \
    --bios        ovmf \
    --efidisk0    "$STORAGE:1,efitype=4m,pre-enrolled-keys=1" \
    --tpmstate0   "$STORAGE:1,version=v2.0" \
    --cpu         host \
    --sockets     1 \
    --cores       "$CORES" \
    --memory      "$MEMORY" \
    --balloon     0 \
    --audio0      device=intel-hda,driver=none \
    --scsihw      virtio-scsi-single \
    --sata1       "$STORAGE:${DISK},discard=on,ssd=1" \
    --net0        "virtio,bridge=${BRIDGE},firewall=1" \
    --ide0        "${VIRTIO_ISO},media=cdrom" \
    --ide2        "${WIN_ISO},media=cdrom" \
    --boot        "order=ide2;sata1" \
    --agent       "enabled=1,fstrim_cloned_disks=1" \
    --vga         std \
    --tablet      1 \
    --onboot      0 \
    --description "Windows 11. Built by provision/windows11/create-vm.sh."

# The answer file goes on sata0, not a third IDE slot: under q35 Proxmox exposes
# only ide0 and ide2 reliably, and the extra IDE positions are the slave devices
# of an emulated controller that Windows does not always enumerate.
if [[ -n "$UNATTEND_ISO" ]]; then
    qm set "$VMID" --sata0 "${UNATTEND_ISO},media=cdrom" >/dev/null
    note "answer file attached on sata0"
fi

# ---------------------------------------------------------------------------
# Start
# ---------------------------------------------------------------------------
if (( START )); then
    note "starting VM $VMID"
    qm start "$VMID"
fi

cat <<EOF

VM $VMID ($NAME) created.
  ${CORES} vCPU, $((MEMORY / 1024)) GiB RAM, ${DISK} GiB disk on ${STORAGE}
  UEFI + Secure Boot + TPM 2.0, virtio-scsi, virtio net on ${BRIDGE}

  Console:  https://$(hostname -f):8006  ->  VM $VMID  ->  Console

ONE manual step, then it is hands-off:
  Windows media prompts "Press any key to boot from CD or DVD". Open the console
  and press a key within about five seconds of start. Miss it and the VM drops to
  the UEFI shell -- just 'qm reset $VMID' and try again. This is a property of
  Microsoft's boot image, not of this script, and it is the reason the template
  workflow below is worth it: you pay it once, not per machine.

Installation then runs unattended for roughly 15-25 minutes, reboots a few times,
and lands at a logon screen with provisioning already applied.
Check C:\\Windows\\Temp\\provision.log inside the guest if anything looks wrong.

Then, to make every future machine a 30-second clone:
  ./make-template.sh --vmid $VMID
EOF
