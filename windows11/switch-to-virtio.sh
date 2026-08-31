#!/usr/bin/env bash
#
# Move a Windows VM's OS disk from AHCI (sata1) to virtio-scsi (scsi0).
#
#   ./switch-to-virtio.sh --vmid 120
#
# Run this AFTER the machine has booted and provision.ps1 has installed the
# VirtIO package. Order matters, and is why this is separate from create-vm.sh:
#
#   create-vm.sh installs onto SATA because Windows drives AHCI natively and
#   needs no injected driver. Installing straight onto virtio-scsi does not work
#   on 24H2+ media -- the answer-file construct that would put the driver into
#   the installed image is rejected by the new setup engine, and drvload only
#   covers WinPE, so Setup finishes and the result bluescreens
#   INACCESSIBLE_BOOT_DEVICE on first boot.
#
# The subtlety this script exists to handle: installing virtio-win-gt-x64.msi
# does NOT make Windows ready to boot from virtio-scsi. The MSI only stages the
# driver in the driver store. Windows binds a driver when it sees the matching
# hardware, and there is no virtio-scsi controller yet -- so vioscsi.sys never
# reaches System32\drivers and its service is never registered boot-start.
# Moving the boot disk at that point bluescreens exactly as before.
#
# So: attach a throwaway virtio-scsi disk first. Windows enumerates the new
# controller, binds vioscsi from the store, and registers it with Start=0
# (BOOT_START). Only then is it safe to move the real disk. The throwaway disk
# is destroyed afterwards.
#
# If the VM does not come back after the switch, the disk is put back on sata1
# automatically. A failed switch should cost a reboot, not an image.
#
set -euo pipefail

VMID=""
WAIT=300

die()  { echo "error: $*" >&2; exit 1; }
note() { echo "==> $*"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --vmid) VMID="$2"; shift 2 ;;
        --wait) WAIT="$2"; shift 2 ;;
        -h|--help) sed -n '2,30p' "$0" | sed 's/^#\s\?//'; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
done

[[ $EUID -eq 0 ]] || die "run as root on a Proxmox node"
[[ -n "$VMID" ]] || die "--vmid is required"
qm config "$VMID" >/dev/null 2>&1 || die "VM $VMID not found on this node"

DISK="$(qm config "$VMID" | awk -F'[ ,]' '/^sata1:/{print $2}')"
[[ -n "$DISK" ]] || die "VM $VMID has no sata1 disk -- already switched?"
note "OS disk: $DISK"

status()  { qm status "$VMID" | awk '{print $2}'; }
unused0() { qm config "$VMID" | awk -F': ' '/^unused0:/{print $2; exit}'; }
wait_stopped() { while [[ "$(status)" == "running" ]]; do sleep 3; done; }

[[ "$(status)" == "running" ]] || die "VM must be running so the guest can be inspected"
qm agent "$VMID" ping >/dev/null 2>&1 \
    || die "guest agent not responding -- provision.ps1 may not have completed.
Check C:\\Windows\\Temp\\provision.log in the guest."

# ---------------------------------------------------------------------------
# Is the guest able to boot from virtio-scsi yet?
# ---------------------------------------------------------------------------
# Start=0 in the vioscsi service key is the actual gate. The presence of the
# driver package in the store is not enough, and neither is a successful MSI.
vioscsi_bootstart() {
    qm guest exec "$VMID" --timeout 60 -- \
        cmd.exe /c 'reg query HKLM\SYSTEM\CurrentControlSet\Services\vioscsi /v Start 2>nul | find "0x0" >nul && exit 0 || exit 1' \
        2>/dev/null | grep -q '"exitcode" : 0'
}

if vioscsi_bootstart; then
    note "vioscsi already registered BOOT_START"
else
    note "vioscsi not bound yet; attaching a throwaway virtio-scsi disk to trigger it"
    qm set "$VMID" --scsihw virtio-scsi-single --scsi1 "${DISK%%:*}:1,ssd=1" >/dev/null
    note "waiting for Windows to bind the driver"
    for _ in $(seq 12); do
        sleep 5
        vioscsi_bootstart && break
    done
    if ! vioscsi_bootstart; then
        qm set "$VMID" --delete scsi1 >/dev/null 2>&1 || true
        [[ -n "$(unused0)" ]] && qm set "$VMID" --delete unused0 >/dev/null 2>&1 || true
        die "Windows did not bind vioscsi. Confirm virtio-win-gt-x64.msi installed
cleanly (C:\\Windows\\Temp\\provision.log) and that the virtio CD is attached."
    fi
    note "vioscsi bound and registered BOOT_START"

    note "removing the throwaway disk"
    qm shutdown "$VMID" --timeout 300; wait_stopped
    qm set "$VMID" --delete scsi1 >/dev/null
    sleep 2
    THROWAWAY="$(unused0)"
    [[ -n "$THROWAWAY" ]] && qm set "$VMID" --delete unused0 >/dev/null
    sleep 2
fi

# ---------------------------------------------------------------------------
# Move the OS disk
# ---------------------------------------------------------------------------
if [[ "$(status)" == "running" ]]; then
    note "shutting down VM $VMID"
    qm shutdown "$VMID" --timeout 300; wait_stopped
fi

note "moving $DISK from sata1 to scsi0"
qm set "$VMID" --delete sata1 >/dev/null
sleep 2
VOL="$(unused0)"
[[ -n "$VOL" ]] || die "could not find the detached volume -- inspect: qm config $VMID"
qm set "$VMID" \
    --scsihw virtio-scsi-single \
    --scsi0 "${VOL},iothread=1,discard=on,ssd=1" \
    --boot order=scsi0 >/dev/null

note "starting VM $VMID on virtio-scsi"
qm start "$VMID"

# ---------------------------------------------------------------------------
# Verify, and undo if it did not come back
# ---------------------------------------------------------------------------
note "waiting up to ${WAIT}s for the guest agent"
deadline=$(( SECONDS + WAIT ))
until qm agent "$VMID" ping >/dev/null 2>&1; do
    if (( SECONDS >= deadline )); then
        echo "guest did not come back; reverting to sata1" >&2
        qm stop "$VMID" >/dev/null 2>&1 || true; wait_stopped
        qm set "$VMID" --delete scsi0 >/dev/null
        sleep 2
        qm set "$VMID" --sata1 "$(unused0),discard=on,ssd=1" --boot order=sata1 >/dev/null
        qm start "$VMID"
        die "switch failed and was reverted; VM $VMID is back on SATA and starting."
    fi
    sleep 5
done

cat <<EOF

VM $VMID is running from virtio-scsi.
  scsi0: $(qm config "$VMID" | awk '/^scsi0:/{print $2}')

Next:
  ./make-template.sh --vmid $VMID
EOF
