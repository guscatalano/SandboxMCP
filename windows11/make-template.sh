#!/usr/bin/env bash
#
# Turn a finished Windows 11 build into a Proxmox template.
#
#   ./make-template.sh --vmid 120
#
# This is the step that converts "I installed Windows once" into "I can have a
# new Windows box in thirty seconds". Everything expensive -- the install, the
# drivers, the guest agent, the updates, your applications -- happens once and is
# then copied.
#
# Sysprep /generalize is run first, inside the guest, via the QEMU guest agent.
# Generalize strips the machine SID, the activation state, driver bindings and
# the computer name. Skipping it produces clones that share a SID, which is
# tolerable on an isolated lab LAN and is a real problem the moment you add a
# domain, WSUS, or anything that identifies machines by SID rather than by name.
# --no-sysprep exists for when you have decided that trade knowingly.
#
set -euo pipefail

VMID=""
DO_SYSPREP=1
WAIT=900

die()  { echo "error: $*" >&2; exit 1; }
note() { echo "==> $*"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --vmid)       VMID="$2"; shift 2 ;;
        --no-sysprep) DO_SYSPREP=0; shift ;;
        --wait)       WAIT="$2"; shift 2 ;;
        -h|--help)    sed -n '2,20p' "$0" | sed 's/^#\s\?//'; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
done

[[ $EUID -eq 0 ]] || die "run as root on a Proxmox node"
[[ -n "$VMID" ]] || die "--vmid is required"
qm config "$VMID" >/dev/null 2>&1 || die "VM $VMID not found on this node"

if qm config "$VMID" | grep -q '^template: 1'; then
    die "VM $VMID is already a template"
fi

# ---------------------------------------------------------------------------
# Sysprep
# ---------------------------------------------------------------------------
if (( DO_SYSPREP )); then
    [[ "$(qm status "$VMID" | awk '{print $2}')" == "running" ]] \
        || die "VM must be running for sysprep (start it and log in once first)"

    # The guest agent is how this script reaches inside the VM. If it does not
    # answer, provision.ps1 either did not run or the VM has not finished
    # booting -- both worth knowing before issuing a destructive command.
    qm agent "$VMID" ping >/dev/null 2>&1 \
        || die "guest agent not responding. Check C:\\Windows\\Temp\\provision.log in the guest."

    # Windows 11 24H2+ turns on device encryption by itself when a TPM and
    # Secure Boot are present. Sysprep refuses to generalize an encrypted OS
    # volume (0x80310039), and only says so in its own log, 20 minutes in.
    note "checking the OS volume is not BitLocker-encrypted"
    if ! qm guest exec "$VMID" --timeout 120 -- \
            cmd.exe /c 'manage-bde -status C: | find "Fully Decrypted" >nul' \
            2>/dev/null | grep -q '"exitcode" : 0'; then
        die "the OS volume is encrypted; sysprep cannot generalize it.
Inside the guest run:
    reg add HKLM\SYSTEM\CurrentControlSet\Control\BitLocker /v PreventDeviceEncryption /t REG_DWORD /d 1 /f
    manage-bde -off C:
then wait for manage-bde -status C: to report Fully Decrypted and re-run.
A current provision.ps1 does this at first logon, so it should not recur."
    fi
    note "OS volume is decrypted"
    note "running sysprep /generalize /oobe /shutdown inside VM $VMID"
    # sysprep.xml lives on the answer-file CD built by build-unattend-iso.sh.
    # Drive letter varies, so probe rather than assume -- same reason as the
    # driver paths in autounattend.xml.
    qm guest exec "$VMID" --timeout 60 -- \
        cmd.exe /c 'for %i in (D E F G H) do @if exist %i:\sysprep.xml C:\Windows\System32\Sysprep\sysprep.exe /generalize /oobe /shutdown /quiet /unattend:%i:\sysprep.xml' \
        >/dev/null 2>&1 || true
    # `|| true` because sysprep powers the machine off mid-command: the agent
    # connection dies and qm reports failure for what is actually success. The
    # real success signal is the VM reaching 'stopped', checked next.

    note "waiting up to ${WAIT}s for the guest to power off"
    deadline=$(( SECONDS + WAIT ))
    while [[ "$(qm status "$VMID" | awk '{print $2}')" == "running" ]]; do
        (( SECONDS < deadline )) || die "VM still running after ${WAIT}s.
Open the console and check: sysprep logs to C:\\Windows\\System32\\Sysprep\\Panther\\setuperr.log
The usual cause is a Store app blocking generalize -- the log names it."
        sleep 10
    done
    note "guest powered off"
else
    note "skipping sysprep (--no-sysprep): clones will share this machine's SID"
    if [[ "$(qm status "$VMID" | awk '{print $2}')" == "running" ]]; then
        note "shutting down VM $VMID"
        qm shutdown "$VMID" --timeout 300
    fi
fi

# ---------------------------------------------------------------------------
# Strip installation media
# ---------------------------------------------------------------------------
# The answer-file ISO holds the admin password in clear text. Leaving it attached
# would mean every clone ships with a readable credential on a mounted CD.
note "detaching installation media"
for dev in ide0 ide2 sata0; do
    if qm config "$VMID" | grep -q "^${dev}:"; then
        qm set "$VMID" --delete "$dev" >/dev/null
        echo "    removed $dev"
    fi
done
qm set "$VMID" --boot order=scsi0 >/dev/null

# ---------------------------------------------------------------------------
# Convert
# ---------------------------------------------------------------------------
note "converting VM $VMID to a template"
qm set "$VMID" --name "$(qm config "$VMID" | awk '/^name:/{print $2}')-template" >/dev/null 2>&1 || true
qm template "$VMID"

cat <<EOF

VM $VMID is now a template. It can no longer be started -- clone it instead:

  ./clone-vm.sh --template $VMID --vmid 121 --name devbox

Each clone boots into OOBE, applies sysprep.xml unattended, generates its own
SID and a random computer name, and lands at a logon screen using the same admin
account. Expect about two minutes, most of it the specialize pass.

Reminder: the answer-file ISO still on your ISO storage contains the admin
password in clear text. Delete it once you are done building:
  rm /var/lib/vz/template/iso/unattend-*.iso
EOF
