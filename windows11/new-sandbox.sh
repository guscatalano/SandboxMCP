#!/usr/bin/env bash
#
# Give me a new throwaway Windows box.
#
#   ./new-sandbox.sh                 # next free ID, boots, prints the IP
#   ./new-sandbox.sh --name scratch2 --cores 8 --memory 16384
#
# Linked clone by default: it takes a few seconds and almost no disk, because a
# linked clone stores only the blocks that differ from the template. The
# trade-off is that the clone depends on the template's disk forever -- which is
# exactly the right trade for something disposable, and the wrong one for a
# machine you intend to keep. Use --full for the latter.
#
# Sandboxes are allocated from a dedicated VMID range (default 900-949) so that
# everything else can reason about them by ID alone: provision/monit/
# pve-backup-check.py skips that range instead of alerting every time a
# deliberately-unprotected guest appears.
#
set -euo pipefail

TEMPLATE="${SANDBOX_TEMPLATE:-122}"
RANGE_LO="${SANDBOX_ID_LO:-900}"
RANGE_HI="${SANDBOX_ID_HI:-949}"
NAME=""
CORES=""
MEMORY=""
FULL=0
WAIT=420

die()  { echo "error: $*" >&2; exit 1; }
note() { echo "==> $*"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --template) TEMPLATE="$2"; shift 2 ;;
        --name)     NAME="$2"; shift 2 ;;
        --cores)    CORES="$2"; shift 2 ;;
        --memory)   MEMORY="$2"; shift 2 ;;
        --full)     FULL=1; shift ;;
        --wait)     WAIT="$2"; shift 2 ;;
        -h|--help)  sed -n '2,18p' "$0" | sed 's/^#\s\?//'; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
done

[[ $EUID -eq 0 ]] || die "run as root on a Proxmox node"
qm config "$TEMPLATE" >/dev/null 2>&1 || die "template $TEMPLATE not found on this node"
qm config "$TEMPLATE" | grep -q '^template: 1' \
    || die "VM $TEMPLATE is not a template -- run make-template.sh first"

# ---------------------------------------------------------------------------
# Pick an ID
# ---------------------------------------------------------------------------
VMID=""
for id in $(seq "$RANGE_LO" "$RANGE_HI"); do
    if ! qm config "$id" >/dev/null 2>&1 && ! pct config "$id" >/dev/null 2>&1; then
        VMID="$id"; break
    fi
done
[[ -n "$VMID" ]] || die "no free VMID in ${RANGE_LO}-${RANGE_HI}; destroy-sandbox.sh some first"

# Windows truncates hostnames past 15 characters, which leaves the Proxmox name
# and the DNS name disagreeing. Keep the generated one short by construction.
[[ -n "$NAME" ]] || NAME="sandbox-${VMID}"
[[ ${#NAME} -le 15 ]] || die "--name must be 15 characters or fewer"
[[ "$NAME" =~ ^[A-Za-z0-9-]+$ ]] || die "--name may contain only letters, digits and hyphens"

# ---------------------------------------------------------------------------
# Clone
# ---------------------------------------------------------------------------
note "cloning template $TEMPLATE -> $VMID ($NAME)$([[ $FULL == 1 ]] && echo ' [full]' || echo ' [linked]')"
qm clone "$TEMPLATE" "$VMID" --name "$NAME" --full "$FULL"

# Sandboxes live on the SDN vnet, not vmbr0: they get 10.66.0.x from the
# zone's own DHCP and reach the internet by SNAT through the host, so they
# consume no address on the LAN.
# Reuse the MAC qm clone just generated. Passing --net0 without a MAC makes
# Proxmox mint a fresh one, which releases this guest's SDN IPAM reservation and
# can hand it a different address than the one already allocated.
MAC="$(qm config "$VMID" | awk -F'[=,]' '/^net0:/{print $2}')"
set_args=(--net0 "virtio=${MAC},bridge=${SANDBOX_BRIDGE:-sbx0},firewall=1"
          --description "SANDBOX - disposable, not backed up. Created by new-sandbox.sh.")
[[ -n "$CORES"  ]] && set_args+=(--cores "$CORES")
[[ -n "$MEMORY" ]] && set_args+=(--memory "$MEMORY")
qm set "$VMID" "${set_args[@]}" >/dev/null

note "starting"
qm start "$VMID"

# ---------------------------------------------------------------------------
# Wait for it to be usable, and say how to reach it
# ---------------------------------------------------------------------------
# A sandbox you have to go hunting for the IP of is not a one-command sandbox.
note "waiting for the guest agent"
deadline=$(( SECONDS + WAIT ))
until qm agent "$VMID" ping >/dev/null 2>&1; do
    (( SECONDS < deadline )) || die "no guest agent after ${WAIT}s. Check the console: qm terminal $VMID"
    sleep 5
done

# ---------------------------------------------------------------------------
# Auto-logon
# ---------------------------------------------------------------------------
# Deskhand drives the desktop through UI Automation, so it needs a logged-in
# session -- a clone sitting at the lock screen is useless. Auto-logon is what
# provides that, and getting it to stick is fiddly for one specific reason:
#
#   OOBE creates a temporary 'defaultuser0', points AutoAdminLogon at it, and
#   during its cleanup deletes AutoAdminLogon and DefaultUserName (and ONLY
#   those two -- DefaultPassword survives). Anything that writes them before
#   that cleanup finishes is silently erased. Declaring <AutoLogon> in the
#   answer file is worse still: OOBE then hangs trying to log in as the disabled
#   defaultuser0 and never completes.
#
# So: disable the image's own startup task before it can fire early, wait for
# OOBE to genuinely finish, settle, then apply and let it reboot once.
note "disabling the in-image auto-logon task before it can race OOBE"
qm guest exec "$VMID" --timeout 60 --     schtasks /Change /TN DeskhandAutoLogon /DISABLE >/dev/null 2>&1 || true

note "waiting for OOBE to finish"
oobe_deadline=$(( SECONDS + 600 ))
until qm guest exec "$VMID" --timeout 60 --         cmd.exe /c 'reg query HKLM\SYSTEM\Setup /v SystemSetupInProgress | find "0x0" >nul'         2>/dev/null | grep -q '"exitcode" : 0'; do
    (( SECONDS < oobe_deadline )) || die "OOBE did not finish within 10 minutes"
    sleep 10
done
sleep 60      # let OOBE's Winlogon cleanup settle; without this it wipes what we write
note "OOBE finished; applying auto-logon"

# The script is baked into the image by install-deskhand.ps1 and holds the
# credential, so nothing sensitive has to travel through this command line.
# It is idempotent: if auto-logon is already correct it does nothing.
qm guest exec "$VMID" --timeout 120 --     powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'C:\Deskhand\apply-autologon.ps1'     >/dev/null 2>&1 || true      # it reboots the guest, which kills the agent channel

note "waiting for the desktop and Deskhand"
sleep 20
up_deadline=$(( SECONDS + 420 ))
until qm guest exec "$VMID" --timeout 60 --         cmd.exe /c 'tasklist | find /i "deskhand-http" >nul'         2>/dev/null | grep -q '"exitcode" : 0'; do
    (( SECONDS < up_deadline )) || { echo "warning: Deskhand did not start; the VM is up but has no session" >&2; break; }
    sleep 10
done

# ---------------------------------------------------------------------------
# Give this sandbox its own Deskhand token
# ---------------------------------------------------------------------------
# The template ships with a token baked into its launcher, which would mean every
# clone shares one secret -- compromise one sandbox and you have them all. Worse,
# nothing would ever tell you what it is. So mint a fresh one per sandbox, write
# it into this clone's launcher, and print it below.
#
# Passed via -EncodedCommand because the token and the PowerShell both travel
# through qm's argument parsing; base64 removes every quoting question at once.
TOKEN="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 40)"
PS_SETTOKEN=$(cat <<PSEOF
\$f = 'C:\Deskhand\run-deskhand.ps1'
\$new = '\$env:DESKHAND_TOKEN = ' + "'${TOKEN}'"
\$out = foreach (\$l in (Get-Content \$f)) {
    if (\$l -like '*DESKHAND_TOKEN*') { \$new } else { \$l }
}
Set-Content \$f -Value \$out -Encoding UTF8
Stop-Process -Name deskhand-http -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3
schtasks /Run /TN Deskhand | Out-Null
PSEOF
)
if command -v iconv >/dev/null 2>&1; then
    B64="$(printf '%s' "$PS_SETTOKEN" | iconv -f UTF-8 -t UTF-16LE | base64 -w0)"
    note "issuing this sandbox its own Deskhand token"
    qm guest exec "$VMID" --timeout 120 --         powershell.exe -NoProfile -EncodedCommand "$B64" >/dev/null 2>&1 || true
    sleep 12
else
    echo "warning: iconv missing; sandbox keeps the template's shared token" >&2
    TOKEN=""
fi

IP="$(qm guest cmd "$VMID" network-get-interfaces 2>/dev/null       | grep -oE '"ip-address" : "10\.66\.[0-9]+\.[0-9]+"'       | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"

cat <<EOF

Sandbox $VMID ($NAME) is up.
  Deskhand : http://${IP:-<no address yet>}:8791
  token    : ${TOKEN:-<unchanged: still the template default>}

  Save that token now -- it is generated per sandbox and printed only here.
  To read it back later:
    qm guest exec $VMID -- cmd.exe /c type C:\Deskhand\run-deskhand.ps1
  RDP      : ${IP:-<run: qm guest cmd $VMID network-get-interfaces>}

Reachable from the LAN only if OPNsense has the route 10.66.0.0/24 -> this node.

Throw it away when done:
  ./destroy-sandbox.sh --vmid $VMID
EOF
