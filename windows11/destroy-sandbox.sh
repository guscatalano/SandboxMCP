#!/usr/bin/env bash
#
# Throw away a sandbox.
#
#   ./destroy-sandbox.sh --vmid 900
#   ./destroy-sandbox.sh --list
#   ./destroy-sandbox.sh --all --yes
#
# This destroys a VM and its disks permanently. There is no undo, so it refuses
# anything that does not look like a sandbox:
#
#   * templates are never destroyed
#   * the VMID must be inside the sandbox range (default 900-949)
#   * the description must carry the SANDBOX marker new-sandbox.sh writes
#
# --force overrides the last two. It deliberately does not override the first.
#
set -euo pipefail

RANGE_LO="${SANDBOX_ID_LO:-900}"
RANGE_HI="${SANDBOX_ID_HI:-949}"
VMID=""
ALL=0
LIST=0
FORCE=0
YES=0

die()  { echo "error: $*" >&2; exit 1; }
note() { echo "==> $*"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --vmid)  VMID="$2"; shift 2 ;;
        --all)   ALL=1; shift ;;
        --list)  LIST=1; shift ;;
        --force) FORCE=1; shift ;;
        --yes|-y) YES=1; shift ;;
        -h|--help) sed -n '2,17p' "$0" | sed 's/^#\s\?//'; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
done

[[ $EUID -eq 0 ]] || die "run as root on a Proxmox node"

sandboxes() {
    for id in $(seq "$RANGE_LO" "$RANGE_HI"); do
        qm config "$id" >/dev/null 2>&1 || continue
        qm config "$id" | grep -q '^template: 1' && continue
        printf '%s\t%s\t%s\n' "$id" \
            "$(qm config "$id" | awk '/^name:/{print $2}')" \
            "$(qm status "$id" | awk '{print $2}')"
    done
}

if (( LIST )); then
    found="$(sandboxes)"
    if [[ -z "$found" ]]; then
        echo "no sandboxes in ${RANGE_LO}-${RANGE_HI}"
    else
        printf '%-6s %-18s %s\n' VMID NAME STATUS
        printf '%s\n' "$found" | while IFS=$'\t' read -r id name st; do
            printf '%-6s %-18s %s\n' "$id" "$name" "$st"
        done
    fi
    exit 0
fi

# ---------------------------------------------------------------------------
# Work out what to destroy
# ---------------------------------------------------------------------------
targets=()
if (( ALL )); then
    while IFS=$'\t' read -r id _ _; do [[ -n "$id" ]] && targets+=("$id"); done < <(sandboxes)
    (( ${#targets[@]} )) || { echo "no sandboxes to destroy"; exit 0; }
elif [[ -n "$VMID" ]]; then
    targets=("$VMID")
else
    die "give --vmid N, or --all, or --list"
fi

for id in "${targets[@]}"; do
    qm config "$id" >/dev/null 2>&1 || die "VM $id not found on this node"

    # Never destroy a template. This is the one guard --force does not lift:
    # losing the template means rebuilding Windows from scratch.
    qm config "$id" | grep -q '^template: 1' \
        && die "VM $id is a TEMPLATE. Refusing. (Destroy it by hand if you really mean to.)"

    if (( ! FORCE )); then
        (( id >= RANGE_LO && id <= RANGE_HI )) \
            || die "VM $id is outside the sandbox range ${RANGE_LO}-${RANGE_HI}. Use --force if you are sure."
        qm config "$id" | grep -q 'SANDBOX' \
            || die "VM $id is not marked SANDBOX in its description. Use --force if you are sure."
    fi
done

# ---------------------------------------------------------------------------
# Confirm, then destroy
# ---------------------------------------------------------------------------
echo "About to permanently destroy:"
for id in "${targets[@]}"; do
    printf '  %-6s %-18s %s\n' "$id" \
        "$(qm config "$id" | awk '/^name:/{print $2}')" \
        "$(qm status "$id" | awk '{print $2}')"
done

if (( ! YES )); then
    read -rp "Type 'destroy' to confirm: " answer
    [[ "$answer" == "destroy" ]] || { echo "aborted"; exit 1; }
fi

for id in "${targets[@]}"; do
    if [[ "$(qm status "$id" | awk '{print $2}')" == "running" ]]; then
        note "stopping $id"
        qm stop "$id" >/dev/null
        while [[ "$(qm status "$id" | awk '{print $2}')" == "running" ]]; do sleep 2; done
    fi
    note "destroying $id"
    # purge=1 also removes it from any backup job and from HA, so nothing is
    # left referring to a guest that no longer exists.
    qm destroy "$id" --purge 1 --destroy-unreferenced-disks 1
done

echo
echo "done."
