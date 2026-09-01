#!/bin/bash
#
# Expand a config file into the QEMU "-device" arguments for an emulated SSD.
#
# One file describes the whole device -- mode, capacity, NAND geometry and
# timing, FTL policy, caches, ZNS/FDP/CSD/KV settings -- instead of a single
# unreadable "-device femu,a=,b=,c=,..." line. FEMU has well over a hundred
# properties; a config file is the difference between a run script you can read
# and one you copy blindly.
#
# Usage:
#   ssd-config.sh <config>                 print the full "-device ..." arguments
#   ssd-config.sh <config> --device-only   print them without the "-device" words
#   ssd-config.sh <config> --check         validate only, print nothing
#   ssd-config.sh --help
#
# Format is INI-ish: "key = value", one per line. '#' and ';' start a comment.
# Keys map one to one onto FEMU's device properties, so anything in
# `qemu-system-x86_64 -device femu,help` is a valid key and means exactly what it
# means there. A key with an empty value is ignored, so a config can list every
# knob it cares about and leave the rest blank.
#
# Two conveniences on top of that:
#
#   mode = bbssd|znssd|nossd|ocssd|csd|kvssd   friendly name for femu_mode
#   [subsys] section                           emitted as a separate
#                                              -device femu-subsys,... and
#                                              wired to the femu device
#
# The [subsys] part matters for FDP: those properties live on the subsystem
# object rather than on the femu device, which is the usual thing people get
# wrong when setting FDP up by hand.
#
# Keys are checked against the emulator itself when one can be found (set
# FEMU_BIN, or leave the build where the compile script puts it), so this cannot
# fall behind the properties FEMU actually has.

set -euo pipefail

usage() {
    sed -n '3,37p' "$0" | sed 's/^# \{0,1\}//'
}

die() { printf 'ssd-config: %s\n' "$*" >&2; exit 1; }
warn() { printf 'ssd-config: %s\n' "$*" >&2; }

case "${1:-}" in
    --help|-h) usage; exit 0 ;;
    "")        usage >&2; exit 1 ;;
esac

CONF="$1"; shift
MODE_OUT=full
for arg in "$@"; do
    case "$arg" in
        --device-only) MODE_OUT=device ;;
        --check)       MODE_OUT=check ;;
        *)             die "unknown option: $arg" ;;
    esac
done
[[ -r "$CONF" ]] || die "config not readable: $CONF"

# ---------------------------------------------------------------- find FEMU
# Only used to validate keys. Not finding it is not fatal; the config still
# expands, we just cannot catch a typo.
find_femu_bin() {
    if [[ -n "${FEMU_BIN:-}" ]]; then
        [[ -x "$FEMU_BIN" ]] && { printf '%s' "$FEMU_BIN"; return; }
        warn "FEMU_BIN=$FEMU_BIN is not executable; falling back to a search"
    fi
    local here root c
    here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    root="$(cd "$here/../../.." && pwd)"
    for c in "$root/build-femu/qemu-system-x86_64" \
             "$root/build/qemu-system-x86_64" \
             "$root/build-official/qemu-system-x86_64"; do
        [[ -x "$c" ]] && { printf '%s' "$c"; return; }
    done
    printf ''
}

# props_of <device>  ->  one property name per line
props_of() {
    "$FEMU" -device "$1,help" 2>&1 |
        sed -n 's/^  \([A-Za-z0-9_.-]*\)=.*/\1/p'
}

FEMU="$(find_femu_bin)"
# assigned, not merely declared: "set -u" trips on ${#arr[@]} of an unset array,
# which is what happens when the emulator cannot be queried
declare -A DEV_PROPS=() SUBSYS_PROPS=()
if [[ -n "$FEMU" ]]; then
    while read -r p; do [[ -n "$p" ]] && DEV_PROPS["$p"]=1; done < <(props_of femu)
    while read -r p; do [[ -n "$p" ]] && SUBSYS_PROPS["$p"]=1; done < <(props_of femu-subsys)
    (( ${#DEV_PROPS[@]} )) || warn "could not read properties from $FEMU; keys unchecked"
else
    warn "no FEMU binary found (set FEMU_BIN to enable key checking)"
fi

# ---------------------------------------------------------------- parse
declare -A DEV SUBSYS
# initialised, not merely declared: "set -u" trips on an unset array
DEV_ORDER=()
SUBSYS_ORDER=()
section=device
lineno=0
while IFS= read -r line || [[ -n "$line" ]]; do
    lineno=$((lineno + 1))
    line="${line%%#*}"; line="${line%%;*}"
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" ]] && continue

    if [[ "$line" == \[*\] ]]; then
        case "${line,,}" in
            "[subsys]"|"[subsystem]") section=subsys ;;
            *)                        section=device ;;   # other headers read as labels
        esac
        continue
    fi

    [[ "$line" == *=* ]] || die "$CONF:$lineno: not a 'key = value' line: $line"
    key="${line%%=*}"; val="${line#*=}"
    key="${key#"${key%%[![:space:]]*}"}"; key="${key%"${key##*[![:space:]]}"}"
    val="${val#"${val%%[![:space:]]*}"}"; val="${val%"${val##*[![:space:]]}"}"
    [[ -n "$key" ]] || die "$CONF:$lineno: empty key"
    [[ -z "$val" ]] && continue

    if [[ "$section" == subsys ]]; then
        [[ -n "${SUBSYS[$key]:-}" ]] || SUBSYS_ORDER+=("$key")
        SUBSYS["$key"]="$val"
    else
        [[ -n "${DEV[$key]:-}" ]] || DEV_ORDER+=("$key")
        DEV["$key"]="$val"
    fi
done < "$CONF"

# ---------------------------------------------------------------- mode
mode_to_int() {
    case "${1,,}" in
        ocssd) echo 0 ;; bbssd) echo 1 ;; nossd) echo 2 ;;
        znssd|zns) echo 3 ;; csd) echo 4 ;; kvssd|kv) echo 5 ;;
        *) die "unknown mode '$1' (ocssd|bbssd|nossd|znssd|csd|kvssd)" ;;
    esac
}
if [[ -n "${DEV[mode]:-}" ]]; then
    [[ -n "${DEV[femu_mode]:-}" ]] && die "set either 'mode' or 'femu_mode', not both"
    DEV[femu_mode]="$(mode_to_int "${DEV[mode]}")"
    DEV_ORDER+=(femu_mode)
    unset 'DEV[mode]'
fi

# ---------------------------------------------------------------- validate
bad=0
if (( ${#DEV_PROPS[@]} )); then
    for k in ${DEV_ORDER[@]+"${DEV_ORDER[@]}"}; do
        [[ -n "${DEV[$k]:-}" ]] || continue
        if [[ -z "${DEV_PROPS[$k]:-}" ]]; then
            if [[ -n "${SUBSYS_PROPS[$k]:-}" ]]; then
                warn "'$k' is a subsystem property; move it under [subsys]"
            else
                warn "unknown property '$k' -- not one FEMU accepts"
            fi
            bad=1
        fi
    done
    for k in ${SUBSYS_ORDER[@]+"${SUBSYS_ORDER[@]}"}; do
        [[ -n "${SUBSYS_PROPS[$k]:-}" ]] || { warn "unknown subsystem property '$k'"; bad=1; }
    done
fi
(( bad )) && die "config rejected; see the warnings above"

# ---------------------------------------------------------------- emit
# A value containing ',' has to be escaped as ',,' or QEMU reads it as the end of
# the property (namespace_modes and namespace_sizes are the ones that bite).
esc() { printf '%s' "${1//,/,,}"; }

SUBSYS_ID="${SUBSYS[id]:-femu-subsys-0}"
dev_args="femu"
[[ -n "${DEV[id]:-}" ]] || dev_args="${dev_args},id=nvme0"

if (( ${#SUBSYS_ORDER[@]} )); then
    sub_args="femu-subsys,id=${SUBSYS_ID}"
    [[ -n "${SUBSYS[nqn]:-}" ]] || sub_args="${sub_args},nqn=subsys0"
    for k in ${SUBSYS_ORDER[@]+"${SUBSYS_ORDER[@]}"}; do
        [[ "$k" == id ]] && continue
        sub_args="${sub_args},${k}=$(esc "${SUBSYS[$k]}")"
    done
fi

for k in ${DEV_ORDER[@]+"${DEV_ORDER[@]}"}; do
    [[ -n "${DEV[$k]:-}" ]] || continue
    dev_args="${dev_args},${k}=$(esc "${DEV[$k]}")"
done
# tie the device to its subsystem unless the config already did
if (( ${#SUBSYS_ORDER[@]} )) && [[ -z "${DEV[subsys]:-}" ]]; then
    dev_args="${dev_args},subsys=${SUBSYS_ID}"
fi

[[ "$MODE_OUT" == check ]] && exit 0

if [[ "$MODE_OUT" == device ]]; then
    (( ${#SUBSYS_ORDER[@]} )) && printf '%s ' "$sub_args"
    printf '%s\n' "$dev_args"
else
    (( ${#SUBSYS_ORDER[@]} )) && printf -- '-device %s ' "$sub_args"
    printf -- '-device %s\n' "$dev_args"
fi
