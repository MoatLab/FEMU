#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Build the CCA tools and run their self-test inside a guest, as root.
#
#   run-guest-tests.sh [-d MEMDEV] [-x DAX] [-o LOG] [CASE...]
#
# MEMDEV defaults to mem0. DAX defaults to the devdax device of a
# non-interleaved region on MEMDEV; without one, cases that need a
# mapping are skipped. CASE is any cca-test case, including
# before-reboot and after-reboot for a runner that reboots the guest in
# between. With no case, every default case runs. The log (default:
# cca-guest-<date>.log in the current directory) records the kernel,
# BAR5 assignment and the test output.
set -euo pipefail

dir=$(cd "$(dirname "$0")" && pwd)
memdev=mem0
dax=""
log=""

usage() {
    sed -n '4,15p' "$0" >&2
    exit 2
}

while getopts "d:x:o:h" opt; do
    case "$opt" in
    d) memdev=$OPTARG ;;
    x) dax=$OPTARG ;;
    o) log=$OPTARG ;;
    *) usage ;;
    esac
done
shift $((OPTIND - 1))
cases=("$@")
log=${log:-cca-guest-$(date +%Y%m%d-%H%M%S).log}

if ((EUID != 0)); then
    echo "run-guest-tests.sh: resource5 mappings need root" >&2
    exit 1
fi

# The devdax device whose region targets a decoder of this memdev.
find_dax() {
    local want d region target uport

    want=$(realpath "/sys/bus/cxl/devices/$memdev" 2>/dev/null) || return 0
    for d in /sys/bus/dax/devices/dax*; do
        [[ -e $d ]] || continue
        region=$(dirname "$(dirname "$(realpath "$d")")")
        [[ $(basename "$region") == region* ]] || continue
        [[ $(cat "$region/interleave_ways" 2>/dev/null) == 1 ]] || continue
        target=$(cat "$region/target0" 2>/dev/null) || continue
        uport=$(realpath "/sys/bus/cxl/devices/$target/../uport" 2>/dev/null) ||
            continue
        [[ $uport == "$want" ]] || continue
        # kmem would have onlined the range as system RAM instead.
        [[ $(basename "$(realpath "$d/driver" 2>/dev/null)") == device_dax ]] ||
            continue
        basename "$d"
        return 0
    done
}

report_env() {
    local pci bdf

    echo "== $(date -Is) $(uname -r) memdev=$memdev dax=${dax:-none}"
    pci=$(realpath "/sys/bus/cxl/devices/$memdev/.." 2>/dev/null) || {
        echo "no $memdev under /sys/bus/cxl/devices"
        return 0
    }
    bdf=$(basename "$pci")
    echo "== PCI function $bdf"
    # Whether firmware assigned BAR5 under the CXL host bridge.
    if command -v lspci >/dev/null; then
        lspci -vv -s "$bdf" 2>/dev/null | grep -E 'Region [0-9]' || true
    fi
    sed -n '6p' "$pci/resource" 2>/dev/null | sed 's/^/resource5: /' || true
    ls -l "$pci/resource5" 2>/dev/null || echo "no resource5 file"
}

make -C "$dir" >/dev/null
dax=${dax:-$(find_dax)}
{
    report_env
    rc=0
    # bash before 4.4 calls an empty array unbound under set -u.
    "$dir/cca-test" -d "$memdev" ${dax:+-x "$dax"} ${cases[@]+"${cases[@]}"} \
        || rc=$?
    echo "== cca-test exit $rc"
    exit "$rc"
} 2>&1 | tee "$log"
