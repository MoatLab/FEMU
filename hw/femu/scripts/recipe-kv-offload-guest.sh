#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Workload recipe: KV-cache offload of two tenants on a raw FEMU BlackBox
# namespace, with or without Flexible Data Placement (FDP). The recipe is
# an fio stand-in for an inference server. It needs no accelerator.
#
#   sudo bash recipe-kv-offload-guest.sh --yes [NAMESPACE]
#
# NAMESPACE is a block device name such as nvme0n1 (the default). The
# script writes over the whole namespace, so --yes is necessary. It needs
# fio 3.34 or newer with the io_uring_cmd engine, nvme-cli, and
# fio/gpu-kv-offload-fdp.fio and recipe-guest-lib.sh next to this script.
# It installs nothing.
#
#   prefill   sequential write of each region (three placement indexes
#             with FDP)
#   run       fio/gpu-kv-offload-fdp.fio for KVO_RUNTIME seconds
#   counters  log page C0h and the block layer, before and after the run
#
# Pass criterion:
#   - with KVO_FDP=1, the namespace reports three placement identifiers
#     or more;
#   - the prefill and the run exit 0 inside their time limits;
#   - fio reports stores and loads, and no error;
#   - the host pages of log page C0h grow by at least 90% of the bytes
#     that fio stored, so the stores reached the FTL;
#   - with KVO_FDP=1, the FDP statistics count at least 90% of the bytes
#     that fio stored.
# PASS means that the recipe ran and the counters moved. It is not a
# statement on performance. Compare the WAF of an FDP run with the WAF
# of a control run to see what placement does.
#
# Environment:
#   KVO_FDP        1: place each store; 0: no placement (the control);
#                  default: 1 when the namespace reports placement
#                  identifiers, else 0
#   KVO_RUNTIME    seconds of the run (default 240)
#   KVO_CONTROL    Use it only to show that the checks can fail.
#                  no-store: run the load job alone, so the check that
#                  the stores ran must fail.
#                  frozen-counters: use the first counter sample two
#                  times, so the two counter checks must fail.
#   RECIPE_CTRL    controller device (default /dev/nvmeX of the namespace)
#   WORKDIR        parent of the new scratch directory (default /tmp)
#
# Summary lines start with KVO_. The last line is
# KVO_RESULT=PASS|FAIL|SETUP-ERROR with key=value fields. The exit status
# is 0 when each check passed, 1 when one failed and 2 when the setup
# failed.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
readonly RECIPE=KVO
readonly PREFILL_RATE=64m
readonly PAGE=4096

# shellcheck source-path=SCRIPTDIR source=recipe-guest-lib.sh
source "$SCRIPT_DIR/recipe-guest-lib.sh" || {
    echo "KVO_RESULT=SETUP-ERROR reason=missing-recipe-guest-lib.sh"
    exit 2
}

usage() {
    echo "usage: sudo bash $(basename "$0") --yes [NAMESPACE]" >&2
    setup_fail usage
}

[[ ${1:-} == --yes ]] || usage
shift
[[ $# -le 1 ]] || usage

fdp=${KVO_FDP:-auto}
runtime=${KVO_RUNTIME:-240}
control=${KVO_CONTROL:-}
parent=${WORKDIR:-/tmp}
job=$SCRIPT_DIR/fio/gpu-kv-offload-fdp.fio

need_number runtime
case $fdp in
auto | 0 | 1) ;;
*) setup_fail "bad-fdp-$fdp" ;;
esac
case $control in
'' | no-store | frozen-counters) ;;
*) setup_fail "bad-control-$control" ;;
esac
[[ $EUID -eq 0 ]] || setup_fail not-root
[[ -r $job ]] || setup_fail missing-gpu-kv-offload-fdp.fio
for tool in fio nvme python3 lsblk blockdev timeout; do
    command -v "$tool" >/dev/null || setup_fail "no-$tool"
done
fio --enghelp=io_uring_cmd 2>/dev/null | grep -q cmd_type ||
    setup_fail fio-has-no-io_uring_cmd

resolve_namespace "${1:-nvme0n1}"
[[ -c $gen_dev ]] || setup_fail "no-generic-node-${gen_dev#/dev/}"
workdir=$(mktemp -d "$parent/femu-kv-offload.XXXXXX") || setup_fail mktemp
recipe_workdir=$workdir
echo "KVO_DEVICE=$ns_name generic=$gen_dev workdir=$workdir"

# Placement identifiers of the namespace: 0 without FDP.
pids=0
fdp_query=ok
fdp_status=$(LC_ALL=C bounded 60 nvme fdp status "$ns_dev" 2>/dev/null) ||
    fdp_query=failed
if [[ $fdp_query == ok ]]; then
    pids=$(grep -c 'Placement Identifier' <<<"$fdp_status" || true)
fi
# A query that fails is the normal answer of a device with no FDP, so
# "auto" then selects the control. KVO_FDP=1 makes FDP a condition.
if [[ $fdp == auto ]]; then
    fdp=$((pids >= 3 ? 1 : 0))
    echo "KVO_FDP_SELECT=auto status_query=$fdp_query"
fi
if ((fdp == 1 && pids < 3)); then
    setup_fail "fdp-needs-3-placement-ids-found-$pids"
fi
echo "KVO_FDP=$fdp placement_ids=$pids"

size=$(blockdev --getsize64 "$ns_dev") || setup_fail no-size
((size >= 512 * 1024 * 1024)) || setup_fail "namespace-below-512m"

# HBMW of the FDP statistics log, in bytes. Without FDP the value is 0.
# With FDP, a log that does not give a plain number is a setup failure.
# nvme-cli can print digit groups, so the C locale is set and "," removed.
fdp_host_bytes() {
    local v

    if ((fdp == 0)); then
        echo 0
        return 0
    fi
    v=$(LC_ALL=C bounded 60 nvme fdp stats "$ctrl_dev" -e 1 2>/dev/null |
        sed -nE 's/.*\(HBMW\): *([0-9,]+).*/\1/p' | head -n 1 |
        tr -d ,) || true
    [[ $v =~ ^[0-9]+$ ]] || return 1
    echo "$v"
}

# Fill each region one time, so that a load reads programmed pages and
# each store of the run writes over valid data. fio rounds a percent
# offset up and a percent size down to 128 KiB, so one block between two
# regions can stay empty. No job of the run reads that block.
prefill_limit=$((size / (32 * 1024 * 1024) + 120))
prefill=(fio --ioengine=io_uring_cmd --cmd_type=nvme "--filename=$gen_dev"
    --thread=1 --bs=128k --iodepth=4 --rw=write "--rate=$PREFILL_RATE"
    "--fdp=$fdp"
    --name=fill-short --size=12% --fdp_pli=0
    --name=fill-long --offset=12% --size=63% --fdp_pli=1
    --name=fill-load --offset=75% --size=25% --fdp_pli=2)
rc=0
bounded "$prefill_limit" "${prefill[@]}" >"$workdir/prefill.log" 2>&1 || rc=$?
if ((rc != 0)); then
    tail -n 5 "$workdir/prefill.log"
    setup_fail "prefill-status-$rc"
fi
echo "KVO_PREFILL=ok namespace_bytes=$size"

sections=()
[[ $control == no-store ]] && sections=(--section=kv-load)

sample before
hbmw_before=$(fdp_host_bytes) || setup_fail no-fdp-statistics
rc=0
FEMU_DEV=$gen_dev FEMU_FDP=$fdp FEMU_RUNTIME=$runtime \
    bounded "$((runtime + 120))" fio --output-format=json \
    "--output=$workdir/run.json" "${sections[@]}" "$job" \
    >"$workdir/run.log" 2>&1 || rc=$?
sample after
hbmw_after=$(fdp_host_bytes) || setup_fail no-fdp-statistics
if [[ $control == frozen-counters ]]; then
    # shellcheck disable=SC2034,SC2154  # sample fills both by name
    after=("${before[@]}")
    hbmw_after=$hbmw_before
fi
if ((rc != 0)); then
    tail -n 5 "$workdir/run.log"
    check_fail "fio-status-$rc"
fi

# Bytes stored and loaded, the error count, and the jobs with no I/O in
# their direction, from the fio report. Each job of the run must do I/O.
fio_sum=$(python3 - "$workdir/run.json" "$control" <<'EOF'
import json
import sys

WANT = {"kv-store-short": "write", "kv-store-long": "write",
        "kv-load": "read"}
if sys.argv[2] == "no-store":
    WANT = {"kv-load": "read"}
try:
    with open(sys.argv[1]) as f:
        jobs = json.load(f)["jobs"]
    seen = {j["jobname"]: j for j in jobs}
    idle = [n for n, d in sorted(WANT.items())
            if n not in seen or seen[n][d]["io_bytes"] <= 0]
    print(sum(j["write"]["io_bytes"] for j in jobs),
          sum(j["read"]["io_bytes"] for j in jobs),
          sum(j["error"] for j in jobs),
          ",".join(idle) or "none")
except (OSError, ValueError, KeyError, TypeError):
    print("0 0 1 no-report")
EOF
) || fio_sum="0 0 1 no-report"
read -r stored loaded errors idle <<<"$fio_sum" || true
stored=${stored:-0}
loaded=${loaded:-0}
errors=${errors:-1}
idle=${idle:-no-report}
echo "KVO_FIO=stored_bytes=$stored loaded_bytes=$loaded errors=$errors" \
    "idle_jobs=$idle"

counter_change run before after
hbmw=$((hbmw_after - hbmw_before))
echo "KVO_FDP_STATS=host_bytes=$hbmw"

((errors == 0)) || check_fail "fio-errors-$errors"
((loaded > 0)) || check_fail no-load
((stored > 0)) || check_fail no-store
[[ $idle == none ]] || check_fail "idle-jobs-$idle"
if ((stored > 0)); then
    at_least_90 "$((d_host * PAGE))" "$stored" ||
        check_fail "c0-host-pages-below-stores"
    if ((fdp == 1)); then
        at_least_90 "$hbmw" "$stored" ||
            check_fail "fdp-host-bytes-below-stores"
    fi
fi

recipe_finish "recipe=kv-offload" "fdp=$fdp" "runtime=$runtime" \
    "stored_bytes=$stored" "waf=$d_waf" "control=${control:-none}"
