#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# FEMU lab 4, Flexible Data Placement (hw/femu/docs/labs/lab4-fdp.md).
# Run in the guest, as root, on a fresh device with a 384 MiB namespace:
#
#   sudo bash lab-fdp.sh fdp|untagged [all|prefill|run]
#
#   fdp       hot writes use placement index 0, cold writes index 1; the
#             namespace must report two placement identifiers or more
#   untagged  no placement directive: for a device with no FDP, or for
#             untagged writes on an FDP device
#   all       prefill, then run (the default)
#   prefill   write the namespace once (cold placement with "fdp"),
#             then take the "before" sample and stop
#   run       the measured run, from the sample of "prefill"
#
# Split the steps to read the per-handle counters on the host between
# them. The job is the one of tutorial 04: a hot 64 MiB region of random
# 4 KiB overwrites and a cold 320 MiB region of sequential rewrites,
# 1 GiB each. The NAND times are off. There is no aging step: the run
# starts right after the prefill, as in tutorial 04. The last line is
#   LAB4 mode=... host=... gc=... nand=... forced_passes=... waf=...
#        hbmw=... mbmw=... check=ok
# LAB_NG (default /dev/ng0n1) is the generic node fio writes through.

set -euo pipefail
# shellcheck source-path=SCRIPTDIR
source "$(dirname "$0")/lab-common.sh"

ng=${LAB_NG:-/dev/ng0n1}
mode=${1:-}
step=${2:-all}
case $mode in
fdp) place=(--fdp=1) hot=(--fdp_pli=0) cold=(--fdp_pli=1) ;;
untagged) place=() hot=() cold=() ;;
*)
    echo "usage: sudo bash $0 fdp|untagged [all|prefill|run]" >&2
    exit 2
    ;;
esac
case $step in
all | prefill | run) ;;
*) lab_die "unknown step $step" ;;
esac

lab_start
[[ -c $ng ]] || lab_die "$ng is not a character device"
if [[ $mode == fdp ]]; then
    pids=$(nvme fdp status "$LAB_NS" 2>/dev/null |
        grep -c 'Placement Identifier') || pids=0
    ((pids >= 2)) ||
        lab_die "the namespace reports $pids placement identifiers, not 2 or more"
fi
job=(--filename="$ng" --ioengine=io_uring_cmd --cmd_type=nvme --bs=4k
    --iodepth=8 "${place[@]}")

if [[ $step != run ]]; then
    lab_time_off
    lab_fio prefill --name=prefill "${job[@]}" "${cold[@]}" --rw=write \
        --size=384M
    lab_snap "$LAB_DIR/before.txt"
    echo "LAB4 prefill=ok"
fi
if [[ $step == prefill ]]; then
    exit 0
fi
[[ -s $LAB_DIR/before.txt ]] || lab_die "no prefill sample; run the prefill step first"

lab_fio run "${job[@]}" --randrepeat=0 \
    --name=hot "${hot[@]}" --rw=randwrite --offset=0 --size=64M \
    --io_size=1G \
    --name=cold "${cold[@]}" --rw=write --offset=64M --size=320M \
    --io_size=1G
lab_snap "$LAB_DIR/after.txt"

line=$(lab_diff "$LAB_DIR/before.txt" "$LAB_DIR/after.txt")
bytes=$(lab_fio_get "$LAB_DIR/run.json" write_bytes)
stats=""
if s=$(nvme fdp stats "$LAB_CTRL" -e 1 2>/dev/null); then
    hb=$(sed -n 's/.*(HBMW): *\([0-9]*\).*/\1/p' <<<"$s")
    mb=$(sed -n 's/.*(MBMW): *\([0-9]*\).*/\1/p' <<<"$s")
    stats="hbmw=${hb:-none} mbmw=${mb:-none} "
fi
echo "LAB4 mode=$mode $line $stats$(lab_check_host "$(lab_field "$line" host)" "$bytes")"
