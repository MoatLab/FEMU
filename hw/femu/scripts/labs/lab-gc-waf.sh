#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# FEMU lab 1, GC and WAF (hw/femu/docs/labs/lab1-gc-and-waf.md).
# Run in the guest, as root, on a fresh device:
#
#   sudo bash lab-gc-waf.sh [extra fio options]
#
# It fills the namespace, ages it with 4 GiB of random 4 KiB writes, then
# measures one more 4 GiB run from the C0h counters. The last line is
#   LAB1 host=... gc=... nand=... forced_passes=... waf=... check=ok
# LAB_TIME=on keeps the NAND and GC times (the run takes minutes, not
# seconds). LAB_IO (default 4G) sets the size of the aging and the run.

set -euo pipefail
# shellcheck source-path=SCRIPTDIR
source "$(dirname "$0")/lab-common.sh"

lab_start
if [[ ${LAB_TIME:-off} != on ]]; then
    lab_time_off
fi
io=${LAB_IO:-4G}
common=(--filename="$LAB_NS" --direct=1 --ioengine=libaio)
rand=(--rw=randwrite --bs=4k --iodepth=32 --io_size="$io" --randrepeat=0)

lab_fio fill --name=fill "${common[@]}" --rw=write --bs=128k --iodepth=16
lab_fio age --name=age "${common[@]}" "${rand[@]}" "$@"
lab_snap "$LAB_DIR/before.txt"
lab_fio run --name=run "${common[@]}" "${rand[@]}" "$@"
lab_snap "$LAB_DIR/after.txt"

line=$(lab_diff "$LAB_DIR/before.txt" "$LAB_DIR/after.txt")
bytes=$(lab_fio_get "$LAB_DIR/run.json" write_bytes)
echo "LAB1 $line $(lab_check_host "$(lab_field "$line" host)" "$bytes")"
