#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# FEMU lab 3, DFTL (hw/femu/docs/labs/lab3-dftl.md). Run in the guest, as
# root, on a fresh device with mapping=dftl:
#
#   sudo bash lab-dftl.sh
#
# The NAND times stay on: part B reads the latency.
#   1. fill the namespace once, sequential 128 KiB writes
#   2. for each working set W in LAB_WS (MiB, default "256 768 1024"):
#      LAB_WARM_MB (default 32) of random 4 KiB reads to warm the CMT,
#      then LAB_READ_MB (default 128) of the same reads, measured; queue
#      depth 1, over the first W MiB
#   3. LAB_WRITE_MB (default 256) of random 4 KiB writes at queue depth
#      32 over the whole namespace
# Each step prints one line:
#   LAB3 step=fill host=... tp_prog=... tp_read=...
#   LAB3 step=warm ws=W tp_read=... tp_prog=...
#   LAB3 step=read ws=W reads=N tp_read=... tp_prog=... miss=... mean_us=...
#   LAB3 step=write host=... tp_prog=... tp_read=... tp_per_host=... waf=...

set -euo pipefail
# shellcheck source-path=SCRIPTDIR
source "$(dirname "$0")/lab-common.sh"

lab_start
common=(--filename="$LAB_NS" --direct=1 --ioengine=libaio)
read_mb=${LAB_READ_MB:-128}
warm_mb=${LAB_WARM_MB:-32}
write_mb=${LAB_WRITE_MB:-256}
read -r -a sets <<<"${LAB_WS:-256 768 1024}"

lab_snap "$LAB_DIR/before.txt"
lab_fio fill --name=fill "${common[@]}" --rw=write --bs=128k --iodepth=16
lab_snap "$LAB_DIR/after.txt"
line=$(lab_diff "$LAB_DIR/before.txt" "$LAB_DIR/after.txt")
echo "LAB3 step=fill $line"

for ws in "${sets[@]}"; do
    lab_snap "$LAB_DIR/warm.txt"
    lab_fio "warm-$ws" --name=warm "${common[@]}" --rw=randread --bs=4k \
        --iodepth=1 --size="${ws}M" --io_size="${warm_mb}M" --randrepeat=0
    lab_snap "$LAB_DIR/before.txt"
    line=$(lab_diff "$LAB_DIR/warm.txt" "$LAB_DIR/before.txt")
    echo "LAB3 step=warm ws=$ws tp_read=$(lab_field "$line" tp_read)" \
        "tp_prog=$(lab_field "$line" tp_prog)"
    lab_fio "read-$ws" --name=read "${common[@]}" --rw=randread --bs=4k \
        --iodepth=1 --size="${ws}M" --io_size="${read_mb}M" --randrepeat=0
    lab_snap "$LAB_DIR/after.txt"
    line=$(lab_diff "$LAB_DIR/before.txt" "$LAB_DIR/after.txt")
    j="$LAB_DIR/read-$ws.json"
    reads=$(($(lab_fio_get "$j" read_bytes) / 4096))
    tpr=$(lab_field "$line" tp_read)
    tpp=$(lab_field "$line" tp_prog)
    miss=$(awk -v a="$tpr" -v b="$reads" 'BEGIN { printf "%.3f", a / b }')
    echo "LAB3 step=read ws=$ws reads=$reads tp_read=$tpr tp_prog=$tpp" \
        "miss=$miss mean_us=$(lab_fio_get "$j" read_clat_mean_us)" \
        "p50_us=$(lab_fio_get "$j" read_p50_us)" \
        "p99_us=$(lab_fio_get "$j" read_p99_us)"
done

lab_snap "$LAB_DIR/before.txt"
lab_fio write --name=write "${common[@]}" --rw=randwrite --bs=4k \
    --iodepth=32 --io_size="${write_mb}M" --randrepeat=0
lab_snap "$LAB_DIR/after.txt"
line=$(lab_diff "$LAB_DIR/before.txt" "$LAB_DIR/after.txt")
host=$(lab_field "$line" host)
tpp=$(lab_field "$line" tp_prog)
ratio=$(awk -v a="$tpp" -v b="$host" 'BEGIN { printf "%.3f", b ? a / b : 0 }')
bytes=$(lab_fio_get "$LAB_DIR/write.json" write_bytes)
echo "LAB3 step=write $line tp_per_host=$ratio $(lab_check_host "$host" "$bytes")"
