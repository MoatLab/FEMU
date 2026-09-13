#!/bin/bash
# Guest side of one QLC-aligned replay: load the payload, replay the trace,
# and hand everything back over the serial console.
#
# The payload arrives as a read-only virtio disk. The root disk is virtio-scsi (/dev/sda),
# so the only virtio-blk disks are the cloud-init seed and the payload, and the
# payload is by far the larger -- picked by size rather than by enumeration
# order, which is not something to bet a 7 GiB dd on.
set -euo pipefail
exec 2>&1

SRC=""
best=0
for d in /dev/vd?; do
    [ -b "$d" ] || continue
    sz=$(blockdev --getsize64 "$d" 2>/dev/null || echo 0)
    echo "[guest] virtio disk $d $sz bytes"
    if [ "$sz" -gt "$best" ]; then best=$sz; SRC=$d; fi
done
DEV=/dev/nvme0n1
CTRL=/dev/nvme0
TRACE=/root/replay.bin
OUT=/dev/shm

say() { echo "[guest] $*"; }

say "kernel $(uname -r)"
say "nvme: $(lsblk -dno NAME,SIZE /dev/nvme0n1 2>/dev/null || echo MISSING)"
[ -b "$DEV" ] || { say "FATAL no $DEV"; exit 1; }
[ -n "$SRC" ] && [ -b "$SRC" ] || { say "FATAL no payload disk found"; lsblk; exit 1; }
say "payload disk is $SRC"

# 4 MiB is the compiler's cap; current Qwen replay commands are <=256 KiB.
# max_sectors_kb is only one split limit. Record segment limits as well;
# a userspace AIO command count need not equal the NVMe command count.
Q=/sys/block/nvme0n1/queue
say "max_hw_sectors_kb=$(cat $Q/max_hw_sectors_kb) max_sectors_kb=$(cat $Q/max_sectors_kb)"
cat "$Q/max_hw_sectors_kb" > "$Q/max_sectors_kb" 2>/dev/null || true
echo none > "$Q/scheduler" 2>/dev/null || true
say "max_sectors_kb now $(cat $Q/max_sectors_kb), scheduler $(cat $Q/scheduler)"
say "memory_page_bytes=$(getconf PAGESIZE) max_segments=$(cat $Q/max_segments) max_segment_size=$(cat $Q/max_segment_size)"
if [ "$(cat $Q/max_sectors_kb)" -lt 256 ]; then
    say "WARNING below the 256 KiB largest replay command; the device will see more commands than the trace has"
fi

IMG_BYTES=$(blockdev --getsize64 "$SRC")
say "payload disk $IMG_BYTES bytes"
[ "$IMG_BYTES" -le "$(blockdev --getsize64 "$DEV")" ] || { say "FATAL payload exceeds namespace"; exit 1; }
[ "$((IMG_BYTES % 16384))" -eq 0 ] || { say "FATAL image is not NAND-page aligned"; exit 1; }

# Leave one memory-page segment for a potentially unaligned userspace buffer.
# Fail rather than silently returning to a fill size that can split mid-page.
MEM_PAGE=$(getconf PAGESIZE)
SEGMENTS=$(cat "$Q/max_segments")
SEG_SIZE=$(cat "$Q/max_segment_size")
MAX_KB=$(cat "$Q/max_sectors_kb")
HW_KB=$(cat "$Q/max_hw_sectors_kb")
[ "$SEG_SIZE" -ge "$MEM_PAGE" ] && [ "$SEGMENTS" -ge "$((262144 / MEM_PAGE + 1))" ] &&
    [ "$MAX_KB" -ge 256 ] && [ "$HW_KB" -ge 256 ] || {
    say "FATAL queue limits do not satisfy the 256 KiB fill contract"; exit 1;
}

say "=== fill: sequential write from LBA 0 ==="
t0=$(date +%s.%N)
# bs is capped well under the queue's max_segments (127) on purpose. A larger
# O_DIRECT write is split by the block layer at a 127-segment = 508 KiB boundary,
# which falls in the middle of the 32nd 16 KiB flash page. That page then belongs
# to both fragments, so it is written twice, and out-of-place update spends an
# extra physical page -- shifting every later page one slot along and scrambling
# the QLC class the layout counted on. With the observed 4 KiB pages and
# max_segments=127, a page-aligned 256 KiB buffer needs at most 64 page segments.
# This is configuration-dependent: PPA verification is still required.
dd if="$SRC" of="$DEV" bs=256k iflag=fullblock oflag=direct conv=fsync status=none || { say "FATAL fill"; exit 1; }
t1=$(date +%s.%N)
say "fill done in $(echo "$t1 - $t0" | bc) s"

say "=== read-back verification ==="
SRC_SHA=$(dd if="$SRC" bs=4M iflag=direct,fullblock status=none | sha256sum | cut -d' ' -f1)
DST_SHA=$(dd if="$DEV" bs=4M count="$IMG_BYTES" iflag=direct,fullblock,count_bytes status=none | sha256sum | cut -d' ' -f1)
say "payload sha256 $SRC_SHA"
say "device  sha256 $DST_SHA"
[ "$SRC_SHA" = "$DST_SHA" ] && say "read-back OK" || { say "FATAL read-back mismatch"; exit 1; }

# The replay's class prediction is only as good as the assumed LPN->PPA order.
# Read it back off the clock before trusting it: two windows, one at the start of
# the image and one deep inside it, so a pattern that drifts is visible.
# Stop here. Everything past the fill is driven over ssh instead, one step at a
# time, so the QLC counter file can be read on the host between steps -- the
# guest cannot see that file, and each snapshot overwrites the last.
say "device is filled and verified; driving the rest over ssh"
say "ALL DONE"
