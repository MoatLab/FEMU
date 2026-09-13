#!/bin/bash
# Bring the guest to a usable state and stop. Everything else runs over SSH.
#
# The serial console is one-shot: cloud-init runs what the seed says and then the
# machine just sits there. Putting an experiment in the seed therefore costs a
# boot and a device fill per question. This script only prepares the device and
# gets out of the way.
set -uo pipefail
exec 2>&1
Q=/sys/block/nvme0n1/queue
echo "[guest] kernel $(uname -r)"
echo "[guest] nvme $(lsblk -dno NAME,SIZE /dev/nvme0n1 2>/dev/null)"
cat "$Q/max_hw_sectors_kb" > "$Q/max_sectors_kb" 2>/dev/null || true
echo none > "$Q/scheduler" 2>/dev/null || true
echo "[guest] max_sectors_kb $(cat $Q/max_sectors_kb), scheduler $(cat $Q/scheduler)"
for d in /dev/vd?; do
    [ -b "$d" ] && echo "[guest] virtio $d $(blockdev --getsize64 "$d") bytes"
done
echo "[guest] READY, device NOT filled; drive the rest over ssh"
