#!/bin/bash
# Drive the whole socket-isolation benchmark end to end.
#   bash run-all.sh                       # isolated, SPDK bdevperf, 512B
#   IOSIZE=4096 bash run-all.sh           # 4 KiB
#   ENGINE=fio bash run-all.sh            # fio + SPDK plugin
#   GUEST_NODE=1 bash run-all.sh          # non-isolated baseline (all on node1)
# Each step (00..04) is also runnable standalone for debugging.
set -e
cd "$(dirname "$0")"
bash 00-check-host.sh
bash 01-launch-vm.sh
bash 02-guest-prep.sh
bash 03-pin.sh
bash 04-measure.sh
echo "=== done ==="
