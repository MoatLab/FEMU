#!/bin/bash
# Step 3: pin the guest vCPUs to node0 cores and the FEMU pollers to node1
# cores (everything else -> node1), then print the isolation check. Run this
# AFTER step 2, once the femu-poller threads exist.
#
# This assumes node0 = even logical CPUs, node1 = odd (the common 2-socket
# interleave; verify with `cat /sys/devices/system/node/node0/cpulist`). Adjust
# the taskset targets below if your host enumerates the sockets differently.
cd "$(dirname "$0")" && . ./env.sh

QP=$(qemu_pid)
[ -z "$QP" ] && { echo "no live QEMU found"; exit 1; }
echo "QP=$QP nthreads=$(sudo ls /proc/$QP/task | wc -l)"

VC=0; PL=0
for T in $(sudo ls /proc/$QP/task); do
  C=$(sudo cat /proc/$QP/task/$T/comm 2>/dev/null)
  case "$C" in
    CPU*KVM*)    sudo taskset -pc $((4 + VC*2)) "$T" >/dev/null 2>&1; VC=$((VC+1)) ;; # node0 even
    femu-poller*) sudo taskset -pc $((5 + PL*2)) "$T" >/dev/null 2>&1; PL=$((PL+1)) ;; # node1 odd
    *)           sudo taskset -pc 1,3 "$T" >/dev/null 2>&1 ;;                          # node1 helpers
  esac
done
echo "pinned: $VC vCPUs -> node0 even, $PL femu-pollers -> node1 odd"
[ "$PL" -eq 0 ] && echo "WARNING: 0 pollers found -- run step 2 first, and check the" \
                        "poller thread name fits the 15-char comm limit."

echo "=== isolation check ==="
for n in 0 1; do echo "  node$n 1G free: $(hp1g_free $n)"; done
echo "  sample poller affinity:"
for t in $(sudo ls /proc/$QP/task); do c=$(sudo cat /proc/$QP/task/$t/comm 2>/dev/null); \
  [ "${c#femu-poller}" != "$c" ] && echo "    $c -> $(sudo taskset -pc $t 2>/dev/null | grep -oE '[0-9,-]+$')"; \
done | head -3
