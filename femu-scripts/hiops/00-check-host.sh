#!/bin/bash
# Step 0: verify the host is ready (hugepages, mount, artifacts, no stale VM).
cd "$(dirname "$0")" && . ./env.sh

echo "=== host kernel cmdline (need 1G hugepages + iommu; see HIOPS.md) ==="
grep -oE 'hugepagesz=1G|hugepages=[0-9]+|intel_iommu=[^ ]+|mitigations=off' /proc/cmdline || \
  echo "  WARNING: expected 1G hugepages / intel_iommu on the cmdline"

echo "=== hugepage pools (need >= ${MEM%G} free 1G on node$GUEST_NODE) ==="
for n in 0 1; do echo "  node$n 1G free: $(hp1g_free $n)"; done
echo "  2M free: $(cat /sys/kernel/mm/hugepages/hugepages-2048kB/free_hugepages)"
mount | grep -q /dev/hugepages || { echo "  mounting hugetlbfs"; sudo mount -t hugetlbfs hugetlbfs /dev/hugepages; }

echo "=== NUMA topology (this harness assumes node0=even CPUs, node1=odd) ==="
for n in 0 1; do echo "  node$n cpus: $(cat /sys/devices/system/node/node$n/cpulist)"; done

echo "=== stale VM? ==="
echo "  $VM_NAME procs: $(pgrep -fc "name $VM_NAME")"

echo "=== artifacts present? ==="
for f in "$QEMU" "$BASE_IMG" "$SEED"; do [ -e "$f" ] && echo "  OK  $f" || echo "  MISSING $f"; done
