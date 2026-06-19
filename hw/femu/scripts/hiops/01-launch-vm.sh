#!/bin/bash
# Step 1: launch the VM. Guest RAM -> node$GUEST_NODE (1G pages); the emulated
# backend (mbe) -> node1 via FEMU_MBE_INTERLEAVE=1. Detaches via setsid+nohup so
# QEMU survives this shell closing. Device flags reflect only the upstreamed
# high-IOPS series (multipoller + poller_ratio + hiops_inline default-on).
cd "$(dirname "$0")" && . ./env.sh

echo "killing any stale $VM_NAME ..."; kill_vm; sleep 4
rm -f "$LOG" "$IMG"
"$FEMU_BUILD/qemu-img" create -f qcow2 -b "$BASE_IMG" -F qcow2 "$IMG" >/dev/null

echo "launching ($SMP vCPU, ${MEM} guest RAM on node$GUEST_NODE, mbe -> node1) ..."
sudo FEMU_MBE_INTERLEAVE=1 setsid nohup "$QEMU" \
  -name "$VM_NAME",debug-threads=on -enable-kvm -cpu host -smp "$SMP" -m "$MEM" \
  -object memory-backend-file,id=g0,size="$MEM",mem-path=/dev/hugepages,share=on,prealloc=on,host-nodes="$GUEST_NODE",policy=bind \
  -numa node,nodeid=0,cpus=0-$((SMP-1)),memdev=g0 -overcommit cpu-pm=on \
  -drive file="$IMG",if=virtio,format=qcow2,cache=none,aio=native \
  -drive file="$SEED",if=virtio,format=raw,readonly=on \
  -device femu,devsz_mb="$DEVSZ_MB",id=nvme0,queues="$SMP",multipoller_enabled=1,poller_ratio=1 \
  -netdev user,id=un0,hostfwd=tcp::"$SSH_PORT"-:22 -device virtio-net-pci,netdev=un0 -nographic \
  > "$LOG" 2>&1 < /dev/null &

echo "waiting ~55s for boot ..."; sleep 55
echo "=== boot check ==="
echo "  qemu live: $(pgrep -fc "qemu-system-x86_64 -name $VM_NAME")"
grep -a 'backend:' "$LOG" | tail -1
for n in 0 1; do echo "  node$n 1G free: $(hp1g_free $n)"; done
echo "  guest nproc: $($GSSH nproc 2>/dev/null) (expect $SMP)"
