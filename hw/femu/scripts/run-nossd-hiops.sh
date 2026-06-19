#!/bin/bash
# Huaicheng Li <huaicheng@cs.uchicago.edu>
# Run FEMU in NoSSD mode tuned for high IOPS.
#
# This is a thin variant of run-nossd.sh that enables the per-queue multipoller
# and a configurable IO-queue count. All knobs are environment-overridable, e.g.:
#   VM_SMP=16 FEMU_QUEUES=16 ./run-nossd-hiops.sh
#
# Drive the device from inside the guest with a polled, high-queue-depth engine
# (e.g. fio with io_uring/io_uring_cmd, multiple per-core jobs, large iodepth).

# Image directory
IMGDIR=$HOME/images
# Virtual machine disk image
OSIMGF=$IMGDIR/u20s.qcow2

# --- tunables (env-overridable) ---
VM_SMP=${VM_SMP:-8}                       # guest vCPUs
VM_MEM=${VM_MEM:-8G}                      # guest RAM
FEMU_DEVSZ_MB=${FEMU_DEVSZ_MB:-4096}      # emulated NVMe size (MB)
FEMU_QUEUES=${FEMU_QUEUES:-8}             # IO queues (scale with VM_SMP)
FEMU_MULTIPOLLER=${FEMU_MULTIPOLLER:-1}   # 1 = one poller thread per IO queue
SSH_PORT=${SSH_PORT:-8080}

if [[ ! -e "$OSIMGF" ]]; then
	echo ""
	echo "VM disk image couldn't be found ..."
	echo "Please prepare a usable VM image and place it as $OSIMGF"
	echo "Once VM disk image is ready, please rerun this script again"
	echo ""
	exit
fi

echo "=== FEMU NoSSD high-IOPS run ==="
echo "  vm smp/mem : $VM_SMP / $VM_MEM"
echo "  femu devsz : ${FEMU_DEVSZ_MB} MB"
echo "  femu queues: $FEMU_QUEUES (multipoller=$FEMU_MULTIPOLLER)"
echo "  ssh fwd    : tcp::${SSH_PORT}-:22"

sudo ./qemu-system-x86_64 \
    -name "FEMU-NoSSD-hiops" \
    -enable-kvm \
    -cpu host \
    -smp $VM_SMP \
    -m $VM_MEM \
    -device virtio-scsi-pci,id=scsi0 \
    -device scsi-hd,drive=hd0 \
    -drive file=$OSIMGF,if=none,aio=native,cache=none,format=qcow2,id=hd0 \
    -device femu,devsz_mb=${FEMU_DEVSZ_MB},id=nvme0,queues=${FEMU_QUEUES},multipoller_enabled=${FEMU_MULTIPOLLER} \
    -net user,hostfwd=tcp::${SSH_PORT}-:22 \
    -net nic,model=virtio \
    -nographic \
    -qmp unix:./qmp-sock,server,nowait
