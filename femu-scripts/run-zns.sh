#!/bin/bash
#
# Huaicheng Li <hcli@cmu.edu>
# Run FEMU as Zoned-Namespace (ZNS) SSDs
#

# Image directory
IMGDIR=/home/inspurssd/hd/images
# Virtual machine disk image
OSIMGF=$IMGDIR/u20s.qcow2

if [[ ! -e "$OSIMGF" ]]; then
	echo ""
	echo "VM disk image couldn't be found ..."
	echo "Please prepare a usable VM image and place it as $OSIMGF"
	echo "Once VM disk image is ready, please rerun this script again"
	echo ""
	exit
fi

num_channels=8            # Number of channels
num_chips_per_channel=1   # Number of NAND flash chips/dies per channel

# Better not change.
num_planes_per_chip=1
num_pages_per_block=512
num_sectors_per_page=8
hw_sector_size=512 # bytes
oob_size=16 # bytes

SSD_SIZE="`expr 1024 \* 16`"
latency_emulation="true"

FEMU_OPTIONS="-device femu"
FEMU_OPTIONS=${FEMU_OPTIONS}",devsz_mb=${SSD_SIZE}"
FEMU_OPTIONS=${FEMU_OPTIONS}",femu_mode=3"
FEMU_OPTIONS=${FEMU_OPTIONS}",znum_ch=${num_channels}"
FEMU_OPTIONS=${FEMU_OPTIONS}",znum_lun=${num_chips_per_channel}"
FEMU_OPTIONS=${FEMU_OPTIONS}",znum_pln=${num_planes_per_chip}"
FEMU_OPTIONS=${FEMU_OPTIONS}",zsec_size=${hw_sector_size}"
FEMU_OPTIONS=${FEMU_OPTIONS}",zsecs_per_pg=${num_sectors_per_page}"
FEMU_OPTIONS=${FEMU_OPTIONS}",zpgs_per_blk=${num_pages_per_block}"
FEMU_OPTIONS=${FEMU_OPTIONS}",zmetasize=${oob_size}"
FEMU_OPTIONS=${FEMU_OPTIONS}",latency_emulation=${latency_emulation}"

sudo x86_64-softmmu/qemu-system-x86_64 \
    -name "FEMU-ZNSSD-VM" \
    -enable-kvm \
    -cpu host \
    -smp 16 \
    -m 16G \
    -device virtio-scsi-pci,id=scsi0 \
    -device scsi-hd,drive=hd0 \
    -drive file=$OSIMGF,if=none,aio=native,cache=none,format=qcow2,id=hd0 \
    ${FEMU_OPTIONS} \
    -net user,hostfwd=tcp::8080-:22 \
    -net nic,model=virtio \
    -nographic \
    -qmp unix:./qmp-sock,server,nowait 2>&1 | tee log
