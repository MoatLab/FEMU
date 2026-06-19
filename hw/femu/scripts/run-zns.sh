#!/bin/bash
#
# Huaicheng Li <huaicheng@vt.edu>
# Run FEMU as Zoned-Namespace (ZNS) SSDs
#

# Image directory
IMGDIR=$HOME/images
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

SSD_SIZE_MB=4096
NUM_CHANNELS=8
NUM_CHIPS_PER_CHANNEL=4
NUM_PLANES_PER_CHIP=2
NUM_BLOCKS_PER_CHIP=32
# SLC:1 MLC:2 TLC:3 QLC:4
# MLC is not allowed
FLASH_TYPE=4

FEMU_OPTIONS="-device femu"
FEMU_OPTIONS=${FEMU_OPTIONS}",devsz_mb=${SSD_SIZE_MB}"
FEMU_OPTIONS=${FEMU_OPTIONS}",namespaces=1"
FEMU_OPTIONS=${FEMU_OPTIONS}",zns_num_ch=${NUM_CHANNELS}"
FEMU_OPTIONS=${FEMU_OPTIONS}",zns_num_lun=${NUM_CHIPS_PER_CHANNEL}"
FEMU_OPTIONS=${FEMU_OPTIONS}",zns_num_plane=${NUM_PLANES_PER_CHIP}"
FEMU_OPTIONS=${FEMU_OPTIONS}",zns_num_blk=${NUM_BLOCKS_PER_CHIP}"
FEMU_OPTIONS=${FEMU_OPTIONS}",zns_flash_type=${FLASH_TYPE}"
FEMU_OPTIONS=${FEMU_OPTIONS}",femu_mode=3"

sudo ./qemu-system-x86_64 \
    -name "FEMU-ZNSSD-VM" \
    -enable-kvm \
    -cpu host \
    -smp 4 \
    -m 4G \
    -device virtio-scsi-pci,id=scsi0 \
    -device scsi-hd,drive=hd0 \
    -drive file=$OSIMGF,if=none,aio=native,cache=none,format=qcow2,id=hd0 \
    ${FEMU_OPTIONS} \
    -net user,hostfwd=tcp::8080-:22 \
    -net nic,model=virtio \
    -nographic \
    -qmp unix:./qmp-sock,server,nowait 2>&1 | tee log
