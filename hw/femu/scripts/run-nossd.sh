#!/bin/bash
# Huaicheng Li <huaicheng@cs.uchicago.edu>
# Run FEMU with no SSD emulation logic, (e.g., for SCM/Optane emulation)

# Image directory
IMGDIR=${IMGDIR:-$HOME/images}
# Virtual machine disk image
OSIMGF=${OSIMGF:-$IMGDIR/u20s.qcow2}


if [[ ! -e "$OSIMGF" ]]; then
	echo ""
	echo "VM disk image couldn't be found ..."
	echo "Build one with ./make-guest-image.sh, or place an image at $OSIMGF"
	echo "(set OSIMGF or IMGDIR to use another path), then rerun this script"
	echo ""
	exit 1
fi

sudo ./qemu-system-x86_64 \
    -name "FEMU-NoSSD-VM" \
    -enable-kvm \
    -cpu host \
    -smp 4 \
    -m 4G \
    -device virtio-scsi-pci,id=scsi0 \
    -device scsi-hd,drive=hd0 \
    -drive file=$OSIMGF,if=none,aio=native,cache=none,format=qcow2,id=hd0 \
    -device femu,devsz_mb=4096,id=nvme0 \
    -net user,hostfwd=tcp::8080-:22 \
    -net nic,model=virtio \
    -nographic \
    -qmp unix:./qmp-sock,server,nowait
