#!/bin/bash


# AAAAAAAAAAAAAAAAAAAAAAAAA

if [[ "$EUID" -ne 0 ]]; then
   echo "Please run as root";
   exit 1
fi

IMGDIR=$HOME/lighthost/iskos_images
# virtual machine disk image
OSIMGF=$IMGDIR/60G

FEMU_BUILDDIR=$HOME/femu/build_femu

IMAGE_DIR=/home/shehbaz/lighthost/iskos_images

NUM_LUN=4

echo "Launching Host"
sudo $FEMU_BUILDDIR/x86_64-softmmu/qemu-system-x86_64 \
	-smp 4
	-drive file=$IMAGE_DIR/40G \
	-m 8192 -enable-kvm \
	-vnc 127.0.0.1:3
	
#	-net user,hostfwd=tcp::10020-:22 -net nic \
# CPU - Create two NUMA Nodes:

#	-smp cpus=8 -numa node,cpus=0-3,nodeid=0 \
#	-numa node,cpus=4-7,nodeid=1 \



#echo "Waiting for Host To Boot"
#sleep 4
#ssh -X shehbaz@localhost -p 10020


#-boot d -cdrom ubuntu-16.04.4-desktop-amd64.iso \
# -nographic \
#-drive file=mynvme,if=none,id=mynvme \
#-device nvme,drive=mynvme,serial=deadbeef,namespaces=1,lver=1,nlbaf=5,lba_index=3,mdts=10,lnum_lun=4,lnum_pln=1,lsecs_per_pg=2 \
