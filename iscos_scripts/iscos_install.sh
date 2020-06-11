#!/bin/bash


IMAGE_DIR=/home/shehbaz/lighthost/iskos_images

# AAAAAAAAAAAAAAAAAAAAAAAAA

if [[ "$EUID" -ne 0 ]]; then
   echo "Please run as root";
   exit 1
fi


#echo "Creating Auxillary Disk"
#qemu-img create PRI 2G
#qemu-img create SEC 2G
#qemu-img create RESTORE 3G
#dd if=/dev/zero of=mynvme bs=1M count=8196
#qemu-img create mynvme 1G
echo "Make sure X forwarding is enabled during ssh"

echo "Launching Host"
sudo qemu-system-x86_64 \
	-smp 12 \
	-drive format=raw,file=$IMAGE_DIR/40G \
	-m 8192 -enable-kvm \
	-boot d -cdrom $IMAGE_DIR/ubuntu-16.04.6-desktop-amd64.iso \
	-vnc 127.0.0.1:2
#	-net user,hostfwd=tcp::10020-:22 -net nic \


	#-boot d -cdrom $IMAGE_DIR/ubuntu-16.04.6-server-amd64.iso \

#echo "Waiting for Host To Boot"
#sleep 4
#ssh -X shehbaz@localhost -p 10020


# -nographic \
#-drive file=mynvme,if=none,id=mynvme \
#-device nvme,drive=mynvme,serial=deadbeef,namespaces=1,lver=1,nlbaf=5,lba_index=3,mdts=10,lnum_lun=4,lnum_pln=1,lsecs_per_pg=2 \
