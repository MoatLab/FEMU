#!/bin/bash
# Huaicheng Li <huaicheng@cs.uchicago.edu>
# Run VM with FEMU support: FEMU as a black-box SSD (FTL managed by the device)

# image directory
IMGDIR=$HOME/images
# virtual machine disk image
OSIMGF=$IMGDIR/u14s.qcow2
# virtual NVMe disk image
NVMEIMGF=$IMGDIR/vssd1.raw
# virtual NVMe disk size: 1GB
NVMEIMGSZ=1G

# every time we create a new SSD image file
#sudo rm -rf $IMGDIR/vssd1.raw

if [[ ! -e "$OSIMGF" ]]; then
	echo ""
	echo "VM disk image couldn't be found ..."
	echo "Please prepare a usable VM image and place it as $OSIMGF"
	echo "Once VM disk image is ready, please rerun this script again"
	echo ""
	exit
fi

# Please match the image file size with the emulated SSD size in vssd1.conf file
[[ ! -e $NVMEIMGF ]] && ./qemu-img create -f raw $NVMEIMGF $NVMEIMGSZ

# huge page related settings
#echo 25000 | sudo tee /proc/sys/vm/nr_hugepages

#[[ ! -d /dev/hugepages2M ]] && sudo mkdir /dev/hugepages2M && sudo mount -t hugetlbfs none /dev/hugepages2M -o pagesize=2M


# Useful options you may want to further try:
#-object iothread,id=iothread0 \
#-device virtio-blk-pci,iothread=iothread0,drive=id0 \
    #-nographic \
    #-device nvme,drive=id0,serial=serial0,id=nvme0 \
    #-kernel /home/huaicheng/git/linux/arch/x86_64/boot/bzImage \
    #-append "root=/dev/vda1 console=ttyS0,115200n8 console=tty0" \
    #-virtfs local,path=/home/huaicheng/share/,security_model=passthrough,mount_tag=host_share \

    #must come before all other qemu options!!!!!!
    #-trace events=/tmp/events \
    #-object memory-backend-file,id=mem1,size=8G,mem-path=/dev/hugepages2M \
    #-device pc-dimm,id=dimm1,memdev=mem1 \
    #-device virtio-scsi-pci,id=scsi1 \
    #-device scsi-hd,drive=hd1 \
    #-drive file=$IMGDIR/vmdata.qcow2,if=none,aio=native,cache=none,format=qcow2,id=hd1 \


sudo x86_64-softmmu/qemu-system-x86_64 \
    -name "FEMU-blackbox-SSD" \
    -enable-kvm \
    -cpu host \
    -smp 4 \
    -m 4G \
    -device virtio-scsi-pci,id=scsi0 \
    -device scsi-hd,drive=hd0 \
    -drive file=$OSIMGF,if=none,aio=native,cache=none,format=qcow2,id=hd0 \
    -drive file=$NVMEIMGF,if=none,aio=threads,format=raw,id=id0 \
    -device nvme,drive=id0,serial=serial0,id=nvme0 \
    -net user,hostfwd=tcp::8080-:22 \
    -net nic,model=virtio \
    -nographic \
    -qmp unix:./qmp-sock,server,nowait 
    #-object iothread,id=iothread0 \
    #-display none \
    #-nographic \
    #-monitor stdio \
    #-s -S \
    #

#sleep 10

#
# Please manually run the following commands for better FEMU performance/accuracy
#

#./pin.sh
#sshsim "~/tsc.sh"
#sshsim "echo 0 | sudo tee /proc/sys/kernel/timer_migration"
#sshsim "echo 0 | sudo tee /sys/kernel/debug/tracing/tracing_on"

echo "VM is up, enjoy it :)"

wait
