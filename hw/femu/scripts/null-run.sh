#!/bin/bash

is_mounted=$(mount | grep "/mnt/tmpfs")

if [[ $is_mounted == "" ]]; then
    sudo mkdir -p /mnt/tmpfs
    sudo mount -t tmpfs -o size=4G tmpfs /mnt/tmpfs
fi

# every time we run a new SSD
sudo rm -rf /mnt/tmpfs/test1.raw

[[ ! -e /mnt/tmpfs/test1.raw ]] && ./qemu-img create -f raw /mnt/tmpfs/test1.raw 4G

#-virtfs local,path=/home/huaicheng/share/,security_model=passthrough,mount_tag=host_share \

#-object iothread,id=iothread0 \
#-device virtio-blk-pci,iothread=iothread0,drive=id0 \
    #-nographic \
    #-device nvme,drive=id0,serial=serial0,id=nvme0 \
    #-kernel /home/huaicheng/git/linux/arch/x86_64/boot/bzImage \
    #-append "root=/dev/vda1 console=ttyS0,115200n8 console=tty0 net.ifnames=0 biosdevname=0 rootdelay=10 nomodeset mce=ignore_ce nosoftlockup audit=0 processor.max_cstate=1 idle=poll nodelayacct" \
    #-drive file=/mnt/tmpfs/test1.raw,if=none,aio=threads,format=raw,id=id0 \
    #-device nvme,drive=id0,serial=serial0,id=nvme0 \

    #-drive file=xxx.img,if=none,cache=none,format=qcow2,id=boot0
    #-device virtio-blk-pci,drive=boot0 \
    #-drive file=null-co:,format=raw \
    #-drive driver=null-aio,latency-ns=100000,if=none,cache=none,id=null0 \
    #-device nvme,drive=null0,serial=serial0,id=nvme0 \
#net.ifnames=0 biosdevname=0 rootdelay=90 nomodeset mce=ignore_ce nosoftlockup audit=0 processor.max_cstate=1 idle=poll nodelayacct" \

    #-device nvme,drive=null0,serial=serial0,id=nvme0 \
sudo x86_64-softmmu/qemu-system-x86_64 \
    -name "nvme-FEMU-test" \
    -smp 4 \
    -m 8192 \
    -cpu host \
    -enable-kvm \
    -drive file=/home/huaicheng/images/u14s.qcow2,if=virtio,aio=threads,cache=none,format=qcow2,id=boot0 \
    -drive driver=null-aio,if=virtio,cache=none,aio=native,id=null0 \
    -net user,hostfwd=tcp::8080-:22 \
    -net nic,model=virtio \
    -nographic
    #-display none \
    #-monitor stdio
    #-s -S \
    #-nographic
    #
