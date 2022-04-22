#!/bin/bash

IMGDIR=$HOME/images

is_mounted=$(mount | grep "/mnt/tmpfs")

if [[ $is_mounted == "" ]]; then
    sudo mkdir -p /mnt/tmpfs
    sudo mount -t tmpfs -o size=4G tmpfs /mnt/tmpfs
fi

# every time we run a new SSD
sudo rm -rf /mnt/tmpfs/test1.raw

[[ ! -e /mnt/tmpfs/test1.raw ]] && ./qemu-img create -f raw /mnt/tmpfs/test1.raw 4G

#-object iothread,id=iothread0 \
#-device virtio-blk-pci,iothread=iothread0,drive=id0 \
    #-nographic \
    #-device nvme,drive=id0,serial=serial0,id=nvme0 \
    #-kernel /home/huaicheng/git/linux/arch/x86_64/boot/bzImage \
    #-append "root=/dev/vda1 console=ttyS0,115200n8 console=tty0" \
    #-virtfs local,path=/home/huaicheng/share/,security_model=passthrough,mount_tag=host_share \

    #-trace events=/tmp/events \

sudo x86_64-softmmu/qemu-system-x86_64 \
    -name "nvme-FEMU-test" \
    -smp 4 \
    -m 8192 \
    -cpu host \
    -enable-kvm \
    -device virtio-scsi-pci,id=scsi0 \
    -device scsi-hd,drive=hd0 \
    -drive file=$IMGDIR/u14s.qcow2,if=none,aio=native,cache=none,format=qcow2,id=hd0 \
    -device virtio-scsi-pci,id=scsi1 \
    -device scsi-hd,drive=hd1 \
    -drive file=$IMGDIR/vmdata.raw,if=none,aio=native,cache=none,format=raw,id=hd1 \
    -drive file=/mnt/tmpfs/test1.raw,if=none,aio=threads,format=raw,id=id0 \
    -object iothread,id=iothread0,poll-max-ns=32768 \
    -device virtio-blk-pci,iothread=iothread0,drive=id0,serial=serial0,id=nvme0 \
    -net user,hostfwd=tcp::8080-:22 \
    -net nic,model=virtio \
    -nographic \
    -qmp unix:./qmp-sock,server,nowait | tee /media/log
    #-display none \
    #-nographic \
    #-monitor stdio \
    #-s -S \
    #

#sleep 10

#./pin.sh
#sshsim "~/tsc.sh"
#sshsim "echo 0 | sudo tee /proc/sys/kernel/timer_migration"
#sshsim "echo 0 | sudo tee /sys/kernel/debug/tracing/tracing_on"

echo "VM is up, enjoy it :)"

wait
