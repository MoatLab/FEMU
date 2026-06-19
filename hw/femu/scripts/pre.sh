#!/bin/bash

tgt=nvme0n1
blun=0
elun=15


echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

#sudo nvme lnvm create -t pblk -d nvme0n1 -b $blun -e $elun -n $tgt
sleep 2
sudo mkfs.ext4 -E lazy_itable_init=0,lazy_journal_init=0 -m 0  /dev/$tgt
sleep 3
if [[ ! -d /mnt/$tgt ]]; then
    mkdir -p /mnt/$tgt
fi
sudo mount /dev/$tgt /mnt/$tgt
sleep 3

sudo chown huaicheng:huaicheng /mnt/$tgt

mkdir -p /mnt/$tgt/{tmpdir,datadir,namedir}


