#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Run FEMU as a key-value SSD (KV): Store, Retrieve, Delete, Exist and List
# commands on keys of up to 16 bytes. The guest needs Linux 6.0 or newer and
# reaches the namespace through NVMe passthrough; there is no block device.

# Image directory
IMGDIR=${IMGDIR:-$HOME/images}
# Virtual machine disk image
OSIMGF=${OSIMGF:-$IMGDIR/u20s.qcow2}
# Host port forwarded to the guest's SSH port; run-guest-ssh.sh reads it too
SSH_PORT=${SSH_PORT:-8080}

# NAND layout that holds the values (must be power of 2)
secsz=512 # sector size in bytes
secs_per_pg=8 # number of sectors in a flash page
pgs_per_blk=256 # number of pages per flash block
blks_per_pl=256 # number of blocks per plane
pls_per_lun=1 # planes per LUN
luns_per_ch=8 # number of chips per channel
nchs=8 # number of channels
# in megabytes; values get this or the usable NAND, whichever is smaller
ssd_size=4096

# Latency in nanoseconds
pg_rd_lat=40000 # page read latency
pg_wr_lat=200000 # page write latency
blk_er_lat=2000000 # block erase latency

# Share of the NAND usable for values (1-100)
gc_thres_pcent=75

#-----------------------------------------------------------------------

# Compose the entire FEMU KV command line options
FEMU_OPTIONS="-device femu"
FEMU_OPTIONS=${FEMU_OPTIONS}",devsz_mb=${ssd_size}"
FEMU_OPTIONS=${FEMU_OPTIONS}",namespaces=1"
FEMU_OPTIONS=${FEMU_OPTIONS}",femu_mode=5"
FEMU_OPTIONS=${FEMU_OPTIONS}",secsz=${secsz}"
FEMU_OPTIONS=${FEMU_OPTIONS}",secs_per_pg=${secs_per_pg}"
FEMU_OPTIONS=${FEMU_OPTIONS}",pgs_per_blk=${pgs_per_blk}"
FEMU_OPTIONS=${FEMU_OPTIONS}",blks_per_pl=${blks_per_pl}"
FEMU_OPTIONS=${FEMU_OPTIONS}",pls_per_lun=${pls_per_lun}"
FEMU_OPTIONS=${FEMU_OPTIONS}",luns_per_ch=${luns_per_ch}"
FEMU_OPTIONS=${FEMU_OPTIONS}",nchs=${nchs}"
FEMU_OPTIONS=${FEMU_OPTIONS}",pg_rd_lat=${pg_rd_lat}"
FEMU_OPTIONS=${FEMU_OPTIONS}",pg_wr_lat=${pg_wr_lat}"
FEMU_OPTIONS=${FEMU_OPTIONS}",blk_er_lat=${blk_er_lat}"
FEMU_OPTIONS=${FEMU_OPTIONS}",gc_thres_pcent=${gc_thres_pcent}"

echo ${FEMU_OPTIONS}

if [[ ! -e "$OSIMGF" ]]; then
    echo ""
    echo "VM disk image couldn't be found ..."
    echo "Build one with ./make-guest-image.sh, or place an image at $OSIMGF"
    echo "(set OSIMGF or IMGDIR to use another path), then rerun this script"
    echo ""
    exit 1
fi

sudo ./qemu-system-x86_64 \
    -name "FEMU-KVSSD-VM",debug-threads=on \
    -enable-kvm \
    -cpu host \
    -smp 4 \
    -m 4G \
    -device virtio-scsi-pci,id=scsi0 \
    -device scsi-hd,drive=hd0 \
    -drive file=$OSIMGF,if=none,aio=native,cache=none,format=qcow2,id=hd0 \
    ${FEMU_OPTIONS} \
    -net user,hostfwd=tcp::${SSH_PORT}-:22 \
    -net nic,model=virtio \
    -nographic \
    -qmp unix:./qmp-sock,server,nowait 2>&1 | tee log
