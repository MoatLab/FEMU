#!/bin/bash
# Run FEMU as a black-box SSD with FDP (Flexible Data Placement) support

# image directory
IMGDIR=$HOME/images
# Virtual machine disk image
OSIMGF=$IMGDIR/u20s.qcow2

# Configurable SSD Controller layout parameters (must be power of 2)
secsz=512         # sector size in bytes
secs_per_pg=8     # number of sectors in a flash page
pgs_per_blk=256   # number of pages per flash block
blks_per_pl=256   # number of blocks per plane
pls_per_lun=1     # keep it at one, no multiplanes support
luns_per_ch=8     # number of chips per channel
nchs=8            # number of channels
ssd_size=12288    # in megabytes, consider 25% overprovisioning

# Latency in nanoseconds
pg_rd_lat=40000   # page read latency
pg_wr_lat=200000  # page write latency
blk_er_lat=2000000 # block erase latency
ch_xfer_lat=0     # channel transfer time

# GC Threshold (1-100)
gc_thres_pcent=75
gc_thres_pcent_high=95

# FDP Configuration
fdp_nruh=4        # number of reclaim unit handles
fdp_nrg=1         # number of reclaim groups
fdp_nru=$blks_per_pl  # total number of reclaim units (= blks_per_pl)

subsys_id="femu-subsys-0"

#-----------------------------------------------------------------------

# Compose femu-subsys device options
SUBSYS_OPTIONS="-device femu-subsys"
SUBSYS_OPTIONS=${SUBSYS_OPTIONS}",id=${subsys_id}"
SUBSYS_OPTIONS=${SUBSYS_OPTIONS}",nqn=subsys0"
SUBSYS_OPTIONS=${SUBSYS_OPTIONS}",fdp=on"
SUBSYS_OPTIONS=${SUBSYS_OPTIONS}",fdp.nruh=${fdp_nruh}"
SUBSYS_OPTIONS=${SUBSYS_OPTIONS}",fdp.nrg=${fdp_nrg}"
SUBSYS_OPTIONS=${SUBSYS_OPTIONS}",fdp.nru=${fdp_nru}"

# Compose femu (NVMe controller) device options
FEMU_OPTIONS="-device femu"
FEMU_OPTIONS=${FEMU_OPTIONS}",devsz_mb=${ssd_size}"
FEMU_OPTIONS=${FEMU_OPTIONS}",namespaces=1"
FEMU_OPTIONS=${FEMU_OPTIONS}",femu_mode=1"
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
FEMU_OPTIONS=${FEMU_OPTIONS}",ch_xfer_lat=${ch_xfer_lat}"
FEMU_OPTIONS=${FEMU_OPTIONS}",gc_thres_pcent=${gc_thres_pcent}"
FEMU_OPTIONS=${FEMU_OPTIONS}",gc_thres_pcent_high=${gc_thres_pcent_high}"
FEMU_OPTIONS=${FEMU_OPTIONS}",subsys=${subsys_id}"

echo "Subsys: ${SUBSYS_OPTIONS}"
echo "FEMU:   ${FEMU_OPTIONS}"

if [[ ! -e "$OSIMGF" ]]; then
    echo ""
    echo "VM disk image couldn't be found ..."
    echo "Please prepare a usable VM image and place it as $OSIMGF"
    echo "Once VM disk image is ready, please rerun this script again"
    echo ""
    exit
fi

sudo ./qemu-system-x86_64 \
    -name "FEMU-FDP-VM" \
    -enable-kvm \
    -cpu host \
    -smp 4 \
    -m 4G \
    ${SUBSYS_OPTIONS} \
    -device virtio-scsi-pci,id=scsi0 \
    -device scsi-hd,drive=hd0 \
    -drive file=$OSIMGF,if=none,aio=native,cache=none,format=qcow2,id=hd0 \
    ${FEMU_OPTIONS} \
    -net user,hostfwd=tcp::8080-:22 \
    -net nic,model=virtio \
    -nographic \
    -qmp unix:./qmp-sock,server,nowait 2>&1 | tee /tmp/femu-fdp.log
