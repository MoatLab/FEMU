#!/bin/bash
# Run FEMU as a Computational Storage Drive (CSD)

# Image directory
IMGDIR=$HOME/images
# Virtual machine disk image
OSIMGF=$IMGDIR/u20s.qcow2

# FEMU CSD parameters
SSD_SIZE_MB=4096
FDM_SIZE_MB=64
NR_CU=4
NR_THREAD=4
TIME_SLICE=200000
CONTEXT_SWITCH_TIME=200
CSF_RUNTIME_SCALE=3
PG_RD_LAT=40000
PG_WR_LAT=200000
BLK_ER_LAT=2000000
CH_XFER_LAT=0

#-----------------------------------------------------------------------

# Compose the entire FEMU CSD command line options
FEMU_OPTIONS="-device femu"
FEMU_OPTIONS=${FEMU_OPTIONS}",devsz_mb=${SSD_SIZE_MB}"
FEMU_OPTIONS=${FEMU_OPTIONS}",namespaces=1"
FEMU_OPTIONS=${FEMU_OPTIONS}",femu_mode=4"
FEMU_OPTIONS=${FEMU_OPTIONS}",fdm_size=${FDM_SIZE_MB}"
FEMU_OPTIONS=${FEMU_OPTIONS}",nr_cu=${NR_CU}"
FEMU_OPTIONS=${FEMU_OPTIONS}",nr_thread=${NR_THREAD}"
FEMU_OPTIONS=${FEMU_OPTIONS}",time_slice=${TIME_SLICE}"
FEMU_OPTIONS=${FEMU_OPTIONS}",context_switch_time=${CONTEXT_SWITCH_TIME}"
FEMU_OPTIONS=${FEMU_OPTIONS}",csf_runtime_scale=${CSF_RUNTIME_SCALE}"
FEMU_OPTIONS=${FEMU_OPTIONS}",pg_rd_lat=${PG_RD_LAT}"
FEMU_OPTIONS=${FEMU_OPTIONS}",pg_wr_lat=${PG_WR_LAT}"
FEMU_OPTIONS=${FEMU_OPTIONS}",blk_er_lat=${BLK_ER_LAT}"
FEMU_OPTIONS=${FEMU_OPTIONS}",ch_xfer_lat=${CH_XFER_LAT}"

echo ${FEMU_OPTIONS}

if [[ ! -e "$OSIMGF" ]]; then
	echo ""
	echo "VM disk image couldn't be found ..."
	echo "Please prepare a usable VM image and place it as $OSIMGF"
	echo "Once VM disk image is ready, please rerun this script again"
	echo ""
	exit
fi

sudo ./qemu-system-x86_64 \
    -name "FEMU-CSD-VM" \
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
