#!/bin/bash
# Huaicheng Li <huaicheng@cs.uchicago.edu>
# Modified by Dongha Yoon <dongha@vt.edu>
# Run Cylon CXL-SSD
if [[ ! -e "$1" ]]; then
    echo "usage: $0 [ssd_size (MB)]"
fi

# IVSHMEM device for CCA (Cylon Caching API)
IVSHMEM_DEV=/dev/shm/ivshmem0
IVSHMEM_DEV_ID=ivshmem0
IVSHMEM_SIZE=1M
if [ ! -e "$IVSHMEM_DEV" ]; then
    sudo mkdir -p /dev/shm
    sudo chmod 777 /dev/shm
    dd if=/dev/zero of=$IVSHMEM_DEV bs=$IVSHMEM_SIZE count=1
    sudo chmod 666 $IVSHMEM_DEV
fi


# Image directory
# IMGDIR=$HOME/images
IMGDIR=~/images
# Virtual machine disk image
OSIMGF=$IMGDIR/ubuntu22.qcow2

if [[ ! -e "$OSIMGF" ]]; then
	echo ""
	echo "VM disk image couldn't be found ..."
	echo "Please prepare a usable VM image and place it as $OSIMGF"
	echo "Once VM disk image is ready, please rerun this script again"
	echo ""
	exit
fi

# CXL-SSD Cache backend memory parameters
cache_backend_dev="/dev/cmahog"
cache_bdev_offset=0
cache_hpa_base=0xae80000000

# CXL-SSD DRAM buffer parameters
policy=2 # Replacement policy [1:LIFO 2:FIFO 3:S3FIFO 4:CLOCK]
prf_dg=0 # Next-n Prefetch degree

# Configurable SSD Controller layout parameters (must be power of 2)
ssd_size=$1		# in MegaBytes
bufsz=512
# bufsz=$((ssd_size/20))
skip_ftl=0

# 96GB
if [ $ssd_size -eq 98304 ]
then
    secsz=512		
    secs_per_pg=8
    pgs_per_blk=256
    blks_per_pl=1536
    pls_per_lun=1       # still not support multiplanes		
    luns_per_ch=8		
    nchs=8  			
fi

# 48GB
if [ $ssd_size -eq 49152 ]
then
    secsz=512		
    secs_per_pg=8
    pgs_per_blk=256
    blks_per_pl=768
    pls_per_lun=1       # still not support multiplanes		
    luns_per_ch=8		
    nchs=8  			
fi


# Latency in nanoseconds
pg_rd_lat=40000
pg_wr_lat=200000
blk_er_lat=2000000
ch_xfer_lat=0

# GC Threshold (1-100)
gc_thres_pcent=75
gc_thres_pcent_high=95

#-----------------------------------------------------------------------

#Compose the entire FEMU BBSSD command line options
FEMU_OPTIONS="-device femu,id=femu-cxlssd"
FEMU_OPTIONS=${FEMU_OPTIONS}",cache_backend_dev=${cache_backend_dev}"
FEMU_OPTIONS=${FEMU_OPTIONS}",cache_bdev_offset=${cache_bdev_offset}"
FEMU_OPTIONS=${FEMU_OPTIONS}",cache_hpa_base=${cache_hpa_base}"
FEMU_OPTIONS=${FEMU_OPTIONS}",devsz_mb=${ssd_size}"
FEMU_OPTIONS=${FEMU_OPTIONS}",namespaces=1"
FEMU_OPTIONS=${FEMU_OPTIONS}",femu_mode=6"
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
FEMU_OPTIONS=${FEMU_OPTIONS}",bufsz_mb=${bufsz}"
FEMU_OPTIONS=${FEMU_OPTIONS}",replacement=${policy}"
FEMU_OPTIONS=${FEMU_OPTIONS}",prefetch_degree=${prf_dg}"
FEMU_OPTIONS=${FEMU_OPTIONS}",cxl_skip_ftl=${skip_ftl}"
FEMU_OPTIONS=${FEMU_OPTIONS}",multipoller_enabled=1"
FEMU_OPTIONS=${FEMU_OPTIONS}",cca_dev=${IVSHMEM_DEV_ID}"

echo ${FEMU_OPTIONS}

nr_hugepages=$((ssd_size/2))

echo 0 | sudo tee /proc/sys/kernel/numa_balancing
# echo $nr_hugepages | sudo tee /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages
echo never | sudo tee /sys/kernel/mm/transparent_hugepage/enabled

n_threads=8
dram_size=16G

sudo x86_64-softmmu/qemu-system-x86_64 \
    -name "FEMU-CXLSSD-VM" \
    -machine type=q35,accel=kvm,nvdimm=on,cxl=on -enable-kvm \
    -cpu host \
    -smp $n_threads \
    -m $dram_size,maxmem=128G,slots=8 \
    -object memory-backend-ram,size=$dram_size,policy=bind,host-nodes=0,id=ram-node0,prealloc=on,prealloc-threads=$n_threads \
    -numa node,nodeid=0,cpus=0-$((n_threads-1)),memdev=ram-node0 \
    --overcommit cpu-pm=on \
    -device virtio-scsi-pci,id=scsi0 \
    -device scsi-hd,drive=hd0 \
    -drive file=$OSIMGF,if=none,aio=native,cache=none,format=qcow2,id=hd0\
    -device ivshmem-plain,memdev=$IVSHMEM_DEV_ID,addr=0x4 \
    -object memory-backend-file,id=$IVSHMEM_DEV_ID,size=$IVSHMEM_SIZE,mem-path=$IVSHMEM_DEV,share=on \
    ${FEMU_OPTIONS} \
    -device pxb-cxl,bus_nr=12,bus=pcie.0,id=cxl.1 \
    -device cxl-rp,port=0,bus=cxl.1,id=root_port13,chassis=0,slot=2 \
    -device cxl-type3,bus=root_port13,femu=femu-cxlssd,id=cxl-ssd0 \
    -M cxl-fmw.0.targets.0=cxl.1,cxl-fmw.0.size=${ssd_size}M \
    -net user,hostfwd=tcp::8080-:22 \
    -net nic,model=e1000 \
    -nographic \
    -qmp unix:./qmp-sock,server,nowait 2>&1 | tee log