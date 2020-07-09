# This script is used to check the latency of the underlying device after making any changes to the latency parameters.
# the NAND Flash latency parameters are defined in ftl/ftl.h 

# This delay is used while queueng the operations in the return path or NVMe completion path.

# Alternatively, We introduce artifical delays also in hw/block/femu/mem-backend.c while doing DMA accesses and disable delays
# induced in the NVMe request return path.


# run on /dev/nvme0n1 by default

if [[ "$#" -eq 0 ]]; then
	DISK=/dev/nvme0n1
	OUTDIR=--filename=$DISK
fi

#otherwise run on current directory

echo "output directory parameter $OUTDIR"

sudo fio --name=seqwrite --rw=write --direct=1 --ioengine=libaio --bs=32k --numjobs=4 --size=2G --runtime=600  --group_reporting $OUTDIR
