# This delay is used while queueng the operations in the return path or NVMe completion path.

# Alternatively, We introduce artifical delays also in hw/block/femu/mem-backend.c while doing DMA accesses and disable delays
# induced in the NVMe request return path.
# run on /dev/nvme0n1 by default

if [[ "$#" -eq 0 ]]; then
	DISK=/dev/nvme0n1
	OUTDIR=--filename=$DISK
fi

#otherwise run on current directory

echo $OUTDIR

sudo fio --name=randwrite --rw=randwrite --direct=1 --ioengine=libaio --bs=32k --numjobs=4 --size=2G --runtime=600  --group_reporting --filename=/dev/nvme0n1

