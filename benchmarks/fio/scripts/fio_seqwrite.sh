#!/bin/bash

if [[ "$#" -ne 1 ]]; then
	echo "Usage ./fio_seqwrite.sh <blocksize in KB>"
	exit
fi

bs=$1k

echo "Running FIO with block size $bs"

fio --name=seqwrite --rw=write --direct=1 --ioengine=libaio --bs=$bsk --numjobs=4 --size=2G --runtime=600  --group_reporting
