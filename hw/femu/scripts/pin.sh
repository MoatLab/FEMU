#!/bin/bash
# Huaicheng Li <huaicheng@cs.uchicago.edu>
# pin vcpu and qemu main thread to certain set of physical CPUs
#

NRCPUS="$(cat /proc/cpuinfo | grep "vendor_id" | wc -l)"

# pin vcpus (use at most 36 pCPUs)
sudo ./ftk/qmp-vcpu-pin -s ./qmp-sock $(seq 0 $NRCPUS) #$(seq 30 47) $(seq 24 29)

# pin main thread to the rest of pCPUs
qemu_pid=$(ps -ef | grep qemu | grep -v grep | tail -n 1 | awk '{print $2}')
sudo taskset -cp 1-$NRCPUS ${qemu_pid}
