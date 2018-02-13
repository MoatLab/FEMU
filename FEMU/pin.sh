#!/bin/bash

# pin vcpus (use at most 36 pCPUs)
sudo ./ftk/qmp-vcpu-pin -s ./qmp-sock $(seq 2 3) #$(seq 30 47) $(seq 24 29)

# pin main thread to the rest of pCPUs
qemu_pid=$(ps -ef | grep qemu | grep -v grep | tail -n 1 | awk '{print $2}')
sudo taskset -cp 0-1 ${qemu_pid}
