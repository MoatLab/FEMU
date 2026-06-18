#!/bin/bash
# Step 2: inside the guest, bind FEMU's NVMe device to SPDK (vfio-pci no-IOMMU)
# and do a short warm run so FEMU enables the dataplane and spawns its
# femu-poller threads (they do not exist until the controller is enabled).
cd "$(dirname "$0")" && . ./env.sh

$GSSH "sudo pkill -9 bdevperf 2>/dev/null; sleep 1
DEV=\$(lspci -d 1d1d: | awk '{print \$1}')
echo guest-FEMU-BDF=\$DEV
cat > /tmp/bj <<EOF
{\"subsystems\":[
 {\"subsystem\":\"iobuf\",\"config\":[{\"method\":\"iobuf_set_options\",\"params\":{\"small_pool_count\":32768,\"large_pool_count\":8192}}]},
 {\"subsystem\":\"bdev\",\"config\":[{\"method\":\"bdev_nvme_attach_controller\",\"params\":{\"name\":\"n1\",\"trtype\":\"PCIe\",\"traddr\":\"0000:\$DEV\"}}]}
]}
EOF
echo 6144 | sudo tee /proc/sys/vm/nr_hugepages >/dev/null
sudo modprobe vfio enable_unsafe_noiommu_mode=1 2>/dev/null
sudo modprobe vfio-pci 2>/dev/null
echo Y | sudo tee /sys/module/vfio/parameters/enable_unsafe_noiommu_mode >/dev/null 2>&1
sudo HUGEMEM=4096 ~/spdk/scripts/setup.sh >/dev/null 2>&1
nohup sudo ~/spdk/build/examples/bdevperf -m $CPUMASK -q 64 -o $IOSIZE -w $RW -t 3 --json /tmp/bj >/dev/null 2>&1 </dev/null &
echo warm-run-launched"

echo "warm run in flight; sleeping 8s so the FEMU pollers spawn ..."; sleep 8
