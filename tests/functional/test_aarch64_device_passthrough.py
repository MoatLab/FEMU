#!/usr/bin/env python3
#
# Boots a nested guest and compare content of a device (passthrough) to a
# reference image. Both vfio group and iommufd passthrough methods are tested.
#
# Copyright (c) 2025 Linaro Ltd.
#
# Author: Pierrick Bouvier <pierrick.bouvier@linaro.org>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import os

from qemu_test import QemuSystemTest, Asset
from qemu_test import exec_command, wait_for_console_pattern
from qemu_test import exec_command_and_wait_for_pattern
from random import randbytes

guest_script = '''
#!/usr/bin/env bash

set -euo pipefail
set -x

# find disks from nvme serial
dev_vfio=$(lsblk --nvme | grep vfio | cut -f 1 -d ' ')
dev_iommufd=$(lsblk --nvme | grep iommufd | cut -f 1 -d ' ')
pci_vfio=$(basename $(readlink -f /sys/block/$dev_vfio/../../../))
pci_iommufd=$(basename $(readlink -f /sys/block/$dev_iommufd/../../../))

# bind disks to vfio
for p in "$pci_vfio" "$pci_iommufd"; do
    if [ "$(cat /sys/bus/pci/devices/$p/driver_override)" == vfio-pci ]; then
        continue
    fi
    echo $p > /sys/bus/pci/drivers/nvme/unbind
    echo vfio-pci > /sys/bus/pci/devices/$p/driver_override
    echo $p > /sys/bus/pci/drivers/vfio-pci/bind
done

# boot nested guest and execute /host/nested_guest.sh
# one disk is passed through vfio group, the other, through iommufd
qemu-system-aarch64 \
-M virt \
-display none \
-serial stdio \
-cpu host \
-enable-kvm \
-m 1G \
-kernel /host/Image.gz \
-drive format=raw,file=/host/guest.ext4,if=virtio \
-append "root=/dev/vda init=/init -- bash /host/nested_guest.sh" \
-virtfs local,path=/host,mount_tag=host,security_model=mapped,readonly=off \
-device vfio-pci,host=$pci_vfio \
-object iommufd,id=iommufd0 \
-device vfio-pci,host=$pci_iommufd,iommufd=iommufd0
'''

nested_guest_script = '''
#!/usr/bin/env bash

set -euo pipefail
set -x

image_vfio=/host/disk_vfio
image_iommufd=/host/disk_iommufd

dev_vfio=$(lsblk --nvme | grep vfio | cut -f 1 -d ' ')
dev_iommufd=$(lsblk --nvme | grep iommufd | cut -f 1 -d ' ')

# compare if devices are identical to original images
diff $image_vfio /dev/$dev_vfio
diff $image_iommufd /dev/$dev_iommufd

echo device_passthrough_test_ok
'''

class Aarch64DevicePassthrough(QemuSystemTest):

    # https://github.com/pbo-linaro/qemu-linux-stack
    #
    # Linux kernel is compiled with defconfig +
    # IOMMUFD + VFIO_DEVICE_CDEV + ARM_SMMU_V3_IOMMUFD
    # https://docs.kernel.org/driver-api/vfio.html#vfio-device-cde
    ASSET_DEVICE_PASSTHROUGH_STACK = Asset(
        ('https://fileserver.linaro.org/s/fx5DXxBYme8dw2G/'
         'download/device_passthrough.tar.xz'),
         '812750b664d61c2986f2b149939ae28cafbd60d53e9c7e4b16e97143845e196d')

    # This tests the device passthrough implementation, by booting a VM
    # supporting it with two nvme disks attached, and launching a nested VM
    # reading their content.
    def test_aarch64_device_passthrough(self):
        self.set_machine('virt')
        self.require_accelerator('tcg')

        self.vm.set_console()

        stack_path_tar_gz = self.ASSET_DEVICE_PASSTHROUGH_STACK.fetch()
        self.archive_extract(stack_path_tar_gz, format="tar")

        stack = self.scratch_file('out')
        kernel = os.path.join(stack, 'Image.gz')
        rootfs_host = os.path.join(stack, 'host.ext4')
        disk_vfio = os.path.join(stack, 'disk_vfio')
        disk_iommufd = os.path.join(stack, 'disk_iommufd')
        guest_cmd = os.path.join(stack, 'guest.sh')
        nested_guest_cmd = os.path.join(stack, 'nested_guest.sh')
        # we generate two random disks
        with open(disk_vfio, "wb") as d: d.write(randbytes(512))
        with open(disk_iommufd, "wb") as d: d.write(randbytes(1024))
        with open(guest_cmd, 'w') as s: s.write(guest_script)
        with open(nested_guest_cmd, 'w') as s: s.write(nested_guest_script)

        self.vm.add_args('-cpu', 'max')
        self.vm.add_args('-m', '2G')
        self.vm.add_args('-M', 'virt,'
                         'virtualization=on,'
                         'gic-version=max,'
                         'iommu=smmuv3')
        self.vm.add_args('-kernel', kernel)
        self.vm.add_args('-drive', f'format=raw,file={rootfs_host}')
        self.vm.add_args('-drive',
                         f'file={disk_vfio},if=none,id=vfio,format=raw')
        self.vm.add_args('-device', 'nvme,serial=vfio,drive=vfio')
        self.vm.add_args('-drive',
                         f'file={disk_iommufd},if=none,id=iommufd,format=raw')
        self.vm.add_args('-device', 'nvme,serial=iommufd,drive=iommufd')
        self.vm.add_args('-virtfs',
                         f'local,path={stack}/,mount_tag=host,'
                         'security_model=mapped,readonly=off')
        # boot and execute guest script
        # init will trigger a kernel panic if script fails
        self.vm.add_args('-append',
                         'root=/dev/vda init=/init -- bash /host/guest.sh')

        self.vm.launch()
        wait_for_console_pattern(self, 'device_passthrough_test_ok',
                                 failure_message='Kernel panic')

if __name__ == '__main__':
    QemuSystemTest.main()
