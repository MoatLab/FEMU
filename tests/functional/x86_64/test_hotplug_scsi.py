#!/usr/bin/env python3
#
# Functional test that hotplugs a virtio scsi disk and checks it on a Linux
# guest
#
# SPDX-License-Identifier: GPL-2.0-or-later

from qemu_test import LinuxKernelTest, Asset, exec_command_and_wait_for_pattern

class HotPlugScsi(LinuxKernelTest):
    ASSET_KERNEL = Asset(
        ('https://archives.fedoraproject.org/pub/archive/fedora/linux/releases'
         '/31/Server/x86_64/os/images/pxeboot/vmlinuz'),
        'd4738d03dbbe083ca610d0821d0a8f1488bebbdccef54ce33e3adb35fda00129')

    ASSET_INITRD = Asset(
        ('https://archives.fedoraproject.org/pub/archive/fedora/linux/releases'
         '/31/Server/x86_64/os/images/pxeboot/initrd.img'),
        '277cd6c7adf77c7e63d73bbb2cded8ef9e2d3a2f100000e92ff1f8396513cd8b')

    def blockdev_add(self) -> None:
        self.vm.cmd('blockdev-add', **{
            'driver': 'null-co',
            'size': 1073741824,
            'node-name': 'disk0'
        })

    def add_scsi_controller(self) -> None:
        self.vm.cmd('device_add', {
            'driver': 'virtio-scsi-pci',
            'id': 'scsi0',
            'bus': 'pci.1',
            'addr': '1',
        })

    def assert_sda(self) -> None:
        exec_command_and_wait_for_pattern(self, 'while ! test -e /sys/block/sda ;'
                                                ' do sleep 0.2 ; done', '# ')

    def assert_no_sda(self) -> None:
        exec_command_and_wait_for_pattern(self, 'while test -e /sys/block/sda ;'
                                                ' do sleep 0.2 ; done', '# ')

    def plug(self) -> None:
        args = {
            'driver':'scsi-hd',
            'drive':'disk0',
            'bus':'scsi0.0',
            'id':'scsi-disk0',
        }

        self.assert_no_sda()
        self.vm.cmd('device_add', args)
        self.wait_for_console_pattern('[sda] Attached SCSI disk')
        self.assert_sda()

    def unplug(self) -> None:
        self.vm.cmd('device_del', id='scsi-disk0')

        self.vm.event_wait('DEVICE_DELETED', 1.0,
                           match={'data': {'device': 'scsi-disk0'}})

        self.assert_no_sda()

    def test(self) -> None:
        self.require_accelerator('kvm')
        self.set_machine('q35')
        self.vm.add_args('-accel', 'kvm')
        self.vm.add_args('-device', 'pcie-pci-bridge,id=pci.1,bus=pcie.0')
        self.vm.add_args('-m', '1G')
        self.vm.add_args('-append', 'console=ttyS0 rd.rescue')

        self.launch_kernel(self.ASSET_KERNEL.fetch(),
                           self.ASSET_INITRD.fetch(),
                           wait_for='Entering emergency mode.')
        self.wait_for_console_pattern('# ')

        self.blockdev_add()
        self.add_scsi_controller()
        self.plug()
        self.unplug()


if __name__ == '__main__':
    LinuxKernelTest.main()

