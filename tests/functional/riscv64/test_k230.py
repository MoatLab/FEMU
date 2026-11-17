#!/usr/bin/env python3
#
# Functional tests that boot Linux on a Kendryte K230 machine.
#
# The direct boot test lets QEMU load OpenSBI, Linux, the device tree, and the
# initramfs.  The firmware boot test starts the K230 SDK U-Boot and uses bootm
# to launch OpenSBI and Linux from images preloaded into RAM.
#
# Author:
#  Junze Cao
#
# SPDX-License-Identifier: GPL-2.0-or-later

import os

from qemu_test import Asset, LinuxKernelTest
from qemu_test import exec_command_and_wait_for_pattern
from qemu_test import interrupt_interactive_console_until_pattern


class K230Machine(LinuxKernelTest):

    ASSET_KERNEL = Asset(
        ('https://raw.githubusercontent.com/zevorn/k230-boot-assets/'
         'c3c32fb46e8307c5063f13e8f367c98bf9273cd1/'
         'yocto/direct-boot/Image'),
        '3a44970213fa68ad318d308518adfc0bf4bee72ed1b2926f9b468f82ef7d7829')
    ASSET_DTB = Asset(
        ('https://raw.githubusercontent.com/zevorn/k230-boot-assets/'
         'c3c32fb46e8307c5063f13e8f367c98bf9273cd1/'
         'yocto/direct-boot/k230-canmv.dtb'),
        '5050240b48ce0988c73eaefa73e4945a40abca503cf488d22a3adf6ef50bbe4c')
    ASSET_INITRD = Asset(
        ('https://raw.githubusercontent.com/zevorn/k230-boot-assets/'
         'c3c32fb46e8307c5063f13e8f367c98bf9273cd1/'
         'yocto/direct-boot/rootfs.cpio.gz'),
        '4e1869a99a232ee60324f71f3a9e84a79b03ccabb5b73f8a727c5ff5be5c0914')
    ASSET_UBOOT = Asset(
        ('https://raw.githubusercontent.com/zevorn/k230-boot-assets/'
         'c3c32fb46e8307c5063f13e8f367c98bf9273cd1/common/u-boot'),
        '0915b9a92a7c911846a8cf691866ef14ef050a51d04209f884ae8e9ec33f36d2')
    ASSET_FW_JUMP = Asset(
        ('https://raw.githubusercontent.com/zevorn/k230-boot-assets/'
         'c3c32fb46e8307c5063f13e8f367c98bf9273cd1/'
         'common/fw_jump.uImage'),
        'cf7788e470f1d6e8c85491ecdc2705518db1b6af54080e8c7a3464bad0d902b7')

    def wait_for_linux_shell(self):
        self.wait_for_console_pattern('meta-k230 initramfs starting...')
        self.wait_for_console_pattern('~ #')

    def test_k230_direct_boot(self):
        self.set_machine('k230')
        kernel_path = self.ASSET_KERNEL.fetch()
        dtb_path = self.ASSET_DTB.fetch()
        initrd_path = self.ASSET_INITRD.fetch()

        self.vm.set_console()
        self.vm.add_args('-kernel', kernel_path,
                         '-dtb', dtb_path,
                         '-initrd', initrd_path,
                         '-append', 'console=ttyS0,115200 earlycon=sbi',
                         '-no-reboot')
        self.vm.launch()
        self.wait_for_linux_shell()

    def test_k230_uboot_boot(self):
        self.set_machine('k230')
        kernel_path = self.ASSET_KERNEL.fetch()
        dtb_path = self.ASSET_DTB.fetch()
        initrd_path = self.ASSET_INITRD.fetch()
        uboot_path = self.ASSET_UBOOT.fetch()
        fw_jump_path = self.ASSET_FW_JUMP.fetch()
        initrd_end = 0x0a100000 + os.path.getsize(initrd_path)

        self.vm.set_console()
        self.vm.add_args(
            '-bios', uboot_path,
            '-device',
            f'loader,file={fw_jump_path},addr=0xc100000,force-raw=on',
            '-device',
            f'loader,file={kernel_path},addr=0x8200000,force-raw=on',
            '-device',
            f'loader,file={initrd_path},addr=0xa100000,force-raw=on',
            '-device',
            f'loader,file={dtb_path},addr=0xa000000,force-raw=on',
            '-no-reboot')
        self.vm.launch()

        interrupt_interactive_console_until_pattern(self, 'K230#')
        commands = (
            'setenv bootargs console=ttyS0,115200 earlycon=sbi',
            'fdt addr 0xa000000',
            'fdt resize 8192',
            'fdt set /chosen linux,initrd-start <0x0 0xa100000>',
            f'fdt set /chosen linux,initrd-end <0x0 0x{initrd_end:x}>',
        )
        for command in commands:
            exec_command_and_wait_for_pattern(self, command, 'K230#')

        exec_command_and_wait_for_pattern(
            self, 'bootm 0xc100000 - 0xa000000',
            'Starting kernel ...', failure_message='ERROR')
        self.wait_for_linux_shell()


if __name__ == '__main__':
    LinuxKernelTest.main()
