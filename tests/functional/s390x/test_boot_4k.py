#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright 2026 Red Hat, Inc.
#
# Author:
#  Thomas Huth <thuth@redhat.com>
'''
Functional test that boots from a (incomplete) disk with 4k sectors
(DASD/ECKD geometry) and multiple kernels installed, so we can check
the boot menu and various LOADPARM options.
'''

from qemu_test import QemuSystemTest, Asset, skipFlakyTest
from qemu_test import wait_for_console_pattern


class S390Boot4k(QemuSystemTest):

    # This disk image has been taken from a DASD with 4k sectors.
    # Note: It's incomplete (to keep it small), it contains just enough
    # data for booting the kernels that are installed on the disk image
    ASSET_DISK = Asset(
        ('https://github.com/huth/qemu-paddock/raw/refs/heads/main/s390x/'
         'f32-4k-bootmenu.raw.xz'),
        'f4e2c91b4ec50a4756e8816b7a7c8ca01cc0d929f7a711cfd8124640c304ea41')

    def wait_for_pattern(self, success_message, vm=None):
        wait_for_console_pattern(self, success_message, vm=vm,
                                 failure_message='panic')

    def basic_machine_setup(self):
        self.set_machine('s390-ccw-virtio')
        disk_path = self.uncompress(self.ASSET_DISK, format="xz")

        self.vm.set_console()
        self.vm.add_args("-nographic", "-no-shutdown", "-blockdev",
                         f"driver=file,filename={disk_path},node-name=d1")

    def test_default(self):
        '''
        Check that the default kernel boots up correctly from a ccw device
        '''
        self.basic_machine_setup()
        self.vm.add_args("-device", "virtio-blk-ccw,drive=d1")
        self.vm.launch()
        self.wait_for_pattern("Linux version 5.8.15-301.fc33.s390x")
        self.wait_for_pattern("Trying to unpack rootfs image as initramfs")

    def test_loadparm_machine(self):
        '''
        Check that we can select a kernel via "-machine loadparm=..."
        '''
        self.basic_machine_setup()
        self.vm.add_args("-device", "virtio-blk-ccw,drive=d1",
                         "-machine", "loadparm=2")
        self.vm.launch()
        self.wait_for_pattern("Linux version 5.6.6-300.fc32.s390x")

    def test_loadparm_device(self):
        '''
        Check that we can select a kernel via  "-device ...,loadparm=..."
        '''
        self.basic_machine_setup()
        self.vm.add_args("-device",
                         "virtio-blk-ccw,drive=d1,bootindex=1,loadparm=3")
        self.vm.launch()
        self.wait_for_pattern("Linux version 5.6.6-300.fc32.s390x")

    @skipFlakyTest("https://gitlab.com/qemu-project/qemu/-/work_items/3350")
    def test_loadparm_pci(self):
        '''
        Check that we can select a kernel via  "-device ...-pci,loadparm=..."
        '''
        self.require_device('virtio-blk-pci')
        self.basic_machine_setup()
        self.vm.add_args("-device",
                         "virtio-blk-pci,drive=d1,bootindex=1,loadparm=2")
        self.vm.launch()
        self.wait_for_pattern("Linux version 5.6.6-300.fc32.s390x")

    def test_scsi_default(self):
        '''
        Check that we can boot via SCSI, too (need to set logical block size
        here to avoid that the auto-detection in the bios fails)
        '''
        self.basic_machine_setup()
        self.vm.add_args("-device", "virtio-scsi", "-device",
            "scsi-hd,drive=d1,physical_block_size=4096,logical_block_size=4096")
        self.vm.launch()
        self.wait_for_pattern("Linux version 5.8.15-301.fc33.s390x")

    def test_scsi_loadparm(self):
        '''
        Check that we can boot via SCSI with loadparm
        '''
        self.basic_machine_setup()
        self.vm.add_args("-device", "virtio-scsi", "-device",
                         ("scsi-hd,drive=d1,bootindex=1,loadparm=3,"
                          "physical_block_size=4096,logical_block_size=4096"))
        self.vm.launch()
        self.wait_for_pattern("Linux version 5.6.6-300.fc32.s390x")

    def test_menu(self):
        '''
        Check that boot menu shows up correctly
        '''
        self.basic_machine_setup()
        self.vm.add_args("-device", "virtio-blk-ccw,drive=d1,bootindex=1",
                         "-boot", "menu=on")
        self.vm.launch()
        self.wait_for_pattern("1. Fedora (5.8.15-301.fc33.s390x) 33")
        self.wait_for_pattern("2. Fedora (5.6.6-300.fc32.s390x) 32")
        self.wait_for_pattern("3. Fedora (0-rescue-b7218f0092704c5a9")
        self.wait_for_pattern("Please choose:")
        # For some unknown reason, sending a key to the bios does not work
        # in the testing framework yet:
        # exec_command_and_wait_for_pattern(self, '2',
        #                              "Linux version 5.6.6-300.fc32.s390x")

    def test_menu_timeout(self):
        '''
        Check that boot menu shows up and boot continues automatically
        when a timeout has been specified
        '''
        self.basic_machine_setup()
        self.vm.add_args("-device", "virtio-blk-ccw,drive=d1,bootindex=1",
                         "-boot", "menu=on,splash-time=1")
        self.vm.launch()
        self.wait_for_pattern("s390-ccw zIPL Boot Menu")
        self.wait_for_pattern("0. default (Fedora (5.8.15-301.fc33.s390x)")
        self.wait_for_pattern("(default will boot in 0 seconds)")
        self.wait_for_pattern("Linux version 5.8.15-301.fc33.s390x")


if __name__ == '__main__':
    QemuSystemTest.main()
