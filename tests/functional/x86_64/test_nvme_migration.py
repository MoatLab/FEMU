#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# x86_64 NVMe migration test

from migration import MigrationTest
from qemu_test import QemuSystemTest, Asset
from qemu_test import wait_for_console_pattern
from qemu_test import exec_command, exec_command_and_wait_for_pattern


class X8664NVMeMigrationTest(MigrationTest):
    ASSET_KERNEL = Asset(
        ('https://archives.fedoraproject.org/pub/archive/fedora/linux/releases'
         '/31/Server/x86_64/os/images/pxeboot/vmlinuz'),
        'd4738d03dbbe083ca610d0821d0a8f1488bebbdccef54ce33e3adb35fda00129')

    ASSET_INITRD = Asset(
        ('https://archives.fedoraproject.org/pub/archive/fedora/linux/releases'
         '/31/Server/x86_64/os/images/pxeboot/initrd.img'),
        '277cd6c7adf77c7e63d73bbb2cded8ef9e2d3a2f100000e92ff1f8396513cd8b')

    ASSET_DISKIMAGE = Asset(
        ('https://archives.fedoraproject.org/pub/archive/fedora/linux/releases'
         '/31/Cloud/x86_64/images/Fedora-Cloud-Base-31-1.9.x86_64.qcow2'),
        'e3c1b309d9203604922d6e255c2c5d098a309c2d46215d8fc026954f3c5c27a0')

    DEFAULT_KERNEL_PARAMS = ('root=/dev/nvme0n1p1 console=ttyS0 net.ifnames=0 '
                             'rd.rescue quiet')

    def wait_for_console_pattern(self, success_message, vm):
        wait_for_console_pattern(
            self,
            success_message,
            failure_message="Kernel panic - not syncing",
            vm=vm,
        )

    def exec_command_and_check(self, command, vm):
        prompt = '# '
        exec_command_and_wait_for_pattern(self,
                                        f"{command} && echo OK || echo FAIL",
                                        'FAIL', vm=vm)
        # Note, that commands we send to the console are echo-ed back,
        # so if we have a word "FAIL" in the command itself, we should
        # expect to see it once.
        wait_for_console_pattern(self, 'OK', failure_message="FAIL", vm=vm)
        self.wait_for_console_pattern(prompt, vm)

    def configure_machine(self, vm):
        kernel_path = self.ASSET_KERNEL.fetch()
        initrd_path = self.ASSET_INITRD.fetch()
        diskimage_path = self.ASSET_DISKIMAGE.fetch()

        vm.set_console()
        vm.add_args("-cpu", "max")
        vm.add_args("-m", "2G")
        vm.add_args("-accel", "kvm")

        vm.add_args('-drive',
                         f'file={diskimage_path},if=none,id=drv0,snapshot=on')
        vm.add_args('-device', 'nvme,bus=pcie.0,' +
                    'drive=drv0,id=nvme-disk0,serial=nvmemigtest,bootindex=1')

        vm.add_args(
            "-kernel",
            kernel_path,
            "-initrd",
            initrd_path,
            "-append",
            self.DEFAULT_KERNEL_PARAMS
        )

    def launch_source_vm(self, vm):
        vm.launch()

        self.wait_for_console_pattern('Entering emergency mode.', vm)
        prompt = '# '
        self.wait_for_console_pattern(prompt, vm)

        # Synchronize on NVMe driver creating the root device
        exec_command_and_wait_for_pattern(self,
                        "while ! (dmesg -c | grep nvme0n1:) ; do sleep 1 ; done",
                        "nvme0n1", vm=vm)
        self.wait_for_console_pattern(prompt, vm)

        # prepare system
        exec_command_and_wait_for_pattern(self, 'mount /dev/nvme0n1p1 /sysroot',
                                          prompt, vm=vm)
        exec_command_and_wait_for_pattern(self, 'chroot /sysroot',
                                          prompt, vm=vm)
        exec_command_and_wait_for_pattern(self, 'mount -t proc proc /proc',
                                          prompt, vm=vm)
        exec_command_and_wait_for_pattern(self, 'mount -t sysfs sysfs /sys',
                                          prompt, vm=vm)

        # Run workload before migration to check if it continues
        # to run properly after migration.
        #
        # Workload is simple: it continuously calculates checksums of
        # all files in /usr/bin to generate some I/O load on
        # the NVMe disk and at the same time it drops caches to
        # make sure that we have some read I/O on the disk as well.
        # If there are any issues with the migration of the NVMe device,
        # we should see errors in dmesg and consequently in the workload log.
        exec_command_and_wait_for_pattern(self,
            "(while [ ! -f /tmp/test_nvme_mig_workload.stop ]; do \
                rm -f /tmp/test_nvme_mig_workload.iter_finished; \
                echo 3 > /proc/sys/vm/drop_caches; \
                find /usr/bin -type f -exec cksum {} \\;; \
                touch /tmp/test_nvme_mig_workload.iter_finished; \
            done) > /dev/null 2> /tmp/test_nvme_mig_workload.errors &",
            prompt, vm=vm)
        exec_command_and_wait_for_pattern(self,
            'echo $! > /tmp/test_nvme_mig_workload.pid',
            prompt, vm=vm)

        # check if process is alive and running
        self.exec_command_and_check(
            "kill -0 $(cat /tmp/test_nvme_mig_workload.pid)", vm)

    def assert_dest_vm(self, vm):
        prompt = '# '

        # check if process is alive and running after migration,
        # if not - fail the test
        self.exec_command_and_check(
            "kill -0 $(cat /tmp/test_nvme_mig_workload.pid)", vm)

        # signal workload to stop
        exec_command_and_wait_for_pattern(self,
            'touch /tmp/test_nvme_mig_workload.stop',
            prompt, vm=vm)

        # wait workload to finish, because we want to examine log
        # to see if there are any errors
        exec_command_and_wait_for_pattern(self,
            "while [ ! -f /tmp/test_nvme_mig_workload.iter_finished ]; do \
                sleep 1; \
            done;",
            prompt, vm=vm)

        exec_command_and_wait_for_pattern(self,
            'cat /tmp/test_nvme_mig_workload.errors',
            prompt, vm=vm)

        # fail the test if non-empty
        self.exec_command_and_check(
            "[ ! -s /tmp/test_nvme_mig_workload.errors ]", vm)

    def test_migration_with_tcp_localhost(self):
        self.set_machine('q35')
        self.require_accelerator("kvm")

        self.migration_with_tcp_localhost()

    def test_migration_with_unix(self):
        self.set_machine('q35')
        self.require_accelerator("kvm")

        self.migration_with_unix()

    def test_migration_with_exec(self):
        self.set_machine('q35')
        self.require_accelerator("kvm")

        self.migration_with_exec()


if __name__ == '__main__':
    MigrationTest.main()
