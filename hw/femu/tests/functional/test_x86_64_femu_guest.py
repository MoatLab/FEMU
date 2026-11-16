#!/usr/bin/env python3
#
# Boot a Linux guest on each FEMU mode and check the real NVMe driver.
#
# The kernel and initramfs come from hw/femu/scripts/build-guest-kernel.sh
# and build-guest-initramfs.sh. FEMU_GUEST_KERNEL and FEMU_GUEST_INITRD
# name them. Without them the test skips, unless FEMU_GUEST_REQUIRED=1,
# and then it fails.
#
#   guest /init: FEMU-READY, FEMU-CHECK <name> ok|fail ..., FEMU-DONE rc=N
#   host: the exact check set of the mode, the size, no failure line,
#         no panic; the GC count for bbssd; then QMP quit.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import os
import re
import socket
import time

from qemu_test import QemuSystemTest

MIB = 1024 * 1024
# 40 lines of 128 KiB under a 4 MiB namespace: 8 lines stay free after
# the first fill, so the overwrite passes must run GC
BBSSD_GEOMETRY = ('secsz=512,secs_per_pg=8,pgs_per_blk=16,blks_per_pl=40,'
                  'pls_per_lun=1,luns_per_ch=1,nchs=2')

MODES = {
    'nossd': dict(dev='femu_mode=2,devsz_mb=64', serial='vNoSSD0',
                  checks=['dev', 'serial', 'queues', 'data'],
                  size=64 * MIB),
    'bbssd': dict(dev='femu_mode=1,devsz_mb=4,' + BBSSD_GEOMETRY,
                  serial='vSSD0',
                  checks=['dev', 'serial', 'queues', 'data'],
                  size=4 * MIB, gc=True),
    'zns': dict(dev='femu_mode=3,devsz_mb=64', serial='vZNSSD0',
                checks=['dev', 'serial', 'queues', 'zone']),
    'kv': dict(dev='femu_mode=5,devsz_mb=64', serial='vKVSSD0',
               checks=['kvdev', 'serial', 'irq', 'kv']),
}

BAD = (b'Kernel panic', b'Call Trace', b'BUG:', b'Oops')
DEADLINE = 240


class FemuGuest(QemuSystemTest):

    timeout = 600

    def setUp(self):
        super().setUp()
        self.kernel = os.environ.get('FEMU_GUEST_KERNEL')
        self.initrd = os.environ.get('FEMU_GUEST_INITRD')
        required = os.environ.get('FEMU_GUEST_REQUIRED') == '1'
        have = all(p and os.access(p, os.R_OK)
                   for p in (self.kernel, self.initrd))
        if not have:
            if required:
                self.fail('FEMU_GUEST_KERNEL or FEMU_GUEST_INITRD is '
                          'missing or unreadable')
            self.skipTest('set FEMU_GUEST_KERNEL and FEMU_GUEST_INITRD')

    def accel(self):
        """FEMU_GUEST_ACCEL, else KVM when /dev/kvm opens, else TCG."""
        forced = os.environ.get('FEMU_GUEST_ACCEL')
        if forced:
            self.log.info('accelerator: %s (forced)', forced)
            return forced
        try:
            fd = os.open('/dev/kvm', os.O_RDWR)
            os.close(fd)
            acc = 'kvm'
        except OSError:
            acc = 'tcg'
        self.log.info('accelerator: %s', acc)
        return acc

    def query_ns(self, vm, **args):
        rsp = vm.qmp('query-femu', path='/machine/peripheral/fd', **args)
        self.assertIn('return', rsp, f'query-femu: {rsp}')
        nss = rsp['return']['namespaces']
        self.assertEqual(len(nss), 1)
        return nss[0]

    def read_console(self, vm, deadline):
        """Every console line up to FEMU-DONE, or a failure at the deadline."""
        sock = vm.console_socket
        buf = b''
        lines = []
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                self.fail('no FEMU-DONE before the deadline; last lines: '
                          + repr(lines[-5:]))
            sock.settimeout(left)
            try:
                c = sock.recv(4096)
            except socket.timeout:
                continue
            if not c:
                self.fail('console closed before FEMU-DONE: '
                          + repr(lines[-5:]))
            buf += c
            while b'\n' in buf:
                line, buf = buf.split(b'\n', 1)
                line = line.rstrip(b'\r')
                lines.append(line)
                self.log.debug('console: %s', line.decode(errors='replace'))
                for bad in BAD:
                    if bad in line:
                        self.fail(f'guest: {line!r}')
                if line.startswith(b'FEMU-DONE'):
                    return lines

    def run_mode(self, name, extra_dev=''):
        m = MODES[name]
        self.set_machine('q35')
        acc = self.accel()
        vm = self.get_vm(name=name)
        vm.set_console()
        # each mode sets its own Identify serial; the serial property is unused
        dev = f'femu,id=fd,{m["dev"]}'
        if extra_dev:
            dev += ',' + extra_dev
        vm.add_args('-accel', acc, '-cpu', 'max', '-m', '512',
                    # no ACPI: the MP table lists one CPU per socket
                    '-smp', '2,sockets=2,cores=1,threads=1',
                    '-nodefaults', '-kernel', self.kernel,
                    '-initrd', self.initrd,
                    '-append', f'console=ttyS0 femu.mode={name} '
                               f'femu.serial={m["serial"]} panic=-1',
                    '-no-reboot', '-device', dev)
        vm.launch()
        lines = self.read_console(vm, time.monotonic() + DEADLINE)
        # query-femu answers once the guest has enabled the controller
        ns = None
        if name == 'bbssd':
            ns = self.query_ns(vm, kind='lines', limit=4096)
        elif name == 'zns':
            ns = self.query_ns(vm)
        vm.shutdown()
        return m, lines, ns

    def check_mode(self, name):
        m, lines, ns = self.run_mode(name)
        text = [ln.decode(errors='replace') for ln in lines]
        self.assertTrue(any(t.startswith('FEMU-READY') for t in text),
                        'no FEMU-READY')
        got = {}
        for t in text:
            g = re.match(r'FEMU-CHECK (\S+) (ok|fail)(.*)', t)
            if g:
                self.assertEqual(g.group(2), 'ok', t)
                self.assertNotIn(g.group(1), got, f'check twice: {t}')
                got[g.group(1)] = g.group(3).strip()
        self.assertEqual(list(got), m['checks'])
        self.assertEqual(text[-1], 'FEMU-DONE rc=0')
        if 'dev' in got:
            size = int(re.match(r'size=(\d+)', got['dev']).group(1))
            self.assertEqual(size, self.expected_size(name, ns))
        if m.get('gc'):
            # a new device starts at 0, so the count is what this run moved
            moved = ns['counters']['gc-write-pages']
            self.log.info('gc-write-pages: %d', moved)
            self.assertGreater(moved, 0, 'GC relocated no page')
            # every logical page is written and none is trimmed, so the
            # valid pages of all lines must be the namespace pages
            self.assertNotIn('next-offset', ns)
            vpc = sum(ln['vpc'] for ln in ns['lines'])
            self.assertEqual(vpc, m['size'] // 4096, 'valid pages differ')

    def expected_size(self, name, ns):
        if name != 'zns':
            return MODES[name]['size']
        z = ns  # FemuNamespaceInfo is a flat union
        return z['zone-size'] * z['zone-counts']['total'] * z['lba-size']

    def test_nossd(self):
        self.check_mode('nossd')

    def test_bbssd(self):
        self.check_mode('bbssd')

    def test_zns(self):
        self.check_mode('zns')

    def test_kv(self):
        self.check_mode('kv')


if __name__ == '__main__':
    QemuSystemTest.main()
