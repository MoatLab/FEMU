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
    # FDP on the bbssd geometry with more blocks: FDP keeps an open unit
    # for each of the 4 handles and for GC, so it needs more free lines
    'fdp': dict(dev='femu_mode=1,devsz_mb=4,subsys=fs0,' +
                BBSSD_GEOMETRY.replace('blks_per_pl=40', 'blks_per_pl=64'),
                pre=('-device', 'femu-subsys,id=fs0,nqn=fs0,fdp=on,fdp.nruh=4'),
                serial='vSSD0',
                checks=['dev', 'serial', 'queues', 'fdp', 'data'],
                size=4 * MIB, gc=True, handles=4),
    'zns': dict(dev='femu_mode=3,devsz_mb=64', serial='vZNSSD0',
                checks=['dev', 'serial', 'queues', 'zone'], full=1),
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
        # a versioned machine keeps the guest view the same across QEMU bases
        machine, _, mopts = os.environ.get('FEMU_MACHINE',
                                           'pc-q35-10.1').partition(',')
        self.set_machine(machine)
        acc = self.accel()
        vm = self.get_vm(name=name)
        vm.set_console()
        # each mode sets its own Identify serial; the serial property is unused
        dev = f'femu,id=fd,{m["dev"]}'
        if extra_dev:
            dev += ',' + extra_dev
        view = os.environ.get('FEMU_VIEW_OUT')
        vm.add_args('-accel', acc, '-cpu', os.environ.get('FEMU_CPU', 'max'),
                    '-m', '512',
                    # no ACPI: the MP table lists one CPU per socket
                    '-smp', '2,sockets=2,cores=1,threads=1',
                    '-nodefaults', '-kernel', self.kernel,
                    '-initrd', self.initrd,
                    '-append', f'console=ttyS0 femu.mode={name} '
                               f'femu.serial={m["serial"]} panic=-1'
                               + (' femu.view=1' if view else ''),
                    '-no-reboot', *m.get('pre', ()), '-device', dev)
        if mopts:
            vm.add_args('-machine', mopts)
        vm.launch()
        lines = self.read_console(vm, time.monotonic() + DEADLINE)
        if view:
            got = [ln for ln in lines if ln.startswith(b'FEMU-VIEW')]
            with open(f'{view}.{name}', 'wb') as f:
                f.writelines(ln + b'\n' for ln in got)
            # an old initramfs or a lost record must not pass as a match
            for kind in (b'cpu ', b'pci ', b'boot BIOS-e820'):
                self.assertTrue(any(ln.startswith(b'FEMU-VIEW ' + kind)
                                    for ln in got), f'no {kind!r} view line')
        # query-femu answers once the guest has enabled the controller
        ns = None
        if name == 'bbssd':
            ns = self.query_ns(vm, kind='lines', limit=4096)
        elif name in ('zns', 'fdp'):
            ns = self.query_ns(vm)
        vm.shutdown()
        # a sanitizer report or a crash at quit must fail the mode
        self.assertEqual(vm.exitcode(), 0, f'QEMU exit code {vm.exitcode()}')
        out = vm.get_log() or ''
        for bad in ('runtime error:', 'Sanitizer'):
            self.assertNotIn(bad, out, 'QEMU reported a sanitizer error')
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
        bad = [t for t in text if t.startswith('FEMU-DMESG')]
        self.assertEqual(bad, [], 'NVMe errors in the guest log')
        self.assertEqual(text[-1], 'FEMU-DONE rc=0')
        if 'dev' in got:
            size = int(re.match(r'size=(\d+)', got['dev']).group(1))
            self.assertEqual(size, self.expected_size(name, ns))
        if m.get('gc'):
            # a new device starts at 0, so the count is what this run moved
            moved = ns['counters']['gc-write-pages']
            self.log.info('gc-write-pages: %d', moved)
            self.assertGreater(moved, 0, 'GC relocated no page')
        if m.get('gc') and 'lines' in ns:
            # every logical page is written and none is trimmed, so the
            # valid pages of all lines must be the namespace pages
            self.assertNotIn('next-offset', ns)
            vpc = sum(ln['vpc'] for ln in ns['lines'])
            self.assertEqual(vpc, m['size'] // 4096, 'valid pages differ')
        if m.get('handles'):
            hs = ns['fdp']['handles']
            self.assertEqual(len(hs), m['handles'], 'FDP handles differ')
            # the guest placed one 4 KiB write on handle 1; Linux writes
            # with no placement go to handle 0, so 2 and 3 stay at 0
            host = {h['id']: h['host-bytes'] for h in hs}
            self.log.info('fdp host-bytes: %s', host)
            self.assertEqual(host.get(1), 4096, 'handle 1 bytes')
            self.assertEqual(host.get(2), 0, 'handle 2 bytes')
            self.assertEqual(host.get(3), 0, 'handle 3 bytes')
            self.assertGreaterEqual(host.get(0, 0), m['size'], 'handle 0')
        if 'full' in m:
            # the guest filled zone 1; a zone left Full by FEMU itself
            # or a fill that never reached Full changes this count
            self.assertEqual(ns['zone-counts']['full'], m['full'],
                             'Full zones differ')

    def expected_size(self, name, ns):
        if name != 'zns':
            return MODES[name]['size']
        z = ns  # FemuNamespaceInfo is a flat union
        return z['zone-size'] * z['zone-counts']['total'] * z['lba-size']

    def test_nossd(self):
        self.check_mode('nossd')

    def test_bbssd(self):
        self.check_mode('bbssd')

    def test_fdp(self):
        self.check_mode('fdp')

    def test_zns(self):
        self.check_mode('zns')

    def test_kv(self):
        self.check_mode('kv')


if __name__ == '__main__':
    QemuSystemTest.main()
