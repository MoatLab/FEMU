#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Functional test for dynamic QMP monitor hotplug
#
# Copyright (c) 2026 Christian Brauner

import asyncio
import os
import random
import threading
import time

from qemu_test import QemuSystemTest

from qemu.qmp.legacy import QEMUMonitorProtocol
from qemu.qmp import QMPClient


class MonitorHotplug(QemuSystemTest):

    def setUp(self):
        super().setUp()
        sock_dir = self.socket_dir()
        self._sock_path = os.path.join(sock_dir.name, 'hotplug.sock')

    def _add_monitor(self, autodelete=False):
        """Create a chardev + monitor and return the socket path."""
        sock = self._sock_path
        self.vm.cmd('chardev-add', id='hotplug-chr', backend={
            'type': 'socket',
            'data': {
                'addr': {
                    'type': 'unix',
                    'data': {'path': sock}
                },
                'server': True,
                'wait': False,
            }
        })
        if autodelete:
            self.vm.cmd('object-add', id='hotplug-mon',
                        qom_type='monitor-qmp',
                        chardev='hotplug-chr',
                        close_action='delete')
        else:
            self.vm.cmd('object-add', id='hotplug-mon',
                        qom_type='monitor-qmp',
                        chardev='hotplug-chr')
        return sock

    def _remove_monitor(self):
        """Remove the monitor + chardev."""
        self.vm.cmd('object-del', id='hotplug-mon')
        self.vm.cmd('chardev-remove', id='hotplug-chr')

    def _connect_and_handshake(self, sock_path):
        """
        Connect to the dynamic monitor socket, perform the QMP
        greeting and capability negotiation, send a command, then
        disconnect.
        """
        qmp = QEMUMonitorProtocol(sock_path)

        # connect(negotiate=True) receives the greeting, validates it,
        # and sends qmp_capabilities automatically.
        greeting = qmp.connect(negotiate=True)
        self.assertIn('QMP', greeting)
        self.assertIn('version', greeting['QMP'])
        self.assertIn('capabilities', greeting['QMP'])

        # Send a real command to prove the session is fully functional
        resp = qmp.cmd_obj({'execute': 'query-version'})
        self.assertIn('return', resp)
        self.assertIn('qemu', resp['return'])

        qmp.close()

    def test_hotplug_cycle(self):
        """
        Hotplug a monitor, do the full QMP handshake, unplug it,
        then repeat the whole cycle a second time.
        """
        self.set_machine('none')
        self.vm.add_args('-nodefaults')
        self.vm.launch()

        # First cycle
        sock = self._add_monitor()
        self._connect_and_handshake(sock)
        self._remove_monitor()

        # Second cycle -- same ids, same path, must work
        sock = self._add_monitor()
        self._connect_and_handshake(sock)
        self._remove_monitor()

    def test_self_removal(self):
        """
        A dynamically-added monitor sends object-del targeting
        itself.  Verify the request is rejected, but the monitor
        can still be deleted from outside its own context.
        """
        self.set_machine('none')
        self.vm.add_args('-nodefaults')
        self.vm.launch()

        sock = self._add_monitor()

        qmp = QEMUMonitorProtocol(sock)
        greeting = qmp.connect(negotiate=True)
        self.assertIn('QMP', greeting)

        # Self-removal: the dynamic monitor raises error
        resp = qmp.cmd_obj({'execute': 'object-del',
                            'arguments': {'id': 'hotplug-mon'}})
        self.assertIn('error', resp)

        qmp.close()

        resp = self.vm.cmd('object-del', id='hotplug-mon')

        # Clean up the chardev
        self.vm.cmd('chardev-remove', id='hotplug-chr')

    def test_auto_delete(self):
        """
        A dynamically-added monitor configured with 'close-action=delete'
        should see itself deleted when the client is closed.
        """
        self.set_machine('none')
        self.vm.add_args('-nodefaults')
        self.vm.launch()

        sock = self._add_monitor(autodelete=True)

        cdevs = [c["label"] for c in self.vm.cmd('query-chardev')]
        objs = [o["name"] for o in self.vm.cmd('qom-list', path='/objects')]
        assert ('hotplug-chr' in cdevs)
        assert ('hotplug-mon' in objs)

        qmp = QEMUMonitorProtocol(sock)
        greeting = qmp.connect(negotiate=True)
        self.assertIn('QMP', greeting)

        cdevs = [c["label"] for c in self.vm.cmd('query-chardev')]
        objs = [o["name"] for o in self.vm.cmd('qom-list', path='/objects')]
        assert ('hotplug-chr' in cdevs)
        assert ('hotplug-mon' in objs)

        qmp.close()

        # Wait upto 10 seconds max for chardev to auto-delete, which
        # is hopefully enough for reliability under high load
        for i in range(int(10 / 0.2)):
            cdevs = [c["label"] for c in self.vm.cmd('query-chardev')]
            if 'hotplug-chr' not in cdevs:
                break
            # Wait a little more then try again
            time.sleep(0.2)

        cdevs = [c["label"] for c in self.vm.cmd('query-chardev')]
        objs = [o["name"] for o in self.vm.cmd('qom-list', path='/objects')]
        assert ('hotplug-chr' not in cdevs)
        assert ('hotplug-mon' not in objs)

    def test_reconnect(self):
        """
        A dynamically-added monitor configured without 'close-action'
        should allow reconnects after the client is closed.
        """
        self.set_machine('none')
        self.vm.add_args('-nodefaults')
        self.vm.launch()

        sock = self._add_monitor()

        qmp = QEMUMonitorProtocol(sock)
        qmp.connect(negotiate=True)

        resp = qmp.cmd_obj({'execute': 'query-chardev'})
        self.assertIn('return', resp)

        qmp.close()

        qmp = QEMUMonitorProtocol(sock)
        qmp.connect(negotiate=True)

        resp = qmp.cmd_obj({'execute': 'query-chardev'})
        self.assertIn('return', resp)

        qmp.close()
        self._remove_monitor()

    def test_large_response(self):
        """
        Send a command with a large response (query-qmp-schema) on a
        dynamically-added monitor to exercise the output buffer flush
        path.
        """
        self.set_machine('none')
        self.vm.add_args('-nodefaults')
        self.vm.launch()

        sock = self._add_monitor()

        qmp = QEMUMonitorProtocol(sock)
        qmp.connect(negotiate=True)

        resp = qmp.cmd_obj({'execute': 'query-qmp-schema'})
        self.assertIn('return', resp)
        self.assertIsInstance(resp['return'], list)
        self.assertGreater(len(resp['return']), 0)

        qmp.close()
        self._remove_monitor()

    def test_events_after_negotiation(self):
        """
        Verify that QMP events are delivered on a dynamically-added
        monitor after capability negotiation completes.
        """
        self.set_machine('none')
        self.vm.add_args('-nodefaults')
        self.vm.launch()

        sock = self._add_monitor()

        qmp = QEMUMonitorProtocol(sock)
        qmp.connect(negotiate=True)

        # Trigger a STOP event via the main monitor, then read it
        # from the dynamic monitor.
        self.vm.cmd('stop')
        resp = qmp.pull_event(wait=True)
        self.assertEqual(resp['event'], 'STOP')

        self.vm.cmd('cont')
        resp = qmp.pull_event(wait=True)
        self.assertEqual(resp['event'], 'RESUME')

        qmp.close()
        self._remove_monitor()

    def stress_mon(self, sock):
        async def main():
            qmp = QMPClient('testvm')
            await qmp.connect(sock)
            # Run query-version in a tight loop so that the
            # monitor thread/dispatcher is very busy at the
            # time we try to delete the monitor
            while True:
                try:
                    # A command which returns a lot of data to make
                    # it more likely we're in the I/O reply path
                    # when deleting the monitor
                    res = await qmp.execute('query-qmp-schema')
                    # Some commands which generate async events
                    # as those can trigger different code paths
                    res = await qmp.execute('stop')
                    res = await qmp.execute('cont')
                except:
                    # we'll get here if the monitor is terminated
                    # by QEMU in which case we must disconnect
                    # out side, but....
                    try:
                        await qmp.disconnect()
                    except (ConnectionResetError, EOFError, BrokenPipeError):
                        # ... disconnect() will probably see
                        # errors too, but we must try to call it
                        # regardless to cleanup asyncio state
                        # and prevent python warnings at GC time
                        pass
                    return
        asyncio.run(main())

    def test_hotplug_stress(self):
        """
        Repeatedly hotplug and unplug a monitor, while another thread
        concurrently issues commands on that monitor. This stresses
        the synchronization with the monitor thread during cleanup
        """
        self.set_machine('none')
        self.vm.add_args('-nodefaults')
        self.vm.launch()

        # Each loop sleeps at most 0.5 seconds, so this should
        # give an upper bound of approx 5 seconds execution
        # time which is reasonable to run by default
        repeat = 10
        for i in range(repeat):
            # First cycle
            sock = self._add_monitor()
            print ("# stress cycle %02d/%02d" % (i, repeat))
            stress = threading.Thread(target=self.stress_mon, args=[sock])
            stress.start()
            # Sleep upto 1/2 second to vary the races
            time.sleep(random.random() / 2)
            self._remove_monitor()
            stress.join()


if __name__ == '__main__':
    QemuSystemTest.main()
