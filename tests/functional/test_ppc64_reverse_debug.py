#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Reverse debugging test
#
# Copyright (c) 2020 ISP RAS
#
# Author:
#  Pavel Dovgalyuk <Pavel.Dovgalyuk@ispras.ru>
#
# This work is licensed under the terms of the GNU GPL, version 2 or
# later.  See the COPYING file in the top-level directory.

from qemu_test import skipIfMissingImports, skipFlakyTest
from reverse_debugging import ReverseDebugging


@skipIfMissingImports('avocado.utils')
class ReverseDebugging_ppc64(ReverseDebugging):

    REG_PC = 0x40

    @skipFlakyTest("https://gitlab.com/qemu-project/qemu/-/issues/1992")
    def test_ppc64_pseries(self):
        self.set_machine('pseries')
        # SLOF branches back to its entry point, which causes this test
        # to take the 'hit a breakpoint again' path. That's not a problem,
        # just slightly different than the other machines.
        self.endian_is_le = False
        self.reverse_debugging()

    @skipFlakyTest("https://gitlab.com/qemu-project/qemu/-/issues/1992")
    def test_ppc64_powernv(self):
        self.set_machine('powernv')
        self.endian_is_le = False
        self.reverse_debugging()


if __name__ == '__main__':
    ReverseDebugging.main()
