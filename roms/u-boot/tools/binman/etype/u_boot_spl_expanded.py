# SPDX-License-Identifier: GPL-2.0+
# Copyright 2021 Google LLC
# Written by Simon Glass <sjg@chromium.org>
#
# Entry-type module for expanded U-Boot SPL binary
#

from patman import tout

from binman import state
from binman.etype.blob_phase import Entry_blob_phase

class Entry_u_boot_spl_expanded(Entry_blob_phase):
    """U-Boot SPL flat binary broken out into its component parts

    Properties / Entry arguments:
        - spl-dtb: Controls whether this entry is selected (set to 'y' or '1' to
            select)

    This is a section containing the U-Boot binary, BSS padding if needed and a
    devicetree. Using this entry type automatically creates this section, with
    the following entries in it:

       u-boot-spl-nodtb
       u-boot-spl-bss-pad
       u-boot-dtb

    Having the devicetree separate allows binman to update it in the final
    image, so that the entries positions are provided to the running U-Boot.

    This entry is selected based on the value of the 'spl-dtb' entryarg. If
    this is non-empty (and not 'n' or '0') then this expanded entry is selected.
    """
    def __init__(self, section, etype, node):
        bss_pad = state.GetEntryArgBool('spl-bss-pad')
        super().__init__(section, etype, node, 'u-boot-spl', 'u-boot-spl-dtb',
                         bss_pad)

    @classmethod
    def UseExpanded(cls, node, etype, new_etype):
        val = state.GetEntryArgBool('spl-dtb')
        tout.DoOutput(tout.INFO if val else tout.DETAIL,
                      "Node '%s': etype '%s': %s %sselected" %
                      (node.path, etype, new_etype, '' if val else 'not '))
        return val
