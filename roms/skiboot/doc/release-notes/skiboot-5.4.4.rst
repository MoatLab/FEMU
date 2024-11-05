.. _skiboot-5.4.4:

=============
skiboot-5.4.4
=============

skiboot-5.4.4 was released on Wednesday May 3rd, 2017. It replaces
:ref:`skiboot-5.4.3` as the current stable release in the 5.4.x series.

Over :ref:`skiboot-5.4.3`, we have a small number of bug fixes:

- hw/fsp: Do not queue SP and SPCN class messages during reset/reload
  In certain cases of communicating with the FSP (e.g. sensors), the OPAL FSP
  driver returns a default code (async
  completion) even though there is no known bound from the time of this error
  return to the actual data being available. The kernel driver keeps waiting
  leading to soft-lockup on the host side.

  Mitigate both these (known) cases by returning OPAL_BUSY so the host driver
  knows to retry later.
- core/pci: Fix PCIe slot's presence
  According to PCIe spec, the presence bit is hardcoded to 1 if PCIe
  switch downstream port doesn't support slot capability. The register
  used for the check in pcie_slot_get_presence_state() is wrong. It
  should be PCIe capability register instead of PCIe slot capability
  register. Otherwise, we always have present bit on the PCI topology.

  The issue is found on Supermicro's p8dtu2u machine: ::

     # lspci -t
     -+-[0022:00]---00.0-[01-08]----00.0-[02-08]--+-01.0-[03]----00.0
      |                                           \-02.0-[04-08]--
     # cat /sys/bus/pci/slots/S002204/adapter
     1
     # lspci -vvs 0022:02:02.0
     # lspci -vvs 0022:02:02.0
     0022:02:02.0 PCI bridge: PLX Technology, Inc. PEX 8718 16-Lane, \
     5-Port PCI Express Gen 3 (8.0 GT/s) Switch (rev ab) (prog-if 00 [Normal decode])
        :
     Capabilities: [68] Express (v2) Downstream Port (Slot+), MSI 00
        :
        SltSta:    Status: AttnBtn- PowerFlt- MRL- CmdCplt- PresDet- Interlock-
                   Changed: MRL- PresDet- LinkState-

    This fixes the issue by checking the correct register (PCIe capability).
    Also, the register's value is cached in advance as we did for slot and
    link capability.
- core/pci: More reliable way to update PCI slot power state

  The power control bit (SLOT_CTL, offset: PCIe cap + 0x18) isn't
  reliable enough to reflect the PCI slot's power state. Instead,
  the power indication bits are more reliable comparatively. This
  leads to mismatch between the cached power state and PCI slot's
  presence state, resulting in the hotplug driver in kernel refuses
  to unplug the devices properly on the request. The issue was
  found on below NVMe card on "supermicro,p8dtu2u" machine. We don't
  have this issue on the integrated PLX 8718 switch. ::

     # lspci
     0022:01:00.0 PCI bridge: PLX Technology, Inc. PEX 9733 33-lane, \
                  9-port PCI Express Gen 3 (8.0 GT/s) Switch (rev aa)
     0022:02:01.0 PCI bridge: PLX Technology, Inc. PEX 9733 33-lane, \
                  9-port PCI Express Gen 3 (8.0 GT/s) Switch (rev aa)
     0022:02:04.0 PCI bridge: PLX Technology, Inc. PEX 9733 33-lane, \
                  9-port PCI Express Gen 3 (8.0 GT/s) Switch (rev aa)
     0022:02:05.0 PCI bridge: PLX Technology, Inc. PEX 9733 33-lane, \
                  9-port PCI Express Gen 3 (8.0 GT/s) Switch (rev aa)
     0022:02:06.0 PCI bridge: PLX Technology, Inc. PEX 9733 33-lane, \
                  9-port PCI Express Gen 3 (8.0 GT/s) Switch (rev aa)
     0022:02:07.0 PCI bridge: PLX Technology, Inc. PEX 9733 33-lane, \
                  9-port PCI Express Gen 3 (8.0 GT/s) Switch (rev aa)
     0022:17:00.0 Non-Volatile memory controller: Device 19e5:0123 (rev 45)

  This updates the cached PCI slot's power state using the power
  indication bits instead of power control bit, to fix above issue.
- core/pci: Avoid hreset after freset
