.. _nvlink:

OPAL/Skiboot Nvlink Interface Documentation
===========================================

Overview
--------

NV-Link is a high speed interconnect that is used in conjunction with
a PCI-E connection to create an interface between chips that provides
very high data bandwidth. The PCI-E connection is used as the control
path to initiate and report status of large data transfers. The data
transfers themselves are sent over the NV-Link.

On IBM Power systems the NV-Link hardware is similar to our standard
PCI hardware so to maximise code reuse the NV-Link is exposed as an
emulated PCI device through system firmware (OPAL/skiboot). Thus each
NV-Link capable device will appear as two devices on a system, the
real PCI-E device and at least one emulated PCI device used for the
NV-Link.

Presently the NV-Link is only capable of data transfers initiated by
the target, thus the emulated PCI device will only handle registers
for link initialisation, DMA transfers and error reporting (EEH).

Emulated PCI Devices
--------------------

Each link will be exported as an emulated PCI device with a minimum of
two emulated PCI devices per GPU. Emulated PCI devices are grouped per
GPU.

The emulated PCI device will be exported as a standard PCI device by
the Linux kernel. It has a standard PCI configuration space to expose
necessary device parameters. The only functionality available is
related to the setup of DMA windows.

Configuration Space Parameters
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

============ =================== =====
============ =================== =====
Vendor ID    0x1014              (IBM)
Device ID    0x04ea
Revision ID  0x00
Class        0x068000 / 0x068001 (Bridge Device Other, ProgIf = 0x0 / 0x1)
BAR0/1       TL/DL Registers
BAR2/3       GEN-ID Registers    (Only for rev-id = 0x1)
============ =================== =====

TL/DL Registers
^^^^^^^^^^^^^^^

Each link has 128KB of TL/DL registers. These will always be mapped
to 64-bit BAR#0 of the emulated PCI device configuration space. ::

 BAR#0 + 128K +-----------+
       	     | NTL (64K) |
 BAR#0 + 64K  +-----------+
      	     | DL (64K)  |
 BAR#0	     +-----------+

Generation Registers (GEN-ID)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

On POWER9 each link has 64K of generation ID registers for the relaxed
ordering mode syncronisation. Refer to the programming guide for
details of the register layout in this BAR.

Relaxed ordering mode will be disabled by default as it requires
device driver support. Device drivers will need to request relaxed
ordering mode through some yet to be designed mechanism.

Vendor Specific Capabilities
^^^^^^^^^^^^^^^^^^^^^^^^^^^^
::

 +-----------------+----------------+----------------+----------------+
 |  Version (0x02) |   Cap Length   |  Next Cap Ptr  |  Cap ID (0x09) |
 +-----------------+----------------+----------------+----------------+
 |                      Procedure Status Register                     |
 +--------------------------------------------------------------------+
 |                      Procedure Control Register                    |
 +---------------------------------------------------+----------------+
 |             Reserved            |   PCI Dev Flag  |   Link Number  |
 +---------------------------------------------------+----------------+

Version

   This refers to the version of the NPU config space.  Used by device
   drivers to determine which fields of the config space they can
   expect to be available.

Procedure Control Register

   Used to start hardware procedures.

   Writes will start the corresponding procedure and set bit 31 in the
   procedure status register. This register must not be written while
   bit 31 is set in the status register. Performing a write while
   another procudure is already in progress will abort that procedure.

   Reads will return the in progress procedure or the last completed
   procedure number depending on the procedure status field.

   Procedure Numbers:

    0. Abort in-progress procedure
    1. NOP
    2. Unsupported procedure
    3. Unsupported procedure
    4. Naples PHY - RESET
    5. Naples PHY - TX_ZCAL
    6. Naples PHY - RX_DCCAL
    7. Naples PHY - TX_RXCAL_ENABLE
    8. Naples PHY - TX_RXCAL_DISABLE
    9. Naples PHY - RX_TRAINING
    10. Naples NPU - RESET
    11. Naples PHY - PHY preterminate
    12. Naples PHY - PHY terminated
    13. Witherspoon TL credit validation

   Procedure 5 (TX_ZCAL) should only be run once. System firmware will
   ensure this so device drivers may call this procedure mutiple
   times.

Procedure Status Register

   The procedure status register is used to determine when execution
   of the procedure number in the control register is complete and if
   it completed successfully.

   This register must be polled frequently to allow system firmware to
   execute the procedures.

   Fields:
       Bit 31 - Procedure in progress
       Bit 30 - Procedure complete
       Bit 3-0 - Procedure completion code

   Procedure completion codes:
       0 - Procedure completed successfully.
       1 - Transient failure. Procedure should be rerun.
       2 - Permanent failure. Procedure will never complete successfully.
       3 - Procedure aborted.
       4 - Unsupported procedure.

PCI Device Flag

   Bit 0 - set if the GPU PCIe device associated with this nvlink was found.
   bit 1 - set if the DL has been taken out of reset.

Link Number

   Physical link number this emulated PCI device is associated
   with. One of 0, 1, 4 or 5 (links 2 & 3 do not exist on Naples).

Reserved

   These fields must be ignored and no value should be assumed.

Interrupts
^^^^^^^^^^

Each link has a single DL/TL interrupt assigned to it. These will be
exposed as an LSI via the emulated PCI device. There are 4 links
consuming 4 LSI interrupts. The 4 remaining interrupts supported by the
corresponding PHB will be routed to OS platform for the purpose of error
reporting.

Device Tree Bindings
--------------------

See :ref:`device-tree/nvlink`
