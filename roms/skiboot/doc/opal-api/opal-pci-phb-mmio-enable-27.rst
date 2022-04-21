.. _OPAL_PCI_PHB_MMIO_ENABLE:

OPAL_PCI_PHB_MMIO_ENABLE
========================

.. code-block:: c

   #define OPAL_PCI_PHB_MMIO_ENABLE		27

   int64_t opal_pci_phb_mmio_enable(uint64_t phb_id, uint16_t window_type,
                                    uint16_t window_num, uint16_t enable);

.. note:: Appears to be POWER7 p7ioc specific. Likely to be removed soon.

**WARNING:** following documentation is from old sources, and is possibly
not representative of OPALv3 as implemented by skiboot. This should be
used as a starting point for full documentation.


The host calls this function to enable or disable PHB decode of the PCI IO
and Memory address spaces below that PHB. Window_num selects an mmio window
within that address space. Enable set to '1' enables the PHB to decode and
forward system real addresses to PCI memory, while enable set to '0' disables
PHB decode and forwarding for the address range defined in a particular MMIO
window.

Not all PHB hardware may support disabling some or all MMIO windows. OPAL
returns :ref:`OPAL_UNSUPPORTED` if called to disable an MMIO window for which
hardware does not support disable. KVM may call this function for all MMIO
windows and ignore the opal_unsuppsorted return code so long as KVM has
disabled MMIO to all downstream PCI devices and assured that KVM and OS guest
partitions cannot issue CI loads/stores to these address spaces from the
processor (e.g.,via HPT).

OPAL returns :ref:`OPAL_SUCCESS` for calls to OPAL to enable them for PHBs that do
not support disable.

``phb_id``
  is the value from the PHB node ibm,opal-phbid property.

``window_type``
  specifies 32-bit or 64-bit PCI memory

  '0' selects PCI IO Space

  '1' selects 32-bit PCI memory space

  '2' selects 64 bit PCI memory space

``window_num``
  is the MMIO window number within the specified PCI memory space

``enable``
  specifies to enable or disable this MMIO window.
