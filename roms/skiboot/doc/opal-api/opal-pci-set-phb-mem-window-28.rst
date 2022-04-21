.. _OPAL_PCI_SET_PHB_MEM_WINDOW:

OPAL_PCI_SET_PHB_MEM_WINDOW
===========================

.. code-block:: c

   #define OPAL_PCI_SET_PHB_MEM_WINDOW             28

   int64_t opal_pci_set_phb_mem_window(uint64_t phb_id,
                                       uint16_t window_type,
                                       uint16_t window_num,
                                       uint64_t addr,
                                       uint64_t pci_addr,
                                       uint64_t size);

.. note:: Appears to be POWER7 p7ioc specific. Likely to be removed soon.

**WARNING:** following documentation is from old sources, and is possibly
not representative of OPALv3 as implemented by skiboot. This should be
used as a starting point for full documentation.

The host calls this function to set the PHB PCI memory window parameters for
PHBs. OPAL sets IO space for P7IOC and KVM cannot relocate this. KVM should
changes these windows only while all devices below the PHB are disabled for
PCI memory ops, and with the target window in disabled state (where supported
by PHB hardware).

``phb_id``
  is the value from the PHB node ibm,opal-phbid property.

``window_type``
  specifies 32-bit or 64-bit PCI memory

  '0' selects IO space, and is not supported for relocation. OPAL
  returns OPAL_UNSUPPORTED for this value.

  '1' selects 32-bit PCI memory space

  '2' selects 64 bit PCI memory space

``window_num``
  is the MMIO window number within the specified PCI memory space

``starting_real_address``
  specifies the location within sytsem (processor)real
  address space this MMIO window starts. This must be a location within the
  IO Hub or PHB node ibm,opal-mmio-real property.

``starting_pci_address``
  specifies the location within PCI 32 or 64-bit
  address space that this MMIO window starts. For 64-bit PCI memory, this
  must be within the low order 60 bit (1 Exabyte) region of PCI memory.
  Addresses above 1EB are reserved to IODA definitions.

``segment_size``
  defines the segment size of this window, in the same format
  as and a matching value from the ibm,opal-memwin32/64 <segment_size>
  property. The window total size, in bytes, is the segment_size times the
  ibm,opal-memwin32/64 <num_segments> property and must not extend beyond
  the ibm,opal-mmio-real property range within system real address space.
  The total MMIO window size is the segment_size times the num_segments
  supported for the specifice window. The host must assure that the
  cumulative address space for all enabled windows does not exceed the total
  PHB 32-bit or 64-bit real address window space, or extend outside these
  address ranges, and that no windows overlap each other in real or PCI
  address space. OPAL does not validate those conditions.

A segment size of '0' indicates to disable this MMIO window. If the PHB
hardware does not support disabling a window, OPAL returns OPAL_UNSUPPORTED
status.

The size of the system real and PCI memory spaces are equal and defined by
segment_size times the number of segments within this MMIO window.

The host must set PHB memory windows to be within the system real address
ranges indicated in the PHB parent HDT hub node ibm,opal-mmio-real property.

Return value:

.. code-block:: c

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->set_phb_mem_window)
		return OPAL_UNSUPPORTED;
