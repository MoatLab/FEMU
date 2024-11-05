.. _OPAL_PCI_MAP_PE_MMIO_WINDOW:

OPAL_PCI_MAP_PE_MMIO_WINDOW
===========================

.. code-block:: c

   #define OPAL_PCI_MAP_PE_MMIO_WINDOW		29

   int64_t opal_pci_map_pe_mmio_window(uint64_t phb_id,
                                       uint64_t pe_number,
                                       uint16_t window_type,
                                       uint16_t window_num,
                                       uint16_t segment_num);

.. note:: Appears to be POWER7 p7ioc specific. Likely to be removed soon.

**WARNING:** following documentation is from old sources, and is possibly
not representative of OPALv3 as implemented by skiboot. This should be
used as a starting point for full documentation.

The host calls this function to map a segment of MMIO address space to a PE.

``phb_id``
  is the value from the PHB node ibm,opal-phbid property.

``window_type``
  specifies 32-bit or 64-bit PCI memory

  '0' selects PCI IO Space. ibm,opal-ioda2 PHBs do not support IO space,
  and OPAL returns opal_unsupported if called for IO windows.

  '1' selects 32-bit PCI memory space

  '2' selects 64 bit PCI memory space

``window_num``
  is the MMIO window number within the specified PCI memory space

``segment_num``
  is an index from 0 to the number of segments minus 1 defined
  or this window, and selects a particular segment within the specified
  window.


Return value:

.. code-block:: c

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->map_pe_mmio_window)
		return OPAL_UNSUPPORTED;
