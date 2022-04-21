.. _OPAL_PCI_MAP_PE_DMA_WINDOW_REAL:

OPAL_PCI_MAP_PE_DMA_WINDOW_REAL
===============================

.. code-block:: c

   #define OPAL_PCI_MAP_PE_DMA_WINDOW_REAL		45

   int64_t opal_pci_map_pe_dma_window_real(uint64_t phb_id,
                                           uint64_t pe_number,
                                           uint16_t window_id,
                                           uint64_t pci_start_addr,
                                           uint64_t pci_mem_size);


**WARNING:** following documentation is from old sources, and is possibly
not representative of OPALv3 as implemented by skiboot. This should be
used as a starting point for full documentation.

The host calls this function to initialize the specified DMA window for
untranslated DMA addresses. This allows a PE to DMA directly to system memory
without TCE translation. The DMA window PCI memory address is equal to the
system memory real address. The PHB passes PCI address bits 04:63 directly to
system real address bits 04:63 when PCI address bits 04:39 are within the
region specified by mem_addr t0 mem_addr + window_size.

The addresses must be 16MB aligned and a multiple of 16MB in size.

``phb_id``
  is the value from the PHB node ibm,opal-phbid property.

``dma_window_number``
  specifies the DMA window

For ibm,opal-ioda PHBs the dma_window_number is an index from 0 to the PHB
total number of windows minus 1. For ibm,opal-ioda2 PHBs the DMA window_number
is an index from 0 to n-1, where n is the number of windows per window set,
within the window set associated with the specified PE number.

``pe_number``
  is the index of the PE that is authorized to DMA to this window
  address space in PCI memory,

``mem_addr``
  is the starting 64-bit system real address mapped directly to the
  starting address in PCI memory. Addresses below 4GB are zero in bits above
  bit 32. This value must be aligned on a 16MB boundary; OPAL returns
  OPAL_PARAMETER for any value that is not a multiple of 16MB.

``window_size``
  is the size, in bytes, of the address range defined by this
  window. This value must be a multiple of 16MB; OPAL returns :ref:`OPAL_PARAMETER`
  for any value that is not a multiple of 16MB. A value of '0' indicates to
  disable this DMA window.
