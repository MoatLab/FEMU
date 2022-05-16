.. _OPAL_PCI_MAP_PE_DMA_WINDOW:

OPAL_PCI_MAP_PE_DMA_WINDOW
==========================

.. code-block:: c

   #define OPAL_PCI_MAP_PE_DMA_WINDOW		44

   static int64_t opal_pci_map_pe_dma_window(uint64_t phb_id,
					     uint64_t pe_number,
					     uint16_t window_id,
					     uint16_t tce_levels,
					     uint64_t tce_table_addr,
					     uint64_t tce_table_size,
					     uint64_t tce_page_size);

**WARNING:** following documentation is from old sources, and is possibly
not representative of OPALv3 as implemented by skiboot. This should be
used as a starting point for full documentation.

The host calls this function to create a DMA window and map it to a PE. This
call returns the address in PCI memory that corresponds to the specified DMA
window, which in part may depend on the particular PHB DMA window used. An
address that is all zeros in the upper 32 bits reflects a DMA window enabled
for 32-bit DMA addresses.

The overall size of the DMA window in PCI memory is determined by the number
of tce_levels times the tce_table_size times the tce_page_size.

``phb_id``
  is the value from the PHB node ``ibm,opal-phbid`` property.

``dma_window_number``
  specifies the DMA window

For ibm,opal-ioda PHBs the dma_window_number is an index from 0 to the PHB
total number of windows minus 1. For ibm,opal-ioda2 PHBs the DMA window_number
is an index from 0 to n-1, where n is the number of windows per window set,
within the window set associated with the specified PE number.

``pe_number``
  is the index of the PE that is authorized to DMA to this window
  address space in PCI memory,

``tce_levels``
  is the number of TCE table levels in the translation hiearchy,
  from 1 to ibm,opal-dmawins property <translation levels>.

``tce_table_addr``
  is the 64-bit system real address of the first level (root,
  for mult-level) TCE table in the translation hiearchy.

``tce_table_size``
  is the size, in bytes, of each TCE table in the translation
  hierarchy. A value of '0' indicates to disable this DMA window.

For ibm,opal-ioda, this must be a value in the range from
128MB / tce_page_size to 256TB / tce_page_size, and must be in the format and
matching a value in the tce_table ranges property that is minimally 256KB for
4K pages.

A particular PE may be mapped to multiple DMA windows, each spanning a DMA
window size corresponding to the win_size32 or win_size_64 specified in the
ibm,opal-dmawins<> property. However, the TCE table base address must be
unique for each window unless it is intended that the same page address in
each DMA window is mapped through the same TCE table entry. Generally, when
mapping the same PE to multiple DMA windows, so as to create a larger overall
DMA window, it is recommended to use consecutive DMA windows and each DMA
window should use a TCE table address that is offset by the win_size value of
predecessor DMA window.

``tce_page_size``
  is the size of PCI memory pages mapped to system real pages
  through all TCE tables in the translation hierarchy. This must be the
  same format as and match a value from the ibm,opal-dmawins property
  <dma-page-sizes>. This page size applies to all TCE tables in the
  translation hierarchy.

``pci_start_addr``
  returns the starting address in PCI memory that corresponds
  to this DMA window based on the input translation parameter values.

``pci_mem_type``
  selects whether this DMA window should be created in 32-bit
  or 64-bit PCI memory. The input values correspond to the same PCI memory
  space locators as MMIO spaces in the ranges<> property -- 0x2 indicated
  32-bit PCI memory and 0x3 indicates 64-bit memory.

Window 0 for both ibm,opal-ioda and ibm,opal-ioda2 PHBs must be within 32-bit
PCI memory and this call return opal_parameter for calls that specify window
0 in 64-bit PCI memory.

The DMA win_size property for 32 bit DMA windows limits the number of
ibm,opal-ioda PHB windows that can map32-bit address space. For example, with
a win_size_32 = 256MB, only 16 DMA windows (and therefore no more than 16
distinct PEs) can map the 4GB of 32-bit PCI memory for DMA. OPAL does not
police this limitation.

Return value:

.. code-block:: c

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->map_pe_dma_window)
		return OPAL_UNSUPPORTED;
