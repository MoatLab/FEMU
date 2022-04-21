.. _OPAL_PCI_EEH_FREEZE_STATUS:

OPAL_PCI_EEH_FREEZE_STATUS
==========================

.. code-block:: c

   #define OPAL_PCI_EEH_FREEZE_STATUS		23

   enum OpalFreezeState {
	OPAL_EEH_STOPPED_NOT_FROZEN = 0,
	OPAL_EEH_STOPPED_MMIO_FREEZE = 1,
	OPAL_EEH_STOPPED_DMA_FREEZE = 2,
	OPAL_EEH_STOPPED_MMIO_DMA_FREEZE = 3,
	OPAL_EEH_STOPPED_RESET = 4,
	OPAL_EEH_STOPPED_TEMP_UNAVAIL = 5,
	OPAL_EEH_STOPPED_PERM_UNAVAIL = 6
   };

   enum OpalPciStatusToken {
	OPAL_EEH_NO_ERROR	= 0,
	OPAL_EEH_IOC_ERROR	= 1,
	OPAL_EEH_PHB_ERROR	= 2,
	OPAL_EEH_PE_ERROR	= 3,
	OPAL_EEH_PE_MMIO_ERROR	= 4,
	OPAL_EEH_PE_DMA_ERROR	= 5
   };

   int64_t opal_pci_eeh_freeze_status(uint64_t phb_id, uint64_t pe_number,
                                      uint8_t *freeze_state,
                                      uint16_t *pci_error_type,
                                      uint64_t *phb_status);

.. note:: The ``phb_status`` parameter is deprecated as
	  of :ref:`skiboot-6.3-rc1`. Linux only ever passed in NULL,
	  and this was safe. Supplying a pointer was previously *unsafe*.
	  Always pass NULL.

.. note:: There once was a :ref:`OPAL_PCI_EEH_FREEZE_STATUS2` call, but it
	  was introduced in firmware and never used by any OS, so it has since
	  been removed from OPAL.

Returns
-------

:ref:`OPAL_PARAMETER`
     Invalid address or PHB.
:ref:`OPAL_UNSUPPORTED`
     PHB does not support this operation.
:ref:`OPAL_HARDWARE`
     Hardware prohibited getting status, OPAL maybe marked it as broken.
:ref:`OPAL_SUCCESS`
     Retreived status.

.. _OPAL_PCI_EEH_FREEZE_STATUS2:

OPAL_PCI_EEH_FREEZE_STATUS2
===========================

.. code-block:: c

   #define OPAL_PCI_EEH_FREEZE_STATUS2		61

Use :ref:`OPAL_PCI_EEH_FREEZE_STATUS` instead of this (removed) call.

While you'd think that a call introduced in the first public OPAL release would
have been used somewhere, it seems that all existing code has only ever used
:ref:`OPAL_PCI_EEH_FREEZE_STATUS` over :ref:`OPAL_PCI_EEH_FREEZE_STATUS2`.

This call has been removed as of :ref:`skiboot-6.4` as it has literally never
been used.
