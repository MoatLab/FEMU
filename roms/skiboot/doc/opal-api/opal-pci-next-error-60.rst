.. _OPAL_PCI_NEXT_ERROR:

OPAL_PCI_NEXT_ERROR
===================

.. code-block:: c

   #define OPAL_PCI_NEXT_ERROR			60

   enum OpalPciStatusToken {
	OPAL_EEH_NO_ERROR	= 0,
	OPAL_EEH_IOC_ERROR	= 1,
	OPAL_EEH_PHB_ERROR	= 2,
	OPAL_EEH_PE_ERROR	= 3,
	OPAL_EEH_PE_MMIO_ERROR	= 4,
	OPAL_EEH_PE_DMA_ERROR	= 5
   };

   enum OpalPciErrorSeverity {
	OPAL_EEH_SEV_NO_ERROR	= 0,
	OPAL_EEH_SEV_IOC_DEAD	= 1,
	OPAL_EEH_SEV_PHB_DEAD	= 2,
	OPAL_EEH_SEV_PHB_FENCED	= 3,
	OPAL_EEH_SEV_PE_ER	= 4,
	OPAL_EEH_SEV_INF	= 5
   };

   int64_t opal_pci_next_error(uint64_t phb_id, uint64_t *first_frozen_pe,
                               uint16_t *pci_error_type, uint16_t *severity);

Retreives details of a PCIe error.

Returns
-------

:ref:`OPAL_SUCCESS`
     Successfully filled `pci_error_type` and `severity` with error details.
:ref:`OPAL_UNSUPPORTED`
     Unsupported operation on this PHB.
:ref:`OPAL_PARAMETER`
     Invalid phb_id, or address for other arguments.
