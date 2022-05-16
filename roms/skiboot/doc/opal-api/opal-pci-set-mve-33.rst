.. _OPAL_PCI_SET_MVE:

OPAL_PCI_SET_MVE
================

.. code-block:: c

   #define OPAL_PCI_SET_MVE			33

   int64_t opal_pci_set_mve(uint64_t phb_id, uint32_t mve_number, uint64_t pe_number);

**WARNING:** following documentation is from old sources, and is possibly
not representative of OPALv3 as implemented by skiboot. This should be
used as a starting point for full documentation.

The host calls this function to bind a PE to an MSI Validation Table Entry
(MVE) in the PHB. The MVE compares the MSI requester (RID) to a PE RID,
including within the XIVE, to validate that the requester is authorized to
signal an interrupt to the associated DMA address for a message value that
selects a particular XIVE.

``phb_id``
  is the value from the PHB node ibm,opal-phbid property.

``mve_number``
  is the index, from 0 to ibm,opal,ibm-num-msi-ports minus1

``pe_number``
  is the index of a PE, from 0 to ibm,opal-num-pes minus 1.

This call maps an MVE to a PE and PE RID domain. OPAL uses the PELT to
determine the PE domain. OPAL treats this call as a NOP for IODA2 PHBs
and returns a status of OPAL_SUCCESS.


Return value:

.. code-block:: c

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->set_mve)
		return OPAL_UNSUPPORTED;
