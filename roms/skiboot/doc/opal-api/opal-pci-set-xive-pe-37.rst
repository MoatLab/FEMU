.. _OPAL_PCI_SET_XIVE_PE:

OPAL_PCI_SET_XIVE_PE
====================

.. code-block:: c

   #define OPAL_PCI_SET_XIVE_PE			37

   int64_t opal_pci_set_xive_pe(uint64_t phb_id, uint64_t pe_number, uint32_t xive_num);

**WARNING:** following documentation is from old sources, and is possibly
not representative of OPALv3 as implemented by skiboot. This should be
used as a starting point for full documentation.

The host calls this function to bind a PE to an XIVE. Only that PE may then
signal an MSI that selects this XIVE.

``phb_id``
  is the value from the PHB node ibm,opal-phbid property.

``pe_number``
  is the index of a PE, from 0 to ibm,opal-num-pes minus 1.

``xive_number``
  is the index, from 0 to ibm,opal,ibm-num-msis minus (num_lsis+1)

This call maps the XIVR indexed by xive_num to the PE specified by
pe_number. For ibm,opal-ioda HW, the pe_number must match the pe_number
set in the MVE.

Return value:

.. code-block:: c

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->set_xive_pe)
		return OPAL_UNSUPPORTED;
