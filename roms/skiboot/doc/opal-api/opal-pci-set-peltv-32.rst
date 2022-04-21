.. _OPAL_PCI_SET_PELTV:

OPAL_PCI_SET_PELTV
==================

.. code-block:: c

   #define OPAL_PCI_SET_PELTV			32

   int64_t opal_pci_set_peltv(uint64_t phb_id, uint32_t parent_pe,
                              uint32_t child_pe, uint8_t state);

**WARNING:** This documentation comes from an old source and is possibly not up
to date with OPALv3. Rely on this documentation only as a starting point,
use the source (and update the docs).


This call sets the PELTV of a parent PE to add or remove a PE number as a PE
within that parent PE domain. The host must call this function for each child
of a parent PE.

``phb_id``
  is the value from the PHB node ibm,opal-phbid property

``parent_pe``
  is the PE number of a PE that is higher in the PCI hierarchy
  to other PEs, such that an error involving this parent PE should cause a
  collateral PE freeze for PEs below this PE in the PCI hierarchy. For example
  a switch upstream bridge is a PE that is parent to PEs reached through that
  upstream bridge such that an error involving the upstream bridge
  (e.g, ERR_FATAL) should cause the PHB to freeze all other PEs below that
  upstream bridge (e.g., a downstream bridge, or devices below a downstream
  bridge).

``child_pe``
  is the PE number of a PE that is lower in the PCI hierarchy
  than another PE, such that an error involving that other PE should cause a
  collateral PE freeze for this child PE. For example a device below a
  downstream bridge of a PCIE switch is a child PE that downstream bridge PE
  and the upstream bridge PE of that switch -- an ERR_Fatal from either bridge
  should result in a collateral freeze of that device PE.

.. code-block:: c

   enum OpalPeltvAction {
	OPAL_REMOVE_PE_FROM_DOMAIN = 0,
	OPAL_ADD_PE_TO_DOMAIN = 1
   };

**OPAL Implementation Note:**
**WARNING TODO**: *CHECK IF THIS IS CORRECT FOR skiboot:*
For ibm,opal-ioda2, OPAL sets the PELTV bit in all RTT entries for the parent
PE when the state argument is '1'. OPAL clears the PELTV bit in all RTT
entries for the parent PE when the state argument is '0' and setting the child
PE bit in the parent PELTV results in an all-zeros value for that PELTV.

Return value:

.. code-block:: c

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->set_peltv)
		return OPAL_UNSUPPORTED;
