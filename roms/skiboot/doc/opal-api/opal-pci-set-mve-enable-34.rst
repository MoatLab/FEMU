.. _OPAL_PCI_SET_MVE_ENABLE:

OPAL_PCI_SET_MVE_ENABLE
=======================


.. code-block:: c

   #define OPAL_PCI_SET_MVE_ENABLE			34

   int64_t opal_pci_set_mve_enable(uint64_t phb_id, uint32_t mve_number, uint32_t state);

   enum OpalMveEnableAction {
	OPAL_DISABLE_MVE = 0,
	OPAL_ENABLE_MVE = 1
   };

**WARNING:** following documentation is from old sources, and is possibly
not representative of OPALv3 as implemented by skiboot. This should be
used as a starting point for full documentation.

The host calls this function to enable or disable an MVE to respond to an MSI
DMA address and message data value.

``phb_id``
  is the value from the PHB node ibm,opal-phbid property.

``mve_number``
  is the index, from 0 to ibm,opal,ibm-num-msi-ports minus1

``state``
  A '1' value of the state parameter indicates to enable the MVE and a '0'
  value indicates to disable the MVE.

This call sets the MVE to an enabled (1) or disabled (0) state.

Return value:

.. code-block:: c

	if (!phb)
		return OPAL_PARAMETER;
	if (!phb->ops->set_mve_enable)
		return OPAL_UNSUPPORTED;
