.. _OPAL_PCI_EEH_FREEZE_SET:

OPAL_PCI_EEH_FREEZE_SET
=======================

.. code-block:: c

   #define OPAL_PCI_EEH_FREEZE_SET			97

   enum OpalEehFreezeActionToken {
	OPAL_EEH_ACTION_CLEAR_FREEZE_MMIO = 1,
	OPAL_EEH_ACTION_CLEAR_FREEZE_DMA = 2,
	OPAL_EEH_ACTION_CLEAR_FREEZE_ALL = 3,

	OPAL_EEH_ACTION_SET_FREEZE_MMIO = 1,
	OPAL_EEH_ACTION_SET_FREEZE_DMA  = 2,
	OPAL_EEH_ACTION_SET_FREEZE_ALL  = 3
   };

   int64_t opal_pci_eeh_freeze_set(uint64_t phb_id, uint64_t pe_number, uint64_t eeh_action_token);

Returns
-------
:ref:`OPAL_PARAMETER`
     Invalid parameter.
:ref:`OPAL_UNSUPPORTED`
     Unsupported operation
:ref:`OPAL_HARDWARE`
     Hardware in a bad state.
