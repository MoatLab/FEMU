.. _OPAL_PCI_EEH_FREEZE_CLEAR:

OPAL_PCI_EEH_FREEZE_CLEAR
=========================

.. code-block:: c

   #define OPAL_PCI_EEH_FREEZE_CLEAR		26

   enum OpalEehFreezeActionToken {
	OPAL_EEH_ACTION_CLEAR_FREEZE_MMIO = 1,
	OPAL_EEH_ACTION_CLEAR_FREEZE_DMA = 2,
	OPAL_EEH_ACTION_CLEAR_FREEZE_ALL = 3,

	OPAL_EEH_ACTION_SET_FREEZE_MMIO = 1,
	OPAL_EEH_ACTION_SET_FREEZE_DMA  = 2,
	OPAL_EEH_ACTION_SET_FREEZE_ALL  = 3
   };

   int64_t opal_pci_eeh_freeze_clear(uint64_t phb_id, uint64_t pe_number, uint64_t eeh_action_token);


Returns
-------
:ref:`OPAL_SUCCESS`
     Success!
:ref:`OPAL_PARAMETER`
     Invalid PHB
:ref:`OPAL_UNSUPPORTED`
     PHB doesn't support this operation.
:ref:`OPAL_HARDWARE`
     Hardware issue prevents completing operation. OPAL may have detected it
     being broken.
