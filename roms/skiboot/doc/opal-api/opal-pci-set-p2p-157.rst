.. _OPAL_PCI_SET_P2P:

OPAL_PCI_SET_P2P
================

.. code-block:: c

   #define OPAL_PCI_SET_P2P			157

   int64_t opal_pci_set_p2p(uint64_t phbid_init, uint64_t phbid_target,
				uint64_t desc, uint16_t pe_number);

   /* PCI p2p descriptor */
   #define OPAL_PCI_P2P_ENABLE		0x1
   #define OPAL_PCI_P2P_LOAD		0x2
   #define OPAL_PCI_P2P_STORE		0x4

The host calls this function to enable PCI peer-to-peer on the PHBs.

Parameters
----------

``phbid_init``
  is the value from the PHB node ibm,opal-phbid property for the device initiating the p2p operation

``phbid_target``
  is the value from the PHB node ibm,opal-phbid property for the device targeted by the p2p operation

``desc``
  tells whether the p2p operation is a store (OPAL_PCI_P2P_STORE) or load (OPAL_PCI_P2P_LOAD). Can be both.
  OPAL_PCI_P2P_ENABLE enables/disables the setting

``pe_number``
  PE number for the initiating device

Return Values
-------------

:ref:`OPAL_SUCCESS`
  Configuration was successful
:ref:`OPAL_PARAMETER`
  Invalid PHB or mode parameter
:ref:`OPAL_UNSUPPORTED`
  Not supported by hardware
