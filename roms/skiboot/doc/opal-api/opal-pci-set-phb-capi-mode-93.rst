.. _OPAL_PCI_SET_PHB_CAPI_MODE:

OPAL_PCI_SET_PHB_CAPI_MODE
==========================

.. code-block:: c

   #define OPAL_PCI_SET_PHB_CAPI_MODE		93

   /* CAPI modes for PHB */
   enum {
     OPAL_PHB_CAPI_MODE_PCIE		= 0,
     OPAL_PHB_CAPI_MODE_CAPI		= 1,
     OPAL_PHB_CAPI_MODE_SNOOP_OFF    = 2,
     OPAL_PHB_CAPI_MODE_SNOOP_ON	= 3,
     OPAL_PHB_CAPI_MODE_DMA		= 4,
     OPAL_PHB_CAPI_MODE_DMA_TVT1	= 5,
   };

   int64_t opal_pci_set_phb_capi_mode(uint64_t phb_id, uint64_t mode, uint64_t pe_number);

Switch the CAPP attached to the given PHB in one of the supported CAPI modes.

Parameters
----------

``uint64_t phb_id``
  the ID of the PHB which identifies attached CAPP to perform mode switch on
``uint64_t mode``
  A mode id as described below
``pe_number``
  PE number for the initiating device

Calling
-------

Switch CAPP attached to the given PHB in one of the following supported modes: ::

  OPAL_PHB_CAPI_MODE_PCIE		= 0
  OPAL_PHB_CAPI_MODE_CAPI		= 1
  OPAL_PHB_CAPI_MODE_SNOOP_OFF    = 2
  OPAL_PHB_CAPI_MODE_SNOOP_ON	= 3
  OPAL_PHB_CAPI_MODE_DMA		= 4
  OPAL_PHB_CAPI_MODE_DMA_TVT1	= 5

Modes `OPAL_PHB_CAPI_MODE_PCIE` and `OPAL_PHB_CAPI_MODE_CAPI` are used to
enable/disable CAPP attached to the PHB.

Modes `OPAL_PHB_CAPI_MODE_SNOOP_OFF` and `OPAL_PHB_CAPI_MODE_SNOOP_ON` are
used to enable/disable CAPP snooping of Powerbus traffic for cache line
invalidates.

Mode `OPAL_PHB_CAPI_MODE_DMA` and `OPAL_PHB_CAPI_MODE_DMA_TVT1` are used to
enable CAPP DMA mode.

Presently Mode `OPAL_PHB_CAPI_MODE_DMA_TVT1` is exclusively used by the Mellanox
CX5 adapter. Requesting this mode will also indicate to opal that the card
requests maximum number of DMA read engines allocated to improve DMA read
performance at cost of reduced bandwidth available to other traffic including
CAPP-PSL transactions.

Notes
-----

* If PHB is in PEC2 then requesting mode `OPAL_PHB_CAPI_MODE_DMA_TVT1` will
  allocate extra 16/8 dma read engines to the PHB depending on its stack
  (stack 0/ stack 1). This is needed to improve the Direct-GPU DMA read
  performance for the Mellanox CX5 card.
* Mode `OPAL_PHB_CAPI_MODE_PCIE` not supported on Power-9.
* Requesting mode `OPAL_PHB_CAPI_MODE_CAPI` on Power-9 will disable fast-reboot.
* Modes `OPAL_PHB_CAPI_MODE_DMA`, `OPAL_PHB_CAPI_MODE_SNOOP_OFF` are
  not supported on Power-9.
* CAPI is only supported on Power-8 and Power-9.

Return Codes
------------

:ref:`OPAL_SUCCESS`
  Switch to the requested capi mode performed successfully.
:ref:`OPAL_PARAMETER`
  The requested value of mode or phb_id parameter is not valid.
:ref:`OPAL_HARDWARE`
  An error occurred while switching the CAPP to requested mode.
:ref:`OPAL_UNSUPPORTED`
  Switching to requested capi mode is not possible at the moment
:ref:`OPAL_RESOURCE`
  CAPP ucode not available hence activating CAPP not supported.
:ref:`OPAL_BUSY`
  CAPP is presently in recovery-mode and mode switch cannot be performed.
