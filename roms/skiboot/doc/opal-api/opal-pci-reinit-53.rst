.. _OPAL_PCI_REINIT:

OPAL_PCI_REINIT
===============

.. code-block:: c

   #define OPAL_PCI_REINIT				53

   enum OpalPciReinitScope {
	/*
	 * Note: we chose values that do not overlap
	 * OpalPciResetScope as OPAL v2 used the same
	 * enum for both
	 */
	OPAL_REINIT_PCI_DEV = 1000
   };

   int64_t opal_pci_reinit(uint64_t phb_id, uint64_t reinit_scope, uint64_t data);

.. note:: Much glory awaits the one who fills in this documentation.

Returns
-------

:ref:`OPAL_PARAMETER`
     Invalid PHB, scope, or device.
:ref:`OPAL_UNSUPPORTED`
     Operation unsupported
:ref:`OPAL_HARDWARE`
     Some hardware issue prevented the reinit.
