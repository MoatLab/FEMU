.. _OPAL_PCI_MSI_EOI:

OPAL_PCI_MSI_EOI
================

.. code-block:: c

   #define OPAL_PCI_MSI_EOI			63

   int64_t opal_pci_msi_eoi(uint64_t phb_id, uint32_t hwirq);

Only required on PHB3 (POWER8) based systems.

Returns
-------

:ref:`OPAL_SUCCESS`
     Success!
:ref:`OPAL_PARAMETER`
     Invalid PHB id or hwirq.
:ref:`OPAL_HARDWARE`
     Hardware or configuration issue.
:ref:`OPAL_UNSUPPORTED`
     Unsupported on this PHB.
