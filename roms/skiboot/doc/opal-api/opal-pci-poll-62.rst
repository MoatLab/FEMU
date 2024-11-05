.. _OPAL_PCI_POLL:

OPAL_PCI_POLL
=============

.. code-block:: c

   #define OPAL_PCI_POLL				62

   int64_t opal_pci_poll(uint64_t id);

Crank the state machine for the PHB id. Returns how many milliseconds for
the caller to sleep.

Returns
-------

Milliseconds for the caller to sleep for, error code, or :ref:`OPAL_SUCCESS`.
