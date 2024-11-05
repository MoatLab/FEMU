.. _OPAL_PCI_GET_HUB_DIAG_DATA:

OPAL_PCI_GET_HUB_DIAG_DATA
==========================

.. code-block:: c

   #define OPAL_PCI_GET_HUB_DIAG_DATA		50

   int64_t opal_pci_get_hub_diag_data(uint64_t hub_id, void *diag_buffer, uint64_t diag_buffer_len);

Fetch diagnostic data for an IO hub. This was only implemented for hardware
specific to POWER7 systems, something that was only ever available
internally to IBM for development purposes.

It is currently not used.

If :ref:`OPAL_PCI_NEXT_ERROR` error type is `OPAL_EEH_IOC_ERROR` and severity
is `OPAL_EEH_SEV_INF`, then the OS should call :ref:`OPAL_PCI_GET_HUB_DIAG_DATA`
to retreive diagnostic data to log appropriately.

Returns
-------
:ref:`OPAL_SUCCESS`
     Diagnostic data copied successfully
:ref:`OPAL_PARAMETER`
     Invalid address, invalid hub ID, or insufficient space in buffer for
     diagnostic data.
:ref:`OPAL_UNSUPPORTED`
     hub doesn't support retreiving diagnostic data.
:ref:`OPAL_CLOSED`
     No pending error.
:ref:`OPAL_INTERNAL_ERROR`
     Something went wrong.
