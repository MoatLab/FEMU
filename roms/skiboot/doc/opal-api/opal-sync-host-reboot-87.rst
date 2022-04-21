.. _OPAL_SYNC_HOST_REBOOT:

OPAL_SYNC_HOST_REBOOT
=====================

.. code-block:: c

   #define OPAL_SYNC_HOST_REBOOT			87

   static int64_t opal_sync_host_reboot(void);

This OPAL call halts asynchronous operations in preparation for something
like kexec. It will halt DMA as well notification of some events (such
as a new error log being available for retreival).

It's meant to be called in a loop until :ref:`OPAL_SUCCESS` is returned.

Returns
-------
:ref:`OPAL_SUCCESS`
  Success!
:ref:`OPAL_BUSY_EVENT`
  not yet complete, call opal_sync_host_reboot() again, possibly with a short delay.
:ref:`OPAL_BUSY`
  Call opal_poll_events() and then retry opal_sync_host_reboot
