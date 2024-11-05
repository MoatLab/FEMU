.. _opal-psr:

======================
OPAL Power Shift Ratio
======================

Sometimes power management firmware needs to throttle power availability
to system components in order to keep within power cap or thermal limits.
It's possible to set a preference as to what trade-offs power management
firmware will make. For example, certain workloads may heavily prefer
throttling CPU over GPUs or vice-versa.

.. _OPAL_GET_POWER_SHIFT_RATIO:

OPAL_GET_POWER_SHIFT_RATIO
==========================
OPAL call to read the power-shifting-ratio using a handle to identify
the type (e.g CPU vs. GPU, CPU vs. MEM) which is exported via
device-tree.

The call can be asynchronus, where the token parameter is used to wait
for the completion.

Parameters
----------

=== =======
=== =======
u32 handle
int token
u32 \*ratio
=== =======

Returns
-------

:ref:`OPAL_SUCCESS`
  Success
:ref:`OPAL_PARAMETER`
  Invalid ratio pointer
:ref:`OPAL_UNSUPPORTED`
  No support for reading psr
:ref:`OPAL_HARDWARE`
  Unable to procced due to the current hardware state
:ref:`OPAL_ASYNC_COMPLETION`
  Request was sent and an async completion message will be sent with
  token and status of the request.

.. _OPAL_SET_POWER_SHIFT_RATIO:

OPAL_SET_POWER_SHIFT_RATIO
==========================
OPAL call to set power-shifting-ratio using a handle to identify
the type of PSR which is exported in device-tree. This call can be
asynchronus where the token parameter is used to wait for the
completion.

Parameters
----------

=== ======
=== ======
u32 handle
int token
u32 ratio
=== ======

Returns
-------

:ref:`OPAL_SUCCESS`
  Success
:ref:`OPAL_PARAMETER`
  Invalid ratio requested
:ref:`OPAL_UNSUPPORTED`
  No support for changing the ratio
:ref:`OPAL_PERMISSION`
  Hardware cannot take the request
:ref:`OPAL_ASYNC_COMPLETION`
  Request was sent and an async completion message will be sent with
  token and status of the request.
:ref:`OPAL_HARDWARE`
  Unable to procced due to the current hardware state
:ref:`OPAL_BUSY`
  Previous request in progress
:ref:`OPAL_INTERNAL_ERROR`
  Error in request response
:ref:`OPAL_TIMEOUT`
  Timeout in request completion
