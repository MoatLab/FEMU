.. _opal-powercap:

===============
OPAL Power Caps
===============

Each entity that can be power capped is described in the device tree,
see :ref:`device-tree/ibm,opal/power-mgt/powercap`. The values for each
power cap aren't in the device tree, but rather fetched using the
:ref:`OPAL_GET_POWERCAP` OPAL call. This is because there may be other
entities such as a service processor that can change the nature of the
power cap asynchronously to OPAL.

.. _OPAL_GET_POWERCAP:

OPAL_GET_POWERCAP
=================
The OPAL_GET_POWERCAP call retreives current information on the power
cap.

For each entity that can be power capped, the device tree
binding indicates what handle should be passed for each of the power cap
properties (minimum possible, maximum possible, current powercap).

The current power cap must be between the minimium possible and maximum
possible power cap. The minimum and maximum values are dynamic to allow
for them possibly being changed by other factors or entities
(e.g. service processor).

The call can be asynchronus, where the token parameter is used to wait
for the completion.

Parameters
----------

=== ======
=== ======
u32 handle
int token
u32 \*pcap
=== ======

Returns
-------

:ref:`OPAL_SUCCESS`
  Success
:ref:`OPAL_PARAMETER`
  Invalid pcap pointer
:ref:`OPAL_UNSUPPORTED`
  No support for reading powercap sensor
:ref:`OPAL_HARDWARE`
  Unable to procced due to the current hardware state
:ref:`OPAL_ASYNC_COMPLETION`
  Request was sent and an async completion message will be sent with
  token and status of the request.

.. _OPAL_SET_POWERCAP:

OPAL_SET_POWERCAP
=================
The OPAL_SET_POWERCAP call sets a power cap.

For each entity that can be power capped, the device tree
binding indicates what handle should be passed for each of the power cap
properties (minimum possible, maximum possible, current powercap).

The current power cap must be between the minimium possible and maximum
possible power cap.

You cannot currently set the minimum or maximum power cap, and thus
OPAL_PERMISSION will be returned if it is attempted to set. In the
future, this may change - but for now, the correct behaviour for an
Operating System is to not attempt to set them.

Parameters
----------
::
        u32 handle
        int token
        u32 pcap

Returns
-------

:ref:`OPAL_SUCCESS`
  Success
:ref:`OPAL_PARAMETER`
  Invalid powercap requested beyond powercap limits
:ref:`OPAL_UNSUPPORTED`
  No support for changing the powercap
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
