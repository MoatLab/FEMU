.. _OPAL_INT_GET_XIRR:

OPAL_INT_GET_XIRR
=================

.. code-block:: c

   #define OPAL_INT_GET_XIRR			122

   int64_t opal_int_get_xirr(uint32_t *out_xirr, bool just_poll);

Modelled on the PAPR call.

For P9 and above systems where host doesn't know about interrupt controller.
An OS can instead make OPAL calls for XICS emulation.

For an OS to use this OPAL call, an ``ibm,opal-intc`` compatible device must
exist in the device tree (see :ref:`xive-device-tree`). If OPAL does not create
such a device, the host OS MUST NOT use this call.
