.. _OPAL_INT_SET_CPPR:

OPAL_INT_SET_CPPR
=================

.. code-block:: c

   #define	OPAL_INT_SET_CPPR			123

   static int64_t opal_int_set_cppr(uint8_t cppr);

Modelled on the ``H_CPPR`` PAPR call.

For P9 and above systems where host doesn't know about interrupt controller.
An OS can instead make OPAL calls for XICS emulation.

For an OS to use this OPAL call, an ``ibm,opal-intc`` compatible device must
exist in the device tree (see :ref:`xive-device-tree`). If OPAL does not create
such a device, the host OS MUST NOT use this call.
