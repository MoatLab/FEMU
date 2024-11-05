.. _OPAL_HANDLE_INTERRUPT:

OPAL_HANDLE_INTERRUPT
=====================

The host OS must pass all interrupts in the `opal-interrupts` property of :ref:`device-tree/ibm,opal` in the device tree to OPAL.

An example dt snippet is:

.. code-block:: dts

  ibm,opal {
            opal-interrupts = <0x10 0x11 0x12 0x13 0x14 0x20010 0x20011 0x20012 0x20013 0x20014 0xffe 0xfff 0x17fe 0x17ff 0x2ffe 0x2fff 0x37fe 0x37ff 0x20ffe 0x20fff 0x217fe 0x217ff 0x22ffe 0x22fff 0x237fe 0x237ff>;
  };

When the host OS gets any of these interrupts, it must call
``OPAL_HANDLE_INTERRUPT``.

The ``OPAL_HANDLE_INTERRUPT`` call takes two parameters, one input and one output.

``uint32_t isn``
  the interrupt

``uint64_t *outstanding_event_mask``
  returns outstanding events for host OS to handle

The host OS should then handle any outstanding events.

See :ref:`OPAL_POLL_EVENTS` for documentation on events.
