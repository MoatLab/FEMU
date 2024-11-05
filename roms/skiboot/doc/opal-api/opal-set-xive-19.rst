.. _OPAL_SET_XIVE:

OPAL_SET_XIVE
=============

.. code-block:: c

   #define OPAL_SET_XIVE				19

   int64_t opal_set_xive(uint32_t isn, uint16_t server, uint8_t priority);

The host calls this function to set the server (target processor)
and priority parameters of an interrupt source.

This can be also used to mask or unmask the interrupt (by changing
the priority to 0xff one masks an interrupt).

WARNINGS:

 - For MSIs or generally edge sensitive interrupts, OPAL provides no
   guarantee as to whether the interrupt will be latched if it occurs
   while masked and replayed on unmask. It may or may not. The OS needs
   to be aware of this. The current implementation will *not* replay,
   neither on P8 nor on P9 XICS emulation.

 - When masking, there is no guarantee that the interrupt will not
   still occur after this call returns. The reason is that it might
   already be on its way past the source controller and latched into one
   of the presenters. There is however a guarantee that it won't replay
   indefinitely so it's acceptable for the OS to simply ignore it.

Parameters
----------

``isn``
  This is a global interrupt number as obtained from the device-tree
  "interrupts" or "interrupt-map" properties.

``server_number``
  is the mangled server (processor) that is to receive the
  interrupt request. The mangling means that the actual processor
  number is shifted left by 2 bits, the bottom bits representing
  the "link". However links aren't supported in OPAL so the bottom
  2 bits should be 0.

``priority``
  is the interrupt priority value applied to the interrupt
  (0=highest, 0xFF = lowest/disabled).


