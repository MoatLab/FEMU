.. _device-tree/ibm,opal/oppanel:

Operator Panel (oppanel)
========================

.. code-block:: dts

  oppanel {
        compatible = "ibm,opal-oppanel";
        #lines = <0x2>;
        #length = <0x10>;
  };

The Operator Panel is a device for displaying small amounts of textual
data to an administrator. On IBM POWER8 systems with an FSP, this is a
small 16x2 LCD panel that can be viewed either from the Web UI of the FSP
(known as ASM) or by physically going to the machine and looking at the
panel.

The operator panel does not have to be present.

If it is, there are OPAL calls to read and write to it.

The device tree entry is so that the host OS knows the size of the panel
and can pass buffers of the appropriate size to the OPAL calls.
