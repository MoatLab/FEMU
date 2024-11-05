.. _device-tree/ibm,opal/nvram:

nvram Device Tree Node
======================

.. code-block:: dts

  nvram {
        compatible = "ibm,opal-nvram";
	#bytes = <0x90000>;
  };

Indicates support (and size of) the :ref:`nvram` facility.
