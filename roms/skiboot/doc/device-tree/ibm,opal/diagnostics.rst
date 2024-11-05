ibm,opal/diagnostics device tree entries
========================================

The diagnostics node under ibm,opal describes a userspace-to-firmware
interface, supporting the runtime processor recovery diagnostics functions.

**Note:** Some systemd init scripts look for the presence of the path
``/ibm,opal/diagnostics`` in order to run the opal-prd daemon.

The properties of a prd node are:

.. code-block:: dts

   / {
      ibm,opal {
        diagnostics {
          compatible = "ibm,opal-prd";
      };
     };
   };

