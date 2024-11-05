.. _device-tree/ibm,opal/power-mgt/powercap:

power-mgt/powercap
------------------

The powercap sensors are populated in this node. Each child node in
the "powercap" node represents a power-cappable component.

For example : ::

        system-powercap/

The :ref:`OPAL_GET_POWERCAP` and :ref:`OPAL_SET_POWERCAP` calls take a handle for
what powercap property to get/set which is defined in the child node.

The compatible property for the linux driver which will be
"ibm,opal-powercap"

Each child node has below properties:

`powercap-current`
  Handle to indicate the current powercap

`powercap-min`
  Absolute minimum possible powercap. This points to the soft powercap minimum
  limit as exported by OCC. The powercap set in the soft powercap range may or
  may not be maintained.

`powercap-max`
  Maximum possible powercap

`powercap-hard-min`
  This value points to the hard minimum powercap limit. The powercap set above
  this limit is guaranteed unless there is a hardware failure

Powercap handle uses the following encoding: ::

        | Class |    Reserved   | Attribute |
        |-------|---------------|-----------|

Note: The format of the powercap handle is ``NOT`` ABI and may change in
the future.

.. code-block:: dts

   power-mgt {
     powercap {
        compatible = "ibm,opal-powercap";

        system-powercap {
                name = "system-powercap";
                powercap-current = <0x00000002>;
                powercap-min = <0x00000000>;
                powercap-max = <0x00000001>;
                powercap-hard-min = <0x000000003>;
        };
     };
    };
