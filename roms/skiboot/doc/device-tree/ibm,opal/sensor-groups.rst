.. _device-tree/ibm,opal/sensor-groups:

ibm,opal/sensor-groups
----------------------

This node contains all sensor groups defined in the system.
Each child node here represents a sensor group.

For example : ::
        occ-csm@1c00020/

The compatible property is set to "ibm,opal-sensor-group"

Each child node has below properties:

`type`
  string to indicate the sensor group

`sensor-group-id`
  Uniquely identifies a sensor group.

`ibm,chip-id`
  This property is added if the sensor group is chip specific

`sensors`
  Phandles of all sensors belonging to this sensor group

`ops`
  Array of opal call numbers to indicate the available sensor group
  operations

.. code-block:: dts

   ibm,opal {
     sensor-groups {
        compatible = "ibm,opal-sensor-group";

        occ-csm@1c00020 {
                name = "occ-csm";
                type = "csm";
                sensor-group-id = <0x01c00020>;
                ibm,chip-id = <0x00000008>;
                ops = <0x9c>;
                sensors = <0x00000175 0x00000176 0x00000177 0x00000178 0x00000179 0x0000017a 0x0000017b 0x0000017c>;
        };
     };
    };
