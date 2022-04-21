.. _device-tree/ibm,opal/flash:

ibm,opal/flash device tree entries
==================================

The flash@<n> nodes under ibm,opal describe flash devices that can be
accessed through the OPAL_FLASH_{READ,ERASE,WRITE} interface.

These interfaces take an 'id' parameter, which corresponds to the ibm,opal-id
property of the node.

The properties under a flash node are:

- ``compatible = "ibm,opal-flash"``

``ibm,opal-id = <id>``
  provides the index used for the OPAL_FLASH_XXX calls to reference this
  flash device

``reg = <0 size>``
  the offset and size of the flash device

``ibm,flash-block-size``
  the read/write/erase block size for the flash interface. Calls
  to read/write/erase must be aligned to the block size.

``#address-cells = <1>``, ``#size-cells = <1>``
  flash devices are currently 32-bit addressable

If valid partitions are found on the flash device, then ``partition@<offset>``
sub-nodes are added to the flash node. These match the Linux binding for
flash partitions; the reg parameter contains the offset and size of the
partition.


Example:

.. code-block:: dts

 flash@0 {
   reg = <0x0 0x4000000>;
   compatible = "ibm,opal-flash";
   ibm,opal-id = <0x0>;
   ibm,flash-block-size = <0x1000>;
   #address-cells = <0x1>;
   phandle = <0x100002bf>;
   #size-cells = <0x1>;
 };
