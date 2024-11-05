reserved-memory device tree nodes
=================================

OPAL exposes reserved memory through a top-level reserved-memory node,
containing subnodes that represent each reserved memory region.

This follows the Linux specification for the /reserved-memory node,
described in the kernel source tree, in:

  Documentation/devicetree/bindings/reserved-memory/reserved-memory.txt

The top-level /reserved-memory node contains: ::

  #size-cells = <2>
  #address-cells = <2>

Addresses and sizes are all 64-bits.

``ranges``
  the empty ranges node indicates no translation of physical
  addresses in the subnodes.

The sub-nodes under the /reserved-memory node contain:

``reg = <address size>``
  the address and size of the reserved memory region. The address
  and size values are two cells each, as signified by the top-level
  ``#{address,size}-cells``

``ibm,prd-label = "string"``
  a string token for use by the prd system. Specific ranges may be
  used by prd - those will be referenced by this label.
