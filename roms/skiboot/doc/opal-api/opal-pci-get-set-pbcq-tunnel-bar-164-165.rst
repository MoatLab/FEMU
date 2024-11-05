.. _OPAL_PCI_GET_PBCQ_TUNNEL_BAR:

OPAL_PCI_GET_PBCQ_TUNNEL_BAR
============================

.. code-block:: c

   #define OPAL_PCI_GET_PBCQ_TUNNEL_BAR 164

   int64_t opal_pci_get_pbcq_tunnel_bar(uint64_t phb_id, uint64_t *addr);

The host calls this function to read the address out of the PBCQ Tunnel
Bar register.

Parameters
----------

``phb_id``
  The value from the PHB node ibm,opal-phbid property for the device.

``addr``
  A pointer to where the address stored in the PBCQ Tunnel Bar register
  will be copied.

Return Values
-------------

:ref:`OPAL_SUCCESS`
  Operation was successful
:ref:`OPAL_PARAMETER`
  Invalid PHB or addr parameter
:ref:`OPAL_UNSUPPORTED`
  Not supported by hardware

.. _OPAL_PCI_SET_PBCQ_TUNNEL_BAR:

OPAL_PCI_SET_PBCQ_TUNNEL_BAR
============================

.. code-block:: c

   #define OPAL_PCI_SET_PBCQ_TUNNEL_BAR 165

   int64_t opal_pci_set_pbcq_tunnel_bar(uint64_t phb_id, uint64_t addr);

The host calls this function to set the PBCQ Tunnel Bar register.

Parameters
----------

`phb_id`
  The value from the PHB node ibm,opal-phbid property for the device.

`addr`
  The value of the address chosen for the PBCQ Tunnel Bar register.
  If the address is 0, then the PBCQ Tunnel Bar register will be reset.
  It the address is non-zero, then the PBCQ Tunnel Bar register will be
  set with ::

   Bit[0:42]      Bit[8:50] of the address

Return Values
-------------

:ref:`OPAL_SUCCESS`
  Operation was successful
:ref:`OPAL_PARAMETER`
  Invalid PHB or addr parameter
:ref:`OPAL_UNSUPPORTED`
  Not supported by hardware
