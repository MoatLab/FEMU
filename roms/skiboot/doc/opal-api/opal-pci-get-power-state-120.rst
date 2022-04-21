.. _OPAL_PCI_GET_POWER_STATE:

OPAL_PCI_GET_POWER_STATE
========================

.. code-block:: c

   #define OPAL_PCI_GET_POWER_STATE		120

   int64_t opal_pci_get_power_state(uint64_t id, uint64_t data);

Get PCI slot power state

Parameter
---------

``uint64_t id``
  PCI slot ID

``uint64_t data``
  memory buffer pointer for power state

Calling
-------

Retrieve PCI slot's power state. The retrieved power state is stored
in buffer pointed by @data.

Return Codes
------------

:ref:`OPAL_SUCCESS`
  PCI slot's power state is retrieved successfully
:ref:`OPAL_PARAMETER`
  The indicated PCI slot isn't found
:ref:`OPAL_UNSUPPORTED`
  Power state retrieval not supported on the PCI slot
