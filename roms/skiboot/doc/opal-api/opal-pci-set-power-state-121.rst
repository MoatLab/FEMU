.. _OPAL_PCI_SET_POWER_STATE:

OPAL_PCI_SET_POWER_STATE
========================

.. code-block:: c

   #define OPAL_PCI_SET_POWER_STATE		121

   int64_t opal_pci_set_power_state(uint64_t async_token, uint64_t id, uint64_t data);

Set PCI slot power state

Parameters
----------

``uint64_t async_token``
  Token of asynchronous message to be sent
  on completion of OPAL_PCI_SLOT_POWER_{OFF, ON}. It is
  ignored when @data is OPAL_PCI_SLOT_{OFFLINE, ONLINE}.

``uint64_t id``
  PCI slot ID

``uint64_t data``
  memory buffer pointer for the power state which
  can be one of OPAL_PCI_SLOT_POWER_{OFF, ON, OFFLINE, ONLINE}.

Calling
-------

Set PCI slot's power state. The power state is stored in buffer pointed
by @data. The typical use is to hot add or remove adapters behind the
indicated PCI slot (by @id) in PCI hotplug path.

User will receive an asychronous message after calling the API. The message
contains the API completion status: event (Power off or on), device node's
phandle identifying the PCI slot, errcode (e.g. :ref:`OPAL_SUCCESS`). The API returns
:ref:`OPAL_ASYNC_COMPLETION` for the case.

The states OPAL_PCI_SLOT_OFFLINE and OPAL_PCI_SLOT_ONLINE are used for removing
or adding devices behind the slot. The device nodes in the device tree are
removed or added accordingly, without actually changing the slot's power state.
The API call will return OPAL_SUCCESS immediately and no further asynchronous
message will be sent.

Return Codes
------------

:ref:`OPAL_SUCCESS`
  PCI hotplug on the slot is completed successfully
:ref:`OPAL_ASYNC_COMPLETION`
  PCI hotplug needs further message to confirm
:ref:`OPAL_PARAMETER`
  The indicated PCI slot isn't found
:ref:`OPAL_UNSUPPORTED`
  Setting power state not supported on the PCI slot
