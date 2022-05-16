.. _OPAL_GET_DEVICE_TREE:

OPAL_GET_DEVICE_TREE
====================

.. code-block:: c

   #define OPAL_GET_DEVICE_TREE			118

   int64_t opal_get_device_tree(uint32_t phandle, uint64_t buf, uint64_t len);

Get device sub-tree.

``uint32_t phandle``
  root device node phandle of the device sub-tree
``uint64_t buf``
  FDT blob buffer or NULL
``uint64_t len``
  length of the FDT blob buffer


Retrieve device sub-tree. The root node's phandle is identified by @phandle.
The typical use is for the kernel to update its device tree following a change
in hardware (e.g. PCI hotplug).

Return Codes
^^^^^^^^^^^^

FDT blob size
  returned FDT blob buffer size when ``buf`` is NULL

:ref:`OPAL_SUCCESS`
  FDT blob is created successfully
:ref:`OPAL_PARAMETER`
  invalid argument @phandle or @len
:ref:`OPAL_INTERNAL_ERROR`
  failure creating FDT blob when calculating its size
:ref:`OPAL_NO_MEM`
  not enough room in buffer for device sub-tree
:ref:`OPAL_EMPTY`
  failure creating FDT blob
