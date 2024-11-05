.. _opal-api-mpipl:

OPAL MPIPL APIs
===============

.. code-block:: c

   #define OPAL_MPIPL_UPDATE                      173
   #define OPAL_MPIPL_REGISTER_TAG                174
   #define OPAL_MPIPL_QUERY_TAG                   175

These calls are used for MPIPL (Memory Preserving Initial Program Load).

It is an OPTIONAL part of the OPAL spec.

If a platform supports MPIPL, then we will have "/ibm,opal/dump" node in
device tree (see :ref:`device-tree/ibm,opal/dump`).

.. _OPAL_MPIPL_UPDATE:

OPAL_MPIPL_UPDATE
==================
Linux kernel will use this call to register/unregister MPIPL.

.. code-block:: c

   #define OPAL_MPIPL_UPDATE                      173

   int64_t opal_mpipl_update(enum mpipl_ops ops, u64 src, u64 dest, u64 size)

   /* MPIPL update operations */
   enum mpipl_ops {
        OPAL_MPIPL_ADD_RANGE            = 0,
        OPAL_MPIPL_REMOVE_RANGE         = 1,
        OPAL_MPIPL_REMOVE_ALL           = 2,
        OPAL_MPIPL_FREE_PRESERVED_MEMORY= 3,
   };

ops :
-----
  OPAL_MPIPL_ADD_RANGE
    Add new entry to MPIPL table. Kernel will send src, dest and size.
    During MPIPL content from source address is moved to destination address.
    src  = Source start address
    dest = Destination start address
    size = size

  OPAL_MPIPL_REMOVE_RANGE
    Remove kernel requested entry from MPIPL table.
    src  = Source start address
    dest = Destination start address
    size = ignore

  OPAL_MPIPL_REMOVE_ALL
    Remove all kernel passed entry from MPIPL table.
    src  = ignore
    dest = ignore
    size = ignore

  OPAL_MPIPL_FREE_PRESERVED_MEMORY
    Post MPIPL, kernel will indicate OPAL that it has processed dump and
    it can clear/release metadata area.
    src  = ignore
    dest = ignore
    size = ignore

Return Values
-------------

``OPAL_SUCCESS``
  Operation success

``OPAL_PARAMETER``
  Invalid parameter

``OPAL_RESOURCE``
  Ran out of space in MDST/MDDT table to add new entry

``OPAL_HARDWARE``
  Platform does not support fadump


.. _OPAL_MPIPL_REGISTER_TAG:

OPAL_MPIPL_REGISTER_TAG
=======================
Kernel will use this API to register tags during MPIPL registration.
It expects OPAL to preserve these tags across MPIPL. Post MPIPL Linux
kernel will use `opal_mpipl_query_tag` call to retrieve these tags.

.. code-block:: c

  opal_mpipl_register_tag(enum opal_mpipl_tags tag, uint64_t tag_val)

  tag:
   OPAL_MPIPL_TAG_KERNEL
     During first boot, kernel will setup its metadata area and asks
     OPAL to preserve metadata area pointer across MPIPL. Post MPIPL
     kernel requests OPAL to provide metadata pointer and it will use
     that pointer to retrieve metadata and create dump.

   OPAL_MPIPL_TAG_BOOT_MEM
     During MPIPL registration kernel will specify how much memory
     firmware can use for Post MPIPL load. Post MPIPL petitboot kernel
     will query for this tag to get boot memory size.

Return Values
-------------
``OPAL_SUCCESS``
  Operation success

``OPAL_PARAMETER``
  Invalid parameter

.. _OPAL_MPIPL_QUERY_TAG:

OPAL_MPIPL_QUERY_TAG
====================
Post MPIPL linux kernel will call this API to get metadata tag. And use this
tag to retrieve metadata information and generate dump.

.. code-block:: c

   #define OPAL_MPIPL_QUERY_TAG                 175

   uint64_t opal_mpipl_query_tag(enum opal_mpipl_tags tag, uint64_t *tag_val)

   enum opal_mpipl_tags {
        OPAL_MPIPL_TAG_CPU      = 0,
        OPAL_MPIPL_TAG_OPAL     = 1,
        OPAL_MPIPL_TAG_KERNEL   = 2,
        OPAL_MPIPL_TAG_BOOT_MEM = 3,
   };

  tag :
     OPAL_MPIPL_TAG_CPU
       Pointer to CPU register data content metadata area
     OPAL_MPIPL_TAG_OPAL
       Pointer to OPAL metadata area
     OPAL_MPIPL_TAG_KERNEL
       During first boot, kernel will setup its metadata area and asks
       OPAL to preserve metadata area pointer across MPIPL. Post MPIPL
       kernel calls this API to get metadata pointer and it will use
       that pointer to retrieve metadata and create dump.
     OPAL_MPIPL_TAG_BOOT_MEM
       During MPIPL registration kernel will specify how much memory
       firmware can use for Post MPIPL load. Post MPIPL petitboot kernel
       will query for this tag to get boot memory size.

Return Values
-------------

``OPAL_SUCCESS``
  Operation success

``OPAL_PARAMETER``
  Invalid parameter
