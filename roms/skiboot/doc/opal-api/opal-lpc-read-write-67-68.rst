.. _OPAL_LPC_READ:

OPAL_LPC_READ
=============

.. code-block:: c

   #define OPAL_LPC_READ				67

   /*
    * Address cycle types for LPC accesses. These also correspond
    * to the content of the first cell of the "reg" property for
    * device nodes on the LPC bus
    */
    enum OpalLPCAddressType {
      OPAL_LPC_MEM	= 0,
      OPAL_LPC_IO	= 1,
      OPAL_LPC_FW	= 2,
   };

   int64_t opal_lpc_read(uint32_t chip_id, enum OpalLPCAddressType addr_type,
			     uint32_t addr, uint32_t *data, uint32_t sz);

This function related to Low Pin Count (LPC) bus. This function reads the
data from IDSEL register for ``chip_id``, which has LPC information.
From ``addr`` for ``addr_type`` with read size ``sz`` bytes in to a
variable named ``data``.

Parameters
----------

``chip_id``
  The ``chip_id`` parameter contains value of the chip number identified at
  boot time.
``addr_type``
  The ``addr_type`` is one of the LPC supported address types.
  Supported address types are:

  - LPC memory,
  - LPC IO and
  - LPC firmware.

``addr``
  The ``addr`` from which the data has to be read.
``data``
  The ``data`` will be used to store the read data.
``sz``
   How many ``sz`` bytes to be read in to ``data``.

Return Codes
------------

:ref:`OPAL_PARAMETER`
   Indicates either ``chip_id`` not found or ``chip_id`` doesn’t contain
   LPC information.
:ref:`OPAL_SUCCESS`
  Indicates Success!

.. _OPAL_LPC_WRITE:

OPAL_LPC_WRITE
==============

.. code-block:: c

   #define OPAL_LPC_WRITE				68

   /*
    * Address cycle types for LPC accesses. These also correspond
    * to the content of the first cell of the "reg" property for
    * device nodes on the LPC bus
    */
    enum OpalLPCAddressType {
      OPAL_LPC_MEM	= 0,
      OPAL_LPC_IO	= 1,
      OPAL_LPC_FW	= 2,
   };

   int64_t opal_lpc_write(uint32_t chip_id, enum OpalLPCAddressType addr_type,
                          uint32_t addr, uint32_t data, uint32_t sz);

This function related to Low Pin Count (LPC) bus. This function writes the
``data`` in to  ECCB register for ``chip_id``, which has LPC information.
From ``addr`` for ``addr_type`` with write size ``sz`` bytes.

Parameters
----------

``chip_id``
  The ``chip_id`` parameter contains value of the chip number identified at
  boot time.
``addr_type``
  The ``addr_type`` is one of the address types LPC supported.
  Supported address types are:

  - LPC memory,
  - LPC IO and
  - LPC firmware.

``addr``
  The ``addr`` to where the ``data`` need to be written.
``data``
  The ``data`` for writing.
``sz``
   How many ``sz`` bytes to write.

Return Codes
------------

:ref:`OPAL_PARAMETER`
   Indicates either ``chip_id`` not found or ``chip_id`` doesn’t contain LPC
   information.
:ref:`OPAL_SUCCESS`
   Indicates Success!
