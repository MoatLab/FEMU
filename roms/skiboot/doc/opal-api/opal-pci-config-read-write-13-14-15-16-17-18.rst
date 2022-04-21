
.. _OPAL_PCI_CONFIG:

============================
OPAL PCI Config Space Access
============================

PCI Config space is read or written to through OPAL calls. All of these calls

.. _OPAL_PCI_CONFIG_return_codes:

OPAL_PCI_CONFIG_* Return codes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

:ref:`OPAL_SUCCESS`
     Read/Write operation completed successfully.
:ref:`OPAL_PARAMETER`
     Invalid parameter. e.g. invalid `phb_id` or `bus_dev_func`.
:ref:`OPAL_HARDWARE`
     Invalid request for the hardware either permanently or in its
     current state. Can also be a hardware problem, e.g. fenced or
     config access is currently blocked.
:ref:`OPAL_UNSUPPORTED`
     Unsupported operation. For example, phb4 doesn't support ASB config
     space writes.
Other return codes
     Should be handled gracefully. For example, for any return code other than
     :ref:`OPAL_SUCCESS`, Linux will return all bits set for the specified size
     for a read, and will ignore the error on a write.

.. _OPAL_PCI_CONFIG_READ_BYTE:

OPAL_PCI_CONFIG_READ_BYTE
-------------------------

.. code-block:: c

   #define OPAL_PCI_CONFIG_READ_BYTE		13

   int64_t opal_pci_config_read_byte(uint64_t phb_id,
				     uint64_t bus_dev_func,
				     uint64_t offset,
				     uint8_t *data);

Reads a single byte from PCI config space,
see :ref:`OPAL_PCI_CONFIG_return_codes`.

.. _OPAL_PCI_CONFIG_READ_HALF_WORD:

OPAL_PCI_CONFIG_READ_HALF_WORD
------------------------------

.. code-block:: c

   #define OPAL_PCI_CONFIG_READ_HALF_WORD  	14

   int64_t opal_pci_config_read_half_word(uint64_t phb_id,
                                          uint64_t bus_dev_func,
				          uint64_t offset,
				          uint16_t *data);

Reads a half word (16 bits) from PCI config space,
see :ref:`OPAL_PCI_CONFIG_return_codes`.

.. _OPAL_PCI_CONFIG_READ_WORD:

OPAL_PCI_CONFIG_READ_WORD
-------------------------

.. code-block:: c

   #define OPAL_PCI_CONFIG_READ_WORD		15

   int64_t opal_pci_config_read_word(uint64_t phb_id,
                                     uint64_t bus_dev_func,
				     uint64_t offset,
				     uint32_t *data);

Reads a word (32 bits) from PCI config space,
see :ref:`OPAL_PCI_CONFIG_return_codes`.

.. _OPAL_PCI_CONFIG_WRITE_BYTE:

OPAL_PCI_CONFIG_WRITE_BYTE
--------------------------

.. code-block:: c

   #define OPAL_PCI_CONFIG_WRITE_BYTE		16

   int64_t opal_pci_config_write_byte(uint64_t phb_id,
				      uint64_t bus_dev_func,
				      uint64_t offset,
				      uint8_t data);

Writes a byte (8 bits) to PCI config space,
see :ref:`OPAL_PCI_CONFIG_return_codes`.

.. _OPAL_PCI_CONFIG_WRITE_HALF_WORD:

OPAL_PCI_CONFIG_WRITE_HALF_WORD
-------------------------------

.. code-block:: c

   #define OPAL_PCI_CONFIG_WRITE_HALF_WORD		17

   int64_t opal_pci_config_read_half_word(uint64_t phb_id,
                                          uint64_t bus_dev_func,
				          uint64_t offset,
				          uint16_t data);

Writes a half word (16 bits) to PCI config space,
see :ref:`OPAL_PCI_CONFIG_return_codes`.

.. _OPAL_PCI_CONFIG_WRITE_WORD:

OPAL_PCI_CONFIG_WRITE_WORD
--------------------------

.. code-block:: c

   #define OPAL_PCI_CONFIG_WRITE_WORD		18

   int64_t opal_pci_config_read_word(uint64_t phb_id,
                                     uint64_t bus_dev_func,
				     uint64_t offset,
				     uint32_t data);

Writes a word (32 bits) to PCI config space,
see :ref:`OPAL_PCI_CONFIG_return_codes`.

