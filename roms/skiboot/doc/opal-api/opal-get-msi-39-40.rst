===================================
OPAL_GET_MSI_32 and OPAL_GET_MSI_64
===================================

.. code-block:: c

   #define OPAL_GET_MSI_32				39
   #define OPAL_GET_MSI_64				40

   int64_t opal_get_msi_32(uint64_t phb_id, uint32_t mve_number,
                           uint32_t xive_num, uint8_t msi_range,
                           uint32_t *msi_address, uint32_t *message_data);

   int64_t opal_get_msi_64(uint64_t phb_id, uint32_t mve_number,
                           uint32_t xive_num, uint8_t msi_range,
                           uint64_t *msi_address, uint32_t *message_data);

.. _OPAL_GET_MSI_32:

OPAL_GET_MSI_32
===============

.. code-block:: c

   #define OPAL_GET_MSI_32				39

   int64_t opal_get_msi_32(uint64_t phb_id, uint32_t mve_number,
                           uint32_t xive_num, uint8_t msi_range,
                           uint32_t *msi_address, uint32_t *message_data);

See :ref:`OPAL_GET_MSI_64`.

.. _OPAL_GET_MSI_64:

OPAL_GET_MSI_64
===============

.. code-block:: c

   #define OPAL_GET_MSI_64				40

   int64_t opal_get_msi_64(uint64_t phb_id, uint32_t mve_number,
                           uint32_t xive_num, uint8_t msi_range,
                           uint64_t *msi_address, uint32_t *message_data);


**WARNING:** the following documentation is from old sources, and is possibly
not representative of OPALv3 as implemented by skiboot. This should be
used as a starting point for full documentation.

OPAL PHBs encode MVE and XIVE specifiers in MSI DMA and message data values.
The host calls these functions to determine the PHB MSI DMA address and message
data to program into a PE PCIE function for a particular MVE and XIVE. The
msi_address parameter returns the MSI DMA address and the msi_data parameter
returns the MSI DMA message data value the PE uses to signal that interrupt.

``phb_id``
  The ``phb_id`` parameter is the value from the PHB node ``ibm,opal-phbid``
  property.

``mve_number``
  The ``mve_number`` is the index of an MVE used to authorize this PE to this
  MSI. For ``ibm,opal-ioda2`` PHBs, the MVE number argument is ignored.

``xive_number``
  The ``xive_number`` is the index of an XIVE that corresponds to a particular
  DMA address and message data value this PE will signal as an MSI ro MSI-X.

``msi_range``
  The msi_range parameter specifies the number of MSIs associated with the
  in put MVE and XIVE, primarily for MSI-conventional Multiple Message
  Enable > 1 MSI. MSI requires consecutive MSIs per MSI address, and each
  MSI DMA address must be unique for any given consecutive power of 2 set
  of 32 message data values,. which in turn select particular PHB XIVEs.
  This value must be a power of 2 value in the range of 0 to 32. OPAL
  returns :ref:`OPAL_PARAMETER` for values outside of this range.

For MSI conventional, the MSI address and message data returned apply to a
power of 2 sequential set of XIVRs starting from the xive_number for the
power of 2 msi_range input argument. The message data returned represents the
power of 2 aligned starting message data value of the first interrupt number
in that sequential range. Valid msi_range input values are from 1 to 32.
Non-power of 2 values result in a return code of :ref:`OPAL_PARAMETER`.

An msi_range value of 0 or 1 signifies that OPAL should return the message
data and message address for exactly one MSI specified by the input XIVE
number. For MSI conventional, the host should specify either a value of 0 or 1,
for an MSI Capability MME value of 1 MSI. For MSI-X XIVRs, the host should
specify a value of '1' for the msi_range argument and call this function for
each MSI-X uniquely.
