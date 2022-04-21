.. _OPAL_PHB_SET_OPTION:

OPAL_PHB_SET_OPTION
===================

.. code-block:: c

   #define OPAL_PHB_SET_OPTION			179

   int64_t opal_phb_set_option(uint64_t phb_id, uint64_t opt, uint64_t setting);


This call translate an PHB option to a PHB flag for specific PHB model and
writes it to the hardware.

Supported options are:

.. code-block:: c

   enum OpalPhbOption {
        OPAL_PHB_OPTION_TVE1_4GB = 0x1,
        OPAL_PHB_OPTION_MMIO_EEH_DISABLE = 0x2
   };

OPAL_PHB_OPTION_TVE1_4GB: If set, uses TVE#1 for DMA access above 4GB; allowed setting 0 or 1.

OPAL_PHB_OPTION_MMIO_EEH_DISABLE: Disables EEH for all MMIO commands; allowed setting 0 or 1.

Returns
-------

:ref:`OPAL_SUCCESS`
   Success
:ref:`OPAL_UNSUPPORTED`
   if either the call or the option is not supported
:ref:`OPAL_PARAMETER`
   if PHB is unknown or a new setting is out of range

.. _OPAL_PHB_GET_OPTION:

OPAL_PHB_GET_OPTION
===================

.. code-block:: c

   #define OPAL_PHB_GET_OPTION				180

   int64_t opal_phb_get_option(uint64_t phb_id, uint64_t opt, uint64_t *setting);

This call reads the hardware specific PHB flag and translates to a PHB option.

For the list of supported options refer to OPAL_PHB_SET_OPTION above.

Returns
-------

:ref:`OPAL_SUCCESS`
   Success
:ref:`OPAL_UNSUPPORTED`
   if either the call or the option is not supported
:ref:`OPAL_PARAMETER`
   if PHB is unknown or a new setting is out of range or no memory
   allocated for the return value
