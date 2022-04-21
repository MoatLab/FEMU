.. _OPAL_XSCOM_READ:

OPAL_XSCOM_READ
===============

.. code-block:: c

   #define OPAL_XSCOM_READ				65

   int xscom_read(uint32_t partid, uint64_t pcb_addr, uint64_t *val);

This low level call will read XSCOM values directly.

They should only be used by low level manufacturing/debug tools.
"Normal" host OS kernel code should not know about XSCOM.

This is also needed by HBRT/`opal-prd`.

Returns
-------

:ref:`OPAL_SUCCESS`
   Success!
:ref:`OPAL_HARDWARE`
   if operation failed
:ref:`OPAL_WRONG_STATE`
   if CPU is asleep
:ref:`OPAL_XSCOM_BUSY`
   Alias for :ref:`OPAL_BUSY`.
:ref:`OPAL_XSCOM_CHIPLET_OFF`
   Alias for :ref:`OPAL_WRONG_STATE`
:ref:`OPAL_XSCOM_PARTIAL_GOOD`
   XSCOM Partial Good
:ref:`OPAL_XSCOM_ADDR_ERROR`
   XSCOM Address Error
:ref:`OPAL_XSCOM_CLOCK_ERROR`
   XSCOM Clock Error
:ref:`OPAL_XSCOM_PARITY_ERROR`
   XSCOM Parity Error
:ref:`OPAL_XSCOM_TIMEOUT`
   XSCOM Timeout
:ref:`OPAL_XSCOM_CTR_OFFLINED`
   XSCOM Controller Offlined due to too many errors.

.. _OPAL_XSCOM_WRITE:

OPAL_XSCOM_WRITE
================

.. code-block:: c

   #define OPAL_XSCOM_WRITE			66

   int xscom_write(uint32_t partid, uint64_t pcb_addr, uint64_t val);


This low level call will write an XSCOM value directly.

They should only be used by low level manufacturing/debug tools.
"Normal" host OS kernel code should not know about XSCOM.

This is also needed by HBRT/`opal-prd`.

Returns
-------

:ref:`OPAL_SUCCESS`
   Success!
:ref:`OPAL_HARDWARE`
   if operation failed
:ref:`OPAL_WRONG_STATE`
   if CPU is asleep
:ref:`OPAL_XSCOM_BUSY`
   Alias for :ref:`OPAL_BUSY`.
:ref:`OPAL_XSCOM_CHIPLET_OFF`
   Alias for :ref:`OPAL_WRONG_STATE`
:ref:`OPAL_XSCOM_PARTIAL_GOOD`
   XSCOM Partial Good
:ref:`OPAL_XSCOM_ADDR_ERROR`
   XSCOM Address Error
:ref:`OPAL_XSCOM_CLOCK_ERROR`
   XSCOM Clock Error
:ref:`OPAL_XSCOM_PARITY_ERROR`
   XSCOM Parity Error
:ref:`OPAL_XSCOM_TIMEOUT`
   XSCOM Timeout
:ref:`OPAL_XSCOM_CTR_OFFLINED`
   XSCOM Controller Offlined due to too many errors.
