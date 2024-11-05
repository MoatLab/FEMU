
=========================================
OPAL Timed Power On and Delayed Power Off
=========================================

.. code-block:: c

   #define OPAL_WRITE_TPO			103
   #define OPAL_READ_TPO			104
   #define OPAL_GET_DPO_STATUS			105

TPO is a Timed Power On facility, and DPO is Delayed Power Off.

It is an OPTIONAL part of the OPAL spec.

If a platform supports Timed Power On (TPO), the RTC node in the device tree
(itself under the "ibm,opal" node will have the has-tpo property:

.. code-block:: dts

  rtc {
     compatible = "ibm,opal-rtc";
     has-tpo;
  };

If the "has-tpo" proprety is *NOT* present then OPAL does *NOT* support TPO.

.. _OPAL_READ_TPO:

OPAL_READ_TPO
=============

.. code-block:: c

   #define OPAL_READ_TPO			104

   static int64_t opal_read_tpo(uint64_t async_token, uint32_t *y_m_d, uint32_t *hr_min);


.. _OPAL_WRITE_TPO:

OPAL_WRITE_TPO
==============

.. code-block:: c

   #define OPAL_WRITE_TPO			103

   int64_t fsp_opal_tpo_write(uint64_t async_token, uint32_t y_m_d, uint32_t hr_min);


.. _OPAL_GET_DPO_STATUS:

OPAL_GET_DPO_STATUS
===================

.. code-block:: c

   #define OPAL_GET_DPO_STATUS			105

   static int64_t opal_get_dpo_status(int64_t *dpo_timeout);

A :ref:`OPAL_MSG_DPO` message may be sent to indicate that there will shortly
be a forced system shutdown. In this case, an OS can call
:ref:`OPAL_GET_DPO_STATUS` to find out how many seconds it has before power
is cut to the system.

This call could be present on systems where the service processor is integrated
with a UPS or similar.

Returns zero if Delayed Power Off is not active, positive value indicating
number of seconds remaining for a forced system shutdown. This will enable
the host to schedule for shutdown voluntarily before timeout occurs.

Returns
-------

:ref:`OPAL_SUCCESS`
     ``dpo_timeout`` is set to the number of seconds remaining before power is
     cut.
:ref:`OPAL_WRONG_STATE`
     A Delayed Power Off is not pending, ``dpo_timeout`` is set to zero.
