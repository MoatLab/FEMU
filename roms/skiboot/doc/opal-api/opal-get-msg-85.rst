.. _OPAL_GET_MSG:

OPAL_GET_MSG
============

.. code-block:: c

   #define OPAL_GET_MSG				85

   int64_t opal_get_msg(uint64_t *buffer, uint64_t size);

:ref:`OPAL_GET_MSG` will get the next pending OPAL Message (see :ref:`opal-messages`).

The maximum size of an opal message is specified in the device tree passed
to the host OS: ::

  ibm,opal {
            opal-msg-size = <0x48>;
  }

It is ALWAYS at least 72 bytes. In the future, OPAL may have messages larger
than 72 bytes. Naturally, a HOST OS will only be able to interpret these
if it correctly uses opal-msg-size. Any OPAL message > 72 bytes, a host OS
may safely ignore.

A host OS *SHOULD* always supply a buffer to OPAL_GET_MSG of either 72
bytes or opal-msg-size. It MUST NOT supply a buffer of < 72 bytes.


Return values
-------------

:ref:`OPAL_RESOURCE`
  no available message.
:ref:`OPAL_PARAMETER`
  buffer is NULL or size is < 72 bytes.
  If buffer size < 72 bytes, the message will NOT be discarded by OPAL.
:ref:`OPAL_PARTIAL`
  If pending opal message is greater than supplied buffer.
  In this case the message is *DISCARDED* by OPAL.
  This is to keep compatibility with host Operating Systems
  with a hard coded opal-msg-size of 72 bytes.
  **NOT CURRENTLY IMPLEMENTED**. Specified so that host OS can
  prepare for the possible future with either a sensible
  error message or by gracefully ignoring such OPAL messages.
:ref:`OPAL_SUCCESS`
  message successfully copied to buffer.
