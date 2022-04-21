.. _OPAL_CHECK_ASYNC_COMPLETION:

OPAL_CHECK_ASYNC_COMPLETION
===========================

:ref:`OPAL_CHECK_ASYNC_COMPLETION` checks if an async OPAL pending message was
completed. (see :ref:`opal-messages`).

.. code-block:: c

   #define OPAL_CHECK_ASYNC_COMPLETION		86

   int64_t opal_check_completion(uint64_t *buffer, uint64_t size, uint64_t token);

Parameters:

buffer
  buffer to copy message into
size
  sizeof buffer to copy message into
token
  async message token

Currently unused by Linux, but it is used by FreeBSD.


Return values
-------------

:ref:`OPAL_PARAMETER`
  buffer parameter is an invalid pointer (NULL or > top of RAM).
:ref:`OPAL_SUCCESS`
  message successfully copied to buffer.
:ref:`OPAL_BUSY`
  message is still pending and should be re-checked later.
