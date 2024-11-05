OPAL Console calls
==================

There are four OPAL calls relating to the OPAL console:

+---------------------------------------------+--------------+------------------------+----------+-----------------+
| Name                                        | API Token ID | Introduced             | Required | Notes           |
|                                             |              |                        | as of    |                 |
+---------------------------------------------+--------------+------------------------+----------+-----------------+
| :ref:`OPAL_CONSOLE_WRITE`                   |   1          | v1.0 (Initial Release) | POWER8   |                 |
+---------------------------------------------+--------------+------------------------+----------+-----------------+
| :ref:`OPAL_CONSOLE_READ`                    |   2          | v1.0 (Initial Release) | POWER8   |                 |
+---------------------------------------------+--------------+------------------------+----------+-----------------+
| :ref:`OPAL_CONSOLE_WRITE_BUFFER_SPACE`      |  25          | v1.0 (Initial Release) | POWER8   |                 |
+---------------------------------------------+--------------+------------------------+----------+-----------------+
| :ref:`OPAL_CONSOLE_FLUSH`                   | 117          | :ref:`skiboot-5.1.13`  | POWER9   |                 |
+---------------------------------------------+--------------+------------------------+----------+-----------------+

The OPAL console calls can support multiple consoles. Each console MUST
be represented in the device tree.

A conforming implementation SHOULD have at least one console. It is valid
for it to simply be an in-memory buffer and only support writing.

[TODO: details on device tree specs for console]

.. _OPAL_CONSOLE_WRITE:

OPAL_CONSOLE_WRITE
------------------

Parameters: ::

  int64_t term_number
  int64_t *length,
  const uint8_t *buffer

Returns:

 - :ref:`OPAL_SUCCESS`
 - :ref:`OPAL_PARAMETER` on invalid term_number
 - :ref:`OPAL_CLOSED` if console device closed
 - :ref:`OPAL_BUSY_EVENT` if unable to write any of buffer

``term_number`` is the terminal number as represented in the device tree.
``length`` is a pointer to the length of buffer.

A conforming implementation SHOULD try to NOT do partial writes, although
partial writes and not writing anything are valid.

.. _OPAL_CONSOLE_WRITE_BUFFER_SPACE:

OPAL_CONSOLE_WRITE_BUFFER_SPACE
-------------------------------

Parameters: ::

  int64_t term_number
  int64_t *length

Returns:

 - :ref:`OPAL_SUCCESS`
 - :ref:`OPAL_PARAMETER` on invalid term_number

Returns the available buffer length for OPAL_CONSOLE_WRITE in ``length``.
This call can be used to help work out if there is sufficient buffer
space to write your full message to the console with OPAL_CONSOLE_WRITE.

.. _OPAL_CONSOLE_READ:

OPAL_CONSOLE_READ
-----------------

Parameters: ::

  int64_t term_number
  int64_t *length
  uint8_t *buffer

Returns:

 - :ref:`OPAL_SUCCESS`
 - :ref:`OPAL_PARAMETER` on invalid term_number
 - :ref:`OPAL_CLOSED`

Use :ref:`OPAL_POLL_EVENTS` for how to determine

.. _OPAL_CONSOLE_FLUSH:

OPAL_CONSOLE_FLUSH
------------------

Parameters: ::

  int64_t term_number

Returns:

 - :ref:`OPAL_SUCCESS`
 - :ref:`OPAL_UNSUPPORTED` if the console does not implement a flush call
 - :ref:`OPAL_PARAMETER` on invalid term_number
 - :ref:`OPAL_PARTIAL` if more to flush, call again
 - :ref:`OPAL_BUSY` if nothing was flushed this call
