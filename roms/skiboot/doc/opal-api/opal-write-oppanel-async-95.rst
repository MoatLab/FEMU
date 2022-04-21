.. _OPAL_WRITE_OPPANEL_ASYNC:

OPAL_WRITE_OPPANEL_ASYNC
========================

.. code-block:: c

   #define OPAL_WRITE_OPPANEL_ASYNC		95

   typedef struct oppanel_line {
	__be64 line;
	__be64 line_len;
   } oppanel_line_t;

   int64_t opal_write_oppanel_async(uint64_t async_token,
                                    oppanel_line_t *lines,
                                    uint64_t num_lines);

Writes to a (possibly physical) Operator Panel. An Operator Panel contains
a small LCD screen (or similar) displaying a small amount of ASCII text.
It can be used to report on boot progress, failure, or witty messages from
a systems administrator.

A typical panel, as present on IBM FSP based machines, is two lines of 16
characters each.

See :ref:`device-tree/ibm,opal/oppanel` for how the panel is described in the
device tree. Not all systems have an operator panel.

Pass in an array of oppanel_line_t structs defining the ASCII characters
to display on each line of the oppanel. If there are two lines on the
physical panel, and you only want to write to the first line, you only
need to pass in one line. If you only want to write to the second line,
you need to pass in both lines, and set the line_len of the first line
to zero.

Returns
-------
:ref:`OPAL_SUCCESS`
     Success! Typically this is async operation, so immediate success is
     unlikely.
:ref:`OPAL_ASYNC_COMPLETION`
     Request submitted asynchronously.
:ref:`OPAL_PARAMETER`
     Invalid `lines` or `num_lines`
:ref:`OPAL_NO_MEM`
     Not enough free memory in OPAL to complete the request.
:ref:`OPAL_INTERNAL_ERROR`
     Other internal error.
