.. _OPAL_TEST:

OPAL_TEST
=========

:ref:`OPAL_TEST` is a REQUIRED call for OPAL and conforming implementations MUST
have it.

It is designed to test basic OPAL call functionality.

Token:

.. code-block:: c

  #define OPAL_TEST				0

Arguments
---------
::

   uint64_t	arg

Returns
-------
::

	0xfeedf00d


Function
--------
:ref:`OPAL_TEST` MAY print a string to the OPAL log with the value of argument.

For example, the reference implementation (skiboot) implements :ref:`OPAL_TEST` as:

.. code-block:: c

  static uint64_t opal_test_func(uint64_t arg)
  {
        printf("OPAL: Test function called with arg 0x%llx\n", arg);

        return 0xfeedf00d;
  }

