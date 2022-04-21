.. _nvram:

==========
OPAL NVRAM
==========

The NVRAM requirements for OPAL systems is derived from LoPAPR, and all
requirements listed in it apply to OPAL with some exceptions. Note that
Section 8.4.1.1.3 "OF Configuration Variables" does NOT apply to OPAL,
neither does 8.4.1.2 "DASD Spin-up Control". Not that the RTAS calls of
`nvram-fetch` and `nvram-store` are roughly equivalent to the
:ref:`OPAL_READ_NVRAM` and :ref:`OPAL_WRITE_NVRAM` calls.

LoPAPR has a minimum requirement of 8KB of Non-Volatile Memory. While this
requirement carries over, it's important to note that historically all OPAL
systems have had roughly 500kb of NVRAM.

See :ref:`device-tree/ibm,opal/nvram` for details on how NVRAM is represented
in the device tree. It's fairly simple, it looks like this:

.. code-block:: dts

  nvram {
        compatible = "ibm,opal-nvram";
	#bytes = <0x90000>;
  };


.. _OPAL_READ_NVRAM:

OPAL_READ_NVRAM
===============

.. code-block:: c

   #define OPAL_READ_NVRAM                         7

   int64_t opal_read_nvram(uint64_t buffer, uint64_t size, uint64_t offset);

:ref:`OPAL_READ_NVRAM` call requests OPAL to read the data from system NVRAM
memory into a memory buffer. The data at ``offset`` from nvram_image
will be copied to memory ``buffer`` of size ``size``.

This is a *synchronous* OPAL call, as OPAL will typically read the content of
NVRAM from its storage (typically flash) during boot, so the call duration
should be along the lines of a ``memcpy()`` operation rather than reading
from storage.


Parameters
----------
::

   uint64_t buffer
   uint64_t size
   uint64_t offset

``buffer``
   the data from nvram will be copied to ``buffer``

``size``
   the data of size ``size`` will be copied

``offset``
   the data will be copied from address equal to base ``nvram_image`` plus ``offset``

Return Values
-------------

:ref:`OPAL_SUCCESS`
  data from nvram to memory ``buffer`` copied successfully

:ref:`OPAL_PARAMETER`
  a parameter ``offset`` or ``size`` was incorrect

:ref:`OPAL_HARDWARE`
  either nvram is not initialized or permanent error related to nvram hardware.

.. _OPAL_WRITE_NVRAM:

OPAL_WRITE_NVRAM
================

.. code-block:: c

   #define OPAL_WRITE_NVRAM                        8

   int64_t opal_write_nvram(uint64_t buffer, uint64_t size, uint64_t offset);

:ref:`OPAL_WRITE_NVRAM` call requests OPAL to write the data to actual system NVRAM memory
from memory ``buffer`` at ``offset``, of size ``size``

Parameters
----------
::

   uint64_t buffer
   uint64_t size
   uint64_t offset

``buffer``
   data from ``buffer`` will be copied to nvram

``size``
   the data of size ``size`` will be copied

``offset``
   the data will be copied to address which is equal to base ``nvram_image`` plus ``offset``

Return Values
-------------

:ref:`OPAL_SUCCESS`
  data from memory ``buffer`` to actual nvram_image copied successfully

:ref:`OPAL_PARAMETER`
  a parameter ``offset`` or ``size`` was incorrect

:ref:`OPAL_HARDWARE`
  either nvram is not initialized or permanent error related to nvram hardware.

:ref:`OPAL_BUSY`
  OPAL is currently busy, retry the :ref:`OPAL_WRITE_NVRAM` call.

:ref:`OPAL_BUSY_EVENT`
  OPAL is currently busy, call :ref:`OPAL_POLL_EVENTS` and then retry :ref:`OPAL_WRITE_NVRAM`
