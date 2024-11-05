.. _opal_nx_coproc_init:

OPAL_NX_COPROC_INIT
===================

This OPAL call resets read offset and queued entries in high and normal
priority receive FIFO control registers. The kernel initializes read
offset entry in RXFIFO that it maintains during initialization. So this
register reset is needed for NX module reload or in kexec boot to make sure
read offset value matches with kernel entries. Otherwise NX reads requests
with wrong offset in RxFIFO which could cause NX request failures.

The kernel initiates this call for each coprocessor type such as 842 and
GZIP per NX instance.

Arguments
---------
::

  ``uint32_t chip_id``
    Contains value of the chip number identified at boot time.

  ``uint32_t pid``
    Contains NX coprocessor type (pid from the device tree).

Returns
-------
OPAL_SUCCESS
  The call to reset readOffset and queued entries for high and normal
  FIFOs was successful.

OPAL_PARAMETER
  Indicates invalid chip ID or NX coprocessor type.

OPAL_UNSUPPORTED
  Not supported on P7 and P8.
