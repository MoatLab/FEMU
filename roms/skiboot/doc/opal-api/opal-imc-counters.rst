.. _opal-imc-counters:

.. _OPAL_IMC_COUNTERS_INIT:

OPAL_IMC_COUNTERS_INIT
======================
OPAL call interface to initialize In-memory collection
infrastructure. Call does multiple scom writes on each
invocation for Core/Trace IMC initialization. And for the
Nest IMC, at this point, call is a no-op and returns
OPAL_SUCCESS. Incase of kexec, OS driver should first
stop the engine via OPAL_IMC_COUNTER_STOP(and then
free the memory if allocated, for nest memory is
mmapped). Incase of kdump, OS driver should stop
the engine via OPAL_IMC_COUNTER_STOP.

OPAL does sanity checks to detect unknown or
unsupported IMC device type and nest units.
check_imc_device_type() function removes
unsupported IMC device type. disable_unavailable_units()
removes unsupported nest units by the microcode.
This way OPAL can lock down and advertise only
supported device type and nest units.

Parameters
----------
``uint32_t type``
  This parameter specifies the imc counter domain.
  The value can be 'OPAL_IMC_COUNTERS_NEST', 'OPAL_IMC_COUNTERS_CORE'
  or 'OPAL_IMC_COUNTERS_TRACE'.

``uint64_t addr``
  This parameter must have a non-zero value.
  This value must be a physical address of the core.

``uint64_t cpu_pir``
  This parameter specifices target cpu pir

Returns
-------

:ref:`OPAL_PARAMETER`
  In case of  unsupported ``type``
:ref:`OPAL_HARDWARE`
  If any error in setting up the hardware.
:ref:`OPAL_SUCCESS`
  On succesfully initialized or even if init operation is a no-op.

.. _OPAL_IMC_COUNTERS_START:

OPAL_IMC_COUNTERS_START
=======================
OPAL call interface for starting the In-Memory Collection
counters for a specified domain (NEST/CORE/TRACE).

Parameters
----------
``uint32_t type``
 This parameter specifies the imc counter domain.
 The value can be 'OPAL_IMC_COUNTERS_NEST',
 'OPAL_IMC_COUNTERS_CORE' or 'OPAL_IMC_COUNTERS_TRACE'.

``uint64_t cpu_pir``
  This parameter specifices target cpu pir

Returns
-------

:ref:`OPAL_PARAMETER`
  In case of  Unsupported ``type``
:ref:`OPAL_HARDWARE`
  If any error in setting up the hardware.
:ref:`OPAL_SUCCESS`
  On successful execution of the operation for the given ``type``.

.. _OPAL_IMC_COUNTERS_STOP:

OPAL_IMC_COUNTERS_STOP
======================
OPAL call interface for stoping In-Memory
Collection counters for a specified domain (NEST/CORE/TRACE).
STOP should always be called after a related START.
While STOP *may* run successfully without an associated
START call, this is not gaurenteed.

Parameters
----------
``uint32_t type``
 This parameter specifies the imc counter domain.
 The value can be 'OPAL_IMC_COUNTERS_NEST',
 'OPAL_IMC_COUNTERS_CORE' or 'OPAL_IMC_COUNTERS_TRACE'

``uint64_t cpu_pir``
  This parameter specifices target cpu pir

Returns
-------

:ref:`OPAL_PARAMETER`
  In case of  Unsupported ``type``
:ref:`OPAL_HARDWARE`
  If any error in setting up the hardware.
:ref:`OPAL_SUCCESS`
  On successful execution of the operation for the given ``type``.
