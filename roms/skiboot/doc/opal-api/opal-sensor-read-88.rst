.. _OPAL_SENSOR_READ:

OPAL_SENSOR_READ
================

.. code-block:: c

   #define OPAL_SENSOR_READ			88

   int64_t opal_sensor_read(uint32_t sensor_hndl, int token, uint32_t *sensor_data);

The OPAL sensor call reads a sensor data using a unique handler to
identity the targeted sensor. The `sensor_handle` is provided
via the device tree and is opaque to the OS (although we currently
do use an encoding scheme).

This call can be asynchronous, when a message needs to be sent to a
service processor for example.  In this case, the call will return
OPAL_ASYNC_COMPLETION and the token parameter will be used to wait for
the completion of the request.

The OPAL API doesn't enforce alimit on the number of sensor calls that can
be in flight.

Internally, :ref:`OPAL_SENSOR_READ` is implemented as a wrapper around
:ref:`OPAL_SENSOR_READ_U64`. Any code targeting processor generations prior
to POWER9 will need to use :ref:`OPAL_CHECK_TOKEN` to ensure :ref:`OPAL_SENSOR_READ_U64`
is present and gracefully fall back to :ref:`OPAL_SENSOR_READ` if it is not.

Parameters
----------
::

	uint32_t sensor_handle
	int	 token
	uint32_t *sensor_data


Return values
-------------
:ref:`OPAL_SUCCESS`
  Success!
:ref:`OPAL_PARAMETER`
  invalid sensor handle
:ref:`OPAL_UNSUPPORTED`
  platform does not support reading sensors.
:ref:`OPAL_ASYNC_COMPLETION`
  a request was sent and an async completion will
  be triggered with the @token argument
:ref:`OPAL_PARTIAL`
  the request completed but the data returned is invalid
:ref:`OPAL_BUSY_EVENT`
  a previous request is still pending
:ref:`OPAL_NO_MEM`
  allocation failed
:ref:`OPAL_INTERNAL_ERROR`
  communication failure with the FSP
:ref:`OPAL_HARDWARE`
  FSP is not available

.. _OPAL_SENSOR_READ_U64:

OPAL_SENSOR_READ_U64
====================

.. code-block:: c

   #define OPAL_SENSOR_READ_U64			162

   s64 opal_sensor_read_u64(u32 sensor_hndl, int token, u64 *sensor_data);

The OPAL sensor call to read sensor data of type u64. Unlike
opal_sensor_read which reads upto u32 this call can be used to
read values of sensors upto 64bits. The calling conventions and
return values are same as :ref:`OPAL_SENSOR_READ`.

All sensors can be read through the :ref:`OPAL_SENSOR_READ_U64` call that
can be read using the :ref:`OPAL_SENSOR_READ` call. Internally,
:ref:`OPAL_SENSOR_READ` is a wrapper around :ref:`OPAL_SENSOR_READ_U64`.
Any code targeting processor generations prior to POWER9 will need to use
:ref:`OPAL_CHECK_TOKEN` to ensure :ref:`OPAL_SENSOR_READ_U64`
is present and gracefully fall back to :ref:`OPAL_SENSOR_READ` if it is not.
