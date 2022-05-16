OPAL API Return Codes
=====================

All OPAL calls return an integer relaying the success/failure of the OPAL
call.

Success is typically indicated by OPAL_SUCCESS. Failure is always indicated
by a negative return code.

Conforming host Operating Systems MUST handle return codes other than those
listed here. In future OPAL versions, additional return codes may be added.

In the reference implementation (skiboot) these are all in `include/opal-api.h`_

.. _include/opal-api.h: https://github.com/open-power/skiboot/blob/master/include/opal-api.h

There have been additions to the return codes from OPAL over time. A conforming
host OS should gracefully handle receiving a new error code for existing calls.

An OS running on a POWER8 system only has to know about error codes that existed
when POWER8 with OPAL was introduced (indicated by YES in the POWER8 column below).
Additional OPAL error codes *may be returned on POWER8 systems* and as such OSs
need to gracefully handle unknown error codes.

An OS running on POWER9 or above must handle all error codes as they were when
POWER9 was introduced. We use the placeholder "v1.0" version for
"since the dawn of time" even though there never was a skiboot v1.0

+--------------------------------+------------------+-----------+-----------+----------------------------------+
| Name                           | Return Code      | POWER8 GA | POWER9 GA | skiboot version where introduced |
+--------------------------------+------------------+-----------+-----------+----------------------------------+
| :ref:`OPAL_SUCCESS`            | 0                | YES       | YES       | v1.0 (initial release)           |
+--------------------------------+------------------+-----------+-----------+----------------------------------+
| :ref:`OPAL_PARAMETER`          | -1               | YES       | YES       | v1.0 (initial release)           |
+--------------------------------+------------------+-----------+-----------+----------------------------------+
| :ref:`OPAL_BUSY`               | -2               | YES       | YES       | v1.0 (initial release)           |
+--------------------------------+------------------+-----------+-----------+----------------------------------+
| :ref:`OPAL_PARTIAL`            | -3               | YES       | YES       | v1.0 (initial release)           |
+--------------------------------+------------------+-----------+-----------+----------------------------------+
| :ref:`OPAL_CONSTRAINED`        | -4               | YES       | YES       | v1.0 (initial release)           |
+--------------------------------+------------------+-----------+-----------+----------------------------------+
| :ref:`OPAL_CLOSED`             | -5               | YES       | YES       | v1.0 (initial release)           |
+--------------------------------+------------------+-----------+-----------+----------------------------------+
| :ref:`OPAL_HARDWARE`           | -6               | YES       | YES       | v1.0 (initial release)           |
+--------------------------------+------------------+-----------+-----------+----------------------------------+
| :ref:`OPAL_UNSUPPORTED`        | -7               | YES       | YES       | v1.0 (initial release)           |
+--------------------------------+------------------+-----------+-----------+----------------------------------+
| :ref:`OPAL_PERMISSION`         | -8               | YES       | YES       | v1.0 (initial release)           |
+--------------------------------+------------------+-----------+-----------+----------------------------------+
| :ref:`OPAL_NO_MEM`             | -9               | YES       | YES       | v1.0 (initial release)           |
+--------------------------------+------------------+-----------+-----------+----------------------------------+
| :ref:`OPAL_RESOURCE`           | -10              | YES       | YES       | v1.0 (initial release)           |
+--------------------------------+------------------+-----------+-----------+----------------------------------+
| :ref:`OPAL_INTERNAL_ERROR`     | -11              | YES       | YES       | v1.0 (initial release)           |
+--------------------------------+------------------+-----------+-----------+----------------------------------+
| :ref:`OPAL_BUSY_EVENT`         | -12              | YES       | YES       | v1.0 (initial release)           |
+--------------------------------+------------------+-----------+-----------+----------------------------------+
| :ref:`OPAL_HARDWARE_FROZEN`    | -13              | YES       | YES       | v1.0 (initial release)           |
+--------------------------------+------------------+-----------+-----------+----------------------------------+
| :ref:`OPAL_WRONG_STATE`        | -14              | YES       | YES       | v1.0 (initial release)           |
+--------------------------------+------------------+-----------+-----------+----------------------------------+
| :ref:`OPAL_ASYNC_COMPLETION`   | -15              | YES       | YES       | v1.0 (initial release)           |
+--------------------------------+------------------+-----------+-----------+----------------------------------+
| :ref:`OPAL_EMPTY`              | -16              | NO        | YES       | v4.0                             |
+--------------------------------+------------------+-----------+-----------+----------------------------------+
| :ref:`OPAL_I2C_TIMEOUT`        | -17              | NO        | YES       | :ref:`skiboot-5.1.0`             |
+--------------------------------+------------------+-----------+-----------+----------------------------------+
| :ref:`OPAL_I2C_INVALID_CMD`    | -18              | NO        | YES       | :ref:`skiboot-5.1.0`             |
+--------------------------------+------------------+-----------+-----------+----------------------------------+
| :ref:`OPAL_I2C_LBUS_PARITY`    | -19              | NO        | YES       | :ref:`skiboot-5.1.0`             |
+--------------------------------+------------------+-----------+-----------+----------------------------------+
| :ref:`OPAL_I2C_BKEND_OVERRUN`  | -20              | NO        | YES       | :ref:`skiboot-5.1.0`             |
+--------------------------------+------------------+-----------+-----------+----------------------------------+
| :ref:`OPAL_I2C_BKEND_ACCESS`   | -21              | NO        | YES       | :ref:`skiboot-5.1.0`             |
+--------------------------------+------------------+-----------+-----------+----------------------------------+
| :ref:`OPAL_I2C_ARBT_LOST`      | -22              | NO        | YES       | :ref:`skiboot-5.1.0`             |
+--------------------------------+------------------+-----------+-----------+----------------------------------+
| :ref:`OPAL_I2C_NACK_RCVD`      | -23              | NO        | YES       | :ref:`skiboot-5.1.0`             |
+--------------------------------+------------------+-----------+-----------+----------------------------------+
| :ref:`OPAL_I2C_STOP_ERR`       | -24              | NO        | YES       | :ref:`skiboot-5.1.0`             |
+--------------------------------+------------------+-----------+-----------+----------------------------------+
| :ref:`OPAL_XSCOM_BUSY`         | OPAL_BUSY        | NO        | YES       | :ref:`skiboot-5.4.0`             |
+--------------------------------+------------------+-----------+-----------+----------------------------------+
| :ref:`OPAL_XSCOM_CHIPLET_OFF`  | OPAL_WRONG_STATE | NO        | YES       | :ref:`skiboot-5.4.0`             |
+--------------------------------+------------------+-----------+-----------+----------------------------------+
| :ref:`OPAL_XSCOM_PARTIAL_GOOD` | -25              | NO        | YES       | :ref:`skiboot-5.4.0`             |
+--------------------------------+------------------+-----------+-----------+----------------------------------+
| :ref:`OPAL_XSCOM_ADDR_ERROR`   | -26              | NO        | YES       | :ref:`skiboot-5.4.0`             |
+--------------------------------+------------------+-----------+-----------+----------------------------------+
| :ref:`OPAL_XSCOM_CLOCK_ERROR`  | -27              | NO        | YES       | :ref:`skiboot-5.4.0`             |
+--------------------------------+------------------+-----------+-----------+----------------------------------+
| :ref:`OPAL_XSCOM_PARITY_ERROR` | -28              | NO        | YES       | :ref:`skiboot-5.4.0`             |
+--------------------------------+------------------+-----------+-----------+----------------------------------+
| :ref:`OPAL_XSCOM_TIMEOUT`      | -29              | NO        | YES       | :ref:`skiboot-5.4.0`             |
+--------------------------------+------------------+-----------+-----------+----------------------------------+
| :ref:`OPAL_XSCOM_CTR_OFFLINED` | -30              | NO        | YES       | :ref:`skiboot-5.4.0`             |
+--------------------------------+------------------+-----------+-----------+----------------------------------+
| :ref:`OPAL_XIVE_PROVISIONING`  | -31              | NO        | YES       | :ref:`skiboot-5.5.0`             |
+--------------------------------+------------------+-----------+-----------+----------------------------------+
| :ref:`OPAL_XIVE_FREE_ACTIVE`   | -32              | NO        | YES       | :ref:`skiboot-5.5.0`             |
+--------------------------------+------------------+-----------+-----------+----------------------------------+
| :ref:`OPAL_TIMEOUT`            | -33              | NO        | YES       | :ref:`skiboot-5.8`               |
+--------------------------------+------------------+-----------+-----------+----------------------------------+


The core set of return codes are:

.. _OPAL_SUCCESS:

OPAL_SUCCESS
------------
.. code-block:: c

 #define OPAL_SUCCESS		0

Success!

.. _OPAL_PARAMETER:

OPAL_PARAMETER
--------------
.. code-block:: c

 #define OPAL_PARAMETER		-1

A parameter was invalid. This will also be returned if you call an
invalid OPAL call. To determine if a specific OPAL call is supported
or not, OPAL_CHECK_TOKEN should be called rather than relying on
OPAL_PARAMETER being returned for an invalid token.

.. _OPAL_BUSY:

OPAL_BUSY
---------
.. code-block:: c

   #define OPAL_BUSY		-2

Try again later. Related to `OPAL_BUSY_EVENT`, but `OPAL_BUSY` indicates that the
caller need not call `OPAL_POLL_EVENTS` itself. **TODO** Clarify current situation.

.. _OPAL_PARTIAL:

OPAL_PARTIAL
------------
.. code-block:: c

   #define OPAL_PARTIAL		-3

The operation partially succeeded.

.. _OPAL_CONSTRAINED:

OPAL_CONSTRAINED
----------------
.. code-block:: c

   #define OPAL_CONSTRAINED	-4

**FIXME**

.. _OPAL_CLOSED:

OPAL_CLOSED
-----------
.. code-block:: c

   #define OPAL_CLOSED		-5

**FIXME** document these

.. _OPAL_HARDWARE:

OPAL_HARDWARE
-------------
.. code-block:: c

   #define OPAL_HARDWARE		-6

**FIXME** document these

.. _OPAL_UNSUPPORTED:

OPAL_UNSUPPORTED
----------------
.. code-block:: c

   #define OPAL_UNSUPPORTED	-7

Unsupported operation. Non-fatal.

.. _OPAL_PERMISSION:

OPAL_PERMISSION
---------------
.. code-block:: c

   #define OPAL_PERMISSION		-8

Inadequate permission to perform the operation.

.. _OPAL_NO_MEM:

OPAL_NO_MEM
-----------
.. code-block:: c

   #define OPAL_NO_MEM		-9

Indicates a temporary or permanent lack of adequate memory to perform the
operation. Ideally, this should never happen. Skiboot reserves a small amount
of memory for its heap and some operations (such as I2C requests) are allocated
from this heap.

If this is ever hit, you should likely file a bug.

.. _OPAL_RESOURCE:

OPAL_RESOURCE
-------------
.. code-block:: c

   #define OPAL_RESOURCE		-10

When trying to use a limited resource, OPAL found that there were none free.
While OPAL_BUSY indicates that OPAL may soon be able to proces the requent,
OPAL_RESOURCE is a more permanent error and while the resource *may* become
available again in the future, it is not certain that it will.

.. _OPAL_INTERNAL_ERROR:

OPAL_INTERNAL_ERROR
-------------------
.. code-block:: c

   #define OPAL_INTERNAL_ERROR	-11

Something has gone wrong inside OPAL. This is likely a bug somewhere and we
return OPAL_INTERNAL_ERROR for safety.

.. _OPAL_BUSY_EVENT:

OPAL_BUSY_EVENT
---------------
.. code-block:: c

   #define OPAL_BUSY_EVENT		-12

The same as `OPAL_BUSY` but signals that the OS should call `OPAL_POLL_EVENTS` as
that may be required to get into a state where the call will succeed.

.. _OPAL_HARDWARE_FROZEN:

OPAL_HARDWARE_FROZEN
--------------------
.. code-block:: c

   #define OPAL_HARDWARE_FROZEN	-13

.. _OPAL_WRONG_STATE:

OPAL_WRONG_STATE
----------------
.. code-block:: c

   #define OPAL_WRONG_STATE	-14

The requested operation requires a (hardware or software) component to be in
a different state. For example, you cannot call OPAL_START_CPU on a CPU that
is not currently in OPAL.

.. _OPAL_ASYNC_COMPLETION:

OPAL_ASYNC_COMPLETION
---------------------
.. code-block:: c

   #define OPAL_ASYNC_COMPLETION	-15

For asynchronous calls, successfully queueing/starting executing the
command is indicated by the OPAL_ASYNC_COMPLETION return code.
pseudo-code for an async call: ::

  token = opal_async_get_token();
  rc = opal_async_example(foo, token);
  if (rc != OPAL_ASYNC_COMPLETION)
      handle_error(rc);
  rc = opal_async_wait(token);
  // handle result here

.. _OPAL_EMPTY:

OPAL_EMPTY
----------
.. code-block:: c

   #define OPAL_EMPTY		-16

The call was successful and the correct result is empty. For example, the
OPAL_IPMI_RECV call can succeed and return that there is no waiting IPMI
message.

.. _OPAL_I2C_TIMEOUT:

OPAL_I2C_TIMEOUT
----------------
.. code-block:: c

  #define OPAL_I2C_TIMEOUT	-17


.. _OPAL_I2C_INVALID_CMD:

OPAL_I2C_INVALID
----------------
.. code-block:: c

  #define OPAL_I2C_INVALID_CMD	-18


.. _OPAL_I2C_LBUS_PARITY:

OPAL_I2C_LBUS_PARITY
--------------------
.. code-block:: c

  #define OPAL_I2C_LBUS_PARITY	-19


.. _OPAL_I2C_BKEND_OVERRUN:

OPAL_I2C_BKEND_OVERRUN
----------------------
.. code-block:: c

  #define OPAL_I2C_BKEND_OVERRUN	-20


.. _OPAL_I2C_BKEND_ACCESS:

OPAL_I2C_BKEND_ACCESS
---------------------
.. code-block:: c

  #define OPAL_I2C_BKEND_ACCESS	-21

.. _OPAL_I2C_ARBT_LOST:

OPAL_I2C_ARBT_LOST
------------------
.. code-block:: c

  #define OPAL_I2C_ARBT_LOST	-22

.. _OPAL_I2C_NACK_RCVD:

OPAL_I2C_NACK_RCVD
------------------
.. code-block:: c

  #define OPAL_I2C_NACK_RCVD	-23

.. _OPAL_I2C_STOP_ERR:

OPAL_I2C_STOP_ERR
-----------------
.. code-block:: c

  #define OPAL_I2C_STOP_ERR	-24


.. _OPAL_XSCOM_BUSY:

OPAL_XSCOM_BUSY
---------------

An alias for :ref:`OPAL_BUSY`

.. _OPAL_XSCOM_CHIPLET_OFF:

OPAL_XSCOM_CHIPLET_OFF
----------------------

An alias for :ref:`OPAL_WRONG_STATE`

.. _OPAL_XSCOM_PARTIAL_GOOD:

OPAL_XSCOM_PARTIAL_GOOD
-----------------------

.. code-block:: c

 #define OPAL_XSCOM_PARTIAL_GOOD -25

.. _OPAL_XSCOM_ADDR_ERROR:

OPAL_XSCOM_ADDR_ERROR
---------------------

.. code-block:: c

  #define OPAL_XSCOM_ADDR_ERROR	-26

.. _OPAL_XSCOM_CLOCK_ERROR:

OPAL_XSCOM_CLOCK_ERROR
----------------------

.. code-block:: c

   #define OPAL_XSCOM_CLOCK_ERROR	-27

.. _OPAL_XSCOM_PARITY_ERROR:

OPAL_XSCOM_PARITY_ERROR
-----------------------

.. code-block:: c

   #define OPAL_XSCOM_PARITY_ERROR	-28

.. _OPAL_XSCOM_TIMEOUT:

OPAL_XSCOM_TIMEOUT
------------------

.. code-block:: c

   #define OPAL_XSCOM_TIMEOUT	-29

.. _OPAL_XSCOM_CTR_OFFLINED:

OPAL_XSCOM_CTR_OFFLINED
-----------------------

.. code-block:: c

   #define OPAL_XSCOM_CTR_OFFLINED	-30

.. _OPAL_XIVE_PROVISIONING:

OPAL_XIVE_PROVISIONING
----------------------

.. code-block:: c

   #define OPAL_XIVE_PROVISIONING	-31

.. _OPAL_XIVE_FREE_ACTIVE:

OPAL_XIVE_FREE_ACTIVE
---------------------

.. code-block:: c

   #define OPAL_XIVE_FREE_ACTIVE	-32

.. _OPAL_TIMEOUT:

OPAL_TIMEOUT
------------

.. code-block:: c

   #define OPAL_TIMEOUT		-33
