.. _OPAL_POLL_EVENTS:

OPAL_POLL_EVENTS
================

Poll for outstanding events.

Fills in a bitmask of pending events.

Current events are:

OPAL_EVENT_OPAL_INTERNAL = 0x1
------------------------------
Currently unused.


OPAL_EVENT_NVRAM = 0x2
----------------------
Unused

.. _OPAL_EVENT_RTC:

OPAL_EVENT_RTC = 0x4
--------------------
**TODO**: clean this up, this is just copied from hw/fsp/fsp-rtc.c: ::

 * Because the RTC calls can be pretty slow, these functions will shoot
 * an asynchronous request to the FSP (if none is already pending)
 *
 * The requests will return OPAL_BUSY_EVENT as long as the event has
 * not been completed.
 *
 * WARNING: An attempt at doing an RTC write while one is already pending
 * will simply ignore the new arguments and continue returning
 * OPAL_BUSY_EVENT. This is to be compatible with existing Linux code.
 *
 * Completion of the request will result in an event OPAL_EVENT_RTC
 * being signaled, which will remain raised until a corresponding call
 * to opal_rtc_read() or opal_rtc_write() finally returns OPAL_SUCCESS,
 * at which point the operation is complete and the event cleared.
 *
 * If we end up taking longer than rtc_read_timeout_ms millieconds waiting
 * for the response from a read request, we simply return a cached value (plus
 * an offset calculated from the timebase. When the read request finally
 * returns, we update our cache value accordingly.
 *
 * There is two separate set of state for reads and writes. If both are
 * attempted at the same time, the event bit will remain set as long as either
 * of the two has a pending event to signal.

OPAL_EVENT_CONSOLE_OUTPUT = 0x8
-------------------------------
TODO

OPAL_EVENT_CONSOLE_INPUT = 0x10
-------------------------------
TODO

OPAL_EVENT_ERROR_LOG_AVAIL = 0x20
---------------------------------
TODO

OPAL_EVENT_ERROR_LOG = 0x40
---------------------------
TODO

OPAL_EVENT_EPOW = 0x80
----------------------
TODO

OPAL_EVENT_LED_STATUS = 0x100
-----------------------------
TODO

OPAL_EVENT_PCI_ERROR = 0x200
----------------------------
TODO

.. _OPAL_EVENT_DUMP_AVAIL:

OPAL_EVENT_DUMP_AVAIL = 0x400
-----------------------------
Signifies that there is a pending system dump available. See :ref:`opal-dumps` suite
of calls for details.

OPAL_EVENT_MSG_PENDING = 0x800
------------------------------
