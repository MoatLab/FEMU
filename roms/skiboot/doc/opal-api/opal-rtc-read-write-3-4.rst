===============================
OPAL Real Time Clock (RTC) APIs
===============================

.. _OPAL_RTC_READ:

OPAL_RTC_READ
=============

Read the Real Time Clock.

Parameters
----------

``uint32_t* year_month_day``
  the year, month and day formatted as follows:

  - bits  0-15 is bcd formatted year (0100-9999)
  - bits 16-23 is bcd formatted month (01-12)
  - bits 24-31 is bcd formatted day (01-31)

``uint64_t* hour_minute_second_millisecond``
  the hour, minute, second and millisecond formatted as follows:

  - bits  0-16 is reserved
  - bits 17-24 is bcd formatted hour (00-23)
  - bits 25-31 is bcd formatted minute (00-59)
  - bits 32-39 is bcd formatted second (00-60)
  - bits 40-63 is bcd formatted milliseconds (000000-999999)

Calling
-------
Since RTC calls can be pretty slow, :ref:`OPAL_RTC_READ` is likely to first return
:ref:`OPAL_BUSY_EVENT`, requiring the caller to wait until the :ref:`OPAL_EVENT_RTC` event
has been signaled. Once the event has been signaled, a subsequent
:ref:`OPAL_RTC_READ` call will retrieve the time. Since the :ref:`OPAL_EVENT_RTC` event is
used for both reading and writing the RTC, callers must be able to handle
the event being signaled for a concurrent in flight :ref:`OPAL_RTC_WRITE` rather
than this read request.

The following code is one way to correctly issue and then wait for a response:

.. code-block:: c

    int rc = OPAL_BUSY_EVENT;
    while (rc == OPAL_BUSY_EVENT) {
    	  rc = opal_rtc_read(&y_m_d, &h_m_s_ms);
          if (rc == OPAL_BUSY_EVENT)
	     opal_poll_events(NULL);
    }

Although as of writing all :ref:`OPAL_RTC_READ` backends are asynchronous, there is
no requirement for them to be - it is valid for :ref:`OPAL_RTC_READ` to immediately
return the retreived value rather than :ref:`OPAL_BUSY_EVENT`.

**TODO**: describe/document format of arguments.

Return codes
------------

:ref:`OPAL_SUCCESS`
  parameters now contain the current time, or one read from cache.

:ref:`OPAL_HARDWARE`
  error in retrieving the time. May be transient error,
  may be permanent.

:ref:`OPAL_PARAMETER`
  year_month_day or hour_minute_second_millisecond parameters are NULL

:ref:`OPAL_INTERNAL_ERROR`
  something went wrong, Possibly reported in error log.
  This can be a transient error

:ref:`OPAL_BUSY_EVENT`
  request is in flight

:ref:`OPAL_BUSY`
  request may be in flight

.. _OPAL_RTC_WRITE:

OPAL_RTC_WRITE
==============

:ref:`OPAL_RTC_WRITE` is much like :ref:`OPAL_RTC_READ` in that it can be asynchronous.

If multiple WRITES are issued before the first one completes, subsequent
writes are ignored. There can only be one write in flight at any one time.

Format of the time is the same as for :ref:`OPAL_RTC_READ`.
