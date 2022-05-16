.. _OPAL_RESYNC_TIMEBASE:

OPAL_RESYNC_TIMEBASE
====================

.. code-block:: c

   #define OPAL_RESYNC_TIMEBASE			79

   int64_t opal_resync_timebase(void);

Resynchronises the timebase for all threads in a core to the timebase from
chiptod.

Returns
-------

:ref:`OPAL_SUCCESS`
     Successfully resynced timebases (or it's a no-op on this platform).
:ref:`OPAL_HARDWARE`
     Failed to resync timebase.
