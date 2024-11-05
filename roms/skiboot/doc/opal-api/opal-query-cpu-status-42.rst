.. _OPAL_QUERY_CPU_STATUS:

OPAL_QUERY_CPU_STATUS
=====================

.. code-block:: c

   #define OPAL_QUERY_CPU_STATUS			42

   enum OpalThreadStatus {
	OPAL_THREAD_INACTIVE = 0x0,
	OPAL_THREAD_STARTED = 0x1,
	OPAL_THREAD_UNAVAILABLE = 0x2 /* opal-v3 */
   };

   int64_t opal_query_cpu_status(uint64_t server_no, uint8_t *thread_status);

Sets `thread_status` to be the state of the `server_no` CPU thread. CPU threads
can be owned by OPAL or the OS. Ownership changes based on :ref:`OPAL_START_CPU`
and :ref:`OPAL_RETURN_CPU`.

``OPAL_THREAD_INACTIVE``
  Active in skiboot, not in OS. Skiboot owns the CPU thread.
``OPAL_THREAD_STARTED``
  CPU has been started by OS, not owned by OPAL.
``OPAL_THREAD_UNAVAILABLE``
  CPU is unavailable. e.g. is guarded out.

Returns
-------

:ref:`OPAL_PARAMETER`
     Invalid address for `thread_status`, invalid CPU, or CPU not in OPAL or OS.
:ref:`OPAL_SUCCESS`
     Successfully retreived status.
