.. _OPAL_QUIESCE:

OPAL_QUIESCE
============

.. code-block:: c

   #define OPAL_QUIESCE				158

   int64_t opal_quiesce(uint32_t quiesce_type, int32_t cpu_target);

The host OS can use :ref:`OPAL_QUIESCE` to ensure CPUs under host control are not
executing OPAL. This is useful in crash or shutdown scenarios to try to
ensure that CPUs are not holding locks, and is intended to be used with
:ref:`OPAL_SIGNAL_SYSTEM_RESET`, for example.

Arguments
---------

quiesce_type
^^^^^^^^^^^^

QUIESCE_HOLD
  Wait for all target(s) currently executing OPAL to
  return to the host. Any new OPAL call that is made
  will be held off until QUIESCE_RESUME.
QUIESCE_REJECT
  Wait for all target(s) currently executing OPAL to
  return to the host. Any new OPAL call that is made
  will fail with OPAL_BUSY until QUIESCE_RESUME.
QUIESCE_LOCK_BREAK
  After QUIESCE_HOLD or QUIESCE_REJECT is successful,
  the CPU can call QUIESCE_LOCK_BREAK to skip all
  locking in OPAL to give the best chance of making
  progress in the crash/debug paths. The host should
  ensure all other CPUs are stopped (e.g., with
  OPAL_SIGNAL_SYSTEM_RESET) before this call is made, to
  avoid concurrency.
QUIESCE_RESUME
  Undo the effects of QUIESCE_HOLD/QUIESCE_REJECT and
  QUIESCE_LOCK_BREAK calls.
QUIESCE_RESUME_FAST_REBOOT
  As above, but also reset the tracking of OS calls
  into firmware as part of fast reboot (secondaries
  will never return to OS, but instead be released
  into a new OS boot).

target_cpu
^^^^^^^^^^

``cpu_nr >= 0``
  The cpu server number of the target cpu to reset.
``-1``
  All cpus except the current one should be quiesced.

Returns
-------

:ref:`OPAL_SUCCESS`
  The quiesce call was successful.
:ref:`OPAL_PARTIAL`
  Some or all of the CPUs executing OPAL when the call was made did not
  return to the host after a timeout of 1 second. This is a best effort
  at quiescing OPAL, and QUIESCE_RESUME must be called to resume normal
  firmware operation.
:ref:`OPAL_PARAMETER`
  A parameter was incorrect.
:ref:`OPAL_BUSY`
  This CPU was not able to complete the operation, either because another
  has concurrently started quiescing the system, or because it has not
  successfully called QUIESCE_HOLD or QUIESCE_REJECT before attempting
  QUIESCE_LOCK_BREAK or QUIESCE_RESUME.
