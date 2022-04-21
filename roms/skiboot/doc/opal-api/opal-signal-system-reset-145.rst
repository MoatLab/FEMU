.. _OPAL_SIGNAL_SYSTEM_RESET:

OPAL_SIGNAL_SYSTEM_RESET
========================
::

   int64_t signal_system_reset(int32_t cpu_nr);
 
This OPAL call causes the specified cpu(s) to be reset to the system
reset exception handler (0x100).

The SRR1 register will indicate a power-saving wakeup when appropriate,
and the wake reason will be System Reset (see Power ISA).

This interrupt may not be recoverable in some cases (e.g., if it is
raised when the target has MSR[RI]=0), so it should not be used in
normal operation, but only for crashing, debugging, and similar
exceptional cases.

OPAL_SIGNAL_SYSTEM_RESET can pull CPUs out of OPAL, which may be
undesirable in a crash or shutdown situation (e.g., because they may
hold locks which are required to access the console, or may be halfway
through setting hardware registers), so OPAL_QUIESCE can be used
before OPAL_SIGNAL_SYSTEM_RESET to (attempt to) ensure all CPUs are
out of OPAL before being interrupted.

Arguments
---------
::

  int32_t cpu_nr
    cpu_nr >= 0        The cpu server number of the target cpu to reset.
    SYS_RESET_ALL (-1) All cpus should be reset.
    SYS_RESET_ALL_OTHERS (-2) All but the current cpu should be reset.

Returns
-------
OPAL_SUCCESS
  The system reset requests to target CPU(s) was successful. This returns
  asynchronously without acknowledgement from targets that system reset
  interrupt processing has completed or even started.

OPAL_PARAMETER
  A parameter was incorrect.

OPAL_HARDWARE
  Hardware indicated failure during reset, some or all of the target CPUs
  may have the system reset delivered.

OPAL_CONSTRAINED
  Platform does not support broadcast operations.

OPAL_PARTIAL
  Platform can not reset sibling threads on the same core as requested.
  None of the specified CPUs are reset in this case.

OPAL_UNSUPPORTED
  This processor/platform is not supported.

