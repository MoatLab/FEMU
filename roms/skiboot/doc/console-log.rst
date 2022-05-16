SkiBoot Console Log
===================

Skiboot maintains a circular textual log buffer in memory.

It can be accessed using any debugging method that can peek at
memory contents. While the debug_descriptor does hold the location
of the memory console, we're pretty keen on keeping its location
static.

Events are logged in the following format:
``[S.T,L] message`` where:

:S: Seconds, which is the timebase divided by 512,000,000.
    **NOTE**: The timebase is reset during boot, so zero is a few dozen
    messages into skiboot booting.
:T: Remaining Timebase. It is *NOT* a fraction of a second, but rather
    timebase%512000000
:L: Log level (see below)

Example: ::

  [    2.223466021,5] FLASH: Found system flash: Macronix MXxxL51235F id:0
  [    3.494892796,7] FLASH: flash subpartition eyecatcher CAPP

You should use the new prlog() call for any log message and set the
log level/priority appropriately.

printf() is mapped to PR_PRINTF and should be phased out and replaced
with prlog() calls.

See timebase.h for full timebase explanation.

Log levels
----------

=============== ==========
Define          Value
=============== ==========
PR_EMERG        0
PR_ALERT        1
PR_CRIT         2
PR_ERR          3
PR_WARNING      4
PR_NOTICE       5
PR_PRINTF       PR_NOTICE
PR_INFO         6
PR_DEBUG        7
PR_TRACE        8
PR_INSANE       9
=============== ==========

The console_log_levels byte in the debug_descriptor controls what
messages are written to any console drivers (e.g. fsp, uart) and
what level is just written to the in memory console (or not at all).

This enables (advanced) users to vary what level of output they want
at runtime in the memory console and through console drivers (fsp/uart)

You can vary two things by poking in the debug descriptor:

1. what log level is printed at all
   e.g. only turn on PR_TRACE at specific points during runtime
2. what log level goes out the fsp/uart console, defaults to PR_PRINTF

We use two 4bit numbers (1 byte) for this in debug descriptor (saving
some space, not needlessly wasting space that we may want in future).

The default is 0x75 (7=PR_DEBUG to in memory console, 5=PR_PRINTF to drivers

If you write 0x77 you will get debug info on uart/fsp console as
well as in memory. If you write 0x95 you get PR_INSANE in memory but
still only PR_NOTICE through drivers.

People who write something like 0x1f will get a very quiet boot indeed.

Debugging
---------

You can change the log level of what goes to the in memory buffer and whta
goes to the driver (i.e. serial port / IPMI Serial over LAN) at boot time
by setting NVRAM variables: ::

  nvram -p ibm,skiboot --update-config log-level-driver=7
  nvram -p ibm,skiboot --update-config log-level-memory=7

You can also use the named versions of emerg, alert, crit, err,
warning, notice, printf, info, debug, trace or insane.  ie. ::

  nvram -p ibm,skiboot --update-config log-level-driver=insane


You an also write to the debug_descriptor to change it at runtime.
