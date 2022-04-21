.. _imc:

OPAL/Skiboot In-Memory Collection (IMC) interface Documentation
===============================================================

Overview:
---------

In-Memory-Collection (IMC) is performance monitoring infrastrcuture
for counters that (once started) can be read from memory at any time by
an operating system. Such counters include those for the Nest and Core
units, enabling continuous monitoring of resource utilisation on the chip.

The API is agnostic as to how these counters are implemented. For the
Nest units, they're implemented by having microcode in an on-chip
microcontroller and for core units, they are implemented as part of core logic
to gather data and periodically write it to the memory locations.

Nest (On-Chip, Off-Core) unit:
------------------------------

Nest units have dedicated hardware counters which can be programmed
to monitor various chip resources such as memory bandwidth,
xlink bandwidth, alink bandwidth, PCI, NVlink and so on. These Nest
unit PMU counters can be programmed in-band via scom. But alternatively,
programming of these counters and periodically moving the counter data
to memory are offloaded to a hardware engine part of OCC (On-Chip Controller).

Microcode, starts to run at system boot in OCC complex, initialize these
Nest unit PMUs and periodically accumulate the nest pmu counter values
to memory. List of supported events by the microcode is packages as a DTS
and stored in IMA_CATALOG partition.

Core unit:
----------

Core IMC PMU counters are handled in the core-imc unit. Each core has
4 Core Performance Monitoring Counters (CPMCs) which are used by Core-IMC logic.
Two of these are dedicated to count core cycles and instructions.
The 2 remaining CPMCs have to multiplex 128 events each.

Core IMC hardware does not support interrupts and it peridocially (based on
sampling duration) fetches the counter data and accumulate to main memory.
Memory to accumulate counter data are refered from "PDBAR" (per-core scom)
and "LDBAR" per-thread spr.

Trace mode of IMC:
------------------

POWER9 support two modes for IMC which are the Accumulation mode and
Trace mode. In Accumulation mode event counts are accumulated in system
memory. Hypervisor/kernel then reads the posted counts periodically, or
when requested. In IMC Trace mode, the 64 bit trace scom value is initialized
with the event information. The CPMC*SEL and CPMC_LOAD in the trace scom, specifies
the event to be monitored and the sampling duration. On each overflow in the
CPMC*SEL, hardware snapshots the program counter along with event counts
and writes into memory pointed by LDBAR. LDBAR has bits to indicate whether
hardware is configured for accumulation or trace mode.
Currently the event monitored for trace-mode is fixed as cycle.

PMI interrupt handling is avoided, since IMC trace mode snapshots the
program counter and update to the memory. And this also provide a way for
the operating system to do instruction sampling in real time without
PMI(Performance Monitoring Interrupts) processing overhead.

**Example:**

Performance data using 'perf top' with and without trace-imc event:


*PMI interrupts count when `perf top` command is executed without trace-imc event.*
::

     # cat /proc/interrupts  (a snippet from the output)
     9944      1072        804        804       1644        804       1306
     804        804        804        804        804        804        804
     804        804       1961       1602        804        804       1258
     [-----------------------------------------------------------------]
     803        803        803        803        803        803        803
     803        803        803        803        804        804        804
     804        804        804        804        804        804        803
     803        803        803        803        803       1306        803
     803   Performance monitoring interrupts


*PMI interrupts count when `perf top` command executed with trace-imc event
(executed right after 'perf top' without trace-imc event).*
::

   # perf top -e trace_imc/trace_cycles/
   12.50%  [kernel]          [k] arch_cpu_idle
   11.81%  [kernel]          [k] __next_timer_interrupt
   11.22%  [kernel]          [k] rcu_idle_enter
   10.25%  [kernel]          [k] find_next_bit
    7.91%  [kernel]          [k] do_idle
    7.69%  [kernel]          [k] rcu_dynticks_eqs_exit
    5.20%  [kernel]          [k] tick_nohz_idle_stop_tick
        [-----------------------]

   # cat /proc/interrupts (a snippet from the output)

   9944      1072        804        804       1644        804       1306
   804        804        804        804        804        804        804
   804        804       1961       1602        804        804       1258
   [-----------------------------------------------------------------]
   803        803        803        803        803        803        803
   803        803        803        804        804        804        804
   804        804        804        804        804        804        803
   803        803        803        803        803       1306        803
   803   Performance monitoring interrupts

Here the PMI interrupts count remains the same.

OPAL APIs:
----------

The OPAL API is simple: a call to init a counter type, and calls to
start and stop collection. The memory locations are described in the
device tree.

See :ref:`opal-imc-counters` and :ref:`device-tree/imc`
