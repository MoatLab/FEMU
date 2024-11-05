Skiboot overview
================

Skiboot is boot and runtime firmware for OpenPOWER systems.
It's loaded by earlier boot firmware (typically Hostboot).
Along with loading the bootloader, it provides some runtime
services to the OS (typically Linux).

Source layout
-------------

========== ===================================================
Directory  Content
========== ===================================================
asm/	   small amount, mainly entry points
ccan/	   bits from CCAN_
core/	   common code among machines.
doc/	   not enough here
external/  tools and userspace components
hdata/	   Parses HDAT from Hostboot/FSP into Device Tree
hw/ 	   drivers for things & fsp things.
include/   headers!
libc/ 	   tiny libc, originally from SLOF_
libfdt/    Manipulate flattened device trees
libflash/  Lib for talking to flash and parsing FFS structs
libpore/   to manipulate PORE [#]_ engine.
libstb/    See :ref:`stb-overview`
libxz/     The xz_embedded_ library
opal-ci/   Some scripts to help Continuous Integration testing
platforms/ Platform (machine/BMC) specific code
test/      Test scripts and binaries
========== ===================================================

.. _CCAN: https://ccodearchive.net/
.. _SLOF: https://github.com/aik/SLOF/
.. _xz_embedded: https://tukaani.org/xz/embedded.html

.. [#] Power On Reset Engine. Used to bring cores out of deep sleep states.
       For POWER9, this also includes the `p9_stop_api` which manipulates
       the low level microcode to-reinit certain SPRs on transition out of
       a state losing STOP state.

We have a spinlock implementation in `asm/lock.S`__
Entry points are detailed in `asm/head.S`__
The main C entry point is in `core/init.c`__: `main_cpu_entry()`__

.. _lock_S: https://github.com/open-power/skiboot/blob/v5.8/asm/lock.S
.. _head_S: https://github.com/open-power/skiboot/blob/v5.8/asm/head.S
.. _core_init_c: https://github.com/open-power/skiboot/blob/v5.8/core/init.c
.. _main_cpu_entry: https://github.com/open-power/skiboot/blob/v5.8/core/init.c#L785

__ lock_S_
__ head_S_
__ core_init_c_
__ main_cpu_entry_

Binaries
--------
The following binaries are built:

==================== =================================================
File                 Purpose
==================== =================================================
skiboot.lid          Binary for flashing onto systems [#]_
skiboot.lid.stb      Secure and Trusted Boot container wrapped skiboot
*skiboot.lid.xz*     XZ compressed binary [#]_
*skiboot.lid.xz.stb* STB container wrapped XZ compressed skiboot [#]_
skiboot.elf          is the elf binary of it, lid comes from this
skiboot.map          plain map of symbols
==================== =================================================

.. [#] Practically speaking, this is just IBM FSP based systems now. Since
       the `skiboot.lid` size is now greater than 1MB, which is the size of
       the default `PAYLOAD` PNOR partition size on OpenPOWER systems, you
       will want the `skiboot.lid.xz` or `skiboot.lid.xz.stb` instead.
.. [#] On OpenPOWER systems, hostboot will read and decompress XZ
       compressed payloads. This shortens boot time (less data to read),
       adds a checksum over the `PAYLOAD` and saves valuable PNOR space.
       If in doubt, use this payload.
.. [#] If a secure boot system, use this payload.

Booting
-------

On boot, every thread of execution jumps to a single entry point in skiboot
so we need to do some magic to ensure we init things properly and don't stomp
on each other. We choose a master thread, putting everybody else into a
spinloop.

Essentially, we do this by doing an atomic fetch and inc and whoever gets 0
gets to be the main thread. The main thread will then distribute tasks to
secondary threads as needed. We do not (currently) do anything fancy like
context switching or scheduling.

When entering skiboot, we enter with one of two data structures describing
the system as initialized by Hostboot. There may be a flattened device tree
(see https://devicetree.org/ ), or a HDAT structure. While Device Tree
is an industry standard, HDAT comes from IBM POWER. On POWER8, skiboot would
get HDAT and a mini-devicetree from an FSP or purely a Device Tree on OpenPOWER
systems. On POWER9, it's just HDAT everywhere (that isn't a simulator).
The HDAT specification is currently not public. It is purely an interface
between Hostboot and skiboot, and is only exposed anywhere else for debugging
purposes.

During boot, skiboot will add a lot to the device tree, manipulating what
may already be there before exporting this new device tree out to the OS.

The main entry point is main_cpu_entry() in core/init.c, this is a carefully
ordered init of things. The sequence is relatively well documented there.

OS interface
------------

OPAL (skiboot) is exclusively called through OPAL calls. The OS has complete
controll of *when* OPAL code is executed. The design of all OPAL APIs is that
we do not block in OPAL, so as not to introduce jitter.

Skiboot maintains its own stack for each CPU, the running OS does not need
to donate or reserve any of its stack space.

With the OPAL API calls and device tree bindings we have the OPAL ABI.

Interrupts
----------

We don't directly handle interrupts in skiboot. The OS is in complete control,
and any interrupts we need to process are first received by the OS. The
:ref:`OPAL_HANDLE_INTERRUPT` call is made by the OS for OPAL to do what's
needed.

Memory
------

We initially occupy a chunk of memory, "heap". We pass to the OS (Linux)
a reservation of what we occupy (including stacks).

In the source file include/mem-map.h we include a memory map. This is
manually generated, not automatically generated.

We use CCAN for a bunch of helper code, turning on things like DEBUG_LOCKS
as these are not a performance issue for us, and we like to be careful.

In include/config.h there are defines for turning on extra tracing.
OPAL is what we name the interface from skiboot to OS (Linux).

Each CPU gets a 16k stack, which is probably more than enough. Stack
should be used sparingly though.

Important memory locations:

============= ============================================================
Location      What's there
============= ============================================================
SKIBOOT_BASE  where skiboot lives, of SKIBOOT_SIZE
HEAP_BASE     Where skiboot heap starts, of HEAP_SIZE
============= ============================================================

There is also SKIBOOT_SIZE (manually calculated) and DEVICE_TREE_MAX_SIZE,
which is largely historical.

Skiboot log
-----------

There is a circular log buffer that skiboot maintains. This can be
accessed either from the FSP or through /dev/mem or through the sysfs
file /sys/firmware/opal/msglog.
