OPAL Specification
==================

**DRAFT - VERSION 0.0.1 AT BEST.**

**COMMENTS ARE WELCOME** - and indeed, needed.

If you are reading this, congratulations: you're now reviewing it!


This document aims to define what it means to be OPAL compliant.

While skiboot is the reference implementation, this documentation should
be complete enough that (given hardware documentation) create another
implementation. It is not recommended that you do this though.

Authors
-------
Stewart Smith <stewart@linux.ibm.com> : OPAL Architect, IBM


Definitions
-----------

Host processor
  the main POWER CPU (e.g. the POWER8 CPU)
Host OS
  the operating system running on the host processor.
OPAL
  OpenPOWER Abstraction Layer.

What is OPAL?
-------------

The OpenPower Abstraction Layer (OPAL) is boot and runtime firmware for
POWER systems. There are several components to what makes up a firmware
image for OpenPower machines.

For example, there may be:

* BMC firmware

  * Firmware that runs purely on the BMC.
  * On IBM systems that have an FSP rather than a BMC, there is FSP firmware
  * While essential to having the machine function, this firmware is not
    part of the OPAL Specification.
* HostBoot

  * HostBoot ( https://github.com/open-power/hostboot ) performs all
    processor, bus and memory initialization within IBM POWER based systems.
* OCC Firmware

  * On Chip Controller ( Firmware for OCC - a PPC405 core inside the IBM
    POWER8 in charge of keeping the system thermally and power safe ).
* SkiBoot

  * Boot and runtime services.
* A linux kernel and initramfs incorporating petitboot

  * The bootloader. This is where a user chooses what OS to boot, and
    petitboot will use kexec to switch to the host Operating System
    (for example, PowerKVM).

While all of these components may be absolutely essential to power on,
boot and operate a specific OpenPower POWER8 system, the majority of
the code mentioned above can be thought of as implementation details
and not something that should form part of an OPAL Specification.

For an OPAL system, we assume that the hardware is functioning and any
hardware management that is specific to a platform is performed by OPAL
firmware transparently to the host OS.

The OPAL Specification focus on the interface between firmware and the
Operating System. It does not dictate that any specific pieces of firmware
code be used, although re-inventing the wheel is strongly discouraged.

The OPAL Specification explicitly allows for:

* A conforming implementation to not use any of the reference implementation
  code.
* A conforming implementation to use any 64bit POWER ISA conforming processor,
  and not be limited to the IBM POWER8.
* A conforming implementation to be a simulator, emulator or virtual environment
* A host OS other than Linux

Explicitly not covered in this specification:

* A 32bit OPAL Specification
  There is no reason this couldn't exist but the current specification is for
  64bit POWER systems only.


Boot Services
-------------

An OPAL compliant firmware implementation will load and execute a payload
capable of booting a Host Operating System.

The reference implementation loads a Linux kernel with an initramfs with
a minimal userspace and the petitboot boot loader - collectively referred
to as skiroot.

The OPAL Specification explicitly allows variation in this payload.

A requirement of the payload is that it MUST support loading and booting
an uncompressed vmlinux Linux kernel.
[**TODO**: expand on what this actually means]

An OPAL system MUST pass a device tree to the host kernel.
[**TODO**: expand the details, add device-tree section and spec]

An OPAL system MUST provide the host kernel with enough information to
know how to call OPAL runtime services.
[**TODO**: expand on this. ]

Explicitly not covered by the OPAL Specification:

* Kernel module ABI for skiroot kernel
* Userspace environment of skiroot
* That skiroot is Linux.

Explicitly allowed:

* Replacing the payload with something of equal/similar functionality
  (whether replacing skiroot with an implementation of Zork would be compliant
  is left as an exercise for the reader)

Payload Environment
-------------------
The payload is started with:

======== =====
Register Value
======== =====
r3       address of flattened device-tree (fdt)
r8       OPAL base
r9       OPAL entry
======== =====

Runtime Services
----------------

An OPAL Specification compliant system provides runtime services to the host
Operating System via a standard interface.

An OPAL call is made by calling opal_entry with:
 *       r0: OPAL Token
 *       r2: OPAL Base
 *  r3..r10: Args (up to 8)

The OPAL API is defined in skiboot/doc/opal-api/

Not all OPAL APIs must be supported for a system to be compliant. When
called with an unsupported token, a compliant firmware implementation
MUST fail gracefully and not crash. Reporting a warning that an unsupported
token was called is okay, as compliant host Operating Systems should use
OPAL_CHECK_TOKEN to test for optional functionality.

All parameters to OPAL calls are big endian. Little endian hosts MUST
appropriately convert parameters before passing them to OPAL.

Machine state across OPAL calls:

* r1 is preserved
* r12 is scratch
* r13 - 31 preserved
* 64bit HV real mode
* big endian
* external interrupts disabled

Detecting OPAL Support
----------------------

A Host OS may need to detect the presence of OPAL as it may support booting
under other platforms. For example, a single Linux kernel can be built to boot
under OPAL and under PowerVM or qemu pseries machine type.

The root node of the device tree MUST have compatible = "ibm,powernv".
See :ref:`device-tree` for more details.

The presence of the "/ibm,opal" entry in the device tree signifies running
under OPAL. Additionally, the "/ibm,opal" node MUST have a compatibile property
listing "ibm,opal-v3".

The "/ibm,opal" node MUST have the following properties:

.. code-block:: dts

 ibm,opal {
	  compatible = "ibm,opal-v3";
	  opal-base-address = <>;
	  opal-entry-address = <>;
	  opal-runtime-size = <>;
 };

The compatible property MAY have other strings, such as a future "ibm,opal-v4".
These are reserved for future use.

Some releases of the reference implementation (skiboot) have had compatible
contain "ibm,opal-v2" as well as "ibm,opal-v3". Host operating systems MUST
NOT rely on "ibm,opal-v2", this is a relic from early OPAL history.

The "ibm,opal" node MUST have a child node named "firmware". It MUST contain
the following:

.. code-block:: dts

 firmware {
	 compatible = "ibm,opal-firmware";
 };

It MUST contain one of the following two properties: git-id, version.
The git-id property is deprecated, and version SHOULD be used. These
are informative and MUST NOT be used by the host OS to determine anything
about the firmware environment.

The version property is a textual representation of the OPAL version.
For example, it may be "skiboot-4.1" or other versioning described
in more detail in :ref:`versioning`.


OPAL log
--------

OPAL implementation SHOULD have an in memory log where informational and
error messages are stored. If present it MUST be human readable and text based.
There is a separate facility (Platform Error Logs) for machine readable errors.

A conforming implementation MAY also output the log to a serial port or similar.
An implementation MAY choose to only output certain log messages to a serial
port.

For example, the reference implementation (skiboot) by default filters log
messages so that only higher priority log messages go over the serial port
while more messages go to the in memory buffer.

[TODO: add device-tree bits here]
