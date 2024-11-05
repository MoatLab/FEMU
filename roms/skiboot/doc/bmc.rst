OPAL <--> BMC interactions
==========================

This document provides information about some of the user-visible interactions
that skiboot performs with the BMC.

IPMI sensors
------------

OPAL will interact with a few IPMI sensors during the boot process. These
are:

  * Boot Count [type 0xc3: OEM reserved]
  * FW Boot progress [type 0x0f: System Firmware Progress]

Boot Count: assertion type. When OPAL reaches a late stage of boot, it sets the
boot count sensor to 0x02. This is intended to allow the BMC detect a failed
or aborted boot, for switching to a known-good firmware image.

FW Boot Progress: assertion type. During boot, skiboot will update this sensor
to one of the IPMI-defined progress codes. The codes use by skiboot are:

  * PCI Resource configuration (0x01)
     * asserted as the PCI devices have been probed and resources allocated
  * Motherboard init (0x14)
     * asserted as the platform-specific components have been initialised
  * OS boot (0x13)
     * asserted after skiboot has loaded the PAYLOAD image, and is about to
       boot it.

Chassis control messages
------------------------

OPAL uses chassis control messages to instruct the BMC to remove power from
the host. These messages are sent during graceful reboot and shutdown processes
initiated by the host.

For a BMC-initiated graceful power-down (or reboot), the BMC is expected to send
an OEM-defined SEL message, using a SMS_ATN to trigger a BMC-to-host
notification. This SEL has a type of 0xc0, and command of 0x04. The data0 field
of the SEL indicates shutdown (0x0) or reboot (0x1).


Watchdog support
----------------

OPAL supports a BMC watchdog during the boot process. This will be disabled
before entering the OS.


Real-time clock
---------------

On platforms where a real-time-clock is not available, skiboot may use the
IPMI SEL Time as a real-time-clock device.

SBE validation
--------------

On some P8 platforms with an AMI or SMC BMC (ie. astbmc) SBE validation is done
by a tool on the BMC. This is done to inspect the SBE and detect if a malicious
host has written to the SBE, especially in multi-tenant
"Bare-Metal-As-A-Service" scenarios.

To complicate this the SBE validation occurs at host-runtime and reads the SBE
SEEPROM over I2C using the FSI master which will conflict with anything the
host may be doing at the same time. To avoid this Skiboot will pause boot until
the validation is complete.
If SBE validation is required the BMC will communicate this to Skiboot by
setting an IPMI System Boot Option with OEM parameter 0x62. When this flag is
set Skiboot will pause and wait for the validation to complete and the flag to
be cleared. This ensures the validation completes before the execution is passed
to Petitboot and the host operating system and any conflicts could occur. During
this process Skiboot will print::

    SBE validation required, waiting for completion
    System will be powered off if validation fails

to the console with an update every minute until complete.

Unfortunately the validation performed by the BMC leaves the SBE in a bad
state. Once the validation is complete Skiboot will reboot to reset everything
to a good state and normal booting can resume. No such reboot is required if
the flag is not set and validation doesn't occur.
