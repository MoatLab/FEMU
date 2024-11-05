POWER9 Changes to OPAL API
==========================

This document is a summary of POWER9 changes to the OPAL API over what it
was for POWER7 and POWER8. As the POWER series of processors (at least up
to POWER9) require changes in the hypervisor to work on a new processor
generation, this gives us an opportunity with POWER9 to clean up several
parts of the OPAL API.

Eventually, when the kernel drops support for POWER8 and before, we can then
remove the associated kernel code too.

OPAL_REINIT_CPUS
----------------
Can now be extended beyond HILE BE/LE bits. If invalid flags are set on
POWER9, OPAL_UNSUPPORTED will be returned.

Device Tree
-----------

- ``/ibm,opal/`` compatible property now just lists ``ibm,opal-v3`` and no longer ``ibm,opal-v2`` (power9 and above only)
- Use only ``stdout-path`` property from POWER9 and above as usage of ``linux,stdout-path`` is deprecated
- Rename ``fsp-ipl-side`` as ``sp-ipl-side`` in ``/ipl-params``
- Add interrupt-parent property for ``/ibm,opal/ipmi`` node on POWER9 and above
  to make use of OPAL irqchip rather than event interface in linux.

TODO
----
Things we still have to do for POWER9:

- PCI to use async API rather than returning delays
- deprecate/remove v1 APIs where there's a V2
- Fix this FWTS warning: ::

   FAILED [MEDIUM] DeviceTreeBaseDTCWarnings: Test 3, dtc reports warnings from
   device tree: Warning (reg_format): "reg" property in /ibm,opal/flash@0 has
   invalid length (8 bytes) (#address-cells == 0, #size-cells == 0)

- Remove mi-version / ml-version from ``/ibm,opal/firmware`` and replace with something better and more portable
