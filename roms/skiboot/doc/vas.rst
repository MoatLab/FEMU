Virtual Accelerator Switchboard (VAS)
=====================================

This document provides information about using VAS from user space.
Applications send NX requests using COPY/PASTE instructions. NX raises
an interrupt when it sees fault on the request buffer. Kernel handles
the interrupt and process the fault.

Skiboot allocates the IRQ and exports it with interrupts property. To
provide backward compatibility for older kernels, enable VAS user space
support with NVRAM command.

	nvram -p ibm,skiboot --update-config vas-user-space=enable

This nvram config update is temporary and can be removed in future if
not needed.
