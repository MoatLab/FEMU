.. _mpipl:

MPIPL (aka FADUMP) Overview
===========================

Memory Preserving Initial Program Load (MPIPL) is a Power feature where the
contents of memory are preserved while the system reboots after a failure.
This is accomplished by the firmware/OS publishing ranges of memory to be
preserved across boots.

Registration
------------
In the OPAL context, OPAL and host Linux communicate the memory ranges to be
preserved via source descriptor tables in the HDAT (MDST and MDDT table inside
SPIRAH). Host Linux can register/unregister using OPAL_MPIPL_UPDATE API (see
:ref:`opal-api-mpipl`).

Initiating dump
---------------
Whenever Linux crashes, it makes reboot2 OPAL call with type as MPIPL. (see
:ref:`opal-api-cec-reboot`). Depending on sevice processor type OPAL makes
appropriate call to initiate MPIPL. On FSP system we call `attn` instruction
(see ``__trigger_attn()``) and on BMC system we call SBE `S0 interrupt`
(see ``p9_sbe_terminate()``).

Dump collection
---------------
Hostboot then re-IPLs the machine taking care to copy over contents of the
source memory to a alternate memory locations as specified in descriptor table.
Hostboot publishes this information in the result descriptor tables (MDRT table
inside SPIRAH structure). The success/failure of the copy is indicated by a
results table.

SBE/Hostboot also does the requisite procedures to gather hardware register
states for all active threads at the time of the crash.

MPIPL boot
----------
On MPIPL boot, OPAL adds device tree entry (``/ibm,opal/dump/mpipl-boot``)
to indicate its MPIPL boot. Kernel will use OPAL_MPIPL_QUERY_TAG API
(:ref:`opal-api-mpipl`) to retrieve metadata tag. Kernel then uses its
existing logic (kdump/fadump) to write out a core dump of OPAL and Linux
kernel in a format that GDB and crash can understand.

Device tree
-----------
We create new device tree node (``/ibm,opal/dump``) to pass dump details to Linux
kernel from OPAL (see :ref:`device-tree/ibm,opal/dump`).
