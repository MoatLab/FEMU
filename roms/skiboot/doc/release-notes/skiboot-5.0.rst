.. _skiboot-5.0:

===========
skiboot 5.0
===========

Skiboot 5.0 was released Friday 10th April 2015.

Changes in 5.0 (since rc3):

 - Fix chip id for nx coprocessors.
 - hw/ipmi: Fix FW Boot Progress sensor
 - bt: Add a temporary workaround for bmc dropping messages
 - FSP/CUPD: Fix lock issue

Changes in rc3 (since rc2):

 - add support for cec_power_down on mambo
 - external/opal-prd: Use link register for cross-endian branch
 - opal header file rework, Linux and skiboot now very closely match (API
   in opal-api.h)
 - libflash: don't use the low level interface if it doesn't exist
 - libflash/file: add file abstraction for libflash
 - external: create a GUARD partition parsing utility

Changes in rc2 (since rc1):

 - opal: Fix an issue where partial LID load causes opal to hang.
 - nx: use proc_gen instead of param
 - use chip id for NX engine Coproc Instance num
 - Fix (hopefully) missing dot symbols in skiboot.map
 - exceptions: Catch exceptions at boot time
 - exceptions: Remove deprecated exception patching stuff
 - mambo: Make mambo_utils.tcl optional
 - mambo: Exit mambo when the simulation is stopped
 - add NX register defines
 - set NX crb input queues to 842 only
 - core: Catch attempts to branch through a NULL pointer
 - plat/firestone: Add missing platform hooks
 - plat/firestone: Add missing platform hooks
 - elog: Don't call uninitialized platform elog_commit
 - external/opal-prd: Use "official" switch-endian syscall
 - hw/ipmi: Rework sensors and fix boot count sensor

Changes in rc1 (since 4.1.1):

General:

  * big OPAL API documentation updates
    We now document around 19 OPAL calls. There's still ~100 left to doc
    though :)
  * skiboot can load FreeBSD kernel payload (thanks to Nathan Whitehorn)
  * You can now run sparse by setting C=1 when building
  * PSI: Revert the timeout for PSI link recovery to architected value
    now 30mins (prev 15)
  * cpuidle: Add validated metrics for idle states
  * core/flash: Add flash API
    OPAL_FLASH_(READ|WRITE|ERASE)
  * capi: Dynamically calculate which CAPP port to use
    no longer hardwired to PHB0
  * vpd: Use slca parent-child relationship to create vpd tree
  * opal: Do not overwrite same HMI event for multiple HMI errors.
    Now Linux will get a HMI event for each HMI error
  * HMI event v2 now includes information about checkstop
  * HMI improvements, handle more conditions gracefully:

    * TB residue error
    * TFMR firmware control error
    * TFMR parity
    * TFMR HDEC parity error
    * TFMR DEC parity error
    * TFMR SPURR/PURR parity error
    * TB residue and HDEC parity HMI errors on split core
  * hostservices: Cache lids prior to first load request
  * Warn when pollers are called with a lock held
    and keep track of lock depth.

    **NOTE:** This means we will get backtraces in skiboot msglog on FSP machines
    This is a KNOWN ISSUE and is largely harmless.
    There's still a couple that we haven't yet cleaned, these
    messages can be thought of as a TODO list for developers.

  * Don't run pollers in time_wait if lock held
  * pci: Don't hang if we have only one CPU
  * Detect recursive poller entry
  * General cleanup
  * Cleanup of opal.h so that we can have Linux and skiboot match
  * add sparse annotations to opal.h
  * Platform hooks for loading and preloading resources (LIDs)
    This lays the groundwork for cutting 4-20 seconds off boot in a
    future skiboot release.
  * Fix potential race when clearing OCC interrupt status
  * Add platform operation for reading sensors

    * add support to read core and memory buffer temperatures

Mambo/POWER8 Functional Simulator:

  * Replace is_mambo_chip() with a better quirks mechanism.
  * Don't hang if we only have one CPU and PCI.

BMC systems:

  * BMC can load payload from flash
  * IPMI on BMC systems: graceful poweroff and reboot
  * IPMI on BMC systems: watchdog timer support
  * IPMI on BMC systems: PNOR locking
  * Support for IPMI progress sensor
  * IPMI boot count sensor
  * capi: Rework microcode flash download and CAPP upload
    load microcode on non-fsp systems
  * NEW opal-prd userspace tool that handles PRD on non-FSP systems.
    and OPAL PRD calls to support it.
  * Improvements to opal-prd, libflash, and ipmi
  * ECC support in libflash
  * Load CAPI micro code, enabling CAPI on OpenPower systems.
  * Dynamically calculate which CAPP port to use, don't hardcode to PHB0
  * memboot flash backend

POWER8

  * add nx-842 coproc support

FSP systems:

  * Make abort() update sp attn area (like assert does)
    On FSP systems this gives better error logs/dumps when abort() is hit
  * FSP/LEDS: Many improvements and bug fixes
  * LED support for FSP machines
    Adds OPAL_LEDS_(GET|SET)_INDICATOR and device-tree bindings
  * Refactor of fsp-rtc
  * OCC loading fixes, including possible race condition where we would
    fail to IPL.

POWER7

  * Fix unsupported return code of OPAL_(UN)REGISTER_DUMP_REGION on P7
  * occ: Don't do bad XSCOMs on P7
    The OCC interrupt register only exists on P8, accessing it on P7 causes
    not only error logs but also causes PRD to eventually gard chips.
  * cpu: Handle opal_reinit_cpus() more gracefully on P7
    no longer generate error logs
  * libflash updates for openpower
  * misc code cleanup
  * add nx-842 coproc support
