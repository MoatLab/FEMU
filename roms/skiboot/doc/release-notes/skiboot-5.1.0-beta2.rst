skiboot-5.1.0-beta2
===================

skiboot-5.1.0-beta2 was released on August 14th, 2015.

skiboot-5.1.0-beta2 is the second beta release of skiboot 5.1, which will
become a new stable release, replacing skiboot-5.0 (released April 14th 2015)

Skiboot 5.1.0-beta2 contains all fixes from skiboot-5.0 stable branch up to
skiboot-5.0.5 and everything from 5.1.0-beta1.

New Features
^^^^^^^^^^^^

Over skiboot-5.1.0-beta1, the following features have been added:

- opal-api: Add OPAL call to handle abnormal reboots.
     OPAL_CEC_REBOOT2
     Currently it will support two reboot types (0). normal reboot, that
     will behave similar to that of opal_cec_reboot() call, and
     (1). platform error reboot.

     Long term, this is designed to replace OPAL_CEC_REBOOT.

Bug fixes
^^^^^^^^^
Over skiboot-5.1.0-beta1, the following bugs have been fixed:

- external/opal-prd: Only map each PRD range once

  - could eventually lead to failing to map PRD ranges
- On skiboot crash, don't try to print symbol when we didn't find one

  - makes backtrace prettier
- On skiboot crash, dump hssr0 and hsrr1 registers correctly.
- Better support old and biarch compilers

  - test "new" compiler flags before using them
  - Specify -mabi=elfv1 if supported (which means it's needed)
- fix boot-coverage-report makefile target
- ipmi: Fix the opal_ipmi_recv() call to handle the error path

  - Could make kernel a sad panda when in continues with other IPMI commands
- IPMI: truncate SELs at 2kb

  - it's the limit of the astbmc. We think.
- IPMI/SEL/PEL:

  - As per PEL spec, we should log events with severity >= 0x22 and "service
    action flag" is "on". But in our case, all logs OPAL originagted logs
    are makred as report externally.
    We now only report logs with severity >= 0x22
- IPMI: fixes to eSEL logging
- hw/phb3: Change reserved PE to 255

  -  Currently, we have reserved PE#0 to which all RIDs are mapped prior
     to PE assignment request from kernel. The last M64 BAR is configured
     to have shared mode. So we have to cut off the first M64 segment,
     which corresponds to reserved PE#0 in kernel. If the first BAR
     (for example PF's IOV BAR) requires huge alignment in kernel, we
     have to waste huge M64 space to accommodate the alignment. If we
     have reserved PE#256, the waste of M64 space will be avoided.

Other changes
^^^^^^^^^^^^^
- unified version numbers for bundled utilities
- external/boot_test/boot_test.sh

  - better usable for automated boot testing
