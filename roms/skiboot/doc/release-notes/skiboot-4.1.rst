.. _skiboot-4.1:

===========
skiboot 4.1
===========

Skiboot 4.1 was released 10th December 2014. It was a release where more
development transitioned to the open source mailing list rather than internal
mailing lists.

Changes include:

 - We now build with -fstack-protector and -Werror
 - Stack checking extensions when built with STACK_CHECK=1
 - Reduced stack usage in some areas, -Wstack-usage=1024 now.

   - Some functions could use 2kb stack, now all are <1kb
 - Unsafe libc functions such as sprintf() have been removed
 - Symbolic backtraces
 - expose skiboot symbol map to OS (via device-tree)
 - removed machine check interrupt patching in OPAL
 - occ/hbrt: Call stopOCC() for implementing reset OCC command from FSP
 - occ: Fix the low level ACK message sent to FSP on receiving {RESET/LOAD}_OCC
 - hardening to errors of various FSP code

   - fsp: Avoid NULL dereference in case of invalid class_resp bits-
     abort if device tree parsing fails
   - FSP: Validate fsp_msg in fsp_queue_msg
   - fsp-elog: Add various NULL checks
 - Finessing of when to use error log vs prerror()
 - More i2c work
 - Can now run under Mambo simulator (see external/mambo/skiboot.tcl)
   (commonly known as "POWER8 Functional Simulator")
 - Document skiboot versioning scheme
 - opal: Handle more TFAC errors.

   - TB_RESIDUE_ERR, FW_CONTROL_ERR and CHIP_TOD_PARITY_ERR
 - ipmi: populate FRU data
 - rtc: Add a generic rtc cache
 - ipmi/rtc: use generic cache
 - Error Logging backend for bmc based machines
 - PSI: Drive link down on HIR
 - occ: Fix clearing of OCC interrupt on remote fix
