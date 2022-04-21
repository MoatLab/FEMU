skiboot-5.3.1
-------------

skiboot-5.3.1 was released on Wednesday August 10th, 2016.

This is the 2nd stable release of skiboot 5.3, the new stable release of
skiboot (first released with 5.3.0 on August 2nd, 2016).

Skiboot 5.3.1 replaces skiboot-5.3.0 as the current stable version. It contains
a few minor bug fixes.

This release follows the Skiboot stable rules, see :ref:`stable-rules`.

Over skiboot-5.3.0, the following fixes are included:

FSP systems:

- FSP/ELOG: elog_enable flag should be false by default
    This issue is one of the corner case, which is related to recent change
    went upstream and only observed in the petitboot prompt, where we see
    only one error log instead of getting all error log in
    /sys/firmware/opal/elog.

NVLink systems (i.e. Garrison):

- npu: reword "error" to indicate it's actually a warning
    Without this patch, you get spurious FirmWare Test Suite (FWTS) warnings
    about NVLink not working on machines that aren't fully populated with
    GPUs.
- hmi: Clean up NPU FIR debug messages
    With the skiboot log set to debug, the FIR (and related registers) were
    logged all in the same message.  It was too much for one line, didn't
    clarify if the numbers were in hex, and didn't show leading zeroes.

General:

- asm: Fix backtrace for unexpected exception
- correct the log level from PR_ERROR down to PR_INFO for some skiboot
  log messages.
