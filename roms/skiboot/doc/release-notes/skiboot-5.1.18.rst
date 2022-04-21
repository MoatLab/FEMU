.. _skiboot-5.1.18:

skiboot-5.1.18
--------------

skiboot-5.1.18 was released on Friday 26th August 2016.

skiboot-5.1.18 is the 19th stable release of 5.1, it follows skiboot-5.1.17
(which was released July 21st, 2016).

This release contains a few minor bug fixes.

Changes are:

All platforms:

- opal/hmi: Fix a TOD HMI failure during a race condition.
  Rare race condition which meant we wouldn't recover from TOD error

- hw/phb3: Update capi initialization sequence
  The capi initialization sequence was revised in a circumvention
  document when a 'link down' error was converted from fatal to Endpoint
  Recoverable. Other, non-capi, register setup was corrected even before
  the initial open-source release of skiboot, but a few capi-related
  registers were not updated then, so this patch fixes it.
  The point is that a link-down error detected by the UTL logic will
  lead to an AIB fence, so that the CAPP unit can detect the error.

FSP platforms:

- FSP/ELOG: Fix OPAL generated elog resend logic
- FSP/ELOG: Fix possible event notifier hangs
- FSP/ELOG: Disable event notification if list is not consistent
- FSP/ELOG: Fix OPAL generated elog event notification
- FSP/ELOG: Disable event notification during kexec
