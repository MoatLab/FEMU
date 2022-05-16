.. _skiboot-5.1.21:

skiboot-5.1.21
--------------

skiboot-5.1.21 was released on Tuesday 19th September 2017.

skiboot-5.1.21 is the 22nd stable release of 5.1, it follows skiboot-5.1.20
(which was released 18th August 2017).

This release contains one backported bug fix to the 5.1.x series.

Changes are:

- FSP: Add check to detect FSP Reset/Reload inside fsp_sync_msg()

  During FSP Reset/Reload we move outstanding MBOX messages from msgq to
  rr_queue including inflight message (fsp_reset_cmdclass()). But we are not
  resetting inflight message state.

  In extreme corner case where we sent message to FSP via fsp_sync_msg() path
  and FSP Reset/Reload happens before getting respose from FSP, then we will
  endup waiting in fsp_sync_msg() until everything becomes normal.

  This patch adds fsp_in_rr() check to fsp_sync_msg() and return error to caller
  if FSP is in R/R.
