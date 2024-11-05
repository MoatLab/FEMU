.. _skiboot-5.4.7:

=============
skiboot-5.4.7
=============

skiboot-5.4.7 was released on Tuesday September 19th, 2017. It replaces
:ref:`skiboot-5.4.6` as the current stable release in the 5.4.x series.

Over :ref:`skiboot-5.4.6`, we have two backported bug fixes for FSP platforms:

- FSP: Add check to detect FSP Reset/Reload inside fsp_sync_msg()

  During FSP Reset/Reload we move outstanding MBOX messages from msgq to
  rr_queue including inflight message (fsp_reset_cmdclass()). But we are not
  resetting inflight message state.

  In extreme corner case where we sent message to FSP via fsp_sync_msg() path
  and FSP Reset/Reload happens before getting respose from FSP, then we will
  endup waiting in fsp_sync_msg() until everything becomes normal.

  This patch adds fsp_in_rr() check to fsp_sync_msg() and return error to
  caller if FSP is in R/R.

- platforms/ibm-fsp/firenze: Fix PCI slot power-off pattern

  When powering off the PCI slot, the corresponding bits should
  be set to 0bxx00xx00 instead of 0bxx11xx11. Otherwise, the
  specified PCI slot can't be put into power-off state. Fortunately,
  it didn't introduce any side-effects so far.
