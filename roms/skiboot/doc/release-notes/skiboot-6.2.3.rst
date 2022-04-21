.. _skiboot-6.2.3:

=============
skiboot-6.2.3
=============

skiboot 6.2.3 was released on Tuesday March 19th, 2019. It replaces
:ref:`skiboot-6.2.2` as the current stable release in the 6.2.x series.

It is recommended that 6.2.3 be used instead of any previous 6.2.x version
due to the bug fixes it contains.

Bug fixes included in this release are:

- p9dsu: Undo slot label name changes

  During some code updates the slot labels were updated to reflect
  the phb layout, however expectations were that the slot labels be
  aligned with the riser card slots and not the system planar slots.

  [stewart: The tale of how we got here is long and varied and not at
  all clear. The first ESS systems went out with a skiboot v5.9.8 with
  additional SuperMicro patches. It was probably a slot table, but who knows,
  we don't have the code so can't check. It's possible it was all coming
  in through HDAT instead). The op-build tree (thus the exact patches)
  shipped on systems that work correct seems to not be around anywhere anymore
  (if it ever was). It was only in skiboot v6.0 that a slot table made
  it in, and, of course, only having remote machines in random configs,
  including possibly with riser cards from Briggs&Stratton rather than
  the ones destined for this system, doesn't make for verifying this
  at all. It also doesn't help that *consistently* there is *never*
  any review on slot tables, and we've had things be wrong in the past.
  Combine this with not upstream Hostboot patches.]

- p9dsu: Fix slot labels for p9dsu2u

  Update the slot labels for the p9dsu2u tables.

- fast-reboot: occ: Call occ_pstates_init() on fast-reset on all machines

  Commit 815417dcda2e ("init, occ: Initialise OCC earlier on BMC systems")
  conditionally invoked occ_pstates_init() only on FSP based systems in
  load_and_boot_kernel(). Due to this pstate table is re-parsed on FSP
  system and skipped on BMC system during fast-reboot. So this patch fixes
  this by invoking occ_pstates_init() on all boxes during fast-reboot.
