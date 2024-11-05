.. _skiboot-5.9.5:

=============
skiboot-5.9.5
=============

skiboot 5.9.5 was released on Wednesday December 13th, 2017. It replaces
:ref:`skiboot-5.9.4` as the current stable release in the 5.9.x series.

Over :ref:`skiboot-5.9.4`, we have a few bug fixes, they are:

- Fix *extremely* rare race in timer code.
- xive: Ensure VC informational FIRs are masked

  Some HostBoot versions leave those as checkstop, they are harmless
  and can sometimes occur during normal operations.
- xive: Fix occasional VC checkstops in xive_reset

  The current workaround for the scrub bug described in
  __xive_cache_scrub() has an issue in that it can leave
  dirty invalid entries in the cache.

  When cleaning up EQs or VPs during reset, if we then
  remove the underlying indirect page for these entries,
  the XIVE will checkstop when trying to flush them out
  of the cache.

  This replaces the existing workaround with a new pair of
  workarounds for VPs and EQs:

  - The VP one does the dummy watch on another entry than
    the one we scrubbed (which does the job of pushing old
    stores out) using an entry that is known to be backed by
    a permanent indirect page.
  - The EQ one switches to a more efficient workaround
    which consists of doing a non-side-effect ESB load from
    the EQ's ESe control bits.
- io: Add load_wait() helper

  This uses the standard form twi/isync pair to ensure a load
  is consumed by the core before continuing. This can be necessary
  under some circumstances for example when having the following
  sequence:

  - Store reg A
  - Load reg A (ensure above store pushed out)
  - delay loop
  - Store reg A

  IE, a mandatory delay between 2 stores. In theory the first store
  is only guaranteed to rach the device after the load from the same
  location has completed. However the processor will start executing
  the delay loop without waiting for the return value from the load.

  This construct enforces that the delay loop isn't executed until
  the load value has been returned.
- xive: Do not return a trigger page for an escalation interrupt

  This is bogus, we don't support them. (Thankfully the callers
  didn't actually try to use this on escalation interrupts).
- xive: Mark a freed IRQ's IVE as valid and masked

  Removing the valid bit means a FIR will trip if it's accessed
  inadvertently. Under some circumstances, the XIVE will speculatively
  access an IVE for a masked interrupt and trip it. So make sure that
  freed entries are still marked valid (but masked).
- hw/nx: Fix NX BAR assignments

  The NX rng BAR is used by each core to source random numbers for the
  DARN instruction. Currently we configure each core to use the NX rng of
  the chip that it exists on. Unfortunately, the NX can be deconfigured by
  hostboot and in this case we need to use the NX of a different chip.

  This patch moves the BAR assignments for the NX into the normal nx-rng
  init path. This lets us check if the normal (chip local) NX is active
  when configuring which NX a core should use so that we can fallback
  gracefully.
