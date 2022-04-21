.. _skiboot-6.0.11:

==============
skiboot-6.0.11
==============

skiboot 6.0.11 was released on Friday November 2nd, 2018. It replaces
:ref:`skiboot-6.0.10` as the current stable release in the 6.0.x series.

It is recommended that 6.0.11 be used instead of any previous 6.0.x version
due to the bug fixes it contains.

The bug fixes are:

- phb4/capp: Only reset FIR bits that cause capp machine check

  During CAPP recovery do_capp_recovery_scoms() will reset the CAPP Fir
  register just after CAPP recovery is completed. This has an
  unintentional side effect of preventing PRD from analyzing and
  reporting this error. If PRD tries to read the CAPP FIR after opal has
  already reset it, then it logs a critical error complaining "No active
  error bits found".

  To prevent this from happening we update do_capp_recovery_scoms() to
  only reset fir bits that cause CAPP machine check (local xstop). This
  is done by reading the CAPP Fir Action0/1 & Mask registers and
  generating a mask which is then written on CAPP_FIR_CLEAR register.
- phb4: Check for RX errors after link training

  Some PHB4 PHYs can get stuck in a bad state where they are constantly
  retraining the link. This happens transparently to skiboot and Linux
  but will causes PCIe to be slow. Resetting the PHB4 clears the
  problem.

  We can detect this case by looking at the RX errors count where we
  check for link stability. This patch does this by modifying the link
  optimal code to check for RX errors. If errors are occurring we
  retrain the link irrespective of the chip rev or card.

  Normally when this problem occurs, the RX error count is maxed out at
  255. When there is no problem, the count is 0. We chose 8 as the max
  rx errors value to give us some margin for a few errors. There is also
  a knob that can be used to set the error threshold for when we should
  retrain the link. i.e. ::

      nvram -p ibm,skiboot --update-config phb-rx-err-max=8

- core/flash: Log return code when ffs_init() fails
- libflash/ipmi-hiomap: Use error codes rather than abort()
- libflash/ipmi-hiomap: Restore window state on window/protocol reset
- libflash/ipmi-hiomap: Improve event handling
- p9dsu: Describe platform BMC register configuration

  Provide the p9dsu-specific BMC configuration values required for the
  host kernel to drive the VGA display correctly.
- p9dsu: Add HIOMAP-over-IPMI support
- libflash/ipmi-hiomap: Cleanup allocation on init failure
