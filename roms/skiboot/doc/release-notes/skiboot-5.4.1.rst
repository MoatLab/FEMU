.. _skiboot-5.4.1:

=============
skiboot-5.4.1
=============

skiboot-5.4.1 was released on Tuesday November 29th 2016. It replaces
:ref:`skiboot-5.4.0` as the current stable release.

Over :ref:`skiboot-5.4.0`, we have a few changes:

- Nuvoton i2c TPM driver: bug fixes and improvements, especially around
  timeouts and error handling.
- Limit number of "Poller recursion detected" errors to display.
  In some error conditions, we could spiral out of control on this
  and spend all of our time printing the exact same backtrace.
- slw: do SLW timer testing while holding xscom lock.
  In some situations without this, it could take long enough to get
  the xscom lock that the 1ms timeout would expire and we'd falsely
  think the SLW timer didn't work when in fact it did.
- p8i2c: Use calculated poll_interval when booting OPAL.
  Otherwise we'd default to 2seconds (TIMER_POLL) during boot on
  chips with a functional i2c interrupt, leading to slow i2c
  during boot (or hitting timeouts instead).
- i2c: More efficiently run TPM I2C operations during boot, avoiding hitting
  timeouts
- fsp: Don't recurse pollers in ibm_fsp_terminate
