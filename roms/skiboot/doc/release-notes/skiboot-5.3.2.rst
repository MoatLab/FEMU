skiboot-5.3.2
-------------

skiboot-5.3.2 was released on Friday August 26th, 2016.

This is the 3rd stable release of skiboot 5.3, the new stable release of
skiboot (first released with 5.3.0 on August 2nd, 2016).

Skiboot 5.3.2 replaces skiboot-5.3.1 as the current stable version. It contains
a few minor bug fixes.

Over skiboot-5.3.1, the following fixes are included:

- opal/hmi: Fix a TOD HMI failure during a race condition.
  Rare race condition which meant we wouldn't recover from TOD error

- lpc: Log LPC SYNC errors as unrecoverable ones for manufacturing
  Only affects systems in manufacturing mode.
  No behaviour change when not in manufacturing mode.

- hw/phb3: Update capi initialization sequence
  The capi initialization sequence was revised in a circumvention
  document when a 'link down' error was converted from fatal to Endpoint
  Recoverable. Other, non-capi, register setup was corrected even before
  the initial open-source release of skiboot, but a few capi-related
  registers were not updated then, so this patch fixes it.
  The point is that a link-down error detected by the UTL logic will
  lead to an AIB fence, so that the CAPP unit can detect the error.
