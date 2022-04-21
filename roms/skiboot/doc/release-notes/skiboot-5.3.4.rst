skiboot-5.3.4
-------------

skiboot-5.3.4 was released on Tuesday September 13th, 2016.

This is the 5th stable release of skiboot 5.3, the new stable release of
skiboot (first released with 5.3.0 on August 2nd, 2016).

Skiboot 5.3.4 replaces skiboot-5.3.3 as the current stable version. It contains
a couple of bug fixes, specifically around failing XSCOMs.

Over skiboot-5.3.3, the following fixes are included:

- xscom: Initialize the data to a known value in xscom_read
  In case of error, don't leave the data random. It helps debugging when
  the user fails to check the error code. This happens due to a bug in the
  PRD wrapper app.
- xscom: Map all HMER status codes to OPAL errors
- centaur: Mark centaur offline after 10 consecutive access errors
  This avoids spamming the logs when the centaur is dead and PRD
  constantly tries to access it
- nvlink: Fix bad PE number check in error inject code path (<= rather than <)
