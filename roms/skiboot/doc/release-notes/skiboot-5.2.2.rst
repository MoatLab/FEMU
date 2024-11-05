skiboot-5.2.2
=============

skiboot-5.2.2 was released on Thursday May 5th, 2016.

skiboot-5.2.2 is the third stable release of skiboot 5.2, the new stable
release of skiboot, which will take over from the 5.1.x series which was
first released August 17th, 2015.

Skiboot 5.2.2 replaces skiboot-5.2.1 as the current stable version, which was
released on April 27th, 2016. Over skiboot-5.2.1, skiboot 5.2.2 contains
one bug fix targeted at P8NVL systems, notably the Garrison platform.

skiboot-5.2.2 contains all bug fixes as of skiboot-5.1.16.

This is the second release that will follow the (now documented) Skiboot
stable rules - see :ref:`stable-rules`.

Over skiboot-5.2.1, the following fixes are included:

P8NVL/Garrison
^^^^^^^^^^^^^^

- PHB3: Fix corruption of pref window register
    On P8+ Garrison platform, the root port's pref window register might
    be not writable and we have to emulate the window because of hardware
    defect. In order to detect that, we read the register content, write
    inversed value and read the register content again. The register is
    regarded as read-only if the values from the two continuous read are
    same. However, the original register content isn't written back and
    it causes corruption on pref window register if it's writable.

    This fixes the above issue by writing the original content back to
    the register at the end.
