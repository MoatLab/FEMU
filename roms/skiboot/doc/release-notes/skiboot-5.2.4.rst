skiboot-5.2.4
=============

skiboot-5.2.4 was released on Tuesday July 12th, 2016.

This is the 5th stable release of skiboot 5.2, the new stable release of
skiboot (first release with 5.2.0 on March 16th 2016).

Skiboot 5.2.4 replaces skiboot-5.2.3 as the current stable version, which was
released on June 30th 2016. Over skiboot-5.2.3, skiboot 5.2.4 contains bug
fixes to make skiboot more resilient to errors in the XSCOM engine and some
build improvements for the pflash utility.

skiboot-5.2.4 contains all bug fixes as of skiboot-5.1.16.

This is the second release that will follow the (now documented) Skiboot
stable rules - see :ref:`stable-rules`.

Over skiboot-5.2.3, the following fixes are included:

All platforms
^^^^^^^^^^^^^

- Make the XSCOM engine code more resilient to errors:

  - hw/xscom: Reset XSCOM engine after querying sleeping core FIR
  - hw/xscom: Reset XSCOM engine after finite number of retries when busy

Userspace utilities
^^^^^^^^^^^^^^^^^^^

- pflash build improvements
