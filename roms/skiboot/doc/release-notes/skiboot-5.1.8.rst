skiboot-5.1.8
-------------

skiboot-5.1.8 was released on October 19th, 2015.

skiboot-5.1.8 is the 9th stable release of 5.1, it follows skiboot-5.1.7
(which was released October 13th, 2015).

Skiboot 5.1.8 contains all fixes from skiboot-5.1.7 and is a minor bug
fix release, with a single fix for recovery from a (rare) error.

Over skiboot-5.1.7, we have the following change:

- opal/hmi: Fix a soft lockup issue on Hypervisor Maintenance Interrupt
  for certain timebase errors.

  We also introduce a timeout to handle the worst situation where all other
  threads are badly stuck without setting a cleanup done bit. Under such
  situation timeout will help to avoid soft lockups and report failure to
  kernel.
