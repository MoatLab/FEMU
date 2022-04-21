skiboot-5.3.6
-------------

skiboot-5.3.6 was released on Saturday September 17th, 2016.

This is the 7th stable release of skiboot 5.3, the new stable release of
skiboot (first released with 5.3.0 on August 2nd, 2016).

Skiboot 5.3.6 replaces skiboot-5.3.5 as the current stable version. It contains
one minor bug fix.

Over skiboot-5.3.5, the following fixes are included:

- SLW: Actually print the register dump only to memory
  A fix in 5.3.5 was only partially correct, we still had the log priority
  incorrect for dumping of the SLW registers.
