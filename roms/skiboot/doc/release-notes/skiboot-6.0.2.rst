.. _skiboot-6.0.2:

=============
skiboot-6.0.2
=============

skiboot 6.0.2 was released on Friday May 18th, 2018. It replaces
:ref:`skiboot-6.0.1` as the current stable release in the 6.0.x series.

It is recommended that 6.0.2 be used instead of any previous 6.0.x version.

Over :ref:`skiboot-6.0.1`, we one bug fix:

- cpu: Clear PCR SPR in opal_reinit_cpus()

  Currently if Linux boots with a non-zero PCR, things can go bad where
  some early userspace programs can take illegal instructions. This is
  being fixed in Linux, but in the mean time, we should cleanup in
  skiboot also.

  This could exhibit itself as petitboot getting killed with SIGILL and
  no boot devices showing up, but only in a situation where you've done
  a kdump from a kernel running a p8 compat guest
