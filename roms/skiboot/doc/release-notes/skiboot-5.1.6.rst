skiboot-5.1.6
=============

skiboot-5.1.6 was released on October 8th, 2015.

skiboot-5.1.6 is the 7th stable release of 5.1, it follows skiboot-5.1.5
(which was released October 1st, 2015).

Skiboot 5.1.6 contains all fixes from skiboot-5.1.5 and is a minor bug
fix release.

Changes
-------
Over skiboot-5.1.5, we have the following changes:

Generic:
^^^^^^^^

- Ensure we run pollers in cpu_wait_job()

  In root causing a bug on AST BMC Alistair found that pollers weren't
  being run for around 3800ms.

  This could show as not resetting the boot count sensor on successful
  boot.

AST BMC Machines
^^^^^^^^^^^^^^^^

- hw/bt.c: Check for timeout after checking for message response

  When deciding if a BT message has timed out we should first check for
  a message response. This will ensure that messages will not time out
  if there was a delay calling the pollers.

  This could show as not resetting the boot count sensor on successful
  boot.
