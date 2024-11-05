.. _skiboot-6.0.12:

==============
skiboot-6.0.12
==============

skiboot 6.0.12 was released on Monday November 12th, 2018. It replaces
:ref:`skiboot-6.0.11` as the current stable release in the 6.0.x series.

It is recommended that 6.0.12 be used instead of any previous 6.0.x version
due to the bug fixes it contains.

The bug fixes are:

- hiomap: quieten warning on failing to move a window

  This isn't *necessarily* an error that we should complain loudly about.
  If, for example, the BMC enforces the Read Only flag on a FFS partition,
  opening a write window *should* fail, and we do indeed test this in
  op-test.

  Thus we deal with the error in a well known path: returning an error
  code and then it's eventually a userspace problem.
- libflash/ipmi-hiomap: Respect daemon presence and flash control
