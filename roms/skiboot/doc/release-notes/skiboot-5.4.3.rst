.. _skiboot-5.4.3:

=============
skiboot-5.4.3
=============

skiboot-5.4.3 was released on Monday January 16th, 2017. It replaces
:ref:`skiboot-5.4.2` as the current stable release.

Over :ref:`skiboot-5.4.2`, we have a small number of bug fixes:

- Makefile: Disable stack protector due to gcc problems
- Makefile: Use -ffixed-r13.
  We use r13 for our own stuff, make sure it's properly fixed
- phb3: Lock the PHB on set_xive callbacks
- arch_flash_arm: Don't assume mtd labels are short
- Stop using 3-operand cmp[l][i] for latest binutils
- hw/phb3: fix error handling in complete reset
