.. _skiboot-5.9.9:

=============
skiboot-5.9.9
=============

skiboot 5.9.9 was released on Monday May 28th, 2018. It replaces
:ref:`skiboot-5.9.8` as the current stable release in the 5.9.x series.

Over :ref:`skiboot-5.9.8`, we have two bug fixes and a build fix, they are:

- OPAL_PCI_SET_POWER_STATE: fix locking in error paths

  Otherwise we could exit OPAL holding locks, potentially leading
  to all sorts of problems later on.
- lpc: Clear pending IRQs at boot

  When we come in from hostboot the LPC master has the bus reset indicator
  set. This error isn't handled until the host kernel unmasks interrupts,
  at which point we get the following suprious error: ::

    [   20.053560375,3] LPC: Got LPC reset on chip 0x0 !
    [   20.053564560,3] LPC[000]: Unknown LPC error Error address reg: 0x00000000

  Fix this by clearing the various error bits in the LPC status register
  before we initalise the skiboot LPC bus driver.
- stb: Build fixes in constructing secure and trusted boot header
