.. _skiboot-5.9.7:

=============
skiboot-5.9.7
=============

skiboot 5.9.7 was released on Friday December 22nd, 2017. It replaces
:ref:`skiboot-5.9.6` as the current stable release in the 5.9.x series.

Over :ref:`skiboot-5.9.6`, we have two bug fixes, they are:

- phb4: Change PCI MMIO timers

  Currently we have a mismatch between the NCU and PCI timers for MMIO
  accesses. The PCI timers must be lower than the NCU timers otherwise
  it may cause checkstops.

  This changes PCI timeouts controlled by skiboot to 33-50ms. It should
  be forwards and backwards compatible with expected hostboot changes to
  the NCU timer.
- p8-i2c: Limit number of retry attempts

  Currently we will attempt to start an I2C transaction until it succeeds.
  In the event that the OCC does not release the lock on an I2C bus this
  results in an async token being held forever and the kernel thread that
  started the transaction will block forever while waiting for an async
  completion message. Fix this by limiting the number of attempts to
  start the transaction.
