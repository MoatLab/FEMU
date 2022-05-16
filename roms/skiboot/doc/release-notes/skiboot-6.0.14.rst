.. _skiboot-6.0.14:

==============
skiboot-6.0.14
==============

skiboot 6.0.14 was released on Tuesday November 27th, 2018. It replaces
:ref:`skiboot-6.0.13` as the current stable release in the 6.0.x series.

It is recommended that 6.0.14 be used instead of any previous 6.0.x version
due to the bug fixes it contains.

Bug fixes included in this release are:

- libflash: Don't merge ECC-protected ranges

  Libflash currently merges contiguous ECC-protected ranges, but doesn't
  check that the ECC bytes at the end of the first and start of the second
  range actually match sanely. More importantly, if blocklevel_read() is
  called with a position at the start of a partition that is contained
  somewhere within a region that has been merged it will update the
  position assuming ECC wasn't being accounted for. This results in the
  position being somewhere well after the actual start of the partition
  which is incorrect.

  For now, remove the code merging ranges. This means more ranges must be
  held and checked however it prevents incorrectly reading ECC-correct
  regions like below: ::

    [  174.334119453,7] FLASH: CAPP partition has ECC
    [  174.437349574,3] ECC: uncorrectable error: ffffffffffffffff ff
    [  174.437426306,3] FLASH: failed to read the first 0x1000 from CAPP partition, rc 14
    [  174.439919343,3] CAPP: Error loading ucode lid. index=201d1

- ipmi: Reduce ipmi_queue_msg_sync() polling loop time to 10ms.

  On a plain boot with hiomap, this reduces the time spent in OPAL
  by ~170ms on p9dsu. This is due to hiomap (currently) using
  synchronous IPMI messages.

  It will also *significantly* reduce latency on runtime flash
  operations with hiomap, as we'll spend typically 10-20ms in OPAL
  rather than 100-200ms. It's not an ideal solution to that, but
  it's a quick and obvious win for jitter.

- opal-prd: Fix opal-prd crash

  Crash log without this patch: ::

      opal-prd[2864]: unhandled signal 11 at 0000000000029320 nip 00000 00102012830 lr 0000000102016890 code 1
