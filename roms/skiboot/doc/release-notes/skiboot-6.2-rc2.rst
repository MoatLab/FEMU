.. _skiboot-6.2-rc2:

skiboot-6.2-rc2
===============

skiboot v6.2-rc2 was released on Thursday November 29th 2018. It is the second
release candidate of skiboot 6.2, which will become the new stable release
of skiboot following the 6.1 release, first released July 11th 2018.

Skiboot 6.2 will mark the basis for op-build v2.2.

skiboot v6.2-rc2 contains all bug fixes as of :ref:`skiboot-6.0.14`,
and :ref:`skiboot-5.4.10` (the currently maintained
stable releases).

For how the skiboot stable releases work, see :ref:`stable-rules` for details.

Over :ref:`skiboot-6.2-rc1`, we have the following changes:

- npu2-opencapi: Log extra information on link training failure
- npu2-opencapi: Detect if link trained in degraded mode
- platform/firenze: Fix branch-to-null crash

  When the bus alloc and free methods were removed we missed a case in the
  Firenze platform slot code that relied on the the bus-specific method to
  the bus pointer in the request structure. This results in a
  branch-to-null during boot and a crash. This patch fixes it by
  initialising it manually here.
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

- libflash: Restore blocklevel tests

  This fell out in f58be46 "libflash/test: Rewrite Makefile.check to
  improve scalability". Add it back in as test-blocklevel.
- Warn on long OPAL calls

  Measure entry/exit time for OPAL calls and warn appropriately if the
  calls take too long (>100ms gets us a DEBUG log, > 1000ms gets us a
  warning).

CI, testing, and utilities
--------------------------

- travis: Coverity fixed their SSL cert
- opal-ci: Use ubuntu:rolling for Ubuntu latest image
- ffspart: Add test for eraseblock size
- ffspart: Add toc test
- hdata/test: workaround dtc bugs

  In dtc v1.4.5 to at least v1.4.7 there have been a few bugs introduced
  that change the layout of what's produced in the dts. In order to be
  immune from them, we should use the (provided) dtdiff utility, but we
  also need to run the dts we're diffing against through a dtb cycle in
  order to ensure we get the same format as what the hdat_to_dt to dts
  conversion will.

  This fixes a bunch of unit test failures on the version of dtc shipped
  with recent Linux distros such as Fedora 29.
