.. _skiboot-6.0.17:

==============
skiboot-6.0.17
==============

skiboot 6.0.17 was released on Wednesday February 20th, 2019. It replaces
:ref:`skiboot-6.0.16` as the current stable release in the 6.0.x series.

It is recommended that 6.0.17 be used instead of any previous 6.0.x version
due to the bug fixes it contains.

Bug fixes included in this release are:

- core/opal: Print PIR value in exit path, which is useful for debugging.
- core/ipmi: Improve error message
- hdata: Fix dtc warnings

  Fix dtc warnings related to mcbist node ::

    Warning (reg_format): "reg" property in /xscom@623fc00000000/mcbist@1 has invalid length (4 bytes) (#address-cells == 1, #size-cells == 1)
    Warning (reg_format): "reg" property in /xscom@623fc00000000/mcbist@2 has invalid length (4 bytes) (#address-cells == 1, #size-cells == 1)
    Warning (reg_format): "reg" property in /xscom@603fc00000000/mcbist@1 has invalid length (4 bytes) (#address-cells == 1, #size-cells == 1)
    Warning (reg_format): "reg" property in /xscom@603fc00000000/mcbist@2 has invalid length (4 bytes) (#address-cells == 1, #size-cells == 1)

  Ideally we should add proper xscom range here... but we are not getting that
  information in HDAT today. Lets fix warning until we get proper data in HDAT.
- hdata/test: workaround dtc bugs

  In dtc v1.4.5 to at least v1.4.7 there have been a few bugs introduced
  that change the layout of what's produced in the dts. In order to be
  immune from them, we should use the (provided) dtdiff utility, but we
  also need to run the dts we're diffing against through a dtb cycle in
  order to ensure we get the same format as what the hdat_to_dt to dts
  conversion will.

  This fixes a bunch of unit test failures on the version of dtc shipped
  with recent Linux distros such as Fedora 29.
- firmware-versions: Add test case for parsing VERSION

  Also make it possible to use with afl-lop/afl-fuzz just to help make
  *sure* we're all good.

  Additionally, if we hit a entry in VERSION that is larger than our
  buffer size, we skip over it gracefully rather than overwriting the
  stack. This is only a problem if VERSION isn't trusted, which as of
  4b8cc05a94513816d43fb8bd6178896b430af08f it is verified as part of
  Secure Boot.
- core/cpu: HID update race

  If the per-core HID register is updated concurrently by multiple
  threads, updates can get lost. This has been observed during fast
  reboot where the HILE bit does not get cleared on all cores, which
  can cause machine check exception interrupts to crash.

  Fix this by only updating HID on thread0.
- cpufeatures: Always advertise POWER8NVL as DD2

  Despite the major version of PVR being 1 (0x004c0100) for POWER8NVL,
  these chips are functionally equalent to P8/P8E DD2 levels.

  This advertises POWER8NVL as DD2. As the result, skiboot adds
  ibm,powerpc-cpu-features/processor-control-facility for such CPUs and
  the linux kernel can use hypervisor doorbell messages to wake secondary
  threads; otherwise "KVM: CPU %d seems to be stuck" would appear because
  of missing LPCR_PECEDH.
