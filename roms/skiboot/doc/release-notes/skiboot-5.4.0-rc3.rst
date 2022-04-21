.. _skiboot-5.4.0-rc3:

=================
skiboot-5.4.0-rc3
=================

skiboot-5.4.0-rc3 was released on Wednesday November 2nd 2016. It is the
third release candidate of skiboot 5.4, which will become the new stable
release of skiboot following the 5.3 release, first released August 2nd 2016.

skiboot-5.4.0-rc3 contains all bug fixes as of :ref:`skiboot-5.3.7`
and :ref:`skiboot-5.1.18` (the currently maintained stable releases).

For how the skiboot stable releases work, see :ref:`stable-rules` for details.

Since this is a release candidate, it should *NOT* be put into production.

The current plan is to release a new release candidate every week until we
feel good about it. The aim is for skiboot-5.4.x to be in op-build v1.13, which
is due by November 23rd 2016.

Over :ref:`skiboot-5.4.0-rc2`, we have a few changes:

- pflash: Fail when file is larger than partition
  You can still shoot yourself in the foot by passing --force.
- core/flash: Don't do anything clever for OPAL_FLASH_{READ, WRITE, ERASE}
  This fixes a bug where opal-prd and opal-gard could fail.
  Fixes: `<https://github.com/open-power/skiboot/issues/44>`_
- boot-tests: force BMC to boot from non-golden side
- fast-reset: Send special reset sequence to operational CPUs only.
  Fixes fast-reset for cases where there are garded CPUs
- Secure/Trusted boot: be much clearer about what is being measured where.
- Secure/Trusted boot: be more resilient to disabled TPM(s).
- Secure/Trusted boot: The ``force-secure-mode`` NVRAM setting introduced
  temporarily in :ref:`skiboot-5.4.0-rc2` has changed behaviour. Now, by
  default, the ``secure-mode`` flag in the device tree is obeyed. As always,
  any skiboot NVRAM options are in no way ABI, API or supported and may cause
  unfinished verbose analogies to appear in release notes relating to the
  dangers of using developer only options.
- gard: Fix compiler warning on modern GCC targetting ARM 32-bit
- opal-prd: systemd scripts improvements, only run on supported systems
