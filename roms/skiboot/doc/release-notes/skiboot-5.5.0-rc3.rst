.. _skiboot-5.5.0-rc3:

skiboot-5.5.0-rc3
=================

skiboot-5.5.0-rc3 was released on Wednesday April 5th 2017. It is the third
release candidate of skiboot 5.5, which will become the new stable release
of skiboot following the 5.4 release, first released November 11th 2016.

skiboot-5.5.0-rc3 contains all bug fixes as of :ref:`skiboot-5.4.3`
and :ref:`skiboot-5.1.19` (the currently maintained stable releases).

For how the skiboot stable releases work, see :ref:`stable-rules` for details.

The current plan is to cut the final 5.5.0 by April 8th, with skiboot 5.5.0
being for all POWER8 and POWER9 platforms in op-build v1.16 (Due April 12th).
This is a short cycle as this release is mainly targetted towards POWER9
bringup efforts.

Following skiboot-5.5.0, we will move to a regular six week release cycle,
similar to op-build, but slightly offset to allow for a short stabilisation
period. Expected release dates and contents are tracked using GitHub milestone
and issues: https://github.com/open-power/skiboot/milestones

Over :ref:`skiboot-5.5.0-rc2`, we have the following changes:

- xive: Fix setting of remote NVT VSD

  This fixes a checkstop when using my XIVE exploitation mode on some multi-chip machines.

- core/init: Use '_' as separator in names of "exports" properties

  The names of the properties under /ibm,opal/firmware/exports are used
  directly by Linux to create files in sysfs. To remain consistent with
  the existing naming of OPAL sysfs files, use '_' as the separator.

  In particular for the symbol map which is already exported separately,
   it's cleaner for the two files to have the same name, eg: ::

      /sys/firmware/opal/exports/symbol_map
      /sys/firmware/opal/symbol_map

- hdata: fix reservation size

  The hostboot reserved ranges are [start, end] pairs rather than
  [start, end) so we need to stick a +1 in there to calculate the
  size properly.

- hdat: Add model-name property for OpenPower system
- hdat: Read description from ibm, vpd binary blob
- hdat: Populate model property with 'Unknown' in error path
