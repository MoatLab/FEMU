.. _skiboot-5.10-rc4:

skiboot-5.10-rc4
================

skiboot v5.10-rc4 was released on Wednesday February 21st 2018. It is the fourth
release candidate of skiboot 5.10, which will become the new stable release
of skiboot following the 5.9 release, first released October 31st 2017.

skiboot v5.10-rc4 contains all bug fixes as of :ref:`skiboot-5.9.8`
and :ref:`skiboot-5.4.9` (the currently maintained stable releases). There
may be more 5.9.x stable releases, it will depend on demand.

For how the skiboot stable releases work, see :ref:`stable-rules` for details.

The current plan is to cut the final 5.10 in February, with skiboot 5.10
being for all POWER8 and POWER9 platforms in op-build v1.21.
This release will be targeted to early POWER9 systems.

Over skiboot-5.10-rc3, we have the following changes:

- core: Fix mismatched names between reserved memory nodes & properties

  OPAL exposes reserved memory regions through the device tree in both new
  (nodes) and old (properties) formats.

  However, the names used for these don't match - we use a generated cell
  address for the nodes, but the plain region name for the properties.

  This fixes a warning from FWTS
- sensor-groups: occ: Add support to disable/enable sensor group

  This patch adds a new opal call to enable/disable a sensor group. This
  call is used to select the sensor groups that needs to be copied to
  main memory by OCC at runtime.
- sensors: occ: Add energy counters

  Export the accumulated power values as energy sensors. The accumulator
  field of power sensors are used for representing energy counters which
  can be exported as energy counters in Linux hwmon interface.
- sensors: Support reading u64 sensor values

  This patch adds support to read u64 sensor values. This also adds
  changes to the core and the backend implementation code to make this
  API as the base call. Host can use this new API to read sensors
  upto 64bits.

  This adds a list to store the pointer to the kernel u32 buffer, for
  older kernels making async sensor u32 reads.
- dt: add /cpus/ibm,powerpc-cpu-features device tree bindings

  This is a new CPU feature advertising interface that is fine-grained,
  extensible, aware of privilege levels, and gives control of features
  to all levels of the stack (firmware, hypervisor, and OS).

  The design and binding specification is described in detail in doc/.
- phb3/phb4/p7ioc: Document supported TCE sizes in DT

  Add a new property, "ibm,supported-tce-sizes", to advertise to Linux how
  big the available TCE sizes are.  Each value is a bit shift, from
  smallest to largest.
- phb4: Fix TCE page size

  The page sizes for TCEs on P9 were inaccurate and just copied from PHB3,
  so correct them.
- Revert "pci: Shared slot state synchronisation for hot reset"

  An issue was found in shared slot reset where the system can be stuck in
  an infinite loop, pull the code out until there's a proper fix.

  This reverts commit 1172a6c57ff3c66f6361e572a1790cbcc0e5ff37.
- hdata/iohub: Use only wildcard slots for pluggables

  We don't want to cause a VID:DID check against pluggable devices, as
  they may use multiple devids.

  Narrow the condition under which VID:DID is listed in the dt, so that
  we'll end up creating a wildcard slot for these instead.
- increase log verbosity in debug builds
- Add -debug to version on DEBUG builds
- cpu_wait_job: Correctly report time spent waiting for job
