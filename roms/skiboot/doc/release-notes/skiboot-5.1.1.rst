skiboot-5.1.1
-------------

skiboot-5.1.1 was released on August 18th, 2015.

skiboot-5.1.1 is the send stable release of 5.1, it follows skiboot-5.1.0.

Skiboot 5.1.1 contains all fixes from skiboot-5.1.0 and is a minor bugfix
release.

Changes
^^^^^^^
Over skiboot-5.1.0, we have the following changes:

- Fix detection of compiler options on ancient GCC (e.g. gcc 4.4, shipped with
  RHEL6)
- ensure the GNUC version defines for GCOV are coming from target CC rather
  than host CC for extract-gcov
- phb3: Continue CAPP setup even if PHB is already in CAPP mode
  This fixes a critical bug in CAPI support.

  CAPI requires that all faults are escalated into a fence, not a
  freeze. This is done by setting bits in a number of MMIO
  registers. phb3_set_capi_mode() calls phb3_init_capp_errors() to do
  this. However, if the PHB is already in CAPP mode - for example in the
  recovery case - phb3_set_capi_mode() will bail out early, and those
  registers will not be set.

  This is quite easy to verify. PCI config space access errors, for
  example, normally cause a freeze. On a CAPI-mode PHB, they should
  cause a fence. Say we have a CAPI card on PHB 0, and we inject a
  PCI config space error: ::

   echo 0x8000000000000000 > /sys/kernel/debug/powerpc/PCI0000/err_injct_inboundA;
   lspci;

  The first time we inject this, the PHB will fence and recover, but
  won't reset the registers. Therefore, the second time we inject it,
  we will incorrectly freeze, not fence.

  Worse, the recovery for the resultant EEH freeze event interacts
  poorly with the CAPP, triggering an EEH recovery of the PHB. The
  combination of the two attempted recoveries will get the PHB into
  an inoperable state.
