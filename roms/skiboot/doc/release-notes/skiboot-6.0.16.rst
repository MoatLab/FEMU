.. _skiboot-6.0.16:

==============
skiboot-6.0.16
==============

skiboot 6.0.16 was released on Tuesday February 5th, 2019. It replaces
:ref:`skiboot-6.0.15` as the current stable release in the 6.0.x series.

It is recommended that 6.0.16 be used instead of any previous 6.0.x version
due to the bug fixes it contains.

Bug fixes included in this release are:

- p9dsu: Fix p9dsu default variant

  Add the default when no riser_id is returned from the ipmi query.

  This addresses: https://github.com/open-power/boston-openpower/issues/1369

  Allow a little more time for BMC reply and cleanup some label strings.

- p9dsu: Fix p9dsu slot tables

  Set the attributes on the slot tables to account for
  builtin or pluggable etypes, this will allow pci
  enumeration to calculate subordinate buses.

  Update some slot label strings.

  Add WIO Slot5 which is standard on the ESS config.

- phb4: Generate checkstop on AIB ECC corr/uncorr for DD2.0 parts

  On DD2.0 parts, PCIe ECC protection is not warranted in the response
  data path. Thus, for these parts, we need to flag any ECC errors
  detected from the adjacent AIB RX Data path so the part can be
  replaced.

  This patch configures the FIRs so that we escalate these AIB ECC
  errors to a checkstop so the parts can be replaced.

- core/lock: Stop drop_my_locks() from always causing abort

  Fix an erroneous failure in an error path that looked like this: ::

      LOCK ERROR: Releasing lock we don't hold depth @0x30493d20 (state: 0x0000000000000001)
      [13836.000173140,0] Aborting!
      CPU 0000 Backtrace:
       S: 0000000031c03930 R: 000000003001d840   ._abort+0x60
       S: 0000000031c039c0 R: 000000003001a0c4   .lock_error+0x64
       S: 0000000031c03a50 R: 0000000030019c70   .unlock+0x54
       S: 0000000031c03af0 R: 000000003001a040   .drop_my_locks+0xf4
