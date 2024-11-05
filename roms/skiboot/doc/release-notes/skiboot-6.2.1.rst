.. _skiboot-6.2.1:

=============
skiboot-6.2.1
=============

skiboot 6.2.1 was released on Wednesday February 20th, 2019. It replaces
:ref:`skiboot-6.2` as the current stable release in the 6.2.x series.

It is recommended that 6.2.1 be used instead of any previous 6.2.x version
due to the bug fixes it contains.

Bug fixes included in this release are:

- libflash/ecc: Fix compilation warning with gcc9

  Fixes: https://github.com/open-power/skiboot/issues/218

- core/opal: Print PIR value in exit path, useful for debugging
- core/ipmi: Improve error message
- firmware-versions: Add test case for parsing VERSION

  If we hit a entry in VERSION that is larger than our
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
- p9dsu: Fix p9dsu slot tables

  Set the attributes on the slot tables to account for
  builtin or pluggable etypes, this will allow pci
  enumeration to calculate subordinate buses.

  Update some slot label strings.

  Add WIO Slot5 which is standard on the ESS config.
- core/lock: Stop drop_my_locks() from always causing abort

  The loop in drop_my_locks() looks like this: ::

            while((l = list_pop(&this_cpu()->locks_held, struct lock, list)) != NULL) {
                    if (warn)
                            prlog(PR_ERR, "  %s\n", l->owner);
                    unlock(l);
            }

  Both list_pop() and unlock() call list_del(). This means that on the
  last iteration of the loop, the list will be empty when we get to
  unlock_check(), causing this: ::

      LOCK ERROR: Releasing lock we don't hold depth @0x30493d20 (state: 0x0000000000000001)
      [13836.000173140,0] Aborting!
      CPU 0000 Backtrace:
       S: 0000000031c03930 R: 000000003001d840   ._abort+0x60
       S: 0000000031c039c0 R: 000000003001a0c4   .lock_error+0x64
       S: 0000000031c03a50 R: 0000000030019c70   .unlock+0x54
       S: 0000000031c03af0 R: 000000003001a040   .drop_my_locks+0xf4

  To fix this, change list_pop() to list_top().
- p9dsu: Fix p9dsu default variant

  Add the default when no riser_id is returned from the ipmi query.

  Allow a little more time for BMC reply and cleanup some label strings.

