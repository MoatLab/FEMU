.. _skiboot-5.6.0-rc2:

skiboot-5.6.0-rc2
=================

skiboot-5.6.0-rc2 was released on Friday May 19th 2017. It is the second
release candidate of skiboot 5.6, which will become the new stable release
of skiboot following the 5.5 release, first released April 7th 2017.

skiboot-5.6.0-rc2 contains all bug fixes as of :ref:`skiboot-5.4.4`
and :ref:`skiboot-5.1.19` (the currently maintained stable releases). We
do not currently expect to do any 5.5.x stable releases.

For how the skiboot stable releases work, see :ref:`stable-rules` for details.

The current plan is to cut the final 5.6.0 by May 22nd, with skiboot 5.6.0
being for all POWER8 and POWER9 platforms in op-build v1.17 (Due May 24th).
This is a short cycle as this release is mainly targetted towards POWER9
bringup efforts.

With skiboot 5.6.0, we are moving to a regular six week release cycle,
similar to op-build, but slightly offset to allow for a short stabilisation
period. Expected release dates and contents are tracked using GitHub milestone
and issues: https://github.com/open-power/skiboot/milestones

Over :ref:`skiboot-5.6.0-rc1`, we have the following changes:

- hw/i2c: Fix early lock drop

  When interacting with an I2C master the p8-i2c driver (common to p9)
  aquires a per-master lock which it holds for the duration of it's
  interaction with the master.  Unfortunately, when
  p8_i2c_check_initial_status() detects that the master is busy with
  another transaction it drops the lock and returns OPAL_BUSY. This is
  contrary to the driver's locking strategy which requires that the
  caller aquire and drop the lock. This leads to a crash due to the
  double unlock(), which skiboot treats as fatal.

- mambo: Add skiboot/linux symbol lookup

  Adds the skisym and linsym commands which can be used to find the
  address of a Linux or Skiboot symbol. To function this requires
  the user to provide the SKIBOOT_MAP and VMLINUX_MAP environmental
  variables which indicate which skiboot.map and System.map files
  should be used.

  Examples:

  - Look up a symbol address: ::

            systemsim % skisym .load_and_boot_kernel
            0x0000000030013a08

  - Set a breakpoint there: ::

            systemsim % b [skisym .load_and_boot_kernel]
            breakpoint set at [0:0]: 0x0000000030013a08 (0x0000000030013A08) Enc:0x7D800026 : mfcr    r12


- libstb: Fix build in OpenSSL 1.1

  The build failure was as follows: ::

    [ HOSTCC ] libstb/create-container.c
    In file included from /usr/include/openssl/asn1.h:24:0,
                     from /usr/include/openssl/ec.h:30,
                     from libstb/create-container.c:36:
    libstb/create-container.c: In function ‘getSigRaw’:
    libstb/create-container.c:104:31: error: dereferencing pointer to incomplete
                                      type ‘ECDSA_SIG {aka struct ECDSA_SIG_st}’
      rlen = BN_num_bytes(signature->r);
                                   ^
