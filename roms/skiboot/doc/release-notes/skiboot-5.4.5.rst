.. _skiboot-5.4.5:

=============
skiboot-5.4.5
=============

skiboot-5.4.5 was released on Friday June 9th, 2017. It replaces
:ref:`skiboot-5.4.4` as the current stable release in the 5.4.x series.

Over :ref:`skiboot-5.4.4`, we have a small number of bug fixes:


- On FSP platforms: notify FSP of Platform Log ID after Host Initiated Reset Reload
  Trigging a Host Initiated Reset (when the host detects the FSP has gone
  out to lunch and should be rebooted), would cause "Unknown Command" messages
  to appear in the OPAL log.

  This patch implements those messages.

  Log showing unknown command: ::

    / # cat /sys/firmware/opal/msglog | grep -i ,3
    [  110.232114723,3] FSP: fsp_trigger_reset() entry
    [  188.431793837,3] FSP #0: Link down, starting R&R
    [  464.109239162,3] FSP #0: Got XUP with no pending message !
    [  466.340598554,3] FSP-DPO: Unknown command 0xce0900
    [  466.340600126,3] FSP: Unhandled message ce0900

- hw/i2c: Fix early lock drop

  When interacting with an I2C master the p8-i2c driver (common to p9)
  aquires a per-master lock which it holds for the duration of it's
  interaction with the master.  Unfortunately, when
  p8_i2c_check_initial_status() detects that the master is busy with
  another transaction it drops the lock and returns OPAL_BUSY. This is
  contrary to the driver's locking strategy which requires that the
  caller aquire and drop the lock. This leads to a crash due to the
  double unlock(), which skiboot treats as fatal.

- head.S: store all of LR and CTR

  When saving the CTR and LR registers the skiboot exception handlers use the
  'stw' instruction which only saves the lower 32 bits of the register. Given
  these are both 64 bit registers this leads to some strange register dumps,
  for example: ::

    ***********************************************
    Unexpected exception 200 !
    SRR0 : 0000000030016968 SRR1 : 9000000000201000
    HSRR0: 0000000000000180 HSRR1: 9000000000001000
    LR   : 3003438830823f50 CTR  : 3003438800000018
    CFAR : 00000000300168fc
    CR   : 40004208  XER: 00000000

  In this dump the upper 32 bits of LR and CTR are actually stack gunk
  which obscures the underlying issue.
