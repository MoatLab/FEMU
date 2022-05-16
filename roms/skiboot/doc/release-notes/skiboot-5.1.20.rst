.. _skiboot-5.1.20:

skiboot-5.1.20
--------------

skiboot-5.1.20 was released on Friday 18th August 2017.

skiboot-5.1.20 is the 21st stable release of 5.1, it follows skiboot-5.1.19
(which was released 16th January 2017).

This release contains a few minor bug fixes backported to the 5.1.x series.
All of the fixes have previously appeared in the 5.4.x stable series.

Changes are:

- FSP/CONSOLE: Workaround for unresponsive ipmi daemon

  In some corner cases, where FSP is active but not responding to
  console MBOX message (due to buggy IPMI) and we have heavy console
  write happening from kernel, then eventually our console buffer
  becomes full. At this point OPAL starts sending OPAL_BUSY_EVENT to
  kernel. Kernel will keep on retrying. This is creating kernel soft
  lockups. In some extreme case when every CPU is trying to write to
  console, user will not be able to ssh and thinks system is hang.

  If we reset FSP or restart IPMI daemon on FSP, system recovers and
  everything becomes normal.

  This patch adds workaround to above issue by returning OPAL_HARDWARE
  when cosole is full. Side effect of this patch is, we may endup dropping
  latest console data. But better to drop console data than system hang.

  Alternative approach is to drop old data from console buffer, make space
  for new data. But in normal condition only FSP can update 'next_out'
  pointer and if we touch that pointer, it may introduce some other
  race conditions. Hence we decided to just new console write request.

- FSP: Set status field in response message for timed out message

  For timed out FSP messages, we set message status as "fsp_msg_timeout".
  But most FSP driver users (like surviellance) are ignoring this field.
  They always look for FSP returned status value in callback function
  (second byte in word1). So we endup treating timed out message as success
  response from FSP.

  Sample output: ::

    [69902.432509048,7] SURV: Sending the heartbeat command to FSP
    [70023.226860117,4] FSP: Response from FSP timed out, word0 = d66a00d7, word1 = 0 state: 3
    ....
    [70023.226901445,7] SURV: Received heartbeat acknowledge from FSP
    [70023.226903251,3] FSP: fsp_trigger_reset() entry

  Here SURV code thought it got valid response from FSP. But actually we didn't
  receive response from FSP.

- FSP: Improve timeout message

  Presently we print word0 and word1 in error log. word0 contains
  sequence number and command class. One has to understand word0
  format to identify command class.

  Lets explicitly print command class, sub command etc.

- FSP/RTC: Remove local fsp_in_reset variable

  Now that we are using fsp_in_rr() to detect FSP reset/reload, fsp_in_reset
  become redundant. Lets remove this local variable.

- FSP/RTC: Fix possible FSP R/R issue in rtc write path

  fsp_opal_rtc_write() checks FSP status before queueing message to FSP. But if
  FSP R/R starts before getting response to queued message then we will continue
  to return OPAL_BUSY_EVENT to host. In some extreme condition host may
  experience hang. Once FSP is back we will repost message, get response from FSP
  and return OPAL_SUCCESS to host.

  This patch caches new values and returns OPAL_SUCCESS if FSP R/R is happening.
  And once FSP is back we will send cached value to FSP.

- hw/fsp/rtc: read/write cached rtc tod on fsp hir.

  Currently fsp-rtc reads/writes the cached RTC TOD on an fsp
  reset. Use latest fsp_in_rr() function to properly read the cached rtc
  value when fsp reset initiated by the hir.

  Below is the kernel trace when we set hw clock, when hir process starts. ::

    [ 1727.775824] NMI watchdog: BUG: soft lockup - CPU#57 stuck for 23s! [hwclock:7688]
    [ 1727.775856] Modules linked in: vmx_crypto ibmpowernv ipmi_powernv uio_pdrv_genirq ipmi_devintf powernv_op_panel uio ipmi_msghandler powernv_rng leds_powernv ip_tables x_tables autofs4 ses enclosure scsi_transport_sas crc32c_vpmsum lpfc ipr tg3 scsi_transport_fc
    [ 1727.775883] CPU: 57 PID: 7688 Comm: hwclock Not tainted 4.10.0-14-generic #16-Ubuntu
    [ 1727.775883] task: c000000fdfdc8400 task.stack: c000000fdfef4000
    [ 1727.775884] NIP: c00000000090540c LR: c0000000000846f4 CTR: 000000003006dd70
    [ 1727.775885] REGS: c000000fdfef79a0 TRAP: 0901   Not tainted  (4.10.0-14-generic)
    [ 1727.775886] MSR: 9000000000009033 <SF,HV,EE,ME,IR,DR,RI,LE>
    [ 1727.775889]   CR: 28024442  XER: 20000000
    [ 1727.775890] CFAR: c00000000008472c SOFTE: 1
                   GPR00: 0000000030005128 c000000fdfef7c20 c00000000144c900 fffffffffffffff4
                   GPR04: 0000000028024442 c00000000090540c 9000000000009033 0000000000000000
                   GPR08: 0000000000000000 0000000031fc4000 c000000000084710 9000000000001003
                   GPR12: c0000000000846e8 c00000000fba0100
    [ 1727.775897] NIP [c00000000090540c] opal_set_rtc_time+0x4c/0xb0
    [ 1727.775899] LR [c0000000000846f4] opal_return+0xc/0x48
    [ 1727.775899] Call Trace:
    [ 1727.775900] [c000000fdfef7c20] [c00000000090540c] opal_set_rtc_time+0x4c/0xb0 (unreliable)
    [ 1727.775901] [c000000fdfef7c60] [c000000000900828] rtc_set_time+0xb8/0x1b0
    [ 1727.775903] [c000000fdfef7ca0] [c000000000902364] rtc_dev_ioctl+0x454/0x630
    [ 1727.775904] [c000000fdfef7d40] [c00000000035b1f4] do_vfs_ioctl+0xd4/0x8c0
    [ 1727.775906] [c000000fdfef7de0] [c00000000035bab4] SyS_ioctl+0xd4/0xf0
    [ 1727.775907] [c000000fdfef7e30] [c00000000000b184] system_call+0x38/0xe0
    [ 1727.775908] Instruction dump:
    [ 1727.775909] f821ffc1 39200000 7c832378 91210028 38a10020 39200000 38810028 f9210020
    [ 1727.775911] 4bfffe6d e8810020 80610028 4b77f61d <60000000> 7c7f1b78 3860000a 2fbffff4

  This is found when executing the `op-test-framework fspresetReload testcase <https://github.com/open-power/op-test-framework/blob/master/testcases/fspresetReload.py>`_

  With this fix ran fsp hir torture testcase in the above test
  which is working fine.

- FSP/CHIPTOD: Return false in error path

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

- hw/fsp: Do not queue SP and SPCN class messages during reset/reload
  In certain cases of communicating with the FSP (e.g. sensors), the OPAL FSP
  driver returns a default code (async
  completion) even though there is no known bound from the time of this error
  return to the actual data being available. The kernel driver keeps waiting
  leading to soft-lockup on the host side.

  Mitigate both these (known) cases by returning OPAL_BUSY so the host driver
  knows to retry later.
