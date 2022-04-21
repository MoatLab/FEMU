.. _skiboot-5.4.8:

=============
skiboot-5.4.8
=============

skiboot-5.4.8 was released on Wednesday October 11th, 2017. It replaces
:ref:`skiboot-5.4.7` as the current stable release in the 5.4.x series.

Over :ref:`skiboot-5.4.7`, we have a few bug fixes for FSP platforms:

- libflash/file: Handle short read()s and write()s correctly

  Currently we don't move the buffer along for a short read() or write()
  and nor do we request only the remaining amount.
- FSP/NVRAM: Handle "get vNVRAM statistics" command

  FSP sends MBOX command (cmd : 0xEB, subcmd : 0x05, mod : 0x00) to get vNVRAM
  statistics. OPAL doesn't maintain any such statistics. Hence return
  FSP_STATUS_INVALID_SUBCMD.

    Sample OPAL log: ::

      [16944.384670488,3] FSP: Unhandled message eb0500
      [16944.474110465,3] FSP: Unhandled message eb0500
      [16945.111280784,3] FSP: Unhandled message eb0500
      [16945.293393485,3] FSP: Unhandled message eb0500
- FSP/CONSOLE: Limit number of error logging

  Commit c8a7535f (FSP/CONSOLE: Workaround for unresponsive ipmi daemon, added
  in skiboot 5.4.6 and 5.7-rc1) added error logging when buffer is full. In some
  corner cases kernel may call this function multiple time and we may endup logging
  error again and again.

  This patch fixes it by generating error log only once.

- FSP/CONSOLE: Fix fsp_console_write_buffer_space() call

  Kernel calls fsp_console_write_buffer_space() to check console buffer space
  availability. If there is enough buffer space to write data, then kernel will
  call fsp_console_write() to write actual data.

  In some extreme corner cases (like one explained in commit c8a7535f)
  console becomes full and this function returns 0 to kernel (or space available
  in console buffer < next incoming data size). Kernel will continue retrying
  until it gets enough space. So we will start seeing RCU stalls.

  This patch keeps track of previous available space. If previous space is same
  as current means not enough space in console buffer to write incoming data.
  It may be due to very high console write operation and slow response from FSP
  -OR- FSP has stopped processing data (ex: because of ipmi daemon died). At this
  point we will start timer with timeout of SER_BUFFER_OUT_TIMEOUT (10 secs).
  If situation is not improved within 10 seconds means something went bad. Lets
  return OPAL_RESOURCE so that kernel can drop console write and continue.
- FSP/CONSOLE: Close SOL session during R/R

  Presently we are not closing SOL and FW console sessions during R/R. Host will
  continue to write to SOL buffer during FSP R/R. If there is heavy console write
  operation happening during FSP R/R (like running `top` command inside console),
  then at some point console buffer becomes full. fsp_console_write_buffer_space()
  returns 0 (or less than required space to write data) to host. While one thread
  is busy writing to console, if some other threads tries to write data to console
  we may see RCU stalls (like below) in kernel.

  kernel call trace: ::

    [ 2082.828363] INFO: rcu_sched detected stalls on CPUs/tasks: { 32} (detected by 16, t=6002 jiffies, g=23154, c=23153, q=254769)
    [ 2082.828365] Task dump for CPU 32:
    [ 2082.828368] kworker/32:3    R  running task        0  4637      2 0x00000884
    [ 2082.828375] Workqueue: events dump_work_fn
    [ 2082.828376] Call Trace:
    [ 2082.828382] [c000000f1633fa00] [c00000000013b6b0] console_unlock+0x570/0x600 (unreliable)
    [ 2082.828384] [c000000f1633fae0] [c00000000013ba34] vprintk_emit+0x2f4/0x5c0
    [ 2082.828389] [c000000f1633fb60] [c00000000099e644] printk+0x84/0x98
    [ 2082.828391] [c000000f1633fb90] [c0000000000851a8] dump_work_fn+0x238/0x250
    [ 2082.828394] [c000000f1633fc60] [c0000000000ecb98] process_one_work+0x198/0x4b0
    [ 2082.828396] [c000000f1633fcf0] [c0000000000ed3dc] worker_thread+0x18c/0x5a0
    [ 2082.828399] [c000000f1633fd80] [c0000000000f4650] kthread+0x110/0x130
    [ 2082.828403] [c000000f1633fe30] [c000000000009674] ret_from_kernel_thread+0x5c/0x68

  Hence lets close SOL (and FW console) during FSP R/R.

- FSP/CONSOLE: Do not associate unavailable console

  Presently OPAL sends associate/unassociate MBOX command for all
  FSP serial console (like below OPAL message). We have to check
  console is available or not before sending this message.

  OPAL log: ::

    [ 5013.227994012,7] FSP: Reassociating HVSI console 1
    [ 5013.227997540,7] FSP: Reassociating HVSI console 2
- FSP: Disable PSI link whenever FSP tells OPAL about impending Reset/Reload

  Commit 42d5d047 fixed scenario where DPO has been initiated, but FSP went
  into reset before the CEC power down came in. But this is generic issue
  that can happen in normal shutdown path as well.

  Hence disable PSI link as soon as we detect FSP impending R/R.


- fsp: return OPAL_BUSY_EVENT on failure sending FSP_CMD_POWERDOWN_NORM
  Also, return OPAL_BUSY_EVENT on failure sending FSP_CMD_REBOOT / DEEP_REBOOT.

  We had a race condition between FSP Reset/Reload and powering down
  the system from the host:

  Roughly:

  == ======================== ==========================================================
  #  FSP                      Host
  == ======================== ==========================================================
  1  Power on
  2                           Power on
  3  (inject EPOW)
  4  (trigger FSP R/R)
  5                           Processes EPOW event, starts shutting down
  6                           calls OPAL_CEC_POWER_DOWN
  7  (is still in R/R)
  8                           gets OPAL_INTERNAL_ERROR, spins in opal_poll_events
  9  (FSP comes back)
  10                          spinning in opal_poll_events
  11 (thinks host is running)
  == ======================== ==========================================================

  The call to OPAL_CEC_POWER_DOWN is only made once as the reset/reload
  error path for fsp_sync_msg() is to return -1, which means we give
  the OS OPAL_INTERNAL_ERROR, which is fine, except that our own API
  docs give us the opportunity to return OPAL_BUSY when trying again
  later may be successful, and we're ambiguous as to if you should retry
  on OPAL_INTERNAL_ERROR.

  For reference, the linux code looks like this: ::

    static void __noreturn pnv_power_off(void)
    {
            long rc = OPAL_BUSY;
    
            pnv_prepare_going_down();
    
            while (rc == OPAL_BUSY || rc == OPAL_BUSY_EVENT) {
                    rc = opal_cec_power_down(0);
                    if (rc == OPAL_BUSY_EVENT)
                            opal_poll_events(NULL);
                    else
                            mdelay(10);
            }
            for (;;)
                    opal_poll_events(NULL);
    }

  Which means that *practically* our only option is to return OPAL_BUSY
  or OPAL_BUSY_EVENT.

  We choose OPAL_BUSY_EVENT for FSP systems as we do want to ensure we're
  running pollers to communicate with the FSP and do the final bits of
  Reset/Reload handling before we power off the system.

