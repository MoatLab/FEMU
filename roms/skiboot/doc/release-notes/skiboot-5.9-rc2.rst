.. _skiboot-5.9-rc2:

skiboot-5.9-rc2
===============

skiboot v5.9-rc2 was released on Monday October 16th 2017. It is the second
release candidate of skiboot 5.9, which will become the new stable release
of skiboot following the 5.8 release, first released August 31st 2017.

skiboot v5.9-rc2 contains all bug fixes as of :ref:`skiboot-5.4.8`
and :ref:`skiboot-5.1.21` (the currently maintained stable releases). We
do not currently expect to do any 5.8.x stable releases.

For how the skiboot stable releases work, see :ref:`stable-rules` for details.

The current plan is to cut the final 5.9 by October 17th, with skiboot 5.9
being for all POWER8 and POWER9 platforms in op-build v1.20 (Due October 18th).
This release will be targetted to early POWER9 systems.

Over :ref:`skiboot-5.9-rc1`, we have the following changes:

- opal-prd: Fix memory leak
- hdata/i2c: update the list of known i2c devs

  This updates the list of known i2c devices - as of HDAT spec v10.5e - so
  that they can be properly identified during the hdat parsing.
- hdata/i2c: log unknown i2c devices

  An i2c device is unknown if either the i2c device list is outdated or
  the device is marked as unknown (0xFF) in the hdat.

- opal/cpu: Mark the core as bad while disabling threads of the core.

  If any of the core fails to sync its TB during chipTOD initialization,
  all the threads of that core are disabled. But this does not make
  linux kernel to ignore the core/cpus. It crashes while bringing them up
  with below backtrace: ::

    [   38.883898] kexec_core: Starting new kernel
    cpu 0x0: Vector: 300 (Data Access) at [c0000003f277b730]
        pc: c0000000001b9890: internal_create_group+0x30/0x304
        lr: c0000000001b9880: internal_create_group+0x20/0x304
        sp: c0000003f277b9b0
       msr: 900000000280b033
       dar: 40
     dsisr: 40000000
      current = 0xc0000003f9f41000
      paca    = 0xc00000000fe00000   softe: 0        irq_happened: 0x01
        pid   = 2572, comm = kexec
    Linux version 4.13.2-openpower1 (jenkins@p89) (gcc version 6.4.0 (Buildroot 2017.08-00006-g319c6e1)) #1 SMP Wed Sep 20 05:42:11 UTC 2017
    enter ? for help
    [c0000003f277b9b0] c0000000008a8780 (unreliable)
    [c0000003f277ba50] c00000000041c3ac topology_add_dev+0x2c/0x40
    [c0000003f277ba70] c00000000006b078 cpuhp_invoke_callback+0x88/0x170
    [c0000003f277bac0] c00000000006b22c cpuhp_up_callbacks+0x54/0xb8
    [c0000003f277bb10] c00000000006bc68 cpu_up+0x11c/0x168
    [c0000003f277bbc0] c00000000002f0e0 default_machine_kexec+0x1fc/0x274
    [c0000003f277bc50] c00000000002e2d8 machine_kexec+0x50/0x58
    [c0000003f277bc70] c0000000000de4e8 kernel_kexec+0x98/0xb4
    [c0000003f277bce0] c00000000008b0f0 SyS_reboot+0x1c8/0x1f4
    [c0000003f277be30] c00000000000b118 system_call+0x58/0x6c

- hw/imc: pause microcode at boot

  IMC nest counters has both in-band (ucode access) and out of
  band access to it. Since not all nest counter configurations
  are supported by ucode, out of band tools are used to characterize
  other configuration.

  So it is prefer to pause the nest microcode at boot to aid the
  nest out of band tools. If the ucode not paused and OS does not
  have IMC driver support, then out to band tools will race with
  ucode and end up getting undesirable values. Patch to check and
  pause the ucode at boot.

  OPAL provides APIs to control IMC counters. OPAL_IMC_COUNTERS_INIT
  is used to initialize these counters at boot. OPAL_IMC_COUNTERS_START
  and OPAL_IMC_COUNTERS_STOP API calls should be used to start and pause
  these IMC engines. `doc/opal-api/opal-imc-counters.rst` details the
  OPAL APIs and their usage.
- xive: Fix VP free block group mode false-positive parameter check

  The check to ensure the buddy allocation idx is aligned to its
  allocation order was not taking into account the allocation split.
  This would result in opal_xive_free_vp_block failures despite
  giving the same value as returned by opal_xive_alloc_vp_block.

  E.g., starting then stopping 4 KVM guests gives the following pattern
  in the host: ::

      opal_xive_alloc_vp_block(5)=0x45000020
      opal_xive_alloc_vp_block(5)=0x45000040
      opal_xive_alloc_vp_block(5)=0x45000060
      opal_xive_alloc_vp_block(5)=0x45000080
      opal_xive_free_vp_block(0x45000020)=-1
      opal_xive_free_vp_block(0x45000040)=0
      opal_xive_free_vp_block(0x45000060)=-1
      opal_xive_free_vp_block(0x45000080)=0
- hw/p8-i2c: Fix deadlock in p9_i2c_bus_owner_change

  When debugging a system where Linux was taking soft lockup errors with
  two CPUs stuck in OPAL:

  ======================= ==============
  CPU0                    CPU1
  ======================= ==============
  lock
  p8_i2c_recover
  opal_handle_interrupt
                          sync_timer
			  cancel_timer
			  p9_i2c_bus_owner_change
			  occ_p9_interrupt
			  xive_source_interrupt
			  opal_handle_interrupt
  ======================= ==============

  p8_i2c_recover() is a timer, and is stuck trying to take master->lock.
  p9_i2c_bus_owner_change() has taken master->lock, but then is stuck waiting
  for all timers to complete. We deadlock.

  Fix this by using cancel_timer_async().

- FSP/CONSOLE: Limit number of error logging

  Commit c8a7535f (FSP/CONSOLE: Workaround for unresponsive ipmi daemon) added
  error logging when buffer is full. In some corner cases kernel may call this
  function multiple time and we may endup logging error again and again.

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
  we may see RCU stalls (like below) in kernel. ::

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
  console is available or not before sending this message. ::

    [ 5013.227994012,7] FSP: Reassociating HVSI console 1
    [ 5013.227997540,7] FSP: Reassociating HVSI console 2
- FSP: Disable PSI link whenever FSP tells OPAL about impending R/R

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
