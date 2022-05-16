.. _skiboot-6.0.20:

==============
skiboot-6.0.20
==============

skiboot 6.0.20 was released on Thursday May 9th, 2019. It replaces
:ref:`skiboot-6.0.19` as the current stable release in the 6.0.x series.

It is recommended that 6.0.20 be used instead of any previous 6.0.x version
due to the bug fixes it contains.

Bug fixes included in this release are:

- core/flash: Retry requests as necessary in flash_load_resource()

  We would like to successfully boot if we have a dependency on the BMC
  for flash even if the BMC is not current ready to service flash
  requests. On the assumption that it will become ready, retry for several
  minutes to cover a BMC reboot cycle and *eventually* rather than
  *immediately* crash out with: ::

      [  269.549748] reboot: Restarting system
      [  390.297462587,5] OPAL: Reboot request...
      [  390.297737995,5] RESET: Initiating fast reboot 1...
      [  391.074707590,5] Clearing unused memory:
      [  391.075198880,5] PCI: Clearing all devices...
      [  391.075201618,7] Clearing region 201ffe000000-201fff800000
      [  391.086235699,5] PCI: Resetting PHBs and training links...
      [  391.254089525,3] FFS: Error 17 reading flash header
      [  391.254159668,3] FLASH: Can't open ffs handle: 17
      [  392.307245135,5] PCI: Probing slots...
      [  392.363723191,5] PCI Summary:
      ...
      [  393.423255262,5] OCC: All Chip Rdy after 0 ms
      [  393.453092828,5] INIT: Starting kernel at 0x20000000, fdt at
      0x30800a88 390645 bytes
      [  393.453202605,0] FATAL: Kernel is zeros, can't execute!
      [  393.453247064,0] Assert fail: core/init.c:593:0
      [  393.453289682,0] Aborting!
      CPU 0040 Backtrace:
       S: 0000000031e03ca0 R: 000000003001af60   ._abort+0x4c
       S: 0000000031e03d20 R: 000000003001afdc   .assert_fail+0x34
       S: 0000000031e03da0 R: 00000000300146d8   .load_and_boot_kernel+0xb30
       S: 0000000031e03e70 R: 0000000030026cf0   .fast_reboot_entry+0x39c
       S: 0000000031e03f00 R: 0000000030002a4c   fast_reset_entry+0x2c
       --- OPAL boot ---

  The OPAL flash API hooks directly into the blocklevel layer, so there's
  no delay for e.g. the host kernel, just for asynchronously loaded
  resources during boot.

- pci/iov: Remove skiboot VF tracking

  This feature was added a few years ago in response to a request to make
  the MaxPayloadSize (MPS) field of a Virtual Function match the MPS of the
  Physical Function that hosts it.

  The SR-IOV specification states the the MPS field of the VF is "ResvP".
  This indicates the VF will use whatever MPS is configured on the PF and
  that the field should be treated as a reserved field in the config space
  of the VF. In other words, a SR-IOV spec compliant VF should always return
  zero in the MPS field.  Adding hacks in OPAL to make it non-zero is...
  misguided at best.

  Additionally, there is a bug in the way pci_device structures are handled
  by VFs that results in a crash on fast-reboot that occurs if VFs are
  enabled and then disabled prior to rebooting. This patch fixes the bug by
  removing the code entirely. This patch has no impact on SR-IOV support on
  the host operating system.

- hw/xscom: Enable sw xstop by default on p9

  This was disabled at some point during bringup to make life easier for
  the lab folks trying to debug NVLink issues. This hack really should
  have never made it out into the wild though, so we now have the
  following situation occuring in the field:

   1) A bad happens
   2) The host kernel recieves an unrecoverable HMI and calls into OPAL to
      request a platform reboot.
   3) OPAL rejects the reboot attempt and returns to the kernel with
      OPAL_PARAMETER.
   4) Kernel panics and attempts to kexec into a kdump kernel.

  A side effect of the HMI seems to be CPUs becoming stuck which results
  in the initialisation of the kdump kernel taking a extremely long time
  (6+ hours). It's also been observed that after performing a dump the
  kdump kernel then crashes itself because OPAL has ended up in a bad
  state as a side effect of the HMI.

  All up, it's not very good so re-enable the software checkstop by
  default. If people still want to turn it off they can using the nvram
  override.

- opal/hmi: Initialize the hmi event with old value of TFMR.

  Do this before we fix TFAC errors. Otherwise the event at host console
  shows no thread error reported in TFMR register.

  Without this patch the console event show TFMR with no thread error:
  (DEC parity error TFMR[59] injection) ::

    [   53.737572] Severe Hypervisor Maintenance interrupt [Recovered]
    [   53.737596]  Error detail: Timer facility experienced an error
    [   53.737611]  HMER: 0840000000000000
    [   53.737621]  TFMR: 3212000870e04000

  After this patch it shows old TFMR value on host console: ::

    [ 2302.267271] Severe Hypervisor Maintenance interrupt [Recovered]
    [ 2302.267305]  Error detail: Timer facility experienced an error
    [ 2302.267320]  HMER: 0840000000000000
    [ 2302.267330]  TFMR: 3212000870e14010

- libflash/ipmi-hiomap: Fix blocks count issue

  We convert data size to block count and pass block count to BMC.
  If data size is not block aligned then we endup sending block count
  less than actual data. BMC will write partial data to flash memory.

  Sample log ::

    [  594.388458416,7] HIOMAP: Marked flash dirty at 0x42010 for 8
    [  594.398756487,7] HIOMAP: Flushed writes
    [  594.409596439,7] HIOMAP: Marked flash dirty at 0x42018 for 3970
    [  594.419897507,7] HIOMAP: Flushed writes

  In this case HIOMAP sent data with block count=0 and hence BMC didn't
  flush data to flash.

  Lets fix this issue by adjusting block count before sending it to BMC.

- Fix hang in pnv_platform_error_reboot path due to TOD failure.

  On TOD failure, with TB stuck, when linux heads down to
  pnv_platform_error_reboot() path due to unrecoverable hmi event, the panic
  cpu gets stuck in OPAL inside ipmi_queue_msg_sync(). At this time, rest
  all other cpus are in smp_handle_nmi_ipi() waiting for panic cpu to proceed.
  But with panic cpu stuck inside OPAL, linux never recovers/reboot. ::

    p0 c1 t0
    NIA : 0x000000003001dd3c <.time_wait+0x64>
    CFAR : 0x000000003001dce4 <.time_wait+0xc>
    MSR : 0x9000000002803002
    LR : 0x000000003002ecf8 <.ipmi_queue_msg_sync+0xec>

    STACK: SP NIA
    0x0000000031c236e0 0x0000000031c23760 (big-endian)
    0x0000000031c23760 0x000000003002ecf8 <.ipmi_queue_msg_sync+0xec>
    0x0000000031c237f0 0x00000000300aa5f8 <.hiomap_queue_msg_sync+0x7c>
    0x0000000031c23880 0x00000000300aaadc <.hiomap_window_move+0x150>
    0x0000000031c23950 0x00000000300ab1d8 <.ipmi_hiomap_write+0xcc>
    0x0000000031c23a90 0x00000000300a7b18 <.blocklevel_raw_write+0xbc>
    0x0000000031c23b30 0x00000000300a7c34 <.blocklevel_write+0xfc>
    0x0000000031c23bf0 0x0000000030030be0 <.flash_nvram_write+0xd4>
    0x0000000031c23c90 0x000000003002c128 <.opal_write_nvram+0xd0>
    0x0000000031c23d20 0x00000000300051e4 <opal_entry+0x134>
    0xc000001fea6e7870 0xc0000000000a9060 <opal_nvram_write+0x80>
    0xc000001fea6e78c0 0xc000000000030b84 <nvram_write_os_partition+0x94>
    0xc000001fea6e7960 0xc0000000000310b0 <nvram_pstore_write+0xb0>
    0xc000001fea6e7990 0xc0000000004792d4 <pstore_dump+0x1d4>
    0xc000001fea6e7ad0 0xc00000000018a570 <kmsg_dump+0x140>
    0xc000001fea6e7b40 0xc000000000028e5c <panic_flush_kmsg_end+0x2c>
    0xc000001fea6e7b60 0xc0000000000a7168 <pnv_platform_error_reboot+0x68>
    0xc000001fea6e7bd0 0xc0000000000ac9b8 <hmi_event_handler+0x1d8>
    0xc000001fea6e7c80 0xc00000000012d6c8 <process_one_work+0x1b8>
    0xc000001fea6e7d20 0xc00000000012da28 <worker_thread+0x88>
    0xc000001fea6e7db0 0xc0000000001366f4 <kthread+0x164>
    0xc000001fea6e7e20 0xc00000000000b65c <ret_from_kernel_thread+0x5c>

  This is because, there is a while loop towards the end of
  ipmi_queue_msg_sync() which keeps looping until "sync_msg" does not match
  with "msg". It loops over time_wait_ms() until exit condition is met. In
  normal scenario time_wait_ms() calls run pollers so that ipmi backend gets
  a chance to check ipmi response and set sync_msg to NULL.

  .. code-block:: c

          while (sync_msg == msg)
                  time_wait_ms(10);

  But in the event when TB is in failed state time_wait_ms()->time_wait_poll()
  returns immediately without calling pollers and hence we end up looping
  forever. This patch fixes this hang by calling opal_run_pollers() in TB
  failed state as well.

- core/ipmi: Print correct netfn value

- core/lock: don't set bust_locks on lock error

  bust_locks is a big hammer that guarantees a mess if it's set while
  all other threads are not stopped.

  I propose removing this in the lock error paths. In debugging the
  previous deadlock false positive, none of the error messages printed,
  and the in-memory console was totally garbled due to lack of locking.

  I think it's generally better for debugging and system integrity to
  keep locks held when lock errors occur. Lock busting should be used
  carefully, just to allow messages to be printed out or machine to be
  restarted, probably when the whole system is single-threaded.

  Skiboot is slowly working toward that being feasible with co-operative
  debug APIs between firmware and host, but for the time being,
  difficult lock crashes are better not to corrupt everything by
  busting locks.
