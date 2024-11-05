.. _skiboot-6.0.9:

=============
skiboot-6.0.9
=============

skiboot 6.0.9 was released on Friday October 12th, 2018. It replaces
:ref:`skiboot-6.0.8` as the current stable release in the 6.0.x series.

It is recommended that 6.0.9 be used instead of any previous 6.0.x version
due to the bug fixes it contains.

The bug fixes are:

- opal/hmi: Ignore debug trigger inject core FIR.

  Core FIR[60] is a side effect of the work around for the CI Vector Load
  issue in DD2.1. Usually this gets delivered as HMI with HMER[17] where
  Linux already ignores it. But it looks like in some cases we may happen
  to see CORE_FIR[60] while we are already in Malfunction Alert HMI
  (HMER[0]) due to other reasons e.g. CAPI recovery or NPU xstop. If that
  happens then just ignore it instead of crashing kernel as not recoverable.

- opal/hmi: Handle early HMIs on thread0 when secondaries are still in OPAL.

  When primary thread receives a CORE level HMI for timer facility errors
  while secondaries are still in OPAL, thread 0 ends up in rendez-vous
  waiting for secondaries to get into hmi handling. This is because OPAL
  runs with MSR(EE=0) and hence HMIs are delayed on secondary threads until
  they are given to Linux OS. Fix this by adding a check for secondary
  state and force them in hmi handling by queuing job on secondary threads.

  I have tested this by injecting HDEC parity error very early during Linux
  kernel boot. Recovery works fine for non-TB errors. But if TB is bad at
  this very eary stage we already doomed.

  Without this patch we see: ::

    [  285.046347408,7] OPAL: Start CPU 0x0843 (PIR 0x0843) -> 0x000000000000a83c
    [  285.051160609,7] OPAL: Start CPU 0x0844 (PIR 0x0844) -> 0x000000000000a83c
    [  285.055359021,7] HMI: Received HMI interrupt: HMER = 0x0840000000000000
    [  285.055361439,7] HMI: [Loc: U78D3.ND1.WZS004A-P1-C48]: P:8 C:17 T:0: TFMR(2e12002870e14000) Timer Facility Error
    [  286.232183823,3] HMI: Rendez-vous stage 1 timeout, CPU 0x844 waiting for thread 1 (sptr=0000ccc1)
    [  287.409002056,3] HMI: Rendez-vous stage 1 timeout, CPU 0x844 waiting for thread 2 (sptr=0000ccc1)
    [  289.073820164,3] HMI: Rendez-vous stage 1 timeout, CPU 0x844 waiting for thread 3 (sptr=0000ccc1)
    [  290.250638683,3] HMI: Rendez-vous stage 1 timeout, CPU 0x844 waiting for thread 1 (sptr=0000ccc2)
    [  291.427456821,3] HMI: Rendez-vous stage 1 timeout, CPU 0x844 waiting for thread 2 (sptr=0000ccc2)
    [  293.092274807,3] HMI: Rendez-vous stage 1 timeout, CPU 0x844 waiting for thread 3 (sptr=0000ccc2)
    [  294.269092904,3] HMI: Rendez-vous stage 1 timeout, CPU 0x844 waiting for thread 1 (sptr=0000ccc3)
    [  295.445910944,3] HMI: Rendez-vous stage 1 timeout, CPU 0x844 waiting for thread 2 (sptr=0000ccc3)
    [  297.110728970,3] HMI: Rendez-vous stage 1 timeout, CPU 0x844 waiting for thread 3 (sptr=0000ccc3)

  After this patch: ::

    [  259.401719351,7] OPAL: Start CPU 0x0841 (PIR 0x0841) -> 0x000000000000a83c
    [  259.406259572,7] OPAL: Start CPU 0x0842 (PIR 0x0842) -> 0x000000000000a83c
    [  259.410615534,7] OPAL: Start CPU 0x0843 (PIR 0x0843) -> 0x000000000000a83c
    [  259.415444519,7] OPAL: Start CPU 0x0844 (PIR 0x0844) -> 0x000000000000a83c
    [  259.419641401,7] HMI: Received HMI interrupt: HMER = 0x0840000000000000
    [  259.419644124,7] HMI: [Loc: U78D3.ND1.WZS004A-P1-C48]: P:8 C:17 T:0: TFMR(2e12002870e04000) Timer Facility Error
    [  259.419650678,7] HMI: Sending hmi job to thread 1
    [  259.419652744,7] HMI: Sending hmi job to thread 2
    [  259.419653051,7] HMI: Received HMI interrupt: HMER = 0x0840000000000000
    [  259.419654725,7] HMI: Sending hmi job to thread 3
    [  259.419654916,7] HMI: Received HMI interrupt: HMER = 0x0840000000000000
    [  259.419658025,7] HMI: Received HMI interrupt: HMER = 0x0840000000000000
    [  259.419658406,7] HMI: [Loc: U78D3.ND1.WZS004A-P1-C48]: P:8 C:17 T:2: TFMR(2e12002870e04000) Timer Facility Error
    [  259.419663095,7] HMI: [Loc: U78D3.ND1.WZS004A-P1-C48]: P:8 C:17 T:3: TFMR(2e12002870e04000) Timer Facility Error
    [  259.419655234,7] HMI: [Loc: U78D3.ND1.WZS004A-P1-C48]: P:8 C:17 T:1: TFMR(2e12002870e04000) Timer Facility Error
    [  259.425109779,7] OPAL: Start CPU 0x0845 (PIR 0x0845) -> 0x000000000000a83c
    [  259.429870681,7] OPAL: Start CPU 0x0846 (PIR 0x0846) -> 0x000000000000a83c
    [  259.434549250,7] OPAL: Start CPU 0x0847 (PIR 0x0847) -> 0x000000000000a83c

- hw/bt.c: quieten all the noisy BT/IPMI messages
- npu2: Use correct kill type for TCE invalidation

  kill_type is enum of OPAL_PCI_TCE_KILL_PAGES, OPAL_PCI_TCE_KILL_PE,
  OPAL_PCI_TCE_KILL_ALL and phb4_tce_kill() gets it right but
  npu2_tce_kill() uses OPAL_PCI_TCE_KILL which is an OPAL API token.

- hw/npu2-opencapi: Fix setting of supported OpenCAPI templates

  In opal_npu_tl_set(), we made a typo that means the OPAL_NPU_TL_SET call
  may not clear the enable bits for templates that were previously enabled
  but are now disabled.

  Fix the typo so we clear NPU2_OTL_CONFIG1_TX_TEMP2_EN as well as
  TEMP{1,3}_EN.

- phb4: Workaround PHB errata with CFG write UR/CA errors

  If the PHB encounters a UR or CA status on a CFG write, it will
  incorrectly freeze the wrong PE. Instead of using the PE# specified
  in the CONFIG_ADDRESS register, it will use the PE# of whatever
  MMIO occurred last.

  Work around this disabling freeze on such errors

- phb4: Handle allocation errors in phb4_eeh_dump_regs()

  If the zalloc fails (and it can be a rather large allocation),
  we will overwite memory at 0 instead of failing.

- phb4: Don't try to access non-existent PEST entries

  In a POWER9 chip, some PHB4s have 256 PEs, some have 512.

  Currently, the diagnostics code retrieves 512 unconditionally,
  which is wrong and causes us to incorrectly report bogus values
  for the "high" PEs on the small PHBs.

  Use the actual number of implemented PEs instead

- phb4: Don't probe a PHB if its garded

  Presently phb4_probe_stack() causes an exception while trying to probe
  a PHB if its garded. This causes skiboot to go into a reboot loop with
  following exception log: ::

     ***********************************************
     Fatal MCE at 000000003006ecd4   .probe_phb4+0x570
     CFAR : 00000000300b98a0
     <snip>
     Aborting!
     CPU 0018 Backtrace:
     S: 0000000031cc37e0 R: 000000003001a51c   ._abort+0x4c
     S: 0000000031cc3860 R: 0000000030028170   .exception_entry+0x180
     S: 0000000031cc3a40 R: 0000000000001f10 *
     S: 0000000031cc3c20 R: 000000003006ecb0   .probe_phb4+0x54c
     S: 0000000031cc3e30 R: 0000000030014ca4   .main_cpu_entry+0x5b0
     S: 0000000031cc3f00 R: 0000000030002700   boot_entry+0x1b8

  This is caused as phb4_probe_stack() will ignore all xscom read/write
  errors to enable PHB Bars and then tries to perform an mmio to read
  PHB Version registers that cause the fatal MCE.

  We fix this by ignoring the PHB probe if the first xscom_write() to
  populate the PHB Bar register fails, which indicates that there is
  something wrong with the PHB.
