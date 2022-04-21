.. _skiboot-5.10.3:

==============
skiboot-5.10.3
==============

skiboot 5.10.3 was released on Thursday March 28th, 2018. It replaces
:ref:`skiboot-5.10.2` as the current stable release in the 5.10.x series.

It is recommended that 5.10.3 be used instead of any previous 5.10.x version
due to the bug fixes and debugging enhancements in it.

Over :ref:`skiboot-5.10.2`, we have a few improvements and bug fixes:

- NPU2: dump NPU2 registers on npu2 HMI

  Due to the nature of debugging npu2 issues, folk are wanting the
  full list of NPU2 registers dumped when there's a problem.

  This is different than the solution introduced in 5.10.1
  as there we would dump the registers in a way that would trigger a FIR
  bit that would confuse PRD.
- npu2: Add performance tuning SCOM inits

  Peer-to-peer GPU bandwidth latency testing has produced some tunable
  values that improve performance. Add them to our device initialization.

  File these under things that need to be cleaned up with nice #defines
  for the register names and bitfields when we get time.

  A few of the settings are dependent on the system's particular NVLink
  topology, so introduce a helper to determine how many links go to a
  single GPU.
- hw/npu2: Assign a unique LPARSHORTID per GPU

  This gets used elsewhere to index items in the XTS tables.
- occ: Set up OCC messaging even if we fail to setup pstates

  This means that we no longer hit this bug if we fail to get valid pstates
  from the OCC. ::

    [console-pexpect]#echo 1 > //sys/firmware/opal/sensor_groups//occ-csm0/clear
    echo 1 > //sys/firmware/opal/sensor_groups//occ-csm0/clear
    [   94.019971181,5] CPU ATTEMPT TO RE-ENTER FIRMWARE! PIR=083d cpu @0x33cf4000 -> pir=083d token=8
    [   94.020098392,5] CPU ATTEMPT TO RE-ENTER FIRMWARE! PIR=083d cpu @0x33cf4000 -> pir=083d token=8
    [   10.318805] Disabling lock debugging due to kernel taint
    [   10.318808] Severe Machine check interrupt [Not recovered]
    [   10.318812]   NIP [000000003003e434]: 0x3003e434
    [   10.318813]   Initiator: CPU
    [   10.318815]   Error type: Real address [Load/Store (foreign)]
    [   10.318817] opal: Hardware platform error: Unrecoverable Machine Check exception
    [   10.318821] CPU: 117 PID: 2745 Comm: sh Tainted: G   M             4.15.9-openpower1 #3
    [   10.318823] NIP:  000000003003e434 LR: 000000003003025c CTR: 0000000030030240
    [   10.318825] REGS: c00000003fa7bd80 TRAP: 0200   Tainted: G   M              (4.15.9-openpower1)
    [   10.318826] MSR:  9000000000201002 <SF,HV,ME,RI>  CR: 48002888  XER: 20040000
    [   10.318831] CFAR: 0000000030030258 DAR: 394a00147d5a03a6 DSISR: 00000008 SOFTE: 1
- core/fast-reboot: disable fast reboot upon fundamental entry/exit/locking errors

  This disables fast reboot in several more cases where serious errors
  like lock corruption or call re-entrancy are detected.
- core/opal: allow some re-entrant calls

  This allows a small number of OPAL calls to succeed despite re-entering
  the firmware, and rejects others rather than aborting.

  This allows a system reset interrupt that interrupts OPAL to do something
  useful. Sreset other CPUs, use the console, which allows xmon to work or
  stack traces to be printed, reboot the system.

  Use OPAL_INTERNAL_ERROR when rejecting, rather than OPAL_BUSY, which is
  used for many other things that does not mean a serious permanent error.
- core/opal: abort in case of re-entrant OPAL call

  The stack is already destroyed by the time we get here, so there
  is not much point continuing.
- npu2: Disable fast reboot

  Fast reboot does not yet work right with the NPU. It's been disabled on
  NVLink and OpenCAPI machines. Do the same for NVLink2.

  This amounts to a port of 3e4577939bbf ("npu: Fix broken fast reset")
  from the npu code to npu2.
