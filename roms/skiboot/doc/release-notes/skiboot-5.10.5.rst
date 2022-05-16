.. _skiboot-5.10.5:

==============
skiboot-5.10.5
==============

skiboot 5.10.5 was released on Tuesday April 24th, 2018. It replaces
:ref:`skiboot-5.10.4` as the current stable release in the 5.10.x series.

It is recommended that 5.10.5 be used instead of any previous 5.10.x version
due to the bug fixes and debugging enhancements in it.

Over :ref:`skiboot-5.10.4`, we have four bug fixes:

- npu2/hw-procedures: fence bricks on GPU reset

  The NPU workbook defines a way of fencing a brick and
  getting the brick out of fence state. We do have an implementation
  of bringing the brick out of fenced/quiesced state. We do
  the latter in our procedures, but to support run time reset
  we need to do the former.

  The fencing ensures that access to memory behind the links
  will not lead to HMI's, but instead SUE's will be populated
  in cache (in the case of speculation). The expectation is then
  that prior to and after reset, the operating system components
  will flush the cache for the region of memory behind the GPU.

  This patch does the following:

    1. Implements a npu2_dev_fence_brick() function to set/clear
       fence state
    2. Clear FIR bits prior to clearing the fence status
    3. Clear's the fence status
    4. We take the powerbus out of CQ fence much later now,
       in credits_check() which is the last hardware procedure
       called after link training.

- hdata/spira: parse vpd to add part-number and serial-number to xscom@ node

  Expected by FWTS and associates our processor with the part/serial
  number, which is obviously a good thing for one's own sanity.
- hw/imc: Check for pause_microcode_at_boot() return status

  pause_microcode_at_boot() loops through all the chip's ucode
  control block and pause the ucode if it is in the running state.
  But it does not fail if any of the chip's ucode is not initialised.

  Add code to return a failure if ucode is not initialized in any
  of the chip. Since pause_microcode_at_boot() is called just before
  attaching the IMC device nodes in imc_init(), add code to check for
  the function return.
- core/cpufeatures: Fix setting DARN and SCV HWCAP feature bits

  DARN and SCV has been assigned AT_HWCAP2 (32-63) bits: ::

    #define PPC_FEATURE2_DARN               0x00200000 /* darn random number insn */
    #define PPC_FEATURE2_SCV                0x00100000 /* scv syscall */

  A cpufeatures-aware OS will not advertise these to userspace without
  this patch.
