.. _skiboot-6.0.8:

=============
skiboot-6.0.8
=============

skiboot 6.0.8 was released on Thursday August 16th, 2018. It replaces
:ref:`skiboot-6.0.7` as the current stable release in the 6.0.x series.

It is recommended that 6.0.8 be used instead of any previous 6.0.x version
due to the bug fixes it contains.

The bug fixes are:

- i2c: Ensure ordering between i2c_request_send() and completion

  i2c_request_send loops waiting for a flag "uc.done" set by
  the completion routine, and then look for a result code
  also set by that same completion.

  There is no synchronization, the completion can happen on another
  processor, so we need to order the stores to uc and the reads
  from uc so that uc.done is stored last and tested first using
  memory barriers.
- i2c: Fix multiple-enqueue of the same request on NACK

  i2c_request_send() will retry the request if the error is a NAK,
  however it forgets to clear the "ud.done" flag. It will thus
  loop again and try to re-enqueue the same request causing internal
  request list corruption.
- phb4: Disable 32-bit MSI in capi mode

  If a capi device does a DMA write targeting an address lower than 4GB,
  it does so through a 32-bit operation, per the PCI spec. In capi mode,
  the first TVE entry is configured in bypass mode, so the address is
  valid. But with any (bad) luck, the address could be 0xFFFFxxxx, thus
  looking like a 32-bit MSI.

  We currently enable both 32-bit and 64-bit MSIs, so the PHB will
  interpret the DMA write as a MSI, which very likely results in an EEH
  (MSI with a bad payload size).

  We can fix it by disabling 32-bit MSI when switching the PHB to capi
  mode. Capi devices are 64-bit.

- capp: Fix the capp recovery timeout comparison

  The current capp recovery timeout control loop in
  do_capp_recovery_scoms() uses a wrong comparison for return value of
  tb_compare(). This may cause do_capp_recovery_scoms() to report an
  timeout earlier than the 168ms stipulated time.

  The patch fixes this by updating the loop timeout control branch in
  do_capp_recovery_scoms() to use the correct enum tb_cmpval.
- phb4/capp: Update DMA read engines set in APC_FSM_READ_MASK based on link-width

  Commit 47c09cdfe7a3("phb4/capp: Calculate STQ/DMA read engines based
  on link-width for PEC") update the CAPP init sequence by calculating
  the needed STQ/DMA-read engines based on link width and populating it
  in XPEC_NEST_CAPP_CNTL register. This however needs to be synchronized
  with the value set in CAPP APC FSM Read Machine Mask Register.

  Hence this patch update phb4_init_capp_regs() to calculate the link
  width of the stack on PEC2 and populate the same values as previously
  populated in PEC CAPP_CNTL register.

- core/cpu: Call memset with proper cpu_thread offset
