.. _skiboot-6.0.6:

=============
skiboot-6.0.6
=============

skiboot 6.0.6 was released on Thursday July 19th, 2018. It replaces
:ref:`skiboot-6.0.5` as the current stable release in the 6.0.x series.

It is recommended that 6.0.5 be used instead of any previous 6.0.x version,
especially in the case where NVLINK2 GPUs and/or Mellanox CX5 adapters are
being used.

Over :ref:`skiboot-6.0.5` we have several important performance related bug
fixes and one stability bug fix:

- phb4/CAPI: Reallocate PEC2 DMA-Read engines to improve GPU-Direct bandwidth

  We reallocate additional 16/8 DMA-Read engines allocated to stack0/1
  on PEC2 respectively. This is needed to improve bandwidth available to
  the Mellanox CX5 adapter when trying to read GPU memory (GPU-Direct).

  If kernel cxl driver indicates a request to allocate maximum possible
  DMA read engines when calling enable_capi_mode() and card is attached
  to PEC2/stack0 slot then we assume its a Mellanox CX5 adapter. We then
  allocate additional 16/8 extra DMA read engines to stack0 and stack1
  respectively on PEC2. This is done by populating the
  XPEC_PCI_PRDSTKOVR and XPEC_NEST_READ_STACK_OVERRIDE as suggested by
  the h/w team.
- phb4: Disable nodal scoped DMA accesses when PB pump mode is enabled

  By default when a PCIe device issues a read request via the PHB it is first
  issued with nodal scope. When accessing GPU memory the NPU does not know at the
  time of response if the requested memory page is off node or not. Therefore
  every read of GPU memory by a PHB is retried with larger scope which introduces
  bandwidth and latency issues.

  On smaller boxes which have pump mode enabled nodal and group scoped reads are
  treated the same and both types of request are broadcast to one chip. Therefore
  we can avoid the retry by disabling nodal scope on the PHB for these boxes. On
  larger boxes nodal (single chip) and group (multiple chip) scoped reads are
  treated differently. Therefore we avoid disabling nodal scope on large boxes
  which have pump mode disabled to avoid all PHB requests being broadcast to
  multiple chips.
- npu2/hw-procedures: Enable parity and credit overflow checks

  Enable these error checking features by setting the appropriate bits in
  our one-off initialization of each "NTL Misc Config 2" register.

  The exception is NDL RX parity checking, which should be disabled during
  the link training procedures.
