skiboot-5.3.3
-------------

skiboot-5.3.3 was released on Friday September 2nd, 2016.

This is the 4th stable release of skiboot 5.3, the new stable release of
skiboot (first released with 5.3.0 on August 2nd, 2016).

Skiboot 5.3.3 replaces skiboot-5.3.2 as the current stable version. It contains
two bug fixes for machines utilizing the NPU (i.e. Garrison)

Over skiboot-5.3.2, the following fixes are included:

- hw/npu: assert the NPU irq min is aligned.
- hw/npu: program NPU BUID reg properly
  The NPU BUID register was incorrectly programmed resulting in npu
  interrupt level 0 causing a PB_CENT_CRESP_ADDR_ERROR checkstop,
  and irqs from npus in odd chips being aliased to and processed
  as the interrupts from the corresponding npu on the even chips.
