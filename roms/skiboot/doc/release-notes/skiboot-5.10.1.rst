.. _skiboot-5.10.1:

==============
skiboot-5.10.1
==============

skiboot 5.10.1 was released on Thursday March 1st, 2018. It replaces
:ref:`skiboot-5.10` as the current stable release in the 5.10.x series.

Over :ref:`skiboot-5.10`, we have an improvement for debugging NPU2/NVLink
problems and a bug fix. These changes are:

- NPU2 HMIs: dump out a *LOT* of npu2 registers for debugging
- libflash/blocklevel: Correct miscalculation in blocklevel_smart_erase()

  This fixes a bug in pflash.

  If blocklevel_smart_erase() detects that the smart erase fits entire in
  one erase block, it has an early bail path. In this path it miscaculates
  where in the buffer the backend needs to read from to perform the final
  write.

  Fixes: https://github.com/open-power/skiboot/issues/151
