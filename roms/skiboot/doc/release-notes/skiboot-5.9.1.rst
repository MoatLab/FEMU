.. _skiboot-5.9.1:

=============
skiboot-5.9.1
=============

skiboot 5.9.1 was released on Tuesday November 14th, 2017. It replaces
:ref:`skiboot-5.9` as the current stable release in the 5.9.x series.

Over :ref:`skiboot-5.9`, we have two NPU2 (NVLink2) fixes and two XIVE
bug fixes:

- npu2: hw-procedures: Refactor reset_ntl procedure

  Change the implementation of reset_ntl to match the latest programming
  guide documentation.
- npu2: hw-procedures: Add phy_rx_clock_sel()

  Change the RX clk mux control to be done by software instead of HW. This
  avoids glitches caused by changing the mux setting.

- xive: Fix ability to clear some EQ flags

  We could never clear "unconditional notify" and "escalate"
- xive: Update inits for DD2.0

  This updates some inits based on information from the HW
  designers. This includes enabling some new DD2.0 features
  that we don't yet exploit.
