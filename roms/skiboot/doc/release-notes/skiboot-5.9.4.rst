.. _skiboot-5.9.4:

=============
skiboot-5.9.4
=============

skiboot 5.9.4 was released on Wednesday November 29th, 2017. It replaces
:ref:`skiboot-5.9.3` as the current stable release in the 5.9.x series.

Over :ref:`skiboot-5.9.3`, we have one NPU2/NVLink2 fix that works around
a potential glitch (the one :ref:`skiboot-5.9.3` would hard crash on rather
than let a system continue to run until it mysteriously crashed later on).

That fix is in two parts:

- npu2: hw-procedures: Change phy_rx_clock_sel values to recover from a
  potential glitch.

- npu2: hw-procedures: Manipulate IOVALID during training

  Ensure that the IOVALID bit for this brick is raised at the start of
  link training, in the reset_ntl procedure.

  Then, to protect us from a glitch when the PHY clock turns off or gets
  chopped, lower IOVALID for the duration of the phy_reset and
  phy_rx_dccal procedures.
