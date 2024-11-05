skiboot-5.2.0-rc2
=================

skiboot-5.2.0-rc2 was released on Wednesday March 9th, 2016.

skiboot-5.2.0-rc2 is the second release candidate of skiboot 5.2, which will
become the new stable release of skiboot following the 5.1 release, first
released August 17th, 2015.

skiboot-5.2.0-rc2 contains all bug fixes as of skiboot-5.1.14.

This is the second release that will follow the (now documented) Skiboot
stable rules - see :ref:`stable-rules`.

The current plan is to release skiboot-5.2.0 mid-March 2016, with a focus on
bug fixing for future 5.2.0-rc releases (if any - I hope this will be the last)

Over skiboot-5.2.0-rc1, we have the following changes:

New platform!
^^^^^^^^^^^^^

- Add Barreleye platform

Generic
^^^^^^^

- hw/p8-i2c: Speed up SMBUS_WRITE
- Fix early backtraces

FSP Platforms
^^^^^^^^^^^^^

- fsp-sensor: rework device tree for sensors
- platforms/firenze: Fix I2C clock source frequency

Simics simulator
^^^^^^^^^^^^^^^^

- Enable Simics UART console

Mambo simulator
^^^^^^^^^^^^^^^

- platforms/mambo: Add terminate callback

  - fix hang in multi-threaded mambo
  - add multithreaded mambo tests

IPMI
^^^^

- hw/ipmi: fix event data 1 for System Firmware Progress sensor
- ipmi: Log exact NetFn value in OPAL logs

AST BMC based platforms
^^^^^^^^^^^^^^^^^^^^^^^

- hw/bt: allow BT driver to use different buffer size

opal-prd utility
^^^^^^^^^^^^^^^^

- opal-prd: Add debug output for firmware-driven OCC events
    We indicate when we have a user-driven event, so add corresponding
    outputs for firmware-driven ones too.

getscom utility
^^^^^^^^^^^^^^^

- Add Naples chip support

