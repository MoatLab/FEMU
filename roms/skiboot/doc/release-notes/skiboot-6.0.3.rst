.. _skiboot-6.0.3:

=============
skiboot-6.0.3
=============

skiboot 6.0.3 was released on Wednesday May 23rd, 2018. It replaces
:ref:`skiboot-6.0.2` as the current stable release in the 6.0.x series.

It is recommended that 6.0.3 be used instead of any previous 6.0.x version.

Over :ref:`skiboot-6.0.3`, we have bug fixes related to i2c booting in
secure mode, and general functionality with a TPM present. These changes are:

- p8-i2c: Remove force reset

  Force reset was added as an attempt to work around some issues with TPM
  devices locking up their I2C bus. In that particular case the problem
  was that the device would hold the SCL line down permanently due to a
  device firmware bug. The force reset doesn't actually do anything to
  alleviate the situation here, it just happens to reset the internal
  master state enough to make the I2C driver appear to work until
  something tries to access the bus again.

  On P9 systems with secure boot enabled there is the added problem
  of the "diagostic mode" not being supported on I2C masters A,B,C and
  D. Diagnostic mode allows the SCL and SDA lines to be driven directly
  by software. Without this force reset is impossible to implement.

  This patch removes the force reset functionality entirely since:

     a) it doesn't do what it's supposed to, and
     b) it's butt ugly code

  Additionally, turn p8_i2c_reset_engine() into p8_i2c_reset_port().
  There's no need to reset every port on a master in response to an
  error that occurred on a specific port.

- libstb/i2c-driver: Bump max timeout

  We have observed some TPMs clock streching the I2C bus for signifigant
  amounts of time when processing commands. The same TPMs also have
  errata that can result in permernantly locking up a bus in response to
  an I2C transaction they don't understand. Using an excessively long
  timeout to prevent this in the field.
- Add TPM timeout workaround

  Set the default timeout for any bus containing a TPM to one second. This
  is needed to work around a bug in the firmware of certain TPMs that will
  clock strech the I2C port the for up to a second. Additionally, when the
  TPM is clock streching it responds to a STOP condition on the bus by
  bricking itself. Clearing this error requires a hard power cycle of the
  system since the TPM is powered by standby power.
