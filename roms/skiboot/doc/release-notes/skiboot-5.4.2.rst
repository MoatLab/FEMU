.. _skiboot-5.4.2:

=============
skiboot-5.4.2
=============

skiboot-5.4.2 was released on Friday December 2nd 2016. It replaces
:ref:`skiboot-5.4.1` as the current stable release.

Over :ref:`skiboot-5.4.1`, we have two bug fixes exclusively aimed at machines
with TPMs:

- i2c: Add nuvoton TPM quirk, disallowing i2cdetect as it can hard lock the TPM
- p8-i2c improve I2C reset code path, solves getting stuck resetting i2c engine

