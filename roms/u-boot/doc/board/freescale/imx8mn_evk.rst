.. SPDX-License-Identifier: GPL-2.0+

imx8mn_evk
==========

U-Boot for the NXP i.MX8MN EVK board

Quick Start
-----------

- Build the ARM Trusted firmware binary
- Get firmware-imx package
- Build U-Boot
- Boot

Get and Build the ARM Trusted firmware
--------------------------------------

Note: srctree is U-Boot source directory
Get ATF from: https://source.codeaurora.org/external/imx/imx-atf
branch: imx_5.4.47_2.2.0

.. code-block:: bash

   $ make PLAT=imx8mn bl31
   $ cp build/imx8mn/release/bl31.bin $(srctree)

Get the ddr firmware
--------------------

.. code-block:: bash

   $ wget https://www.nxp.com/lgfiles/NMG/MAD/YOCTO/firmware-imx-8.9.bin
   $ chmod +x firmware-imx-8.9.bin
   $ ./firmware-imx-8.9
   $ cp firmware-imx-8.9/firmware/ddr/synopsys/ddr4*.bin $(srctree)

Build U-Boot
------------

.. code-block:: bash

   $ export CROSS_COMPILE=aarch64-poky-linux-
   $ make imx8mn_ddr4_evk_defconfig
   $ export ATF_LOAD_ADDR=0x960000
   $ make

Burn the flash.bin to MicroSD card offset 32KB:

.. code-block:: bash

   $sudo dd if=flash.bin of=/dev/sd[x] bs=1024 seek=32 conv=notrunc
   $sudo dd if=u-boot.itb of=/dev/sd[x] bs=1024 seek=384 conv=notrunc

Boot
----

Set Boot switch to SD boot
