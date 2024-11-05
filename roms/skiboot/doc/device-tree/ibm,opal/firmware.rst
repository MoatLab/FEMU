System Firmware
===============

The 'firmware' node under 'ibm,opal' lists system and OPAL firmware version.

.. code-block:: dts

  firmware {
	symbol-map = <0x0 0x300ac650 0x0 0x1b3f5>;
	compatible = "ibm,opal-firmware";
	ml-version = [4d 4c 20 46 57 37 37 30 2e 32 30 20 46 57 37 37 30 2e 32 30 20 46 57 37 37 30 2e 32 30];
	mi-version = <0x4d49205a 0x4c373730 0x5f303735 0x205a4c37 0x37305f30 0x3735205a 0x4c373730 0x5f303735>;
	version = "skiboot-5.0-rc2";
	phandle = <0x8e>;
	linux,phandle = <0x8e>;
  };

``compatible``
  property describes OPAL compatibility.

``symbol-map``
  property describes OPAL symbol start address and size.

``version``
  property describes OPAL version. It replaced a property named 'git-id' early
  in the POWER8 lifecycle, so may not always be present. It will be absent on
  IBM FSP based systems running firmware prior to FW840. The 'version' property
  is present on all GA POWER8 BMC systems.

  On POWER9 and above, it is always present.

``mi-version``
  property describes Microcode Image. Only on IBM FSP systems.
  Will (likely) not be present on POWER9 systems.

``ml-version``
  property describes Microcode Level. Only on IBM FSP systems.
  Will (likely) not be present on POWER9 systems.

MI/ML format
------------
::

   <ML/MI> <T side version> <P side version> <boot side version>
