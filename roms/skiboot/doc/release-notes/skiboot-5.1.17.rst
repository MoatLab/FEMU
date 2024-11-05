skiboot-5.1.17
--------------

skiboot-5.1.17 was released on Thursday 21st July 2016.

skiboot-5.1.17 is the 18th stable release of 5.1, it follows skiboot-5.1.16
(which was released April 29th, 2016).

This release contains a few minor bug fixes.

Changes
^^^^^^^

All platforms:

- Fix a few typos in user visible (OPAL log) strings
- pci: Do a dummy config write to devices to establish bus number
- Make the XSCOM engine code more resilient to errors:
  - hw/xscom: Reset XSCOM engine after querying sleeping core FIR
  - hw/xscom: Reset XSCOM engine after finite number of retries when busy
  - xscom: Return OPAL_WRONG_STATE on XSCOM ops if CPU is asleep
