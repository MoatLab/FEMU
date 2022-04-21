.. _skiboot-5.10.4:

==============
skiboot-5.10.4
==============

skiboot 5.10.4 was released on Wednesday April 4th, 2018. It replaces
:ref:`skiboot-5.10.3` as the current stable release in the 5.10.x series.

It is recommended that 5.10.3 be used instead of any previous 5.10.x version
due to the bug fixes and debugging enhancements in it.

Over :ref:`skiboot-5.10.3`, we have one bug fix:

- xive: disable store EOI support

  Hardware has limitations which would require to put a sync after each
  store EOI to make sure the MMIO operations that change the ESB state
  are ordered. This is a killer for performance and the PHBs do not
  support the sync. So remove the store EOI for the moment, until
  hardware is improved.

  Also, while we are at changing the XIVE source flags, let's fix the
  settings for the PHB4s which should follow these rules :

  - SHIFT_BUG    for DD10
  - STORE_EOI    for DD20 and if enabled
  - TRIGGER_PAGE for DDx0 and if not STORE_EOI
