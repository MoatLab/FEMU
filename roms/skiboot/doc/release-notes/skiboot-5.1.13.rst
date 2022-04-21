.. _skiboot-5.1.13:

skiboot-5.1.13
--------------

skiboot-5.1.13 was released on Wed January 27th, 2016.

skiboot-5.1.13 is the 14th stable release of 5.1, it follows skiboot-5.1.12
(which was released December 4th, 2015). This release contains bug fixes.

General
^^^^^^^

- core/device.c: Sort nodes with name@unit names by unit

  - This gives predictable device tree ordering to the payload
    (usually petitboot)
  - This means that utilities such as "lspci" will always return the same
    ordering.

- Add OPAL_CONSOLE_FLUSH to the OPAL API
  uart consoles only flush output when polled.  The Linux kernel calls
  these pollers frequently, except when in a panic state.  As such, panic
  messages are not fully printed unless the system is configured to reboot
  after panic.

  This patch adds a new call to the OPAL API to flush the buffer.  If the
  system has a uart console (i.e. BMC machines), it will incrementally
  flush the buffer, returning if there is more to be flushed or not.  If
  the system has a different console, the function will have no effect.
  This will allow the Linux kernel to ensure that panic message have been
  fully printed out.

CAPI
^^^^

- hmi: Identify the phb upon CAPI malfunction alert
  Previously, any error on a CAPI adapter would assume PHB0.
  This could cause issues on Firestone machines.

gard utility
^^^^^^^^^^^^

- Fix displaying 'cleared' gard records
  When a garded component is replaced hostboot detects this and updates the
  gard partition.

  Previously, there was ambiguity on if the gard record ID or the whole gard
  record needed to be erased. This fix makes gard and hostboot agree.

firestone platform
^^^^^^^^^^^^^^^^^^

- fix spacing in slot name
  The other SlotN names have no space.
