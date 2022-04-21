skiboot-5.1.7
-------------

skiboot-5.1.7 was released on October 13th, 2015.

skiboot-5.1.7 is the 8th stable release of 5.1, it follows skiboot-5.1.6
(which was released October 8th, 2015).

Skiboot 5.1.7 contains all fixes from skiboot-5.1.6 and is a minor bug
fix release with one important bug fix for FSP systems.

Over skiboot-5.1.6, we have the following changes:

Generic:

- PHB3: Retry fundamental reset
    This introduces another PHB3 state (PHB3_STATE_FRESET_START)
    allowing to redo fundamental reset if the link doesn't come up
    in time at the first attempt, to improve the robustness of PHB's
    fundamental reset. If the link comes up after the first reset,
    the 2nd reset won't be issued at all.

FSP based systems:

- hw/fsp/fsp-leds.c: use allocated buffer for FSP_CMD_GET_LED_LIST response

  This fixes a bug where we would overwrite roughly 4kb of memory belonging
  to Linux when the FSP would ask firmware for a list of LEDs in the system.
  This wouldn't happen often (once before Linux was running and possibly
  only once during runtime, and *early* runtime at that) but it was possible
  for this corruption to show up and be detected.
