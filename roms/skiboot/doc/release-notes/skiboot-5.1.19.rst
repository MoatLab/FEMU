.. _skiboot-5.1.19:

skiboot-5.1.19
--------------

skiboot-5.1.19 was released on Monday 16th January 2017.

skiboot-5.1.19 is the 20th stable release of 5.1, it follows skiboot-5.1.18
(which was released 26th August 2016).

This release contains a few minor bug fixes.

Changes are:

Generic:

- Makefile: Disable stack protector due to gcc problems
- stack: Don't recurse into __stack_chk_fail
- Makefile: Use -ffixed-r13
  We did not find evidence of this ever being a problem, but this fix
  is good and preventative.
- Limit number of "Poller recursion detected" errors to display
  In some error conditions, we could spiral out of control on this
  and spend all of our time printing the exact same backtrace.
  Limit it to 16 times, because 16 is a nice number.

FSP based Systems:

- fsp: Don't recurse pollers in ibm_fsp_terminate
  If we were to terminate in a poller, we'd call op_display() which
  called pollers which hit the recursive poller warning, which ended
  in not much fun at all.

PCI:

- hw/phb3: set PHB retry state correctly when fresetting during a creset
- phb3: Lock the PHB on set_xive callbacks
    Those are called by the interrupts core and thus skip the locking
    implicit in the PCI opal calls.
- hw/{phb3, p7ioc}: Return success for freset on empty PHB
  OPAL_CLOSED is returned when fundamental reset is issued on the
  PHB who doesn't have subordinate devices (root port excluded).
  The kernel raises an error message, which is unnecessary. This
  returns OPAL_SUCCESS for this case to avoid the error message.
- hw/phb3: fix error handling in complete reset
  During a complete reset, when we get a timeout waiting for pending
  transaction in state PHB3_STATE_CRESET_WAIT_CQ, we mark the PHB as broken
  and return OPAL_PARAMETER.
  Change the return code to OPAL_HARDWARE which is way more sensible, and set
  the state to PHB3_STATE_FENCED so that the kernel can retry the complete
  reset.
