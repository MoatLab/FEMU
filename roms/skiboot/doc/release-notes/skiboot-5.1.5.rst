skiboot-5.1.5
-------------

skiboot-5.1.5 was released on October 1st, 2015.

skiboot-5.1.5 is the 6th stable release of 5.1, it follows skiboot-5.1.4
(which was released September 26th, 2015).

Skiboot 5.1.5 contains all fixes from skiboot-5.1.4 and is a minor bug
fix release.

Changes
^^^^^^^
Over skiboot-5.1.4, we have the following changes:

Generic
^^^^^^^
- centaur: Add indirect XSCOM support
  Fixes a bug where opal-prd would not be able to recover from a bunch
  of errors as the indirect XSCOMs to centaurs would fail.
- xscom: Fix logging of indirect XSCOM errors
  Better logging of error messages.
- PHB3: Fix wrong PE number in error injection
- Improvement in boot_test.sh utility to support copying a pflash binary
  to BMCs.

AST BMC machines
^^^^^^^^^^^^^^^^

- ipmi-sel: Run power action immediately if host not up
    Our normal sequence for a soft power action (IPMI 'power soft' or
    'power cycle') involve receiving a SEL from the BMC, sending a message
    to Linux's opal platform support which instructs the host OS to shut
    down, and finally the host will request OPAL to cut power.

    When the host is not yet up we will send the message to /dev/null, and
    no action will be taken. This patches changes that behaviour to perform
    the action immediately if we know how.

OpenPower machines:
^^^^^^^^^^^^^^^^^^^

- opal-prd: Increase IPMI timeout to a slightly better value
  Proactively bump the timeout to 5seconds to match current value in petitboot
  Observed in the wild that this fixes bugs for petitboot.

