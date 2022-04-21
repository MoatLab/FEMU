.. _skiboot-4.1.1:

=============
skiboot 4.1.1
=============

Skiboot 4.1 was released 30th January 2015.

 * fsp: Avoid NULL dereference in case of invalid class_resp bits
   CQ: SW288484
 * Makefile: Support CROSS_COMPILE as well as CROSS
 * Additional unit testing:

   * Tiny hello_world kernel
   * Will run boot tests with hello_world and (if present) petitboot
     image in the POWER8 Functional simulator (mambo) (if present)
   * Run CCAN unit tests as part of 'make check'
   * Increased testing of PEL code
   * unit test console-log
   * skeleton libc unit tests
 * Fix compatible match for palmetto & habanero
   The strings should be "tyan,..." not "ibm,..."
   (N/A for IBM systems)
 * i2c: Unify the frequencies to calculate bit rate divisor
 * Unlock rtc cache lock when cache isn't valid
   Could cause IPL crash on POWER7
 * Initial documentation for OPAL API, ABI and Specification
 * Add Firestone platform
 * Fix crash when one socket wasn't populated with a CPU
   LTC-Bugzilla: 120562
 * Bug fix in RTC state machine which possibly led to RTC not working
 * Makefile fixes for running with some GCC 4.9 compilers
 * Add device tree properties for pstate vdd and vcs values
 * cpuidle: Add validated metrics for idle states
   Export residency times in device tree
 * Revert "platforms/astbmc: Temporary reboot workaround"
   (N/A for IBM systems)
 * Fix buffer overrun in print_* functions.
   This could cause IPL failures or conceivably other runtime problems

