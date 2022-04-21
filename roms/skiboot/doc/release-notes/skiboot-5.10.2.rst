.. _skiboot-5.10.2:

==============
skiboot-5.10.2
==============

skiboot 5.10.2 was released on Tuesday March 6th, 2018. It replaces
:ref:`skiboot-5.10.1` as the current stable release in the 5.10.x series.

Over :ref:`skiboot-5.10.1`, we have one improvement:

- Tie tm-suspend fw-feature and opal_reinit_cpus() together

  Currently opal_reinit_cpus(OPAL_REINIT_CPUS_TM_SUSPEND_DISABLED)
  always returns OPAL_UNSUPPORTED.

  This ties the tm suspend fw-feature to the
  opal_reinit_cpus(OPAL_REINIT_CPUS_TM_SUSPEND_DISABLED) so that when tm
  suspend is disabled, we correctly report it to the kernel.  For
  backwards compatibility, it's assumed tm suspend is available if the
  fw-feature is not present.

  Currently hostboot will clear fw-feature(TM_SUSPEND_ENABLED) on P9N
  DD2.1. P9N DD2.2 will set fw-feature(TM_SUSPEND_ENABLED).  DD2.0 and
  below has TM disabled completely (not just suspend).

  We are using opal_reinit_cpus() to determine this setting (rather than
  the device tree/HDAT) as some future firmware may let us change this
  dynamically after boot. That is not the case currently though.
