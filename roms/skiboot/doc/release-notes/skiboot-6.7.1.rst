.. _skiboot-6.7.1:

==============
skiboot-6.7.1
==============

skiboot 6.7.1 was released on Wednesday January 06, 2021. It replaces
:ref:`skiboot-6.7` as the current stable release in the 6.7.x series.

It is recommended that 6.7.1 be used instead of 6.7 version due to the
bug fixes it contains.

Bug fixes included in this release are:

- SBE: Account cancelled timer request

- SBE: Rate limit timer requests

- SBE: Check timer state before scheduling timer

- platform/mowgli: Limit PHB0/(pec0) to gen3 speed

- Revert "mowgli: Limit slot1 to Gen3 by default"

- xscom: Fix xscom error logging caused due to xscom OPAL call

- xive/p9: Remove assert from xive_eq_for_target()

- Fix possible deadlock with DEBUG build

- core/platform: Fallback to full_reboot if fast-reboot fails

- core/cpu: fix next_ungarded_primary
