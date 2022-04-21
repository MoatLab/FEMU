.. _skiboot-5.7-rc2:

skiboot-5.7-rc2
===============

skiboot v5.7-rc2 was released on Thursday July 13th 2017. It is the second
release candidate of skiboot 5.7, which will become the new stable release
of skiboot following the 5.6 release, first released 24th May 2017.

skiboot v5.7-rc2 contains all bug fixes as of :ref:`skiboot-5.4.6`
and :ref:`skiboot-5.1.19` (the currently maintained stable releases). We
do not currently expect to do any 5.6.x stable releases.

For how the skiboot stable releases work, see :ref:`stable-rules` for details.

The current plan is to cut the final 5.7 in the next week or so, with skiboot
5.7 being for all POWER8 and POWER9 platforms in op-build v1.18
(due July 12th, but will come *after* skiboot 5.7).

This is the second release using the new regular six week release cycle,
similar to op-build, but slightly offset to allow for a short stabilisation
period. Expected release dates and contents are tracked using GitHub milestone
and issues: https://github.com/open-power/skiboot/milestones

Over :ref:`skiboot-5.7-rc1`, we have the following changes:

POWER9
------

There are many important changes for POWER9 DD1 and DD2 systems. POWER9 support
should be considered in development and skiboot 5.7 is certainly **NOT**
suitable for POWER9 production environments.

- HDAT: Add IPMI sensor data under /bmc node
- numa/associativity: Add a new level of NUMA for GPU's

  Today we have an issue where the NUMA nodes corresponding
  to GPU's have the same affinity/distance as normal memory
  nodes. Our reference-points today supports two levels
  [0x4, 0x4] for normal systems and [0x4, 0x3] for Power8E
  systems. This patch adds a new level [0x4, X, 0x2] and
  uses node-id as at all levels for the GPU.
- xive: Enable memory backing of queues

  This dedicates 6x64k pages of memory permanently for the XIVE to
  use for internal queue overflow. This allows the XIVE to deal with
  some corner cases where the internal queues might prove insufficient.

- xive: Properly get rid of donated indirect pages during reset

  Otherwise they keep being used accross kexec causing memory
  corruption in subsequent kernels once KVM has been used.

- cpu: Better handle unknown flags in opal_reinit_cpus()

  At the moment, if we get passed flags we don't know about, we
  return OPAL_UNSUPPORTED but we still perform whatever actions
  was requied by the flags we do support. Additionally, on P8,
  we attempt a SLW re-init which hasn't been supported since
  Murano DD2.0 and will crash your system.

  It's too late to fix on existing systems so Linux will have to
  be careful at least on P8, but to avoid future issues let's clean
  that up, make sure we only use slw_reinit() when HILE isn't
  supported.
- cpu: Unconditionally cleanup TLBs on P9 in opal_reinit_cpus()

  This can work around problems where Linux fails to properly
  cleanup part or all of the TLB on kexec.

- Fix scom addresses for power9 nx checkstop hmi handling.

  Scom addresses for NX status, DMA & ENGINE FIR and PBI FIR has changed
  for Power9. Fixup thoes while handling nx checkstop for Power9.
- Fix scom addresses for power9 core checkstop hmi handling.

  Scom addresses for CORE FIR (Fault Isolation Register) and Malfunction
  Alert Register has changed for Power9. Fixup those while handling core
  checkstop for Power9.

  Without this change HMI handler fails to check for correct reason for
  core checkstop on Power9.

- core/mem_region: check return value of add_region

  The only sensible thing to do if this fails is to abort() as we've
  likely just failed reserving reserved memory regions, and nothing
  good comes from that.

PHB4
^^^^
- phb4: Do more retries on link training failures
  Currently we only retry once when we have a link training failure.
  This changes this to be 3 retries as 1 retry is not giving us enough
  reliablity.

  This will increase the boot time, especially on systems where we
  incorrectly detect a link presence when there really is nothing
  present. I'll post a followup patch to optimise our timings to help
  mitigate this later.

- phb4: Workaround phy lockup by doing full PHB reset on retry

  For PHB4 it's possible that the phy may end up in a bad state where it
  can no longer recieve data. This can manifest as the link not
  retraining. A simple PERST will not clear this. The PHB must be
  completely reset.

  This changes the retry state to CRESET to do this.

  This issue may also manifest itself as the link training in a degraded
  state (lower speed or narrower width). This patch doesn't attempt to
  fix that (will come later).
- pci: Add ability to trace timing

  PCI link training is responsible for a huge chunk of the skiboot boot
  time, so add the ability to trace it waiting in the main state
  machine.
- pci: Print resetting PHB notice at higher log level

  Currently during boot there a long delay while we wait for the PHBs to
  be reset and train. During this time, there is no output from skiboot
  and the last message doesn't give an indication of what's happening.

  This boosts the PHB reset message from info to notice so users can see
  what's happening during this long period of waiting.
- phb4: Only set one bit in nfir

  The MPIPL procedure says to only set bit 26 when forcing the PEC into
  freeze mode. Currently we set bits 24-27.

  This changes the code to follow spec and only set bit 26.
- phb4: Fix order of pfir/nfir clearing in CRESET

  According to the workbook, pfir must be cleared before the nfir.
  The way we have it now causes the nfir to not clear properly in some
  error circumstances.

  This swaps the order to match the workbook.
- phb4: Remove incorrect state transition

  When waiting in PHB4_SLOT_CRESET_WAIT_CQ for transations to end, we
  incorrectly move onto the next state.  Generally we don't hit this as
  the transactions have ended already anyway.

  This removes the incorrect state transition.
- phb4: Set default lane equalisation

  Set default lane equalisation if there is nothing in the device-tree.

  Default value taken from hdat and confirmed by hardware team. Neatens
  the code up a bit too.
- hdata: Fix phb4 lane-eq property generation

  The lane-eq data we get from hdat is all 7s but what we end up in the
  device tree is: ::

    xscom@603fc00000000/pbcq@4010c00/stack@0/ibm,lane-eq
                     00000000 31c339e0 00000000 0000000c
                     00000000 00000000 00000000 00000000
                     00000000 31c30000 77777777 77777777
                     77777777 77777777 77777777 77777777

  This fixes grabbing the properties from hdat and fixes the call to put
  them in the device tree.
- phb4: Fix PHB4 fence recovery.

  We had a few problems:

  - We used the wrong register to trigger the reset (spec bug)
  - We should clear the PFIR and NFIR while the reset is asserted
  - ... and in the right order !
  - We should only apply the DD1 workaround after the reset has
    been lifted.
  - We should ensure we use ASB whenever we are fenced or doing a
    CRESET
  - Make config ops write with ASB
- phb4: Verbose EEH options

  Enabled via nvram pci-eeh-verbose=true. ie. ::

    nvram -p ibm,skiboot --update-config pci-eeh-verbose=true
- phb4: Print more info when PHB fences

  For now at PHBERR level. We don't have room in the diags data
  passed to Linux for these unfortunately.


Testing/development
-------------------
- lpc: remove double LPC prefix from messages
- opal-ci/fetch-debian-jessie-installer: follow redirects
  Fixes some CI failures
- test/qemu-jessie: bail out fast on kernel panic
- test/qemu-jessie: dump boot log on failure
- travis: add fedora26
- xz: add fallthrough annotations to silence GCC7 warning
