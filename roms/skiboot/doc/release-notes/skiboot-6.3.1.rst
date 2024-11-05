.. _skiboot-6.3.1:

==============
skiboot-6.3.1
==============

skiboot 6.3.1 was released on Friday May 10th, 2019. It replaces
:ref:`skiboot-6.3` as the current stable release in the 6.3.x series.

It is recommended that 6.3.1 be used instead of 6.3 version
due to the bug fixes it contains.

Bug fixes included in this release are:

- platforms/astbmc: Check for SBE validation step

  On some POWER8 astbmc systems an update to the SBE requires pausing at
  runtime to ensure integrity of the SBE. If this is required the BMC will
  set a chassis boot option IPMI flag using the OEM parameter 0x62. If
  Skiboot sees this flag is set it waits until the SBE update is complete
  and the flag is cleared.
  Unfortunately the mystery operation that validates the SBE also leaves
  it in a bad state and unable to be used for timer operations. To
  workaround this the flag is checked as soon as possible (ie. when IPMI
  and the console are set up), and once complete the system is rebooted.

- ipmi: ensure forward progress on ipmi_queue_msg_sync()

  BT responses are handled using a timer doing the polling. To hope to
  get an answer to an IPMI synchronous message, the timer needs to run.

  We can't just check all timers though as there may be a timer that
  wants a lock that's held by a code path calling ipmi_queue_msg_sync(),
  and if we did enforce that as a requirement, it's a pretty subtle
  API that is asking to be broken.

  So, if we just run a poll function to crank anything that the IPMI
  backend needs, then we should be fine.

  This issue shows up very quickly under QEMU when loading the first
  flash resource with the IPMI HIOMAP backend.

- pci/iov: Remove skiboot VF tracking

  This feature was added a few years ago in response to a request to make
  the MaxPayloadSize (MPS) field of a Virtual Function match the MPS of the
  Physical Function that hosts it.

  The SR-IOV specification states the the MPS field of the VF is "ResvP".
  This indicates the VF will use whatever MPS is configured on the PF and
  that the field should be treated as a reserved field in the config space
  of the VF. In other words, a SR-IOV spec compliant VF should always return
  zero in the MPS field.  Adding hacks in OPAL to make it non-zero is...
  misguided at best.

  Additionally, there is a bug in the way pci_device structures are handled
  by VFs that results in a crash on fast-reboot that occurs if VFs are
  enabled and then disabled prior to rebooting. This patch fixes the bug by
  removing the code entirely. This patch has no impact on SR-IOV support on
  the host operating system.
