.. _skiboot-6.2.2:

=============
skiboot-6.2.2
=============

skiboot 6.2.2 was released on Wednesday March 6th, 2019. It replaces
:ref:`skiboot-6.2.1` as the current stable release in the 6.2.x series.

It is recommended that 6.2.2 be used instead of any previous 6.2.x version
due to the bug fixes it contains.

Over :ref:`skiboot-6.2.1` we have several bug fixes, including important ones
for powercap, ipmi-hiomap, astbmc and BMC communication driver.

powercap
========
- powercap: occ: Fix the powercapping range allowed for user

  OCC provides two limits for minimum powercap. One being hard powercap
  minimum which is guaranteed by OCC and the other one is a soft
  powercap minimum which is lesser than hard-min and may or may not be
  asserted due to various power-thermal reasons. So to allow the users
  to access the entire powercap range, this patch exports soft powercap
  minimum as the "powercap-min" DT property. And it also adds a new
  DT property called "powercap-hard-min" to export the hard-min powercap
  limit.

ASTBMC
======
- astbmc: Enable IPMI HIOMAP for AMI platforms

  Required for Habanero, Palmetto and Romulus.

- astbmc: Try IPMI HIOMAP for P8 (again)

  The HIOMAP protocol was developed after the release of P8 in preparation
  for P9. As a consequence P9 always uses it, but it has rarely been
  enabled for P8. P8DTU has recently added IPMI HIOMAP support to its BMC
  firmware, so enable its use in skiboot with P8 machines. Doing so
  requires some rework to ensure fallback works correctly as in the past
  the fallback was to mbox, which will only work for P9.

  Tested on Garrison, Palmetto without HIOMAP, Palmetto with HIOMAP, and
  Witherspoon.

- ast-io: Rework ast_sio_is_enabled() test sequence

  The postcondition of probing with a lock sequence is easier to make
  correct than with unlock. The original implementation left SuperIO
  locked after execution which broke an assumption of some callers.

  Tested on Garrison, Palmetto without HIOMAP, Palmetto with HIOMAP and
  Witherspoon.

P8DTU
=====
- p8dtu: Enable HIOMAP support

- p8dtu: Configure BMC graphics

  We can no-longer read the values from the BMC in the way we have in the
  past. Values were provided by Eric Chen of SMC.

IPMI-HIOMAP
===========
- ipmi-hiomap test case enhancements/fixes.

- libflash/ipmi-hiomap: Enforce message size for empty response

  The protocol defines the response to the associated messages as empty
  except for the command ID and sequence fields. If the BMC is returning
  extra data consider the message malformed.

- libflash/ipmi-hiomap: Remove unused close handling

  Issuing a HIOMAP_C_CLOSE is not required by the protocol specification,
  rather a close can be implicit in a subsequent
  CREATE_{READ,WRITE}_WINDOW request. The implicit close provides an
  opportunity to reduce LPC traffic and the implementation takes up that
  optimisation, so remove the case from the IPMI callback handler.

- libflash/ipmi-hiomap: Overhaul event handling

  Reworking the event handling was inspired by a bug report by Vasant
  where the host would get wedged on multiple flash access attempts in the
  face of a persistent error state on the BMC-side. The cause of this bug
  was the early-exit based on ctx->update, which erronously assumed that
  all events had been completely handled in prior calls to
  ipmi_hiomap_handle_events(). This is not true if e.g.
  HIOMAP_E_DAEMON_READY is clear in the prior calls.

  Regardless, there were other correctness and efficiency problems with
  the handling strategy:

  * Ack-able event state was not restored in the face of errors in the
    process of re-establishing protocol state

  * It forced needless window restoration with respect to the context in
    which ipmi_hiomap_handle_events() was called.

  * Tests for HIOMAP_E_DAEMON_READY and HIOMAP_E_FLASH_LOST were redundant
    with the overhauled error handling introduced in the previous patch

  Fix all of the above issues and add comments to explain the event
  handling flow.

  Tests for correctness follow later in the series.

- libflash/ipmi-hiomap: Overhaul error handling

  The aim is to improve the robustness with respect to absence of the
  BMC-side daemon. The current error handling roughly mirrors what was
  done for the mailbox implementation, but there's room for improvement.

  Errors are split into two classes, those that affect the transport state
  and those that affect the window validity. From here, we push the
  transport state error checks right to the bottom of the stack, to ensure
  the link is known to be in a good state before any message is sent.
  Window validity tests remain as they were in the hiomap_window_move()
  and ipmi_hiomap_read() functions. Validity tests are not necessary in
  the write and erase paths as we will receive an error response from the
  BMC when performing a dirty or flush on an invalid window.

  Recovery also remains as it was, done on entry to the blocklevel
  callbacks. If an error state is encountered in the middle of an
  operation no attempt is made to recover it on the spot, instead the
  error is returned up the stack and the caller can choose how it wishes
  to respond.

- libflash/ipmi-hiomap: Fix leak of msg in callback

BMC communication
=================
- core/ipmi: Add ipmi sync messages to top of the list

  In ipmi_queue_msg_sync() path OPAL will wait until it gets response from
  BMC. If we do not get response ontime we may endup in kernel hardlockups.
  Hence lets add sync messages to top of the queue. This will reduces the
  chance of hardlockups.

- hw/bt: Introduce separate list for synchronous messages

  BT send logic always sends top of bt message list to BMC. Once BMC reads the
  message, it clears the interrupt and bt_idle() becomes true.

  bt_add_ipmi_msg_head() adds message to top of the list. If bt message list
  is not empty then:

    - if bt_idle() is true then we will endup sending message to BMC before
      getting response from BMC for inflight message. Looks like on some
      BMC implementation this results in message timeout.
    - else we endup starting message timer without actually sending message
      to BMC.. which is not correct.

  This patch introduces separate list to track synchronous messages.
  bt_add_ipmi_msg_head() will add messages to tail of this new list. We
  will always process this queue before processing normal queue.

  Finally this patch introduces new variable (inflight_bt_msg) to track
  inflight message. This will point to current inflight message.

- hw/bt: Fix message retry handler

  In some corner cases (like BMC reboot), bt_send_and_unlock() starts
  message timer, but won't send message to BMC as driver is not free to
  send message. bt_expire_old_msg() function enables H2B interrupt without
  actually sending message.

  This patch fixes above issue.

- ipmi/power: Fix system reboot issue

  Kernel makes reboot/shudown OPAL call for reboot/shutdown. Once kernel
  gets response from OPAL it runs opal_poll_events() until firmware
  handles the request.

  On BMC based system, OPAL makes IPMI call (IPMI_CHASSIS_CONTROL) to
  initiate system reboot/shutdown. At present OPAL queues IPMI messages
  and return SUCESS to Host. If BMC is not ready to accept command (like
  BMC reboot), then these message will fail. We have to manually
  reboot/shutdown the system using BMC interface.

  This patch adds logic to validate message return value. If message failed,
  then it will resend the message. At some stage BMC will be ready to accept
  message and handles IPMI message.

- hw/bt: Add backend interface to disable ipmi message retry option

  During boot OPAL makes IPMI_GET_BT_CAPS call to BMC to get BT interface
  capabilities which includes IPMI message max resend count, message
  timeout, etc,. Most of the time OPAL gets response from BMC within
  specified timeout. In some corner cases (like mboxd daemon reset in BMC,
  BMC reboot, etc) OPAL may not get response within timeout period. In
  such scenarios, OPAL resends message until max resend count reaches.

  OPAL uses synchronous IPMI message (ipmi_queue_msg_sync()) for few
  operations like flash read, write, etc. Thread will wait in OPAL until
  it gets response from BMC. In some corner cases like BMC reboot, thread
  may wait in OPAL for long time (more than 20 seconds) and results in
  kernel hardlockup.

  This patch introduces new interface to disable message resend option. We
  will disable message resend option for synchrous message. This will
  greatly reduces kernel hardlock up issues.

  This is short term fix. Long term solution is to convert all synchronous
  messages to asynhrounous one.

- qemu: bt device isn't always hanging off /

  Just use the normal for_each_compatible instead.

  Otherwise in the qemu model as executed by op-test,
  we wouldn't go down the astbmc_init() path, thus not having flash.

PHB3
====
- hw/phb3/naples: Disable D-states

  Putting "Mellanox Technologies MT27700 Family [ConnectX-4] [15b3:1013]"
  (more precisely, the second of 2 its PCI functions, no matter in what
  order) into the D3 state causes EEH with the "PCT timeout" error.
  This has been noticed on garrison machines only and firestones do not
  seem to have this issue.

  This disables D-states changing for devices on root buses on Naples by
  installing a config space access filter (copied from PHB4).
