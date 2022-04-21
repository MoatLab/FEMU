.. _skiboot-6.3.3:

==============
skiboot-6.3.3
==============

skiboot 6.3.3 was released on Wednesday Aug 6th, 2019. It replaces
:ref:`skiboot-6.3.2` as the current stable release in the 6.3.x series.

It is recommended that 6.3.3 be used instead of any previous 6.3.x version
due to the bug fixes it contains.

Bug fixes included in this release are:

- struct p9_sbe_msg doesn't need to be packed

  Only the reg member is sent anywhere (via xscom_write), so the structure
  does not need to be packed.

.. code-block:: text

  Fixes GCC9 build problem:
  hw/sbe-p9.c: In function ‘p9_sbe_msg_send’:
  hw/sbe-p9.c:270:9: error: taking address of packed member of ‘struct p9_sbe_msg’ may result in an unaligned p
  ointer value [-Werror=address-of-packed-member]
    270 |  data = &msg->reg[0];
        |         ^~~~~~~~~~~~

- hdata/vpd: fix printing (char*)0x00
  GCC9 now catches this bug:

.. code-block:: text

  In file included from hdata/vpd.c:17:
  In function ‘vpd_vini_parse’,
      inlined from ‘vpd_data_parse’ at hdata/vpd.c:416:3:
  /skiboot/include/skiboot.h:93:31: error: ‘%s’ directive argument is null [-Werror=format-overflow=]
     93 | #define prlog(l, f, ...) do { _prlog(l, pr_fmt(f), ##__VA_ARGS__); } while(0)
          |                               ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  hdata/vpd.c:390:5: note: in expansion of macro ‘prlog’
    390 |     prlog(PR_WARNING,
          |     ^~~~~
  hdata/vpd.c: In function ‘vpd_data_parse’:
  hdata/vpd.c:391:46: note: format string is defined here
    391 |           "VPD: CCIN desc not available for: %s\n",
          |                                              ^~
  cc1: all warnings being treated as errors

- errorlog: Prevent alignment error building with gcc9.

.. code-block:: text

  Fixes this build error:
  [ 52s] hw/fsp/fsp-elog-write.c: In function 'opal_elog_read':
  [ 52s] hw/fsp/fsp-elog-write.c:213:12: error: taking address of packed member of 'struct errorlog' may result
  in an unaligned pointer value [-Werror=address-of-packed-member]
  [ 52s] 213 | list_del(&log_data->link);
  [ 52s] | ^~~~~~~~~~~~~~~

- Support BMC IPMI heartbeat command

  A few years ago, the OpenBMC code added support for a "heartbeat"
  command to send to the host. This command is used after the BMC is reset
  to check if the host is running. Support was never added to the host
  side however so currently when the BMC sends this command, this appears
  in the host console:
  IPMI: unknown OEM SEL command ff received

  There is no response needed by the host (other then the low level
  acknowledge of the command which already occurs). This commit
  handles the command so the error is no longer printed (does nothing with
  the command though since no action is needed). Here's the tested output
  of this patch in the host console (with debug enabled):
  IPMI: BMC issued heartbeat command: 00

- Add: add mihawk platform file
