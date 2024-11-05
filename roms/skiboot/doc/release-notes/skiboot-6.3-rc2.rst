.. _skiboot-6.3-rc2:

skiboot-6.3-rc2
===============

skiboot v6.3-rc2 was released on Thursday April 11th 2019. It is the second
release candidate of skiboot 6.3, which will become the new stable release
of skiboot following the 6.2 release, first released December 14th 2018.

Skiboot 6.3 will mark the basis for op-build v2.3. I expect to tag the final
skiboot 6.3 in the next week.

skiboot v6.3-rc2 contains all bug fixes as of :ref:`skiboot-6.0.19`,
and :ref:`skiboot-6.2.3` (the currently maintained
stable releases).

For how the skiboot stable releases work, see :ref:`stable-rules` for details.

Over :ref:`skiboot-6.3-rc1`, we have the following changes:

- libflash/ipmi-hiomap: Fix blocks count issue

  We convert data size to block count and pass block count to BMC.
  If data size is not block aligned then we endup sending block count
  less than actual data. BMC will write partial data to flash memory.

  Sample log ::

    [  594.388458416,7] HIOMAP: Marked flash dirty at 0x42010 for 8
    [  594.398756487,7] HIOMAP: Flushed writes
    [  594.409596439,7] HIOMAP: Marked flash dirty at 0x42018 for 3970
    [  594.419897507,7] HIOMAP: Flushed writes

  In this case HIOMAP sent data with block count=0 and hence BMC didn't
  flush data to flash.

- opal/hmi: Never trust a cow!

  With opencapi, it's fairly common to trigger HMIs during AFU
  development on the FPGA, by not replying in time to an NPU command,
  for example. So shift the blame reported by that cow to avoid crowding
  my mailbox.
- hw/npu2: Dump (more) npu2 registers on link error and HMIs

  We were already logging some NPU registers during an HMI. This patch
  cleans up a bit how it is done and separates what is global from what
  is specific to nvlink or opencapi.

  Since we can now receive an error interrupt when an opencapi link goes
  down unexpectedly, we also dump the NPU state but we limit it to the
  registers of the brick which hit the error.

  The list of registers to dump was worked out with the hw team to
  allow for proper debugging. For each register, we print the name as
  found in the NPU workbook, the scom address and the register value.
- hw/npu2: Report errors to the OS if an OpenCAPI brick is fenced

  Now that the NPU may report interrupts due to the link going down
  unexpectedly, report those errors to the OS when queried by the
  'next_error' PHB callback.

  The hardware doesn't support recovery of the link when it goes down
  unexpectedly. So we report the PHB as dead, so that the OS can log the
  proper message, notify the drivers and take the devices down.
- hw/npu2: Fix OpenCAPI PE assignment

  When we support mixing NVLink and OpenCAPI devices on the same NPU, we're
  going to have to share the same range of 16 PE numbers between NVLink and
  OpenCAPI PHBs.

  For OpenCAPI devices, PE assignment is only significant for determining
  which System Interrupt Log register is used for a particular brick - unlike
  NVLink, it doesn't play any role in determining how links are fenced.

  Split the PE range into a lower half which is used for NVLink, and an upper
  half that is used for OpenCAPI, with a fixed PE number assigned per brick.

  As the PE assignment for OpenCAPI devices is fixed, set the PE once
  during device init and then ignore calls to the set_pe() operation.

- opal-api: Reserve 2 OPAL API calls for future OpenCAPI LPC use

  OpenCAPI Lowest Point of Coherency (LPC) memory is going to require
  some extra OPAL calls to set up NPU BARs. These calls will most likely be
  called OPAL_NPU_LPC_ALLOC and OPAL_NPU_LPC_RELEASE, we're not quite ready
  to upstream that code yet though.

- cpufeatures: Add tm-suspend-hypervisor-assist and tm-suspend-xer-so-bug node

  tm-suspend-hypervisor-assist for P9 >=DD2.2
  And a tm-suspend-xer-so-bug node for P9 DD2.2 only.

  I also treat P9P as P9 DD2.3 and add a unit test for the cpufeatures
  infrastructure.

  Fixes: https://github.com/open-power/skiboot/issues/233
