.. _skiboot-5.8-rc1:

skiboot-5.8-rc1
===============

skiboot v5.8-rc1 was released on Tuesday August 22nd 2017. It is the first
release candidate of skiboot 5.8, which will become the new stable release
of skiboot following the 5.7 release, first released 25th July 2017.

skiboot v5.8-rc1 contains all bug fixes as of :ref:`skiboot-5.4.6`
and :ref:`skiboot-5.1.20` (the currently maintained stable releases). We
do not currently expect to do any 5.7.x stable releases.

For how the skiboot stable releases work, see :ref:`stable-rules` for details.

The current plan is to cut the final 5.8 by August 25th, with skiboot 5.8
being for all POWER8 and POWER9 platforms in op-build v1.19 (Due August 25th).
This is a short cycle as this release is mainly targetted towards POWER9
bringup efforts.

Over skiboot-5.7, we have the following changes:

New Features
------------
- sensors: occ: Add support to clear sensor groups

  Adds a generic API to clear sensor groups. OCC inband sensor groups
  such as CSM, Profiler and Job Scheduler can be cleared using this API.
  It will clear the min/max of all sensors belonging to OCC sensor
  groups.

- sensors: occ: Add CSM_{min/max} sensors

  HWMON's lowest/highest attribute is used by CSM agent, so map min/max
  device-tree properties "sensor-data-min" and "sensor-data-max" to
  the min/max of CSM.

- sensors: occ: Add support for OCC inband sensors

  Add support to parse and export OCC inband sensors which are copied
  by OCC to main memory in P9. Each OCC writes three buffers which
  includes one names buffer for sensor meta data and two buffers for
  sensor readings. While OCC writes to one buffer the sensor values
  can be read from the other buffer. The sensors are updated every
  100ms.

  This patch adds power, temperature, current and voltage sensors to
  ``/ibm,opal/sensors`` device-tree node which can be exported by the
  ibmpowernv-hwmon driver in Linux.

- psr: occ: Add support to change power-shifting-ratio

  Add support to set the CPU-GPU power shifting ratio which is used by
  the OCC power capping algorithm. PSR value of 100 takes all power away
  from CPU first and a PSR value of 0 caps GPU first.

- powercap: occ: Add a generic powercap framework

  This patch adds a generic powercap framework and exports OCC powercap
  sensors using which system powercap can be set inband through OPAL-OCC
  command-response interface.
- phb4: Enable PCI peer-to-peer

  P9 supports PCI peer-to-peer: a PCI device can write directly to the
  mmio space of another PCI device. It completely by-passes the CPU.

  It requires some configuration on the PHBs involved:

  1. on the initiating side, the address for the read/write operation is
     in the mmio space of the target, i.e. well outside the range normally
     allowed. So we disable range-checking on the TVT entry in bypass mode.

  2. on the target side, we need to explicitly enable p2p by setting a
     bit in a configuration register. It has the side-effect of reserving
     an outbound (as seen from the CPU) store queue for p2p. Therefore we
     only enable p2p on the PHBs using it, as we don't want to waste the
     resource if we don't have to.

  P9 supports p2p mmio writes. Reads are currently only supported if the
  two devices are under the same PHB but that is expected to change in
  the future, and it raises questions about intermediate switches
  configuration, so we report an error for the time being.

  The patch adds a new OPAL call to allow the OS to declare a p2p
  (initiator, target) pair.

- NX 842 and GZIP support on POWER9


POWER9 DD2
----------

Further support for POWER9 DD2 revision chips. Notable changes include:

- xscom: Grab P9 DD2 revision level
- vas: Set mmio enable bits in DD2

  POWER9 DD2 added some new "enable" bits that must be set for VAS to
  work. These bits were unused in DD1.
- hdat: Add POWER9 DD2.0 specific pa_features

  Same as the default but with TM off.

POWER9
------
- Base NPU2 support on POWER9 DD2
- hdata/i2c: Work around broken I2C array version

  Work around a bug in the I2C devices array that shows the
  array version as being v2 when only the v1 data is populated.
- Recognize the 2s2u zz platform

  OPAL currently doesn't know about the 2s2u zz. It recognizes such a
  box as a generic BMC machine and fails to boot. Add the 2s2u as a
  supported platform.

  There will subsequently be a 2s2u-L system which may have a different
  compatible property, which will need to be handled later.
- hdata/spira: POWER9 NX isn't software compatible with P7/P8 NX, don't claim so
- NX: Add P9 NX support for gzip compression engine

  Power 9 introduces NX gzip compression engine. This patch adds gzip
  compression support in NX. Virtual Accelerator Switch (VAS) is used to
  access NX gzip engine and the channel configuration will be done with
  the receive FIFO. So RxFIFO address, logical partition ID (lpid),
  process ID (pid) and thread ID (tid) are used to configure RxFIFO.
  P9 NX supports high and normal priority FIFOS. Skiboot configures User
  Mode Access Control (UMAC) noitify match register with these values and
  also enables other registers to enable / disable the engine.

  Creates the following device-tree entries to provide RxFIFO address,
  RxFIFO size, Fifo priority, lpid, pid and tid values so that kernel
  can drive P9 NX gzip engine.

  The following nodes are located under an xscom node: ::
       /xscom@<xscom_addr>/nx@<nx_addr>

       /ibm,gzip-high-fifo          : High priority gzip RxFIFO
       /ibm,gzip-normal-fifo        : Normal priority gzip RxFIFO

    Each RxFIFO node contain:s

    ``compatible``
      ``ibm,p9-nx-gzip``
    ``priority``
      High or Normal
    ``rx-fifo-address``
      RxFIFO address
    ``rx-fifo-size``
      RxFIFO size
    ``lpid``
      0xfff (1's for 12 bits in UMAC notify match register)
    ``pid``
      gzip coprocessor type
    ``tid``
      counter for gzip

- NX: Add P9 NX support for 842 compression engine

  This patch adds changes needed for 842 compression engine on power 9.
  Virtual Accelerator Switch (VAS) is used to access NX 842 engine on P9
  and the channel setup will be done with receive FIFO. So RxFIFO
  address, logical partition ID (lpid), process ID (pid) and thread ID
  (tid) are used for this setup. p9 NX supports high and normal priority
  FIFOs. skiboot is not involved to process data with 842 engine, but
  configures User Mode Access Control (UMAC) noitify match register with
  these values and export them to kernel with device-tree entries.

  Also configure registers to setup and enable / disable the engine with
  the appropriate registers. Creates the following device-tree entries to
  provide RxFIFO address, RxFIFO size, Fifo priority, lpid, pid and tid
  values so that kernel can drive P9 NX 842 engine.

    The following nodes are located under an xscom node:
    ``/xscom@<xscom_addr>/nx@<nx_addr>``

    ``/ibm,842-high-fifo``
      High priority 842 RxFIFO
    ``/ibm,842-normal-fifo``
      Normal priority 842 RxFIFO

    Each RxFIFO node contains:

    ``compatible``
      ibm,p9-nx-842
    ``priority``
      High or Normal
    ``rx-fifo-address``
      RxFIFO address
    ``rx-fifo-size``
      RXFIFO size
    ``lpid``
      0xfff (1's for 12 bits set in UMAC notify match register)
    ``pid``
      842 coprocessor type
    ``tid``
      Counter for 842
- vas: Create MMIO device tree node

  Create a device tree node for VAS and add properties that Linux
  will need to configure/use VAS.
- opal: Extract sw checkstop fir address from HDAT.

  Extract sw checkstop fir address info from HDAT and populate device tree
  node ibm,sw-checkstop-fir.

  This patch is required for OPAL_CEC_REBOOT2 OPAL call to work as expected
  on p9.

  With this patch a device property 'ibm,sw-checkstop-fir' is now properly
  populated: ::

    # lsprop ibm,sw-checkstop-fir
    ibm,sw-checkstop-fir
                     05012000 0000001f

PHB4
----
- hdat: Fix PCIe GEN4 lane-eq setting for DD2

  For PCIe GEN4, DD2 uses only 1 byte per PCIe lane for the lane-eq
  settings (DD1 uses 2 bytes)
- pci: Wait for CRS and switch link when restoring bus numbers

  When a complete reset occurs, after the PHB recovers it propagates a
  reset down the wire to every device.  At the same time, skiboot talks to
  every device in order to restore the state of devices to what they were
  before the reset.

  In some situations, such as devices that recovered slowly and/or were
  behind a switch, skiboot attempted to access config space of the device
  before the link was up and the device could respond.

  Fix this by retrying CRS until the device responds correctly, and for
  devices behind a switch, making sure the switch has its link up first.
- pci: Track whether a PCI device is a virtual function

  This can be checked from config space, but we will need to know this when
  restoring the PCI topology, and it is not always safe to access config
  space during this period.
- phb4: Enhanced PCIe training tracing

  This add more details to the PCI training tracing (aka Rick Mata
  mode). It enables the PCIe Link Training and Status State
  Machine (LTSSM) tracing and details on speed and link width.

  Output now looks like this when enabled (via nvram): ::

    [    1.096995141,3] PHB#0000[0:0]: TRACE:0x0000001101000000  0ms          GEN1:x16:detect
    [    1.102849137,3] PHB#0000[0:0]: TRACE:0x0000102101000000 11ms presence GEN1:x16:polling
    [    1.104341838,3] PHB#0000[0:0]: TRACE:0x0000182101000000 14ms training GEN1:x16:polling
    [    1.104357444,3] PHB#0000[0:0]: TRACE:0x00001c5101000000 14ms training GEN1:x16:recovery
    [    1.104580394,3] PHB#0000[0:0]: TRACE:0x00001c5103000000 14ms training GEN3:x16:recovery
    [    1.123259359,3] PHB#0000[0:0]: TRACE:0x00001c5104000000 51ms training GEN4:x16:recovery
    [    1.141737656,3] PHB#0000[0:0]: TRACE:0x0000144104000000 87ms presence GEN4:x16:L0
    [    1.141752318,3] PHB#0000[0:0]: TRACE:0x0000154904000000 87ms trained  GEN4:x16:L0
    [    1.141757964,3] PHB#0000[0:0]: TRACE: Link trained.
    [    1.096834019,3] PHB#0001[0:1]: TRACE:0x0000001101000000  0ms          GEN1:x16:detect
    [    1.105578525,3] PHB#0001[0:1]: TRACE:0x0000102101000000 17ms presence GEN1:x16:polling
    [    1.112763075,3] PHB#0001[0:1]: TRACE:0x0000183101000000 31ms training GEN1:x16:config
    [    1.112778956,3] PHB#0001[0:1]: TRACE:0x00001c5081000000 31ms training GEN1:x08:recovery
    [    1.113002083,3] PHB#0001[0:1]: TRACE:0x00001c5083000000 31ms training GEN3:x08:recovery
    [    1.114833873,3] PHB#0001[0:1]: TRACE:0x0000144083000000 35ms presence GEN3:x08:L0
    [    1.114848832,3] PHB#0001[0:1]: TRACE:0x0000154883000000 35ms trained  GEN3:x08:L0
    [    1.114854650,3] PHB#0001[0:1]: TRACE: Link trained.

- phb4: Fix reading wrong size registers in EEH dump

  These registers are supposed to be 16bit, and it makes part of the
  register dump misleading.
- phb4: Ignore slot state if performing complete reset

  If a PHB is being completely reset, its state is about to be blown away
  anyway, so if it's not in an appropriate state, creset it regardless.
- phb4: Prepare for link down when creset called from kernel

  phb4_creset() is typically called by functions that prepare the link
  to go down.  In cases where creset() is called directly by the kernel,
  this isn't the case and it can cause issues.  Prepare for link down in
  creset, just like we do in freset and hreset.
- phb4: Skip attempting to fix PHBs broken on boot

  If a PHB is marked broken it didn't work on boot, and if it didn't work
  on boot then there's no point trying to recover it later
- phb4: Fix duplicate in EEH register dump
- phb4: Be more conservative on link presence timeout

  In this patch we tuned our link timing to be more agressive:
  ``cf960e2884 phb4: Improve reset and link training timing``

  Cards should take only 32ms but unfortunately we've seen some take
  up to 440ms. Hence bump our timer up to 1000ms.

  This can hurt boot times on systems where slots indicate a hotplug
  status but no electrical link is present (which we've seen). Since we
  have to wait 1 second between PERST and touching config space anyway,
  it shouldn't hurt too much.
- phb4: Assert PERST before PHB reset

  Currently we don't assert PERST before issuing a PHB reset. This means
  any link issues while resetting the PHB will be logged as errors.

  This asserts PERST before we start resetting the PHB to avoid this.
- Revert "phb4: Read PERST signal rather than assuming it's asserted"

  This reverts commit b42ff2b904165addf32e77679cebb94a08086966

  The original patch assumes that PERST has been asserted well before (>
  250ms) we hit here (ie. during hostboot).

  In a subesquent patch this will no longer be the case as we need to
  assert PERST during PHB reset, which may only be a few milliseconds
  before we hit this code.

  Hence revert this patch. Go back to the software mechanism using
  skip_perst to determine if PERST should be asserted or not. This
  allows us to keep the speed optimisation on boot.
- phb4: Set REGB error enables based on link state

  Currently we always set these enables when initing the PHB. If the
  link is already down, we shouldn't set them as it may cause spurious
  errors.

  This changes the code to only sets them if the link is up.
- phb4: Mark PHB as fenced on creset

  If we have to inject an error to trigger recover, we end up not
  marking the PHB as fenced in the PHB struct. This fixes that.
- phb4: Clear errors before deasserting reset

  During reset we may have logged some errors (eg. due to the link going
  down).

  Hence before we deassert PERST or Hot Reset, we need to clear these
  errors. This ensures that once link training starts, only new errors
  are logged.
- phb4: Disable device config space access when fenced

  On DD2 you can't access device config space when fenced, so just
  disable access whenever we are fenced.
- phb4: Dump devctl and devstat registers

  Dump devctl and devstat registers.  These would have been useful when
  debugging the MPS issue.
- phb4: Only clear some PHB config space registers on errors

  Currently on error we clear the entire PHB config space.  This is a
  problem as the PCIe Maximum Payload Size (MPS) negotiation may have
  already occurred. Clearing MPS in the PHB back to a default of 128
  bytes will result an error for a device which already has a larger MPS
  configured.

  This will manifest itself as error due to a malformed TLP packet. ie.
  ``phbPblErrorStatus bit 41  = "Malformed TLP error"``

  This has been seen after kexec on with some adapters.

  This fixes the problem by only clearing a subset of registers on a phb
  error.

Utilities
---------
- external/xscom-utils: Add ``--list-bits``

  When using getscom/putscom it's helpful to know what bits are set in the
  register. This patch adds an option to print out which bits are set
  along with the value that was read/written to the register. Note that
  this output indicates which bits are set using the IBM bit ordering
  since that's what the XSCOM documentation uses.


opal-prd
--------

- opal-prd: Do not pass pnor file while starting daemon.

  This change to the included systemd init file means opal-prd can
  start and run on IBM FSP based systems.

  We do not have pnor support on all the system. Also we have logic to
  autodetect PNOR. Hence do not pass ``--pnor`` by default.

- opal-prd: Disable pnor access interface on FSP system

  On FSP system host does not have access to PNOR. Hence disable PNOR
  access interfaces.

OPAL Sensors
------------
- sensor-groups : occ: Add 'ops' DT property

  Add new device-tree property 'ops' to define different operations
  supported on each sensor-group.

- OCC: Map OCC sensor to a chip-id

  Parse device tree to get chip-id for OCC sensor.

- HDAT: Add chip-id property to ipmi sensors

  Presently we do not have a way to map sensor to chip id. Hence we are
  always passing chip id 0 for occ_reset request (see occ_sensor_id_to_chip()).

  This patch adds chip-id property to sensors (whenever its available) so that
  we can map occ sensor to chip-id and pass valid chip-id to occ_reset request.

- xive: Check for valid PIR index when decoding

  This fixes an unlikely but possible assert() fail on kdump.

- sensors: occ: Skip the deconfigured core sensors

  This patch skips the deconfigured cores from the core sensors while
  parsing the sensor names in the main memory as these sensor values are
  not updated by OCC.

Tests
-----
- hdata_to_dt: use a realistic PVR and chip revision

- nx: PR_INFO that NX RNG and Crypto not yet supported on POWER9

- external/pflash: Add tests
- external/pflash: Reinstate the progress bars

  Recent work did some optimising which unfortunately removed some of the
  progress bars in pflash.

  It turns out that there's only one thing people prefer to correctly
  programmed flash chips, it is the ability to watch little equals
  characters go across their screens for potentially minutes.
- external/pflash: Correct erase alignment checks

  pflash should check the alignment of addresses and sizes when asked to
  erase. There are two possibilities:

  1. The user has specified sizes manually in which case pflash should
     be as flexible as possible, blocklevel_smart_erase() permits this. To
     prevent possible mistakes pflash will require --force to perform a
     manual erase of unaligned sizes.
  2. The user used -P to specify a partition, partitions aren't
     necessarily erase granule aligned anymore, blocklevel_smart_erase() can
     handle. In this it doesn't make sense to warn/error about misalignment
     since the misalignment is inherent to the FFS partition and not really
     user input.

- external/pflash: Check the result of strtoul

  Also add 0x in front of --info output to avoid a copy and paste mistake.

- libflash/file: Break up MTD erase ioctl() calls

  Unfortunately not all drivers are created equal and several drivers on
  which pflash relies block in the kernel for quite some time and ignore
  signals.

  This is really only a problem if pflash is to perform large erases. So
  don't, perform these ops in small chunks.

  An in kernel fix is possible in most cases but it takes time and systems
  will be running older drivers for quite some time. Since sector erases
  aren't significantly slower than whole chip erases there isn't much of a
  performance penalty to breaking up the erase ioctl()s.

General
-------
- opal-msg: Increase the max-async completion count by max chips possible

- occ: Add support for OPAL-OCC command/response interface

  This patch adds support for a shared memory based command/response
  interface between OCC and OPAL. In HOMER, there is an OPAL command
  buffer and an OCC response buffer which is used to send inband
  commands to OCC.

- HDAT/device-tree: only add lid-type on pre-POWER9 systems

  Largely a relic of back when we had multiple entry points into OPAL depending
  on which mechanism on an FSP we were using to get loaded, this isn't needed
  on modern P9 as we only have one entry point (we don't do the PHYP LID hack).
