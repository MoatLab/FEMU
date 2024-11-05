.. _skiboot-6.0-rc2:

skiboot-6.0-rc2
===============

skiboot v6.0-rc2 was released on Wednesday May 9th 2018. It is the second
release candidate of skiboot 6.0, which will become the new stable release
of skiboot following the 5.11 release, first released April 6th 2018.

Skiboot 6.0 will mark the basis for op-build v2.0 and will be required for
POWER9 systems.

skiboot v6.0-rc2 contains all bug fixes as of :ref:`skiboot-5.11`,
:ref:`skiboot-5.10.5`, and :ref:`skiboot-5.4.9` (the currently maintained
stable releases). Once 6.0 is released, we do *not* expect any further
stable releases in the 5.10.x series, nor in the 5.11.x series.

For how the skiboot stable releases work, see :ref:`stable-rules` for details.

The current plan is to cut the final 6.0 in early May (maybe in a day or two
after this -rc if things look okay), with skiboot 6.0
being for all POWER8 and POWER9 platforms in op-build v2.0.

Over skiboot-6.0-rc1, we have the following changes:

- Update default stop-state-disable mask to cut only stop11

  Stability improvements in microcode for stop4/stop5 are
  available in upstream hcode images. Stop4 and stop5 can
  be safely enabled by default.

  Use ~0xE0000000 to cut all but stop0,1,2 in case there
  are any issues with stop4/5.

  example: ::

    nvram -p ibm,skiboot --update-config opal-stop-state-disable-mask=0x1FFFFFFF

  **Note**: that DD2.1 chips that have a frequency <1867Mhz possible *need* to
  run a hcode image *different* than the default in op-build (set
  `BR2_HCODE_LATEST_VERSION=y` in your config)

- ibm,firmware-versions: add hcode to device tree

  op-build commit 736a08b996e292a449c4996edb264011dfe56a40
  added hcode to the VERSION partition, let's parse it out
  and let the user know.

- ipmi: Add BMC firmware version to device tree

  BMC Get device ID command gives BMC firmware version details. Lets add this
  to device tree. User space tools will use this information to display BMC
  version details.

- mambo: Enable XER CA32 and OV32 bits on P9

  POWER9 adds 32 bit carry and overflow bits to the XER, but we need to
  set the relevant CTRL1 bit to enable them.

- Makefile: Fix building natively on ppc64le

  When on ppc64le and CROSS is not set by the environment, make assumes
  ppc64 and sets a default CROSS. Check for ppc64le as well, so that
  'make' works out of the box on ppc64le.
- p9dsu: timeout for variant detection, default to 2uess

- core/direct-controls: improve p9_stop_thread error handling

  p9_stop_thread should fail the operation if it finds the thread was
  already quiescd. This implies something else is doing direct controls
  on the thread (e.g., pdbg) or there is some exceptional condition we
  don't know how to deal with. Proceeding here would cause things to
  trample on each other, for example the hard lockup watchdog trying to
  send a sreset to the core while it is stopped for debugging with pdbg
  will end in tears.

  If p9_stop_thread times out waiting for the thread to quiesce, do
  not hit it with a core_start direct control, because we don't know
  what state things are in and doing more things at this point is worse
  than doing nothing. There is no good recipe described in the workbook
  to de-assert the core_stop control if it fails to quiesce the thread.
  After timing out here, the thread may eventually quiesce and get
  stuck, but that's simpler to debug than undefied behaviour.

- core/direct-controls: fix p9_cont_thread for stopped/inactive threads

  Firstly, p9_cont_thread should check that the thread actually was
  quiesced before it tries to resume it. Anything could happen if we
  try this from an arbitrary thread state.

  Then when resuming a quiesced thread that is inactive or stopped (in
  a stop idle state), we must not send a core_start direct control,
  clear_maint must be used in these cases.
- occ: Use major version number while checking the pstate table format

  The minor version increments of the pstate table are backward
  compatible. The minor version is changed when the pstate table
  remains same and the existing reserved bytes are used for pointing
  new data. So use only major version number while parsing the pstate
  table. This will allow old skiboot to parse the pstate table and
  handle minor version updates.

- hmi: Clear unknown debug trigger

  On some systems, seeing hangs like this when Linux starts: ::

      [ 170.027252763,5] OCC: All Chip Rdy after 0 ms
      [ 170.062930145,5] INIT: Starting kernel at 0x20011000, fdt at 0x30ae0530 366247 bytes)
      [ 171.238270428,5] OPAL: Switch to little-endian OS

  If you look at the in memory skiboot console (or do `nvram -p
  ibm,skiboot --update-config log-level-driver=7`) we see the console get
  spammed with: ::

      [ 5209.109790675,7] HMI: Received HMI interrupt: HMER = 0x0000400000000000
      [ 5209.109792716,7] HMI: Received HMI interrupt: HMER = 0x0000400000000000
      [ 5209.109794695,7] HMI: Received HMI interrupt: HMER = 0x0000400000000000
      [ 5209.109796689,7] HMI: Received HMI interrupt: HMER = 0x0000400000000000

  We're taking the debug trigger (bit 17) early on, before the
  hmi_debug_trigger function in the kernel is set up.

  This clears the HMI in Skiboot and reports to the kernel instead of
  bringing down the machine.

- core/hmi: assign flags=0 in case nothing set by handle_hmi_exception

  Theoretically we could have returned junk to the OS in this parameter.

- SLW: Fix mambo boot to use stop states

  After commit 35c66b8ce5a2 ("SLW: Move MAMBO simulator checks to
  slw_init"), mambo boot no longer calls add_cpu_idle_state_properties()
  and as such we never enable stop states.

  After adding the call back, we get more testing coverage as well
  as faster mambo SMT boots.

- phb4: Hardware init updates

  CFG Write Request Timeout was incorrectly set to informational and not
  fatal for both non-CAPI and CAPI, so set it to fatal.  This was a
  mistake in the specification.  Correcting this fixes a niche bug in
  escalation (which is necessary on pre-DD2.2) that can cause a checkstop
  due to a NCU timeout.

  In addition, set the values in the timeout control registers to match.
  This fixes an extremely rare and unreproducible bug, though the current
  timings don't make sense since they're higher than the NCU timeout (16)
  which will checkstop the machine anyway.

- SLW: quieten 'Configuring self-restore' for DARN,NCU_SPEC_BAR and HRMOR
- Experimental support for building with Clang
- Improvements to testing and Travis CI
