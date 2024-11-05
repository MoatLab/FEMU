.. _skiboot-6.2:

skiboot-6.2
===============

skiboot v6.2 was released on Friday December 14th 2018. It is the first
release of skiboot 6.2, which becomes the new stable release
of skiboot following the 6.1 release, first released July 11th 2018.

Skiboot 6.2 will mark the basis for op-build v2.2.

skiboot v6.2 contains all bug fixes as of :ref:`skiboot-6.0.14`,
and :ref:`skiboot-5.4.10` (the currently maintained
stable releases).

For how the skiboot stable releases work, see :ref:`stable-rules` for details.

This release has been a longer cycle than typical for a variety of reasons. It
also contains a lot of cleanup work and minor bug fixes (much like skiboot 6.1
did).

Over skiboot 6.1, we have the following changes:

General
-------

Since v6.2-rc2:

- i2c: Fix i2c request hang during opal init if timers are not checked

  If an i2c request cannot go through the first time, because the bus is
  found in error and need a reset or it's locked by the OCC for example,
  the underlying i2c implementation is using timers to manage the
  request. However during opal init, opal pollers may not be called, it
  depends in the context in which the i2c request is made. If the
  pollers are not called, the timers are not checked and we can end up
  with an i2c request which will not move foward and skiboot hangs.

  Fix it by explicitly checking the timers if we are waiting for an i2c
  request to complete and it seems to be taking a while.

Since v6.1:

- cpu: Quieten OS endian switch messages

  Users see these when loading an OS from Petitboot: ::

     [  119.486794100,5] OPAL: Switch to big-endian OS
     [  120.022302604,5] OPAL: Switch to little-endian OS

  Which is expected and doesn't provide any information the user can act
  on. Switch them to PR_INFO so they still appear in the log, but not on
  the serial console.
- Recognise signed VERSION partition

  A few things need to change to support a signed VERSION partition:

  - A signed VERSION partition will be 4K + SECURE_BOOT_HEADERS_SIZE (4K).
  - The VERSION partition needs to be loaded after secure/trusted boot is
    set up, and therefore after nvram_init().
  - Added to the trustedboot resources array.

  This also moves the ipmi_dt_add_bmc_info() call to after
  flash_dt_add_fw_version() since it adds info to ibm,firmware-versions.
- Run pollers in time_wait() when not booting

  This only bit us hard with hiomap in one scenario.

  Our OPAL API has been OPAL_POLL_EVENTS may be needed to make forward
  progress on ongoing operations, and the internal to skiboot API has been
  that time_wait() of a suitable time will run pollers (on at least one
  CPU) to help ensure forward progress can be made.

  In a perfect world, interrupts are used but they may: a) be disabled, or
  b) the thing we're doing can't use interrupts because computers are
  generally terrible.

  Back in 3db397ea5892a (circa 2015), we changed skiboot so that we'd run
  pollers only on the boot CPU, and not if we held any locks. This was to
  reduce the chance of programming code that could deadlock, as well as to
  ensure that we didn't just thrash all the cachelines for running pollers
  all over a large system during boot, or hard spin on the same locks on
  all secondary CPUs.

  The problem arises if the OS we're booting makes an OPAL call early on,
  with interrupts disabled, that requires a poller to run to make forward
  progress. An example of this would be OPAL_WRITE_NVRAM early in Linux
  boot (where Linux sets up the partitions it wants) - something that
  occurs iff we've had to reformat NVRAM this boot (i.e. first boot or
  corrupted NVRAM).

  The hiomap implementation should arguably *not* rely on synchronous IPMI
  messages, but this is a future improvement (as was for mbox before it).
  The mbox-flash code solved this problem by spinning on check_timers().

  More generically though, the approach of running the pollers when no
  longer booting means we behave more in line with what the API is meant
  to be, rather than have this odd case of "time_wait() for a condition
  that could also be tripped by an interrupt works fine unless the OS is
  up and running but hasn't set interrupts up yet".
- ipmi: Reduce ipmi_queue_msg_sync() polling loop time to 10ms

  On a plain boot, this reduces the time spent in OPAL by ~170ms on
  p9dsu. This is due to hiomap (currently) using synchronous IPMI
  messages.

  It will also *significantly* reduce latency on runtime flash
  operations for hiomap, as we'll spend typically 10-20ms in OPAL
  rather than 100-200ms. It's not an ideal solution to that, but
  it's a quick and obvious win for jitter.
- core/device: NULL pointer dereference fix
- core/flash: NULL pointer dereference fixes
- core/cpu: Call memset with proper cpu_thread offset
- libflash: Add ipmi-hiomap, and prefer it for PNOR access

  ipmi-hiomap implements the PNOR access control protocol formerly known
  as "the mbox protocol" but uses IPMI instead of the AST LPC mailbox as a
  transport. As there is no-longer any mailbox involved in this alternate
  implementation the old protocol name is quite misleading, and so it has
  been renamed to "the hiomap protoocol" (Host I/O Mapping protocol). The
  same commands and events are used though this client-side implementation
  assumes v2 of the protocol is supported by the BMC.

  The code is a heavily-reworked copy of the mbox-flash source and is
  introduced this way to allow for the mbox implementation's eventual
  removal.

  mbox-flash should in theory be renamed to mbox-hiomap for consistency,
  but as it is on life-support effective immediately we may as well just
  remove it entirely when the time is right.
- opal/hmi: Handle early HMIs on thread0 when secondaries are still in OPAL.

  When primary thread receives a CORE level HMI for timer facility errors
  while secondaries are still in OPAL, thread 0 ends up in rendez-vous
  waiting for secondaries to get into hmi handling. This is because OPAL
  runs with MSR(EE=0) and hence HMIs are delayed on secondary threads until
  they are given to Linux OS. Fix this by adding a check for secondary
  state and force them in hmi handling by queuing job on secondary threads.

  I have tested this by injecting HDEC parity error very early during Linux
  kernel boot. Recovery works fine for non-TB errors. But if TB is bad at
  this very eary stage we already doomed.

  Without this patch we see: ::

    [  285.046347408,7] OPAL: Start CPU 0x0843 (PIR 0x0843) -> 0x000000000000a83c
    [  285.051160609,7] OPAL: Start CPU 0x0844 (PIR 0x0844) -> 0x000000000000a83c
    [  285.055359021,7] HMI: Received HMI interrupt: HMER = 0x0840000000000000
    [  285.055361439,7] HMI: [Loc: U78D3.ND1.WZS004A-P1-C48]: P:8 C:17 T:0: TFMR(2e12002870e14000) Timer Facility Error
    [  286.232183823,3] HMI: Rendez-vous stage 1 timeout, CPU 0x844 waiting for thread 1 (sptr=0000ccc1)
    [  287.409002056,3] HMI: Rendez-vous stage 1 timeout, CPU 0x844 waiting for thread 2 (sptr=0000ccc1)
    [  289.073820164,3] HMI: Rendez-vous stage 1 timeout, CPU 0x844 waiting for thread 3 (sptr=0000ccc1)
    [  290.250638683,3] HMI: Rendez-vous stage 1 timeout, CPU 0x844 waiting for thread 1 (sptr=0000ccc2)
    [  291.427456821,3] HMI: Rendez-vous stage 1 timeout, CPU 0x844 waiting for thread 2 (sptr=0000ccc2)
    [  293.092274807,3] HMI: Rendez-vous stage 1 timeout, CPU 0x844 waiting for thread 3 (sptr=0000ccc2)
    [  294.269092904,3] HMI: Rendez-vous stage 1 timeout, CPU 0x844 waiting for thread 1 (sptr=0000ccc3)
    [  295.445910944,3] HMI: Rendez-vous stage 1 timeout, CPU 0x844 waiting for thread 2 (sptr=0000ccc3)
    [  297.110728970,3] HMI: Rendez-vous stage 1 timeout, CPU 0x844 waiting for thread 3 (sptr=0000ccc3)

  After this patch: ::

    [  259.401719351,7] OPAL: Start CPU 0x0841 (PIR 0x0841) -> 0x000000000000a83c
    [  259.406259572,7] OPAL: Start CPU 0x0842 (PIR 0x0842) -> 0x000000000000a83c
    [  259.410615534,7] OPAL: Start CPU 0x0843 (PIR 0x0843) -> 0x000000000000a83c
    [  259.415444519,7] OPAL: Start CPU 0x0844 (PIR 0x0844) -> 0x000000000000a83c
    [  259.419641401,7] HMI: Received HMI interrupt: HMER = 0x0840000000000000
    [  259.419644124,7] HMI: [Loc: U78D3.ND1.WZS004A-P1-C48]: P:8 C:17 T:0: TFMR(2e12002870e04000) Timer Facility Error
    [  259.419650678,7] HMI: Sending hmi job to thread 1
    [  259.419652744,7] HMI: Sending hmi job to thread 2
    [  259.419653051,7] HMI: Received HMI interrupt: HMER = 0x0840000000000000
    [  259.419654725,7] HMI: Sending hmi job to thread 3
    [  259.419654916,7] HMI: Received HMI interrupt: HMER = 0x0840000000000000
    [  259.419658025,7] HMI: Received HMI interrupt: HMER = 0x0840000000000000
    [  259.419658406,7] HMI: [Loc: U78D3.ND1.WZS004A-P1-C48]: P:8 C:17 T:2: TFMR(2e12002870e04000) Timer Facility Error
    [  259.419663095,7] HMI: [Loc: U78D3.ND1.WZS004A-P1-C48]: P:8 C:17 T:3: TFMR(2e12002870e04000) Timer Facility Error
    [  259.419655234,7] HMI: [Loc: U78D3.ND1.WZS004A-P1-C48]: P:8 C:17 T:1: TFMR(2e12002870e04000) Timer Facility Error
    [  259.425109779,7] OPAL: Start CPU 0x0845 (PIR 0x0845) -> 0x000000000000a83c
    [  259.429870681,7] OPAL: Start CPU 0x0846 (PIR 0x0846) -> 0x000000000000a83c
    [  259.434549250,7] OPAL: Start CPU 0x0847 (PIR 0x0847) -> 0x000000000000a83c

- core/cpu: Fix memory allocation for job array

  fixes: 7a3f307e core/cpu: parallelise global CPU register setting jobs

  This bug would result in boot-hang on some configurations due to
  cpu_wait_job() endlessly waiting for the last bogus jobs[cpu->pir] pointer.
- i2c: Fix multiple-enqueue of the same request on NACK

  i2c_request_send() will retry the request if the error is a NAK,
  however it forgets to clear the "ud.done" flag. It will thus
  loop again and try to re-enqueue the same request causing internal
  request list corruption.
- i2c: Ensure ordering between i2c_request_send() and completion

  i2c_request_send loops waiting for a flag "uc.done" set by
  the completion routine, and then look for a result code
  also set by that same completion.

  There is no synchronization, the completion can happen on another
  processor, so we need to order the stores to uc and the reads
  from uc so that uc.done is stored last and tested first using
  memory barriers.
- pci: Clarify power down logic

  Currently pci_scan_bus() unconditionally calls pci_slot_set_power_state()
  when it's finished scanning a bus. This is one of those things that
  makes you go "WHAT?" when you first see it and frankly the skiboot PCI
  code could do with less of that.

Fast Reboot
^^^^^^^^^^^

- fast-reboot: parallel memory clearing

  Arbitrarily pick 16GB as the unit of parallelism, and
  split up clearing memory into jobs and schedule them
  node-local to the memory (or on node 0 if we can't
  work that out because it's the memory up to SKIBOOT_BASE)

  This seems to cut at least ~40% time from memory zeroing on
  fast-reboot on a 256GB Boston system.

  For many systems, scanning PCI takes about as much time as
  zeroing all of RAM, so we may as well do them at the same time
  and cut a few seconds off the total fast reboot time.
- fast-reboot: verify firmware "romem" checksum

  This takes a checksum of skiboot memory after boot that should be
  unchanged during OS operation, and verifies it before allowing a
  fast reboot.

  This is not read-only memory from skiboot's point of view, beause
  it includes things like the opal branch table that gets populated
  during boot.

  This helps to improve the integrity of firmware against host and
  runtime firmware memory scribble bugs.

- core/fast-reboot: print the fast reboot disable reason

  Once things start to go wrong, disable_fast_reboot can be called a
  number of times, so make the first reason sticky, and also print it
  to the console at disable time. This helps with making sense of
  fast reboot disables.
- Add fast-reboot property to /ibm,opal DT node

  this means that if it's permanently disabled on boot, the test suite can
  pick that up and not try a fast reboot test.

Utilities
---------

Since v6.2-rc2:

- opal-prd: hservice: Enable hservice->wakeup() in BMC

  This patch enables HBRT to use HYP special wakeup register in openBMC
  which until now was only used in FSP based machines.

  This patch also adds a capability check for opal-prd so that HBRT can
  decide if the host special wakeup register can be used.
- ffspart: Support flashing already ECC protected images

  We do this by assuming filenames with '.ecc' in them are already ECC
  protected.

  This solves a practical problem in transitioning op-build to use ffspart
  for pnor assembly rather than three perl scripts and a lot of XML.

  We also update the ffspart tests to take into account ECC requirements.
- ffspart: Increase MAX_LINE to above PATH_MAX

  Otherwise we saw failures in CI and the ~221 character paths Jankins
  likes to have.
- libflash/file: greatly increase perf of file_erase()

  Do 4096 byte chunks not 8 byte chunks. A ffspart invocation constructing
  a 64MB PNOR goes from a couple of seconds to ~0.1seconds with this
  patch.

Since v6.2-rc1:
- libflash: Don't merge ECC-protected ranges

  Libflash currently merges contiguous ECC-protected ranges, but doesn't
  check that the ECC bytes at the end of the first and start of the second
  range actually match sanely. More importantly, if blocklevel_read() is
  called with a position at the start of a partition that is contained
  somewhere within a region that has been merged it will update the
  position assuming ECC wasn't being accounted for. This results in the
  position being somewhere well after the actual start of the partition
  which is incorrect.

  For now, remove the code merging ranges. This means more ranges must be
  held and checked however it prevents incorrectly reading ECC-correct
  regions like below: ::

    [  174.334119453,7] FLASH: CAPP partition has ECC
    [  174.437349574,3] ECC: uncorrectable error: ffffffffffffffff ff
    [  174.437426306,3] FLASH: failed to read the first 0x1000 from CAPP partition, rc 14
    [  174.439919343,3] CAPP: Error loading ucode lid. index=201d1

- libflash: Restore blocklevel tests

  This fell out in f58be46 "libflash/test: Rewrite Makefile.check to
  improve scalability". Add it back in as test-blocklevel.

Since v6.1:

- pflash: Add --skip option for reading

  Add a --skip=N option to pflash to skip N number of bytes when reading.
  This would allow users to print the VERSION partition without the STB
  header by specifying the --skip=4096 argument, and it's a more generic
  solution rather than making pflash depend on secure/trusted boot code.
- xscom-utils: Rework getsram

  Allow specifying a file on the command line to read OCC SRAM data into.
  If no file is specified then we print it to stdout as text. This is a
  bit inconsistent, but it retains compatibility with the existing tool.
- xscom-utils/getsram: Make it work on P9

  The XSCOM base address of the OCC control registers changed slightly
  between P8 and P9. Fix this up and add a bit of PVR checking so we look
  in the right place.
- opal-prd: Fix opal-prd crash

  Presently callback function from HBRT uses r11 to point to target function
  pointer. r12 is garbage. This works fine when we compile with "-no-pie" option
  (as we don't use r12 to calculate TOC).

  As per ABIv2 : "r12 : Function entry address at global entry point"

  With "-pie" compilation option, we have to set r12 to point to global function
  entry point. So that we can calculate TOC properly.

  Crash log without this patch: ::

      opal-prd[2864]: unhandled signal 11 at 0000000000029320 nip 00000 00102012830 lr 0000000102016890 code 1


Development and Debugging
-------------------------

Since v6.1-rc1:
- Warn on long OPAL calls

  Measure entry/exit time for OPAL calls and warn appropriately if the
  calls take too long (>100ms gets us a DEBUG log, > 1000ms gets us a
  warning).

Since v6.1:

- core/lock: Use try_lock_caller() in lock_caller() to capture owner

  Otherwise we can get reports of core/lock.c owning the lock, which is
  not helpful when tracking down ownership issues.
- core/flash: Emit a warning if Skiboot version doesn't match

  This means you'll get a warning that you've modified skiboot separately
  to the rest of the PNOR image, which can be useful in determining what
  firmware is actually running on a machine.
- gcov: link in ctors* as newer GCC doesn't group them all

  It seems that newer toolchains get us multiple ctors sections to link in
  rather than just one. If we discard them (as we were doing), then we
  don't have a working gcov build (and we get the "doesn't look sane"
  warning on boot).
- core/flash: Log return code when ffs_init() fails

  Knowing the return code is at least better than not knowing the return
  code.
- gcov: Fix building with GCC8
- travis/ci: rework Dockerfiles to produce build artifacts

  ubuntu-latest was also missing clang, as ubuntu-latest is closer to
  ubuntu 18.04 than 16.04
- cpu: add cpu_queue_job_on_node()

  Add a job scheduling API which will run the job on the requested
  chip_id (or return failure).
- opal-ci: Build old dtc version for fedora 28

  There are patches that will go into dtc to fix the issues we hit, but
  for the moment let's just build and use a slightly older version.
- mem_region: Merge similar allocations when dumping

  Currently we print one line for each allocation done at runtime when
  dumping the memory allocations. We do a few thousand allocations at
  boot so this can result in a huge amount of text being printed which
  is a) slow to print, and b) Can result in the log buffer overflowing
  which destroys otherwise useful information.

  This patch adds a de-duplication to this memory allocation dump by
  merging "similar" allocations (same location, same size) into one.

  Unfortunately, the algorithm used to do the de-duplication is quadratic,
  but considering we only dump the allocations in the event of a fatal
  error I think this is acceptable. I also did some benchmarking and found
  that on a ZZ it takes ~3ms to do a dump with 12k allocations. On a Zaius
  it's slightly longer at about ~10ms for 10k allocs. However, the
  difference there was due to the output being written to the UART.

  This patch also bumps the log level to PR_NOTICE. PR_INFO messages are
  suppressed at the default log level, which probably isn't something you
  want considering we only dump the allocations when we run out of skiboot
  heap space.
- core/lock: fix timeout warning causing a deadlock false positive

  If a lock waiter exceeds the warning timeout, it prints a message
  while still registered as requesting the lock. Printing the message
  can take locks, so if one is held when the owner of the original
  lock tries to print a message, it will get a false positive deadlock
  detection, which brings down the system.

  This can easily be hit when there is a lot of HMI activity from a
  KVM guest, where the timebase was not returned to host timebase
  before calling the HMI handler.
- hw/p8-i2c: Print the set error bits

  This is purely to save me from having to look it up every time someone
  gets an I2C error.
- init: Fix starting stripped kernel

  Currently if we try to run a raw/stripped binary kernel (ie. without
  the elf header) we crash with: ::

      [    0.008757768,5] INIT: Waiting for kernel...
      [    0.008762937,5] INIT: platform wait for kernel load failed
      [    0.008768171,5] INIT: Assuming kernel at 0x20000000
      [    0.008779241,3] INIT: ELF header not found. Assuming raw binary.
      [    0.017047348,5] INIT: Starting kernel at 0x0, fdt at 0x3044b230 14339 bytes
      [    0.017054251,0] FATAL: Kernel is zeros, can't execute!
      [    0.017059054,0] Assert fail: core/init.c:590:0
      [    0.017065371,0] Aborting!

  This is because we haven't set kernel_entry correctly in this path.
  This fixes it.
- cpu: Better output when waiting for a very long job

  Instead of printing at the end if the job took more than 1s,
  print in the loop every 30s along with a backtrace. This will
  give us some output if the job is deadlocked.
- lock: Fix interactions between lock dependency checker and stack checker

  The lock dependency checker does a few nasty things that can cause
  re-entrancy deadlocks in conjunction with the stack checker or
  in fact other debug tests.

  A lot of it revolves around taking a new lock (dl_lock) as part
  of the locking process.

  This tries to fix it by making sure we do not hit the stack
  checker while holding dl_lock.

  We achieve that in part by directly using the low-level __try_lock
  and manually unlocking on the dl_lock, and making some functions
  "nomcount".

  In addition, we mark the dl_lock as being in the console path to
  avoid deadlocks with the UART driver.

  We move the enabling of the deadlock checker to a separate config
  option from DEBUG_LOCKS as well, in case we chose to disable it
  by default later on.
- xscom-utils/adu_scoms.py: run 2to3 over it
- clang: -Wno-error=ignored-attributes

CI, testing, and utilities
--------------------------

Since v6.1-rc2:

- opal-ci: Drop fedora27, add fedora29
- ci: Bump Qemu version

  This moves the qemu version to qemu-powernv-for-skiboot-7 which is based
  on upstream's 3.1.0, and supports a Power9 machine.

  It also includes a fix for the skiboot XSCOM errors: ::

     XSCOM: read error gcid=0x0 pcb_addr=0x1020013 stat=0x0

  There is no modelling of the xscom behaviour but the reads/writes
  now succeed which is enough for skiboot to not error out.
- test: Update qemu arguments to use bmc simulator

  THe qemu skiboot platform as of 8340a9642bba ("plat/qemu: use the common
  OpenPOWER routines to initialize") uses the common aspeed BMC setup
  routines. This means a BT interface is always set up, and if the
  corresponding Qemu model is not present the timeout is 30 seconds.

  It looks like this every time an IPMI message is sent: ::

     BT: seq 0x9e netfn 0x06 cmd 0x31: Maximum queue length exceeded
     BT: seq 0x9d netfn 0x06 cmd 0x31: Removed from queue
     BT: seq 0x9f netfn 0x06 cmd 0x31: Maximum queue length exceeded
     BT: seq 0x9e netfn 0x06 cmd 0x31: Removed from queue
     BT: seq 0xa0 netfn 0x06 cmd 0x31: Maximum queue length exceeded
     BT: seq 0x9f netfn 0x06 cmd 0x31: Removed from queue

  Avoid this by adding the bmc simulator model to the Qemu powernv
  machine.
- ci: Add opal-utils to Debian unstable

  This puts a 'pflash' in the users PATH, allowing more test coverage of
  ffspart.
- ci: Drop P8 mambo from Debian unstable

  Debian Unstable has removed OpenSSL 1.0.0 from the repository so mambo
  no longer runs: ::

      /opt/ibm/systemsim-p8/bin/systemsim-pegasus: error while loading shared
      libraries: libcrypto.so.1.0.0: cannot open shared object file: No such
      file or directory

  By removing it from the container these tests will be automatically
  skipped.

  Tracked in https://github.com/open-power/op-build/issues/2519
- ci: Add dtc dependencies for rawhide

  Both F28 and Rawhide build their own dtc version. Rawhide was missing
  the required build deps.
- ci: Update Debian unstable packages

  This syncs Debian unstable with Ubuntu 18.04 in order to get the clang
  package. It also adds qemu to the Debian install, which makes sense
  Debian also has 2.12.
- ci: Use Ubuntu latest config for Debian unstable

  Debian unstable has the same GCOV issue with 8.2 as Ubuntu latest so it
  makes sense to share configurations there.
- ci: Disable GCOV builds in ubuntu-latest

  They are known to be broken with GCC 8.2:
  https://github.com/open-power/skiboot/issues/206
- ci: Update gcov comment in Fedora 28
- plat/qemu: fix platform initialization when the BT device is not present

  A QEMU PowerNV machine does not necessarily have a BT device. It needs
  to be defined on the command line with : ::

      -device ipmi-bmc-sim,id=bmc0 -device isa-ipmi-bt,bmc=bmc0,irq=10

  When the QEMU platform is initialized by skiboot, we need to check
  that such a device is present and if not, skip the AST initialization.

Since v6.1-rc1:

- travis: Coverity fixed their SSL cert
- opal-ci: Use ubuntu:rolling for Ubuntu latest image
- ffspart: Add test for eraseblock size
- ffspart: Add toc test
- hdata/test: workaround dtc bugs

  In dtc v1.4.5 to at least v1.4.7 there have been a few bugs introduced
  that change the layout of what's produced in the dts. In order to be
  immune from them, we should use the (provided) dtdiff utility, but we
  also need to run the dts we're diffing against through a dtb cycle in
  order to ensure we get the same format as what the hdat_to_dt to dts
  conversion will.

  This fixes a bunch of unit test failures on the version of dtc shipped
  with recent Linux distros such as Fedora 29.


Mambo Platform
^^^^^^^^^^^^^^

- mambo: Merge PMEM_DISK and PMEM_VOLATILE code

  PMEM_VOLATILE and PMEM_DISK can't be used together and are basically
  copies of the same code.

  This merges the two and allows them used together.  Same API is kept.
- hw/chiptod: test QUIRK_NO_CHIPTOD in opal_resync_timebase

  This allows some test coverage of deep stop states in Linux with
  Mambo.
- core/mem_region: mambo reserve kernel payload areas

  Mambo image payloads get overwritten by the OS and by
  fast reboot memory clearing because they have no region
  defined. Add them, which allows fast reboot to work.

Qemu platform
^^^^^^^^^^^^^

Since v6.2-rc2:
- plat/qemu: use the common OpenPOWER routines to initialize

  Back in 2016, we did not have a large support of the PowerNV devices
  under QEMU and we were using our own custom ones. This has changed and
  we can now use all the common init routines of the OpenPOWER
  platforms.

Since v6.1:

- nx: Don't abort on missing NX when using a QEMU machine

  These don't have an NX node (and probably never will) as they
  don't provide any coprocessor. However, the DARN instruction
  works so this abort is unnecessary.

POWER8 Platforms
----------------
- SBE-p8: Do all sbe timer update with xscom lock held

  Without this, on some P8 platforms, we could (falsely) think the SBE timer
  had stalled getting the dreaded "timer stuck" message.

  The code was doing the mftb() to set the start of the timeout period while
  *not* holding the lock, so the 1ms timeout started sometime when somebody
  else had the xscom lock.

  The simple solution is to just do the whole routine holding the xscom lock,
  so do it that way.

Vesnin Platform
^^^^^^^^^^^^^^^
- platforms/astbmc/vesnin: Send list of PCI devices to BMC through IPMI

  Implements sending a list of installed PCI devices through IPMI protocol.
  Each PCI device description is sent as a standalone IPMI message.
  A list of devices can be gathered from separate messages using the
  session identifier. The session Id is an incremental counter that is
  updated at the start of synchronization session.


POWER9 Platforms
----------------

- STOP API: API conditionally supports 255 SCOM restore entries for each quad.
- hdata/i2c: Skip unknown device type

  Do not add unknown I2C devices to device tree.
- hdata/i2c: Add whitelisting for Host I2C devices

  Many of the devices that we get information about through HDAT are for
  use by firmware rather than the host operating system. This patch adds
  a boolean flag to hdat_i2c_info structure that indicates whether devices
  with a given purpose should be reserved for use inside of OPAL (or some
  other firmware component, such as the OCC).
- hdata/iohub: Fix Cumulus Hub ID number
- opal/hmi: Wakeup the cpu before reading core_fir

  When stop state 5 is enabled, reading the core_fir during an HMI can
  result in a xscom read error with xscom_read() returning an
  OPAL_XSCOM_PARTIAL_GOOD error code and core_fir value of all FFs. At
  present this return error code is not handled in decode_core_fir()
  hence the invalid core_fir value is sent to the kernel where it
  interprets it as a FATAL hmi causing a system check-stop.

  This can be prevented by forcing the core to wake-up using before
  reading the core_fir. Hence this patch wraps the call to
  read_core_fir() within calls to dctl_set_special_wakeup() and
  dctl_clear_special_wakeup().
- xive: Disable block tracker

  Due to some HW errata, the block tracking facility (performance optimisation
  for large systems) should be disabled on Nimbus chips. Disable it unconditionally
  for now.
- opal/hmi: Ignore debug trigger inject core FIR.

  Core FIR[60] is a side effect of the work around for the CI Vector Load
  issue in DD2.1. Usually this gets delivered as HMI with HMER[17] where
  Linux already ignores it. But it looks like in some cases we may happen
  to see CORE_FIR[60] while we are already in Malfunction Alert HMI
  (HMER[0]) due to other reasons e.g. CAPI recovery or NPU xstop. If that
  happens then just ignore it instead of crashing kernel as not recoverable.
- hdata: Make sure reserved node name starts with "ibm, "

  HDAT does not provide consistent label format for reserved memory label.
  Few starts with "ibm," while few other starts with component name.
- hdata: Fix dtc warnings

  Fix dtc warnings related to mcbist node. ::

    Warning (reg_format): "reg" property in /xscom@623fc00000000/mcbist@1 has invalid length (4 bytes) (#address-cells == 1, #size-cells == 1)
    Warning (reg_format): "reg" property in /xscom@623fc00000000/mcbist@2 has invalid length (4 bytes) (#address-cells == 1, #size-cells == 1)
    Warning (reg_format): "reg" property in /xscom@603fc00000000/mcbist@1 has invalid length (4 bytes) (#address-cells == 1, #size-cells == 1)
    Warning (reg_format): "reg" property in /xscom@603fc00000000/mcbist@2 has invalid length (4 bytes) (#address-cells == 1, #size-cells == 1)

  Ideally we should add proper xscom range here... but we are not getting that
  information in HDAT today. Lets fix warning until we get proper data in HDAT.

PHB4
^^^^

- phb4: Generate checkstop on AIB ECC corr/uncorr for DD2.0 parts

  On DD2.0 parts, PCIe ECC protection is not warranted in the response
  data path. Thus, for these parts, we need to flag any ECC errors
  detected from the adjacent AIB RX Data path so the part can be
  replaced.

  This patch configures the FIRs so that we escalate these AIB ECC
  errors to a checkstop so the parts can be replaced.
- phb4: Reset pfir and nfir if new errors reported during ETU reset

  During fast-reboot new PEC errors can be latched even after ETU-Reset
  is asserted. This will result in values of variables nfir_cache and
  pfir_cache to be out of sync.

  During step-2 of CRESET nfir_cache and pfir_cache values are used to
  bring the PHB out of reset state. However if these variables are out
  as noted above of date the nfir/pfir registers are never reset
  completely and ETU still remains frozen.

  Hence this patch updates step-2 of phb4_creset to re-read the values of
  nfir/pfir registers to check if any new errors were reported after
  ETU-reset was asserted, report these new errors and reset the
  nfir/pfir registers. This should bring the ETU out of reset
  successfully.
- phb4: Disable nodal scoped DMA accesses when PB pump mode is enabled

  By default when a PCIe device issues a read request via the PHB it is first
  issued with nodal scope. When accessing GPU memory the NPU does not know at the
  time of response if the requested memory page is off node or not. Therefore
  every read of GPU memory by a PHB is retried with larger scope which introduces
  bandwidth and latency issues.

  On smaller boxes which have pump mode enabled nodal and group scoped reads are
  treated the same and both types of request are broadcast to one chip. Therefore
  we can avoid the retry by disabling nodal scope on the PHB for these boxes. On
  larger boxes nodal (single chip) and group (multiple chip) scoped reads are
  treated differently. Therefore we avoid disabling nodal scope on large boxes
  which have pump mode disabled to avoid all PHB requests being broadcast to
  multiple chips.
- phb4/capp: Only reset FIR bits that cause capp machine check

  During CAPP recovery do_capp_recovery_scoms() will reset the CAPP Fir
  register just after CAPP recovery is completed. This has an
  unintentional side effect of preventing PRD from analyzing and
  reporting this error. If PRD tries to read the CAPP FIR after opal has
  already reset it, then it logs a critical error complaining "No active
  error bits found".

  To prevent this from happening we update do_capp_recovery_scoms() to
  only reset fir bits that cause CAPP machine check (local xstop). This
  is done by reading the CAPP Fir Action0/1 & Mask registers and
  generating a mask which is then written on CAPP_FIR_CLEAR register.

- phb4: Check for RX errors after link training

  Some PHB4 PHYs can get stuck in a bad state where they are constantly
  retraining the link. This happens transparently to skiboot and Linux
  but will causes PCIe to be slow. Resetting the PHB4 clears the
  problem.

  We can detect this case by looking at the RX errors count where we
  check for link stability. This patch does this by modifying the link
  optimal code to check for RX errors. If errors are occurring we
  retrain the link irrespective of the chip rev or card.

  Normally when this problem occurs, the RX error count is maxed out at
  255. When there is no problem, the count is 0. We chose 8 as the max
  rx errors value to give us some margin for a few errors. There is also
  a knob that can be used to set the error threshold for when we should
  retrain the link. ie ::

      nvram -p ibm,skiboot --update-config phb-rx-err-max=8

- hw/phb4: Add a helper to dump the PELT-V

  The "Partitionable Endpoint Lookup Table (Vector)" is used by the PHB
  when processing EEH events. The PELT-V defines which PEs should be
  additionally frozen in the event of an error being flagged on a
  given PE. Knowing the state of the PELT-V is sometimes useful for
  debugging PHB issues so this patch adds a helper to dump it.

- hw/phb4: Print the PEs in the EEH dump in hex

  Linux always displays the PE number in hexidecimal while skiboot
  displays the PEST index (PE number) in decimal. This makes correlating
  errors between Skiboot and Linux more annoying than it should be so
  this patch makes Skiboot print the PEST number in hex.

- phb4: Reallocate PEC2 DMA-Read engines to improve GPU-Direct bandwidth

  We reallocate additional 16/8 DMA-Read engines allocated to stack0/1
  on PEC2 respectively. This is needed to improve bandwidth available to
  the Mellanox CX5 adapter when trying to read GPU memory (GPU-Direct).

  If kernel cxl driver indicates a request to allocate maximum possible
  DMA read engines when calling enable_capi_mode() and card is attached
  to PEC2/stack0 slot then we assume its a Mellanox CX5 adapter. We then
  allocate additional 16/8 extra DMA read engines to stack0 and stack1
  respectively on PEC2. This is done by populating the
  XPEC_PCI_PRDSTKOVR and XPEC_NEST_READ_STACK_OVERRIDE as suggested by
  the h/w team.
- phb4: Enable PHB MMIO-0/1 Bars only when mmio window exists

  Presently phb4_probe_stack() will always enable PHB MMIO0/1 windows
  even if they doesn't exist in phy_map. Hence we do some minor shuffling
  in the phb4_probe_stack() so that MMIO-0/1 Bars are only enabled if
  there corresponding MMIO window exists in the phy_map. In case phy_map
  for an mmio window is '0' we set the corresponding BAR register to
  '0'.
- hw/phb4: Use local_alloc for phb4 structures

  Struct phb4 is fairly heavyweight at 283664 bytes. On systems with
  6x PHBs per socket this results in using 3.2MB of heap space the PHB
  structures alone. This is a fairly large chunk of our 12MB heap and
  on systems with particularly large PCIe topologies, or additional
  PHBs we can fail to boot because we cannot allocate space for the
  FDT blob.

  This patch switches to using local_alloc() for the PHB structures
  so they don't consume too large a portion of our 12MB heap space.
- phb4: Fix typo in disable lane eq code

  In this commit ::

      commit 737c0ba3d72b8aab05a765a9fc111a48faac0f75
      Author: Michael Neuling <mikey@neuling.org>
      Date:   Thu Feb 22 10:52:18 2018 +1100
      phb4: Disable lane eq when retrying some nvidia GEN3 devices

  We made a typo and set PH2 twice. This fixes it.

  It worked previously as if only phase 2 (PH2) is set it, skips phase 2
  and phase 3 (PH3).
- phb4: Don't probe a PHB if its garded

  Presently phb4_probe_stack() causes an exception while trying to probe
  a PHB if its garded. This causes skiboot to go into a reboot loop with
  following exception log: ::

     ***********************************************
     Fatal MCE at 000000003006ecd4   .probe_phb4+0x570
     CFAR : 00000000300b98a0
     <snip>
     Aborting!
    CPU 0018 Backtrace:
     S: 0000000031cc37e0 R: 000000003001a51c   ._abort+0x4c
     S: 0000000031cc3860 R: 0000000030028170   .exception_entry+0x180
     S: 0000000031cc3a40 R: 0000000000001f10 *
     S: 0000000031cc3c20 R: 000000003006ecb0   .probe_phb4+0x54c
     S: 0000000031cc3e30 R: 0000000030014ca4   .main_cpu_entry+0x5b0
     S: 0000000031cc3f00 R: 0000000030002700   boot_entry+0x1b8

  This is caused as phb4_probe_stack() will ignore all xscom read/write
  errors to enable PHB Bars and then tries to perform an mmio to read
  PHB Version registers that cause the fatal MCE.

  We fix this by ignoring the PHB probe if the first xscom_write() to
  populate the PHB Bar register fails, which indicates that there is
  something wrong with the PHB.
- phb4: Workaround PHB errata with CFG write UR/CA errors

  If the PHB encounters a UR or CA status on a CFG write, it will
  incorrectly freeze the wrong PE. Instead of using the PE# specified
  in the CONFIG_ADDRESS register, it will use the PE# of whatever
  MMIO occurred last.

  Work around this disabling freeze on such errors
- phb4: Handle allocation errors in phb4_eeh_dump_regs()

  If the zalloc fails (and it can be a rather large allocation),
  we will overwite memory at 0 instead of failing.
- phb4: Don't try to access non-existent PEST entries

  In a POWER9 chip, some PHB4s have 256 PEs, some have 512.

  Currently, the diagnostics code retrieves 512 unconditionally,
  which is wrong and causes us to incorrectly report bogus values
  for the "high" PEs on the small PHBs.

  Use the actual number of implemented PEs instead

CAPI2
^^^^^

- phb4/capp: Use link width to allocate STQ engines to CAPP

  Update phb4_init_capp_regs() to allocates STQ Engines to CAPP/PEC2
  based on link width instead of always assuming it to x8.

  Also re-factor the function slightly to evaluate the link-width only
  once and cache it so that it can also be used to allocate DMA read
  engines.
- phb4/capp: Update DMA read engines set in APC_FSM_READ_MASK based on link-width

  Commit 47c09cdfe7a3("phb4/capp: Calculate STQ/DMA read engines based
  on link-width for PEC") update the CAPP init sequence by calculating
  the needed STQ/DMA-read engines based on link width and populating it
  in XPEC_NEST_CAPP_CNTL register. This however needs to be synchronized
  with the value set in CAPP APC FSM Read Machine Mask Register.

  Hence this patch update phb4_init_capp_regs() to calculate the link
  width of the stack on PEC2 and populate the same values as previously
  populated in PEC CAPP_CNTL register.
- capp: Fix the capp recovery timeout comparison

  The current capp recovery timeout control loop in
  do_capp_recovery_scoms() uses a wrong comparison for return value of
  tb_compare(). This may cause do_capp_recovery_scoms() to report an
  timeout earlier than the 168ms stipulated time.

  The patch fixes this by updating the loop timeout control branch in
  do_capp_recovery_scoms() to use the correct enum tb_cmpval.
- phb4: Disable 32-bit MSI in capi mode

  If a capi device does a DMA write targeting an address lower than 4GB,
  it does so through a 32-bit operation, per the PCI spec. In capi mode,
  the first TVE entry is configured in bypass mode, so the address is
  valid. But with any (bad) luck, the address could be 0xFFFFxxxx, thus
  looking like a 32-bit MSI.

  We currently enable both 32-bit and 64-bit MSIs, so the PHB will
  interpret the DMA write as a MSI, which very likely results in an EEH
  (MSI with a bad payload size).

  We can fix it by disabling 32-bit MSI when switching the PHB to capi
  mode. Capi devices are 64-bit.

NVLINK2
^^^^^^^

Since v6.2-rc2:
- Add purging CPU L2 and L3 caches into NPU hreset.

  If a GPU is passed through to a guest and the guest unexpectedly terminates,
  there can be cache lines in CPUs that belong to the GPU. So purge the caches
  as part of the reset sequence. L1 is write through, so doesn't need to be purged.

  The sequence to purge the L2 and L3 caches from the hw team:

  L2 purge:
  1. initiate purge ::

      putspy pu.ex EXP.L2.L2MISC.L2CERRS.PRD_PURGE_CMD_TYPE L2CAC_FLUSH -all
      putspy pu.ex EXP.L2.L2MISC.L2CERRS.PRD_PURGE_CMD_TRIGGER ON -all

  2. check this is off in all caches to know purge completed ::

      getspy pu.ex EXP.L2.L2MISC.L2CERRS.PRD_PURGE_CMD_REG_BUSY -all

  3. ::

      putspy pu.ex EXP.L2.L2MISC.L2CERRS.PRD_PURGE_CMD_TRIGGER OFF -all

  L3 purge:
  1. Start the purge: ::

      putspy pu.ex EXP.L3.L3_MISC.L3CERRS.L3_PRD_PURGE_TTYPE FULL_PURGE -all
      putspy pu.ex EXP.L3.L3_MISC.L3CERRS.L3_PRD_PURGE_REQ ON -all

  2. Ensure that the purge has completed by checking the status bit: ::

      getspy pu.ex EXP.L3.L3_MISC.L3CERRS.L3_PRD_PURGE_REQ -all

     You should see it say OFF if it's done: ::

       p9n.ex k0:n0:s0:p00:c0
       EXP.L3.L3_MISC.L3CERRS.L3_PRD_PURGE_REQ
       OFF

- npu2: Return sensible PCI error when not frozen

  The current kernel calls OPAL_PCI_EEH_FREEZE_STATUS with an uninitialized
  @pci_error_type parameter and then analyzes it even if the OPAL call
  returned OPAL_SUCCESS. This is results in unexpected EEH events and NPU
  freezes.

  This initializes @pci_error_type and @severity to known safe values.

- npu2: Advertise correct TCE page size

  The P9 NPU workbook says that only 4K/64K/16M/256M page size are supported
  and in fact npu2_map_pe_dma_window() supports just these but in absence of
  the "ibm,supported-tce-sizes" property Linux assumes the default P9 PHB4
  page sizes - 4K/64K/2M/1G - so when Linux tries 2M/1G TCEs, we get lots of
  "Unexpected TCE size" from npu2_tce_kill().

  This advertises TCE page sizes so Linux could handle it correctly, i.e.
  fall back to 4K/64K TCEs.

Since v6.1:

- npu2: Add support for relaxed-ordering mode

  Some device drivers support out of order access to GPU memory. This does
  not affect the CPU view of memory but it does affect the GPU view of
  memory. It should only be enabled if the GPU driver has requested it.

  Add OPAL APIs allowing the driver to query relaxed ordering state or
  request it to be set for a device. Current hardware only allows relaxed
  ordering to be enabled per PCIe root port. So the code here doesn't
  enable relaxed ordering until it has been explicitly requested for every
  device on the port.
- Add the other 7 ATSD registers to the device tree.
- npu2/hw-procedures: Don't open code NPU2_NTL_MISC_CFG2_BRICK_ENABLE

  Name this bit properly. There's a lot more cleanup like this to be done,
  but I'm catching this one now as part of some related changes.
- npu2/hw-procedures: Enable parity and credit overflow checks

  Enable these error checking features by setting the appropriate bits in
  our one-off initialization of each "NTL Misc Config 2" register.

  The exception is NDL RX parity checking, which should be disabled during
  the link training procedures.
- npu2: Use correct kill type for TCE invalidation

  kill_type is enum of OPAL_PCI_TCE_KILL_PAGES, OPAL_PCI_TCE_KILL_PE,
  OPAL_PCI_TCE_KILL_ALL and phb4_tce_kill() gets it right but
  npu2_tce_kill() uses OPAL_PCI_TCE_KILL which is an OPAL API token.

  This fixes an obvious mistype.

OpenCAPI
^^^^^^^^

Since v6.2-rc1:

- npu2-opencapi: Log extra information on link training failure
- npu2-opencapi: Detect if link trained in degraded mode

Since v6.1:

- Support OpenCAPI on Witherspoon platform
- npu2-opencapi: Enable presence detection on ZZ

  Presence detection for opencapi adapters was broken for ZZ planars v3
  and below. All ZZ systems currently used in the lab have had their
  planar upgraded, so we can now remove the override we had to force
  presence and activate presence detection. Which should improve boot
  time.

  Considering the state of opal support on ZZ, this is really only for
  lab usage on BML. The opencapi enablement team has okay'd the
  change. In the unlikely case somebody tries opencapi on an old ZZ, the
  presence detection through i2c will show that no adapter is present
  and skiboot won't try to access or train the link.
- npu2-opencapi: Don't send commands to NPU when link is down

  Even if an opencapi link is down, we currently always try to issue a
  config read operation when probing for PCI devices, because of the
  default scan map used for an opencapi PHB. The config operation fails,
  as expected, but it can also raise a FIR bit and trigger an HMI.

  For opencapi, there's no root device like for a "normal" PCI PHB, so
  there's no reason to do the config operation. To fix it, we keep the
  scan map blank by default, and only add a device once the link is
  trained.
- opal/hmi: Catch NPU2 HMIs for opencapi

  HMIs for NPU2 are filtered with the 'compatible' string of the PHB, so
  add opencapi to the mix.
- occ: Wait if OCC GPU presence status not immediately available

  It takes a few seconds for the OCC to set everything up in order to read
  GPU presence. At present, we try to kick off OCC initialisation as early as
  possible to maximise the time it has to read GPU presence.

  Unfortunately sometimes that's not enough, so add a loop in
  occ_get_gpu_presence() so that on the first time we try to get GPU presence
  we keep trying for up to 2 seconds. Experimentally this seems to be
  adequate.
- hw/npu2-hw-procedures: Enable RX auto recal on OpenCAPI links

  The RX_RC_ENABLE_AUTO_RECAL flag is required on OpenCAPI but not NVLink.

  Traditionally, Hostboot sets this value according to the machine type.
  However, now that Witherspoon supports both NVLink and OpenCAPI, it can't
  tell whether or not a link is OpenCAPI.

  So instead, set it in skiboot, where it will only be triggered after we've
  done device detection and found an OpenCAPI device.
- hw/npu2-opencapi: Fix setting of supported OpenCAPI templates

  In opal_npu_tl_set(), we made a typo that means the OPAL_NPU_TL_SET call
  may not clear the enable bits for templates that were previously enabled
  but are now disabled.

  Fix the typo so we clear NPU2_OTL_CONFIG1_TX_TEMP2_EN as well as
  TEMP{1,3}_EN.

Barreleye G2 and Zaius platforms
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- zaius: Add a slot table
- zaius: Add slots for the Barreleye G2 HDD rack

  The Barreleye G2 is distinct from the Zaius in that it features a 24
  Bay NVMe/SATA HDD rack. To provide meaningful slot names for each NVMe
  device we need to define a slot table for the NVMe capable HDD bays.

  Unfortunately this isn't straightforward because the PCIe path to the
  NVMe devices isn't fixed. The PCIe topology is something like:
  P9 -> HBA card -> 9797 switch -> 20x NVMe HDD slots

  The 9797 switch is partitioned into two (or four) virtual switches which
  allow multiple HBA cards to be used (e.g. one per socket). As a result
  the exact BDFN of the ports will vary depending on how the system is
  configured.

  That said, the virtual switch configuration of the 9797 does not change
  the device and function numbers of the switch downports. This means that
  we can define a single slot table that maps switch ports to the NVMe bay
  names.

  Unfortunately we still need to guess which bus to use this table on, so
  we assume that any switch downport we find with the PEX9797 VDID is part
  of the 9797 that supports the HDD rack.

FSP based platforms (firenze and ZZ)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Since v6.2-rc1:
- platform/firenze: Fix branch-to-null crash

  When the bus alloc and free methods were removed we missed a case in the
  Firenze platform slot code that relied on the the bus-specific method to
  the bus pointer in the request structure. This results in a
  branch-to-null during boot and a crash. This patch fixes it by
  initialising it manually here.


Since v6.1:

- phb4/capp: Update the expected Eye-catcher for CAPP ucode lid

  Currently on a FSP based P9 system load_capp_code() expects CAPP ucode
  lid header to have eye-catcher magic of 'CAPPPSLL'. However skiboot
  currently supports CAPP ucode only lids that have a eye-catcher magic
  of 'CAPPLIDH'. This prevents skiboot from loading the ucode with this
  error message: ::

    CAPP: ucode header invalid

  We fix this issue by updating load_capp_ucode() to use the eye-catcher
  value of 'CAPPLIDH' instead of 'CAPPPSLL'.

- FSP: Improve Reset/Reload log message

  Below message is confusing. Lets make it clear.

  FSP sends "R/R complete notification" whenever there is a dump. We use `flag`
  to identify whether its its R/R completion -OR- just new dump notification. ::

    [  483.406351956,6] FSP: SP says Reset/Reload complete
    [  483.406354278,5] DUMP: FipS dump available. ID = 0x1a00001f [size: 6367640 bytes]
    [  483.406355968,7]   A Reset/Reload was NOT done

Witherspoon platform
^^^^^^^^^^^^^^^^^^^^

- platforms/astbmc/witherspoon: Implement OpenCAPI support

  OpenCAPI on Witherspoon is slightly more involved than on Zaius and ZZ, due
  to the OpenCAPI links using the SXM2 connectors that are used for NVLink
  GPUs.

  This patch adds the regular OpenCAPI platform information, and also a
  Witherspoon-specific presence detection callback that uses the previously
  added OCC GPU presence detection to figure out the device types plugged
  into each SXM2 socket.

  The SXM2 connectors are capable of carrying 2 OpenCAPI links, and future
  OpenCAPI devices are expected to make use of this. However, we don't yet
  support ganged links and the various implications that has for handling
  things like device reset, so for now, we only enable 1 brick per device.

Contributors
------------

The v6.2 release of skiboot contains 240 changesets from 28 developers, working for 2 employers.
A total of 9146 lines were added, and 2610 removed (delta 6536).

Developers with the most changesets
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
=========================== == =======
Developer                   #  %
=========================== == =======
Stewart Smith               58 (24.2%)
Andrew Jeffery              30 (12.5%)
Oliver O'Halloran           27 (11.2%)
Joel Stanley                17 (7.1%)
Vaibhav Jain                14 (5.8%)
Benjamin Herrenschmidt      12 (5.0%)
Frederic Barrat             11 (4.6%)
Nicholas Piggin             11 (4.6%)
Andrew Donnellan            10 (4.2%)
Vasant Hegde                 9 (3.8%)
Reza Arbab                   8 (3.3%)
Samuel Mendoza-Jonas         5 (2.1%)
Alexey Kardashevskiy         4 (1.7%)
Michael Neuling              4 (1.7%)
Prem Shanker Jha             3 (1.2%)
Cédric Le Goater             2 (0.8%)
Rashmica Gupta               2 (0.8%)
Mahesh J Salgaonkar          2 (0.8%)
Alistair Popple              2 (0.8%)
Shilpasri G Bhat             1 (0.4%)
Adriana Kobylak              1 (0.4%)
Madhavan Srinivasan          1 (0.4%)
Artem Senichev               1 (0.4%)
Russell Currey               1 (0.4%)
Vaidyanathan Srinivasan      1 (0.4%)
Cyril Bur                    1 (0.4%)
Jeremy Kerr                  1 (0.4%)
Michael Ellerman             1 (0.4%)
=========================== == =======


Developers with the most changed lines
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

========================= ==== =======
Developer                    # %
========================= ==== =======
Andrew Jeffery            2861 (29.3%)
Stewart Smith             1891 (19.4%)
Prem Shanker Jha          1046 (10.7%)
Andrew Donnellan           799 (8.2%)
Oliver O'Halloran          649 (6.6%)
Reza Arbab                 441 (4.5%)
Nicholas Piggin            412 (4.2%)
Vaibhav Jain               278 (2.8%)
Cédric Le Goater           250 (2.6%)
Frederic Barrat            168 (1.7%)
Rashmica Gupta             161 (1.6%)
Joel Stanley               152 (1.6%)
Benjamin Herrenschmidt     138 (1.4%)
Artem Senichev             101 (1.0%)
Samuel Mendoza-Jonas        83 (0.9%)
Michael Neuling             82 (0.8%)
Michael Ellerman            61 (0.6%)
Mahesh J Salgaonkar         50 (0.5%)
Vasant Hegde                44 (0.5%)
Alexey Kardashevskiy        32 (0.3%)
Adriana Kobylak             29 (0.3%)
Alistair Popple             18 (0.2%)
Shilpasri G Bhat             4 (0.0%)
Madhavan Srinivasan          3 (0.0%)
Cyril Bur                    3 (0.0%)
Jeremy Kerr                  3 (0.0%)
Russell Currey               2 (0.0%)
Vaidyanathan Srinivasan      2 (0.0%)
========================= ==== =======


Developers with the most lines removed
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

========================= ==== =======
Developer                    # %
========================= ==== =======
Cédric Le Goater           205 (7.9%)
Samuel Mendoza-Jonas         8 (0.3%)
Shilpasri G Bhat             1 (0.0%)
========================= ==== =======

Developers with the most signoffs
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

========================= ==== =======
Developer                    # %
========================= ==== =======
Stewart Smith              182 (95.3%)
Alistair Popple              3 (1.6%)
Akshay Adiga                 2 (1.0%)
Christophe Lombard           1 (0.5%)
Ryan Grimm                   1 (0.5%)
Michael Neuling              1 (0.5%)
Mahesh J Salgaonkar          1 (0.5%)
Total                      191
========================= ==== =======

Developers with the most reviews
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

================================ ==== =======
Developer                           # %
================================ ==== =======
Andrew Donnellan                   15 (19.7%)
Frederic Barrat                    11 (14.5%)
Oliver O'Halloran                   9 (11.8%)
Alistair Popple                     8 (10.5%)
Vasant Hegde                        5 (6.6%)
Samuel Mendoza-Jonas                4 (5.3%)
Christophe Lombard                  3 (3.9%)
Gregory S. Still                    3 (3.9%)
Mahesh J Salgaonkar                 2 (2.6%)
RANGANATHPRASAD G. BRAHMASAMUDRA    2 (2.6%)
Jennifer A. Stofer                  2 (2.6%)
AMIT J. TENDOLKAR                   2 (2.6%)
Christian R. Geddes                 2 (2.6%)
Cédric Le Goater                    1 (1.3%)
Shilpasri G Bhat                    1 (1.3%)
Daniel M. Crowell                   1 (1.3%)
Alexey Kardashevskiy                1 (1.3%)
Joel Stanley                        1 (1.3%)
Vaibhav Jain                        1 (1.3%)
Nicholas Piggin                     1 (1.3%)
Andrew Jeffery                      1 (1.3%)
Total                              76
================================ ==== =======

Developers with the most test credits
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

========================= ==== =======
Developer                    # %
========================= ==== =======
Jenkins Server               3 (12.0%)
Cronus HW CI                 3 (12.0%)
Hostboot CI                  3 (12.0%)
Jenkins OP Build CI          3 (12.0%)
FSP CI Jenkins               3 (12.0%)
Jenkins OP HW                3 (12.0%)
Vasant Hegde                 2 (8.0%)
Andrew Donnellan             1 (4.0%)
Oliver O'Halloran            1 (4.0%)
Andrew Jeffery               1 (4.0%)
HWSV CI                      1 (4.0%)
Artem Senichev               1 (4.0%)
Total                       25
========================= ==== =======

Developers who gave the most tested-by credits
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

========================= ==== =======
Developer                    # %
========================= ==== =======
Prem Shanker Jha            19 (76.0%)
Frederic Barrat              2 (8.0%)
Andrew Jeffery               1 (4.0%)
Vaibhav Jain                 1 (4.0%)
Stewart Smith                1 (4.0%)
Benjamin Herrenschmidt       1 (4.0%)
========================= ==== =======

Developers with the most report credits
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

========================= ==== =======
Developer                    # %
========================= ==== =======
Vasant Hegde                 2 (25.0%)
Frederic Barrat              1 (12.5%)
Dawn Sylvia                  1 (12.5%)
Meng Li                      1 (12.5%)
Tyler Seredynski             1 (12.5%)
Pridhiviraj Paidipeddi       1 (12.5%)
Stephanie Swanson            1 (12.5%)
========================= ==== =======

Developers who gave the most report credits
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

========================= ==== =======
Developer                    # %
========================= ==== =======
Stewart Smith                2 (25.0%)
Vaidyanathan Srinivasan      2 (25.0%)
Vasant Hegde                 1 (12.5%)
Vaibhav Jain                 1 (12.5%)
Andrew Donnellan             1 (12.5%)
Michael Neuling              1 (12.5%)
========================= ==== =======

Employers with the most hackers
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

========================= ==== =======
Developer                    # %
========================= ==== =======
IBM                         27 (96.4%)
YADRO                        1 (3.6%)
========================= ==== =======
