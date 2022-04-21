.. _skiboot-5.10-rc2:

skiboot-5.10-rc2
================

skiboot v5.10-rc2 was released on Friday February 9th 2018. It is the second
release candidate of skiboot 5.10, which will become the new stable release
of skiboot following the 5.9 release, first released October 31st 2017.

skiboot v5.10-rc2 contains all bug fixes as of :ref:`skiboot-5.9.8`
and :ref:`skiboot-5.4.9` (the currently maintained stable releases). There
may be more 5.9.x stable releases, it will depend on demand.

For how the skiboot stable releases work, see :ref:`stable-rules` for details.

The current plan is to cut the final 5.10 in February, with skiboot 5.10
being for all POWER8 and POWER9 platforms in op-build v1.21.
This release will be targeted to early POWER9 systems.

Over skiboot-5.10-rc1, we have the following changes:

- hw/npu2: Implement logging HMI actions
- opal-prd: Fix FTBFS with -Werror=format-overflow

  i2c.c fails to compile with gcc7 and -Werror=format-overflow used in
  Debian Unstable and Ubuntu 18.04 : ::

    i2c.c: In function ‘i2c_init’:
    i2c.c:211:15: error: ‘%s’ directive writing up to 255 bytes into a
    region of size 236 [-Werror=format-overflow=]

- core/exception: beautify exception handler, add MCE-involved registers

  Print DSISR and DAR, to help with deciphering machine check exceptions,
  and improve the output a bit, decode NIP symbol, improve alignment, etc.
  Also print a specific header for machine check, because we do expect to
  see these if there is a hardware failure.

  Before: ::

    [    0.005968779,3] ***********************************************
    [    0.005974102,3] Unexpected exception 200 !
    [    0.005978696,3] SRR0 : 000000003002ad80 SRR1 : 9000000000001000
    [    0.005985239,3] HSRR0: 00000000300027b4 HSRR1: 9000000030001000
    [    0.005991782,3] LR   : 000000003002ad80 CTR  : 0000000000000000
    [    0.005998130,3] CFAR : 00000000300b58bc
    [    0.006002769,3] CR   : 40000004  XER: 20000000
    [    0.006008069,3] GPR00: 000000003002ad80 GPR16: 0000000000000000
    [    0.006015170,3] GPR01: 0000000031c03bd0 GPR17: 0000000000000000
    [...]

  After: ::

    [    0.003287941,3] ***********************************************
    [    0.003561769,3] Fatal MCE at 000000003002ad80   .nvram_init+0x24
    [    0.003579628,3] CFAR : 00000000300b5964
    [    0.003584268,3] SRR0 : 000000003002ad80 SRR1 : 9000000000001000
    [    0.003590812,3] HSRR0: 00000000300027b4 HSRR1: 9000000030001000
    [    0.003597355,3] DSISR: 00000000         DAR  : 0000000000000000
    [    0.003603480,3] LR   : 000000003002ad68 CTR  : 0000000030093d80
    [    0.003609930,3] CR   : 40000004         XER  : 20000000
    [    0.003615698,3] GPR00: 00000000300149e8 GPR16: 0000000000000000
    [    0.003622799,3] GPR01: 0000000031c03bc0 GPR17: 0000000000000000
    [...]
- core/init: manage MSR[ME] explicitly, always enable

  The current boot sequence inherits MSR[ME] from the IPL firmware, and
  never changes it. Some environments disable MSR[ME] (e.g., mambo), and
  others can enable it (hostboot).

  This has two problems. First, MSR[ME] must be disabled while in the
  process of taking over the interrupt vector from the previous
  environment.  Second, after installing our machine check handler,
  MSR[ME] should be enabled to get some useful output rather than a
  checkstop.
- fast-reboot: occ: Re-parse the pstate table during fast-reboot

  OCC shares the frequency list to host by copying the pstate table to
  main memory in HOMER. This table is parsed during boot to create
  device-tree properties for frequency and pstate IDs. OCC can update
  the pstate table to present a new set of frequencies to the host. But
  host will remain oblivious to these changes unless it is re-inited
  with the updated device-tree CPU frequency properties. So this patch
  allows to re-parse the pstate table and update the device-tree
  properties during fast-reboot.

  OCC updates the pstate table when asked to do so using pstate-table
  bias command. And this is mainly used by WOF team for
  characterization purposes.
- fast-reboot: move pci_reset error handling into fast-reboot code

  pci_reset() currently does a platform reboot if it fails. It
  should not know about fast-reboot at this level, so instead have
  it return an error, and the fast reboot caller will do the
  platform reboot.

  The code essentially does the same thing, but flexibility is
  improved. Ideally the fast reboot code should perform pci_reset
  and all such fail-able operations before the CPU resets itself
  and destroys its own stack. That's not the case now, but that
  should be the goal.
- capi: Fix the max tlbi divider and the directory size.

  Switch to 512KB mode (directory size) as we don’t use bit 48 of the tag
  in addressing the array. This mode is controlled by the Snoop CAPI
  Configuration Register.
  Set the maximum of the number of data polls received before signaling
  TLBI hang detect timer expired. The value of '0000' is equal to 16.
- npu2/tce: Fix page size checking

  The page size is encoded in the TVT data [59:63] as @shift+11 but
  the tce_kill handler does not do the math right; this fixes it.
- stb: Enforce secure boot if called before libstb initialized
- stb: Correctly error out when no PCR for resource
- core/init: move imc catalog preload init after the STB init.

  As a safer side move the imc catalog preload after the STB init
  to make sure the imc catalog resource get's verified and measured
  properly during loading when both secure and trusted boot modes
  are on.
- libstb: fix failure of calling trusted measure without STB initialization.

  When we load a flash resource during OPAL init, STB calls trusted measure
  to measure the given resource. There is a situation when a flash gets loaded
  before STB initialization then trusted measure cannot measure properly.

  So this patch fixes this issue by calling trusted measure only if the
  corresponding trusted init was done.

  The ideal fix is to make sure STB init done at the first place during init
  and then do the loading of flash resources, by that way STB can properly
  verify and measure the all resources.
- libstb: fix failure of calling cvc verify without STB initialization.

  Currently in OPAL init time at various stages we are loading various
  PNOR partition containers from the flash device. When we load a flash
  resource STB calls the CVC verify and trusted measure(sha512) functions.
  So when we have a flash resource gets loaded before STB initialization,
  then cvc verify function fails to start the verify and enforce the boot.

  Below is one of the example failure where our VERSION partition gets
  loading early in the boot stage without STB initialization done.

  This is with secure mode off.
  STB: VERSION NOT VERIFIED, invalid param. buf=0x305ed930, len=4096 key-hash=0x0 hash-size=0

  In the same code path when secure mode is on, the boot process will abort.

  So this patch fixes this issue by calling cvc verify only if we have
  STB init was done.

  And also we need a permanent fix in init path to ensure STB init gets
  done at first place and then start loading all other flash resources.
- libstb/tpm_chip: Add missing new line to print messages.
- libstb: increase the log level of verify/measure messages to PR_NOTICE.

  Currently libstb logs the verify and hash caluculation messages in
  PR_INFO level. So when there is a secure boot enforcement happens
  in loading last flash resource(Ex: BOOTKERNEL), the previous verify
  and measure messages are not logged to console, which is not clear
  to the end user which resource is verified and measured.
  So this patch fixes this by increasing the log level to PR_NOTICE.
