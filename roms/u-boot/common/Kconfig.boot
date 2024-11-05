menu "Boot options"

menu "Boot images"

config ANDROID_BOOT_IMAGE
	bool "Enable support for Android Boot Images"
	default y if FASTBOOT
	help
	  This enables support for booting images which use the Android
	  image format header.

config FIT
	bool "Support Flattened Image Tree"
	select MD5
	select SHA1
	help
	  This option allows you to boot the new uImage structure,
	  Flattened Image Tree.  FIT is formally a FDT, which can include
	  images of various types (kernel, FDT blob, ramdisk, etc.)
	  in a single blob.  To boot this new uImage structure,
	  pass the address of the blob to the "bootm" command.
	  FIT is very flexible, supporting compression, multiple images,
	  multiple configurations, verification through hashing and also
	  verified boot (secure boot using RSA).

if FIT

config FIT_EXTERNAL_OFFSET
	hex "FIT external data offset"
	default 0x0
	help
	  This specifies a data offset in fit image.
	  The offset is from data payload offset to the beginning of
	  fit image header. When specifies a offset, specific data
	  could be put in the hole between data payload and fit image
	  header, such as CSF data on i.MX platform.

config FIT_ENABLE_SHA256_SUPPORT
	bool "Support SHA256 checksum of FIT image contents"
	default y
	select SHA256
	help
	  Enable this to support SHA256 checksum of FIT image contents. A
	  SHA256 checksum is a 256-bit (32-byte) hash value used to check that
	  the image contents have not been corrupted.

config FIT_ENABLE_SHA384_SUPPORT
	bool "Support SHA384 checksum of FIT image contents"
	default n
	select SHA384
	help
	  Enable this to support SHA384 checksum of FIT image contents. A
	  SHA384 checksum is a 384-bit (48-byte) hash value used to check that
	  the image contents have not been corrupted. Use this for the highest
	  security.

config FIT_ENABLE_SHA512_SUPPORT
	bool "Support SHA512 checksum of FIT image contents"
	default n
	select SHA512
	help
	  Enable this to support SHA512 checksum of FIT image contents. A
	  SHA512 checksum is a 512-bit (64-byte) hash value used to check that
	  the image contents have not been corrupted.

config FIT_FULL_CHECK
	bool "Do a full check of the FIT before using it"
	default y
	help
	  Enable this do a full check of the FIT to make sure it is valid. This
	  helps to protect against carefully crafted FITs which take advantage
	  of bugs or omissions in the code. This includes a bad structure,
	  multiple root nodes and the like.

config FIT_SIGNATURE
	bool "Enable signature verification of FIT uImages"
	depends on DM
	select HASH
	select RSA
	select RSA_VERIFY
	select IMAGE_SIGN_INFO
	select FIT_FULL_CHECK
	help
	  This option enables signature verification of FIT uImages,
	  using a hash signed and verified using RSA. If
	  CONFIG_SHA_PROG_HW_ACCEL is defined, i.e support for progressive
	  hashing is available using hardware, then the RSA library will use
	  it. See doc/uImage.FIT/signature.txt for more details.

	  WARNING: When relying on signed FIT images with a required signature
	  check the legacy image format is disabled by default, so that
	  unsigned images cannot be loaded. If a board needs the legacy image
	  format support in this case, enable it using
	  CONFIG_LEGACY_IMAGE_FORMAT.

config FIT_SIGNATURE_MAX_SIZE
	hex "Max size of signed FIT structures"
	depends on FIT_SIGNATURE
	default 0x10000000
	help
	  This option sets a max size in bytes for verified FIT uImages.
	  A sane value of 256MB protects corrupted DTB structures from overlapping
	  device memory. Assure this size does not extend past expected storage
	  space.

config FIT_ENABLE_RSASSA_PSS_SUPPORT
	bool "Support rsassa-pss signature scheme of FIT image contents"
	depends on FIT_SIGNATURE
	default n
	help
	  Enable this to support the pss padding algorithm as described
	  in the rfc8017 (https://tools.ietf.org/html/rfc8017).

config FIT_CIPHER
	bool "Enable ciphering data in a FIT uImages"
	depends on DM
	select AES
	help
	  Enable the feature of data ciphering/unciphering in the tool mkimage
	  and in the u-boot support of the FIT image.

config FIT_VERBOSE
	bool "Show verbose messages when FIT images fail"
	help
	  Generally a system will have valid FIT images so debug messages
	  are a waste of code space. If you are debugging your images then
	  you can enable this option to get more verbose information about
	  failures.

config FIT_BEST_MATCH
	bool "Select the best match for the kernel device tree"
	help
	  When no configuration is explicitly selected, default to the
	  one whose fdt's compatibility field best matches that of
	  U-Boot itself. A match is considered "best" if it matches the
	  most specific compatibility entry of U-Boot's fdt's root node.
	  The order of entries in the configuration's fdt is ignored.

config FIT_IMAGE_POST_PROCESS
	bool "Enable post-processing of FIT artifacts after loading by U-Boot"
	depends on TI_SECURE_DEVICE || SOCFPGA_SECURE_VAB_AUTH
	help
	  Allows doing any sort of manipulation to blobs after they got extracted
	  from FIT images like stripping off headers or modifying the size of the
	  blob, verification, authentication, decryption etc. in a platform or
	  board specific way. In order to use this feature a platform or board-
	  specific implementation of board_fit_image_post_process() must be
	  provided. Also, anything done during this post-processing step would
	  need to be comprehended in how the images were prepared before being
	  injected into the FIT creation (i.e. the blobs would have been pre-
	  processed before being added to the FIT image).

config FIT_PRINT
        bool "Support FIT printing"
        default y
        help
          Support printing the content of the fitImage in a verbose manner.

if SPL

config SPL_FIT
	bool "Support Flattened Image Tree within SPL"
	depends on SPL
	select SPL_OF_LIBFDT

config SPL_FIT_PRINT
	bool "Support FIT printing within SPL"
	depends on SPL_FIT
	help
	  Support printing the content of the fitImage in a verbose manner in SPL.

config SPL_FIT_FULL_CHECK
	bool "Do a full check of the FIT before using it"
	help
	  Enable this do a full check of the FIT to make sure it is valid. This
	  helps to protect against carefully crafted FITs which take advantage
	  of bugs or omissions in the code. This includes a bad structure,
	  multiple root nodes and the like.


config SPL_FIT_SIGNATURE
	bool "Enable signature verification of FIT firmware within SPL"
	depends on SPL_DM
	depends on SPL_LOAD_FIT || SPL_LOAD_FIT_FULL
	select FIT_SIGNATURE
	select SPL_FIT
	select SPL_CRYPTO_SUPPORT
	select SPL_HASH_SUPPORT
	select SPL_RSA
	select SPL_RSA_VERIFY
	select SPL_IMAGE_SIGN_INFO
	select SPL_FIT_FULL_CHECK

config SPL_LOAD_FIT
	bool "Enable SPL loading U-Boot as a FIT (basic fitImage features)"
	select SPL_FIT
	help
	  Normally with the SPL framework a legacy image is generated as part
	  of the build. This contains U-Boot along with information as to
	  where it should be loaded. This option instead enables generation
	  of a FIT (Flat Image Tree) which provides more flexibility. In
	  particular it can handle selecting from multiple device tree
	  and passing the correct one to U-Boot.

	  This path has the following limitations:

	  1. "loadables" images, other than FDTs, which do not have a "load"
	     property will not be loaded. This limitation also applies to FPGA
	     images with the correct "compatible" string.
	  2. For FPGA images, only the "compatible" = "u-boot,fpga-legacy"
	     loading method is supported.
	  3. FDTs are only loaded for images with an "os" property of "u-boot".
	     "linux" images are also supported with Falcon boot mode.

config SPL_LOAD_FIT_ADDRESS
	hex "load address of fit image"
	depends on SPL_LOAD_FIT
	default 0x0
	help
	  Specify the load address of the fit image that will be loaded
	  by SPL.

config SPL_LOAD_FIT_APPLY_OVERLAY
	bool "Enable SPL applying DT overlays from FIT"
	depends on SPL_LOAD_FIT
	select OF_LIBFDT_OVERLAY
	help
	  The device tree is loaded from the FIT image. Allow the SPL is to
	  also load device-tree overlays from the FIT image an apply them
	  over the device tree.

config SPL_LOAD_FIT_APPLY_OVERLAY_BUF_SZ
	depends on SPL_LOAD_FIT_APPLY_OVERLAY
	default 0x10000
	hex "size of temporary buffer used to load the overlays"
	help
	  The size of the area where the overlays will be loaded and
	  uncompress. Must be at least as large as biggest overlay
	  (uncompressed)

config SPL_LOAD_FIT_FULL
	bool "Enable SPL loading U-Boot as a FIT (full fitImage features)"
	select SPL_FIT
	help
	  Normally with the SPL framework a legacy image is generated as part
	  of the build. This contains U-Boot along with information as to
	  where it should be loaded. This option instead enables generation
	  of a FIT (Flat Image Tree) which provides more flexibility. In
	  particular it can handle selecting from multiple device tree
	  and passing the correct one to U-Boot.

config SPL_FIT_IMAGE_POST_PROCESS
	bool "Enable post-processing of FIT artifacts after loading by the SPL"
	depends on SPL_LOAD_FIT
	help
	  Allows doing any sort of manipulation to blobs after they got extracted
	  from the U-Boot FIT image like stripping off headers or modifying the
	  size of the blob, verification, authentication, decryption etc. in a
	  platform or board specific way. In order to use this feature a platform
	  or board-specific implementation of board_fit_image_post_process() must
	  be provided. Also, anything done during this post-processing step would
	  need to be comprehended in how the images were prepared before being
	  injected into the FIT creation (i.e. the blobs would have been pre-
	  processed before being added to the FIT image).

config SPL_FIT_SOURCE
	string ".its source file for U-Boot FIT image"
	depends on SPL_FIT
	help
	  Specifies a (platform specific) FIT source file to generate the
	  U-Boot FIT image. This could specify further image to load and/or
	  execute.

config USE_SPL_FIT_GENERATOR
	bool "Use a script to generate the .its script"
	default y if SPL_FIT && (!ARCH_SUNXI && !RISCV)

config SPL_FIT_GENERATOR
	string ".its file generator script for U-Boot FIT image"
	depends on USE_SPL_FIT_GENERATOR
	default "arch/arm/mach-rockchip/make_fit_atf.py" if SPL_LOAD_FIT && ARCH_ROCKCHIP
	default "arch/arm/mach-zynqmp/mkimage_fit_atf.sh" if SPL_LOAD_FIT && ARCH_ZYNQMP
	help
	  Specifies a (platform specific) script file to generate the FIT
	  source file used to build the U-Boot FIT image file. This gets
	  passed a list of supported device tree file stub names to
	  include in the generated image.

endif # SPL

endif # FIT

config LEGACY_IMAGE_FORMAT
	bool "Enable support for the legacy image format"
	default y if !FIT_SIGNATURE
	help
	  This option enables the legacy image format. It is enabled by
	  default for backward compatibility, unless FIT_SIGNATURE is
	  set where it is disabled so that unsigned images cannot be
	  loaded. If a board needs the legacy image format support in this
	  case, enable it here.

config SUPPORT_RAW_INITRD
	bool "Enable raw initrd images"
	help
	  Note, defining the SUPPORT_RAW_INITRD allows user to supply
	  kernel with raw initrd images. The syntax is slightly different, the
	  address of the initrd must be augmented by it's size, in the following
	  format: "<initrd address>:<initrd size>".

config OF_BOARD_SETUP
	bool "Set up board-specific details in device tree before boot"
	depends on OF_LIBFDT
	help
	  This causes U-Boot to call ft_board_setup() before booting into
	  the Operating System. This function can set up various
	  board-specific information in the device tree for use by the OS.
	  The device tree is then passed to the OS.

config OF_SYSTEM_SETUP
	bool "Set up system-specific details in device tree before boot"
	depends on OF_LIBFDT
	help
	  This causes U-Boot to call ft_system_setup() before booting into
	  the Operating System. This function can set up various
	  system-specific information in the device tree for use by the OS.
	  The device tree is then passed to the OS.

config OF_STDOUT_VIA_ALIAS
	bool "Update the device-tree stdout alias from U-Boot"
	depends on OF_LIBFDT
	help
	  This uses U-Boot's serial alias from the aliases node to update
	  the device tree passed to the OS. The "linux,stdout-path" property
	  in the chosen node is set to point to the correct serial node.
	  This option currently references CONFIG_CONS_INDEX, which is
	  incorrect when used with device tree as this option does not
	  exist / should not be used.

config SYS_EXTRA_OPTIONS
	string "Extra Options (DEPRECATED)"
	help
	  The old configuration infrastructure (= mkconfig + boards.cfg)
	  provided the extra options field. If you have something like
	  "HAS_BAR,BAZ=64", the optional options
	    #define CONFIG_HAS
	    #define CONFIG_BAZ	64
	  will be defined in include/config.h.
	  This option was prepared for the smooth migration from the old
	  configuration to Kconfig. Since this option will be removed sometime,
	  new boards should not use this option.

config HAVE_SYS_TEXT_BASE
	bool
	depends on !NIOS2 && !XTENSA
	depends on !EFI_APP
	default y

config SYS_TEXT_BASE
	depends on HAVE_SYS_TEXT_BASE
	default 0x80800000 if ARCH_OMAP2PLUS || ARCH_K3
	default 0x4a000000 if ARCH_SUNXI && !MACH_SUN9I && !MACH_SUN8I_V3S
	default 0x2a000000 if ARCH_SUNXI && MACH_SUN9I
	default 0x42e00000 if ARCH_SUNXI && MACH_SUN8I_V3S
	hex "Text Base"
	help
	  The address in memory that U-Boot will be running from, initially.

config SYS_CLK_FREQ
	depends on ARC || ARCH_SUNXI || MPC83xx
	int "CPU clock frequency"
	help
	  TODO: Move CONFIG_SYS_CLK_FREQ for all the architecture

config ARCH_FIXUP_FDT_MEMORY
	bool "Enable arch_fixup_memory_banks() call"
	default y
	help
	  Enable FDT memory map syncup before OS boot. This feature can be
	  used for booting OS with different memory setup where the part of
	  the memory location should be used for different purpose.

config CHROMEOS
	bool "Support booting Chrome OS"
	help
	  Chrome OS requires U-Boot to set up a table indicating the boot mode
	  (e.g. Developer mode) and a few other things. Enable this if you are
	  booting on a Chromebook to avoid getting an error about an invalid
	  firmware ID.

config CHROMEOS_VBOOT
	bool "Support Chrome OS verified boot"
	help
	  This is intended to enable the full Chrome OS verified boot support
	  in U-Boot. It is not actually implemented in the U-Boot source code
	  at present, so this option is always set to 'n'. It allows
	  distinguishing between booting Chrome OS in a basic way (developer
	  mode) and a full boot.

endmenu		# Boot images

menu "Boot timing"

config BOOTSTAGE
	bool "Boot timing and reporting"
	help
	  Enable recording of boot time while booting. To use it, insert
	  calls to bootstage_mark() with a suitable BOOTSTAGE_ID from
	  bootstage.h. Only a single entry is recorded for each ID. You can
	  give the entry a name with bootstage_mark_name(). You can also
	  record elapsed time in a particular stage using bootstage_start()
	  before starting and bootstage_accum() when finished. Bootstage will
	  add up all the accumulated time and report it.

	  Normally, IDs are defined in bootstage.h but a small number of
	  additional 'user' IDs can be used by passing BOOTSTAGE_ID_ALLOC
	  as the ID.

	  Calls to show_boot_progress() will also result in log entries but
	  these will not have names.

config SPL_BOOTSTAGE
	bool "Boot timing and reported in SPL"
	depends on BOOTSTAGE
	help
	  Enable recording of boot time in SPL. To make this visible to U-Boot
	  proper, enable BOOTSTAGE_STASH as well. This will stash the timing
	  information when SPL finishes and load it when U-Boot proper starts
	  up.

config TPL_BOOTSTAGE
	bool "Boot timing and reported in TPL"
	depends on BOOTSTAGE
	help
	  Enable recording of boot time in SPL. To make this visible to U-Boot
	  proper, enable BOOTSTAGE_STASH as well. This will stash the timing
	  information when TPL finishes and load it when U-Boot proper starts
	  up.

config BOOTSTAGE_REPORT
	bool "Display a detailed boot timing report before booting the OS"
	depends on BOOTSTAGE
	help
	  Enable output of a boot time report just before the OS is booted.
	  This shows how long it took U-Boot to go through each stage of the
	  boot process. The report looks something like this:

		Timer summary in microseconds:
		       Mark    Elapsed  Stage
			  0          0  reset
		  3,575,678  3,575,678  board_init_f start
		  3,575,695         17  arch_cpu_init A9
		  3,575,777         82  arch_cpu_init done
		  3,659,598     83,821  board_init_r start
		  3,910,375    250,777  main_loop
		 29,916,167 26,005,792  bootm_start
		 30,361,327    445,160  start_kernel

config BOOTSTAGE_RECORD_COUNT
	int "Number of boot stage records to store"
	depends on BOOTSTAGE
	default 30
	help
	  This is the size of the bootstage record list and is the maximum
	  number of bootstage records that can be recorded.

config SPL_BOOTSTAGE_RECORD_COUNT
	int "Number of boot stage records to store for SPL"
	depends on SPL_BOOTSTAGE
	default 5
	help
	  This is the size of the bootstage record list and is the maximum
	  number of bootstage records that can be recorded.

config TPL_BOOTSTAGE_RECORD_COUNT
	int "Number of boot stage records to store for TPL"
	depends on TPL_BOOTSTAGE
	default 5
	help
	  This is the size of the bootstage record list and is the maximum
	  number of bootstage records that can be recorded.

config BOOTSTAGE_FDT
	bool "Store boot timing information in the OS device tree"
	depends on BOOTSTAGE
	help
	  Stash the bootstage information in the FDT. A root 'bootstage'
	  node is created with each bootstage id as a child. Each child
	  has a 'name' property and either 'mark' containing the
	  mark time in microseconds, or 'accum' containing the
	  accumulated time for that bootstage id in microseconds.
	  For example:

		bootstage {
			154 {
				name = "board_init_f";
				mark = <3575678>;
			};
			170 {
				name = "lcd";
				accum = <33482>;
			};
		};

	  Code in the Linux kernel can find this in /proc/devicetree.

config BOOTSTAGE_STASH
	bool "Stash the boot timing information in memory before booting OS"
	depends on BOOTSTAGE
	help
	  Some OSes do not support device tree. Bootstage can instead write
	  the boot timing information in a binary format at a given address.
	  This happens through a call to bootstage_stash(), typically in
	  the CPU's cleanup_before_linux() function. You can use the
	  'bootstage stash' and 'bootstage unstash' commands to do this on
	  the command line.

config BOOTSTAGE_STASH_ADDR
	hex "Address to stash boot timing information"
	default 0
	help
	  Provide an address which will not be overwritten by the OS when it
	  starts, so that it can read this information when ready.

config BOOTSTAGE_STASH_SIZE
	hex "Size of boot timing stash region"
	default 0x1000
	help
	  This should be large enough to hold the bootstage stash. A value of
	  4096 (4KiB) is normally plenty.

config SHOW_BOOT_PROGRESS
	bool "Show boot progress in a board-specific manner"
	help
	  Defining this option allows to add some board-specific code (calling
	  a user-provided function show_boot_progress(int) that enables you to
	  show the system's boot progress on some display (for example, some
	  LEDs) on your board. At the moment, the following checkpoints are
	  implemented:

	  Legacy uImage format:

	  Arg	Where			When
	    1	common/cmd_bootm.c	before attempting to boot an image
	   -1	common/cmd_bootm.c	Image header has bad	 magic number
	    2	common/cmd_bootm.c	Image header has correct magic number
	   -2	common/cmd_bootm.c	Image header has bad	 checksum
	    3	common/cmd_bootm.c	Image header has correct checksum
	   -3	common/cmd_bootm.c	Image data   has bad	 checksum
	    4	common/cmd_bootm.c	Image data   has correct checksum
	   -4	common/cmd_bootm.c	Image is for unsupported architecture
	    5	common/cmd_bootm.c	Architecture check OK
	   -5	common/cmd_bootm.c	Wrong Image Type (not kernel, multi)
	    6	common/cmd_bootm.c	Image Type check OK
	   -6	common/cmd_bootm.c	gunzip uncompression error
	   -7	common/cmd_bootm.c	Unimplemented compression type
	    7	common/cmd_bootm.c	Uncompression OK
	    8	common/cmd_bootm.c	No uncompress/copy overwrite error
	   -9	common/cmd_bootm.c	Unsupported OS (not Linux, BSD, VxWorks, QNX)

	    9	common/image.c		Start initial ramdisk verification
	  -10	common/image.c		Ramdisk header has bad	   magic number
	  -11	common/image.c		Ramdisk header has bad	   checksum
	   10	common/image.c		Ramdisk header is OK
	  -12	common/image.c		Ramdisk data   has bad	   checksum
	   11	common/image.c		Ramdisk data   has correct checksum
	   12	common/image.c		Ramdisk verification complete, start loading
	  -13	common/image.c		Wrong Image Type (not PPC Linux ramdisk)
	   13	common/image.c		Start multifile image verification
	   14	common/image.c		No initial ramdisk, no multifile, continue.

	   15	arch/<arch>/lib/bootm.c All preparation done, transferring control to OS

	  -30	arch/powerpc/lib/board.c	Fatal error, hang the system
	  -31	post/post.c		POST test failed, detected by post_output_backlog()
	  -32	post/post.c		POST test failed, detected by post_run_single()

	   34	common/cmd_doc.c	before loading a Image from a DOC device
	  -35	common/cmd_doc.c	Bad usage of "doc" command
	   35	common/cmd_doc.c	correct usage of "doc" command
	  -36	common/cmd_doc.c	No boot device
	   36	common/cmd_doc.c	correct boot device
	  -37	common/cmd_doc.c	Unknown Chip ID on boot device
	   37	common/cmd_doc.c	correct chip ID found, device available
	  -38	common/cmd_doc.c	Read Error on boot device
	   38	common/cmd_doc.c	reading Image header from DOC device OK
	  -39	common/cmd_doc.c	Image header has bad magic number
	   39	common/cmd_doc.c	Image header has correct magic number
	  -40	common/cmd_doc.c	Error reading Image from DOC device
	   40	common/cmd_doc.c	Image header has correct magic number
	   41	common/cmd_ide.c	before loading a Image from a IDE device
	  -42	common/cmd_ide.c	Bad usage of "ide" command
	   42	common/cmd_ide.c	correct usage of "ide" command
	  -43	common/cmd_ide.c	No boot device
	   43	common/cmd_ide.c	boot device found
	  -44	common/cmd_ide.c	Device not available
	   44	common/cmd_ide.c	Device available
	  -45	common/cmd_ide.c	wrong partition selected
	   45	common/cmd_ide.c	partition selected
	  -46	common/cmd_ide.c	Unknown partition table
	   46	common/cmd_ide.c	valid partition table found
	  -47	common/cmd_ide.c	Invalid partition type
	   47	common/cmd_ide.c	correct partition type
	  -48	common/cmd_ide.c	Error reading Image Header on boot device
	   48	common/cmd_ide.c	reading Image Header from IDE device OK
	  -49	common/cmd_ide.c	Image header has bad magic number
	   49	common/cmd_ide.c	Image header has correct magic number
	  -50	common/cmd_ide.c	Image header has bad	 checksum
	   50	common/cmd_ide.c	Image header has correct checksum
	  -51	common/cmd_ide.c	Error reading Image from IDE device
	   51	common/cmd_ide.c	reading Image from IDE device OK
	   52	common/cmd_nand.c	before loading a Image from a NAND device
	  -53	common/cmd_nand.c	Bad usage of "nand" command
	   53	common/cmd_nand.c	correct usage of "nand" command
	  -54	common/cmd_nand.c	No boot device
	   54	common/cmd_nand.c	boot device found
	  -55	common/cmd_nand.c	Unknown Chip ID on boot device
	   55	common/cmd_nand.c	correct chip ID found, device available
	  -56	common/cmd_nand.c	Error reading Image Header on boot device
	   56	common/cmd_nand.c	reading Image Header from NAND device OK
	  -57	common/cmd_nand.c	Image header has bad magic number
	   57	common/cmd_nand.c	Image header has correct magic number
	  -58	common/cmd_nand.c	Error reading Image from NAND device
	   58	common/cmd_nand.c	reading Image from NAND device OK

	  -60	common/env_common.c	Environment has a bad CRC, using default

	   64	net/eth.c		starting with Ethernet configuration.
	  -64	net/eth.c		no Ethernet found.
	   65	net/eth.c		Ethernet found.

	  -80	common/cmd_net.c	usage wrong
	   80	common/cmd_net.c	before calling net_loop()
	  -81	common/cmd_net.c	some error in net_loop() occurred
	   81	common/cmd_net.c	net_loop() back without error
	  -82	common/cmd_net.c	size == 0 (File with size 0 loaded)
	   82	common/cmd_net.c	trying automatic boot
	   83	common/cmd_net.c	running "source" command
	  -83	common/cmd_net.c	some error in automatic boot or "source" command
	   84	common/cmd_net.c	end without errors

	  FIT uImage format:

	  Arg	Where			When
	  100	common/cmd_bootm.c	Kernel FIT Image has correct format
	  -100	common/cmd_bootm.c	Kernel FIT Image has incorrect format
	  101	common/cmd_bootm.c	No Kernel subimage unit name, using configuration
	  -101	common/cmd_bootm.c	Can't get configuration for kernel subimage
	  102	common/cmd_bootm.c	Kernel unit name specified
	  -103	common/cmd_bootm.c	Can't get kernel subimage node offset
	  103	common/cmd_bootm.c	Found configuration node
	  104	common/cmd_bootm.c	Got kernel subimage node offset
	  -104	common/cmd_bootm.c	Kernel subimage hash verification failed
	  105	common/cmd_bootm.c	Kernel subimage hash verification OK
	  -105	common/cmd_bootm.c	Kernel subimage is for unsupported architecture
	  106	common/cmd_bootm.c	Architecture check OK
	  -106	common/cmd_bootm.c	Kernel subimage has wrong type
	  107	common/cmd_bootm.c	Kernel subimage type OK
	  -107	common/cmd_bootm.c	Can't get kernel subimage data/size
	  108	common/cmd_bootm.c	Got kernel subimage data/size
	  -108	common/cmd_bootm.c	Wrong image type (not legacy, FIT)
	  -109	common/cmd_bootm.c	Can't get kernel subimage type
	  -110	common/cmd_bootm.c	Can't get kernel subimage comp
	  -111	common/cmd_bootm.c	Can't get kernel subimage os
	  -112	common/cmd_bootm.c	Can't get kernel subimage load address
	  -113	common/cmd_bootm.c	Image uncompress/copy overwrite error

	  120	common/image.c		Start initial ramdisk verification
	  -120	common/image.c		Ramdisk FIT image has incorrect format
	  121	common/image.c		Ramdisk FIT image has correct format
	  122	common/image.c		No ramdisk subimage unit name, using configuration
	  -122	common/image.c		Can't get configuration for ramdisk subimage
	  123	common/image.c		Ramdisk unit name specified
	  -124	common/image.c		Can't get ramdisk subimage node offset
	  125	common/image.c		Got ramdisk subimage node offset
	  -125	common/image.c		Ramdisk subimage hash verification failed
	  126	common/image.c		Ramdisk subimage hash verification OK
	  -126	common/image.c		Ramdisk subimage for unsupported architecture
	  127	common/image.c		Architecture check OK
	  -127	common/image.c		Can't get ramdisk subimage data/size
	  128	common/image.c		Got ramdisk subimage data/size
	  129	common/image.c		Can't get ramdisk load address
	  -129	common/image.c		Got ramdisk load address

	  -130	common/cmd_doc.c	Incorrect FIT image format
	  131	common/cmd_doc.c	FIT image format OK

	  -140	common/cmd_ide.c	Incorrect FIT image format
	  141	common/cmd_ide.c	FIT image format OK

	  -150	common/cmd_nand.c	Incorrect FIT image format
	  151	common/cmd_nand.c	FIT image format OK

endmenu

menu "Boot media"

config NOR_BOOT
	bool "Support for booting from NOR flash"
	depends on NOR
	help
	  Enabling this will make a U-Boot binary that is capable of being
	  booted via NOR.  In this case we will enable certain pinmux early
	  as the ROM only partially sets up pinmux.  We also default to using
	  NOR for environment.

config NAND_BOOT
	bool "Support for booting from NAND flash"
	default n
	imply MTD_RAW_NAND
	help
	  Enabling this will make a U-Boot binary that is capable of being
	  booted via NAND flash. This is not a must, some SoCs need this,
	  some not.

config ONENAND_BOOT
	bool "Support for booting from ONENAND"
	default n
	imply MTD_RAW_NAND
	help
	  Enabling this will make a U-Boot binary that is capable of being
	  booted via ONENAND. This is not a must, some SoCs need this,
	  some not.

config QSPI_BOOT
	bool "Support for booting from QSPI flash"
	default n
	help
	  Enabling this will make a U-Boot binary that is capable of being
	  booted via QSPI flash. This is not a must, some SoCs need this,
	  some not.

config SATA_BOOT
	bool "Support for booting from SATA"
	default n
	help
	  Enabling this will make a U-Boot binary that is capable of being
	  booted via SATA. This is not a must, some SoCs need this,
	  some not.

config SD_BOOT
	bool "Support for booting from SD/EMMC"
	default n
	help
	  Enabling this will make a U-Boot binary that is capable of being
	  booted via SD/EMMC. This is not a must, some SoCs need this,
	  some not.

config SPI_BOOT
	bool "Support for booting from SPI flash"
	default n
	help
	  Enabling this will make a U-Boot binary that is capable of being
	  booted via SPI flash. This is not a must, some SoCs need this,
	  some not.

endmenu

menu "Autoboot options"

config AUTOBOOT
	bool "Autoboot"
	default y
	help
	  This enables the autoboot.  See doc/README.autoboot for detail.

config BOOTDELAY
	int "delay in seconds before automatically booting"
	default 2
	depends on AUTOBOOT
	help
	  Delay before automatically running bootcmd;
	  set to 0 to autoboot with no delay, but you can stop it by key input.
	  set to -1 to disable autoboot.
	  set to -2 to autoboot with no delay and not check for abort

	  If this value is >= 0 then it is also used for the default delay
	  before starting the default entry in bootmenu. If it is < 0 then
	  a default value of 10s is used.

	  See doc/README.autoboot for details.

config AUTOBOOT_KEYED
	bool "Stop autobooting via specific input key / string"
	default n
	help
	  This option enables stopping (aborting) of the automatic
	  boot feature only by issuing a specific input key or
	  string. If not enabled, any input key will abort the
	  U-Boot automatic booting process and bring the device
	  to the U-Boot prompt for user input.

config AUTOBOOT_PROMPT
	string "Autoboot stop prompt"
	depends on AUTOBOOT_KEYED
	default "Autoboot in %d seconds\\n"
	help
	  This string is displayed before the boot delay selected by
	  CONFIG_BOOTDELAY starts. If it is not defined	there is no
	  output indicating that autoboot is in progress.

	  Note that this define is used as the (only) argument to a
	  printf() call, so it may contain '%' format specifications,
	  provided that it also includes, sepearated by commas exactly
	  like in a printf statement, the required arguments. It is
	  the responsibility of the user to select only such arguments
	  that are valid in the given context.

config AUTOBOOT_ENCRYPTION
	bool "Enable encryption in autoboot stopping"
	depends on AUTOBOOT_KEYED
	help
	  This option allows a string to be entered into U-Boot to stop the
	  autoboot. The string itself is hashed and compared against the hash
	  in the environment variable 'bootstopkeysha256'. If it matches then
	  boot stops and a command-line prompt is presented.

	  This provides a way to ship a secure production device which can also
	  be accessed at the U-Boot command line.

config AUTOBOOT_DELAY_STR
	string "Delay autobooting via specific input key / string"
	depends on AUTOBOOT_KEYED && !AUTOBOOT_ENCRYPTION
	help
	  This option delays the automatic boot feature by issuing
	  a specific input key or string. If CONFIG_AUTOBOOT_DELAY_STR
	  or the environment variable "bootdelaykey" is specified
	  and this string is received from console input before
	  autoboot starts booting, U-Boot gives a command prompt. The
	  U-Boot prompt will time out if CONFIG_BOOT_RETRY_TIME is
	  used, otherwise it never times out.

config AUTOBOOT_STOP_STR
	string "Stop autobooting via specific input key / string"
	depends on AUTOBOOT_KEYED && !AUTOBOOT_ENCRYPTION
	help
	  This option enables stopping (aborting) of the automatic
	  boot feature only by issuing a specific input key or
	  string. If CONFIG_AUTOBOOT_STOP_STR or the environment
	  variable "bootstopkey" is specified and this string is
	  received from console input before autoboot starts booting,
	  U-Boot gives a command prompt. The U-Boot prompt never
	  times out, even if CONFIG_BOOT_RETRY_TIME is used.

config AUTOBOOT_KEYED_CTRLC
	bool "Enable Ctrl-C autoboot interruption"
	depends on AUTOBOOT_KEYED && !AUTOBOOT_ENCRYPTION
	default n
	help
	  This option allows for the boot sequence to be interrupted
	  by ctrl-c, in addition to the "bootdelaykey" and "bootstopkey".
	  Setting this variable	provides an escape sequence from the
	  limited "password" strings.

config AUTOBOOT_STOP_STR_SHA256
	string "Stop autobooting via SHA256 encrypted password"
	depends on AUTOBOOT_KEYED && AUTOBOOT_ENCRYPTION
	help
	  This option adds the feature to only stop the autobooting,
	  and therefore boot into the U-Boot prompt, when the input
	  string / password matches a values that is encypted via
	  a SHA256 hash and saved in the environment variable
	  "bootstopkeysha256". If the value in that variable
	  includes a ":", the portion prior to the ":" will be treated
	  as a salt value.

config AUTOBOOT_USE_MENUKEY
	bool "Allow a specify key to run a menu from the environment"
	depends on !AUTOBOOT_KEYED
	help
	  If a specific key is pressed to stop autoboot, then the commands in
	  the environment variable 'menucmd' are executed before boot starts.

config AUTOBOOT_MENUKEY
	int "ASCII value of boot key to show a menu"
	default 0
	depends on AUTOBOOT_USE_MENUKEY
	help
	  If this key is pressed to stop autoboot, then the commands in the
	  environment variable 'menucmd' will be executed before boot starts.
	  For example, 33 means "!" in ASCII, so pressing ! at boot would take
	  this action.

config AUTOBOOT_MENU_SHOW
	bool "Show a menu on boot"
	depends on CMD_BOOTMENU
	help
	  This enables the boot menu, controlled by environment variables
	  defined by the board. The menu starts after running the 'preboot'
	  environmnent variable (if enabled) and before handling the boot delay.
	  See README.bootmenu for more details.

endmenu

config USE_BOOTARGS
	bool "Enable boot arguments"
	help
	  Provide boot arguments to bootm command. Boot arguments are specified
	  in CONFIG_BOOTARGS option. Enable this option to be able to specify
	  CONFIG_BOOTARGS string. If this option is disabled, CONFIG_BOOTARGS
	  will be undefined and won't take any space in U-Boot image.

config BOOTARGS
	string "Boot arguments"
	depends on USE_BOOTARGS && !USE_DEFAULT_ENV_FILE
	help
	  This can be used to pass arguments to the bootm command. The value of
	  CONFIG_BOOTARGS goes into the environment value "bootargs". Note that
	  this value will also override the "chosen" node in FDT blob.

config BOOTARGS_SUBST
	bool "Support substituting strings in boot arguments"
	help
	  This allows substituting string values in the boot arguments. These
	  are applied after the commandline has been built.

	  One use for this is to insert the root-disk UUID into the command
	  line where bootargs contains "root=${uuid}"

		setenv bootargs "console= root=${uuid}"
		# Set the 'uuid' environment variable
		part uuid mmc 2:2 uuid

		# Command-line substitution will put the real uuid into the
		# kernel command line
		bootm

config USE_BOOTCOMMAND
	bool "Enable a default value for bootcmd"
	help
	  Provide a default value for the bootcmd entry in the environment.  If
	  autoboot is enabled this is what will be run automatically.  Enable
	  this option to be able to specify CONFIG_BOOTCOMMAND as a string.  If
	  this option is disabled, CONFIG_BOOTCOMMAND will be undefined and
	  won't take any space in U-Boot image.

config BOOTCOMMAND
	string "bootcmd value"
	depends on USE_BOOTCOMMAND && !USE_DEFAULT_ENV_FILE
	default "run distro_bootcmd" if DISTRO_DEFAULTS
	help
	  This is the string of commands that will be used as bootcmd and if
	  AUTOBOOT is set, automatically run.

config USE_PREBOOT
	bool "Enable preboot"
	help
	  When this option is enabled, the existence of the environment
	  variable "preboot" will be checked immediately before starting the
	  CONFIG_BOOTDELAY countdown and/or running the auto-boot command resp.
	  entering interactive mode.

	  This feature is especially useful when "preboot" is automatically
	  generated or modified. For example, the boot code can modify the
	  "preboot" when a user holds down a certain combination of keys.

config PREBOOT
	string "preboot default value"
	depends on USE_PREBOOT && !USE_DEFAULT_ENV_FILE
	default "usb start" if USB_KEYBOARD
	default ""
	help
	  This is the default of "preboot" environment variable.

config DEFAULT_FDT_FILE
	string "Default fdt file"
	help
	  This option is used to set the default fdt file to boot OS.

endmenu		# Booting
