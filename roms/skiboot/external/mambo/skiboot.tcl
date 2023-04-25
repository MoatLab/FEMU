# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#
# scripts to run skiboot (and a payload) with Mambo (otherwise known as the
# POWER[89] Functional Simulator)
#
# Copyright 2014-2019 IBM Corp.

# need to get images path defined early
source $env(LIB_DIR)/ppc/util.tcl
if { [file exists qtrace_utils.tcl] } then {
	source qtrace_utils.tcl
}

#
# Call tclreadline's Loop to move to friendlier
# commandline if one exists
#
proc readline { } {
    set readline [catch { package require tclreadline }]
    if { $readline == 0 } {
        ::tclreadline::Loop
    }
}

proc mconfig { name env_name def } {
    global mconf
    global env

    if { [info exists env($env_name)] } { set mconf($name) $env($env_name) }
    if { ![info exists mconf($name)] } { set mconf($name) $def }
}

mconfig cpus CPUS 1
mconfig threads THREADS 1
mconfig memory MEM_SIZE 4G

# Create multiple memory nodes? This will create a MEM_SIZE region
# on each chip (CPUS above).
mconfig numa MAMBO_NUMA 0

# Should we stop on an illeagal instruction
mconfig stop_on_ill MAMBO_STOP_ON_ILL false

# Location of application binary to load
mconfig boot_image SKIBOOT ../../skiboot.lid

# Boot: Memory location to load boot_image, for binary or vmlinux
mconfig boot_load MAMBO_BOOT_LOAD 0x30000000

# Boot: Value of PC after loading, for binary or vmlinux
mconfig boot_pc	MAMBO_BOOT_PC 0x30000010

# Payload: Allow for a Linux style ramdisk/initrd
if { ![info exists env(SKIBOOT_ZIMAGE)] } {
	error "Please set SKIBOOT_ZIMAGE to the path of your zImage.epapr"
}
mconfig payload PAYLOAD $env(SKIBOOT_ZIMAGE)

mconfig linux_cmdline LINUX_CMDLINE ""

# Paylod: Memory location for a Linux style ramdisk/initrd
mconfig payload_addr PAYLOAD_ADDR 0x20000000;

# FW: Where should ePAPR Flat Devtree Binary be loaded
mconfig epapr_dt_addr EPAPR_DT_ADDR 0x1f00000;# place at 31M

# Disk: Location of file to use a bogus disk 0
mconfig rootdisk ROOTDISK none

# Disk: File to use for re COW file: none or <file>
mconfig rootdisk_cow MAMBO_ROOTDISK_COW none

# Disk: COW method to use
mconfig rootdisk_cow_method MAMBO_ROOTDISK_COW_METHOD newcow

# Disk: COW hash size
mconfig rootdisk_cow_hash MAMBO_ROOTDISK_COW_HASH 1024

# Net: What type of networking: none, phea, bogus
mconfig net MAMBO_NET none

# Net: What MAC address to use
mconfig net_mac MAMBO_NET_MAC 00:11:22:33:44:55

# Net: What is the name of the tap device
mconfig net_tapdev MAMBO_NET_TAPDEV "tap0"

# Enable (default) or disable the "speculation-policy-favor-security" setting,
# set to 0 to disable. When enabled it causes Linux's RFI flush to be enabled.
mconfig speculation_policy_favor_security MAMBO_SPECULATION_POLICY_FAVOR_SECURITY 1

# These values ~= P9N DD2.3, except for fw_count_cache_flush_assist=0 because it
# exercises more kernel code.
# See https://github.com/open-power/hostboot/blob/7ce2a9daac0ccf759376929b2ec40bbbc7ca3398/src/usr/hdat/hdatiplparms.H#L520
mconfig needs_l1d_flush_msr_hv		MAMBO_NEEDS_L1D_FLUSH_MSR_HV	1
mconfig needs_l1d_flush_msr_pr		MAMBO_NEEDS_L1D_FLUSH_MSR_PR	1
mconfig fw_l1d_thread_split		MAMBO_FW_L1D_THREAD_SPLIT	1
mconfig needs_spec_barrier		MAMBO_NEEDS_SPEC_BARRIER	1
mconfig fw_bcctrl_serialized		MAMBO_FW_BCCTRL_SERIALIZED	0
mconfig fw_count_cache_disabled		MAMBO_FW_COUNT_CACHE_DISABLED	0
mconfig needs_count_cache_flush		MAMBO_NEEDS_COUNT_CACHE_FLUSH	1
mconfig fw_count_cache_flush_assist	MAMBO_COUNT_CACHE_FLUSH_ASSIST	0
mconfig inst_spec_barrier_ori31		MAMBO_INST_SPEC_BARRIER_ORI31	1
mconfig inst_l1d_flush_trig2		MAMBO_INST_L1D_FLUSH_TRIG2	1
mconfig inst_l1d_flush_ori30		MAMBO_INST_L1D_FLUSH_ORI30	0

#
# Create machine config
#
set default_config [display default_configure]
define dup $default_config myconf
myconf config cpus $mconf(cpus)
myconf config processor/number_of_threads $mconf(threads)
myconf config memory_size $mconf(memory)
myconf config processor_option/ATTN_STOP true
myconf config processor_option/stop_on_illegal_instruction $mconf(stop_on_ill)
myconf config UART/0/enabled false
myconf config SimpleUART/enabled false
myconf config enable_rtas_support false
myconf config processor/cpu_frequency 512M
myconf config processor/timebase_frequency 1/1
myconf config enable_pseries_nvram false
myconf config machine_option/NO_RAM TRUE
myconf config machine_option/NO_ROM TRUE
myconf config machine_option/MEMORY_OVERFLOW FALSE

if { $default_config == "PEGASUS" } {
    # We need to be DD2 or greater on p8 for the HILE HID bit.
    myconf config processor/initial/PVR 0x4b0201

    if { $mconf(numa) } {
        myconf config memory_region_id_shift 35
    }
}

if { $default_config == "P9" } {
    # PVR configured for POWER9 DD2.3 Scale out 24 Core (ie SMT4)
    # This still is not configured with LPAR-per-thread, which will make
    # multi-thread KVM not work properly. And possibly even small-core is
    # not set correctly either.
    myconf config processor/initial/PVR 0x4e1203
    myconf config processor/initial/SIM_CTRL1 0x42283c1710000000

    if { $mconf(numa) } {
        myconf config memory_region_id_shift 45
    }
}

if { $default_config == "P10" } {
    # PVR configured for POWER10 DD2.0, LPAR-per-thread
    myconf config processor/initial/SIM_CTRL  0x0c1dd60000000000
    if { $mconf(threads) == 8 } {
        # Big-core mode.
        myconf config processor/initial/PVR 0x00800200
        myconf config processor/initial/SIM_CTRL1 0xc0400c0400040a40
	puts "Set P10 big-core mode"
    } else {
        # Small-core mode.
        myconf config processor/initial/PVR 0x00801200
        myconf config processor/initial/SIM_CTRL1 0xc0400c0401040a40
        if { $mconf(threads) != 1 && $mconf(threads) != 2 && $mconf(threads) != 4 } {
            puts "ERROR: Bad threads configuration"
            exit
        }
        if { $mconf(threads) != 4 && $mconf(cpus) != 1 } {
            puts "ERROR: Bad threads, cpus configuration"
            exit
        }

	puts "Set P10 small-core mode"
    }

    if { $mconf(numa) } {
        myconf config memory_region_id_shift 44
    }
}


if { $mconf(numa) } {
    myconf config memory_regions $mconf(cpus)
}

if { [info exists env(SKIBOOT_SIMCONF)] } {
    source $env(SKIBOOT_SIMCONF)
}

define machine myconf mysim

# Some mambo does not expose SIM_CTRL as a config option. Also set the SPRs
# after machine is defined.
if { $default_config == "P10" } {
    for { set c 0 } { $c < $mconf(cpus) } { incr c } {
        for { set t 0 } { $t < $mconf(threads) } { incr t } {
	    mysim mcm 0 cpu $c thread $t set spr ctrl 0x0c1dd60000000000
        }
    }
}

#
# Include various utilities
#

source $env(LIB_DIR)/common/epapr.tcl
if {![info exists of::encode_compat]} {
    source $env(LIB_DIR)/common/openfirmware_utils.tcl
}

# Only source mambo_utils.tcl if it exists in the current directory. That
# allows running mambo in another directory to the one skiboot.tcl is in.
if { [file exists mambo_utils.tcl] } then {
	source mambo_utils.tcl

	if { [info exists env(USER_MAP)] } {
		global user_symbol_map user_symbol_list

		set fp [open $env(USER_MAP) r]
		set user_symbol_map [read $fp]
	        set user_symbol_list [split $user_symbol_map "\n"]
		close $fp
	}

	if { [info exists env(VMLINUX_MAP)] } {
		global linux_symbol_map linux_symbol_list

		set fp [open $env(VMLINUX_MAP) r]
		set linux_symbol_map [read $fp]
	        set linux_symbol_list [split $linux_symbol_map "\n"]
		close $fp
	}

	if { [info exists env(SKIBOOT_MAP)] } {
		global skiboot_symbol_map skiboot_symbol_list

		set fp [open $env(SKIBOOT_MAP) r]
		set skiboot_symbol_map [read $fp]
	        set skiboot_symbol_list [split $skiboot_symbol_map "\n"]
		close $fp
	}
}

#
# Instanciate xscom
#

set xscom_base 0x1A0000000000
mysim xscom create $xscom_base

# Setup bogus IO

if { $mconf(rootdisk) != "none" } {
    # Now load the bogus disk image
    switch $mconf(rootdisk_cow) {
	none {
	    mysim bogus disk init 0 $mconf(rootdisk) rw
	    puts "bogusdisk initialized for $mconf(rootdisk)"
	}
	default {
	    mysim bogus disk init 0 $mconf(rootdisk) \
		$mconf(rootdisk_cow_method) \
		$mconf(rootdisk_cow) $mconf(rootdisk_cow_hash)
	}
    }
}
switch $mconf(net) {
    none {
	puts "No network support selected"
    }
    bogus - bogusnet {
        mysim bogus net init 0 $mconf(net_mac) $mconf(net_tapdev)
    }
    default {
	error "Bad net \[none | bogus]: $mconf(net)"
    }
}

# Device tree fixups

set root_node [mysim of find_device "/"]

mysim of addprop $root_node string "epapr-version" "ePAPR-1.0"
mysim of setprop $root_node "compatible" "ibm,powernv"

set cpus_node [mysim of find_device "/cpus"]
mysim of addprop $cpus_node int "#address-cells" 1
mysim of addprop $cpus_node int "#size-cells" 0

set mem0_node [mysim of find_device "/memory@0"]
mysim of addprop $mem0_node int "ibm,chip-id" 0

set xscom_node [ mysim of addchild $root_node xscom [format %x $xscom_base]]
set reg [list $xscom_base 0x10000000]
mysim of addprop $xscom_node array64 "reg" reg
mysim of addprop $xscom_node empty "scom-controller" ""
mysim of addprop $xscom_node int "ibm,chip-id" 0
mysim of addprop $xscom_node int "#address-cells" 1
mysim of addprop $xscom_node int "#size-cells" 1
set compat [list]
lappend compat "ibm,xscom"
lappend compat "ibm,power8-xscom"
set compat [of::encode_compat $compat]
mysim of addprop $xscom_node byte_array "compatible" $compat

set chosen_node [mysim of find_device /chosen]
set base_addr [list $mconf(payload_addr)]
mysim of addprop $chosen_node array64 "kernel-base-address" base_addr

# Load any initramfs
set cpio_start 0x80000000
set cpio_end $cpio_start
set cpio_size 0
if { [info exists env(SKIBOOT_INITRD)] } {

    set cpios [split $env(SKIBOOT_INITRD) ","]

    foreach cpio_file $cpios {
	    set cpio_file [string trim $cpio_file]
	    set cpio_size [file size $cpio_file]
	    mysim mcm 0 memory fread $cpio_end $cpio_size $cpio_file
	    set cpio_end [expr $cpio_end + $cpio_size]
	    # Linux requires cpios are 4 byte aligned
	    set cpio_end [expr $cpio_end + 3 & 0xfffffffffffffffc]
    }

    mysim of addprop $chosen_node int "linux,initrd-start" $cpio_start
    mysim of addprop $chosen_node int "linux,initrd-end"   $cpio_end
}

# Map persistent memory disks
proc pmem_node_add { root start size } {
    set start_hex [format %x $start]
    set node [mysim of addchild $root "pmem@$start_hex" ""]
    set reg [list [expr $start >> 32] [expr $start & 0xffffffff] [expr $size >> 32] [expr $size & 0xffffffff] ]
    mysim of addprop $node array "reg" reg
    mysim of addprop $node string "compatible" "pmem-region"
    mysim of addprop $node empty "volatile" "1"
    mysim of addprop $node int "ibm,chip-id" 0
    return [expr $start + $size]
}

set pmem_files ""
if { [info exists env(PMEM_DISK)] } {
    set pmem_files [split $env(PMEM_DISK) ","]
}
set pmem_sizes ""
if { [info exists env(PMEM_VOLATILE)] } {
    set pmem_sizes [split $env(PMEM_VOLATILE) ","]
}
set pmem_modes ""
if { [info exists env(PMEM_MODE)] } {
    set pmem_modes [split $env(PMEM_MODE) ","]
}
set pmem_root [mysim of addchild $root_node "pmem" ""]
mysim of addprop $pmem_root int "#address-cells" 2
mysim of addprop $pmem_root int "#size-cells" 2
mysim of addprop $pmem_root empty "ranges" ""
# Start above where XICS normally is at 0x1A0000000000
set pmem_start [expr 0x20000000000]
set pmem_file_ix 0
foreach pmem_file $pmem_files { # PMEM_DISK
    set pmem_file [string trim $pmem_file]
    set pmem_size [file size $pmem_file]
    if { [expr [llength $pmem_modes] > $pmem_file_ix] } {
	set pmem_mode [lindex $pmem_modes $pmem_file_ix]
    } else {
	set pmem_mode "rw"
    }
    if {[catch {mysim memory mmap $pmem_start $pmem_size $pmem_file $pmem_mode}]} {
	puts "ERROR: pmem: 'mysim mmap' command needs newer mambo"
	exit
    }
    set pmem_start [pmem_node_add $pmem_root $pmem_start $pmem_size]
    set pmem_file_ix [expr $pmem_file_ix + 1]
}
foreach pmem_size $pmem_sizes { # PMEM_VOLATILE
    set pmem_start [pmem_node_add $pmem_root $pmem_start $pmem_size]
}


# Default NVRAM is blank and will be formatted by Skiboot if no file is provided
set fake_nvram_start $cpio_end
set fake_nvram_size 0x40000
# Load any fake NVRAM file if provided
if { [info exists env(SKIBOOT_NVRAM)] } {
    # Set up and write NVRAM file
    set fake_nvram_file $env(SKIBOOT_NVRAM)
    set fake_nvram_size [file size $fake_nvram_file]
    mysim mcm 0 memory fread $fake_nvram_start $fake_nvram_size $fake_nvram_file
}

# Add device tree entry for NVRAM
set reserved_memory [mysim of addchild $root_node "reserved-memory" ""]
mysim of addprop $reserved_memory int "#size-cells" 2
mysim of addprop $reserved_memory int "#address-cells" 2
mysim of addprop $reserved_memory empty "ranges" ""

set cvc_code_start [expr $fake_nvram_start + $fake_nvram_size]
set cvc_code_end $cvc_code_start
set cvc_code_size 0

if { [info exists env(SKIBOOT_CVC_CODE)] } {
    set cvc_file $env(SKIBOOT_CVC_CODE)

    set cvc_code_size [file size $cvc_file]
    mysim mcm 0 memory fread $cvc_code_start $cvc_code_size $cvc_file
    set cvc_code_end [expr $cvc_code_start + $cvc_code_size]

    # Set up Device Tree for Container Verification Code
    set hb [mysim of addchild $root_node "ibm,hostboot" ""]
    set hb_reserved_memory [mysim of addchild $hb "reserved-memory" ""]
    mysim of addprop $hb_reserved_memory int "#address-cells" 2
    mysim of addprop $hb_reserved_memory int "#size-cells" 2

    set hb_cvc_code_node [mysim of addchild $hb_reserved_memory "ibm,secure-crypt-algo-code" [format %x $cvc_code_start]]
    set reg [list $cvc_code_start $cvc_code_size]
    mysim of addprop $hb_cvc_code_node array64 "reg" reg
    mysim of addprop $hb_cvc_code_node empty "name" "ibm,secure-crypt-algo-code"

    set cvc_code_node [mysim of addchild $reserved_memory "ibm,secure-crypt-algo-code" [format %x $cvc_code_start]]
    set reg [list $cvc_code_start $cvc_code_size]
    mysim of addprop $cvc_code_node array64 "reg" reg
    mysim of addprop $cvc_code_node empty "name" "ibm,secure-crypt-algo-code"
}

set initramfs_res [mysim of addchild $reserved_memory "initramfs" ""]
set reg [list $cpio_start $cpio_size ]
mysim of addprop $initramfs_res array64 "reg" reg
mysim of addprop $initramfs_res empty "name" "initramfs"

set fake_nvram_node [mysim of addchild $reserved_memory "ibm,fake-nvram" ""]
set reg [list $fake_nvram_start $fake_nvram_size ]
mysim of addprop $fake_nvram_node array64 "reg" reg
mysim of addprop $fake_nvram_node empty "name" "ibm,fake-nvram"

set opal_node [mysim of addchild $root_node "ibm,opal" ""]

# Allow P9/P10 to use all idle states
if { $default_config == "P9" || $default_config == "P10" } {
    set power_mgt_node [mysim of addchild $opal_node "power-mgt" ""]
    mysim of addprop $power_mgt_node int "ibm,enabled-stop-levels" 0xffffffff
}

proc add_feature_node { parent name { value 1 } } {
    if { $value != 1 } {
	set value "disabled"
    } else {
	set value "enabled"
    }
    set np [mysim of addchild $parent $name ""]
    mysim of addprop $np empty $value ""
}

set np [mysim of addchild $opal_node "fw-features" ""]
add_feature_node $np "speculation-policy-favor-security" $mconf(speculation_policy_favor_security)
add_feature_node $np "needs-l1d-flush-msr-hv-1-to-0" $mconf(needs_l1d_flush_msr_hv)
add_feature_node $np "needs-l1d-flush-msr-pr-0-to-1" $mconf(needs_l1d_flush_msr_pr)
add_feature_node $np "fw-l1d-thread-split" $mconf(fw_l1d_thread_split)
add_feature_node $np "needs-spec-barrier-for-bound-checks" $mconf(needs_spec_barrier)
add_feature_node $np "fw-bcctrl-serialized" $mconf(fw_bcctrl_serialized)
add_feature_node $np "fw-count-cache-disabled" $mconf(fw_count_cache_disabled)
add_feature_node $np "needs-count-cache-flush-on-context-switch" $mconf(needs_count_cache_flush)
add_feature_node $np "fw-count-cache-flush-bcctr2,0,0" $mconf(fw_count_cache_flush_assist)
add_feature_node $np "inst-spec-barrier-ori31,31,0" $mconf(inst_spec_barrier_ori31)
add_feature_node $np "inst-l1d-flush-trig2" $mconf(inst_l1d_flush_trig2)
add_feature_node $np "inst-l1d-flush-ori30,30,0" $mconf(inst_l1d_flush_ori30)


# Init CPUs
set pir 0
for { set c 0 } { $c < $mconf(cpus) } { incr c } {
    set cpu_node [mysim of find_device "/cpus/PowerPC@$pir"]
    mysim of addprop $cpu_node int "ibm,pir" $pir
    set reg  [list 0x0000001c00000028 0xffffffffffffffff]
    mysim of addprop $cpu_node array64 "ibm,processor-segment-sizes" reg

    mysim of addprop $cpu_node int "ibm,chip-id" $c

    # Create a chip node to tell skiboot to create another chip for this CPU.
    # This bubbles up to Linux which will then see a new chip (aka nid).
    # For chip 0 the xscom node above has already definied chip 0, so skip it.
    if { $c > 0 } {
        set node [mysim of addchild $root_node "mambo-chip" [format %x $c]]
        mysim of addprop $node int "ibm,chip-id" $c
        mysim of addprop $node string "compatible" "ibm,mambo-chip"

        if { $mconf(numa) } {
            set shift [myconf query memory_region_id_shift]
            set addr [format %lx [expr (1 << $shift) * $c]]
            set node [mysim of find_device "/memory@$addr"]
            mysim of addprop $node int "ibm,chip-id" $c
        }
    }

    set reg {}
    lappend reg 0x0000000c 0x00000010 0x00000018 0x00000022
    mysim of addprop $cpu_node array "ibm,processor-page-sizes" reg

    set reg {}
    lappend reg 0x0c 0x000 3 0x0c 0x0000 ;#  4K seg  4k pages
    lappend reg              0x10 0x0007 ;#  4K seg 64k pages
    lappend reg              0x18 0x0038 ;#  4K seg 16M pages
    lappend reg 0x10 0x110 2 0x10 0x0001 ;# 64K seg 64k pages
    lappend reg              0x18 0x0008 ;# 64K seg 16M pages
    lappend reg 0x18 0x100 1 0x18 0x0000 ;# 16M seg 16M pages
    lappend reg 0x22 0x120 1 0x22 0x0003 ;# 16G seg 16G pages
    mysim of addprop $cpu_node array "ibm,segment-page-sizes" reg

    if { $default_config == "P9" || $default_config == "P10" } {
        # Set actual page size encodings
        set reg {}
        # 4K pages
        lappend reg 0x0000000c
        # 64K pages
        lappend reg 0xa0000010
        # 2M pages
        lappend reg 0x20000015
        # 1G pages
        lappend reg 0x4000001e
        mysim of addprop $cpu_node array "ibm,processor-radix-AP-encodings" reg

        set reg {}
	# POWER9 PAPR defines upto bytes 62-63
	# POWER10 PAPR defines upto byte 64-65
	# header + bytes 0-5
	if { $default_config == "P9" } {
		lappend reg 0x4000f63fc70080c0
	} else {
		lappend reg 0x4200f63fc70080c0
	}
	# bytes 6-13
	lappend reg 0x8000000000000000
	# bytes 14-21
	lappend reg 0x0000800080008000
	# bytes 22-29 22/23=TM
	lappend reg 0x0000800080008000
	# bytes 30-37
	lappend reg 0x80008000C0008000
	# bytes 38-45 40/41=radix
	lappend reg 0x8000800080008000
	# bytes 46-55
	lappend reg 0x8000800080008000
	# bytes 54-61 58/59=seg tbl
	lappend reg 0x8000800080008000
	# bytes 62-69 64/65=DAWR1(P10 only)
	if { $default_config == "P9" } {
		lappend reg 0x8000000000000000
	} else {
		lappend reg 0x8000800000000000
	}
	mysim of addprop $cpu_node array64 "ibm,pa-features" reg
    } else {
        set reg {}
	lappend reg 0x6000f63fc70080c0
	mysim of addprop $cpu_node array64 "ibm,pa-features" reg
    }

    set irqreg [list]
    for { set t 0 } { $t < $mconf(threads) } { incr t } {
	mysim mcm 0 cpu $c thread $t set spr pc $mconf(boot_pc)
	mysim mcm 0 cpu $c thread $t set gpr 3 $mconf(epapr_dt_addr)
	mysim mcm 0 cpu $c thread $t config_on
	mysim mcm 0 cpu $c thread $t set spr pir $pir
	lappend irqreg $pir
	incr pir
    }
    mysim of addprop $cpu_node array "ibm,ppc-interrupt-server#s" irqreg
}

#Add In-Memory Collection Counter nodes
if { $default_config == "P9" || $default_config == "P10" } {
   #Add the base node "imc-counters"
   set imc_c [mysim of addchild $root_node "imc-counters" ""]
   mysim of addprop $imc_c string "compatible" "ibm,opal-in-memory-counters"
   mysim of addprop $imc_c int "#address-cells" 1
   mysim of addprop $imc_c int "#size-cells" 1
   mysim of addprop $imc_c int "version-id" 1

      #Add a common mcs event node
      set mcs_et [mysim of addchild $imc_c "nest-mcs-events" ""]
      mysim of addprop $mcs_et int "#address-cells" 1
      mysim of addprop $mcs_et int "#size-cells" 1

         #Add a event
         set et [mysim of addchild $mcs_et event [format %x 0]]
         mysim of addprop  $et string "event-name" "64B_RD_OR_WR_DISP_PORT01"
         mysim of addprop  $et string "unit" "MiB/s"
         mysim of addprop  $et string "scale" "4"
         mysim of addprop  $et int "reg" 0

        #Add a event
        set et [mysim of addchild $mcs_et event [format %x 1]]
        mysim of addprop  $et string "event-name" "64B_WR_DISP_PORT01"
        mysim of addprop  $et string "unit" "MiB/s"
        mysim of addprop  $et int "reg" 40

        #Add a event
        set et [mysim of addchild $mcs_et event [format %x 2]]
        mysim of addprop  $et string "event-name" "64B_RD_DISP_PORT01"
        mysim of addprop  $et string "scale" "100"
        mysim of addprop  $et int "reg" 64

        #Add a event
        set et [mysim of addchild $mcs_et event [format %x 3]]
        mysim of addprop  $et string "event-name" "64B_XX_DISP_PORT01"
        mysim of addprop  $et int "reg" 32

     #Add a mcs device node
     set mcs_01 [mysim of addchild $imc_c "mcs01" ""]
     mysim of addprop $mcs_01 string "compatible" "ibm,imc-counters"
     mysim of addprop  $mcs_01 string "events-prefix" "PM_MCS01_"
     mysim of addprop  $mcs_01 int "reg" 65536
     mysim of addprop  $mcs_01 int "size" 262144
     mysim of addprop  $mcs_01 int "offset" 1572864
     mysim of addprop  $mcs_01 int "events" $mcs_et
     mysim of addprop  $mcs_01 int "type" 16
     mysim of addprop $mcs_01 string "unit" "KiB/s"
     mysim of addprop $mcs_01 string "scale" "8"

      #Add a common core event node
      set ct_et [mysim of addchild $imc_c "core-thread-events" ""]
      mysim of addprop $ct_et int "#address-cells" 1
      mysim of addprop $ct_et int "#size-cells" 1

         #Add a event
         set cet [mysim of addchild $ct_et event [format %x 200]]
         mysim of addprop  $cet string "event-name" "0THRD_NON_IDLE_PCYC"
         mysim of addprop  $cet string "desc" "The number of processor cycles when all threads are idle"
         mysim of addprop  $cet int "reg" 200

     #Add a core device node
     set core [mysim of addchild $imc_c "core" ""]
     mysim of addprop $core string "compatible" "ibm,imc-counters"
     mysim of addprop  $core string "events-prefix" "CPM_"
     mysim of addprop  $core int "reg" 24
     mysim of addprop  $core int "size" 8192
     mysim of addprop  $core string "scale" "512"
     mysim of addprop  $core int "events" $ct_et
     mysim of addprop  $core int "type" 4

     #Add a thread device node
     set thread [mysim of addchild $imc_c "thread" ""]
     mysim of addprop $thread string "compatible" "ibm,imc-counters"
     mysim of addprop  $thread string "events-prefix" "CPM_"
     mysim of addprop  $thread int "reg" 24
     mysim of addprop  $thread int "size" 8192
     mysim of addprop  $thread string "scale" "512"
     mysim of addprop  $thread int "events" $ct_et
     mysim of addprop  $thread int "type" 1

      #Add a common trace event  node
      set tr_et [mysim of addchild $imc_c "trace-events" ""]
      mysim of addprop $tr_et int "#address-cells" 1
      mysim of addprop $tr_et int "#size-cells" 1

         #Add an event
         set tr [mysim of addchild $tr_et event [format 10200000]]
         mysim of addprop  $tr string "event-name" "cycles"
         mysim of addprop  $tr string "desc" "Reference cycles"
         mysim of addprop  $tr int "reg" 0x10200000

     #Add a trace device node
     set trace [mysim of addchild $imc_c "trace" ""]
     mysim of addprop $trace string "compatible" "ibm,imc-counters"
     mysim of addprop  $trace string "events-prefix" "trace_"
     mysim of addprop  $trace int "reg" 0
     mysim of addprop  $trace int "size" 262144
     mysim of addprop  $trace int "events" $tr_et
     mysim of addprop  $trace int "type" 2

}

mconfig enable_stb SKIBOOT_ENABLE_MAMBO_STB 0

if { [info exists env(SKIBOOT_ENABLE_MAMBO_STB)] } {
    set stb_node [ mysim of addchild $root_node "ibm,secureboot" "" ]

    # For P8 we still use the softrom emulation
    if { $default_config == "PEGASUS" || ! [info exists env(SKIBOOT_CVC_CODE)] } {
	mysim of addprop $stb_node string "compatible" "ibm,secureboot-v1-softrom"
    } else {
	# on P9 we can use the real CVC
	mysim of addprop $stb_node string "compatible" "ibm,secureboot-v2"
    }
#    mysim of addprop $stb_node string "secure-enabled" ""
    mysim of addprop $stb_node string "trusted-enabled" ""
    mysim of addprop $stb_node string "hash-algo" "sha512"
    mysim of addprop $stb_node int "hw-key-hash-size" 64
    set hw_key_hash {}
    lappend hw_key_hash 0x40d487ff
    lappend hw_key_hash 0x7380ed6a
    lappend hw_key_hash 0xd54775d5
    lappend hw_key_hash 0x795fea0d
    lappend hw_key_hash 0xe2f541fe
    lappend hw_key_hash 0xa9db06b8
    lappend hw_key_hash 0x466a42a3
    lappend hw_key_hash 0x20e65f75
    lappend hw_key_hash 0xb4866546
    lappend hw_key_hash 0x0017d907
    lappend hw_key_hash 0x515dc2a5
    lappend hw_key_hash 0xf9fc5095
    lappend hw_key_hash 0x4d6ee0c9
    lappend hw_key_hash 0xb67d219d
    lappend hw_key_hash 0xfb708535
    lappend hw_key_hash 0x1d01d6d1
    mysim of addprop $stb_node array "hw-key-hash" hw_key_hash

    if { $default_config != "PEGASUS" && [info exists env(SKIBOOT_CVC_CODE)] } {
	set cvc_node [ mysim of addchild $stb_node "ibm,cvc" "" ]
	mysim of addprop $cvc_node string "compatible" "ibm,container-verification-code"
	mysim of addprop $cvc_node int "memory-region" $hb_cvc_code_node

	# I'm sure hardcoding these addresses will *never* cause us a problem...
	set sha_node [ mysim of addchild $cvc_node "ibm,cvc-service" [format %x 0x40]]
	mysim of addprop $sha_node string "name" "ibm,cvc-service"
	mysim of addprop $sha_node string "compatible" "ibm,cvc-sha512"
	mysim of addprop $sha_node int "reg" 0x40
	mysim of addprop $sha_node int "version" 1

	set verify_node [ mysim of addchild $cvc_node "ibm,cvc-service" [format %x 0x50]]
	mysim of addprop $verify_node string "name" "ibm,cvc-service"
	mysim of addprop $verify_node string "compatible" "ibm,cvc-verify"
	mysim of addprop $verify_node int "reg" 0x50
	mysim of addprop $verify_node int "version" 1
    }
}

# Kernel command line args, appended to any from the device tree
# e.g.: of::set_bootargs "xmon"
#
# Can be set from the environment by setting LINUX_CMDLINE.
of::set_bootargs $mconf(linux_cmdline)

# Load images

set boot_size [file size $mconf(boot_image)]
mysim memory fread $mconf(boot_load) $boot_size $mconf(boot_image)

set payload_size [file size $mconf(payload)]
mysim memory fread $mconf(payload_addr) $payload_size $mconf(payload)

set available_space [expr $mconf(boot_load) - $mconf(payload_addr)]
if { $payload_size > $available_space } {
    set overflow [expr $payload_size - $available_space]
    error "vmlinux is too large by $overflow bytes ($payload_size > $available_space), consider adjusting PAYLOAD_ADDR"
}

# Flatten it
epapr::of2dtb mysim $mconf(epapr_dt_addr)

# Set run speed
mysim mode fastest

if { [info exists env(GDB_SERVER)] } {
    mysim debugger wait $env(GDB_SERVER)
}

if { [info exists env(SKIBOOT_AUTORUN)] } {
    if [catch { mysim go }] {
	readline
    }
} else {
	readline
}

if { [info exists env(SKIBOOT_AUTORUN)] && $env(SKIBOOT_AUTORUN) == 2 } {
    quit
}
