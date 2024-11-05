// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * This file deals with setup of /cpus/ibm,powerpc-cpu-features dt
 *
 * Copyright 2017-2019 IBM Corp.
 */

#include <skiboot.h>
#include <cpu.h>
#include <processor.h>
#include <ccan/str/str.h>
#include <device.h>

#ifdef DEBUG
#define DBG(fmt, a...)	prlog(PR_DEBUG, "CPUFT: " fmt, ##a)
#else
#define DBG(fmt, a...)
#endif

/* Device-tree visible constants follow */
#define ISA_V2_07B	2070
#define ISA_V3_0B	3000
#define ISA_V3_1	3100

#define USABLE_PR		(1U << 0)
#define USABLE_OS		(1U << 1)
#define USABLE_HV		(1U << 2)

#define HV_SUPPORT_HFSCR	(1U << 0)
#define OS_SUPPORT_FSCR		(1U << 0)

/* Following are definitions for the match tables, not the DT binding itself */
#define ISA_BASE	0

#define HV_NONE		0
#define HV_CUSTOM	1
#define HV_HFSCR	2

#define OS_NONE		0
#define OS_CUSTOM	1
#define OS_FSCR		2

/* CPU bitmasks for match table */
#define CPU_P8_DD1	(1U << 0)
#define CPU_P8_DD2	(1U << 1)
#define CPU_P9_DD1	(1U << 2)
#define CPU_P9_DD2_0_1	(1U << 3) // 2.01 or 2.1
#define CPU_P9P		(1U << 4)
#define CPU_P9_DD2_2    (1U << 5)
#define CPU_P9_DD2_3    (1U << 6)
#define CPU_P10		(1U << 7)

#define CPU_P9_DD2      (CPU_P9_DD2_0_1|CPU_P9_DD2_2|CPU_P9_DD2_3|CPU_P9P)

#define CPU_P8		(CPU_P8_DD1|CPU_P8_DD2)
#define CPU_P9		(CPU_P9_DD1|CPU_P9_DD2|CPU_P9P)
#define CPU_ALL		(CPU_P8|CPU_P9|CPU_P10)

struct cpu_feature {
	const char *name;
	uint32_t cpus_supported;
	uint32_t isa;
	uint32_t usable_privilege;
	uint32_t hv_support;
	uint32_t os_support;
	uint32_t hfscr_bit_nr;
	uint32_t fscr_bit_nr;
	uint32_t hwcap_bit_nr;
	const char *dependencies_names; /* space-delimited names */
};

/*
 * The base (or NULL) cpu feature set is the CPU features available
 * when no child nodes of the /cpus/ibm,powerpc-cpu-features node exist. The
 * base feature set is POWER8 (ISAv2.07B), less features that are listed
 * explicitly.
 *
 * XXX: currently, the feature dependencies are not necessarily captured
 * exactly or completely. This is somewhat acceptable because all
 * implementations must be aware of all these features.
 */
static const struct cpu_feature cpu_features_table[] = {
	/*
	 * Big endian as in ISAv2.07B, MSR_LE=0
	 */
	{ "big-endian",
	CPU_ALL,
	ISA_BASE, USABLE_HV|USABLE_OS|USABLE_PR,
	HV_CUSTOM, OS_CUSTOM,
	-1, -1, -1,
	NULL, },

	/*
	 * Little endian as in ISAv2.07B, MSR_LE=1.
	 *
	 * When both big and little endian are defined, there is an LPCR ILE
	 * bit and implementation specific way to switch HILE mode, MSR_SLE,
	 * etc.
	 */
	{ "little-endian",
	CPU_ALL,
	ISA_BASE, USABLE_HV|USABLE_OS|USABLE_PR,
	HV_CUSTOM, OS_CUSTOM,
	-1, -1, -1,
	NULL, },

	/*
	 * MSR_HV=1 mode as in ISAv2.07B (i.e., hypervisor privileged
	 * instructions and registers).
	 */
	{ "hypervisor",
	CPU_ALL,
	ISA_BASE, USABLE_HV,
	HV_CUSTOM, OS_NONE,
	-1, -1, -1,
	NULL, },

	/*
	 * ISAv2.07B interrupt vectors, registers, and control registers
	 * (e.g., AIL, ILE, HV, etc LPCR bits).
	 *
	 * This does not necessarily specify all possible interrupt types.
	 * floating-point, for example requires some ways to handle floating
	 * point exceptions, but the low level details of interrupt handler
	 * is not a dependency there. There will always be *some* interrupt
	 * handler, (and some way to provide memory magagement, etc.).
	 */
	{ "interrupt-facilities",
	CPU_ALL,
	ISA_BASE, USABLE_HV|USABLE_OS,
	HV_CUSTOM, OS_CUSTOM,
	-1, -1, -1,
	NULL, },

	{ "smt",
	CPU_ALL,
	ISA_BASE, USABLE_HV|USABLE_OS|USABLE_PR,
	HV_CUSTOM, OS_CUSTOM,
	-1, -1, 14,
	NULL, },

	/*
	 * ISAv2.07B Program Priority Registers (PPR)
	 * PPR and associated control registers (e.g. RPR, PSPB),
	 * priority "or" instructions, etc.
	 */
	{ "program-priority-register",
	CPU_ALL,
	ISA_BASE, USABLE_HV|USABLE_OS|USABLE_PR,
	HV_NONE, OS_NONE,
	-1, -1, -1,
	NULL, },

	/*
	 * ISAv2.07B Book3S Chapter 5.7.9.1. Virtual Page Class Key Protecion
	 * AMR, IAMR, AMOR, UAMOR, etc registers and MMU key bits.
	 */
	{ "virtual-page-class-key-protection",
	CPU_ALL,
	ISA_BASE, USABLE_HV|USABLE_OS|USABLE_PR,
	HV_CUSTOM, OS_CUSTOM,
	-1, -1, -1,
	NULL, },

	/*
	 * ISAv2.07B SAO storage control attribute
	 */
	{ "strong-access-ordering",
	CPU_ALL & ~CPU_P9_DD1,
	ISA_BASE, USABLE_HV|USABLE_OS|USABLE_PR,
	HV_CUSTOM, OS_CUSTOM,
	-1, -1, -1,
	NULL, },

	/*
	 * ISAv2.07B no-execute storage control attribute
	 */
	{ "no-execute",
	CPU_ALL,
	ISA_BASE, USABLE_HV|USABLE_OS,
	HV_CUSTOM, OS_CUSTOM,
	-1, -1, -1,
	NULL, },

	/*
	 * Cache inhibited attribute supported on large pages.
	 */
	{ "cache-inhibited-large-page",
	CPU_ALL,
	ISA_BASE, USABLE_HV|USABLE_OS,
	HV_CUSTOM, OS_CUSTOM,
	-1, -1, -1,
	NULL, },

	/*
	 * ISAv2.07B Book3S Chapter 8. Debug Facilities
	 * CIEA, CIABR, DEAW, MEte, trace interrupt, etc.
	 * Except CFAR, branch tracing.
	 */
	{ "debug-facilities",
	CPU_ALL,
	ISA_BASE, USABLE_HV|USABLE_OS,
	HV_CUSTOM, OS_CUSTOM,
	-1, -1, -1,
	NULL, },

	/*
	 * DAWR1, DAWRX1 etc.
	 */
	{ "debug-facilities-v31",
	CPU_P10,
	ISA_V3_1, USABLE_HV|USABLE_OS,
	HV_CUSTOM, OS_CUSTOM,
	-1, -1, -1,
	NULL, },

	/*
	 * ISAv2.07B CFAR
	 */
	{ "come-from-address-register",
	CPU_ALL,
	ISA_BASE, USABLE_HV|USABLE_OS,
	HV_CUSTOM, OS_CUSTOM,
	-1, -1, -1,
	"debug-facilities", },

	/*
	 * ISAv2.07B Branch tracing (optional in ISA)
	 */
	{ "branch-tracing",
	CPU_ALL,
	ISA_BASE, USABLE_HV|USABLE_OS,
	HV_CUSTOM, OS_CUSTOM,
	-1, -1, -1,
	"debug-facilities", },

	/*
	 * ISAv2.07B Floating-point Facility
	 */
	{ "floating-point",
	CPU_ALL,
	ISA_BASE, USABLE_HV|USABLE_OS|USABLE_PR,
	HV_CUSTOM, OS_CUSTOM,
	PPC_BITLSHIFT(63), -1, 27,
	NULL, },

	/*
	 * ISAv2.07B Vector Facility (VMX)
	 */
	{ "vector",
	CPU_ALL,
	ISA_BASE, USABLE_HV|USABLE_OS|USABLE_PR,
	HV_CUSTOM, OS_CUSTOM,
	PPC_BITLSHIFT(62), -1, 28,
	"floating-point", },

	/*
	 * ISAv2.07B Vector-scalar Facility (VSX)
	 */
	{ "vector-scalar",
	CPU_ALL,
	ISA_BASE, USABLE_HV|USABLE_OS|USABLE_PR,
	HV_CUSTOM, OS_CUSTOM,
	-1, -1, 7,
	"vector", },

	{ "vector-crypto",
	CPU_ALL,
	ISA_BASE, USABLE_HV|USABLE_OS|USABLE_PR,
	HV_NONE, OS_NONE,
	-1, -1, 57,
	"vector", },

	/*
	 * ISAv2.07B Quadword Load and Store instructions
	 * including lqarx/stdqcx. instructions.
	 */
	{ "quadword-load-store",
	CPU_ALL,
	ISA_BASE, USABLE_HV|USABLE_OS|USABLE_PR,
	HV_NONE, OS_NONE,
	-1, -1, -1,
	NULL, },

	/*
	 * ISAv2.07B Binary Coded Decimal (BCD)
	 * BCD fixed point instructions
	 */
	{ "decimal-integer",
	CPU_ALL,
	ISA_BASE, USABLE_HV|USABLE_OS|USABLE_PR,
	HV_NONE, OS_NONE,
	-1, -1, -1,
	NULL, },

	/*
	 * ISAv2.07B Decimal floating-point Facility (DFP)
	 */
	{ "decimal-floating-point",
	CPU_ALL,
	ISA_BASE, USABLE_HV|USABLE_OS|USABLE_PR,
	HV_NONE, OS_NONE,
	-1, -1, 10,
	"floating-point", },

	/*
	 * ISAv2.07B
	 * DSCR, default data prefetch LPCR, etc
	 */
	{ "data-stream-control-register",
	CPU_ALL,
	ISA_BASE, USABLE_HV|USABLE_OS|USABLE_PR,
	HV_CUSTOM, OS_CUSTOM,
	PPC_BITLSHIFT(61), PPC_BITLSHIFT(61), 61,
	NULL, },

	/*
	 * ISAv2.07B Branch History Rolling Buffer (BHRB)
	 */
	{ "branch-history-rolling-buffer",
	CPU_ALL,
	ISA_BASE, USABLE_HV|USABLE_OS|USABLE_PR,
	HV_CUSTOM, OS_CUSTOM,
	PPC_BITLSHIFT(59), -1, -1,
	NULL, },

	/*
	 * ISAv2.07B Transactional Memory Facility (TM or HTM)
	 */
	{ "transactional-memory",
	CPU_P8, /* P9 support is not enabled yet */
	ISA_BASE, USABLE_HV|USABLE_OS|USABLE_PR,
	HV_CUSTOM, OS_CUSTOM,
	PPC_BITLSHIFT(58), -1, 62,
	NULL, },

	/*
	 * ISAv3.0B TM additions
	 * TEXASR bit 17, self-induced vs external footprint overflow
	 */
	{ "transactional-memory-v3",
	0,
	ISA_V3_0B, USABLE_HV|USABLE_OS|USABLE_PR,
	HV_NONE, OS_NONE,
	-1, -1, -1,
	"transactional-memory", },

	/*
	 * ISAv2.07B Event-Based Branch Facility (EBB)
	 */
	{ "event-based-branch",
	CPU_ALL,
	ISA_BASE, USABLE_HV|USABLE_OS|USABLE_PR,
	HV_CUSTOM, OS_CUSTOM,
	PPC_BITLSHIFT(56), PPC_BITLSHIFT(56), 60,
	NULL, },

	/*
	 * ISAv2.07B Target Address Register (TAR)
	 */
	{ "target-address-register",
	CPU_ALL,
	ISA_BASE, USABLE_HV|USABLE_OS|USABLE_PR,
	HV_CUSTOM, OS_CUSTOM,
	PPC_BITLSHIFT(55), PPC_BITLSHIFT(55), 58,
	NULL, },

	/*
	 * ISAv2.07B Control Register (CTRL)
	 */
	{ "control-register",
	CPU_ALL,
	ISA_BASE, USABLE_HV|USABLE_OS,
	HV_CUSTOM, OS_CUSTOM,
	-1, -1, -1,
	NULL, },

	/*
	 * ISAv2.07B Book3S Chapter 11. Processor Control.
	 * msgsnd, msgsndp, doorbell, etc.
	 *
	 * ISAv3.0B is not compatible (different addressing, HFSCR required
	 * for msgsndp).
	 */
	{ "processor-control-facility",
	CPU_P8_DD2, /* P8 DD1 has no dbell */
	ISA_BASE, USABLE_HV|USABLE_OS,
	HV_CUSTOM, OS_CUSTOM,
	-1, -1, -1,
	NULL, },

	/*
	 * ISAv2.07B PURR, SPURR registers
	 */
	{ "processor-utilization-of-resources-register",
	CPU_ALL,
	ISA_BASE, USABLE_HV|USABLE_OS,
	HV_CUSTOM, OS_CUSTOM,
	-1, -1, -1,
	NULL, },

	/*
	 * POWER8 initiate coprocessor store word indexed (icswx) instruction
	 */
	{ "coprocessor-icswx",
	CPU_P8,
	ISA_BASE, USABLE_HV|USABLE_OS,
	HV_CUSTOM, OS_CUSTOM,
	-1, -1, -1,
	NULL, },

	/*
	 * ISAv2.07B hash based MMU and all instructions, registers,
	 * data structures, exceptions, etc.
	 */
	{ "mmu-hash",
	CPU_P8,
	ISA_BASE, USABLE_HV|USABLE_OS,
	HV_CUSTOM, OS_CUSTOM,
	-1, -1, -1,
	NULL, },

	/*
	 * POWER8 MCE / machine check exception.
	 */
	{ "machine-check-power8",
	CPU_P8,
	ISA_BASE, USABLE_HV|USABLE_OS,
	HV_CUSTOM, OS_CUSTOM,
	-1, -1, -1,
	NULL, },

	/*
	 * POWER8 PMU / performance monitor unit.
	 */
	{ "performance-monitor-power8",
	CPU_P8,
	ISA_BASE, USABLE_HV|USABLE_OS,
	HV_CUSTOM, OS_CUSTOM,
	-1, -1, -1,
	NULL, },

	/*
	 * ISAv2.07B alignment interrupts set DSISR register
	 *
	 * POWER CPUs do not used this, and it's removed from ISAv3.0B.
	 */
	{ "alignment-interrupt-dsisr",
	0,
	ISA_BASE, USABLE_HV|USABLE_OS,
	HV_NONE, OS_NONE,
	-1, -1, -1,
	NULL, },

	/*
	 * ISAv2.07B / POWER8 doze, nap, sleep, winkle instructions
	 * XXX: is Linux we using some BookIV specific implementation details
	 * in nap handling? We have no POWER8 specific key here.
	 */
	{ "idle-nap",
	CPU_P8,
	ISA_BASE, USABLE_HV,
	HV_CUSTOM, OS_NONE,
	-1, -1, -1,
	NULL, },

	/*
	 * ISAv2.07B wait instruction
	 */
	{ "wait",
	CPU_P8,
	ISA_BASE, USABLE_HV|USABLE_OS|USABLE_PR,
	HV_NONE, OS_NONE,
	-1, -1, -1,
	NULL, },

	{ "subcore",
	CPU_P8,
	ISA_BASE, USABLE_HV|USABLE_OS,
	HV_CUSTOM, OS_CUSTOM,
	-1, -1, -1,
	"smt", },

	/*
	 * ISAv3.0B radix based MMU
	 */
	{ "mmu-radix",
	CPU_P9|CPU_P10,
	ISA_V3_0B, USABLE_HV|USABLE_OS,
	HV_CUSTOM, OS_CUSTOM,
	-1, -1, -1,
	NULL, },

	/*
	 * ISAv3.0B hash based MMU, new hash pte format, PCTR, etc
	 */
	{ "mmu-hash-v3",
	CPU_P9|CPU_P10,
	ISA_V3_0B, USABLE_HV|USABLE_OS,
	HV_CUSTOM, OS_CUSTOM,
	-1, -1, -1,
	NULL, },

	/*
	 * ISAv3.0B wait instruction
	 */
	{ "wait-v3",
	CPU_P9|CPU_P10,
	ISA_V3_0B, USABLE_HV|USABLE_OS|USABLE_PR,
	HV_NONE, OS_NONE,
	-1, -1, -1,
	NULL, },

	/*
	 * ISAv3.0B stop idle instructions and registers
	 * XXX: Same question as for idle-nap
	 */
	{ "idle-stop",
	CPU_P9|CPU_P10,
	ISA_V3_0B, USABLE_HV|USABLE_OS,
	HV_CUSTOM, OS_CUSTOM,
	-1, -1, -1,
	NULL, },

	/*
	 * ISAv3.0B Hypervisor Virtualization Interrupt
	 * Also associated system registers, LPCR EE, HEIC, HVICE,
	 * system reset SRR1 reason, etc.
	 */
	{ "hypervisor-virtualization-interrupt",
	CPU_P9|CPU_P10,
	ISA_V3_0B, USABLE_HV,
	HV_CUSTOM, OS_NONE,
	-1, -1, -1,
	NULL, },

	/*
	 * POWER9 MCE / machine check exception.
	 */
	{ "machine-check-power9",
	CPU_P9,
	ISA_V3_0B, USABLE_HV|USABLE_OS,
	HV_CUSTOM, OS_CUSTOM,
	-1, -1, -1,
	NULL, },

	/*
	 * POWER10 MCE / machine check exception.
	 */
	{ "machine-check-power10",
	CPU_P10,
	ISA_V3_0B, USABLE_HV|USABLE_OS,
	HV_CUSTOM, OS_CUSTOM,
	-1, -1, -1,
	NULL, },

	/*
	 * POWER9 PMU / performance monitor unit.
	 */
	{ "performance-monitor-power9",
	CPU_P9,
	ISA_V3_0B, USABLE_HV|USABLE_OS,
	HV_CUSTOM, OS_CUSTOM,
	-1, -1, -1,
	NULL, },

	/*
	 * POWER10 PMU / performance monitor unit.
	 */
	{ "performance-monitor-power10",
	CPU_P10,
	ISA_V3_1, USABLE_HV|USABLE_OS,
	HV_CUSTOM, OS_CUSTOM,
	-1, -1, -1,
	NULL, },

	/*
	 * ISAv3.0B scv/rfscv system call instructions and exceptions, fscr bit
	 * etc.
	 */
	{ "system-call-vectored",
	CPU_P9|CPU_P10,
	ISA_V3_0B, USABLE_OS|USABLE_PR,
	HV_NONE, OS_CUSTOM,
	-1, PPC_BITLSHIFT(51), 52,
	NULL, },

	/*
	 * ISAv3.0B Book3S Chapter 10. Processor Control.
	 * global msgsnd, msgsndp, msgsync, doorbell, etc.
	 */
	{ "processor-control-facility-v3",
	CPU_P9|CPU_P10,
	ISA_V3_0B, USABLE_HV|USABLE_OS,
	HV_CUSTOM, OS_NONE,
	PPC_BITLSHIFT(53), -1, -1,
	NULL, },

	/*
	 * ISAv3.0B addpcis instruction
	 */
	{ "pc-relative-addressing",
	CPU_P9|CPU_P10,
	ISA_V3_0B, USABLE_HV|USABLE_OS|USABLE_PR,
	HV_NONE, OS_NONE,
	-1, -1, -1,
	NULL, },

	/*
	 * ISAv2.07B Book3S Chapter 7. Timer Facilities
	 * TB, VTB, DEC, HDEC, IC, etc registers and exceptions.
	 * Not including PURR or SPURR registers.
	 */
	{ "timer-facilities",
	CPU_ALL,
	ISA_BASE, USABLE_HV|USABLE_OS,
	HV_NONE, OS_NONE,
	-1, -1, -1,
	NULL, },

	/*
	 * ISAv3.0B Book3S Chapter 7. Timer Facilities
	 * Large decrementer and hypervisor decrementer
	 */
	{ "timer-facilities-v3",
	CPU_P9|CPU_P10,
	ISA_V3_0B, USABLE_HV|USABLE_OS,
	HV_NONE, OS_NONE,
	-1, -1, -1,
	"timer-facilities", },

	/*
	 * ISAv3.0B deliver a random number instruction (darn)
	 */
	{ "random-number-generator",
	CPU_P9|CPU_P10,
	ISA_V3_0B, USABLE_HV|USABLE_OS|USABLE_PR,
	HV_NONE, OS_NONE,
	-1, -1, 53,
	NULL, },

	/*
	 * ISAv3.0B fixed point instructions and registers
	 * multiply-add, modulo, count trailing zeroes, cmprb, cmpeqb,
	 * extswsli, mfvsrld, mtvsrdd, mtvsrws, addex, CA32, OV32,
	 * mcrxrx, setb
	 */
	{ "fixed-point-v3",
	CPU_P9|CPU_P10,
	ISA_V3_0B, USABLE_HV|USABLE_OS|USABLE_PR,
	HV_NONE, OS_NONE,
	-1, -1, -1,
	NULL, },

	{ "decimal-integer-v3",
	CPU_P9|CPU_P10,
	ISA_V3_0B, USABLE_HV|USABLE_OS|USABLE_PR,
	HV_NONE, OS_NONE,
	-1, -1, -1,
	"fixed-point-v3 decimal-integer", },

	/*
	 * ISAv3.0B lightweight mffs
	 */
	{ "floating-point-v3",
	CPU_P9|CPU_P10,
	ISA_V3_0B, USABLE_HV|USABLE_OS|USABLE_PR,
	HV_NONE, OS_NONE,
	-1, -1, -1,
	"floating-point", },

	{ "decimal-floating-point-v3",
	CPU_P9|CPU_P10,
	ISA_V3_0B, USABLE_HV|USABLE_OS|USABLE_PR,
	HV_NONE, OS_NONE,
	-1, -1, -1,
	"floating-point-v3 decimal-floating-point", },

	{ "vector-v3",
	CPU_P9|CPU_P10,
	ISA_V3_0B, USABLE_HV|USABLE_OS|USABLE_PR,
	HV_NONE, OS_NONE,
	-1, -1, -1,
	"vector", },

	{ "vector-scalar-v3",
	CPU_P9|CPU_P10,
	ISA_V3_0B, USABLE_HV|USABLE_OS|USABLE_PR,
	HV_NONE, OS_NONE,
	-1, -1, -1,
	"vector-v3 vector-scalar" },

	{ "vector-binary128",
	CPU_P9|CPU_P10,
	ISA_V3_0B, USABLE_HV|USABLE_OS|USABLE_PR,
	HV_NONE, OS_NONE,
	-1, -1, 54,
	"vector-scalar-v3", },

	{ "vector-binary16",
	CPU_P9|CPU_P10,
	ISA_V3_0B, USABLE_HV|USABLE_OS|USABLE_PR,
	HV_NONE, OS_NONE,
	-1, -1, -1,
	"vector-v3", },

	/*
	 * ISAv3.0B external exception for EBB
	 */
	{ "event-based-branch-v3",
	CPU_P9|CPU_P10,
	ISA_V3_0B, USABLE_HV|USABLE_OS|USABLE_PR,
	HV_NONE, OS_NONE,
	-1, -1, -1,
	"event-based-branch", },

	/*
	 * ISAv3.0B Atomic Memory Operations (AMO)
	 */
	{ "atomic-memory-operations",
	CPU_P9|CPU_P10,
	ISA_V3_0B, USABLE_HV|USABLE_OS|USABLE_PR,
	HV_NONE, OS_NONE,
	-1, -1, -1,
	NULL, },

	/*
	 * ISAv3.0B Copy-Paste Facility
	 */
	{ "copy-paste",
	CPU_P9|CPU_P10,
	ISA_V3_0B, USABLE_HV|USABLE_OS|USABLE_PR,
	HV_NONE, OS_NONE,
	-1, -1, -1,
	NULL, },

	/*
	 * ISAv3.0B GSR SPR register
	 * POWER9 does not implement it
	 */
	{ "group-start-register",
	0,
	ISA_V3_0B, USABLE_HV|USABLE_OS,
	HV_NONE, OS_NONE,
	-1, -1, -1,
	NULL, },

	/*
	 * Enable matrix multiply accumulate.
	 */
	{ "matrix-multiply-accumulate",
	CPU_P10,
	ISA_V3_1, USABLE_PR,
	HV_CUSTOM, OS_CUSTOM,
	-1, -1, 49,
	NULL, },

	/*
	 * Enable prefix instructions. Toolchains assume this is
	 * enabled for when compiling for ISA 3.1.
	 */
	{ "prefix-instructions",
	CPU_P10,
	ISA_V3_1, USABLE_HV|USABLE_OS|USABLE_PR,
	HV_HFSCR, OS_FSCR,
	13, 13, -1,
	NULL, },

	/*
	 * Due to hardware bugs in POWER9, the hypervisor needs to assist
	 * guests.
	 *
	 * Presence of this feature indicates presence of the bug.
	 *
	 * See linux kernel commit 4bb3c7a0208f
	 * and linux Documentation/powerpc/transactional_memory.txt
	 */
	{ "tm-suspend-hypervisor-assist",
	CPU_P9_DD2_2|CPU_P9_DD2_3|CPU_P9P,
	ISA_V3_0B, USABLE_HV,
	HV_CUSTOM, OS_NONE,
	-1, -1, -1,
	NULL, },

	/*
	 * Due to hardware bugs in POWER9, the hypervisor can hit
	 * CPU bugs in the operations it needs to do for
	 * tm-suspend-hypervisor-assist.
	 *
	 * Presence of this "feature" means processor is affected by the bug.
	 *
	 * See linux kernel commit 4bb3c7a0208f
	 * and linux Documentation/powerpc/transactional_memory.txt
	 */
	{ "tm-suspend-xer-so-bug",
	CPU_P9_DD2_2,
	ISA_V3_0B, USABLE_HV,
	HV_CUSTOM, OS_NONE,
	-1, -1, -1,
	NULL, },
};

static void add_cpu_feature_nodeps(struct dt_node *features,
				   const struct cpu_feature *f)
{
	struct dt_node *feature;

	feature = dt_new(features, f->name);
	assert(feature);

	dt_add_property_cells(feature, "isa", f->isa);
	dt_add_property_cells(feature, "usable-privilege", f->usable_privilege);

	if (f->usable_privilege & USABLE_HV) {
		if (f->hv_support != HV_NONE) {
			uint32_t s = 0;
			if (f->hv_support == HV_HFSCR)
				s |= HV_SUPPORT_HFSCR;

			dt_add_property_cells(feature, "hv-support", s);
			if (f->hfscr_bit_nr != -1)
				dt_add_property_cells(feature, "hfscr-bit-nr", f->hfscr_bit_nr);
		} else {
			assert(f->hfscr_bit_nr == -1);
		}
	}

	if (f->usable_privilege & USABLE_OS) {
		if (f->os_support != OS_NONE) {
			uint32_t s = 0;
			if (f->os_support == OS_FSCR)
				s |= OS_SUPPORT_FSCR;
			dt_add_property_cells(feature, "os-support", s);
			if (f->fscr_bit_nr != -1)
				dt_add_property_cells(feature, "fscr-bit-nr", f->fscr_bit_nr);
		} else {
			assert(f->fscr_bit_nr == -1);
		}
	}

	if (f->usable_privilege & USABLE_PR) {
		if (f->hwcap_bit_nr != -1)
			dt_add_property_cells(feature, "hwcap-bit-nr", f->hwcap_bit_nr);
	}

	if (f->dependencies_names)
		dt_add_property(feature, "dependencies", NULL, 0);
}

static void add_cpufeatures_dependencies(struct dt_node *features)
{
	struct dt_node *feature;

	dt_for_each_node(features, feature) {
		const struct cpu_feature *f = NULL;
		const char *deps_names;
		struct dt_property *deps;
		int nr_deps;
		int i;

		/* Find features with dependencies */

		deps = __dt_find_property(feature, "dependencies");
		if (!deps)
			continue;

		/* Find the matching cpu table */
		for (i = 0; i < ARRAY_SIZE(cpu_features_table); i++) {
			f = &cpu_features_table[i];
			if (!strcmp(f->name, feature->name))
				break;
		}
		assert(f);
		assert(f->dependencies_names);

		/*
		 * Count number of depended features and allocate space
		 * for phandles in the property.
		 */
		deps_names = f->dependencies_names;
		nr_deps = strcount(deps_names, " ") + 1;
		dt_resize_property(&deps, nr_deps * sizeof(u32));

		DBG("feature %s has %d dependencies (%s)\n", f->name, nr_deps, deps_names);
		/*
		 * For each one, find the depended feature then advance to
		 * next name.
		 */
		for (i = 0; i < nr_deps; i++) {
			struct dt_node *dep;
			int len;

			if (nr_deps - i == 1)
				len = strlen(deps_names);
			else
				len = strchr(deps_names, ' ') - deps_names;

			dt_for_each_node(features, dep) {
				if (!strncmp(deps_names, dep->name, len))
					goto found_dep;
			}

			prlog(PR_ERR, "CPUFT: feature %s dependencies not found\n", f->name);
			break;
found_dep:
			DBG(" %s found dep (%s)\n", f->name, dep->name);
			dt_property_set_cell(deps, i, dep->phandle);

			/* Advance over the name + delimiter */
			deps_names += len + 1;
		}
	}
}

static void add_cpufeatures(struct dt_node *cpus,
			    uint32_t cpu_feature_isa, uint32_t cpu_feature_cpu,
			    const char *cpu_name)
{
	struct dt_node *features;
	int i;

	DBG("creating cpufeatures for cpu:%d isa:%d\n", cpu_feature_cpu, cpu_feature_isa);

	features = dt_new(cpus, "ibm,powerpc-cpu-features");
	assert(features);

	dt_add_property_cells(features, "isa", cpu_feature_isa);

	dt_add_property_string(features, "device_type", "cpu-features");
	dt_add_property_string(features, "compatible", "ibm,powerpc-cpu-features");
	dt_add_property_string(features, "display-name", cpu_name);

	/* add without dependencies */
	for (i = 0; i < ARRAY_SIZE(cpu_features_table); i++) {
		const struct cpu_feature *f = &cpu_features_table[i];

		if (f->cpus_supported & cpu_feature_cpu) {
			DBG("  '%s'\n", f->name);
			add_cpu_feature_nodeps(features, f);
		}
	}

	/* dependency construction pass */
	add_cpufeatures_dependencies(features);
}

void dt_add_cpufeatures(struct dt_node *root)
{
	int version;
	uint32_t cpu_feature_isa = 0;
	uint32_t cpu_feature_cpu = 0;
	struct dt_node *cpus;
	const char *cpu_name = NULL;

	version = mfspr(SPR_PVR);
	switch(PVR_TYPE(version)) {
	case PVR_TYPE_P8:
		if (!cpu_name)
			cpu_name = "POWER8";
		/* fallthrough */
	case PVR_TYPE_P8E:
		if (!cpu_name)
			cpu_name = "POWER8E";
		/* fallthrough */
		cpu_feature_isa = ISA_V2_07B;
		if (PVR_VERS_MAJ(version) == 1)
			cpu_feature_cpu = CPU_P8_DD1;
		else
			cpu_feature_cpu = CPU_P8_DD2;
		break;
	case PVR_TYPE_P8NVL:
		cpu_name = "POWER8NVL";
		cpu_feature_isa = ISA_V2_07B;
		cpu_feature_cpu = CPU_P8_DD2;
		break;
	case PVR_TYPE_P9:
		if (!cpu_name)
			cpu_name = "POWER9";

		cpu_feature_isa = ISA_V3_0B;
		if (is_power9n(version) &&
			   (PVR_VERS_MAJ(version) == 2)) {
			/* P9N DD2.x */
			switch (PVR_VERS_MIN(version)) {
			case 0:
			case 1:
				cpu_feature_cpu = CPU_P9_DD2_0_1;
				break;
			case 2:
				cpu_feature_cpu = CPU_P9_DD2_2;
				break;
			case 3:
				cpu_feature_cpu = CPU_P9_DD2_3;
				break;
			default:
				assert(0);
			}
		} else if (is_power9c(version) &&
                            (PVR_VERS_MAJ(version) == 1)) {
                          /* P9C DD1.x */
			switch (PVR_VERS_MIN(version)) {
                        case 1:
				/* Cumulus DD1.1 => Nimbus DD2.1 */
				cpu_feature_cpu = CPU_P9_DD2_0_1;
				break;
			case 2:
				/* Cumulus DD1.2 */
				cpu_feature_cpu = CPU_P9_DD2_2;
				break;
			case 3:
				/* Cumulus DD1.3 */
				cpu_feature_cpu = CPU_P9_DD2_3;
				break;
			default:
				assert(0);
			}
		} else {
			assert(0);
		}

		break;
	case PVR_TYPE_P9P:
		if (!cpu_name)
			cpu_name = "POWER9P";

		cpu_feature_isa = ISA_V3_0B;
		cpu_feature_cpu = CPU_P9P;
		break;
	case PVR_TYPE_P10:
		if (!cpu_name)
			cpu_name = "POWER10";

		cpu_feature_isa = ISA_V3_1;
		cpu_feature_cpu = CPU_P10;
		break;
	default:
		return;
	}

	cpus = dt_new_check(root, "cpus");

	add_cpufeatures(cpus, cpu_feature_isa, cpu_feature_cpu, cpu_name);
}
