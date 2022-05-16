// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2016-2019 IBM Corp. */
/*
 * In-Memory Collection (IMC) Counters :
 * Power9 has IMC instrumentation support with which several
 * metrics of the platform can be monitored. These metrics
 * are backed by the Performance Monitoring Units (PMUs) and
 * their counters. IMC counters can be configured to run
 * continuously from startup to shutdown and data from these
 * counters are fed directly into a pre-defined memory location.
 *
 * Depending on the counters' location and monitoring engines,
 * they are classified into three domains :
 * Nest IMC, core IMC and thread IMC.
 *
 * Nest Counters :
 * Nest counters are per-chip counters and can help in providing utilisation
 * metrics like memory bandwidth, Xlink/Alink bandwidth etc.
 * A microcode in OCC programs the nest counters and moves counter values to
 * per chip HOMER region in a fixed offset for each unit. Engine has a
 * control block structure for communication with Hypervisor(Host OS).
 */

#ifndef __IMC_H
#define __IMC_H

/*
 * Control Block structure offset in HOMER nest Region
 */
#define P9_CB_STRUCT_OFFSET		0x1BFC00
#define P9_CB_STRUCT_CMD		0x1BFC08
#define P9_CB_STRUCT_SPEED		0x1BFC10

/* Nest microcode Status */
#define NEST_IMC_PAUSE		0x2
#define NEST_IMC_RUNNING	0x1
#define NEST_IMC_NOP		0

/*
 * Control Block Structure:
 *
 * Name          Producer        Consumer        Values  Desc
 * IMCRunStatus   IMC Code       Hypervisor      0       Initializing
 *                               (Host OS)       1       Running
 *                                               2       Paused
 *
 * IMCCommand     Hypervisor     IMC Code        0       NOP
 *                                               1       Resume
 *                                               2       Pause
 *                                               3       Clear and Restart
 *
 * IMCCollection Hypervisor      IMC Code        0       128us
 * Speed					 1       256us
 *                                               2       1ms
 *                                               3       4ms
 *                                               4       16ms
 *                                               5       64ms
 *                                               6       256ms
 *                                               7       1000ms
 *
 * IMCAvailability IMC Code      Hypervisor      -       64-bit value describes
 *                                                       the Vector Nest PMU
 *                                                       availability.
 *                                                       Bits 0-47 denote the
 *                                                       availability of 48 different
 *                                                       nest units.
 *                                                       Rest are reserved. For details
 *                                                       regarding which bit belongs
 *                                                       to which unit, see
 *                                                       include/nest_imc.h.
 *                                                       If a bit is unset (0),
 *                                                       then, the corresponding unit
 *                                                       is unavailable. If its set (1),
 *                                                       then, the unit is available.
 *
 * IMCRun Mode    Hypervisor     IMC Code        0       Normal Mode (Monitor Mode)
 *                                               1       Debug Mode 1 (PB)
 *                                               2       Debug Mode 2 (MEM)
 *                                               3       Debug Mode 3 (PCIE)
 *                                               4       Debug Mode 4 (CAPP)
 *                                               5       Debug Mode 5 (NPU 1)
 *                                               6       Debug Mode 6 (NPU 2)
 */
struct imc_chip_cb
{
	be64 imc_chip_run_status;
	be64 imc_chip_command;
	be64 imc_chip_collection_speed;
	be64 imc_chip_avl_vector;
	be64 imc_chip_run_mode;
} __packed;

/* Size of IMC dtb LID (256KBytes) */
#define MAX_DECOMPRESSED_IMC_DTB_SIZE		0x40000
#define MAX_COMPRESSED_IMC_DTB_SIZE		0x40000

/* IMC device types */
#define IMC_COUNTER_CHIP		0x10
#define IMC_COUNTER_CORE		0x4
#define IMC_COUNTER_THREAD		0x1
#define IMC_COUNTER_TRACE		0x2

/*
 * Nest IMC operations
 */
#define NEST_IMC_ENABLE			0x1
#define NEST_IMC_DISABLE		0x2

/*
 * Core IMC SCOMs
 */
#define CORE_IMC_EVENT_MASK_ADDR_P9	0x20010AA8ull
#define CORE_IMC_EVENT_MASK_ADDR_P10	0x20020400ull
#define CORE_IMC_EVENT_MASK		0x0402010000000000ull
#define CORE_IMC_PDBAR_MASK		0x0003ffffffffe000ull
#define CORE_IMC_HTM_MODE_ENABLE	0xE800000000000000ull
#define CORE_IMC_HTM_MODE_DISABLE	0xE000000000000000ull

/*
 * Trace IMC SCOMs for IMC trace-mode.
 *
 * TRACE_IMC_SCOM layout
 *
 *  0          4         8         12        16        20        24        28
 * | - - - - | - - - - | - - - - | - - - - | - - - - | - - - - | - - - - | - - - - |
 *   [ ] [      CPMC_LOAD [2:33]
 *    |
 *    *SAMPSEL
 *
 *  32        36        40        44        48        52        56        60
 * | - - - - | - - - - | - - - - | - - - - | - - - - | - - - - | - - - - | - - - - |
 *     ] [               ] [             ]   [   ] [     RESERVED [51:63]        ]
 *     		|		 |	       |
 *     		*CPMC1SEL	 *CPMC2SEL     *BUFFERSIZE
 */
#define TRACE_IMC_ADDR_P9            0x20010AA9ull
#define TRACE_IMC_ADDR_P10           0x20020401ull
#define TRACE_IMC_SAMPLESEL(x)	((uint64_t)x << 62)
#define TRACE_IMC_CPMC_LOAD(x)	((0xffffffff - (uint64_t)x) << 30)
#define TRACE_IMC_CPMC1SEL(x)	((uint64_t)x << 23)
#define TRACE_IMC_CPMC2SEL(x)	((uint64_t)x << 16)
#define TRACE_IMC_BUFFERSIZE(x)	((uint64_t)x << 13)
#define TRACE_IMC_SCOM(a, b, c, d, e)	(TRACE_IMC_SAMPLESEL(a)	|\
					TRACE_IMC_CPMC_LOAD(b)	|\
					TRACE_IMC_CPMC1SEL(c)	|\
					TRACE_IMC_CPMC2SEL(d)	|\
					TRACE_IMC_BUFFERSIZE(e))

void imc_init(void);
void imc_catalog_preload(void);
void imc_decompress_catalog(void);

#define MAX_NEST_COMBINED_UNITS		4
struct combined_units_node {
	const char *name;
	u64 unit1;
	u64 unit2;
};
#endif /* __IMC_H */
