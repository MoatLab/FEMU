// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#ifndef __MEM_MAP_H
#define __MEM_MAP_H

/* This is our main offset for relocation. All our buffers
 * are offset from that and our code relocates itself to
 * that location
 */
#define SKIBOOT_BASE		0x30000000

/* Stack size set to 32K, 16K for general stack and 16K for an emergency
 * stack.
 */
#define STACK_SHIFT		15
#define STACK_SIZE		(1 << STACK_SHIFT)

/* End of the exception region we copy from 0x0. 0x0-0x100 will have
 * IPL data and is not actually for exception vectors.
 */
#define EXCEPTION_VECTORS_END	0x3000

#define NACA_OFF		0x4000

/* The NACA and other stuff in head.S need to be at the start: we
 * give it 64k before placing the SPIRA and related data.
 */
#define SPIRA_OFF		0x00010000
#define SPIRA_SIZE		0x400
#define SPIRAH_OFF		0x00010400
#define SPIRAH_SIZE		0x300

#define PROC_DUMP_AREA_OFF	(SPIRAH_OFF + SPIRAH_SIZE)
#define PROC_DUMP_AREA_SIZE	0x100

/* Actual SPIRA size is lesser than 1K (presently 0x340 bytes).
 * Use 1K for legacy SPIRA.
 *
 * SPIRA-H is lesser than 768 bytes (presently we use 288 bytes)
 * Use 768 bytes for SPIRAH.
 *
 * Use 256 bytes for processor dump area. (presently we use
 * sizeof(proc_dump_area) = 0x30 bytes).
 *
 * Then follow with for proc_init_data (aka PROCIN).
 * These need to be at fixed addresses in case we're ever little
 * endian: linker can't endian reverse a pointer for us.  Text, data
 * et. al. follows this.
 */
#define PROCIN_OFF		(SPIRA_OFF + 0x800)

/* Initial MDST and MDDT tables like PROCIN, we need fixed addresses,
 * we leave a 2k gap for PROCIN
 */
#define MDST_TABLE_OFF		(SPIRA_OFF + 0x1000)
#define MDST_TABLE_SIZE		0x400

#define MDDT_TABLE_OFF		(SPIRA_OFF + 0x1400)
#define MDDT_TABLE_SIZE		0x400

/* Like MDST and MDDT, we need fixed address for CPU control header.
 * We leave a 2k gap for MDST. CPU_CTL table is of size ~4k
 */
#define CPU_CTL_OFF             (SPIRA_OFF + 0x1800)

/* We keep a gap of 5M for skiboot text & bss for now. We will
 * then we have our heap which goes up to base + 14M (so 11M for
 * now, though we can certainly reduce that a lot).
 *
 * Ideally, we should fix the heap end and use _end to basically
 * initialize our heap so that it covers anything from _end to
 * that heap end, avoiding wasted space.
 *
 * That's made a bit tricky however due to how we create those
 * regions statically in mem_region.c, but still on the list of
 * things to improve.
 *
 * As of A Long Time Ago (2014/4/6), we used approc 512K for skiboot
 * core and 2M of heap on a 1 socket machine.
 *
 * As of still a Long Time Ago (2015/5/7) we used approx 800k for skiboot,
 * 500k HEAP for mambo boot.
 *
 * As of mid-2019, a 2 socket Romulus uses ~4MB heap.
 */
#define HEAP_BASE		(SKIBOOT_BASE + 0x00600000)
#define HEAP_SIZE		0x00a00000

/* This is the location of our console buffer at base + 16M */
#define INMEM_CON_START		(SKIBOOT_BASE + 0x01000000)
#define INMEM_CON_LEN  		0x100000

/* This is the location of HBRT console buffer at base + 17M */
#define HBRT_CON_START		(SKIBOOT_BASE + 0x01100000)
#define HBRT_CON_LEN  		0x100000

/* Tell FSP to put the init data at base + 20M, allocate 8M */
#define SPIRA_HEAP_BASE		(SKIBOOT_BASE + 0x01200000)
#define SPIRA_HEAP_SIZE		0x00800000

/* This is our PSI TCE table. It's 256K entries on P8 */
#define PSI_TCE_TABLE_BASE	(SKIBOOT_BASE + 0x01a00000)
#define PSI_TCE_TABLE_SIZE	0x00200000UL

/* This is our dump result table after MPIPL. Hostboot will write to this
 * memory after moving memory content from source to destination memory.
 */
#define MDRT_TABLE_BASE		(SKIBOOT_BASE + 0x01c00000)
#define MDRT_TABLE_SIZE		0x00008000

/* This is our dump metadata area. We will use this memory to save metadata
 * (like crashing CPU details, payload tags) before triggering MPIPL.
 */
#define DUMP_METADATA_AREA_BASE	(SKIBOOT_BASE + 0x01c08000)
#define DUMP_METADATA_AREA_SIZE	0x8000

/* Total size of the above area
 *
 * (Ensure this has at least a 64k alignment)
 */
#define SKIBOOT_SIZE		0x01c10000

/* We start laying out the CPU stacks from here, indexed by PIR
 * each stack is STACK_SIZE in size (naturally aligned power of
 * two) and the bottom of the stack contains the cpu thread
 * structure for the processor, so it can be obtained by a simple
 * bit mask from the stack pointer. Within the CPU stack is divided
 * into a normal and emergency stack to cope with a single level of
 * re-entrancy.
 *
 * The size of this array is dynamically determined at boot time
 */
#define CPU_STACKS_BASE		(SKIBOOT_BASE + SKIBOOT_SIZE)

/*
 * Address at which we load the kernel LID. This is also where
 * we expect a passed-in kernel if booting without FSP and
 * without a built-in kernel.
 */
#define KERNEL_LOAD_BASE	((void *)0x20000000)
#define KERNEL_LOAD_SIZE	0x08000000

#define INITRAMFS_LOAD_BASE	KERNEL_LOAD_BASE + KERNEL_LOAD_SIZE
#define INITRAMFS_LOAD_SIZE	0x08000000

/* Size allocated to build the device-tree */
#define	DEVICE_TREE_MAX_SIZE	0x80000


#endif /* __MEM_MAP_H */
