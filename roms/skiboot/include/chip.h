// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#ifndef __CHIP_H
#define __CHIP_H

#include <stdint.h>
#include <lock.h>

#include <ccan/list/list.h>

/*
 * Note on chip IDs:
 *
 * We carry a "chip_id" around, in the cpu_thread, but also as
 * ibm,chip-id properties.
 *
 * This ID is the HW fabric ID of a chip based on the XSCOM numbering,
 * also known as "GCID" (Global Chip ID).
 *
 * The format of this number is different between chip generations and care must
 * be taken when trying to convert between this chip ID and some other
 * representation such as PIR values, interrupt-server numbers etc... :
 *
 */

/*
 * P8 GCID
 * -------
 *
 * Global chip ID is a 6 bit number:
 *
 *     NodeID      ChipID
 * |           |           |
 * |___|___|___|___|___|___|
 *
 * The the ChipID is 3 bits long, the GCID is the same as the high bits of PIR
 */
#define P8_PIR2GCID(pir) (((pir) >> 7) & 0x3f)

#define P8_PIR2COREID(pir) (((pir) >> 3) & 0xf)

#define P8_PIR2THREADID(pir) ((pir) & 0x7)

/*
 * P9 GCID
 * -------
 *
 * Global chip ID is a 7 bit number:
 *
 *        NodeID      ChipID
 * |               |           |
 * |___|___|___|___|___|___|___|
 *
 * Bit 56 is unused according to the manual by we add it to the coreid here,
 * thus we have a 6-bit core number.
 *
 * Note: XIVE Only supports 4-bit chip numbers ...
 *
 * Upper PIR Bits
 * --------------
 *
 * Normal-Core Mode:
 * 57:61 CoreID
 * 62:63 ThreadID
 *
 * Fused-Core Mode:
 * 57:59 FusedQuadID
 * 60    FusedCoreID
 * 61:63 FusedThreadID
 *
 * FusedCoreID 0 contains normal-core chiplet 0 and 1
 * FusedCoreID 1 contains normal-core chiplet 2 and 3
 *
 * Fused cores have interleaved threads:
 * core chiplet 0/2 = t0, t2, t4, t6
 * core chiplet 1/3 = t1, t3, t5, t7
 *
 */
#define P9_PIR2GCID(pir) (((pir) >> 8) & 0x7f)

#define P9_PIR2COREID(pir) (((pir) >> 2) & 0x3f)

#define P9_PIR2THREADID(pir) ((pir) & 0x3)

#define P9_GCID2NODEID(gcid)	(((gcid) >> 3) & 0xf)

#define P9_GCID2CHIPID(gcid) ((gcid) & 0x7)

#define P9_PIR2FUSEDQUADID(pir) (((pir) >> 4) & 0x7)

#define P9_PIR2FUSEDCOREID(pir) (((pir) >> 3) & 0x1)

#define P9_PIR2FUSEDTHREADID(pir) ((pir) & 0x7)

#define P9_PIRFUSED2NORMALCOREID(pir) \
	(P9_PIR2FUSEDQUADID(pir) << 2) | \
	(P9_PIR2FUSEDCOREID(pir) << 1) | \
	(P9_PIR2FUSEDTHREADID(pir) & 1)

#define P9_PIRFUSED2NORMALTHREADID(pir) (((pir) >> 1) & 0x3)

#define P10_PIR2FUSEDCOREID(pir) P9_PIR2FUSEDCOREID(pir)
#define P10_PIRFUSED2NORMALCOREID(pir) P9_PIRFUSED2NORMALCOREID(pir)
#define P10_PIRFUSED2NORMALTHREADID(pir) P9_PIRFUSED2NORMALTHREADID(pir)

/* P9 specific ones mostly used by XIVE */
#define P9_PIR2LOCALCPU(pir) ((pir) & 0xff)
#define P9_PIRFROMLOCALCPU(chip, cpu)	(((chip) << 8) | (cpu))

/*
 * P10 PIR
 * -------
 *
 * PIR layout:
 *
 * |  49|  50|  51|  52|  53|  54|  55|  56|  57|  58|  59|  60|  61|  62|  63|
 * |Spare ID      |Topology ID        |Sp. |Quad ID       |Core ID  |Thread ID|
 *
 * Bit 56 is a spare quad ID. In big-core mode, thread ID extends to bit 61.
 *
 * P10 GCID
 * --------
 *
 * - Global chip ID is also called Topology ID.
 * - Node ID is called Group ID (? XXX P10).
 *
 * Global chip ID is a 4 bit number.
 *
 * There is a topology mode bit that can be 0 or 1, which changes GCID mapping.
 *
 * Topology mode 0:
 *      NodeID    ChipID
 * |              |    |
 * |____|____|____|____|
 *
 * Topology mode 1:
 *    NodeID    ChipID
 * |         |         |
 * |____|____|____|____|
 */
#define P10_PIR2GCID(pir) (((pir) >> 8) & 0xf)

#define P10_PIR2COREID(pir) (((pir) >> 2) & 0x3f)

#define P10_PIR2THREADID(pir) ((pir) & 0x3)

// XXX P10 These depend on the topology mode, how to get that (system type?)
#define P10_GCID2NODEID(gcid, mode) ((mode) == 0 ? ((gcid) >> 1) & 0x7 : ((gcid) >> 2) & 0x3)
#define P10_GCID2CHIPID(gcid, mode) ((mode) == 0 ? (gcid) & 0x1 : (gcid) & 0x3)

/* P10 specific ones mostly used by XIVE */
#define P10_PIR2LOCALCPU(pir) ((pir) & 0xff)
#define P10_PIRFROMLOCALCPU(chip, cpu)	(((chip) << 8) | (cpu))

struct dt_node;
struct centaur_chip;
struct mfsi;
struct xive;
struct lpcm;
struct vas;
struct p9_sbe;
struct p9_dio;

/* Chip type */
enum proc_chip_type {
	PROC_CHIP_UNKNOWN,
	PROC_CHIP_P8_MURANO,
	PROC_CHIP_P8_VENICE,
	PROC_CHIP_P8_NAPLES,
	PROC_CHIP_P9_NIMBUS,
	PROC_CHIP_P9_CUMULUS,
	PROC_CHIP_P9P,
	PROC_CHIP_P10,
};

/* Simulator quirks */
enum proc_chip_quirks {
	QUIRK_NO_CHIPTOD	= 0x00000001,
	QUIRK_MAMBO_CALLOUTS	= 0x00000002,
	QUIRK_NO_F000F		= 0x00000004,
	QUIRK_NO_PBA		= 0x00000008,
	QUIRK_NO_OCC_IRQ       	= 0x00000010,
	QUIRK_SIMICS		= 0x00000020,
	QUIRK_SLOW_SIM		= 0x00000040,
	QUIRK_NO_DIRECT_CTL	= 0x00000080,
	QUIRK_NO_RNG		= 0x00000100,
	QUIRK_QEMU              = 0x00000200,
	QUIRK_AWAN		= 0x00000400,
};

extern enum proc_chip_quirks proc_chip_quirks;

static inline bool chip_quirk(unsigned int q)
{
	return !!(proc_chip_quirks & q);
}

#define MAX_CHIPS	(1 << 6)	/* 6-bit chip ID */

/*
 * For each chip in the system, we maintain this structure
 *
 * This contains fields used by different modules including
 * modules in hw/ but is handy to keep per-chip data
 */
struct proc_chip {
	uint32_t		id;		/* HW Chip ID (GCID) */
	struct dt_node		*devnode;	/* "xscom" chip node */

	/* These are only initialized after xcom_init */
	enum proc_chip_type	type;
	uint32_t		ec_level;	/* 0xMm (DD1.0 = 0x10) */
	uint8_t                 ec_rev;		/* sub-revision */

	/* Those two values are only populated on machines with an FSP
	 * dbob_id = Drawer/Block/Octant/Blade (DBOBID)
	 * pcid    = HDAT processor_chip_id
	 */
	uint32_t		dbob_id;
	uint32_t		pcid;

	/* If we expect to have an OCC (i.e. P8) and it is functional,
	 * set TRUE. If something has told us it is not, set FALSE and
	 * we can not wait for OCCs to init. This is only going to be
	 * FALSE in a simulator that doesn't simulate OCCs. */
	bool			occ_functional;

	/* Used by hw/xscom.c */
	uint64_t		xscom_base;

	/* Used by hw/lpc.c */
	struct lpcm		*lpc;

	/* Used by hw/slw.c */
	uint64_t		slw_base;
	uint64_t		slw_bar_size;
	uint64_t		slw_image_size;

	/* Used by hw/homer.c */
	uint64_t		homer_base;
	uint64_t		homer_size;
	uint64_t		occ_common_base;
	uint64_t		occ_common_size;
	uint8_t			throttle;

	/* Must hold capi_lock to change */
	uint8_t			capp_phb3_attached_mask;
	uint8_t			capp_ucode_loaded;

	/* Used by hw/centaur.c */
	struct centaur_chip	*centaurs;

	/* Used by hw/p8-i2c.c */
	struct list_head	i2cms;

	/* Used by hw/psi.c */
	struct psi		*psi;

	/* Used by hw/fsi-master.c */
	struct mfsi		*fsi_masters;

	/* Used by hw/xive.c */
	struct xive		*xive;

	struct vas		*vas;

	/* Used by hw/nx-compress.c */
	uint64_t		nx_base;
	/* location code of this chip */
	const uint8_t		*loc_code;

	/* Used by hw/sbe-p9.c */
	struct p9_sbe		*sbe;

	/* Used by hw/dio-p9.c */
	struct p9_dio		*dio;

	/* Used during OCC init */
	bool			ex_present;

	/* Used by hw/vas.c on p10 */
	uint32_t		primary_topology;
};

extern uint32_t pir_to_chip_id(uint32_t pir);

/*
 * Note: In P9 fused-core mode, these will return the "normal"
 * core ID and thread ID (ie, thread ID 0..3)
 */
extern uint32_t pir_to_core_id(uint32_t pir);
extern uint32_t pir_to_thread_id(uint32_t pir);

/* In P9 fused core mode, this is the "fused" core ID, in
 * normal core mode or P8, this is the same as pir_to_core_id
 */
extern uint32_t pir_to_fused_core_id(uint32_t pir);

extern struct proc_chip *next_chip(struct proc_chip *chip);

#define for_each_chip(__c) for (__c=next_chip(NULL); __c; __c=next_chip(__c))

extern struct proc_chip *get_chip(uint32_t chip_id);

extern void init_chips(void);

/* helper to get number of chips in the system */
static inline int nr_chips(void)
{
	struct proc_chip *chip;
	int nr_chips = 0;

	for_each_chip(chip)
		nr_chips++;

	return nr_chips;
}

/* helper to get location code of a chip */
static inline const char *chip_loc_code(uint32_t chip_id)
{
	struct proc_chip *chip;

	chip = get_chip(chip_id);
	if (!chip)
		return NULL;

	return chip->loc_code;
}

#endif /* __CHIP_H */

