// SPDX-License-Identifier: Apache-2.0
/*
 * XIVE2: eXternal Interrupt Virtualization Engine. POWER10 interrupt
 * controller
 *
 * Copyright (c) 2016-2019, IBM Corporation.
 */

#define pr_fmt(fmt) "XIVE: " fmt

#include <skiboot.h>
#include <xscom.h>
#include <chip.h>
#include <io.h>
#include <xive.h>
#include <xive2-regs.h>
#include <xscom-p10-regs.h>
#include <interrupts.h>
#include <timebase.h>
#include <bitmap.h>
#include <buddy.h>
#include <phys-map.h>
#include <p10_stop_api.H>


/* Verbose debug */
#undef XIVE_VERBOSE_DEBUG
#undef DEBUG

/* Extra debug options used in debug builds */
#ifdef DEBUG
#define XIVE_CHECK_LOCKS
#define XIVE_DEBUG_INIT_CACHE_UPDATES
#define XIVE_EXTRA_CHECK_INIT_CACHE
#else
#undef  XIVE_CHECK_LOCKS
#undef  XIVE_DEBUG_INIT_CACHE_UPDATES
#undef  XIVE_EXTRA_CHECK_INIT_CACHE
#endif

/*
 * VSDs, blocks, set translation etc...
 *
 * For the following data structures, the XIVE use a mechanism called
 * Virtualization Structure Tables (VST) to manage the memory layout
 * and access: ESBs (Event State Buffers), EAS (Event assignment
 * structures), ENDs (Event Notification Descriptors) and NVT/NVP
 * (Notification Virtual Targets/Processors).
 *
 * These structures divide those tables into 16 "blocks". Each XIVE
 * instance has a definition for all 16 blocks that can either represent
 * an actual table in memory or a remote XIVE MMIO port to access a
 * block that is owned by that remote XIVE.
 *
 * Our SW design will consist of allocating one block per chip (and thus
 * per XIVE instance) for now, thus giving us up to 16 supported chips in
 * the system. We may have to revisit that if we ever support systems with
 * more than 16 chips but that isn't on our radar at the moment or if we
 * want to do like pHyp on some machines and dedicate 2 blocks per chip
 * for some structures.
 *
 * Thus we need to be careful that we never expose to Linux the concept
 * of block and block boundaries, but instead we provide full number ranges
 * so that consecutive blocks can be supported.
 *
 * Similarily, for MMIO access, the BARs support what is called "set
 * translation" which allows the BAR to be devided into a certain
 * number of sets. Each "set" can be routed to a specific block and
 * offset within a block.
 */

#define XIVE_MAX_BLOCKS		16
#define XIVE_VSD_SIZE		8

/*
 * Max number of ESBs. (direct table)
 *
 * The max number of ESBs supported in the P10 MMIO space is 1TB/128K: 8M.
 *
 * 1M is our current top limit of ESB entries and EAS entries
 * pre-allocated per chip. That allocates 256KB per chip for the state
 * bits and 8M per chip for the EAS.
 */

#define XIVE_INT_ORDER		20 /* 1M interrupts */
#define XIVE_INT_COUNT		(1ul << XIVE_INT_ORDER)

/*
 * First interrupt number, also the first logical interrupt number
 * allocated by Linux (maximum ISA interrupt number + 1)
 */
#define XIVE_INT_FIRST		0x10

/* Corresponding direct table sizes */
#define XIVE_ESB_SIZE		(XIVE_INT_COUNT / 4)
#define XIVE_EAT_SIZE		(XIVE_INT_COUNT * 8)

/* Use 64K for everything by default */
#define XIVE_ESB_SHIFT		(16 + 1) /* trigger + mgmt pages */
#define XIVE_ESB_PAGE_SIZE     (1ul << XIVE_ESB_SHIFT) /* 2 pages */

/*
 * Max number of ENDs. (indirect table)
 *
 * The max number of ENDs supported in the P10 MMIO space is 2TB/128K: 16M.
 * Since one END is 32 bytes, a 64K indirect subpage can hold 2K ENDs.
 * We need 8192 subpages, ie, 64K of memory for the indirect table.
 */
#define END_PER_PAGE		(PAGE_SIZE / sizeof(struct xive_end))

#define XIVE_END_ORDER		23 /* 8M ENDs */
#define XIVE_END_COUNT		(1ul << XIVE_END_ORDER)
#define XIVE_END_TABLE_SIZE	((XIVE_END_COUNT / END_PER_PAGE) * XIVE_VSD_SIZE)

#define XIVE_END_SHIFT		(16 + 1) /* ESn + ESe pages */

/* One bit per number of priorities configured */
#define xive_end_bitmap_size(x)	(XIVE_END_COUNT >> xive_cfg_vp_prio_shift(x))

/* Number of priorities (and thus ENDs) we allocate for each VP */
#define xive_cfg_vp_prio_shift(x) GETFIELD(CQ_XIVE_CFG_VP_INT_PRIO, (x)->config)
#define xive_cfg_vp_prio(x)	(1 << xive_cfg_vp_prio_shift(x))

/* Max priority number */
#define xive_max_prio(x)	(xive_cfg_vp_prio(x) - 1)

/* Priority used for gather/silent escalation (KVM) */
#define xive_escalation_prio(x)	xive_max_prio(x)

/*
 * Max number of VPs. (indirect table)
 *
 * The max number of NVPs we support in our MMIO space is 1TB/128K: 8M.
 * Since one NVP is 32 bytes, a 64K indirect subpage can hold 2K NVPs.
 * We need 4096 pointers, ie, 32K of memory for the indirect table.
 *
 * However, we use 8 priorities (by default) per NVP and the number of
 * ENDs is configured to 8M. Therefore, our VP space is limited to 1M.
 */
#define VP_PER_PAGE		(PAGE_SIZE / sizeof(struct xive_nvp))

#define XIVE_VP_ORDER(x)	(XIVE_END_ORDER - xive_cfg_vp_prio_shift(x))
#define XIVE_VP_COUNT(x)	(1ul << XIVE_VP_ORDER(x))
#define XIVE_VP_TABLE_SIZE(x)	((XIVE_VP_COUNT(x) / VP_PER_PAGE) * XIVE_VSD_SIZE)

#define XIVE_NVP_SHIFT		17 /* NVPG BAR: two pages, even NVP, odd NVG */

/* VP Space maximums in Gen1 and Gen2 modes */
#define VP_SHIFT_GEN1		19	/* in sync with END_W6_VP_OFFSET_GEN1 */
#define VP_SHIFT_GEN2		24	/* in sync with END_W6_VP_OFFSET */

/*
 * VP ids for HW threads.
 *
 * Depends on the thread id bits configuration of the IC. 8bit is the
 * default for P10 and 7bit for p9.
 *
 * These values are global because they should be common to all chips
 */
static uint32_t xive_threadid_shift;
static uint32_t	xive_hw_vp_base;
static uint32_t xive_hw_vp_count;

/*
 * The XIVE operation mode indicates the active "API" and corresponds
 * to the "version/mode" parameter of the opal_xive_reset() call
 */
static enum {
	/* No XICS emulation */
	XIVE_MODE_EXPL	= OPAL_XIVE_MODE_EXPL, /* default */
	XIVE_MODE_NONE,
} xive_mode = XIVE_MODE_NONE;

/*
 * The XIVE exploitation mode options indicates the active features and
 * is part of the mode parameter of the opal_xive_reset() call
 */
static uint64_t xive_expl_options;

#define XIVE_EXPL_ALL_OPTIONS 0

/*
 * Each source controller has one of these. There's one embedded in
 * the XIVE struct for IPIs
 */
struct xive_src {
	struct irq_source		is;
	const struct irq_source_ops	*orig_ops;
	struct xive			*xive;
	void				*esb_mmio;
	uint32_t			esb_base;
	uint32_t			esb_shift;
	uint32_t			flags;
};

struct xive_cpu_state {
	struct xive	*xive;
	void		*tm_ring1;

	/* Base HW VP and associated queues */
	uint32_t	vp_blk;
	uint32_t	vp_idx;
	uint32_t	end_blk;
	uint32_t	end_idx; /* Base end index of a block of 8 */

	struct lock	lock;
};

enum xive_generation {
	XIVE_GEN1 = 1, /* P9 compat mode */
	XIVE_GEN2 = 2, /* P10 default */
};

enum xive_quirks {
	/* HW527671 - 8bits Hardwired Thread Id range not implemented */
	XIVE_QUIRK_THREADID_7BITS	= 0x00000001,
	/* HW542974 - interrupt command priority checker not working properly */
	XIVE_QUIRK_BROKEN_PRIO_CHECK	= 0x00000002,
};

struct xive {
	uint32_t		 chip_id;
	uint32_t		 block_id;
	struct dt_node		*x_node;

	enum xive_generation	 generation;
	uint64_t		 capabilities;
	uint64_t		 config;

	uint64_t		 xscom_base;

	/* MMIO regions */
	void			*ic_base;
	uint64_t		 ic_size;
	uint32_t		 ic_shift;
	void			*ic_tm_direct_base;

	void			*tm_base;
	uint64_t		 tm_size;
	uint32_t		 tm_shift;
	void			*nvp_base;
	uint64_t		 nvp_size;
	void			*esb_base;
	uint64_t		 esb_size;
	void			*end_base;
	uint64_t		 end_size;

	/* Set on XSCOM register access error */
	bool			 last_reg_error;

	/* Per-XIVE mutex */
	struct lock		 lock;

	/* Pre-allocated tables.
	 *
	 * We setup all the VDS for actual tables (ie, by opposition to
	 * forwarding ports) as either direct pre-allocated or indirect
	 * and partially populated.
	 *
	 * Currently, the ESB and the EAS tables are direct and fully
	 * pre-allocated based on XIVE_INT_COUNT.
	 *
	 * The other tables are indirect, we thus pre-allocate the indirect
	 * table (ie, pages of pointers) and populate enough of the pages
	 * for our basic setup using 64K subpages.
	 *
	 * The size of the indirect tables are driven by XIVE_VP_COUNT
	 * and XIVE_END_COUNT. The number of pre-allocated ones are
	 * driven by xive_hw_vp_count for the HW threads. The number
	 * of END depends on number of VP.
	 */

	/* Direct SBE and EAT tables */
	void			*sbe_base;
	void			*eat_base;

	/* Indirect END table. NULL entries are unallocated, count is
	 * the numbre of pointers (ie, sub page placeholders).
	 */
	beint64_t		*end_ind_base;
	uint32_t		 end_ind_count;
	uint64_t 		 end_ind_size;

	/* END allocation bitmap. Each bit represent #priority ENDs */
	bitmap_t		*end_map;

	/* Indirect NVT/VP table. NULL entries are unallocated, count is
	 * the numbre of pointers (ie, sub page placeholders).
	 */
	beint64_t		*vp_ind_base;
	uint32_t		 vp_ind_count;
	uint64_t 		 vp_ind_size;

	/* VP space size. Depends on Gen1/2 mode */
	uint32_t		 vp_shift;

	/* Pool of donated pages for provisioning indirect END and VP pages */
	struct list_head	 donated_pages;

	/* To ease a possible change to supporting more than one block of
	 * interrupts per chip, we store here the "base" global number
	 * and max number of interrupts for this chip. The global number
	 * encompass the block number and index.
	 */
	uint32_t		 int_base;
	uint32_t		 int_count;

	/* Due to the overlap between IPIs and HW sources in the EAS table,
	 * we keep some kind of top-down allocator. It is used for HW sources
	 * to "allocate" interrupt entries and will limit what can be handed
	 * out as IPIs. Of course this assumes we "allocate" all HW sources
	 * before we start handing out IPIs.
	 *
	 * Note: The numbers here are global interrupt numbers so that we can
	 * potentially handle more than one block per chip in the future.
	 */
	uint32_t		 int_hw_bot;	/* Bottom of HW allocation */
	uint32_t		 int_ipi_top;	/* Highest IPI handed out so far + 1 */

	/* The IPI allocation bitmap */
	bitmap_t		*ipi_alloc_map;

	/* We keep track of which interrupts were ever enabled to
	 * speed up xive_reset
	 */
	bitmap_t		*int_enabled_map;

	/* Embedded source IPIs */
	struct xive_src		 ipis;

	/* Embedded escalation interrupts */
	struct xive_src		 esc_irqs;

	/* In memory queue overflow */
	void			*q_ovf;

	/* Cache/sync injection */
	uint64_t		 sync_inject_size;
	void			*sync_inject;

	/* INT HW Errata */
	uint64_t		quirks;
};

/* First XIVE unit configured on the system */
static struct xive *one_xive;

/* Global DT node */
static struct dt_node *xive_dt_node;

/* Block <-> Chip conversions.
 *
 * As chipIDs may not be within the range of 16 block IDs supported by XIVE,
 * we have a 2 way conversion scheme.
 *
 * From block to chip, use the global table below.
 *
 * From chip to block, a field in struct proc_chip contains the first block
 * of that chip. For now we only support one block per chip but that might
 * change in the future
 */
#define XIVE_INVALID_CHIP	0xffffffff
#define XIVE_MAX_CHIPS		16
static uint32_t xive_block_to_chip[XIVE_MAX_CHIPS];
static uint32_t xive_block_count;

static uint32_t xive_chip_to_block(uint32_t chip_id)
{
	struct proc_chip *c = get_chip(chip_id);

	assert(c);
	assert(c->xive);
	return c->xive->block_id;
}

/*
 * Conversion between GIRQ and block/index.
 *
 * ------------------------------------
 * |000E|BLOC|                   INDEX|
 * ------------------------------------
 *   4     4           24
 *
 * the E bit indicates that this is an escalation interrupt, in
 * that case, the BLOC/INDEX represents the END containing the
 * corresponding escalation descriptor.
 *
 * Global interrupt numbers for non-escalation interrupts are thus
 * limited to 28 bits.
 */

#define INT_SHIFT		24
#define INT_ESC_SHIFT		(INT_SHIFT + 4) /* 4bits block id */

#if XIVE_INT_ORDER > INT_SHIFT
#error "Too many ESBs for IRQ encoding"
#endif

#if XIVE_END_ORDER > INT_SHIFT
#error "Too many ENDs for escalation IRQ number encoding"
#endif

#define GIRQ_TO_BLK(__g)	(((__g) >> INT_SHIFT) & 0xf)
#define GIRQ_TO_IDX(__g)	((__g) & ((1 << INT_SHIFT) - 1))
#define BLKIDX_TO_GIRQ(__b,__i)	(((uint32_t)(__b)) << INT_SHIFT | (__i))

#define GIRQ_IS_ESCALATION(__g)	((__g) & (1 << INT_ESC_SHIFT))
#define MAKE_ESCALATION_GIRQ(__b,__i)(BLKIDX_TO_GIRQ(__b,__i) | (1 << INT_ESC_SHIFT))


/* Block/IRQ to chip# conversions */
#define PC_BLK_TO_CHIP(__b)	(xive_block_to_chip[__b])
#define VC_BLK_TO_CHIP(__b)	(xive_block_to_chip[__b])
#define GIRQ_TO_CHIP(__isn)	(VC_BLK_TO_CHIP(GIRQ_TO_BLK(__isn)))

/* Routing of physical processors to VPs */
#define PIR2VP_IDX( __pir)	(xive_hw_vp_base | P10_PIR2LOCALCPU(__pir))
#define PIR2VP_BLK(__pir)	(xive_chip_to_block(P10_PIR2GCID(__pir)))
#define VP2PIR(__blk, __idx)	(P10_PIRFROMLOCALCPU(VC_BLK_TO_CHIP(__blk), (__idx) & 0xff))

/* Decoding of OPAL API VP IDs. The VP IDs are encoded as follow
 *
 * Block group mode:
 *
 * -----------------------------------
 * |GVEOOOOO|                   INDEX|
 * -----------------------------------
 *  ||   |
 *  ||  Order
 *  |Virtual
 *  Group
 *
 * G (Group)   : Set to 1 for a group VP (not currently supported)
 * V (Virtual) : Set to 1 for an allocated VP (vs. a physical processor ID)
 * E (Error)   : Should never be 1, used internally for errors
 * O (Order)   : Allocation order of the VP block
 *
 * The conversion is thus done as follow (groups aren't implemented yet)
 *
 *  If V=0, O must be 0 and 24-bit INDEX value is the PIR
 *  If V=1, the order O group is allocated such that if N is the number of
 *          chip bits considered for allocation (*)
 *          then the INDEX is constructed as follow (bit numbers such as 0=LSB)
 *           - bottom O-N bits is the index within the "VP block"
 *           - next N bits is the XIVE blockID of the VP
 *           - the remaining bits is the per-chip "base"
 *          so the conversion consists of "extracting" the block ID and moving
 *          down the upper bits by N bits.
 *
 * In non-block-group mode, the difference is that the blockID is
 * on the left of the index (the entire VP block is in a single
 * block ID)
 */

#define VP_GROUP_SHIFT		31
#define VP_VIRTUAL_SHIFT	30
#define VP_ERROR_SHIFT		29
#define VP_ORDER_SHIFT		24

#define vp_group(vp)		(((vp) >> VP_GROUP_SHIFT) & 1)
#define vp_virtual(vp) 		(((vp) >> VP_VIRTUAL_SHIFT) & 1)
#define vp_order(vp)		(((vp) >> VP_ORDER_SHIFT) & 0x1f)
#define vp_index(vp)		((vp) & ((1 << VP_ORDER_SHIFT) - 1))

/* VP allocation */
static uint32_t xive_chips_alloc_bits = 0;
static struct buddy *xive_vp_buddy;
static struct lock xive_buddy_lock = LOCK_UNLOCKED;

/* VP# decoding/encoding */
static bool xive_decode_vp(uint32_t vp, uint32_t *blk, uint32_t *idx,
			   uint8_t *order, bool *group)
{
	uint32_t o = vp_order(vp);
	uint32_t n = xive_chips_alloc_bits;
	uint32_t index = vp_index(vp);
	uint32_t imask = (1 << (o - n)) - 1;

	/* Groups not supported yet */
	if (vp_group(vp))
		return false;
	if (group)
		*group = false;

	/* PIR case */
	if (!vp_virtual(vp)) {
		if (find_cpu_by_pir(index) == NULL)
			return false;
		if (blk)
			*blk = PIR2VP_BLK(index);
		if (idx)
			*idx = PIR2VP_IDX(index);
		return true;
	}

	/* Ensure o > n, we have *at least* 2 VPs per block */
	if (o <= n)
		return false;

	/* Combine the index base and index */
	if (idx)
		*idx = ((index >> n) & ~imask) | (index & imask);
	/* Extract block ID */
	if (blk)
		*blk = (index >> (o - n)) & ((1 << n) - 1);

	/* Return order as well if asked for */
	if (order)
		*order = o;

	return true;
}

static uint32_t xive_encode_vp(uint32_t blk, uint32_t idx, uint32_t order)
{
	uint32_t vp = (1 << VP_VIRTUAL_SHIFT) | (order << VP_ORDER_SHIFT);
	uint32_t n = xive_chips_alloc_bits;
	uint32_t imask = (1 << (order - n)) - 1;

	vp |= (idx & ~imask) << n;
	vp |= blk << (order - n);
	vp |= idx & imask;
	return  vp;
}

/*
 * XSCOM/MMIO helpers
 */
#define XIVE_NO_MMIO -1

#define xive_regw(__x, __r, __v) \
	__xive_regw(__x, __r, X_##__r, __v, #__r)
#define xive_regr(__x, __r) \
	__xive_regr(__x, __r, X_##__r, #__r)
#define xive_regwx(__x, __r, __v) \
	__xive_regw(__x, XIVE_NO_MMIO, X_##__r, __v, #__r)
#define xive_regrx(__x, __r) \
	__xive_regr(__x, XIVE_NO_MMIO, X_##__r, #__r)

#ifdef XIVE_VERBOSE_DEBUG
#define xive_vdbg(__x,__fmt,...)	prlog(PR_DEBUG,"[ IC %02x  ] " __fmt, (__x)->chip_id, ##__VA_ARGS__)
#define xive_cpu_vdbg(__c,__fmt,...)	prlog(PR_DEBUG,"[CPU %04x] " __fmt, (__c)->pir, ##__VA_ARGS__)
#else
#define xive_vdbg(x,fmt,...)		do { } while(0)
#define xive_cpu_vdbg(x,fmt,...)	do { } while(0)
#endif

#define xive_dbg(__x,__fmt,...)		prlog(PR_DEBUG,"[ IC %02x  ] " __fmt, (__x)->chip_id, ##__VA_ARGS__)
#define xive_cpu_dbg(__c,__fmt,...)	prlog(PR_DEBUG,"[CPU %04x] " __fmt, (__c)->pir, ##__VA_ARGS__)
#define xive_notice(__x,__fmt,...)	prlog(PR_NOTICE,"[ IC %02x  ] " __fmt, (__x)->chip_id, ##__VA_ARGS__)
#define xive_cpu_notice(__c,__fmt,...)	prlog(PR_NOTICE,"[CPU %04x] " __fmt, (__c)->pir, ##__VA_ARGS__)
#define xive_warn(__x,__fmt,...)	prlog(PR_WARNING,"[ IC %02x  ] " __fmt, (__x)->chip_id, ##__VA_ARGS__)
#define xive_cpu_warn(__c,__fmt,...)	prlog(PR_WARNING,"[CPU %04x] " __fmt, (__c)->pir, ##__VA_ARGS__)
#define xive_err(__x,__fmt,...)		prlog(PR_ERR,"[ IC %02x  ] " __fmt, (__x)->chip_id, ##__VA_ARGS__)
#define xive_cpu_err(__c,__fmt,...)	prlog(PR_ERR,"[CPU %04x] " __fmt, (__c)->pir, ##__VA_ARGS__)

/*
 * The XIVE subengine being accessed can be deduced from the XSCOM
 * reg, and from there, the page offset in the IC BAR.
 */
static void* xive_ic_page(struct xive *x, uint32_t x_reg)
{
	uint64_t pgoff = (x_reg >> 8) & 0x3;

	return x->ic_base + (pgoff << x->ic_shift);
}

static void __xive_regw(struct xive *x, uint32_t m_reg, uint32_t x_reg, uint64_t v,
			const char *rname)
{
	bool use_xscom = (m_reg == XIVE_NO_MMIO) || !x->ic_base;
	int64_t rc;

	x->last_reg_error = false;

	assert(x_reg != 0);

	if (use_xscom) {
		rc = xscom_write(x->chip_id, x->xscom_base + x_reg, v);
		if (rc) {
			if (!rname)
				rname = "???";
			xive_err(x, "Error writing register %s\n", rname);
			/* Anything else we can do here ? */
			x->last_reg_error = true;
		}
	} else {
		out_be64(xive_ic_page(x, x_reg) + m_reg, v);
	}
}

static uint64_t __xive_regr(struct xive *x, uint32_t m_reg, uint32_t x_reg,
			    const char *rname)
{
	bool use_xscom = (m_reg == XIVE_NO_MMIO) || !x->ic_base;
	int64_t rc;
	uint64_t val;

	x->last_reg_error = false;

	assert(x_reg != 0);

	if (use_xscom) {
		rc = xscom_read(x->chip_id, x->xscom_base + x_reg, &val);
		if (rc) {
			if (!rname)
				rname = "???";
			xive_err(x, "Error reading register %s\n", rname);
			/* Anything else we can do here ? */
			x->last_reg_error = true;
			return -1ull;
		}
	} else {
		val = in_be64(xive_ic_page(x, x_reg) + m_reg);
	}
	return val;
}

/* Locate a controller from an IRQ number */
static struct xive *xive_from_isn(uint32_t isn)
{
	uint32_t chip_id = GIRQ_TO_CHIP(isn);
	struct proc_chip *c = get_chip(chip_id);

	if (!c)
		return NULL;
	return c->xive;
}

static struct xive *xive_from_pc_blk(uint32_t blk)
{
	uint32_t chip_id = PC_BLK_TO_CHIP(blk);
	struct proc_chip *c = get_chip(chip_id);

	if (!c)
		return NULL;
	return c->xive;
}

static struct xive *xive_from_vc_blk(uint32_t blk)
{
	uint32_t chip_id = VC_BLK_TO_CHIP(blk);
	struct proc_chip *c = get_chip(chip_id);

	if (!c)
		return NULL;
	return c->xive;
}

static struct xive_end *xive_get_end(struct xive *x, unsigned int idx)
{
	struct xive_end *p;

	if (idx >= (x->end_ind_count * END_PER_PAGE))
		return NULL;
	p = (struct xive_end *)(be64_to_cpu(x->end_ind_base[idx / END_PER_PAGE]) &
			       VSD_ADDRESS_MASK);
	if (!p)
		return NULL;

	return &p[idx % END_PER_PAGE];
}

static struct xive_eas *xive_get_eas(struct xive *x, unsigned int isn)
{
	struct xive_eas *eat;
	uint32_t idx = GIRQ_TO_IDX(isn);

	if (GIRQ_IS_ESCALATION(isn)) {
		/* Allright, an escalation EAS is buried inside an END, let's
		 * try to find it
		 */
		struct xive_end *end;

		if (x->chip_id != VC_BLK_TO_CHIP(GIRQ_TO_BLK(isn))) {
			xive_err(x, "%s, ESC ISN 0x%x not on right chip\n",
				 __func__, isn);
			return NULL;
		}
		end = xive_get_end(x, idx);
		if (!end) {
			xive_err(x, "%s, ESC ISN 0x%x END not found\n",
				 __func__, isn);
			return NULL;
		}

		/* If using single-escalation, don't let anybody get
		 * to the individual escalation interrupts
		 */
		if (xive_get_field32(END_W0_UNCOND_ESCALATE, end->w0))
			return NULL;

		/* Grab the escalation END */
		return (struct xive_eas *)(char *)&end->w4;
	} else {
		/* Check the block matches */
		if (isn < x->int_base || isn >= x->int_count) {
			xive_err(x, "%s, ISN 0x%x not on right chip\n",
				 __func__, isn);
			return NULL;
		}
		assert (idx < XIVE_INT_COUNT);

		/* If we support >1 block per chip, this should still
		 * work as we are likely to make the table contiguous
		 * anyway
		 */
		eat = x->eat_base;
		assert(eat);

		return eat + idx;
	}
}

static struct xive_nvp *xive_get_vp(struct xive *x, unsigned int idx)
{
	struct xive_nvp *p;

	assert(idx < (x->vp_ind_count * VP_PER_PAGE));
	p = (struct xive_nvp *)(be64_to_cpu(x->vp_ind_base[idx / VP_PER_PAGE]) &
			       VSD_ADDRESS_MASK);
	if (!p)
		return NULL;

	return &p[idx % VP_PER_PAGE];
}

/*
 * Store the END base of the VP in W5, using the new architected field
 * in P10. Used to be the pressure relief interrupt field on P9.
 */
static void xive_vp_set_end_base(struct xive_nvp *vp,
				 uint32_t end_blk, uint32_t end_idx)
{
	vp->w5 = xive_set_field32(NVP_W5_VP_END_BLOCK, 0, end_blk) |
		xive_set_field32(NVP_W5_VP_END_INDEX, 0, end_idx);

	/* This is the criteria to know if a VP was allocated */
	assert(vp->w5 != 0);
}

static void xive_init_default_vp(struct xive_nvp *vp,
				 uint32_t end_blk, uint32_t end_idx)
{
	memset(vp, 0, sizeof(struct xive_nvp));

	xive_vp_set_end_base(vp, end_blk, end_idx);

	vp->w0 = xive_set_field32(NVP_W0_VALID, 0, 1);
}

/*
 * VPs of the HW threads have their own set of ENDs which is allocated
 * when XIVE is initialized. These are tagged with a FIRMWARE bit so
 * that they can be identified when the driver is reset (kexec).
 */
static void xive_init_hw_end(struct xive_end *end)
{
	memset(end, 0, sizeof(struct xive_end));
	end->w0 = xive_set_field32(END_W0_FIRMWARE1, 0, 1);
}

static void *xive_get_donated_page(struct xive *x)
{
	return (void *)list_pop_(&x->donated_pages, 0);
}

#define XIVE_ALLOC_IS_ERR(_idx)	((_idx) >= 0xfffffff0)

#define XIVE_ALLOC_NO_SPACE	0xffffffff /* No possible space */
#define XIVE_ALLOC_NO_IND	0xfffffffe /* Indirect need provisioning */
#define XIVE_ALLOC_NO_MEM	0xfffffffd /* Local allocation failed */

static uint32_t xive_alloc_end_set(struct xive *x, bool alloc_indirect)
{
	uint32_t ind_idx;
	int idx;
	int end_base_idx;

	xive_vdbg(x, "Allocating END set...\n");

	assert(x->end_map);

	/* Allocate from the END bitmap. Each bit is 8 ENDs */
	idx = bitmap_find_zero_bit(*x->end_map, 0, xive_end_bitmap_size(x));
	if (idx < 0) {
		xive_dbg(x, "Allocation from END bitmap failed !\n");
		return XIVE_ALLOC_NO_SPACE;
	}

	end_base_idx = idx << xive_cfg_vp_prio_shift(x);

	xive_vdbg(x, "Got ENDs 0x%x..0x%x\n", end_base_idx,
		  end_base_idx + xive_max_prio(x));

	/* Calculate the indirect page where the ENDs reside */
	ind_idx = end_base_idx / END_PER_PAGE;

	/* Is there an indirect page ? If not, check if we can provision it */
	if (!x->end_ind_base[ind_idx]) {
		/* Default flags */
		uint64_t vsd_flags = SETFIELD(VSD_TSIZE, 0ull, 4) |
			SETFIELD(VSD_MODE, 0ull, VSD_MODE_EXCLUSIVE);
		void *page;

		/* If alloc_indirect is set, allocate the memory from OPAL own,
		 * otherwise try to provision from the donated pool
		 */
		if (alloc_indirect) {
			/* Allocate/provision indirect page during boot only */
			xive_vdbg(x, "Indirect empty, provisioning from local pool\n");
			page = local_alloc(x->chip_id, PAGE_SIZE, PAGE_SIZE);
			if (!page) {
				xive_dbg(x, "provisioning failed !\n");
				return XIVE_ALLOC_NO_MEM;
			}
			vsd_flags |= VSD_FIRMWARE;
		} else {
			xive_vdbg(x, "Indirect empty, provisioning from donated pages\n");
			page = xive_get_donated_page(x);
			if (!page) {
				xive_vdbg(x, "no idirect pages available !\n");
				return XIVE_ALLOC_NO_IND;
			}
		}
		memset(page, 0, PAGE_SIZE);
		x->end_ind_base[ind_idx] = cpu_to_be64(vsd_flags |
			(((uint64_t)page) & VSD_ADDRESS_MASK));
		/* Any cache scrub needed ? */
	}

	bitmap_set_bit(*x->end_map, idx);
	return end_base_idx;
}

static void xive_free_end_set(struct xive *x, uint32_t ends)
{
	uint32_t idx;
	uint8_t  prio_mask = xive_max_prio(x);

	xive_vdbg(x, "Freeing END 0x%x..0x%x\n", ends, ends + xive_max_prio(x));

	assert((ends & prio_mask) == 0);
	assert(x->end_map);

	idx = ends >> xive_cfg_vp_prio_shift(x);
	bitmap_clr_bit(*x->end_map, idx);
}

static bool xive_provision_vp_ind(struct xive *x, uint32_t vp_idx, uint32_t order)
{
	uint32_t pbase, pend, i;

	pbase = vp_idx / VP_PER_PAGE;
	pend  = (vp_idx + (1 << order)) / VP_PER_PAGE;

	for (i = pbase; i <= pend; i++) {
		void *page;
		u64 vsd;

		/* Already provisioned ? */
		if (x->vp_ind_base[i])
			continue;

		/* Try to grab a donated page */
		page = xive_get_donated_page(x);
		if (!page)
			return false;

		/* Install the page */
		memset(page, 0, PAGE_SIZE);
		vsd = ((uint64_t)page) & VSD_ADDRESS_MASK;
		vsd |= SETFIELD(VSD_TSIZE, 0ull, 4);
		vsd |= SETFIELD(VSD_MODE, 0ull, VSD_MODE_EXCLUSIVE);
		x->vp_ind_base[i] = cpu_to_be64(vsd);
	}
	return true;
}

static void xive_init_vp_allocator(void)
{
	/* Initialize chip alloc bits */
	xive_chips_alloc_bits = ilog2(xive_block_count);

	prlog(PR_INFO, "%d chips considered for VP allocations\n",
	      1 << xive_chips_alloc_bits);

	/* Allocate a buddy big enough for XIVE_VP_ORDER allocations.
	 *
	 * each bit in the buddy represents 1 << xive_chips_alloc_bits
	 * VPs.
	 */
	xive_vp_buddy = buddy_create(XIVE_VP_ORDER(one_xive));
	assert(xive_vp_buddy);

	/*
	 * We reserve the whole range of VP ids representing HW threads.
	 */
	assert(buddy_reserve(xive_vp_buddy, xive_hw_vp_base,
			     xive_threadid_shift));
}

static uint32_t xive_alloc_vps(uint32_t order)
{
	uint32_t local_order, i;
	int vp;

	/* The minimum order is 2 VPs per chip */
	if (order < (xive_chips_alloc_bits + 1))
		order = xive_chips_alloc_bits + 1;

	/* We split the allocation */
	local_order = order - xive_chips_alloc_bits;

	/* We grab that in the global buddy */
	assert(xive_vp_buddy);
	lock(&xive_buddy_lock);
	vp = buddy_alloc(xive_vp_buddy, local_order);
	unlock(&xive_buddy_lock);
	if (vp < 0)
		return XIVE_ALLOC_NO_SPACE;

	/* Provision on every chip considered for allocation */
	for (i = 0; i < (1 << xive_chips_alloc_bits); i++) {
		struct xive *x = xive_from_pc_blk(i);
		bool success;

		/* Return internal error & log rather than assert ? */
		assert(x);
		lock(&x->lock);
		success = xive_provision_vp_ind(x, vp, local_order);
		unlock(&x->lock);
		if (!success) {
			lock(&xive_buddy_lock);
			buddy_free(xive_vp_buddy, vp, local_order);
			unlock(&xive_buddy_lock);
			return XIVE_ALLOC_NO_IND;
		}
	}

	/* Encode the VP number. "blk" is 0 as this represents
	 * all blocks and the allocation always starts at 0
	 */
	return xive_encode_vp(0, vp, order);
}

static void xive_free_vps(uint32_t vp)
{
	uint32_t idx;
	uint8_t order, local_order;

	assert(xive_decode_vp(vp, NULL, &idx, &order, NULL));

	/* We split the allocation */
	local_order = order - xive_chips_alloc_bits;

	/* Free that in the buddy */
	lock(&xive_buddy_lock);
	buddy_free(xive_vp_buddy, idx, local_order);
	unlock(&xive_buddy_lock);
}

enum xive_cache_type {
	xive_cache_easc,
	xive_cache_esbc,
	xive_cache_endc,
	xive_cache_nxc,
};

/*
 * Cache update
 */

#define FLUSH_CTRL_POLL_VALID PPC_BIT(0)  /* POLL bit is the same for all */

static int64_t __xive_cache_scrub(struct xive *x,
				  enum xive_cache_type ctype,
				  uint64_t block, uint64_t idx,
				  bool want_inval __unused, bool want_disable __unused)
{
	uint64_t ctrl_reg, x_ctrl_reg;
	uint64_t poll_val, ctrl_val;

#ifdef XIVE_CHECK_LOCKS
	assert(lock_held_by_me(&x->lock));
#endif
	switch (ctype) {
	case xive_cache_easc:
		poll_val =
			SETFIELD(VC_EASC_FLUSH_POLL_BLOCK_ID, 0ll, block) |
			SETFIELD(VC_EASC_FLUSH_POLL_OFFSET, 0ll, idx) |
			VC_EASC_FLUSH_POLL_BLOCK_ID_MASK |
			VC_EASC_FLUSH_POLL_OFFSET_MASK;
		xive_regw(x, VC_EASC_FLUSH_POLL, poll_val);
		ctrl_reg = VC_EASC_FLUSH_CTRL;
		x_ctrl_reg = X_VC_EASC_FLUSH_CTRL;
		break;
	case xive_cache_esbc:
		poll_val =
			SETFIELD(VC_ESBC_FLUSH_POLL_BLOCK_ID, 0ll, block) |
			SETFIELD(VC_ESBC_FLUSH_POLL_OFFSET, 0ll, idx) |
			VC_ESBC_FLUSH_POLL_BLOCK_ID_MASK |
			VC_ESBC_FLUSH_POLL_OFFSET_MASK;
		xive_regw(x, VC_ESBC_FLUSH_POLL, poll_val);
		ctrl_reg = VC_ESBC_FLUSH_CTRL;
		x_ctrl_reg = X_VC_ESBC_FLUSH_CTRL;
		break;
	case xive_cache_endc:
		poll_val =
			SETFIELD(VC_ENDC_FLUSH_POLL_BLOCK_ID, 0ll, block) |
			SETFIELD(VC_ENDC_FLUSH_POLL_OFFSET, 0ll, idx) |
			VC_ENDC_FLUSH_POLL_BLOCK_ID_MASK |
			VC_ENDC_FLUSH_POLL_OFFSET_MASK;
		xive_regw(x, VC_ENDC_FLUSH_POLL, poll_val);
		ctrl_reg = VC_ENDC_FLUSH_CTRL;
		x_ctrl_reg = X_VC_ENDC_FLUSH_CTRL;
		break;
	case xive_cache_nxc:
		poll_val =
			SETFIELD(PC_NXC_FLUSH_POLL_BLOCK_ID, 0ll, block) |
			SETFIELD(PC_NXC_FLUSH_POLL_OFFSET, 0ll, idx) |
			PC_NXC_FLUSH_POLL_BLOCK_ID_MASK |
			PC_NXC_FLUSH_POLL_OFFSET_MASK;
		xive_regw(x, PC_NXC_FLUSH_POLL, poll_val);
		ctrl_reg = PC_NXC_FLUSH_CTRL;
		x_ctrl_reg = X_PC_NXC_FLUSH_CTRL;
		break;
	default:
		return OPAL_INTERNAL_ERROR;
	}

	/* XXX Add timeout !!! */
	for (;;) {
		ctrl_val = __xive_regr(x, ctrl_reg, x_ctrl_reg, NULL);
		if (!(ctrl_val & FLUSH_CTRL_POLL_VALID))
			break;
		/* Small delay */
		time_wait(100);
	}
	sync();
	return 0;
}

static int64_t xive_easc_scrub(struct xive *x, uint64_t block, uint64_t idx)
{
	return __xive_cache_scrub(x, xive_cache_easc, block, idx, false, false);
}

static int64_t xive_nxc_scrub(struct xive *x, uint64_t block, uint64_t idx)
{
	return __xive_cache_scrub(x, xive_cache_nxc, block, idx, false, false);
}

static int64_t xive_nxc_scrub_clean(struct xive *x, uint64_t block, uint64_t idx)
{
	return __xive_cache_scrub(x, xive_cache_nxc, block, idx, true, false);
}

static int64_t xive_endc_scrub(struct xive *x, uint64_t block, uint64_t idx)
{
	return __xive_cache_scrub(x, xive_cache_endc, block, idx, false, false);
}

#define XIVE_CACHE_WATCH_MAX_RETRIES 10

static int64_t __xive_cache_watch(struct xive *x, enum xive_cache_type ctype,
				  uint64_t block, uint64_t idx,
				  uint32_t start_dword, uint32_t dword_count,
				  beint64_t *new_data, bool light_watch,
				  bool synchronous)
{
	uint64_t sreg, sregx, dreg0, dreg0x;
	uint64_t dval0, sval, status;
	int64_t i;
	int retries = 0;

#ifdef XIVE_CHECK_LOCKS
	assert(lock_held_by_me(&x->lock));
#endif
	switch (ctype) {
	case xive_cache_endc:
		sreg = VC_ENDC_WATCH0_SPEC;
		sregx = X_VC_ENDC_WATCH0_SPEC;
		dreg0 = VC_ENDC_WATCH0_DATA0;
		dreg0x = X_VC_ENDC_WATCH0_DATA0;
		sval = SETFIELD(VC_ENDC_WATCH_BLOCK_ID, idx, block);
		break;
	case xive_cache_nxc:
		sreg = PC_NXC_WATCH0_SPEC;
		sregx = X_PC_NXC_WATCH0_SPEC;
		dreg0 = PC_NXC_WATCH0_DATA0;
		dreg0x = X_PC_NXC_WATCH0_DATA0;
		sval = SETFIELD(PC_NXC_WATCH_BLOCK_ID, idx, block);
		break;
	default:
		return OPAL_INTERNAL_ERROR;
	}

	/* The full bit is in the same position for ENDC and NXC */
	if (!light_watch)
		sval |= VC_ENDC_WATCH_FULL;

	for (;;) {
		/* Write the cache watch spec */
		__xive_regw(x, sreg, sregx, sval, NULL);

		/* Load data0 register to populate the watch */
		dval0 = __xive_regr(x, dreg0, dreg0x, NULL);

		/* If new_data is NULL, this is a dummy watch used as a
		 * workaround for a HW bug
		 */
		if (!new_data) {
			__xive_regw(x, dreg0, dreg0x, dval0, NULL);
			return 0;
		}

		/* Write the words into the watch facility. We write in reverse
		 * order in case word 0 is part of it as it must be the last
		 * one written.
		 */
		for (i = start_dword + dword_count - 1; i >= start_dword ;i--) {
			uint64_t dw = be64_to_cpu(new_data[i - start_dword]);
			__xive_regw(x, dreg0 + i * 8, dreg0x + i, dw, NULL);
		}

		/* Write data0 register to trigger the update if word 0 wasn't
		 * written above
		 */
		if (start_dword > 0)
			__xive_regw(x, dreg0, dreg0x, dval0, NULL);

		/* This may not be necessary for light updates (it's possible
		 * that a sync in sufficient, TBD). Ensure the above is
		 * complete and check the status of the watch.
		 */
		status = __xive_regr(x, sreg, sregx, NULL);

		/* Bits FULL and CONFLICT are in the same position in
		 * ENDC and NXC
		 */
		if (!(status & VC_ENDC_WATCH_FULL) ||
		    !(status & VC_ENDC_WATCH_CONFLICT))
			break;
		if (!synchronous)
			return OPAL_BUSY;

		if (++retries == XIVE_CACHE_WATCH_MAX_RETRIES) {
			xive_err(x, "Reached maximum retries %d when doing "
				 "a %s cache update\n", retries,
				 ctype == xive_cache_endc ? "ENDC" : "NXC");
			return OPAL_BUSY;
		}
	}

	/* Perform a scrub with "want_invalidate" set to false to push the
	 * cache updates to memory as well
	 */
	return __xive_cache_scrub(x, ctype, block, idx, false, false);
}

#ifdef XIVE_DEBUG_INIT_CACHE_UPDATES
static bool xive_check_endc_update(struct xive *x, uint32_t idx, struct xive_end *end)
{
	struct xive_end *end_p = xive_get_end(x, idx);
	struct xive_end end2;

	assert(end_p);
	end2 = *end_p;
	if (memcmp(end, &end2, sizeof(struct xive_end)) != 0) {
		xive_err(x, "END update mismatch idx %d\n", idx);
		xive_err(x, "want: %08x %08x %08x %08x\n",
			 end->w0, end->w1, end->w2, end->w3);
		xive_err(x, "      %08x %08x %08x %08x\n",
			 end->w4, end->w5, end->w6, end->w7);
		xive_err(x, "got : %08x %08x %08x %08x\n",
			 end2.w0, end2.w1, end2.w2, end2.w3);
		xive_err(x, "      %08x %08x %08x %08x\n",
			 end2.w4, end2.w5, end2.w6, end2.w7);
		return false;
	}
	return true;
}

static bool xive_check_nxc_update(struct xive *x, uint32_t idx, struct xive_nvp *vp)
{
	struct xive_nvp *vp_p = xive_get_vp(x, idx);
	struct xive_nvp vp2;

	assert(vp_p);
	vp2 = *vp_p;
	if (memcmp(vp, &vp2, sizeof(struct xive_nvp)) != 0) {
		xive_err(x, "VP update mismatch idx %d\n", idx);
		xive_err(x, "want: %08x %08x %08x %08x\n",
			 vp->w0, vp->w1, vp->w2, vp->w3);
		xive_err(x, "      %08x %08x %08x %08x\n",
			 vp->w4, vp->w5, vp->w6, vp->w7);
		xive_err(x, "got : %08x %08x %08x %08x\n",
			 vp2.w0, vp2.w1, vp2.w2, vp2.w3);
		xive_err(x, "      %08x %08x %08x %08x\n",
			 vp2.w4, vp2.w5, vp2.w6, vp2.w7);
		return false;
	}
	return true;
}
#else
static inline bool xive_check_endc_update(struct xive *x __unused,
					uint32_t idx __unused,
					struct xive_end *end __unused)
{
	return true;
}

static inline bool xive_check_nxc_update(struct xive *x __unused,
					 uint32_t idx __unused,
					 struct xive_nvp *vp __unused)
{
	return true;
}
#endif

static int64_t xive_escalation_ive_cache_update(struct xive *x, uint64_t block,
				     uint64_t idx, struct xive_eas *eas,
				     bool synchronous)
{
	return __xive_cache_watch(x, xive_cache_endc, block, idx,
				  2, 1, &eas->w, true, synchronous);
}

static int64_t xive_endc_cache_update(struct xive *x, uint64_t block,
				     uint64_t idx, struct xive_end *end,
				     bool synchronous)
{
	int64_t ret;

	ret = __xive_cache_watch(x, xive_cache_endc, block, idx,
				 0, 4, (beint64_t *)end, false, synchronous);
	xive_check_endc_update(x, idx, end);
	return ret;
}

static int64_t xive_nxc_cache_update(struct xive *x, uint64_t block,
				     uint64_t idx, struct xive_nvp *vp,
				     bool synchronous)
{
	int64_t ret;

	ret = __xive_cache_watch(x, xive_cache_nxc, block, idx,
				 0, 4, (beint64_t *)vp, false, synchronous);
	xive_check_nxc_update(x, idx, vp);
	return ret;
}

/*
 * VSD
 */
static bool xive_set_vsd(struct xive *x, uint32_t tbl, uint32_t idx, uint64_t v)
{
	/* Set VC subengine */
	xive_regw(x, VC_VSD_TABLE_ADDR,
		  SETFIELD(VC_VSD_TABLE_SELECT, 0ull, tbl) |
		  SETFIELD(VC_VSD_TABLE_ADDRESS, 0ull, idx));
	if (x->last_reg_error)
		return false;
	xive_regw(x, VC_VSD_TABLE_DATA, v);
	if (x->last_reg_error)
		return false;

	/* also set PC subengine if table is used */
	if (tbl == VST_EAS || tbl == VST_ERQ || tbl == VST_IC)
		return true;

	xive_regw(x, PC_VSD_TABLE_ADDR,
		  SETFIELD(PC_VSD_TABLE_SELECT, 0ull, tbl) |
		  SETFIELD(PC_VSD_TABLE_ADDRESS, 0ull, idx));
	if (x->last_reg_error)
		return false;
	xive_regw(x, PC_VSD_TABLE_DATA, v);
	if (x->last_reg_error)
		return false;
	return true;
}

static bool xive_set_local_tables(struct xive *x)
{
	uint64_t base, i;

	/* These have to be power of 2 sized */
	assert(is_pow2(XIVE_ESB_SIZE));
	assert(is_pow2(XIVE_EAT_SIZE));

	/* All tables set as exclusive */
	base = SETFIELD(VSD_MODE, 0ull, VSD_MODE_EXCLUSIVE);

	/* ESB: direct mode */
	if (!xive_set_vsd(x, VST_ESB, x->block_id, base |
			  (((uint64_t)x->sbe_base) & VSD_ADDRESS_MASK) |
			  SETFIELD(VSD_TSIZE, 0ull, ilog2(XIVE_ESB_SIZE) - 12)))
		return false;

	/* EAS: direct mode */
	if (!xive_set_vsd(x, VST_EAS, x->block_id, base |
			  (((uint64_t)x->eat_base) & VSD_ADDRESS_MASK) |
			  SETFIELD(VSD_TSIZE, 0ull, ilog2(XIVE_EAT_SIZE) - 12)))
		return false;

	/* END: indirect mode with 64K subpages */
	if (!xive_set_vsd(x, VST_END, x->block_id, base |
			  (((uint64_t)x->end_ind_base) & VSD_ADDRESS_MASK) |
			  VSD_INDIRECT | SETFIELD(VSD_TSIZE, 0ull,
						  ilog2(x->end_ind_size) - 12)))
		return false;

	/* NVP: indirect mode with 64K subpages */
	if (!xive_set_vsd(x, VST_NVP, x->block_id, base |
			  (((uint64_t)x->vp_ind_base) & VSD_ADDRESS_MASK) |
			  VSD_INDIRECT | SETFIELD(VSD_TSIZE, 0ull,
						  ilog2(x->vp_ind_size) - 12)))
		return false;

	/* NVG: not used  */
	/* NVC: not used */

	/* INT and SYNC: indexed with the Topology# */
	if (!xive_set_vsd(x, VST_IC, x->chip_id, base |
			  (((uint64_t)x->ic_base) & VSD_ADDRESS_MASK) |
			  SETFIELD(VSD_TSIZE, 0ull, ilog2(x->ic_size) - 12)))
		return false;

	if (!xive_set_vsd(x, VST_SYNC, x->chip_id, base |
			  (((uint64_t)x->sync_inject) & VSD_ADDRESS_MASK) |
			  SETFIELD(VSD_TSIZE, 0ull, ilog2(x->sync_inject_size) - 12)))
		return false;

	/*
	 * ERQ: one 64K page for each queue overflow. Indexed with :
	 *
	 * 0:IPI, 1:HWD, 2:NxC, 3:INT, 4:OS-Queue, 5:Pool-Queue, 6:Hard-Queue
	 */
	for (i = 0; i < VC_QUEUE_COUNT; i++) {
		u64 addr = ((uint64_t)x->q_ovf) + i * PAGE_SIZE;
		u64 cfg, sreg, sregx;

		if (!xive_set_vsd(x, VST_ERQ, i, base |
				  (addr & VSD_ADDRESS_MASK) |
			  SETFIELD(VSD_TSIZE, 0ull, 4)))
			return false;

		sreg = VC_QUEUES_CFG_REM0 + i * 8;
		sregx = X_VC_QUEUES_CFG_REM0 + i;
		cfg = __xive_regr(x, sreg, sregx, NULL);
		cfg |= VC_QUEUES_CFG_MEMB_EN;
		cfg = SETFIELD(VC_QUEUES_CFG_MEMB_SZ, cfg, 4);
		__xive_regw(x, sreg, sregx, cfg, NULL);
	}

	return true;
}


/*
 * IC BAR layout
 *
 * Page 0:		Internal CQ register accesses (reads & writes)
 * Page 1:		Internal PC register accesses (reads & writes)
 * Page 2:		Internal VC register accesses (reads & writes)
 * Page 3:		Internal TCTXT (TIMA) reg accesses (read & writes)
 * Page 4:		Notify Port page (writes only, w/data),
 * Page 5:		Reserved
 * Page 6:		Sync Poll page (writes only, dataless)
 * Page 7:		Sync Inject page (writes only, dataless)
 * Page 8:		LSI Trigger page (writes only, dataless)
 * Page 9:		LSI SB Management page (reads & writes dataless)
 * Pages 10-255:	Reserved
 * Pages 256-383: 	Direct mapped Thread Context Area (reads & writes)
 *                	covering the 128 threads in P10.
 * Pages 384-511: 	Reserved
 */

#define XIVE_IC_CQ_PGOFF	0
#define XIVE_IC_PC_PGOFF	1
#define XIVE_IC_VC_PGOFF	2
#define XIVE_IC_TCTXT_PGOFF	3
#define XIVE_NOTIFY_PGOFF	4
#define XIVE_SYNC_POLL_PGOFF	6
#define XIVE_SYNC_INJECT_PGOFF	7
#define XIVE_LSI_TRIGGER_PGOFF	8
#define XIVE_LSI_MGMT_PGOFF	9
#define XIVE_IC_TM_DIRECT_PGOFF 256

static bool xive_configure_ic_bars(struct xive *x)
{
	uint64_t chip_id = x->chip_id;
	uint64_t val;

	/* Reset all bars to zero */
	xive_regwx(x, CQ_RST_CTL, CQ_RST_PB_BAR_RESET);

	/* IC BAR */
	phys_map_get(chip_id, XIVE_IC, 0, (uint64_t *)&x->ic_base, &x->ic_size);
	val = (uint64_t)x->ic_base | CQ_IC_BAR_VALID | CQ_IC_BAR_64K;
	x->ic_shift = 16;

	xive_regwx(x, CQ_IC_BAR, val);
	if (x->last_reg_error)
		return false;

	/*
	 * TM BAR, same address for each chip. Hence we create a fake
	 * chip 0 and use that for all phys_map_get(XIVE_TM) calls.
	 */
	phys_map_get(0, XIVE_TM, 0, (uint64_t *)&x->tm_base, &x->tm_size);
	val = (uint64_t)x->tm_base | CQ_TM_BAR_VALID | CQ_TM_BAR_64K;
	x->tm_shift = 16;

	xive_regwx(x, CQ_TM_BAR, val);
	if (x->last_reg_error)
		return false;

	/* IC BAR sub-pages shortcuts */
	x->ic_tm_direct_base = x->ic_base +
		(XIVE_IC_TM_DIRECT_PGOFF << x->ic_shift);

	return true;
}

/*
 * NVPG, NVC, ESB, END BARs have common attributes: 64k page and only
 * one set covering the whole BAR.
 */
static bool xive_configure_bars(struct xive *x)
{
	uint64_t chip_id = x->chip_id;
	uint64_t val;
	uint64_t esb_size;
	uint64_t end_size;
	uint64_t nvp_size;

	x->nvp_size = XIVE_VP_COUNT(x) << XIVE_NVP_SHIFT;
	x->esb_size = XIVE_INT_COUNT << XIVE_ESB_SHIFT;
	x->end_size = XIVE_END_COUNT << XIVE_END_SHIFT;

	/*
	 * NVC BAR is not configured because we do not use the XIVE2
	 * Crowd capability.
	 */

	/* NVPG BAR: two pages, even NVP, odd NVG */
	phys_map_get(chip_id, XIVE_NVPG, 0, (uint64_t *)&x->nvp_base, &nvp_size);
	if (x->nvp_size > nvp_size) {
		xive_err(x, "NVP table is larger than default: "
			 "0x%012llx > 0x%012llx\n", x->nvp_size, nvp_size);
		return false;
	}

	val = (uint64_t)x->nvp_base | CQ_BAR_VALID | CQ_BAR_64K |
		SETFIELD(CQ_BAR_RANGE, 0ull, ilog2(x->nvp_size) - 24);
	xive_regwx(x, CQ_NVPG_BAR, val);
	if (x->last_reg_error)
		return false;

	/* ESB BAR */
	phys_map_get(chip_id, XIVE_ESB, 0, (uint64_t *)&x->esb_base, &esb_size);
	if (x->esb_size > esb_size) {
		xive_err(x, "ESB table is larger than default: "
			 "0x%012llx > 0x%012llx\n", x->esb_size, esb_size);
		return false;
	}

	val = (uint64_t)x->esb_base | CQ_BAR_VALID | CQ_BAR_64K |
		SETFIELD(CQ_BAR_RANGE, 0ull, ilog2(x->esb_size) - 24);
	xive_regwx(x, CQ_ESB_BAR, val);
	if (x->last_reg_error)
		return false;

	/* END BAR */
	phys_map_get(chip_id, XIVE_END, 0, (uint64_t *)&x->end_base, &end_size);
	if (x->end_size > end_size) {
		xive_err(x, "END table is larger than default: "
			 "0x%012llx > 0x%012llx\n", x->end_size, end_size);
		return false;
	}

	val = (uint64_t)x->end_base | CQ_BAR_VALID | CQ_BAR_64K |
		SETFIELD(CQ_BAR_RANGE, 0ull, ilog2(x->end_size) - 24);
	xive_regwx(x, CQ_END_BAR, val);
	if (x->last_reg_error)
		return false;

	xive_dbg(x, "IC:  %14p [0x%012llx]\n", x->ic_base, x->ic_size);
	xive_dbg(x, "TM:  %14p [0x%012llx]\n", x->tm_base, x->tm_size);
	xive_dbg(x, "NVP: %14p [0x%012llx]\n", x->nvp_base, x->nvp_size);
	xive_dbg(x, "ESB: %14p [0x%012llx]\n", x->esb_base, x->esb_size);
	xive_dbg(x, "END: %14p [0x%012llx]\n", x->end_base, x->end_size);
	xive_dbg(x, "OVF: %14p [0x%012x]\n", x->q_ovf,
		 VC_QUEUE_COUNT * PAGE_SIZE);

	return true;
}

static void xive_dump_mmio(struct xive *x)
{
	prlog(PR_DEBUG, " CQ_CFG_PB_GEN = %016llx\n",
	      in_be64(x->ic_base + CQ_CFG_PB_GEN));
	prlog(PR_DEBUG, " CQ_MSGSND     = %016llx\n",
	      in_be64(x->ic_base + CQ_MSGSND));
}

static const struct {
	uint64_t bitmask;
	const char *name;
} xive_capabilities[] = {
	{ CQ_XIVE_CAP_PHB_PQ_DISABLE, "PHB PQ disable mode support" },
	{ CQ_XIVE_CAP_PHB_ABT, "PHB address based trigger mode support" },
	{ CQ_XIVE_CAP_EXPLOITATION_MODE, "Exploitation mode" },
	{ CQ_XIVE_CAP_STORE_EOI, "StoreEOI mode support" },
	{ CQ_XIVE_CAP_VP_SAVE_RESTORE, "VP Context Save and Restore" },
};

static void xive_dump_capabilities(struct xive *x, uint64_t cap_val)
{
	int i;

	xive_dbg(x, "capabilities: %016llx\n", cap_val);
	xive_dbg(x, "\tVersion: %lld\n",
		 GETFIELD(CQ_XIVE_CAP_VERSION, cap_val));
	xive_dbg(x, "\tUser interrupt priorities: [ 1 - %d ]\n",
		 1 << GETFIELD(CQ_XIVE_CAP_USER_INT_PRIO, cap_val));
	xive_dbg(x, "\tVP interrupt priorities: [ %d - 8 ]\n",
		 1 << GETFIELD(CQ_XIVE_CAP_VP_INT_PRIO, cap_val));
	xive_dbg(x, "\tExtended Blockid bits: %lld\n",
		 4 + GETFIELD(CQ_XIVE_CAP_BLOCK_ID_WIDTH, cap_val));

	for (i = 0; i < ARRAY_SIZE(xive_capabilities); i++) {
		if (xive_capabilities[i].bitmask & cap_val)
			xive_dbg(x, "\t%s\n", xive_capabilities[i].name);
	}
}

static const struct {
	uint64_t bitmask;
	const char *name;
} xive_configs[] = {
	{ CQ_XIVE_CFG_GEN1_TIMA_OS, "Gen1 mode TIMA OS" },
	{ CQ_XIVE_CFG_GEN1_TIMA_HYP, "Gen1 mode TIMA Hyp" },
	{ CQ_XIVE_CFG_GEN1_TIMA_HYP_BLK0, "Gen1 mode TIMA General Hypervisor Block0" },
	{ CQ_XIVE_CFG_GEN1_TIMA_CROWD_DIS, "Gen1 mode TIMA Crowd disable" },
	{ CQ_XIVE_CFG_GEN1_END_ESX, "Gen1 mode END ESx" },
	{ CQ_XIVE_CFG_EN_VP_SAVE_RESTORE, "VP Context Save and Restore" },
	{ CQ_XIVE_CFG_EN_VP_SAVE_REST_STRICT, "VP Context Save and Restore strict" },
};

static void xive_dump_configuration(struct xive *x, const char *prefix,
				    uint64_t cfg_val)
{
	int i ;

	xive_dbg(x, "%s configuration: %016llx\n", prefix, cfg_val);
	xive_dbg(x, "\tHardwired Thread Id range: %lld bits\n",
		 7 + GETFIELD(CQ_XIVE_CFG_HYP_HARD_RANGE, cfg_val));
	xive_dbg(x, "\tUser Interrupt priorities: [ 1 - %d ]\n",
		 1 << GETFIELD(CQ_XIVE_CFG_USER_INT_PRIO, cfg_val));
	xive_dbg(x, "\tVP Interrupt priorities: [ 0 - %d ]\n", xive_max_prio(x));
	xive_dbg(x, "\tBlockId bits: %lld bits\n",
		 4 + GETFIELD(CQ_XIVE_CFG_BLOCK_ID_WIDTH, cfg_val));
	if (CQ_XIVE_CFG_HYP_HARD_BLKID_OVERRIDE & cfg_val)
		xive_dbg(x, "\tHardwired BlockId: %lld\n",
			 GETFIELD(CQ_XIVE_CFG_HYP_HARD_BLOCK_ID, cfg_val));

	for (i = 0; i < ARRAY_SIZE(xive_configs); i++) {
		if (xive_configs[i].bitmask & cfg_val)
			xive_dbg(x, "\t%s\n", xive_configs[i].name);
	}
}

/*
 * Default XIVE configuration
 */
#define XIVE_CONFIGURATION                                        \
	(SETFIELD(CQ_XIVE_CFG_HYP_HARD_RANGE, 0ull, CQ_XIVE_CFG_THREADID_8BITS) | \
	 SETFIELD(CQ_XIVE_CFG_VP_INT_PRIO, 0ull, CQ_XIVE_CFG_INT_PRIO_8))

/*
 * Gen1 configuration for tests (QEMU)
 */
#define XIVE_CONFIGURATION_GEN1						\
	(SETFIELD(CQ_XIVE_CFG_HYP_HARD_RANGE, 0ull, CQ_XIVE_CFG_THREADID_7BITS) | \
	 SETFIELD(CQ_XIVE_CFG_VP_INT_PRIO, 0ull, CQ_XIVE_CFG_INT_PRIO_8) | \
	 CQ_XIVE_CFG_GEN1_TIMA_OS |					\
	 CQ_XIVE_CFG_GEN1_TIMA_HYP |					\
	 CQ_XIVE_CFG_GEN1_TIMA_HYP_BLK0 |				\
	 CQ_XIVE_CFG_GEN1_TIMA_CROWD_DIS |				\
	 CQ_XIVE_CFG_GEN1_END_ESX)

static bool xive_has_cap(struct xive *x, uint64_t cap)
{
	return !!x && !!(x->capabilities & cap);
}

#define XIVE_CAN_STORE_EOI(x) xive_has_cap(x, CQ_XIVE_CAP_STORE_EOI)

static bool xive_cfg_save_restore(struct xive *x)
{
	return !!(x->config & CQ_XIVE_CFG_EN_VP_SAVE_RESTORE);
}

/*
 * When PQ_disable is available, configure the ESB cache to improve
 * performance for PHB ESBs.
 *
 * split_mode :
 *   1/3rd of the cache is reserved for PHB ESBs and the rest to
 *   IPIs. This is sufficient to keep all the PHB ESBs in cache and
 *   avoid ESB cache misses during IO interrupt processing.
 *
 * hash_array_enable :
 *   Internal cache hashing optimization. The hash_array tracks for
 *   ESBs where the original trigger came from so that we avoid
 *   getting the EAS into the cache twice.
 */
static void xive_config_esb_cache(struct xive *x)
{
	uint64_t val = xive_regr(x, VC_ESBC_CFG);

	if (xive_has_cap(x, CQ_XIVE_CAP_PHB_PQ_DISABLE)) {
		val |= VC_ESBC_CFG_SPLIT_MODE | VC_ESBC_CFG_HASH_ARRAY_ENABLE;
		val = SETFIELD(VC_ESBC_CFG_MAX_ENTRIES_IN_MODIFIED, val, 0xE);
		xive_dbg(x, "ESB cache configured with split mode "
			 "and hash array. VC_ESBC_CFG=%016llx\n", val);
	} else
		val &= ~VC_ESBC_CFG_SPLIT_MODE;

	xive_regw(x, VC_ESBC_CFG, val);
}

static void xive_config_fused_core(struct xive *x)
{
	uint64_t val = xive_regr(x, TCTXT_CFG);

	if (this_cpu()->is_fused_core) {
		val |= TCTXT_CFG_FUSE_CORE_EN;
		xive_dbg(x, "configured for fused cores. "
			 "PC_TCTXT_CFG=%016llx\n", val);
	} else
		val &= ~TCTXT_CFG_FUSE_CORE_EN;
	xive_regw(x, TCTXT_CFG, val);
}

static void xive_config_reduced_priorities_fixup(struct xive *x)
{
	if (xive_cfg_vp_prio_shift(x) < CQ_XIVE_CFG_INT_PRIO_8 &&
	    x->quirks & XIVE_QUIRK_BROKEN_PRIO_CHECK) {
		uint64_t val = xive_regr(x, PC_ERR1_CFG1);

		val &= ~PC_ERR1_CFG1_INTERRUPT_INVALID_PRIO;
		xive_dbg(x, "workaround for reduced priorities. "
			 "PC_ERR1_CFG1=%016llx\n", val);
		xive_regw(x, PC_ERR1_CFG1, val);
	}
}

static bool xive_config_init(struct xive *x)
{
	x->capabilities = xive_regr(x, CQ_XIVE_CAP);
	xive_dump_capabilities(x, x->capabilities);

	x->generation = GETFIELD(CQ_XIVE_CAP_VERSION, x->capabilities);

	/*
	 * Allow QEMU to override version for tests
	 */
	if (x->generation != XIVE_GEN2 && !chip_quirk(QUIRK_QEMU)) {
		xive_err(x, "Invalid XIVE controller version %d\n",
			 x->generation);
		return false;
	}

	x->config = xive_regr(x, CQ_XIVE_CFG);
	xive_dump_configuration(x, "default", x->config);

	/* Start with default settings */
	x->config = x->generation == XIVE_GEN1 ? XIVE_CONFIGURATION_GEN1 :
		XIVE_CONFIGURATION;

	if (x->quirks & XIVE_QUIRK_THREADID_7BITS)
		x->config = SETFIELD(CQ_XIVE_CFG_HYP_HARD_RANGE, x->config,
				     CQ_XIVE_CFG_THREADID_7BITS);

	/*
	 * Hardwire the block ID. The default value is the topology ID
	 * of the chip which is different from the block.
	 */
	x->config |= CQ_XIVE_CFG_HYP_HARD_BLKID_OVERRIDE |
		SETFIELD(CQ_XIVE_CFG_HYP_HARD_BLOCK_ID, 0ull, x->block_id);

	/*
	 * Enable "VP Context Save and Restore" by default. it is
	 * compatible with KVM which currently does the context
	 * save&restore in the entry/exit path of the vCPU
	 */
	if (x->capabilities & CQ_XIVE_CAP_VP_SAVE_RESTORE)
		x->config |= CQ_XIVE_CFG_EN_VP_SAVE_RESTORE;

	xive_dump_configuration(x, "new", x->config);
	xive_regw(x, CQ_XIVE_CFG, x->config);
	if (xive_regr(x, CQ_XIVE_CFG) != x->config) {
		xive_err(x, "configuration setting failed\n");
	}

	/*
	 * Disable error reporting in the FIR for info errors from the VC.
	 */
	xive_regw(x, CQ_FIRMASK_OR, CQ_FIR_VC_INFO_ERROR_0_2);

	/*
	 * Mask CI Load and Store to bad location, as IPI trigger
	 * pages may be mapped to user space, and a read on the
	 * trigger page causes a checkstop
	 */
	xive_regw(x, CQ_FIRMASK_OR, CQ_FIR_PB_RCMDX_CI_ERR1);

	/*
	 * VP space settings. P9 mode is 19bits.
	 */
	x->vp_shift = x->generation == XIVE_GEN1 ?
		VP_SHIFT_GEN1 : VP_SHIFT_GEN2;

	/*
	 * VP ids for HW threads. These values are hardcoded in the
	 * CAM line of the HW context
	 *
	 *     POWER10     |chip|0000000000000001|threadid|
	 *     28bits        4           16          8
	 *
	 *     POWER9           |chip|000000000001|thrdid |
	 *     23bits              4      12          7
	 */

	/* TODO (cosmetic): set VP ids for HW threads only once */
	xive_threadid_shift = 7 + GETFIELD(CQ_XIVE_CFG_HYP_HARD_RANGE,
					   x->config);

	xive_hw_vp_base  = 1 << xive_threadid_shift;
	xive_hw_vp_count = 1 << xive_threadid_shift;

	xive_dbg(x, "store EOI is %savailable\n",
		 XIVE_CAN_STORE_EOI(x) ? "" : "not ");

	xive_config_fused_core(x);

	xive_config_esb_cache(x);

	xive_config_reduced_priorities_fixup(x);

	return true;
}

/* Set Translation tables : 1 block per chip */
static bool xive_setup_set_xlate(struct xive *x)
{
	unsigned int i;

	/* Configure ESBs */
	xive_regw(x, CQ_TAR,
		  CQ_TAR_AUTOINC | SETFIELD(CQ_TAR_SELECT, 0ull, CQ_TAR_ESB));
	if (x->last_reg_error)
		return false;
	for (i = 0; i < XIVE_MAX_BLOCKS; i++) {
		xive_regw(x, CQ_TDR, CQ_TDR_VALID |
			  SETFIELD(CQ_TDR_BLOCK_ID, 0ull, x->block_id));
		if (x->last_reg_error)
			return false;
	}

	/* Configure ENDs */
	xive_regw(x, CQ_TAR,
		  CQ_TAR_AUTOINC | SETFIELD(CQ_TAR_SELECT, 0ull, CQ_TAR_END));
	if (x->last_reg_error)
		return false;
	for (i = 0; i < XIVE_MAX_BLOCKS; i++) {
		xive_regw(x, CQ_TDR, CQ_TDR_VALID |
			  SETFIELD(CQ_TDR_BLOCK_ID, 0ull, x->block_id));
		if (x->last_reg_error)
			return false;
	}

	/* Configure NVPs */
	xive_regw(x, CQ_TAR,
		  CQ_TAR_AUTOINC | SETFIELD(CQ_TAR_SELECT, 0ull, CQ_TAR_NVPG));
	if (x->last_reg_error)
		return false;
	for (i = 0; i < XIVE_MAX_BLOCKS; i++) {
		xive_regw(x, CQ_TDR, CQ_TDR_VALID |
			  SETFIELD(CQ_TDR_BLOCK_ID, 0ull, x->block_id));
		if (x->last_reg_error)
			return false;
	}
	return true;
}

static bool xive_prealloc_tables(struct xive *x)
{
	uint32_t i;
	uint32_t pbase, pend;

	/* ESB has 4 entries per byte */
	x->sbe_base = local_alloc(x->chip_id, XIVE_ESB_SIZE, XIVE_ESB_SIZE);
	if (!x->sbe_base) {
		xive_err(x, "Failed to allocate SBE\n");
		return false;
	}

	/* PQs are initialized to 0b01 which corresponds to "ints off" */
	memset(x->sbe_base, 0x55, XIVE_ESB_SIZE);
	xive_dbg(x, "SBE  at %p size 0x%lx\n", x->sbe_base, XIVE_ESB_SIZE);

	/* EAS entries are 8 bytes */
	x->eat_base = local_alloc(x->chip_id, XIVE_EAT_SIZE, XIVE_EAT_SIZE);
	if (!x->eat_base) {
		xive_err(x, "Failed to allocate EAS\n");
		return false;
	}

	/*
	 * We clear the entries (non-valid). They will be initialized
	 * when actually used
	 */
	memset(x->eat_base, 0, XIVE_EAT_SIZE);
	xive_dbg(x, "EAT  at %p size 0x%lx\n", x->eat_base, XIVE_EAT_SIZE);

	/* Indirect END table. Limited to one top page. */
	x->end_ind_size = ALIGN_UP(XIVE_END_TABLE_SIZE, PAGE_SIZE);
	if (x->end_ind_size > PAGE_SIZE) {
		xive_err(x, "END indirect table is too big !\n");
		return false;
	}
	x->end_ind_base = local_alloc(x->chip_id, x->end_ind_size,
				      x->end_ind_size);
	if (!x->end_ind_base) {
		xive_err(x, "Failed to allocate END indirect table\n");
		return false;
	}
	memset(x->end_ind_base, 0, x->end_ind_size);
	xive_dbg(x, "ENDi at %p size 0x%llx #%ld entries\n", x->end_ind_base,
		 x->end_ind_size, XIVE_END_COUNT);
	x->end_ind_count = XIVE_END_TABLE_SIZE / XIVE_VSD_SIZE;

	/* Indirect VP table. Limited to one top page. */
	x->vp_ind_size = ALIGN_UP(XIVE_VP_TABLE_SIZE(x), PAGE_SIZE);
	if (x->vp_ind_size > PAGE_SIZE) {
		xive_err(x, "VP indirect table is too big !\n");
		return false;
	}
	x->vp_ind_base = local_alloc(x->chip_id, x->vp_ind_size,
				     x->vp_ind_size);
	if (!x->vp_ind_base) {
		xive_err(x, "Failed to allocate VP indirect table\n");
		return false;
	}
	xive_dbg(x, "VPi  at %p size 0x%llx #%ld entries\n", x->vp_ind_base,
		 x->vp_ind_size, XIVE_VP_COUNT(x));
	x->vp_ind_count = XIVE_VP_TABLE_SIZE(x) / XIVE_VSD_SIZE;
	memset(x->vp_ind_base, 0, x->vp_ind_size);

	/* Allocate pages for the VP ids representing HW threads */
	pbase = xive_hw_vp_base / VP_PER_PAGE;
	pend  = (xive_hw_vp_base + xive_hw_vp_count) / VP_PER_PAGE;

	xive_dbg(x, "Allocating pages %d to %d of VPs (for %d VPs)\n",
		 pbase, pend, xive_hw_vp_count);
	for (i = pbase; i <= pend; i++) {
		void *page;
		u64 vsd;

		/* Indirect entries have a VSD format */
		page = local_alloc(x->chip_id, PAGE_SIZE, PAGE_SIZE);
		if (!page) {
			xive_err(x, "Failed to allocate VP page\n");
			return false;
		}
		xive_dbg(x, "VP%d at %p size 0x%x\n", i, page, PAGE_SIZE);
		memset(page, 0, PAGE_SIZE);
		vsd = ((uint64_t)page) & VSD_ADDRESS_MASK;

		vsd |= SETFIELD(VSD_TSIZE, 0ull, 4);
		vsd |= SETFIELD(VSD_MODE, 0ull, VSD_MODE_EXCLUSIVE);
		vsd |= VSD_FIRMWARE;
		x->vp_ind_base[i] = cpu_to_be64(vsd);
	}

	/*
	 * Allocate page for cache and sync injection (512 * 128 hw
	 * threads) + one extra page for future use
	 */
	x->sync_inject_size = PAGE_SIZE + PAGE_SIZE;
	x->sync_inject = local_alloc(x->chip_id, x->sync_inject_size,
				     x->sync_inject_size);
	if (!x->sync_inject) {
		xive_err(x, "Failed to allocate sync pages\n");
		return false;
	}

	/*
	 * The Memory Coherence Directory uses 16M "granule" to track
	 * shared copies of a cache line. If any cache line within the
	 * 16M range gets touched by someone outside of the group, the
	 * MCD forces accesses to any cache line within the range to
	 * include everyone that might have a shared copy.
	 */
#define QUEUE_OVF_ALIGN (16 << 20) /* MCD granule size */

	/*
	 * Allocate the queue overflow pages and use a 16M alignment
	 * to avoid sharing with other structures and reduce traffic
	 * on the PowerBus.
	 */
	x->q_ovf = local_alloc(x->chip_id, VC_QUEUE_COUNT * PAGE_SIZE,
			       QUEUE_OVF_ALIGN);
	if (!x->q_ovf) {
		xive_err(x, "Failed to allocate queue overflow\n");
		return false;
	}
	return true;
}

static void xive_add_provisioning_properties(void)
{
	beint32_t chips[XIVE_MAX_CHIPS];
	uint32_t i, count;

	dt_add_property_cells(xive_dt_node,
			      "ibm,xive-provision-page-size", PAGE_SIZE);

	count = 1 << xive_chips_alloc_bits;
	for (i = 0; i < count; i++)
		chips[i] = cpu_to_be32(xive_block_to_chip[i]);
	dt_add_property(xive_dt_node, "ibm,xive-provision-chips",
			chips, 4 * count);
}

static void xive_create_mmio_dt_node(struct xive *x)
{
	uint64_t tb = (uint64_t)x->tm_base;
	uint32_t stride = 1u << x->tm_shift;

	xive_dt_node = dt_new_addr(dt_root, "interrupt-controller", tb);
	assert(xive_dt_node);

	dt_add_property_u64s(xive_dt_node, "reg",
			     tb + 0 * stride, stride,
			     tb + 1 * stride, stride,
			     tb + 2 * stride, stride,
			     tb + 3 * stride, stride);

	dt_add_property_strings(xive_dt_node, "compatible",
				"ibm,opal-xive-pe", "ibm,opal-intc");

	dt_add_property_cells(xive_dt_node, "ibm,xive-eq-sizes",
			      12, 16, 21, 24);

	dt_add_property_cells(xive_dt_node, "ibm,xive-#priorities",
			      xive_cfg_vp_prio(x));

	dt_add_property(xive_dt_node, "single-escalation-support", NULL, 0);

	if (XIVE_CAN_STORE_EOI(x))
		dt_add_property(xive_dt_node, "store-eoi", NULL, 0);

	if (xive_cfg_save_restore(x))
		dt_add_property(xive_dt_node, "vp-save-restore", NULL, 0);

	xive_add_provisioning_properties();

}

static void xive_setup_forward_ports(struct xive *x, struct proc_chip *remote_chip)
{
	struct xive *remote_xive = remote_chip->xive;
	uint64_t base = SETFIELD(VSD_MODE, 0ull, VSD_MODE_FORWARD);

	if (!xive_set_vsd(x, VST_ESB, remote_xive->block_id,
			  base | ((uint64_t)remote_xive->esb_base) |
			  SETFIELD(VSD_TSIZE, 0ull, ilog2(x->esb_size) - 12)))
		goto error;

	/* EAS: No remote */

	if (!xive_set_vsd(x, VST_END, remote_xive->block_id,
			  base | ((uint64_t)remote_xive->end_base) |
			  SETFIELD(VSD_TSIZE, 0ull, ilog2(x->end_size) - 12)))
		goto error;

	if (!xive_set_vsd(x, VST_NVP, remote_xive->block_id,
			  base | ((uint64_t)remote_xive->nvp_base) |
			  SETFIELD(VSD_TSIZE, 0ull, ilog2(x->nvp_size) - 12)))
		goto error;

	/* NVG: not used */
	/* NVC: not used */

	if (!xive_set_vsd(x, VST_IC, remote_xive->chip_id,
			  base | ((uint64_t)remote_xive->ic_base) |
			  SETFIELD(VSD_TSIZE, 0ull, ilog2(x->ic_size) - 12)))
		goto error;

	if (!xive_set_vsd(x, VST_SYNC, remote_xive->chip_id,
			  base | ((uint64_t)remote_xive->sync_inject) |
			  SETFIELD(VSD_TSIZE, 0ull, ilog2(x->sync_inject_size) - 12)))
		goto error;

	/* ERQ: No remote */

	return;

 error:
	xive_err(x, "Failure configuring forwarding ports\n");
}

static void late_init_one_xive(struct xive *x)
{
	struct proc_chip *chip;

	/* We need to setup the cross-chip forward ports. Let's
	 * iterate all chip and set them up accordingly
	 */
	for_each_chip(chip) {
		/* We skip ourselves or chips without a xive */
		if (chip->xive == x || !chip->xive)
			continue;

		/* Setup our forward ports to that chip */
		xive_setup_forward_ports(x, chip);
	}
}

static bool xive_check_ipi_free(struct xive *x, uint32_t irq, uint32_t count)
{
	uint32_t i, idx = GIRQ_TO_IDX(irq);

	for (i = 0; i < count; i++)
		if (bitmap_tst_bit(*x->ipi_alloc_map, idx + i))
			return false;
	return true;
}

uint32_t xive2_alloc_hw_irqs(uint32_t chip_id, uint32_t count,
				      uint32_t align)
{
	struct proc_chip *chip = get_chip(chip_id);
	struct xive *x;
	uint32_t base, i;

	assert(chip);
	assert(is_pow2(align));

	x = chip->xive;
	assert(x);

	lock(&x->lock);

	/* Allocate the HW interrupts */
	base = x->int_hw_bot - count;
	base &= ~(align - 1);
	if (base < x->int_ipi_top) {
		xive_err(x,
			 "HW alloc request for %d interrupts aligned to %d failed\n",
			 count, align);
		unlock(&x->lock);
		return XIVE_IRQ_ERROR;
	}
	if (!xive_check_ipi_free(x, base, count)) {
		xive_err(x, "HWIRQ boot allocator request overlaps dynamic allocator\n");
		unlock(&x->lock);
		return XIVE_IRQ_ERROR;
	}

	x->int_hw_bot = base;

	/* Initialize the corresponding EAS entries to sane defaults,
	 * IE entry is valid, not routed and masked, EQ data is set
	 * to the GIRQ number.
	 */
	for (i = 0; i < count; i++) {
		struct xive_eas *eas = xive_get_eas(x, base + i);

		eas->w = xive_set_field64(EAS_VALID, 0, 1) |
			 xive_set_field64(EAS_MASKED, 0, 1) |
			 xive_set_field64(EAS_END_DATA, 0, base + i);
	}

	unlock(&x->lock);
	return base;
}

uint32_t xive2_alloc_ipi_irqs(uint32_t chip_id, uint32_t count,
				       uint32_t align)
{
	struct proc_chip *chip = get_chip(chip_id);
	struct xive *x;
	uint32_t base, i;

	assert(chip);
	assert(is_pow2(align));

	x = chip->xive;
	assert(x);

	lock(&x->lock);

	/* Allocate the IPI interrupts */
	base = x->int_ipi_top + (align - 1);
	base &= ~(align - 1);
	if (base >= x->int_hw_bot) {
		xive_err(x,
			 "IPI alloc request for %d interrupts aligned to %d failed\n",
			 count, align);
		unlock(&x->lock);
		return XIVE_IRQ_ERROR;
	}
	if (!xive_check_ipi_free(x, base, count)) {
		xive_err(x, "IPI boot allocator request overlaps dynamic allocator\n");
		unlock(&x->lock);
		return XIVE_IRQ_ERROR;
	}

	x->int_ipi_top = base + count;

	/* Initialize the corresponding EAS entries to sane defaults,
	 * IE entry is valid, not routed and masked, END data is set
	 * to the GIRQ number.
	 */
	for (i = 0; i < count; i++) {
		struct xive_eas *eas = xive_get_eas(x, base + i);

		eas->w = xive_set_field64(EAS_VALID, 0, 1) |
			 xive_set_field64(EAS_MASKED, 0, 1) |
			 xive_set_field64(EAS_END_DATA, 0, base + i);
	}

	unlock(&x->lock);
	return base;
}

void *xive2_get_trigger_port(uint32_t girq)
{
	uint32_t idx = GIRQ_TO_IDX(girq);
	struct xive *x;

	/* Find XIVE on which the EAS resides */
	x = xive_from_isn(girq);
	if (!x)
		return NULL;

	if (GIRQ_IS_ESCALATION(girq)) {
		/* There is no trigger page for escalation interrupts */
		return NULL;
	} else {
		/* Make sure it's an IPI on that chip */
		if (girq < x->int_base ||
		    girq >= x->int_ipi_top)
			return NULL;

		return x->esb_base + idx * XIVE_ESB_PAGE_SIZE;
	}
}

/*
 *  Notify Port page (writes only, w/data), separated into two
 *  categories, both sent to VC:
 *   - IPI queue (Addr bit 52 = 0) (for NPU)
 *   - HW queue (Addr bit 52 = 1)
 */
uint64_t xive2_get_notify_port(uint32_t chip_id, uint32_t ent)
{
	struct proc_chip *chip = get_chip(chip_id);
	struct xive *x;
	uint32_t offset = 0;

	assert(chip);
	x = chip->xive;
	assert(x);

	/* This is where we can assign a different HW queue to a different
	 * source by offsetting into the cache lines of the notify port
	 *
	 * For now we keep it very basic, this will have to be looked at
	 * again on real HW with some proper performance analysis.
	 *
	 * Here's what Florian says on the matter:
	 *
	 * <<
	 * The first 2k of the notify port page can all be used for PCIe triggers
	 *
	 * However the idea would be that we try to use the first 4 cache lines to
	 * balance the PCIe Interrupt requests to use the least used snoop buses
	 * (we went from 2 to 4 snoop buses for P9). snoop 0 is heavily used
	 * (I think TLBIs are using that in addition to the normal addresses),
	 * snoop 3 is used for all Int commands, so I think snoop 2 (CL 2 in the
	 * page) is the least used overall. So we probably should that one for
	 * the Int commands from PCIe.
	 *
	 * In addition, our EAS cache supports hashing to provide "private" cache
	 * areas for the PHBs in the shared 1k EAS cache. This allows e.g. to avoid
	 * that one "thrashing" PHB thrashes the EAS cache for everyone, or provide
	 * a PHB with a private area that would allow high cache hits in case of a
	 * device using very few interrupts. The hashing is based on the offset within
	 * the cache line. So using that, you can e.g. set the EAS cache up so that
	 * IPIs use 512 entries, the x16 PHB uses 256 entries and the x8 PHBs 128
	 * entries each - or IPIs using all entries and sharing with PHBs, so PHBs
	 * would use 512 entries and 256 entries respectively.
	 *
	 * This is a tuning we would probably do later in the lab, but as a "prep"
	 * we should set up the different PHBs such that they are using different
	 * 8B-aligned offsets within the cache line, so e.g.
	 * PH4_0  addr        0x100        (CL 2 DW0
	 * PH4_1  addr        0x108        (CL 2 DW1)
	 * PH4_2  addr        0x110        (CL 2 DW2)
	 * etc.
	 * >>
	 *
	 * I'm using snoop1 for PHB0 and snoop2 for everybody else.
	 */

	/* Florian adds :
	 *
	 * we just set them up for a start to have different offsets
	 * within the cache line so that we could use the allocation
	 * restrictions that can be enforced in the interrupt
	 * controller
	 *
	 * P10 might now be randomizing the cache line bits in HW to
	 * balance snoop bus usage
	 */
	switch(ent) {
	case XIVE_HW_SRC_PHBn(0):
		offset = 0x800;
		break;
	case XIVE_HW_SRC_PHBn(1):
		offset = 0x908;
		break;
	case XIVE_HW_SRC_PHBn(2):
		offset = 0x910;
		break;
	case XIVE_HW_SRC_PHBn(3):
		offset = 0x918;
		break;
	case XIVE_HW_SRC_PHBn(4):
		offset = 0x920;
		break;
	case XIVE_HW_SRC_PHBn(5):
		offset = 0x928;
		break;
	case XIVE_HW_SRC_PSI:
		offset = 0x930;
		break;
	default:
		assert(false);
		return 0;
	}

	return ((uint64_t)x->ic_base) +
		(XIVE_NOTIFY_PGOFF << x->ic_shift) + offset;
}

/* Manufacture the powerbus packet bits 32:63 */
__attrconst uint32_t xive2_get_notify_base(uint32_t girq)
{
	return (GIRQ_TO_BLK(girq) << 28)  | GIRQ_TO_IDX(girq);
}

static bool xive_get_irq_targetting(uint32_t isn, uint32_t *out_target,
				    uint8_t *out_prio, uint32_t *out_lirq)
{
	struct xive_eas *eas;
	struct xive *x, *end_x;
	struct xive_end *end;
	uint32_t end_blk, end_idx;
	uint32_t vp_blk, vp_idx;
	uint32_t prio, server;
	bool is_escalation = GIRQ_IS_ESCALATION(isn);

	/* Find XIVE on which the EAS resides */
	x = xive_from_isn(isn);
	if (!x)
		return false;
	/* Grab the EAS */
	eas = xive_get_eas(x, isn);
	if (!eas)
		return false;
	if (!xive_get_field64(EAS_VALID, eas->w) && !is_escalation) {
		xive_err(x, "ISN %x lead to invalid EAS !\n", isn);
		return false;
	}

	if (out_lirq)
		*out_lirq = xive_get_field64(EAS_END_DATA, eas->w);

	/* Find the END and its xive instance */
	end_blk = xive_get_field64(EAS_END_BLOCK, eas->w);
	end_idx = xive_get_field64(EAS_END_INDEX, eas->w);
	end_x = xive_from_vc_blk(end_blk);

	/* This can fail if the interrupt hasn't been initialized yet
	 * but it should also be masked, so fail silently
	 */
	if (!end_x)
		goto pick_default;
	end = xive_get_end(end_x, end_idx);
	if (!end)
		goto pick_default;

	/* XXX Check valid and format 0 */

	/* No priority conversion, return the actual one ! */
	if (xive_get_field64(EAS_MASKED, eas->w))
		prio = 0xff;
	else
		prio = xive_get_field32(END_W7_F0_PRIORITY, end->w7);
	if (out_prio)
		*out_prio = prio;

	vp_blk = xive_get_field32(END_W6_VP_BLOCK, end->w6);
	vp_idx = xive_get_field32(END_W6_VP_OFFSET, end->w6);
	server = VP2PIR(vp_blk, vp_idx);

	if (out_target)
		*out_target = server;

	xive_vdbg(end_x, "END info for ISN %x: prio=%d, server=0x%x (VP %x/%x)\n",
		  isn, prio, server, vp_blk, vp_idx);
	return true;

pick_default:
	xive_vdbg(end_x, "END info for ISN %x: Using masked defaults\n", isn);

	if (out_prio)
		*out_prio = 0xff;
	/* Pick a random default, me will be fine ... */
	if (out_target)
		*out_target = mfspr(SPR_PIR);
	return true;
}

static inline bool xive_end_for_target(uint32_t target, uint8_t prio,
				      uint32_t *out_end_blk,
				      uint32_t *out_end_idx)
{
	struct xive *x;
	struct xive_nvp *vp;
	uint32_t vp_blk, vp_idx;
	uint32_t end_blk, end_idx;

	if (prio > xive_max_prio(one_xive))
		return false;

	/* Get the VP block/index from the target word */
	if (!xive_decode_vp(target, &vp_blk, &vp_idx, NULL, NULL))
		return false;

	/* Grab the target VP's XIVE */
	x = xive_from_pc_blk(vp_blk);
	if (!x)
		return false;

	/* Find the VP structrure where we stashed the END number */
	vp = xive_get_vp(x, vp_idx);
	if (!vp)
		return false;

	end_blk = xive_get_field32(NVP_W5_VP_END_BLOCK, vp->w5);
	end_idx = xive_get_field32(NVP_W5_VP_END_INDEX, vp->w5);

	/* Currently the END block and VP block should be the same */
	if (end_blk != vp_blk) {
		xive_err(x, "end_blk != vp_blk (%d vs. %d) for target 0x%08x/%d\n",
			 end_blk, vp_blk, target, prio);
		assert(false);
	}

	if (out_end_blk)
		*out_end_blk = end_blk;
	if (out_end_idx)
		*out_end_idx = end_idx + prio;

	return true;
}

static int64_t xive_set_irq_targetting(uint32_t isn, uint32_t target,
				       uint8_t prio, uint32_t lirq,
				       bool synchronous)
{
	struct xive *x;
	struct xive_eas *eas, new_eas;
	uint32_t end_blk, end_idx;
	bool is_escalation = GIRQ_IS_ESCALATION(isn);
	int64_t rc;

	/* Find XIVE on which the EAS resides */
	x = xive_from_isn(isn);
	if (!x)
		return OPAL_PARAMETER;
	/* Grab the EAS */
	eas = xive_get_eas(x, isn);
	if (!eas)
		return OPAL_PARAMETER;
	if (!xive_get_field64(EAS_VALID, eas->w) && !is_escalation) {
		xive_err(x, "ISN %x lead to invalid EAS !\n", isn);
		return OPAL_PARAMETER;
	}

	lock(&x->lock);

	/* Read existing EAS */
	new_eas = *eas;

	/* Are we masking ? */
	if (prio == 0xff && !is_escalation) {
		new_eas.w = xive_set_field64(EAS_MASKED, new_eas.w, 1);
		xive_vdbg(x, "ISN %x masked !\n", isn);

		/* Put prio 7 in the END */
		prio = xive_max_prio(x);
	} else {
		/* Unmasking */
		new_eas.w = xive_set_field64(EAS_MASKED, new_eas.w, 0);
		xive_vdbg(x, "ISN %x unmasked !\n", isn);

		/* For normal interrupt sources, keep track of which ones
		 * we ever enabled since the last reset
		 */
		if (!is_escalation)
			bitmap_set_bit(*x->int_enabled_map, GIRQ_TO_IDX(isn));
	}

	/* If prio isn't 0xff, re-target the EAS. First find the END
	 * correponding to the target
	 */
	if (prio != 0xff) {
		if (!xive_end_for_target(target, prio, &end_blk, &end_idx)) {
			xive_err(x, "Can't find END for target/prio 0x%x/%d\n",
				 target, prio);
			unlock(&x->lock);
			return OPAL_PARAMETER;
		}

		/* Try to update it atomically to avoid an intermediary
		 * stale state
		 */
		new_eas.w = xive_set_field64(EAS_END_BLOCK, new_eas.w, end_blk);
		new_eas.w = xive_set_field64(EAS_END_INDEX, new_eas.w, end_idx);
	}
	new_eas.w = xive_set_field64(EAS_END_DATA, new_eas.w, lirq);

	xive_vdbg(x,"ISN %x routed to end %x/%x lirq=%08x EAS=%016llx !\n",
		  isn, end_blk, end_idx, lirq, new_eas.w);

	/* Updating the cache differs between real EAS and escalation
	 * EAS inside an END
	 */
	if (is_escalation) {
		rc = xive_escalation_ive_cache_update(x, x->block_id,
				GIRQ_TO_IDX(isn), &new_eas, synchronous);
	} else {
		sync();
		*eas = new_eas;
		rc = xive_easc_scrub(x, x->block_id, GIRQ_TO_IDX(isn));
	}

	unlock(&x->lock);
	return rc;
}

static void xive_update_irq_mask(struct xive_src *s, uint32_t idx, bool masked)
{
	void *mmio_base = s->esb_mmio + (1ul << s->esb_shift) * idx;
	uint32_t offset;

	/* XXX FIXME: A quick mask/umask can make us shoot an interrupt
	 * more than once to a queue. We need to keep track better
	 */
	if (s->flags & XIVE_SRC_EOI_PAGE1)
		mmio_base += 1ull << (s->esb_shift - 1);
	if (masked)
		offset = XIVE_ESB_SET_PQ_01;
	else
		offset = XIVE_ESB_SET_PQ_00;

	in_be64(mmio_base + offset);
}

#define XIVE_SYNC_IPI      0x000
#define XIVE_SYNC_HW       0x080
#define XIVE_SYNC_NxC      0x100
#define XIVE_SYNC_INT      0x180
#define XIVE_SYNC_OS_ESC   0x200
#define XIVE_SYNC_POOL_ESC 0x280
#define XIVE_SYNC_HARD_ESC 0x300

static int64_t xive_sync(struct xive *x __unused)
{
	uint64_t r;
	void *sync_base;

	lock(&x->lock);

	sync_base = x->ic_base + (XIVE_SYNC_POLL_PGOFF << x->ic_shift);

	out_be64(sync_base + XIVE_SYNC_IPI, 0);
	out_be64(sync_base + XIVE_SYNC_HW, 0);
	out_be64(sync_base + XIVE_SYNC_NxC, 0);
	out_be64(sync_base + XIVE_SYNC_INT, 0);
	out_be64(sync_base + XIVE_SYNC_OS_ESC, 0);
	out_be64(sync_base + XIVE_SYNC_POOL_ESC, 0);
	out_be64(sync_base + XIVE_SYNC_HARD_ESC, 0);

	/* XXX Add timeout */
	for (;;) {
		r = xive_regr(x, VC_ENDC_SYNC_DONE);
		if ((r & VC_ENDC_SYNC_POLL_DONE) == VC_ENDC_SYNC_POLL_DONE)
			break;
		cpu_relax();
	}
	xive_regw(x, VC_ENDC_SYNC_DONE, r & ~VC_ENDC_SYNC_POLL_DONE);

	/*
	 * Do a read after clearing the sync done bit to prevent any
	 * race between CI write and next sync command
	 */
	xive_regr(x, VC_ENDC_SYNC_DONE);

	unlock(&x->lock);
	return 0;
}

static int64_t __xive_set_irq_config(struct irq_source *is, uint32_t girq,
				     uint64_t vp, uint8_t prio, uint32_t lirq,
				     bool update_esb, bool sync)
{
	struct xive_src *s = container_of(is, struct xive_src, is);
	uint32_t old_target, vp_blk;
	u8 old_prio;
	int64_t rc;

	/* Grab existing target */
	if (!xive_get_irq_targetting(girq, &old_target, &old_prio, NULL))
		return OPAL_PARAMETER;

	/* Let XIVE configure the END. We do the update without the
	 * synchronous flag, thus a cache update failure will result
	 * in us returning OPAL_BUSY
	 */
	rc = xive_set_irq_targetting(girq, vp, prio, lirq, false);
	if (rc)
		return rc;

	/* Do we need to update the mask ? */
	if (old_prio != prio && (old_prio == 0xff || prio == 0xff)) {
		/* The source has special variants of masking/unmasking */
		if (update_esb) {
			/* Ensure it's enabled/disabled in the source
			 * controller
			 */
			xive_update_irq_mask(s, girq - s->esb_base,
					     prio == 0xff);
		}
	}

	/*
	 * Synchronize the source and old target XIVEs to ensure that
	 * all pending interrupts to the old target have reached their
	 * respective queue.
	 *
	 * WARNING: This assumes the VP and it's queues are on the same
	 *          XIVE instance !
	 */
	if (!sync)
		return OPAL_SUCCESS;
	xive_sync(s->xive);
	if (xive_decode_vp(old_target, &vp_blk, NULL, NULL, NULL)) {
		struct xive *x = xive_from_pc_blk(vp_blk);
		if (x)
			xive_sync(x);
	}

	return OPAL_SUCCESS;
}

static int64_t xive_set_irq_config(uint32_t girq, uint64_t vp, uint8_t prio,
				   uint32_t lirq, bool update_esb)
{
	struct irq_source *is = irq_find_source(girq);

	return __xive_set_irq_config(is, girq, vp, prio, lirq, update_esb,
				     true);
}

static void xive_source_interrupt(struct irq_source *is, uint32_t isn)
{
	struct xive_src *s = container_of(is, struct xive_src, is);

	if (!s->orig_ops || !s->orig_ops->interrupt)
		return;
	s->orig_ops->interrupt(is, isn);
}

static uint64_t xive_source_attributes(struct irq_source *is, uint32_t isn)
{
	struct xive_src *s = container_of(is, struct xive_src, is);

	if (!s->orig_ops || !s->orig_ops->attributes)
		return IRQ_ATTR_TARGET_LINUX;
	return s->orig_ops->attributes(is, isn);
}

static char *xive_source_name(struct irq_source *is, uint32_t isn)
{
	struct xive_src *s = container_of(is, struct xive_src, is);

	if (!s->orig_ops || !s->orig_ops->name)
		return NULL;
	return s->orig_ops->name(is, isn);
}

void xive2_source_mask(struct irq_source *is, uint32_t isn)
{
	struct xive_src *s = container_of(is, struct xive_src, is);

	xive_update_irq_mask(s, isn - s->esb_base, true);
}

static const struct irq_source_ops xive_irq_source_ops = {
	.interrupt = xive_source_interrupt,
	.attributes = xive_source_attributes,
	.name = xive_source_name,
};

static void __xive_register_source(struct xive *x, struct xive_src *s,
				   uint32_t base, uint32_t count,
				   uint32_t shift, void *mmio, uint32_t flags,
				   bool secondary, void *data,
				   const struct irq_source_ops *orig_ops)
{
	s->esb_base = base;
	s->esb_shift = shift;
	s->esb_mmio = mmio;
	s->flags = flags;
	s->orig_ops = orig_ops;
	s->xive = x;
	s->is.start = base;
	s->is.end = base + count;
	s->is.ops = &xive_irq_source_ops;
	s->is.data = data;

	__register_irq_source(&s->is, secondary);
}

void xive2_register_hw_source(uint32_t base, uint32_t count, uint32_t shift,
			     void *mmio, uint32_t flags, void *data,
			     const struct irq_source_ops *ops)
{
	struct xive_src *s;
	struct xive *x = xive_from_isn(base);

	assert(x);

	s = malloc(sizeof(struct xive_src));
	assert(s);
	__xive_register_source(x, s, base, count, shift, mmio, flags,
			       false, data, ops);
}

static void __xive2_register_esb_source(uint32_t base, uint32_t count,
				void *data, const struct irq_source_ops *ops)
{
	struct xive_src *s;
	struct xive *x = xive_from_isn(base);
	uint32_t base_idx = GIRQ_TO_IDX(base);
	void *mmio_base;
	uint32_t flags = XIVE_SRC_EOI_PAGE1 | XIVE_SRC_TRIGGER_PAGE;

	assert(x);

	s = malloc(sizeof(struct xive_src));
	assert(s);

	if (XIVE_CAN_STORE_EOI(x))
		flags |= XIVE_SRC_STORE_EOI;

	/* Callbacks assume the MMIO base corresponds to the first
	 * interrupt of that source structure so adjust it
	 */
	mmio_base = x->esb_base + (1ul << XIVE_ESB_SHIFT) * base_idx;
	__xive_register_source(x, s, base, count, XIVE_ESB_SHIFT, mmio_base,
			       flags, false, data, ops);
}

/*
 * Check that IPI sources have interrupt numbers in the IPI interrupt
 * number range
 */
void xive2_register_ipi_source(uint32_t base, uint32_t count, void *data,
			       const struct irq_source_ops *ops)
{
	struct xive *x = xive_from_isn(base);

	assert(x);
	assert(base >= x->int_base && (base + count) <= x->int_ipi_top);

	__xive2_register_esb_source(base, count, data, ops);
}

/*
 * Some HW sources (PHB) can disable the use of their own ESB pages
 * and offload all the checks on ESB pages of the IC. The interrupt
 * numbers are not necessarily in the IPI range.
 */
void xive2_register_esb_source(uint32_t base, uint32_t count)
{
	__xive2_register_esb_source(base, count, NULL, NULL);
}

uint64_t xive2_get_esb_base(uint32_t base)
{
	struct xive *x = xive_from_isn(base);
	uint32_t base_idx = GIRQ_TO_IDX(base);

	assert(x);

	return (uint64_t) x->esb_base + (1ul << XIVE_ESB_SHIFT) * base_idx;
}

static void xive_set_quirks(struct xive *x, struct proc_chip *chip __unused)
{
	uint64_t quirks = 0;

	/* This extension is dropped for P10 */
	if (proc_gen == proc_gen_p10)
		quirks |= XIVE_QUIRK_THREADID_7BITS;

	/* Broken check on invalid priority when reduced priorities is in use */
	if (proc_gen == proc_gen_p10)
		quirks |= XIVE_QUIRK_BROKEN_PRIO_CHECK;

	xive_dbg(x, "setting XIVE quirks to %016llx\n", quirks);
	x->quirks = quirks;
}

static struct xive *init_one_xive(struct dt_node *np)
{
	struct xive *x;
	struct proc_chip *chip;
	uint32_t flags;

	x = zalloc(sizeof(struct xive));
	assert(x);
	x->x_node = np;
	x->xscom_base = dt_get_address(np, 0, NULL);
	x->chip_id = dt_get_chip_id(np);

	/* "Allocate" a new block ID for the chip */
	x->block_id = xive_block_count++;
	assert (x->block_id < XIVE_MAX_CHIPS);
	xive_block_to_chip[x->block_id] = x->chip_id;
	init_lock(&x->lock);

	chip = get_chip(x->chip_id);
	assert(chip);

	xive_notice(x, "Initializing XIVE block ID %d...\n", x->block_id);
	chip->xive = x;

	xive_set_quirks(x, chip);

	list_head_init(&x->donated_pages);

	/* Base interrupt numbers and allocator init */

	x->int_base	= BLKIDX_TO_GIRQ(x->block_id, 0);
	x->int_count	= x->int_base + XIVE_INT_COUNT;
	x->int_hw_bot	= x->int_count;
	x->int_ipi_top	= x->int_base;

	if (x->int_ipi_top < XIVE_INT_FIRST)
		x->int_ipi_top = XIVE_INT_FIRST;

	/* Allocate a few bitmaps */
	x->end_map = local_alloc(x->chip_id, BITMAP_BYTES(xive_end_bitmap_size(x)), PAGE_SIZE);
	assert(x->end_map);
	memset(x->end_map, 0, BITMAP_BYTES(xive_end_bitmap_size(x)));

	/*
	 * Allocate END index 0 to make sure it can not be used as an
	 * END base for a VP. This is the criteria to know if a VP was
	 * allocated.
	 */
	bitmap_set_bit(*x->end_map, 0);

	x->int_enabled_map = local_alloc(x->chip_id, BITMAP_BYTES(XIVE_INT_COUNT), PAGE_SIZE);
	assert(x->int_enabled_map);
	memset(x->int_enabled_map, 0, BITMAP_BYTES(XIVE_INT_COUNT));
	x->ipi_alloc_map = local_alloc(x->chip_id, BITMAP_BYTES(XIVE_INT_COUNT), PAGE_SIZE);
	assert(x->ipi_alloc_map);
	memset(x->ipi_alloc_map, 0, BITMAP_BYTES(XIVE_INT_COUNT));

	xive_dbg(x, "Handling interrupts [%08x..%08x]\n",
		 x->int_base, x->int_count - 1);

	/* Setup the IC BARs */
	if (!xive_configure_ic_bars(x))
		goto fail;

	/* Some basic global inits such as page sizes etc... */
	if (!xive_config_init(x))
		goto fail;

	/* Configure the set translations for MMIO */
	if (!xive_setup_set_xlate(x))
		goto fail;

	/* Dump some MMIO registers for diagnostics */
	xive_dump_mmio(x);

	/* Pre-allocate a number of tables */
	if (!xive_prealloc_tables(x))
		goto fail;

	/* Setup the XIVE structures BARs */
	if (!xive_configure_bars(x))
		goto fail;

	/*
	 * Configure local tables in VSDs (forward ports will be
	 * handled later)
	 */
	if (!xive_set_local_tables(x))
		goto fail;

	/* Register built-in source controllers (aka IPIs) */
	flags = XIVE_SRC_EOI_PAGE1 | XIVE_SRC_TRIGGER_PAGE;
	if (XIVE_CAN_STORE_EOI(x))
		flags |= XIVE_SRC_STORE_EOI;
	__xive_register_source(x, &x->ipis, x->int_base,
			       x->int_hw_bot - x->int_base, XIVE_ESB_SHIFT,
			       x->esb_base, flags, true, NULL, NULL);

	/* Register escalation sources (ENDs)
	 *
	 * The ESe PQ bits are used for coalescing and the END ESB for
	 * interrupt management. The word 4&5 of the END is the EAS
	 * for the escalation source and the indexing is the same as
	 * the END.
	 *
	 * This is an OPAL primary source, IPIs are secondary.
	 */
	__xive_register_source(x, &x->esc_irqs,
			       MAKE_ESCALATION_GIRQ(x->block_id, 0),
			       XIVE_END_COUNT, XIVE_END_SHIFT,
			       x->end_base, XIVE_SRC_EOI_PAGE1,
			       false, NULL, NULL);


	return x;
 fail:
	xive_err(x, "Initialization failed...\n");

	/* Should this be fatal ? */
	//assert(false);
	return NULL;
}

static void xive_reset_enable_thread(struct cpu_thread *c)
{
	struct proc_chip *chip = get_chip(c->chip_id);
	struct xive *x = chip->xive;
	uint32_t fc, bit;
	uint64_t enable;

	/* Get fused core number */
	fc = (c->pir >> 3) & 0xf;

	/* Get bit in register */
	bit = c->pir & 0x3f;

	/* Get which register to access */
	if (fc < 8) {
		xive_regw(x, TCTXT_EN0_RESET, PPC_BIT(bit));
		xive_regw(x, TCTXT_EN0_SET, PPC_BIT(bit));

		enable = xive_regr(x, TCTXT_EN0);
		if (!(enable & PPC_BIT(bit)))
			xive_cpu_err(c, "Failed to enable thread\n");
	} else {
		xive_regw(x, TCTXT_EN1_RESET, PPC_BIT(bit));
		xive_regw(x, TCTXT_EN1_SET, PPC_BIT(bit));

		enable = xive_regr(x, TCTXT_EN1);
		if (!(enable & PPC_BIT(bit)))
			xive_cpu_err(c, "Failed to enable thread\n");
	}
}

void xive2_cpu_callin(struct cpu_thread *cpu)
{
	struct xive_cpu_state *xs = cpu->xstate;
	uint8_t old_w2 __unused, w2 __unused;

	if (!xs)
		return;

	/* Reset the HW thread context and enable it */
	xive_reset_enable_thread(cpu);

	/* Set VT to 1 */
	old_w2 = in_8(xs->tm_ring1 + TM_QW3_HV_PHYS + TM_WORD2);
	out_8(xs->tm_ring1 + TM_QW3_HV_PHYS + TM_WORD2, 0x80);
	w2 = in_8(xs->tm_ring1 + TM_QW3_HV_PHYS + TM_WORD2);

	xive_cpu_vdbg(cpu, "Initialized TIMA VP=%x/%x W01=%016llx W2=%02x->%02x\n",
		      xs->vp_blk, xs->vp_idx,
		      in_be64(xs->tm_ring1 + TM_QW3_HV_PHYS),
		      old_w2, w2);
}

#ifdef XIVE_EXTRA_CHECK_INIT_CACHE
#define CHECK_INIT_CACHE_LOOP 0x100
static void xive_special_cache_check(struct xive *x, uint32_t blk, uint32_t idx)
{
	struct xive_nvp vp = {0};
	uint32_t i;

	/*
	 * SIMICS checks the value of reserved fields
	 */
	if (chip_quirk(QUIRK_SIMICS))
		return;

	for (i = 0; i < CHECK_INIT_CACHE_LOOP; i++) {
		struct xive_nvp *vp_m = xive_get_vp(x, idx);

		memset(vp_m, (~i) & 0xff, sizeof(*vp_m));
		sync();
		vp.w1 = (i << 16) | i;
		assert(!xive_nxc_cache_update(x, blk, idx, &vp, true));
		if (!xive_check_nxc_update(x, idx, &vp)) {
			xive_dbg(x, "NXC update test failed at %d iterations\n", i);
			return;
		}
	}
	xive_dbg(x, "NXC update test passed for %d/0x%x\n", blk, idx);
}
#else
static inline void xive_special_cache_check(struct xive *x __unused,
					    uint32_t blk __unused,
					    uint32_t idx __unused)
{
}
#endif

static void xive_init_cpu_exploitation(struct xive_cpu_state *xs)
{
	struct xive_end end;
	struct xive_nvp vp;
	struct xive *x_vp, *x_end;
	int i;

	/* Grab the XIVE where the VP resides. It could be different from
	 * the local chip XIVE if not using block group mode
	 */
	x_vp = xive_from_pc_blk(xs->vp_blk);
	assert(x_vp);

	/* Grab the XIVE where the END resides. It should be the same
	 * as the VP.
	 */
	x_end = xive_from_vc_blk(xs->end_blk);
	assert(x_end);

	xive_init_hw_end(&end);

	/* Use the cache watch to update all ENDs reserved for HW VPs */
	lock(&x_end->lock);
	for (i = 0; i < xive_cfg_vp_prio(x_end); i++)
		xive_endc_cache_update(x_end, xs->end_blk, xs->end_idx + i,
				       &end, true);
	unlock(&x_end->lock);

	/* Initialize/enable the VP */
	xive_init_default_vp(&vp, xs->end_blk, xs->end_idx);

	/* Use the cache watch to write it out */
	lock(&x_vp->lock);
	xive_special_cache_check(x_vp, xs->vp_blk, xs->vp_idx);
	xive_nxc_cache_update(x_vp, xs->vp_blk, xs->vp_idx, &vp, true);
	unlock(&x_vp->lock);
}

static void xive_configure_ex_special_bar(struct xive *x, struct cpu_thread *c)
{
	uint64_t xa, val;
	int64_t rc;

	xive_cpu_vdbg(c, "Setting up special BAR\n");
	xa = XSCOM_ADDR_P10_NCU(pir_to_core_id(c->pir), P10_NCU_SPEC_BAR);
	val = (uint64_t)x->tm_base | P10_NCU_SPEC_BAR_ENABLE;
	if (x->tm_shift == 16)
		val |= P10_NCU_SPEC_BAR_256K;
	xive_cpu_vdbg(c, "NCU_SPEC_BAR_XA[%08llx]=%016llx\n", xa, val);
	rc = xscom_write(c->chip_id, xa, val);
	if (rc) {
		xive_cpu_err(c, "Failed to setup NCU_SPEC_BAR\n");
		/* XXXX  what do do now ? */
	}
}

void xive2_late_init(void)
{
	struct cpu_thread *c;

	prlog(PR_INFO, "SLW: Configuring self-restore for NCU_SPEC_BAR\n");
	for_each_present_cpu(c) {
		if(cpu_is_thread0(c)) {
			struct proc_chip *chip = get_chip(c->chip_id);
			struct xive *x = chip->xive;
			uint64_t xa, val, rc;
			xa = XSCOM_ADDR_P10_NCU(pir_to_core_id(c->pir), P10_NCU_SPEC_BAR);
			val = (uint64_t)x->tm_base | P10_NCU_SPEC_BAR_ENABLE;
			/* Bail out if wakeup engine has already failed */
			if (wakeup_engine_state != WAKEUP_ENGINE_PRESENT) {
				prlog(PR_ERR, "XIVE proc_stop_api fail detected\n");
				break;
			}
			rc = proc_stop_save_scom((void *)chip->homer_base, xa, val,
				PROC_STOP_SCOM_REPLACE, PROC_STOP_SECTION_L3);
			if (rc) {
				xive_cpu_err(c, "proc_stop_save_scom failed for NCU_SPEC_BAR rc=%lld\n",
					     rc);
				wakeup_engine_state = WAKEUP_ENGINE_FAILED;
			}
		}
	}
}

static void xive_provision_cpu(struct xive_cpu_state *xs, struct cpu_thread *c)
{
	struct xive *x;

	/* VP ids for HW threads are pre-allocated */
	xs->vp_blk = PIR2VP_BLK(c->pir);
	xs->vp_idx = PIR2VP_IDX(c->pir);

	/* For now we use identical block IDs for VC and PC but that might
	 * change. We allocate the ENDs on the same XIVE as the VP.
	 */
	xs->end_blk = xs->vp_blk;

	/* Grab the XIVE where the END resides. It could be different from
	 * the local chip XIVE if not using block group mode
	 */
	x = xive_from_vc_blk(xs->end_blk);
	assert(x);

	/* Allocate a set of ENDs for that VP */
	xs->end_idx = xive_alloc_end_set(x, true);
	assert(!XIVE_ALLOC_IS_ERR(xs->end_idx));
}

static void xive_init_cpu(struct cpu_thread *c)
{
	struct proc_chip *chip = get_chip(c->chip_id);
	struct xive *x = chip->xive;
	struct xive_cpu_state *xs;

	if (!x)
		return;

	/*
	 * Each core pair (EX) needs this special BAR setup to have the
	 * right powerbus cycle for the TM area (as it has the same address
	 * on all chips so it's somewhat special).
	 *
	 * Because we don't want to bother trying to figure out which core
	 * of a pair is present we just do the setup for each of them, which
	 * is harmless.
	 */
	if (cpu_is_thread0(c) || cpu_is_core_chiplet_primary(c))
		xive_configure_ex_special_bar(x, c);

	/* Initialize the state structure */
	c->xstate = xs = local_alloc(c->chip_id, sizeof(struct xive_cpu_state), 1);
	assert(xs);
	memset(xs, 0, sizeof(struct xive_cpu_state));
	xs->xive = x;

	init_lock(&xs->lock);

	/* Shortcut to TM HV ring */
	xs->tm_ring1 = x->tm_base + (1u << x->tm_shift);

	/* Provision a VP id and some ENDs for a HW thread */
	xive_provision_cpu(xs, c);

	xive_init_cpu_exploitation(xs);
}

static uint64_t xive_convert_irq_flags(uint64_t iflags)
{
	uint64_t oflags = 0;

	if (iflags & XIVE_SRC_STORE_EOI)
		oflags |= OPAL_XIVE_IRQ_STORE_EOI2;

	/* OPAL_XIVE_IRQ_TRIGGER_PAGE is only meant to be set if
	 * the interrupt has a *separate* trigger page.
	 */
	if ((iflags & XIVE_SRC_EOI_PAGE1) &&
	    (iflags & XIVE_SRC_TRIGGER_PAGE))
		oflags |= OPAL_XIVE_IRQ_TRIGGER_PAGE;

	if (iflags & XIVE_SRC_LSI)
		oflags |= OPAL_XIVE_IRQ_LSI;

	return oflags;
}

static int64_t opal_xive_get_irq_info(uint32_t girq,
				      beint64_t *out_flags,
				      beint64_t *out_eoi_page,
				      beint64_t *out_trig_page,
				      beint32_t *out_esb_shift,
				      beint32_t *out_src_chip)
{
	struct irq_source *is = irq_find_source(girq);
	struct xive_src *s = container_of(is, struct xive_src, is);
	uint32_t idx;
	uint64_t mm_base;
	uint64_t eoi_page = 0, trig_page = 0;

	if (xive_mode != XIVE_MODE_EXPL)
		return OPAL_WRONG_STATE;
	if (is == NULL || out_flags == NULL)
		return OPAL_PARAMETER;
	assert(is->ops == &xive_irq_source_ops);

	if (out_flags)
		*out_flags = cpu_to_be64(xive_convert_irq_flags(s->flags));

	idx = girq - s->esb_base;

	if (out_esb_shift)
		*out_esb_shift = cpu_to_be32(s->esb_shift);

	mm_base = (uint64_t)s->esb_mmio + (1ull << s->esb_shift) * idx;

	/* The EOI page can either be the first or second page */
	if (s->flags & XIVE_SRC_EOI_PAGE1) {
		uint64_t p1off = 1ull << (s->esb_shift - 1);
		eoi_page = mm_base + p1off;
	} else
		eoi_page = mm_base;

	/* The trigger page, if it exists, is always the first page */
	if (s->flags & XIVE_SRC_TRIGGER_PAGE)
		trig_page = mm_base;

	if (out_eoi_page)
		*out_eoi_page = cpu_to_be64(eoi_page);
	if (out_trig_page)
		*out_trig_page = cpu_to_be64(trig_page);
	if (out_src_chip)
		*out_src_chip = cpu_to_be32(GIRQ_TO_CHIP(girq));

	return OPAL_SUCCESS;
}

static int64_t opal_xive_get_irq_config(uint32_t girq,
					beint64_t *out_vp,
					uint8_t *out_prio,
					beint32_t *out_lirq)
{
	uint32_t vp;
	uint32_t lirq;
	uint8_t prio;

	if (xive_mode != XIVE_MODE_EXPL)
               return OPAL_WRONG_STATE;

	if (xive_get_irq_targetting(girq, &vp, &prio, &lirq)) {
		*out_vp = cpu_to_be64(vp);
		*out_prio = prio;
		*out_lirq = cpu_to_be32(lirq);
		return OPAL_SUCCESS;
	} else
		return OPAL_PARAMETER;
}

static int64_t opal_xive_set_irq_config(uint32_t girq,
					uint64_t vp,
					uint8_t prio,
					uint32_t lirq)
{
	/*
	 * This variant is meant for a XIVE-aware OS, thus it will
	 * *not* affect the ESB state of the interrupt. If used with
	 * a prio of FF, the EAS will be masked. In that case the
	 * races have to be handled by the OS.
	 */
	if (xive_mode != XIVE_MODE_EXPL)
               return OPAL_WRONG_STATE;

	return xive_set_irq_config(girq, vp, prio, lirq, false);
}

static int64_t opal_xive_get_queue_info(uint64_t vp, uint32_t prio,
					beint64_t *out_qpage,
					beint64_t *out_qsize,
					beint64_t *out_qeoi_page,
					beint32_t *out_escalate_irq,
					beint64_t *out_qflags)
{
	uint32_t blk, idx;
	struct xive *x;
	struct xive_end *end;

	if (xive_mode != XIVE_MODE_EXPL)
               return OPAL_WRONG_STATE;

	if (!xive_end_for_target(vp, prio, &blk, &idx))
		return OPAL_PARAMETER;

	x = xive_from_vc_blk(blk);
	if (!x)
		return OPAL_PARAMETER;

	end = xive_get_end(x, idx);
	if (!end)
		return OPAL_PARAMETER;

	if (out_escalate_irq) {
		uint32_t esc_idx = idx;

		/* If escalations are routed to a single queue, fix up
		 * the escalation interrupt number here.
		 */
		if (xive_get_field32(END_W0_UNCOND_ESCALATE, end->w0))
			esc_idx |= xive_escalation_prio(x);
		*out_escalate_irq =
			cpu_to_be32(MAKE_ESCALATION_GIRQ(blk, esc_idx));
	}

	/* If this is a single-escalation gather queue, that's all
	 * there is to return
	 */
	if (xive_get_field32(END_W0_SILENT_ESCALATE, end->w0)) {
		if (out_qflags)
			*out_qflags = 0;
		if (out_qpage)
			*out_qpage = 0;
		if (out_qsize)
			*out_qsize = 0;
		if (out_qeoi_page)
			*out_qeoi_page = 0;
		return OPAL_SUCCESS;
	}

	if (out_qpage) {
		if (xive_get_field32(END_W0_ENQUEUE, end->w0))
			*out_qpage = cpu_to_be64(
				((uint64_t)xive_get_field32(END_W2_EQ_ADDR_HI, end->w2) << 32) |
				xive_get_field32(END_W3_EQ_ADDR_LO, end->w3));
		else
			*out_qpage = 0;
	}
	if (out_qsize) {
		if (xive_get_field32(END_W0_ENQUEUE, end->w0))
			*out_qsize = cpu_to_be64(xive_get_field32(END_W3_QSIZE, end->w3) + 12);
		else
			*out_qsize = 0;
	}
	if (out_qeoi_page) {
		*out_qeoi_page = cpu_to_be64(
			(uint64_t)x->end_base + idx * XIVE_ESB_PAGE_SIZE);
	}
	if (out_qflags) {
		*out_qflags = 0;
		if (xive_get_field32(END_W0_VALID, end->w0))
			*out_qflags |= cpu_to_be64(OPAL_XIVE_EQ_ENABLED);
		if (xive_get_field32(END_W0_UCOND_NOTIFY, end->w0))
			*out_qflags |= cpu_to_be64(OPAL_XIVE_EQ_ALWAYS_NOTIFY);
		if (xive_get_field32(END_W0_ESCALATE_CTL, end->w0))
			*out_qflags |= cpu_to_be64(OPAL_XIVE_EQ_ESCALATE);
	}

	return OPAL_SUCCESS;
}

static void xive_cleanup_end(struct xive_end *end)
{
	end->w0 = xive_set_field32(END_W0_FIRMWARE1, 0, xive_end_is_firmware1(end));
	end->w1 = xive_set_field32(END_W1_ESe_Q, 0, 1) |
		  xive_set_field32(END_W1_ESn_Q, 0, 1);
	end->w2 = end->w3 = end->w4 = end->w5 = end->w6 = end->w7 = 0;
}

static int64_t opal_xive_set_queue_info(uint64_t vp, uint32_t prio,
					uint64_t qpage,
					uint64_t qsize,
					uint64_t qflags)
{
	uint32_t blk, idx;
	struct xive *x;
	struct xive_end *old_end;
	struct xive_end end;
	uint32_t vp_blk, vp_idx;
	bool group;
	int64_t rc;

	if (!xive_end_for_target(vp, prio, &blk, &idx))
		return OPAL_PARAMETER;

	x = xive_from_vc_blk(blk);
	if (!x)
		return OPAL_PARAMETER;

	old_end = xive_get_end(x, idx);
	if (!old_end)
		return OPAL_PARAMETER;

	/* If this is a silent escalation queue, it cannot be
	 * configured directly
	 */
	if (xive_get_field32(END_W0_SILENT_ESCALATE, old_end->w0))
		return OPAL_PARAMETER;

	/* This shouldn't fail or xive_end_for_target would have
	 * failed already
	 */
	if (!xive_decode_vp(vp, &vp_blk, &vp_idx, NULL, &group))
		return OPAL_PARAMETER;

	/*
	 * Make a local copy which we will later try to commit using
	 * the cache watch facility
	 */
	end = *old_end;

	if (qflags & OPAL_XIVE_EQ_ENABLED) {
		switch(qsize) {
			/* Supported sizes */
		case 12:
		case 16:
		case 21:
		case 24:
			end.w3 = cpu_to_be32(qpage & END_W3_EQ_ADDR_LO);
			end.w2 = cpu_to_be32((qpage >> 32) & END_W2_EQ_ADDR_HI);
			end.w3 = xive_set_field32(END_W3_QSIZE, end.w3, qsize - 12);
			end.w0 = xive_set_field32(END_W0_ENQUEUE, end.w0, 1);
			break;
		case 0:
			end.w2 = end.w3 = 0;
			end.w0 = xive_set_field32(END_W0_ENQUEUE, end.w0, 0);
			break;
		default:
			return OPAL_PARAMETER;
		}

		/* Ensure the priority and target are correctly set (they will
		 * not be right after allocation
		 */
		end.w6 = xive_set_field32(END_W6_VP_BLOCK, 0, vp_blk) |
			xive_set_field32(END_W6_VP_OFFSET, 0, vp_idx);
		end.w7 = xive_set_field32(END_W7_F0_PRIORITY, 0, prio);
		/* XXX Handle group i bit when needed */

		/* Always notify flag */
		if (qflags & OPAL_XIVE_EQ_ALWAYS_NOTIFY)
			end.w0 = xive_set_field32(END_W0_UCOND_NOTIFY, end.w0, 1);
		else
			end.w0 = xive_set_field32(END_W0_UCOND_NOTIFY, end.w0, 0);

		/* Escalation flag */
		if (qflags & OPAL_XIVE_EQ_ESCALATE)
			end.w0 = xive_set_field32(END_W0_ESCALATE_CTL, end.w0, 1);
		else
			end.w0 = xive_set_field32(END_W0_ESCALATE_CTL, end.w0, 0);

		/* Unconditionally clear the current queue pointer, set
		 * generation to 1 and disable escalation interrupts.
		 */
		end.w1 = xive_set_field32(END_W1_GENERATION, 0, 1) |
			 xive_set_field32(END_W1_ES, 0, xive_get_field32(END_W1_ES, old_end->w1));

		/* Enable. We always enable backlog for an enabled queue
		 * otherwise escalations won't work.
		 */
		end.w0 = xive_set_field32(END_W0_VALID, end.w0, 1);
		end.w0 = xive_set_field32(END_W0_BACKLOG, end.w0, 1);
	} else
		xive_cleanup_end(&end);

	/* Update END, non-synchronous */
	lock(&x->lock);
	rc = xive_endc_cache_update(x, blk, idx, &end, false);
	unlock(&x->lock);

	return rc;
}

static int64_t opal_xive_get_queue_state(uint64_t vp, uint32_t prio,
					 beint32_t *out_qtoggle,
					 beint32_t *out_qindex)
{
	uint32_t blk, idx;
	struct xive *x;
	struct xive_end *end;
	int64_t rc;

	if (xive_mode != XIVE_MODE_EXPL)
		return OPAL_WRONG_STATE;

	if (!out_qtoggle || !out_qindex ||
	    !xive_end_for_target(vp, prio, &blk, &idx))
		return OPAL_PARAMETER;

	x = xive_from_vc_blk(blk);
	if (!x)
		return OPAL_PARAMETER;

	end = xive_get_end(x, idx);
	if (!end)
		return OPAL_PARAMETER;

	/* Scrub the queue */
	lock(&x->lock);
	rc = xive_endc_scrub(x, blk, idx);
	unlock(&x->lock);
	if (rc)
		return rc;

	/* We don't do disable queues */
	if (!xive_get_field32(END_W0_VALID, end->w0))
		return OPAL_WRONG_STATE;

	*out_qtoggle = cpu_to_be32(xive_get_field32(END_W1_GENERATION, end->w1));
	*out_qindex  = cpu_to_be32(xive_get_field32(END_W1_PAGE_OFF, end->w1));

	return OPAL_SUCCESS;
}

static int64_t opal_xive_set_queue_state(uint64_t vp, uint32_t prio,
					 uint32_t qtoggle, uint32_t qindex)
{
	uint32_t blk, idx;
	struct xive *x;
	struct xive_end *end, new_end;
	int64_t rc;

	if (xive_mode != XIVE_MODE_EXPL)
		return OPAL_WRONG_STATE;

	if (!xive_end_for_target(vp, prio, &blk, &idx))
		return OPAL_PARAMETER;

	x = xive_from_vc_blk(blk);
	if (!x)
		return OPAL_PARAMETER;

	end = xive_get_end(x, idx);
	if (!end)
		return OPAL_PARAMETER;

	/* We don't do disable queues */
	if (!xive_get_field32(END_W0_VALID, end->w0))
		return OPAL_WRONG_STATE;

	new_end = *end;

	new_end.w1 = xive_set_field32(END_W1_GENERATION, new_end.w1, qtoggle);
	new_end.w1 = xive_set_field32(END_W1_PAGE_OFF, new_end.w1, qindex);

	lock(&x->lock);
	rc = xive_endc_cache_update(x, blk, idx, &new_end, false);
	unlock(&x->lock);

	return rc;
}

static int64_t opal_xive_donate_page(uint32_t chip_id, uint64_t addr)
{
	struct proc_chip *c = get_chip(chip_id);
	struct list_node *n;

	if (xive_mode != XIVE_MODE_EXPL)
		return OPAL_WRONG_STATE;
	if (!c)
		return OPAL_PARAMETER;
	if (!c->xive)
		return OPAL_PARAMETER;
	if (addr & 0xffff)
		return OPAL_PARAMETER;

	n = (struct list_node *)addr;
	lock(&c->xive->lock);
	list_add(&c->xive->donated_pages, n);
	unlock(&c->xive->lock);
	return OPAL_SUCCESS;
}

static int64_t opal_xive_get_vp_info(uint64_t vp_id,
				     beint64_t *out_flags,
				     beint64_t *out_cam_value,
				     beint64_t *out_report_cl_pair,
				     beint32_t *out_chip_id)
{
	struct xive *x;
	struct xive_nvp *vp;
	uint32_t blk, idx;
	bool group;

	if (!xive_decode_vp(vp_id, &blk, &idx, NULL, &group))
		return OPAL_PARAMETER;
	/* We don't do groups yet */
	if (group)
		return OPAL_PARAMETER;
	x = xive_from_pc_blk(blk);
	if (!x)
		return OPAL_PARAMETER;
	vp = xive_get_vp(x, idx);
	if (!vp)
		return OPAL_PARAMETER;

	if (out_flags) {
		uint32_t end_blk, end_idx;
		struct xive_end *end;
		struct xive *end_x;
		*out_flags = 0;

		/*
		 * We would like to a way to stash a SW bit in the VP
		 * to know whether silent escalation is enabled or
		 * not, but unlike what happens with ENDs, the PC
		 * cache watch doesn't implement the reserved bit in
		 * the VPs... so we have to go look at END 7 instead.
		 */

		/* Grab END for prio 7 to check for silent escalation */
		if (!xive_end_for_target(vp_id, xive_escalation_prio(x),
					 &end_blk, &end_idx))
			return OPAL_PARAMETER;

		end_x = xive_from_vc_blk(end_blk);
		if (!end_x)
			return OPAL_PARAMETER;

		end = xive_get_end(x, end_idx);
		if (!end)
			return OPAL_PARAMETER;
		if (xive_get_field32(NVP_W0_VALID, vp->w0))
			*out_flags |= cpu_to_be64(OPAL_XIVE_VP_ENABLED);
		if (xive_cfg_save_restore(x))
			*out_flags |= cpu_to_be64(OPAL_XIVE_VP_SAVE_RESTORE);
		if (xive_get_field32(END_W0_SILENT_ESCALATE, end->w0))
			*out_flags |= cpu_to_be64(OPAL_XIVE_VP_SINGLE_ESCALATION);
	}

	if (out_cam_value) {
		uint64_t cam_value;

		cam_value = (blk << x->vp_shift) | idx;

		/*
		 * If save-restore is enabled, force the CAM line
		 * value with the H bit.
		 */
		if (xive_cfg_save_restore(x))
			cam_value |= TM10_QW1W2_HO;

		*out_cam_value = cpu_to_be64(cam_value);
	}

	if (out_report_cl_pair) {
		uint64_t report_cl_pair;

		report_cl_pair = ((uint64_t)(be32_to_cpu(vp->w6) & 0x0fffffff)) << 32;
		report_cl_pair |= be32_to_cpu(vp->w7) & 0xffffff00;

		*out_report_cl_pair = cpu_to_be64(report_cl_pair);
	}

	if (out_chip_id)
		*out_chip_id = cpu_to_be32(xive_block_to_chip[blk]);

	return OPAL_SUCCESS;
}

static int64_t xive_setup_silent_gather(uint64_t vp_id, bool enable)
{
	uint32_t blk, idx, i;
	struct xive_end *end_orig;
	struct xive_end end;
	struct xive *x;
	int64_t rc;

	/* Get base END block */
	if (!xive_end_for_target(vp_id, 0, &blk, &idx)) {
		prlog(PR_ERR, "%s: Invalid VP 0x%08llx\n", __func__, vp_id);
		return OPAL_PARAMETER;
	}
	x = xive_from_vc_blk(blk);
	if (!x) {
		prlog(PR_ERR, "%s: VP 0x%08llx has invalid block %d\n", __func__,
		      vp_id, blk);
		return OPAL_PARAMETER;
	}

	/* Grab prio 7 */
	end_orig = xive_get_end(x, idx + xive_escalation_prio(x));
	if (!end_orig) {
		xive_err(x, "Failed to get silent gather END 0x%x for VP 0x%08llx\n",
			 idx + xive_escalation_prio(x), vp_id);
		return OPAL_PARAMETER;
	}

	/* If trying to enable silent gather, make sure prio 7 is not
	 * already enabled as a normal queue
	 */
	if (enable && xive_get_field32(END_W0_VALID, end_orig->w0) &&
	    !xive_get_field32(END_W0_SILENT_ESCALATE, end_orig->w0)) {
		xive_err(x, "silent gather END 0x%x already in use\n",
			 idx + xive_escalation_prio(x));
		return OPAL_PARAMETER;
	}

	end = *end_orig;

	if (enable) {
		/* W0: Enabled and "s" set, no other bit */
		end.w0 = xive_set_field32(END_W0_FIRMWARE1, end.w0, 0);
		end.w0 = xive_set_field32(END_W0_VALID, end.w0, 1);
		end.w0 = xive_set_field32(END_W0_SILENT_ESCALATE, end.w0, 1);
		end.w0 = xive_set_field32(END_W0_ESCALATE_CTL, end.w0, 1);
		end.w0 = xive_set_field32(END_W0_BACKLOG, end.w0, 1);

		/* Set new "N" for END escalation (vs. ESB)  */
		end.w0 = xive_set_field32(END_W0_ESCALATE_END, end.w0, 1);

		/* W1: Mark ESn as 01, ESe as 00 */
		end.w1 = xive_set_field32(END_W1_ESn_P, end.w1, 0);
		end.w1 = xive_set_field32(END_W1_ESn_Q, end.w1, 1);
		end.w1 = xive_set_field32(END_W1_ESe, end.w1, 0);
	} else if (xive_get_field32(END_W0_SILENT_ESCALATE, end.w0))
		xive_cleanup_end(&end);

	if (!memcmp(end_orig, &end, sizeof(end)))
		rc = 0;
	else
		rc = xive_endc_cache_update(x, blk, idx + xive_escalation_prio(x),
					    &end, false);
	if (rc)
		return rc;

	/* Mark/unmark all other prios with the new "u" bit and update
	 * escalation
	 */
	for (i = 0; i < xive_cfg_vp_prio(x); i++) {
		if (i == xive_escalation_prio(x))
			continue;
		end_orig = xive_get_end(x, idx + i);
		if (!end_orig)
			continue;
		end = *end_orig;
		if (enable) {
			/* Set "u" bit */
			end.w0 = xive_set_field32(END_W0_UNCOND_ESCALATE, end.w0, 1);

			/* Set new "N" for END escalation (vs. ESB)  */
			/* TODO (Gen2+) : use ESB escalation configuration */
			end.w0 = xive_set_field32(END_W0_ESCALATE_END, end.w0, 1);

			/* Re-route escalation interrupt (previous
			 * route is lost !) to the gather queue
			 */
			end.w4 = xive_set_field32(END_W4_END_BLOCK, end.w4, blk);
			end.w4 = xive_set_field32(END_W4_ESC_END_INDEX,
					  end.w4, idx + xive_escalation_prio(x));
		} else if (xive_get_field32(END_W0_UNCOND_ESCALATE, end.w0)) {
			/* Clear the "u" bit, disable escalations if it was set */
			end.w0 = xive_set_field32(END_W0_UNCOND_ESCALATE, end.w0, 0);
			end.w0 = xive_set_field32(END_W0_ESCALATE_CTL, end.w0, 0);
		}
		if (!memcmp(end_orig, &end, sizeof(end)))
			continue;
		rc = xive_endc_cache_update(x, blk, idx + i, &end, false);
		if (rc)
			break;
	}

	return rc;
}

static int64_t opal_xive_set_vp_info(uint64_t vp_id,
				     uint64_t flags,
				     uint64_t report_cl_pair)
{
	struct xive *x;
	struct xive_nvp *vp, vp_new;
	uint32_t blk, idx;
	bool group;
	int64_t rc;

	if (!xive_decode_vp(vp_id, &blk, &idx, NULL, &group))
		return OPAL_PARAMETER;
	/* We don't do groups yet */
	if (group)
		return OPAL_PARAMETER;
	if (report_cl_pair & 0xff)
		return OPAL_PARAMETER;
	x = xive_from_pc_blk(blk);
	if (!x)
		return OPAL_PARAMETER;
	vp = xive_get_vp(x, idx);
	if (!vp)
		return OPAL_PARAMETER;

	/* Consistency check. */
	if ((flags & OPAL_XIVE_VP_SAVE_RESTORE) && !xive_cfg_save_restore(x))
		return OPAL_PARAMETER;

	lock(&x->lock);

	vp_new = *vp;
	if (flags & OPAL_XIVE_VP_ENABLED) {
		vp_new.w0 = xive_set_field32(NVP_W0_VALID, vp_new.w0, 1);
		vp_new.w6 = cpu_to_be32(report_cl_pair >> 32);
		vp_new.w7 = cpu_to_be32(report_cl_pair & 0xffffffff);

		if (flags & OPAL_XIVE_VP_SINGLE_ESCALATION)
			rc = xive_setup_silent_gather(vp_id, true);
		else
			rc = xive_setup_silent_gather(vp_id, false);

		/*
		 * Prepare NVP to be HW owned for automatic save-restore
		 */
		if (xive_cfg_save_restore(x)) {
			/*
			 * Set NVP privilege level. Default to OS.
			 * This check only makes sense for KVM guests
			 * currently. We would need an extra flag to
			 * distinguish from pool level.
			 */
			vp_new.w0 = xive_set_field32(NVP_W0_VPRIV, vp_new.w0, 0);

			vp_new.w2 = xive_set_field32(NVP_W2_CPPR, vp_new.w2, 0xFF);
			vp_new.w0 = xive_set_field32(NVP_W0_HW, vp_new.w0, 1);
		}
	} else {
		/*
		 * TODO (kvm): disabling a VP invalidates the associated ENDs.
		 *
		 * The loads then return all 1s which can be an issue for the
		 * Linux code to handle.
		 */

		vp_new.w0 = vp_new.w6 = vp_new.w7 = 0;
		rc = xive_setup_silent_gather(vp_id, false);
	}

	if (rc) {
		if (rc != OPAL_BUSY)
			xive_dbg(x, "Silent gather setup failed with err %lld\n", rc);
		goto bail;
	}

	rc = xive_nxc_cache_update(x, blk, idx, &vp_new, false);
	if (rc)
		goto bail;

	/* When disabling, we scrub clean (invalidate the entry) so
	 * we can avoid cache ops in alloc/free
	 */
	if (!(flags & OPAL_XIVE_VP_ENABLED))
		xive_nxc_scrub_clean(x, blk, idx);

bail:
	unlock(&x->lock);
	return rc;
}

static int64_t opal_xive_get_vp_state(uint64_t vp_id, beint64_t *out_state)
{
	struct xive *x;
	struct xive_nvp *vp;
	uint32_t blk, idx;
	int64_t rc;
	bool group;

	if (!out_state || !xive_decode_vp(vp_id, &blk, &idx, NULL, &group))
		return OPAL_PARAMETER;
	if (group)
		return OPAL_PARAMETER;
	x = xive_from_pc_blk(blk);
	if (!x)
		return OPAL_PARAMETER;
	vp = xive_get_vp(x, idx);
	if (!vp)
		return OPAL_PARAMETER;

	/* Scrub the vp */
	lock(&x->lock);
	rc = xive_nxc_scrub(x, blk, idx);
	unlock(&x->lock);
	if (rc)
		return rc;

	if (!xive_get_field32(NVP_W0_VALID, vp->w0))
		return OPAL_WRONG_STATE;

	/*
	 * return a state matching the layout of WORD 0-1 of the TIMA
	 * as this is expected by current implementation.
	 */
	*out_state = cpu_to_be64(((uint64_t) 0x0) << 54 |
		(uint64_t)xive_get_field32(NVP_W2_CPPR, vp->w2)  << 48 |
		(uint64_t)xive_get_field32(NVP_W2_IPB,  vp->w2)  << 40 |
		(uint64_t)xive_get_field32(NVP_W2_LSMFB, vp->w2) << 32);

	return OPAL_SUCCESS;
}

static void *xive_cpu_get_tima(struct cpu_thread *c)
{
	struct xive_cpu_state *xs = c->xstate;
	struct xive *x = xs->xive;

	return x->ic_tm_direct_base + ((c->pir & 0xff) << x->ic_shift);
}

static void xive_cleanup_cpu_tima(struct cpu_thread *c)
{
	struct xive_cpu_state *xs __unused = c->xstate;
	void *cpu_tm_base = xive_cpu_get_tima(c);
	uint8_t old_w2 __unused, w2 __unused;

	/* Reset the HW context */
	xive_reset_enable_thread(c);

	/* Set VT to 1 */
	old_w2 = in_8(cpu_tm_base + TM_QW3_HV_PHYS + TM_WORD2);
	out_8(cpu_tm_base + TM_QW3_HV_PHYS + TM_WORD2, 0x80);
	w2 = in_8(cpu_tm_base + TM_QW3_HV_PHYS + TM_WORD2);

	/* Dump HV state */
	xive_cpu_vdbg(c, "[reset] VP TIMA VP=%x/%x W01=%016llx W2=%02x->%02x\n",
		      xs->vp_blk, xs->vp_idx,
		      in_be64(cpu_tm_base + TM_QW3_HV_PHYS),
		      old_w2, w2);
}

static int64_t xive_vc_ind_cache_kill(struct xive *x, uint64_t type)
{
	uint64_t val;

	/* We clear the whole thing */
	xive_regw(x, VC_AT_MACRO_KILL_MASK, 0);
	xive_regw(x, VC_AT_MACRO_KILL, VC_AT_MACRO_KILL_VALID |
		  SETFIELD(VC_AT_MACRO_KILL_VSD, 0ull, type));

	/* XXX Add timeout */
	for (;;) {
		val = xive_regr(x, VC_AT_MACRO_KILL);
		if (!(val & VC_AT_MACRO_KILL_VALID))
			break;
	}
	return 0;
}

static int64_t xive_pc_ind_cache_kill(struct xive *x)
{
	uint64_t val;

	/* We clear the whole thing */
	xive_regw(x, PC_AT_KILL_MASK, 0);
	xive_regw(x, PC_AT_KILL, PC_AT_KILL_VALID |
		  SETFIELD(VC_AT_MACRO_KILL_VSD, 0ull, VST_NVP));

	/* XXX Add timeout */
	for (;;) {
		val = xive_regr(x, PC_AT_KILL);
		if (!(val & PC_AT_KILL_VALID))
			break;
	}
	return 0;
}

static void xive_cleanup_vp_ind(struct xive *x)
{
	int i;

	xive_dbg(x, "Cleaning up %d VP ind entries...\n", x->vp_ind_count);
	for (i = 0; i < x->vp_ind_count; i++) {
		if (be64_to_cpu(x->vp_ind_base[i]) & VSD_FIRMWARE) {
			xive_dbg(x, " %04x ... skip (firmware)\n", i);
			continue;
		}
		if (x->vp_ind_base[i] != 0) {
			x->vp_ind_base[i] = 0;
			xive_dbg(x, " %04x ... cleaned\n", i);
		}
	}
	xive_pc_ind_cache_kill(x);
}

static void xive_cleanup_end_ind(struct xive *x)
{
	int i;

	xive_dbg(x, "Cleaning up %d END ind entries...\n", x->end_ind_count);
	for (i = 0; i < x->end_ind_count; i++) {
		if (be64_to_cpu(x->end_ind_base[i]) & VSD_FIRMWARE) {
			xive_dbg(x, " %04x ... skip (firmware)\n", i);
			continue;
		}
		if (x->end_ind_base[i] != 0) {
			x->end_ind_base[i] = 0;
			xive_dbg(x, " %04x ... cleaned\n", i);
		}
	}
	xive_vc_ind_cache_kill(x, VST_END);
}

static void xive_reset_one(struct xive *x)
{
	struct cpu_thread *c;
	bool end_firmware;
	int i;

	xive_notice(x, "Resetting one xive...\n");

	lock(&x->lock);

	/* Check all interrupts are disabled */
	i = bitmap_find_one_bit(*x->int_enabled_map, 0, XIVE_INT_COUNT);
	if (i >= 0)
		xive_warn(x, "Interrupt %d (and maybe more) not disabled"
			  " at reset !\n", i);

	/* Reset IPI allocation */
	xive_dbg(x, "freeing alloc map %p/%p\n",
		 x->ipi_alloc_map, *x->ipi_alloc_map);
	memset(x->ipi_alloc_map, 0, BITMAP_BYTES(XIVE_INT_COUNT));

	xive_dbg(x, "Resetting ENDs...\n");

	/* Reset all allocated ENDs and free the user ones */
	bitmap_for_each_one(*x->end_map, xive_end_bitmap_size(x), i) {
		struct xive_end end0;
		struct xive_end *end;
		int j;

		if (i == 0)
			continue;
		end_firmware = false;
		for (j = 0; j < xive_cfg_vp_prio(x); j++) {
			uint32_t idx = (i << xive_cfg_vp_prio_shift(x)) | j;

			end = xive_get_end(x, idx);
			if (!end)
				continue;

			/* We need to preserve the firmware bit, otherwise
			 * we will incorrectly free the ENDs that are reserved
			 * for the physical CPUs
			 */
			if (xive_get_field32(END_W0_VALID, end->w0)) {
				if (!xive_end_is_firmware1(end))
					xive_dbg(x, "END 0x%x:0x%x is valid at reset: %08x %08x\n",
						 x->block_id, idx, end->w0, end->w1);
				end0 = *end;
				xive_cleanup_end(&end0);
				xive_endc_cache_update(x, x->block_id, idx, &end0, true);
			}
			if (xive_end_is_firmware1(end))
				end_firmware = true;
		}
		if (!end_firmware)
			bitmap_clr_bit(*x->end_map, i);
	}

	/* Take out all VPs from HW and reset all CPPRs to 0 */
	for_each_present_cpu(c) {
		if (c->chip_id != x->chip_id)
			continue;
		if (!c->xstate)
			continue;
		xive_cleanup_cpu_tima(c);
	}

	/* Reset all user-allocated VPs. This is inefficient, we should
	 * either keep a bitmap of allocated VPs or add an iterator to
	 * the buddy which is trickier but doable.
	 */
	for (i = 0; i < XIVE_VP_COUNT(x); i++) {
		struct xive_nvp *vp;
		struct xive_nvp vp0 = {0};

		/* Ignore the physical CPU VPs */
		if (i >= xive_hw_vp_count &&
		    i < (xive_hw_vp_base + xive_hw_vp_count))
			continue;

		/* Is the VP valid ? */
		vp = xive_get_vp(x, i);
		if (!vp || !xive_get_field32(NVP_W0_VALID, vp->w0))
			continue;

		/* Clear it */
		xive_dbg(x, "VP 0x%x:0x%x is valid at reset\n", x->block_id, i);
		xive_nxc_cache_update(x, x->block_id, i, &vp0, true);
	}

	/* Forget about remaining donated pages */
	list_head_init(&x->donated_pages);

	/* And cleanup donated indirect VP and END pages */
	xive_cleanup_vp_ind(x);
	xive_cleanup_end_ind(x);

	/* The rest must not be called with the lock held */
	unlock(&x->lock);

	/* Re-configure VPs */
	for_each_present_cpu(c) {
		struct xive_cpu_state *xs = c->xstate;

		if (c->chip_id != x->chip_id || !xs)
			continue;

		xive_init_cpu_exploitation(xs);
	}
}

static void xive_reset_mask_source_cb(struct irq_source *is,
				      void *data __unused)
{
	struct xive_src *s = container_of(is, struct xive_src, is);
	struct xive *x;
	uint32_t isn;

	if (is->ops != &xive_irq_source_ops)
		return;

	/* Skip escalation sources */
	if (GIRQ_IS_ESCALATION(is->start))
		return;

	x = s->xive;

	/* Iterate all interrupts */
	for (isn = is->start; isn < is->end; isn++) {
		/* Has it ever been enabled ? */
		if (!bitmap_tst_bit(*x->int_enabled_map, GIRQ_TO_IDX(isn)))
			continue;
		/* Mask it and clear the enabled map bit */
		xive_vdbg(x, "[reset] disabling source 0x%x\n", isn);
		__xive_set_irq_config(is, isn, 0, 0xff, isn, true, false);
		bitmap_clr_bit(*x->int_enabled_map, GIRQ_TO_IDX(isn));
	}
}

void xive2_cpu_reset(void)
{
	struct cpu_thread *c = this_cpu();
	struct xive_cpu_state *xs = c->xstate;

	out_8(xs->tm_ring1 + TM_QW3_HV_PHYS + TM_CPPR, 0);

	in_be64(xs->tm_ring1 + TM_SPC_PULL_POOL_CTX);
}

static int64_t __xive_reset(uint64_t mode)
{
	struct proc_chip *chip;

	xive_mode = mode;

	/* Mask all interrupt sources */
	irq_for_each_source(xive_reset_mask_source_cb, NULL);

	/* For each XIVE do a sync... */
	for_each_chip(chip) {
		if (!chip->xive)
			continue;
		xive_sync(chip->xive);
	}

	/* For each XIVE reset everything else... */
	for_each_chip(chip) {
		if (!chip->xive)
			continue;
		xive_reset_one(chip->xive);
	}

	/* Cleanup global VP allocator */
	buddy_reset(xive_vp_buddy);

	/*
	 * We reserve the whole range of VP ids for HW threads.
	 */
	assert(buddy_reserve(xive_vp_buddy, xive_hw_vp_base, xive_threadid_shift));

	return OPAL_SUCCESS;
}

/* Called by fast reboot */
int64_t xive2_reset(void)
{
	if (xive_mode == XIVE_MODE_NONE)
		return OPAL_SUCCESS;
	return __xive_reset(XIVE_MODE_EXPL);
}

static int64_t opal_xive_reset(uint64_t mode)
{
	prlog(PR_DEBUG, "XIVE reset. mode = %llx\n", mode);

	if (!(mode & XIVE_MODE_EXPL)) {
		prlog(PR_NOTICE, "No emulation mode. XIVE exploitation mode "
		      "is the default\n");
	}

	xive_expl_options = mode & ~XIVE_MODE_EXPL;
	if (xive_expl_options & ~XIVE_EXPL_ALL_OPTIONS) {
		prerror("invalid XIVE exploitation mode option %016llx\n",
			xive_expl_options);
		return OPAL_PARAMETER;
	}

	return __xive_reset(XIVE_MODE_EXPL);
}

static int64_t opal_xive_free_vp_block(uint64_t vp_base)
{
	uint32_t blk, idx, i, j, count;
	uint8_t order;
	bool group;

	if (xive_mode != XIVE_MODE_EXPL)
		return OPAL_WRONG_STATE;

	if (!xive_decode_vp(vp_base, &blk, &idx, &order, &group))
		return OPAL_PARAMETER;
	if (group)
		return OPAL_PARAMETER;
	if (blk)
		return OPAL_PARAMETER;
	if (order < (xive_chips_alloc_bits + 1))
		return OPAL_PARAMETER;
	if (idx & ((1 << (order - xive_chips_alloc_bits)) - 1))
		return OPAL_PARAMETER;

	count = 1 << order;
	for (i = 0; i < count; i++) {
		uint32_t vp_id = vp_base + i;
		uint32_t blk, idx, end_blk, end_idx;
		struct xive *x;
		struct xive_nvp *vp;

		if (!xive_decode_vp(vp_id, &blk, &idx, NULL, NULL)) {
			prerror("Couldn't decode VP id %u\n", vp_id);
			return OPAL_INTERNAL_ERROR;
		}
		x = xive_from_pc_blk(blk);
		if (!x) {
			prerror("Instance not found for deallocated VP"
				" block %d\n", blk);
			return OPAL_INTERNAL_ERROR;
		}
		vp = xive_get_vp(x, idx);
		if (!vp) {
			prerror("VP not found for deallocation !");
			return OPAL_INTERNAL_ERROR;
		}

		/* VP must be disabled */
		if (xive_get_field32(NVP_W0_VALID, vp->w0)) {
			prlog(PR_ERR, "freeing active VP %d\n", vp_id);
			return OPAL_XIVE_FREE_ACTIVE;
		}

		/* Not populated */
		if (vp->w5 == 0)
			continue;

		end_blk = xive_get_field32(NVP_W5_VP_END_BLOCK, vp->w5);
		end_idx = xive_get_field32(NVP_W5_VP_END_INDEX, vp->w5);

		lock(&x->lock);

		/* Ensure ENDs are disabled and cleaned up. Ideally the caller
		 * should have done it but we double check it here
		 */
		for (j = 0; j < xive_cfg_vp_prio(x); j++) {
			struct xive *end_x = xive_from_vc_blk(end_blk);
			struct xive_end end, *orig_end = xive_get_end(end_x, end_idx + j);

			if (!xive_get_field32(END_W0_VALID, orig_end->w0))
				continue;

			prlog(PR_WARNING, "freeing VP %d with queue %d active\n",
			      vp_id, j);
			end = *orig_end;
			xive_cleanup_end(&end);
			xive_endc_cache_update(x, end_blk, end_idx + j, &end, true);
		}

		/* Mark it not populated so we don't try to free it again */
		vp->w5 = 0;

		if (end_blk != blk) {
			prerror("Block mismatch trying to free ENDs\n");
			unlock(&x->lock);
			return OPAL_INTERNAL_ERROR;
		}

		xive_free_end_set(x, end_idx);
		unlock(&x->lock);
	}

	xive_free_vps(vp_base);

	return OPAL_SUCCESS;
}

static int64_t opal_xive_alloc_vp_block(uint32_t alloc_order)
{
	uint32_t vp_base, ends, count, i;
	int64_t rc;

	if (xive_mode != XIVE_MODE_EXPL)
		return OPAL_WRONG_STATE;

	prlog(PR_TRACE, "opal_xive_alloc_vp_block(%d)\n", alloc_order);

	vp_base = xive_alloc_vps(alloc_order);
	if (XIVE_ALLOC_IS_ERR(vp_base)) {
		if (vp_base == XIVE_ALLOC_NO_IND)
			return OPAL_XIVE_PROVISIONING;
		return OPAL_RESOURCE;
	}

	/* Allocate ENDs and initialize VPs */
	count = 1 << alloc_order;
	for (i = 0; i < count; i++) {
		uint32_t vp_id = vp_base + i;
		uint32_t blk, idx;
		struct xive *x;
		struct xive_nvp *vp;

		if (!xive_decode_vp(vp_id, &blk, &idx, NULL, NULL)) {
			prerror("Couldn't decode VP id %u\n", vp_id);
			return OPAL_INTERNAL_ERROR;
		}
		x = xive_from_pc_blk(blk);
		if (!x) {
			prerror("Instance not found for allocated VP"
				" block %d\n", blk);
			rc = OPAL_INTERNAL_ERROR;
			goto fail;
		}
		vp = xive_get_vp(x, idx);
		if (!vp) {
			prerror("VP not found after allocation !");
			rc = OPAL_INTERNAL_ERROR;
			goto fail;
		}

		/* Allocate ENDs, if fails, free the VPs and return */
		lock(&x->lock);
		ends = xive_alloc_end_set(x, false);
		unlock(&x->lock);
		if (XIVE_ALLOC_IS_ERR(ends)) {
			if (ends == XIVE_ALLOC_NO_IND)
				rc = OPAL_XIVE_PROVISIONING;
			else
				rc = OPAL_RESOURCE;
			goto fail;
		}

		/* Initialize the VP structure. We don't use a cache watch
		 * as we have made sure when freeing the entries to scrub
		 * it out of the cache.
		 */
		memset(vp, 0, sizeof(*vp));

		/* Store the END base of the VP in W5 (new in p10) */
		xive_vp_set_end_base(vp, blk, ends);
	}
	return vp_base;
 fail:
	opal_xive_free_vp_block(vp_base);

	return rc;
}

static int64_t xive_try_allocate_irq(struct xive *x)
{
	int idx, base_idx, max_count, girq;
	struct xive_eas *eas;

	lock(&x->lock);

	base_idx = x->int_ipi_top - x->int_base;
	max_count = x->int_hw_bot - x->int_ipi_top;

	idx = bitmap_find_zero_bit(*x->ipi_alloc_map, base_idx, max_count);
	if (idx < 0) {
		unlock(&x->lock);
		return OPAL_RESOURCE;
	}
	bitmap_set_bit(*x->ipi_alloc_map, idx);
	girq = x->int_base + idx;

	/* Mark the EAS valid. Don't bother with the HW cache, it's
	 * still masked anyway, the cache will be updated when unmasked
	 * and configured.
	 */
	eas = xive_get_eas(x, girq);
	if (!eas) {
		bitmap_clr_bit(*x->ipi_alloc_map, idx);
		unlock(&x->lock);
		return OPAL_PARAMETER;
	}
	eas->w = xive_set_field64(EAS_VALID, 0, 1) |
		 xive_set_field64(EAS_MASKED, 0, 1) |
		 xive_set_field64(EAS_END_DATA, 0, girq);
	unlock(&x->lock);

	return girq;
}

static int64_t opal_xive_allocate_irq(uint32_t chip_id)
{
	struct proc_chip *chip;
	bool try_all = false;
	int64_t rc;

	if (xive_mode != XIVE_MODE_EXPL)
		return OPAL_WRONG_STATE;

	if (chip_id == OPAL_XIVE_ANY_CHIP) {
		try_all = true;
		chip_id = this_cpu()->chip_id;
	}
	chip = get_chip(chip_id);
	if (!chip)
		return OPAL_PARAMETER;

	/* Try initial target chip */
	if (!chip->xive)
		rc = OPAL_PARAMETER;
	else
		rc = xive_try_allocate_irq(chip->xive);
	if (rc >= 0 || !try_all)
		return rc;

	/* Failed and we try all... do so */
	for_each_chip(chip) {
		if (!chip->xive)
			continue;
		rc = xive_try_allocate_irq(chip->xive);
		if (rc >= 0)
			break;
	}
	return rc;
}

static int64_t opal_xive_free_irq(uint32_t girq)
{
	struct irq_source *is = irq_find_source(girq);
	struct xive_src *s = container_of(is, struct xive_src, is);
	struct xive *x = xive_from_isn(girq);
	struct xive_eas *eas;
	uint32_t idx;

	if (xive_mode != XIVE_MODE_EXPL)
               return OPAL_WRONG_STATE;
	if (!x || !is)
		return OPAL_PARAMETER;

	idx = GIRQ_TO_IDX(girq);

	lock(&x->lock);

	eas = xive_get_eas(x, girq);
	if (!eas) {
		unlock(&x->lock);
		return OPAL_PARAMETER;
	}

	/* Mask the interrupt source */
	xive_update_irq_mask(s, girq - s->esb_base, true);

	/* Mark the EAS masked and invalid */
	eas->w = xive_set_field64(EAS_VALID, 0, 1) |
		 xive_set_field64(EAS_MASKED, 0, 1);
	xive_easc_scrub(x, x->block_id, idx);

	/* Free it */
	if (!bitmap_tst_bit(*x->ipi_alloc_map, idx)) {
		unlock(&x->lock);
		return OPAL_PARAMETER;
	}
	bitmap_clr_bit(*x->ipi_alloc_map, idx);
	bitmap_clr_bit(*x->int_enabled_map, idx);
	unlock(&x->lock);

	return OPAL_SUCCESS;
}

static int64_t opal_xive_dump_tm(uint32_t offset, const char *n, uint32_t pir)
{
	struct cpu_thread *c = find_cpu_by_pir(pir);
	struct xive_cpu_state *xs;
	struct xive *x;
	void *cpu_tm_base;
	uint64_t v0,v1;

	if (!c)
		return OPAL_PARAMETER;
	xs = c->xstate;
	if (!xs || !xs->tm_ring1)
		return OPAL_INTERNAL_ERROR;
	x = xs->xive;
	cpu_tm_base = xive_cpu_get_tima(c);

	lock(&x->lock);
	v0 = in_be64(cpu_tm_base + offset);
	if (offset == TM_QW3_HV_PHYS) {
		v1 = in_8(cpu_tm_base + offset + 8);
		v1 <<= 56;
	} else {
		v1 = in_be32(cpu_tm_base + offset + 8);
		v1 <<= 32;
	}
	prlog(PR_INFO, "CPU[%04x]: TM state for QW %s\n", pir, n);
	prlog(PR_INFO, "CPU[%04x]: NSR CPPR IPB LSMFB ACK# INC AGE PIPR"
	      " W2       W3\n", pir);
	prlog(PR_INFO, "CPU[%04x]: %02x  %02x   %02x  %02x    %02x   "
	       "%02x  %02x  %02x   %08x %08x\n", pir,
	      (uint8_t)(v0 >> 58) & 0xff, (uint8_t)(v0 >> 48) & 0xff,
	      (uint8_t)(v0 >> 40) & 0xff, (uint8_t)(v0 >> 32) & 0xff,
	      (uint8_t)(v0 >> 24) & 0xff, (uint8_t)(v0 >> 16) & 0xff,
	      (uint8_t)(v0 >>  8) & 0xff, (uint8_t)(v0      ) & 0xff,
	      (uint32_t)(v1 >> 32) & 0xffffffff,
	      (uint32_t)(v1 & 0xffffffff));
	unlock(&x->lock);

	return OPAL_SUCCESS;
}

static int64_t opal_xive_dump_vp(uint32_t vp_id)
{
	uint32_t blk, idx;
	uint8_t order;
	bool group;
	struct xive *x;
	struct xive_nvp *vp;
	uint32_t *vpw;

	if (!xive_decode_vp(vp_id, &blk, &idx, &order, &group))
		return OPAL_PARAMETER;

	x = xive_from_vc_blk(blk);
	if (!x)
		return OPAL_PARAMETER;
	vp = xive_get_vp(x, idx);
	if (!vp)
		return OPAL_PARAMETER;
	lock(&x->lock);

	xive_nxc_scrub_clean(x, blk, idx);

	vpw = ((uint32_t *)vp) + (group ? 8 : 0);
	prlog(PR_INFO, "VP[%08x]: 0..3: %08x %08x %08x %08x\n", vp_id,
	      vpw[0], vpw[1], vpw[2], vpw[3]);
	prlog(PR_INFO, "VP[%08x]: 4..7: %08x %08x %08x %08x\n", vp_id,
	      vpw[4], vpw[5], vpw[6], vpw[7]);
	unlock(&x->lock);

	return OPAL_SUCCESS;
}

static int64_t opal_xive_sync_irq_src(uint32_t girq)
{
	struct xive *x = xive_from_isn(girq);

	if (!x)
		return OPAL_PARAMETER;
	return xive_sync(x);
}

static int64_t opal_xive_sync_irq_target(uint32_t girq)
{
	uint32_t target, vp_blk;
	struct xive *x;

	if (!xive_get_irq_targetting(girq, &target, NULL, NULL))
		return OPAL_PARAMETER;
	if (!xive_decode_vp(target, &vp_blk, NULL, NULL, NULL))
		return OPAL_PARAMETER;
	x = xive_from_pc_blk(vp_blk);
	if (!x)
		return OPAL_PARAMETER;
	return xive_sync(x);
}

static int64_t opal_xive_sync(uint32_t type, uint32_t id)
{
	int64_t rc = OPAL_SUCCESS;;

	if (type & XIVE_SYNC_EAS)
		rc = opal_xive_sync_irq_src(id);
	if (rc)
		return rc;
	if (type & XIVE_SYNC_QUEUE)
		rc = opal_xive_sync_irq_target(id);
	if (rc)
		return rc;

	/* Add more ... */

	return rc;
}

static int64_t opal_xive_dump(uint32_t type, uint32_t id)
{
	switch (type) {
	case XIVE_DUMP_TM_HYP:
		return opal_xive_dump_tm(TM_QW3_HV_PHYS, "PHYS", id);
	case XIVE_DUMP_TM_POOL:
		return opal_xive_dump_tm(TM_QW2_HV_POOL, "POOL", id);
	case XIVE_DUMP_TM_OS:
		return opal_xive_dump_tm(TM_QW1_OS, "OS  ", id);
	case XIVE_DUMP_TM_USER:
		return opal_xive_dump_tm(TM_QW0_USER, "USER", id);
	case XIVE_DUMP_VP:
		return opal_xive_dump_vp(id);
	default:
		return OPAL_PARAMETER;
	}
}

static void xive_init_globals(void)
{
	uint32_t i;

	for (i = 0; i < XIVE_MAX_CHIPS; i++)
		xive_block_to_chip[i] = XIVE_INVALID_CHIP;
}

/*
 * The global availability of some capabilities used in other drivers
 * (PHB, PSI) is deduced from the capabilities of the first XIVE chip
 * of the system. It should be common to all chips.
 */
bool xive2_cap_phb_pq_disable(void)
{
	return xive_has_cap(one_xive, CQ_XIVE_CAP_PHB_PQ_DISABLE);
}

bool xive2_cap_phb_abt(void)
{
	if (!xive_has_cap(one_xive, CQ_XIVE_CAP_PHB_ABT))
		return false;

	/*
	 * We need 'PQ disable' to use ABT mode, else the OS will use
	 * two different sets of ESB pages (PHB and IC) to control the
	 * interrupt sources. Can not work.
	 */
	if (!xive2_cap_phb_pq_disable()) {
		prlog_once(PR_ERR, "ABT mode is set without PQ disable. "
			   "Ignoring bogus configuration\n");
		return false;
	}

	return true;
}

bool xive2_cap_store_eoi(void)
{
	return xive_has_cap(one_xive, CQ_XIVE_CAP_STORE_EOI);
}

void xive2_init(void)
{
	struct dt_node *np;
	struct proc_chip *chip;
	struct cpu_thread *cpu;
	bool first = true;

	/* Look for xive nodes and do basic inits */
	dt_for_each_compatible(dt_root, np, "ibm,power10-xive-x") {
		struct xive *x;

		/* Initialize some global stuff */
		if (first)
			xive_init_globals();

		/* Create/initialize the xive instance */
		x = init_one_xive(np);
		if (first)
			one_xive = x;
		first = false;
	}
	if (first)
		return;

	/*
	 * P8 emulation is not supported on P10 anymore. Exploitation
	 * is the default XIVE mode. We might introduce a GEN2 mode.
	 */
	xive_mode = XIVE_MODE_EXPL;

	/* Init VP allocator */
	xive_init_vp_allocator();

	/* Create a device-tree node for Linux use */
	xive_create_mmio_dt_node(one_xive);

	/* Some inits must be done after all xive have been created
	 * such as setting up the forwarding ports
	 */
	for_each_chip(chip) {
		if (chip->xive)
			late_init_one_xive(chip->xive);
	}

	/* Initialize per-cpu structures */
	for_each_present_cpu(cpu) {
		xive_init_cpu(cpu);
	}

	/* Calling boot CPU */
	xive2_cpu_callin(this_cpu());

	/* Register XIVE exploitation calls */
	opal_register(OPAL_XIVE_RESET, opal_xive_reset, 1);
	opal_register(OPAL_XIVE_GET_IRQ_INFO, opal_xive_get_irq_info, 6);
	opal_register(OPAL_XIVE_GET_IRQ_CONFIG, opal_xive_get_irq_config, 4);
	opal_register(OPAL_XIVE_SET_IRQ_CONFIG, opal_xive_set_irq_config, 4);
	opal_register(OPAL_XIVE_GET_QUEUE_INFO, opal_xive_get_queue_info, 7);
	opal_register(OPAL_XIVE_SET_QUEUE_INFO, opal_xive_set_queue_info, 5);
	opal_register(OPAL_XIVE_DONATE_PAGE, opal_xive_donate_page, 2);
	opal_register(OPAL_XIVE_ALLOCATE_IRQ, opal_xive_allocate_irq, 1);
	opal_register(OPAL_XIVE_FREE_IRQ, opal_xive_free_irq, 1);
	opal_register(OPAL_XIVE_ALLOCATE_VP_BLOCK, opal_xive_alloc_vp_block, 1);
	opal_register(OPAL_XIVE_FREE_VP_BLOCK, opal_xive_free_vp_block, 1);
	opal_register(OPAL_XIVE_GET_VP_INFO, opal_xive_get_vp_info, 5);
	opal_register(OPAL_XIVE_SET_VP_INFO, opal_xive_set_vp_info, 3);
	opal_register(OPAL_XIVE_SYNC, opal_xive_sync, 2);
	opal_register(OPAL_XIVE_DUMP, opal_xive_dump, 2);
	opal_register(OPAL_XIVE_GET_QUEUE_STATE, opal_xive_get_queue_state, 4);
	opal_register(OPAL_XIVE_SET_QUEUE_STATE, opal_xive_set_queue_state, 4);
	opal_register(OPAL_XIVE_GET_VP_STATE, opal_xive_get_vp_state, 2);
}
