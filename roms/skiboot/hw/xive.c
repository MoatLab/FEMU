// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * XIVE: eXternal Interrupt Virtualization Engine. POWER9 interrupt
 * controller
 *
 * Copyright (c) 2016-2019, IBM Corporation.
 */

#include <skiboot.h>
#include <xscom.h>
#include <chip.h>
#include <io.h>
#include <xive.h>
#include <xive-p9-regs.h>
#include <xscom-p9-regs.h>
#include <interrupts.h>
#include <timebase.h>
#include <bitmap.h>
#include <buddy.h>
#include <phys-map.h>
#include <p9_stop_api.H>

/* Always notify from EQ to VP (no EOI on EQs). Will speed up
 * EOIs at the expense of potentially higher powerbus traffic.
 */
#define EQ_ALWAYS_NOTIFY

/* Verbose debug */
#undef XIVE_VERBOSE_DEBUG

/* Extra debug options used in debug builds */
#ifdef DEBUG
#define XIVE_DEBUG_DUPLICATES
#define XIVE_PERCPU_LOG
#define XIVE_DEBUG_INIT_CACHE_UPDATES
#define XIVE_EXTRA_CHECK_INIT_CACHE
#undef XIVE_CHECK_MISROUTED_IPI
#define XIVE_CHECK_LOCKS
#else
#undef  XIVE_DEBUG_DUPLICATES
#undef  XIVE_PERCPU_LOG
#undef  XIVE_DEBUG_INIT_CACHE_UPDATES
#undef  XIVE_EXTRA_CHECK_INIT_CACHE
#undef  XIVE_CHECK_MISROUTED_IPI
#undef  XIVE_CHECK_LOCKS
#endif

/*
 *
 * VSDs, blocks, set translation etc...
 *
 * This stuff confused me to no end so here's an attempt at explaining
 * my understanding of it and how I use it in OPAL & Linux
 *
 * For the following data structures, the XIVE use a mechanism called
 * Virtualization Structure Tables (VST) to manage the memory layout
 * and access: ESBs (Event State Buffers, aka IPI sources), EAS/IVT
 * (Event assignment structures), END/EQs (Notification descriptors
 * aka event queues) and NVT/VPD (Notification Virtual Targets).
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
 * We will pre-allocate some of the tables in order to support a "fallback"
 * mode operations where an old-style XICS is emulated via OPAL calls. This
 * is achieved by having a default of one VP per physical thread associated
 * with one EQ and one IPI. There is also enought EATs to cover all the PHBs.
 *
 * Similarily, for MMIO access, the BARs support what is called "set
 * translation" which allows the BAR to be divided into a certain
 * number of sets. The VC BAR (ESBs, ENDs, ...) supports 64 sets and
 * the PC BAR supports 16. Each "set" can be routed to a specific
 * block and offset within a block.
 *
 * For now, we will not use much of that functionality. We will use a
 * fixed split between ESB and ENDs for the VC BAR as defined by the
 * constants below and we will allocate all the PC BARs set to the
 * local block of that chip
 */

#define XIVE_VSD_SIZE		sizeof(u64)

/* VC BAR contains set translations for the ESBs and the EQs.
 *
 * It's divided in 64 sets, each of which can be either ESB pages or EQ pages.
 * The table configuring this is the EDT
 *
 * Additionally, the ESB pages come in pair of Linux_Trig_Mode isn't enabled
 * (which we won't enable for now as it assumes write-only permission which
 * the MMU doesn't support).
 *
 * To get started we just hard wire the following setup:
 *
 * VC_BAR size is 512G. We split it into 384G of ESBs (48 sets) and 128G
 * of ENDs (16 sets) for the time being. IE. Each set is thus 8GB
 */

#define VC_ESB_SETS	48
#define VC_END_SETS	16
#define VC_MAX_SETS	64

/* The table configuring the PC set translation (16 sets) is the VDT */
#define PC_MAX_SETS	16

/* XXX This is the currently top limit of number of ESB/SBE entries
 * and EAS/IVT entries pre-allocated per chip. This should probably
 * turn into a device-tree property or NVRAM setting, or maybe
 * calculated from the amount of system RAM...
 *
 * This is currently set to 1M
 *
 * This is independent of the sizing of the MMIO space.
 *
 * WARNING: Due to how XICS emulation works, we cannot support more
 * interrupts per chip at this stage as the full interrupt number
 * (block + index) has to fit in a 24-bit number.
 *
 * That gives us a pre-allocated space of 256KB per chip for the state
 * bits and 8M per chip for the EAS/IVT.
 *
 * Note: The HW interrupts from PCIe and similar other entities that
 * use their own state bit array will have to share that IVT space,
 * so we could potentially make the IVT size twice as big, but for now
 * we will simply share it and ensure we don't hand out IPIs that
 * overlap the HW interrupts.
 *
 * TODO: adjust the VC BAR range for IPI ESBs on this value
 */

#define XIVE_INT_ORDER		20 /* 1M interrupts */
#define XIVE_INT_COUNT		(1ul << XIVE_INT_ORDER)

/*
 * First interrupt number, also the first logical interrupt number
 * allocated by Linux (the first numbers are reserved for ISA)
 */
#define XIVE_INT_FIRST		0x10

/* Corresponding direct table sizes */

#define SBE_PER_BYTE	        4 /* PQ bits couples */
#define SBE_SIZE	        (XIVE_INT_COUNT / SBE_PER_BYTE)
#define IVT_SIZE	        (XIVE_INT_COUNT * sizeof(struct xive_ive))

/* Use 64K for everything by default */
#define XIVE_ESB_SHIFT		(16 + 1) /* trigger + mgmt pages */
#define XIVE_ESB_PAGE_SIZE	(1ul << XIVE_ESB_SHIFT) /* 2 pages */

/* Max number of EQs. We allocate an indirect table big enough so
 * that when fully populated we can have that many EQs.
 *
 * The max number of EQs we support in our MMIO space is 128G/128K
 * ie. 1M. Since one EQ is 8 words (32 bytes), a 64K page can hold
 * 2K EQs. We need 512 pointers, ie, 4K of memory for the indirect
 * table.
 *
 * TODO: adjust the VC BAR range for END ESBs on this value
 */
#define EQ_PER_PAGE		(PAGE_SIZE / sizeof(struct xive_eq))

#define XIVE_EQ_ORDER		20 /* 1M ENDs */
#define XIVE_EQ_COUNT		(1ul << XIVE_EQ_ORDER)
#define XIVE_EQ_TABLE_SIZE	((XIVE_EQ_COUNT / EQ_PER_PAGE) * XIVE_VSD_SIZE)

#define XIVE_EQ_SHIFT		(16 + 1) /* ESn + ESe pages */

/* Number of priorities (and thus EQDs) we allocate for each VP */
#define NUM_INT_PRIORITIES	8

/* Max priority number */
#define XIVE_MAX_PRIO		7

/* Priority used for the one queue in XICS emulation */
#define XIVE_EMULATION_PRIO	7

/* Priority used for gather/silent escalation (KVM) */
#define XIVE_ESCALATION_PRIO	7

/* Max number of VPs. We allocate an indirect table big enough so
 * that when fully populated we can have that many VPs.
 *
 * The max number of VPs we support in our MMIO space is 64G/64K
 * ie. 1M. Since one VP is 16 words (64 bytes), a 64K page can hold
 * 1K EQ. We need 1024 pointers, ie, 8K of memory for the indirect
 * table.
 *
 * HOWEVER: A block supports only up to 512K VPs (19 bits of target
 * in the EQ). Since we currently only support 1 block per chip,
 * we will allocate half of the above. We might add support for
 * 2 blocks per chip later if necessary.
 *
 * TODO: adjust the PC BAR range
 */
#define VP_PER_PAGE		(PAGE_SIZE / sizeof(struct xive_vp))

#define NVT_SHIFT		19	/* in sync with EQ_W6_NVT_INDEX */

/*
 * We use 8 priorities per VP and the number of EQs is configured to
 * 1M. Therefore, our VP space is limited to 128k.
 */
#define XIVE_VP_ORDER		(XIVE_EQ_ORDER - 3) /* 128k */
#define XIVE_VP_COUNT		(1ul << XIVE_VP_ORDER)
#define XIVE_VP_TABLE_SIZE	((XIVE_VP_COUNT / VP_PER_PAGE) * XIVE_VSD_SIZE)

/*
 * VP ids for HW threads.
 *
 * These values are hardcoded in the CAM line of the HW context and
 * they depend on the thread id bits of the chip, 7bit for p9.
 *
 *     HW CAM Line      |chip|000000000001|thrdid |
 *     23bits              4      12          7
 */
#define XIVE_THREADID_SHIFT	7
#define XIVE_HW_VP_BASE		(1 << XIVE_THREADID_SHIFT)
#define XIVE_HW_VP_COUNT	(1 << XIVE_THREADID_SHIFT)

/* The xive operation mode indicates the active "API" and corresponds
 * to the "mode" parameter of the opal_xive_reset() call
 */
static enum {
	XIVE_MODE_EMU	= OPAL_XIVE_MODE_EMU,
	XIVE_MODE_EXPL	= OPAL_XIVE_MODE_EXPL,
	XIVE_MODE_NONE,
} xive_mode = XIVE_MODE_NONE;


/* Each source controller has one of these. There's one embedded
 * in the XIVE struct for IPIs
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

#define LOG_TYPE_XIRR	0
#define LOG_TYPE_XIRR2	1
#define LOG_TYPE_POPQ	2
#define LOG_TYPE_EOI	3
#define LOG_TYPE_EQD	4

struct xive_log_ent {
	uint8_t type;
	uint8_t cnt;
	uint64_t tb;
#define MAX_LOG_DATA	8
	uint32_t data[MAX_LOG_DATA];
};
#define MAX_LOG_ENT	32

struct xive_cpu_state {
	struct xive	*xive;
	void		*tm_ring1;

#ifdef XIVE_PERCPU_LOG
	struct xive_log_ent log[MAX_LOG_ENT];
	uint32_t	log_pos;
#endif
	/* Base HW VP and associated queues */
	uint32_t	vp_blk;
	uint32_t	vp_idx;
	uint32_t	eq_blk;
	uint32_t	eq_idx; /* Base eq index of a block of 8 */
	void		*eq_page;

	/* Pre-allocated IPI */
	uint32_t	ipi_irq;

	/* Use for XICS emulation */
	struct lock	lock;
	uint8_t		cppr;
	uint8_t		mfrr;
	uint8_t		pending;
	uint8_t		prev_cppr;
	uint32_t	*eqbuf;
	uint32_t	eqptr;
	uint32_t	eqmsk;
	uint8_t		eqgen;
	void		*eqmmio;
	uint64_t	total_irqs;
};

#ifdef XIVE_PERCPU_LOG

static void log_add(struct xive_cpu_state *xs, uint8_t type,
		    uint8_t count, ...)
{
	struct xive_log_ent *e = &xs->log[xs->log_pos];
	va_list args;
	int i;

	e->type = type;
	e->cnt = count;
	e->tb = mftb();
	va_start(args, count);
	for (i = 0; i < count; i++)
		e->data[i] = va_arg(args, u32);
	va_end(args);
	xs->log_pos = xs->log_pos + 1;
	if (xs->log_pos == MAX_LOG_ENT)
		xs->log_pos = 0;
}

static void log_print(struct xive_cpu_state *xs)
{
	uint32_t pos = xs->log_pos;
	uint8_t buf[256];
	int i, j;
	static const char *lts[] = {
		">XIRR",
		"<XIRR",
		" POPQ",
		"  EOI",
		"  EQD"
	};
	for (i = 0; i < MAX_LOG_ENT; i++) {
		struct xive_log_ent *e = &xs->log[pos];
		uint8_t *b = buf, *eb = &buf[255];

		b += snprintf(b, eb-b, "%08llx %s ", e->tb,
			      lts[e->type]);
		for (j = 0; j < e->cnt && b < eb; j++)
			b += snprintf(b, eb-b, "%08x ", e->data[j]);
		printf("%s\n", buf);
		pos = pos + 1;
		if (pos == MAX_LOG_ENT)
			pos = 0;
	}
}

#else /* XIVE_PERCPU_LOG */

static inline void log_add(struct xive_cpu_state *xs __unused,
			   uint8_t type __unused,
			   uint8_t count __unused, ...) { }
static inline void log_print(struct xive_cpu_state *xs __unused) { }

#endif /* XIVE_PERCPU_LOG */

struct xive {
	uint32_t	chip_id;
	uint32_t	block_id;
	struct dt_node	*x_node;

	uint64_t	xscom_base;

	/* MMIO regions */
	void		*ic_base;
	uint64_t	ic_size;
	uint32_t	ic_shift;
	void		*tm_base;
	uint64_t	tm_size;
	uint32_t	tm_shift;
	void		*pc_base;
	uint64_t	pc_size;
	void		*vc_base;
	uint64_t	vc_size;

	void		*esb_mmio;
	void		*eq_mmio;

	/* Set on XSCOM register access error */
	bool		last_reg_error;

	/* Per-XIVE mutex */
	struct lock	lock;

	/* Pre-allocated tables.
	 *
	 * We setup all the VDS for actual tables (ie, by opposition to
	 * forwarding ports) as either direct pre-allocated or indirect
	 * and partially populated.
	 *
	 * Currently, the ESB/SBE and the EAS/IVT tables are direct and
	 * fully pre-allocated based on XIVE_INT_COUNT.
	 *
	 * The other tables are indirect, we thus pre-allocate the indirect
	 * table (ie, pages of pointers) and populate enough of the pages
	 * for our basic setup using 64K pages.
	 *
	 * The size of the indirect tables are driven by XIVE_VP_COUNT and
	 * XIVE_EQ_COUNT. The number of pre-allocated ones are driven by
	 * XIVE_HW_VP_COUNT (number of EQ depends on number of VP) in block
	 * mode, otherwise we only preallocate INITIAL_BLK0_VP_COUNT on
	 * block 0.
	 */

	/* Direct SBE and IVT tables */
	void		*sbe_base;
	void		*ivt_base;

	/* Indirect END/EQ table. NULL entries are unallocated, count is
	 * the numbre of pointers (ie, sub page placeholders).
	 */
	__be64		*eq_ind_base;
	uint32_t	eq_ind_count;

	/* EQ allocation bitmap. Each bit represent 8 EQs */
	bitmap_t	*eq_map;

	/* Indirect NVT/VP table. NULL entries are unallocated, count is
	 * the numbre of pointers (ie, sub page placeholders).
	 */
	__be64		*vp_ind_base;
	uint32_t	vp_ind_count;

	/* Pool of donated pages for provisioning indirect EQ and VP pages */
	struct list_head donated_pages;

	/* To ease a possible change to supporting more than one block of
	 * interrupts per chip, we store here the "base" global number
	 * and max number of interrupts for this chip. The global number
	 * encompass the block number and index.
	 */
	uint32_t	int_base;
	uint32_t	int_max;

	/* Due to the overlap between IPIs and HW sources in the IVT table,
	 * we keep some kind of top-down allocator. It is used for HW sources
	 * to "allocate" interrupt entries and will limit what can be handed
	 * out as IPIs. Of course this assumes we "allocate" all HW sources
	 * before we start handing out IPIs.
	 *
	 * Note: The numbers here are global interrupt numbers so that we can
	 * potentially handle more than one block per chip in the future.
	 */
	uint32_t	int_hw_bot;	/* Bottom of HW allocation */
	uint32_t	int_ipi_top;	/* Highest IPI handed out so far + 1 */

	/* The IPI allocation bitmap */
	bitmap_t	*ipi_alloc_map;

	/* We keep track of which interrupts were ever enabled to
	 * speed up xive_reset
	 */
	bitmap_t	*int_enabled_map;

	/* Embedded source IPIs */
	struct xive_src	ipis;

	/* Embedded escalation interrupts */
	struct xive_src	esc_irqs;

	/* In memory queue overflow */
	void		*q_ovf;
};

#define XIVE_CAN_STORE_EOI(x) XIVE_STORE_EOI_ENABLED

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

/* Conversion between GIRQ and block/index.
 *
 * ------------------------------------
 * |0000000E|BLOC|               INDEX|
 * ------------------------------------
 *      8      4           20
 *
 * the E bit indicates that this is an escalation interrupt, in
 * that case, the BLOCK/INDEX points to the EQ descriptor associated
 * with the escalation.
 *
 * Global interrupt numbers for non-escalation interrupts are thus
 * limited to 24 bits because the XICS emulation encodes the CPPR
 * value in the top (MSB) 8 bits. Hence, 4 bits are left for the XIVE
 * block number and the remaining 20 bits for the interrupt index
 * number.
 */
#define INT_SHIFT		20
#define INT_ESC_SHIFT		(INT_SHIFT + 4) /* 4bits block id */

#if XIVE_INT_ORDER > INT_SHIFT
#error "Too many ESBs for IRQ encoding"
#endif

#if XIVE_EQ_ORDER > INT_SHIFT
#error "Too many EQs for escalation IRQ number encoding"
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
#define PIR2VP_IDX(__pir)	(XIVE_HW_VP_BASE | P9_PIR2LOCALCPU(__pir))
#define PIR2VP_BLK(__pir)	(xive_chip_to_block(P9_PIR2GCID(__pir)))
#define VP2PIR(__blk, __idx)	(P9_PIRFROMLOCALCPU(VC_BLK_TO_CHIP(__blk), (__idx) & 0x7f))

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

/* VP allocation */
static uint32_t xive_chips_alloc_bits = 0;
static struct buddy *xive_vp_buddy;
static struct lock xive_buddy_lock = LOCK_UNLOCKED;

/* VP# decoding/encoding */
static bool xive_decode_vp(uint32_t vp, uint32_t *blk, uint32_t *idx,
			   uint8_t *order, bool *group)
{
	uint32_t o = (vp >> 24) & 0x1f;
	uint32_t n = xive_chips_alloc_bits;
	uint32_t index = vp & 0x00ffffff;
	uint32_t imask = (1 << (o - n)) - 1;

	/* Groups not supported yet */
	if ((vp >> 31) & 1)
		return false;
	if (group)
		*group = false;

	/* PIR case */
	if (((vp >> 30) & 1) == 0) {
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
	uint32_t vp = 0x40000000 | (order << 24);
	uint32_t n = xive_chips_alloc_bits;
	uint32_t imask = (1 << (order - n)) - 1;

	vp |= (idx & ~imask) << n;
	vp |= blk << (order - n);
	vp |= idx & imask;
	return  vp;
}

#define xive_regw(__x, __r, __v) \
	__xive_regw(__x, __r, X_##__r, __v, #__r)
#define xive_regr(__x, __r) \
	__xive_regr(__x, __r, X_##__r, #__r)
#define xive_regwx(__x, __r, __v) \
	__xive_regw(__x, 0, X_##__r, __v, #__r)
#define xive_regrx(__x, __r) \
	__xive_regr(__x, 0, X_##__r, #__r)

#ifdef XIVE_VERBOSE_DEBUG
#define xive_vdbg(__x,__fmt,...)	prlog(PR_DEBUG,"XIVE[ IC %02x  ] " __fmt, (__x)->chip_id, ##__VA_ARGS__)
#define xive_cpu_vdbg(__c,__fmt,...)	prlog(PR_DEBUG,"XIVE[CPU %04x] " __fmt, (__c)->pir, ##__VA_ARGS__)
#else
#define xive_vdbg(x,fmt,...)		do { } while(0)
#define xive_cpu_vdbg(x,fmt,...)	do { } while(0)
#endif

#define xive_dbg(__x,__fmt,...)		prlog(PR_DEBUG,"XIVE[ IC %02x  ] " __fmt, (__x)->chip_id, ##__VA_ARGS__)
#define xive_cpu_dbg(__c,__fmt,...)	prlog(PR_DEBUG,"XIVE[CPU %04x] " __fmt, (__c)->pir, ##__VA_ARGS__)
#define xive_warn(__x,__fmt,...)	prlog(PR_WARNING,"XIVE[ IC %02x  ] " __fmt, (__x)->chip_id, ##__VA_ARGS__)
#define xive_cpu_warn(__c,__fmt,...)	prlog(PR_WARNING,"XIVE[CPU %04x] " __fmt, (__c)->pir, ##__VA_ARGS__)
#define xive_err(__x,__fmt,...)		prlog(PR_ERR,"XIVE[ IC %02x  ] " __fmt, (__x)->chip_id, ##__VA_ARGS__)
#define xive_cpu_err(__c,__fmt,...)	prlog(PR_ERR,"XIVE[CPU %04x] " __fmt, (__c)->pir, ##__VA_ARGS__)

static void __xive_regw(struct xive *x, uint32_t m_reg, uint32_t x_reg, uint64_t v,
			const char *rname)
{
	bool use_xscom = (m_reg == 0) || !x->ic_base;
	int64_t rc;

	x->last_reg_error = false;

	if (use_xscom) {
		assert(x_reg != 0);
		rc = xscom_write(x->chip_id, x->xscom_base + x_reg, v);
		if (rc) {
			if (!rname)
				rname = "???";
			xive_err(x, "Error writing register %s\n", rname);
			/* Anything else we can do here ? */
			x->last_reg_error = true;
		}
	} else {
		out_be64(x->ic_base + m_reg, v);
	}
}

static uint64_t __xive_regr(struct xive *x, uint32_t m_reg, uint32_t x_reg,
			    const char *rname)
{
	bool use_xscom = (m_reg == 0) || !x->ic_base;
	int64_t rc;
	uint64_t val;

	x->last_reg_error = false;

	if (use_xscom) {
		assert(x_reg != 0);
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
		val = in_be64(x->ic_base + m_reg);
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

static struct xive_eq *xive_get_eq(struct xive *x, unsigned int idx)
{
	struct xive_eq *p;

	if (idx >= (x->eq_ind_count * EQ_PER_PAGE))
		return NULL;
	p = (struct xive_eq *)(be64_to_cpu(x->eq_ind_base[idx / EQ_PER_PAGE]) &
			       VSD_ADDRESS_MASK);
	if (!p)
		return NULL;

	return &p[idx % EQ_PER_PAGE];
}

static struct xive_ive *xive_get_ive(struct xive *x, unsigned int isn)
{
	struct xive_ive *ivt;
	uint32_t idx = GIRQ_TO_IDX(isn);

	if (GIRQ_IS_ESCALATION(isn)) {
		/* All right, an escalation IVE is buried inside an EQ, let's
		 * try to find it
		 */
		struct xive_eq *eq;

		if (x->chip_id != VC_BLK_TO_CHIP(GIRQ_TO_BLK(isn))) {
			xive_err(x, "xive_get_ive, ESC ISN 0x%x not on right chip\n", isn);
			return NULL;
		}
		eq = xive_get_eq(x, idx);
		if (!eq) {
			xive_err(x, "xive_get_ive, ESC ISN 0x%x EQ not found\n", isn);
			return NULL;
		}

		/* If using single-escalation, don't let anybody get to the individual
		 * escalation interrupts
		 */
		if (xive_get_field32(EQ_W0_UNCOND_ESCALATE, eq->w0))
			return NULL;

		/* Grab the buried IVE */
		return (struct xive_ive *)(char *)&eq->w4;
	} else {
		/* Check the block matches */
		if (isn < x->int_base || isn >= x->int_max) {
			xive_err(x, "xive_get_ive, ISN 0x%x not on right chip\n", isn);
			return NULL;
		}
		assert (idx < XIVE_INT_COUNT);

		/* If we support >1 block per chip, this should still work as
		 * we are likely to make the table contiguous anyway
		 */
		ivt = x->ivt_base;
		assert(ivt);

		return ivt + idx;
	}
}

static struct xive_vp *xive_get_vp(struct xive *x, unsigned int idx)
{
	struct xive_vp *p;

	assert(idx < (x->vp_ind_count * VP_PER_PAGE));
	p = (struct xive_vp *)(be64_to_cpu(x->vp_ind_base[idx / VP_PER_PAGE]) &
			       VSD_ADDRESS_MASK);
	if (!p)
		return NULL;

	return &p[idx % VP_PER_PAGE];
}

static void xive_init_default_vp(struct xive_vp *vp,
				 uint32_t eq_blk, uint32_t eq_idx)
{
	memset(vp, 0, sizeof(struct xive_vp));

	/* Stash the EQ base in the pressure relief interrupt field */
	vp->w1 = cpu_to_be32((eq_blk << 28) | eq_idx);
	vp->w0 = xive_set_field32(VP_W0_VALID, 0, 1);
}

static void xive_init_emu_eq(uint32_t vp_blk, uint32_t vp_idx,
			     struct xive_eq *eq, void *backing_page,
			     uint8_t prio)
{
	memset(eq, 0, sizeof(struct xive_eq));

	eq->w1 = xive_set_field32(EQ_W1_GENERATION, 0, 1);
	eq->w3 = cpu_to_be32(((uint64_t)backing_page) & EQ_W3_OP_DESC_LO);
	eq->w2 = cpu_to_be32((((uint64_t)backing_page) >> 32) & EQ_W2_OP_DESC_HI);
	eq->w6 = xive_set_field32(EQ_W6_NVT_BLOCK, 0, vp_blk) |
		 xive_set_field32(EQ_W6_NVT_INDEX, 0, vp_idx);
	eq->w7 = xive_set_field32(EQ_W7_F0_PRIORITY, 0, prio);
	eq->w0 = xive_set_field32(EQ_W0_VALID, 0, 1) |
		 xive_set_field32(EQ_W0_ENQUEUE, 0, 1) |
		 xive_set_field32(EQ_W0_FIRMWARE, 0, 1) |
		 xive_set_field32(EQ_W0_QSIZE, 0, EQ_QSIZE_64K) |
#ifdef EQ_ALWAYS_NOTIFY
		 xive_set_field32(EQ_W0_UCOND_NOTIFY, 0, 1) |
#endif
		 0 ;
}

static uint32_t *xive_get_eq_buf(uint32_t eq_blk, uint32_t eq_idx)
{
	struct xive *x = xive_from_vc_blk(eq_blk);
	struct xive_eq *eq;
	uint64_t addr;

	assert(x);
	eq = xive_get_eq(x, eq_idx);
	assert(eq);
	assert(xive_get_field32(EQ_W0_VALID, eq->w0));
	addr = ((((uint64_t)be32_to_cpu(eq->w2)) & 0x0fffffff) << 32) | be32_to_cpu(eq->w3);

	return (uint32_t *)addr;
}

static void *xive_get_donated_page(struct xive *x)
{
	return (void *)list_pop_(&x->donated_pages, 0);
}

#define XIVE_ALLOC_IS_ERR(_idx)	((_idx) >= 0xfffffff0)

#define XIVE_ALLOC_NO_SPACE	0xffffffff /* No possible space */
#define XIVE_ALLOC_NO_IND	0xfffffffe /* Indirect need provisioning */
#define XIVE_ALLOC_NO_MEM	0xfffffffd /* Local allocation failed */

static uint32_t xive_alloc_eq_set(struct xive *x, bool alloc_indirect)
{
	uint32_t ind_idx;
	int idx;
	int eq_base_idx;

	xive_vdbg(x, "Allocating EQ set...\n");

	assert(x->eq_map);

	/* Allocate from the EQ bitmap. Each bit is 8 EQs */
	idx = bitmap_find_zero_bit(*x->eq_map, 0, XIVE_EQ_COUNT >> 3);
	if (idx < 0) {
		xive_dbg(x, "Allocation from EQ bitmap failed !\n");
		return XIVE_ALLOC_NO_SPACE;
	}

	eq_base_idx = idx << 3;

	xive_vdbg(x, "Got EQs 0x%x..0x%x\n", eq_base_idx,
		  eq_base_idx + XIVE_MAX_PRIO);

	/* Calculate the indirect page where the EQs reside */
	ind_idx = eq_base_idx / EQ_PER_PAGE;

	/* Is there an indirect page ? If not, check if we can provision it */
	if (!x->eq_ind_base[ind_idx]) {
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
		x->eq_ind_base[ind_idx] = cpu_to_be64(vsd_flags |
			(((uint64_t)page) & VSD_ADDRESS_MASK));
		/* Any cache scrub needed ? */
	}

	bitmap_set_bit(*x->eq_map, idx);
	return eq_base_idx;
}

static void xive_free_eq_set(struct xive *x, uint32_t eqs)
{
	uint32_t idx;

	xive_vdbg(x, "Freeing EQ 0x%x..0x%x\n", eqs, eqs + XIVE_MAX_PRIO);

	assert((eqs & 7) == 0);
	assert(x->eq_map);

	idx = eqs >> 3;
	bitmap_clr_bit(*x->eq_map, idx);
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

	prlog(PR_INFO, "XIVE: %d chips considered for VP allocations\n",
	      1 << xive_chips_alloc_bits);

	/* Allocate a buddy big enough for XIVE_VP_ORDER allocations.
	 *
	 * each bit in the buddy represents 1 << xive_chips_alloc_bits
	 * VPs.
	 */
	xive_vp_buddy = buddy_create(XIVE_VP_ORDER);
	assert(xive_vp_buddy);

	/* We reserve the whole range of VPs representing HW chips.
	 *
	 * These are 0x80..0xff, so order 7 starting at 0x80. This will
	 * reserve that range on each chip.
	 */
	assert(buddy_reserve(xive_vp_buddy, XIVE_HW_VP_BASE,
			     XIVE_THREADID_SHIFT));
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
	xive_cache_ivc,
	xive_cache_sbc,
	xive_cache_eqc,
	xive_cache_vpc,
};

static int64_t __xive_cache_watch(struct xive *x, enum xive_cache_type ctype,
				  uint64_t block, uint64_t idx,
				  uint32_t start_dword, uint32_t dword_count,
				  __be64 *new_data, bool light_watch,
				  bool synchronous);

static void xive_scrub_workaround_vp(struct xive *x, uint32_t block, uint32_t idx __unused)
{
	/* VP variant of the workaround described in __xive_cache_scrub(),
	 * we need to be careful to use for that workaround an NVT that
	 * sits on the same xive but isn NOT part of a donated indirect
	 * entry.
	 *
	 * The reason is that the dummy cache watch will re-create a
	 * dirty entry in the cache, even if the entry is marked
	 * invalid.
	 *
	 * Thus if we are about to dispose of the indirect entry backing
	 * it, we'll cause a checkstop later on when trying to write it
	 * out.
	 *
	 * Note: This means the workaround only works for block group
	 * mode.
	 */
	__xive_cache_watch(x, xive_cache_vpc, block, XIVE_HW_VP_BASE, 0,
			   0, NULL, true, false);
}

static void xive_scrub_workaround_eq(struct xive *x, uint32_t block __unused, uint32_t idx)
{
	void *mmio;

	/* EQ variant of the workaround described in __xive_cache_scrub(),
	 * a simple non-side effect load from ESn will do
	 */
	mmio = x->eq_mmio + idx * XIVE_ESB_PAGE_SIZE;

	/* Ensure the above has returned before we do anything else
	 * the XIVE store queue is completely empty
	 */
	load_wait(in_be64(mmio + XIVE_ESB_GET));
}

static int64_t __xive_cache_scrub(struct xive *x, enum xive_cache_type ctype,
				  uint64_t block, uint64_t idx,
				  bool want_inval, bool want_disable)
{
	uint64_t sreg, sregx, mreg, mregx;
	uint64_t mval, sval;

#ifdef XIVE_CHECK_LOCKS
	assert(lock_held_by_me(&x->lock));
#endif

	/* Workaround a HW bug in XIVE where the scrub completion
	 * isn't ordered by loads, thus the data might still be
	 * in a queue and may not have reached coherency.
	 *
	 * The workaround is two folds: We force the scrub to also
	 * invalidate, then after the scrub, we do a dummy cache
	 * watch which will make the HW read the data back, which
	 * should be ordered behind all the preceding stores.
	 *
	 * Update: For EQs we can do a non-side effect ESB load instead
	 * which is faster.
	 */
	want_inval = true;

	switch (ctype) {
	case xive_cache_ivc:
		sreg = VC_IVC_SCRUB_TRIG;
		sregx = X_VC_IVC_SCRUB_TRIG;
		mreg = VC_IVC_SCRUB_MASK;
		mregx = X_VC_IVC_SCRUB_MASK;
		break;
	case xive_cache_sbc:
		sreg = VC_SBC_SCRUB_TRIG;
		sregx = X_VC_SBC_SCRUB_TRIG;
		mreg = VC_SBC_SCRUB_MASK;
		mregx = X_VC_SBC_SCRUB_MASK;
		break;
	case xive_cache_eqc:
		sreg = VC_EQC_SCRUB_TRIG;
		sregx = X_VC_EQC_SCRUB_TRIG;
		mreg = VC_EQC_SCRUB_MASK;
		mregx = X_VC_EQC_SCRUB_MASK;
		break;
	case xive_cache_vpc:
		sreg = PC_VPC_SCRUB_TRIG;
		sregx = X_PC_VPC_SCRUB_TRIG;
		mreg = PC_VPC_SCRUB_MASK;
		mregx = X_PC_VPC_SCRUB_MASK;
		break;
	default:
		return OPAL_INTERNAL_ERROR;
	}
	if (ctype == xive_cache_vpc) {
		mval = PC_SCRUB_BLOCK_ID | PC_SCRUB_OFFSET;
		sval = SETFIELD(PC_SCRUB_BLOCK_ID, idx, block) |
			PC_SCRUB_VALID;
	} else {
		mval = VC_SCRUB_BLOCK_ID | VC_SCRUB_OFFSET;
		sval = SETFIELD(VC_SCRUB_BLOCK_ID, idx, block) |
			VC_SCRUB_VALID;
	}
	if (want_inval)
		sval |= PC_SCRUB_WANT_INVAL;
	if (want_disable)
		sval |= PC_SCRUB_WANT_DISABLE;

	__xive_regw(x, mreg, mregx, mval, NULL);
	__xive_regw(x, sreg, sregx, sval, NULL);

	/* XXX Add timeout !!! */
	for (;;) {
		sval = __xive_regr(x, sreg, sregx, NULL);
		if (!(sval & VC_SCRUB_VALID))
			break;
		/* Small delay */
		time_wait(100);
	}
	sync();

	/* Workaround for HW bug described above (only applies to
	 * EQC and VPC
	 */
	if (ctype == xive_cache_eqc)
		xive_scrub_workaround_eq(x, block, idx);
	else if (ctype == xive_cache_vpc)
		xive_scrub_workaround_vp(x, block, idx);

	return 0;
}

static int64_t xive_ivc_scrub(struct xive *x, uint64_t block, uint64_t idx)
{
	/* IVC has no "want_inval" bit, it always invalidates */
	return __xive_cache_scrub(x, xive_cache_ivc, block, idx, false, false);
}

static int64_t xive_vpc_scrub(struct xive *x, uint64_t block, uint64_t idx)
{
	return __xive_cache_scrub(x, xive_cache_vpc, block, idx, false, false);
}

static int64_t xive_vpc_scrub_clean(struct xive *x, uint64_t block, uint64_t idx)
{
	return __xive_cache_scrub(x, xive_cache_vpc, block, idx, true, false);
}

static int64_t xive_eqc_scrub(struct xive *x, uint64_t block, uint64_t idx)
{
	return __xive_cache_scrub(x, xive_cache_eqc, block, idx, false, false);
}

#define XIVE_CACHE_WATCH_MAX_RETRIES 10

static int64_t __xive_cache_watch(struct xive *x, enum xive_cache_type ctype,
				  uint64_t block, uint64_t idx,
				  uint32_t start_dword, uint32_t dword_count,
				  __be64 *new_data, bool light_watch,
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
	case xive_cache_eqc:
		sreg = VC_EQC_CWATCH_SPEC;
		sregx = X_VC_EQC_CWATCH_SPEC;
		dreg0 = VC_EQC_CWATCH_DAT0;
		dreg0x = X_VC_EQC_CWATCH_DAT0;
		sval = SETFIELD(VC_EQC_CWATCH_BLOCKID, idx, block);
		break;
	case xive_cache_vpc:
		sreg = PC_VPC_CWATCH_SPEC;
		sregx = X_PC_VPC_CWATCH_SPEC;
		dreg0 = PC_VPC_CWATCH_DAT0;
		dreg0x = X_PC_VPC_CWATCH_DAT0;
		sval = SETFIELD(PC_VPC_CWATCH_BLOCKID, idx, block);
		break;
	default:
		return OPAL_INTERNAL_ERROR;
	}

	/* The full bit is in the same position for EQC and VPC */
	if (!light_watch)
		sval |= VC_EQC_CWATCH_FULL;

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
		 * EQC and VPC
		 */
		if (!(status & VC_EQC_CWATCH_FULL) ||
		    !(status & VC_EQC_CWATCH_CONFLICT))
			break;
		if (!synchronous)
			return OPAL_BUSY;

		if (++retries == XIVE_CACHE_WATCH_MAX_RETRIES) {
			xive_err(x, "Reached maximum retries %d when doing "
				 "a %s cache update\n", retries,
				 ctype == xive_cache_eqc ? "EQC" : "VPC");
			return OPAL_BUSY;
		}
	}

	/* Perform a scrub with "want_invalidate" set to false to push the
	 * cache updates to memory as well
	 */
	return __xive_cache_scrub(x, ctype, block, idx, false, false);
}

static int64_t xive_escalation_ive_cache_update(struct xive *x, uint64_t block,
				     uint64_t idx, struct xive_ive *ive,
				     bool synchronous)
{
	return __xive_cache_watch(x, xive_cache_eqc, block, idx,
				  2, 1, &ive->w, true, synchronous);
}

static int64_t xive_eqc_cache_update(struct xive *x, uint64_t block,
				     uint64_t idx, struct xive_eq *eq,
				     bool synchronous)
{
	return __xive_cache_watch(x, xive_cache_eqc, block, idx,
				  0, 4, (__be64 *)eq, false, synchronous);
}

static int64_t xive_vpc_cache_update(struct xive *x, uint64_t block,
				     uint64_t idx, struct xive_vp *vp,
				     bool synchronous)
{
	return __xive_cache_watch(x, xive_cache_vpc, block, idx,
				  0, 8, (__be64 *)vp, false, synchronous);
}

static bool xive_set_vsd(struct xive *x, uint32_t tbl, uint32_t idx, uint64_t v)
{
	/* Set VC version */
	xive_regw(x, VC_VSD_TABLE_ADDR,
		  SETFIELD(VST_TABLE_SELECT, 0ull, tbl) |
		  SETFIELD(VST_TABLE_OFFSET, 0ull, idx));
	if (x->last_reg_error)
		return false;
	xive_regw(x, VC_VSD_TABLE_DATA, v);
	if (x->last_reg_error)
		return false;

	/* Except for IRQ table, also set PC version */
	if (tbl == VST_TSEL_IRQ)
		return true;

	xive_regw(x, PC_VSD_TABLE_ADDR,
		  SETFIELD(VST_TABLE_SELECT, 0ull, tbl) |
		  SETFIELD(VST_TABLE_OFFSET, 0ull, idx));
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
	assert(is_pow2(SBE_SIZE));
	assert(is_pow2(IVT_SIZE));

	/* All tables set as exclusive */
	base = SETFIELD(VSD_MODE, 0ull, VSD_MODE_EXCLUSIVE);

	/* Set IVT as direct mode */
	if (!xive_set_vsd(x, VST_TSEL_IVT, x->block_id, base |
			  (((uint64_t)x->ivt_base) & VSD_ADDRESS_MASK) |
			  SETFIELD(VSD_TSIZE, 0ull, ilog2(IVT_SIZE) - 12)))
		return false;

	/* Set SBE as direct mode */
	if (!xive_set_vsd(x, VST_TSEL_SBE, x->block_id, base |
			  (((uint64_t)x->sbe_base) & VSD_ADDRESS_MASK) |
			  SETFIELD(VSD_TSIZE, 0ull, ilog2(SBE_SIZE) - 12)))
		return false;

	/* Set EQDT as indirect mode with 64K subpages */
	if (!xive_set_vsd(x, VST_TSEL_EQDT, x->block_id, base |
			  (((uint64_t)x->eq_ind_base) & VSD_ADDRESS_MASK) |
			  VSD_INDIRECT | SETFIELD(VSD_TSIZE, 0ull, 4)))
		return false;

	/* Set VPDT as indirect mode with 64K subpages */
	if (!xive_set_vsd(x, VST_TSEL_VPDT, x->block_id, base |
			  (((uint64_t)x->vp_ind_base) & VSD_ADDRESS_MASK) |
			  VSD_INDIRECT | SETFIELD(VSD_TSIZE, 0ull, 4)))
		return false;

	/* Setup queue overflows */
	for (i = 0; i < VC_QUEUE_OVF_COUNT; i++) {
		u64 addr = ((uint64_t)x->q_ovf) + i * PAGE_SIZE;
		u64 cfg, sreg, sregx;

		if (!xive_set_vsd(x, VST_TSEL_IRQ, i, base |
				  (addr & VSD_ADDRESS_MASK) |
			  SETFIELD(VSD_TSIZE, 0ull, 4)))
			return false;
		sreg = VC_IRQ_CONFIG_IPI +  i * 8;
		sregx = X_VC_IRQ_CONFIG_IPI + i;
		cfg = __xive_regr(x, sreg, sregx, NULL);
		cfg |= VC_IRQ_CONFIG_MEMB_EN;
		cfg = SETFIELD(VC_IRQ_CONFIG_MEMB_SZ, cfg, 4);
		__xive_regw(x, sreg, sregx, cfg, NULL);
	}

	return true;
}

static bool xive_configure_bars(struct xive *x)
{
	uint64_t chip_id = x->chip_id;
	uint64_t val;

	/* IC BAR */
	phys_map_get(chip_id, XIVE_IC, 0, (uint64_t *)&x->ic_base, &x->ic_size);
	val = (uint64_t)x->ic_base | CQ_IC_BAR_VALID | CQ_IC_BAR_64K;
	x->ic_shift = 16;

	xive_regwx(x, CQ_IC_BAR, val);
	if (x->last_reg_error)
		return false;

	/* TM BAR, only configure TM1. Note that this has the same address
	 * for each chip !!!  Hence we create a fake chip 0 and use that for
	 * all phys_map_get(XIVE_TM) calls.
	 */
	phys_map_get(0, XIVE_TM, 0, (uint64_t *)&x->tm_base, &x->tm_size);
	val = (uint64_t)x->tm_base | CQ_TM_BAR_VALID | CQ_TM_BAR_64K;
	x->tm_shift = 16;

	xive_regwx(x, CQ_TM1_BAR, val);
	if (x->last_reg_error)
		return false;
	xive_regwx(x, CQ_TM2_BAR, 0);
	if (x->last_reg_error)
		return false;

	/* PC BAR. Clear first, write mask, then write value */
	phys_map_get(chip_id, XIVE_PC, 0, (uint64_t *)&x->pc_base, &x->pc_size);
	xive_regwx(x, CQ_PC_BAR, 0);
	if (x->last_reg_error)
		return false;
	val = ~(x->pc_size - 1) & CQ_PC_BARM_MASK;
	xive_regwx(x, CQ_PC_BARM, val);
	if (x->last_reg_error)
		return false;
	val = (uint64_t)x->pc_base | CQ_PC_BAR_VALID;
	xive_regwx(x, CQ_PC_BAR, val);
	if (x->last_reg_error)
		return false;

	/* VC BAR. Clear first, write mask, then write value */
	phys_map_get(chip_id, XIVE_VC, 0, (uint64_t *)&x->vc_base, &x->vc_size);
	xive_regwx(x, CQ_VC_BAR, 0);
	if (x->last_reg_error)
		return false;
	val = ~(x->vc_size - 1) & CQ_VC_BARM_MASK;
	xive_regwx(x, CQ_VC_BARM, val);
	if (x->last_reg_error)
		return false;
	val = (uint64_t)x->vc_base | CQ_VC_BAR_VALID;
	xive_regwx(x, CQ_VC_BAR, val);
	if (x->last_reg_error)
		return false;

	/* Calculate some MMIO bases in the VC BAR */
	x->esb_mmio = x->vc_base;
	x->eq_mmio = x->vc_base + (x->vc_size / VC_MAX_SETS) * VC_ESB_SETS;

	/* Print things out */
	xive_dbg(x, "IC: %14p [0x%012llx/%d]\n", x->ic_base, x->ic_size,
		 x->ic_shift);
	xive_dbg(x, "TM: %14p [0x%012llx/%d]\n", x->tm_base, x->tm_size,
		 x->tm_shift);
	xive_dbg(x, "PC: %14p [0x%012llx]\n", x->pc_base, x->pc_size);
	xive_dbg(x, "VC: %14p [0x%012llx]\n", x->vc_base, x->vc_size);

	return true;
}

static void xive_dump_mmio(struct xive *x)
{
	prlog(PR_DEBUG, " CQ_CFG_PB_GEN = %016llx\n",
	      in_be64(x->ic_base + CQ_CFG_PB_GEN));
	prlog(PR_DEBUG, " CQ_MSGSND     = %016llx\n",
	      in_be64(x->ic_base + CQ_MSGSND));
}

static bool xive_config_init(struct xive *x)
{
	uint64_t val;

	/* Configure PC and VC page sizes and disable Linux trigger mode */
	xive_regwx(x, CQ_PBI_CTL, CQ_PBI_PC_64K | CQ_PBI_VC_64K | CQ_PBI_FORCE_TM_LOCAL);
	if (x->last_reg_error)
		return false;

	/*** The rest can use MMIO ***/

	/* Enable indirect mode in VC config */
	val = xive_regr(x, VC_GLOBAL_CONFIG);
	val |= VC_GCONF_INDIRECT;
	xive_regw(x, VC_GLOBAL_CONFIG, val);

	/* Enable indirect mode in PC config */
	val = xive_regr(x, PC_GLOBAL_CONFIG);
	val |= PC_GCONF_INDIRECT;
	val |= PC_GCONF_CHIPID_OVR;
	val = SETFIELD(PC_GCONF_CHIPID, val, x->block_id);
	xive_regw(x, PC_GLOBAL_CONFIG, val);
	xive_dbg(x, "PC_GLOBAL_CONFIG=%016llx\n", val);

	val = xive_regr(x, PC_TCTXT_CFG);
	val |= PC_TCTXT_CFG_BLKGRP_EN | PC_TCTXT_CFG_HARD_CHIPID_BLK;
	val |= PC_TCTXT_CHIPID_OVERRIDE;
	val |= PC_TCTXT_CFG_TARGET_EN;
	val = SETFIELD(PC_TCTXT_CHIPID, val, x->block_id);
	val = SETFIELD(PC_TCTXT_INIT_AGE, val, 0x2);
	val |= PC_TCTXT_CFG_LGS_EN;
	/* Disable pressure relief as we hijack the field in the VPs */
	val &= ~PC_TCTXT_CFG_STORE_ACK;
	if (this_cpu()->is_fused_core)
		val |= PC_TCTXT_CFG_FUSE_CORE_EN;
	else
		val &= ~PC_TCTXT_CFG_FUSE_CORE_EN;
	xive_regw(x, PC_TCTXT_CFG, val);
	xive_dbg(x, "PC_TCTXT_CFG=%016llx\n", val);

	val = xive_regr(x, CQ_CFG_PB_GEN);
	/* 1-block-per-chip mode */
	val = SETFIELD(CQ_INT_ADDR_OPT, val, 2);
	xive_regw(x, CQ_CFG_PB_GEN, val);

	/* Enable StoreEOI */
	val = xive_regr(x, VC_SBC_CONFIG);
	if (XIVE_CAN_STORE_EOI(x))
		val |= VC_SBC_CONF_CPLX_CIST | VC_SBC_CONF_CIST_BOTH;
	else
		xive_dbg(x, "store EOI is disabled\n");

	val |= VC_SBC_CONF_NO_UPD_PRF;
	xive_regw(x, VC_SBC_CONFIG, val);

	/* Disable block tracking on Nimbus (we may want to enable
	 * it on Cumulus later). HW Erratas.
	 */
	val = xive_regr(x, PC_TCTXT_TRACK);
	val &= ~PC_TCTXT_TRACK_EN;
	xive_regw(x, PC_TCTXT_TRACK, val);

	/* Enable relaxed ordering of trigger forwarding */
	val = xive_regr(x, VC_AIB_TX_ORDER_TAG2);
	val |= VC_AIB_TX_ORDER_TAG2_REL_TF;
	xive_regw(x, VC_AIB_TX_ORDER_TAG2, val);

	/* Enable new END s and u bits for silent escalate */
	val = xive_regr(x, VC_EQC_CONFIG);
	val |= VC_EQC_CONF_ENABLE_END_s_BIT;
	val |= VC_EQC_CONF_ENABLE_END_u_BIT;
	xive_regw(x, VC_EQC_CONFIG, val);

	/* Disable error reporting in the FIR for info errors
	 * from the VC.
	 */
	xive_regw(x, CQ_FIRMASK_OR, CQ_FIR_VC_INFO_ERROR_0_1);

	/* Mask CI Load and Store to bad location, as IPI trigger
	 * pages may be mapped to user space, and a read on the
	 * trigger page causes a checkstop
	 */
	xive_regw(x, CQ_FIRMASK_OR, CQ_FIR_PB_RCMDX_CI_ERR1);

	return true;
}

static bool xive_setup_set_xlate(struct xive *x)
{
	unsigned int i;

	/* Configure EDT for ESBs (aka IPIs) */
	xive_regw(x, CQ_TAR, CQ_TAR_TBL_AUTOINC | CQ_TAR_TSEL_EDT);
	if (x->last_reg_error)
		return false;
	for (i = 0; i < VC_ESB_SETS; i++) {
		xive_regw(x, CQ_TDR,
			  /* IPI type */
			  (1ull << 62) |
			  /* block ID */
			  (((uint64_t)x->block_id) << 48) |
			  /* offset */
			  (((uint64_t)i) << 32));
		if (x->last_reg_error)
			return false;
	}

	/* Configure EDT for ENDs (aka EQs) */
	for (i = 0; i < VC_END_SETS; i++) {
		xive_regw(x, CQ_TDR,
			  /* EQ type */
			  (2ull << 62) |
			  /* block ID */
			  (((uint64_t)x->block_id) << 48) |
			  /* offset */
			  (((uint64_t)i) << 32));
		if (x->last_reg_error)
			return false;
	}

	/* Configure VDT */
	xive_regw(x, CQ_TAR, CQ_TAR_TBL_AUTOINC | CQ_TAR_TSEL_VDT);
	if (x->last_reg_error)
		return false;
	for (i = 0; i < PC_MAX_SETS; i++) {
		xive_regw(x, CQ_TDR,
			  /* Valid bit */
			  (1ull << 63) |
			  /* block ID */
			  (((uint64_t)x->block_id) << 48) |
			  /* offset */
			  (((uint64_t)i) << 32));
		if (x->last_reg_error)
			return false;
	}
	return true;
}

static bool xive_prealloc_tables(struct xive *x)
{
	uint32_t i, vp_init_count, vp_init_base;
	uint32_t pbase, pend;
	uint64_t al;

	/* ESB/SBE has 4 entries per byte */
	x->sbe_base = local_alloc(x->chip_id, SBE_SIZE, SBE_SIZE);
	if (!x->sbe_base) {
		xive_err(x, "Failed to allocate SBE\n");
		return false;
	}
	/* SBEs are initialized to 0b01 which corresponds to "ints off" */
	memset(x->sbe_base, 0x55, SBE_SIZE);
	xive_dbg(x, "SBE at %p size 0x%lx\n", x->sbe_base, SBE_SIZE);

	/* EAS/IVT entries are 8 bytes */
	x->ivt_base = local_alloc(x->chip_id, IVT_SIZE, IVT_SIZE);
	if (!x->ivt_base) {
		xive_err(x, "Failed to allocate IVT\n");
		return false;
	}
	/* We clear the entries (non-valid). They will be initialized
	 * when actually used
	 */
	memset(x->ivt_base, 0, IVT_SIZE);
	xive_dbg(x, "IVT at %p size 0x%lx\n", x->ivt_base, IVT_SIZE);

	/* Indirect EQ table.  Limited to one top page. */
	al = ALIGN_UP(XIVE_EQ_TABLE_SIZE, PAGE_SIZE);
	if (al > PAGE_SIZE) {
		xive_err(x, "EQ indirect table is too big !\n");
		return false;
	}
	x->eq_ind_base = local_alloc(x->chip_id, al, al);
	if (!x->eq_ind_base) {
		xive_err(x, "Failed to allocate EQ indirect table\n");
		return false;
	}
	memset(x->eq_ind_base, 0, al);
	xive_dbg(x, "EQi at %p size 0x%llx\n", x->eq_ind_base, al);
	x->eq_ind_count = XIVE_EQ_TABLE_SIZE / XIVE_VSD_SIZE;

	/* Indirect VP table.  Limited to one top page. */
	al = ALIGN_UP(XIVE_VP_TABLE_SIZE, PAGE_SIZE);
	if (al > PAGE_SIZE) {
		xive_err(x, "VP indirect table is too big !\n");
		return false;
	}
	x->vp_ind_base = local_alloc(x->chip_id, al, al);
	if (!x->vp_ind_base) {
		xive_err(x, "Failed to allocate VP indirect table\n");
		return false;
	}
	xive_dbg(x, "VPi at %p size 0x%llx\n", x->vp_ind_base, al);
	x->vp_ind_count = XIVE_VP_TABLE_SIZE / XIVE_VSD_SIZE;
	memset(x->vp_ind_base, 0, al);

	/* Populate/initialize VP/EQs indirect backing */
	vp_init_count = XIVE_HW_VP_COUNT;
	vp_init_base = XIVE_HW_VP_BASE;

	/* Allocate pages for some VPs in indirect mode */
	pbase = vp_init_base / VP_PER_PAGE;
	pend  = (vp_init_base + vp_init_count) / VP_PER_PAGE;

	xive_dbg(x, "Allocating pages %d to %d of VPs (for %d VPs)\n",
		 pbase, pend, vp_init_count);
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

	/* Allocate the queue overflow pages */
	x->q_ovf = local_alloc(x->chip_id, VC_QUEUE_OVF_COUNT * PAGE_SIZE, PAGE_SIZE);
	if (!x->q_ovf) {
		xive_err(x, "Failed to allocate queue overflow\n");
		return false;
	}
	return true;
}

static void xive_add_provisioning_properties(void)
{
	__be32 chips[XIVE_MAX_CHIPS];
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
			      NUM_INT_PRIORITIES);
	dt_add_property(xive_dt_node, "single-escalation-support", NULL, 0);

	xive_add_provisioning_properties();
}

static void xive_setup_forward_ports(struct xive *x, struct proc_chip *remote_chip)
{
	struct xive *remote_xive = remote_chip->xive;
	uint64_t base = SETFIELD(VSD_MODE, 0ull, VSD_MODE_FORWARD);
	uint32_t remote_id = remote_xive->block_id;
	uint64_t nport;

	/* ESB(SBE), EAS(IVT) and END(EQ) point to the notify port */
	nport = ((uint64_t)remote_xive->ic_base) + (1ul << remote_xive->ic_shift);
	if (!xive_set_vsd(x, VST_TSEL_IVT, remote_id, base | nport))
		goto error;
	if (!xive_set_vsd(x, VST_TSEL_SBE, remote_id, base | nport))
		goto error;
	if (!xive_set_vsd(x, VST_TSEL_EQDT, remote_id, base | nport))
		goto error;

	/* NVT/VPD points to the remote NVT MMIO sets */
	if (!xive_set_vsd(x, VST_TSEL_VPDT, remote_id,
			  base | ((uint64_t)remote_xive->pc_base) |
			  SETFIELD(VSD_TSIZE, 0ull, ilog2(x->pc_size) - 12)))
		goto error;

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

uint32_t xive_alloc_hw_irqs(uint32_t chip_id, uint32_t count, uint32_t align)
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

	/* Initialize the corresponding IVT entries to sane defaults,
	 * IE entry is valid, not routed and masked, EQ data is set
	 * to the GIRQ number.
	 */
	for (i = 0; i < count; i++) {
		struct xive_ive *ive = xive_get_ive(x, base + i);

		ive->w = xive_set_field64(IVE_VALID, 0ul, 1) |
			 xive_set_field64(IVE_MASKED, 0ul, 1) |
			 xive_set_field64(IVE_EQ_DATA, 0ul, base + i);
	}

	unlock(&x->lock);
	return base;
}

uint32_t xive_alloc_ipi_irqs(uint32_t chip_id, uint32_t count, uint32_t align)
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

	/* Initialize the corresponding IVT entries to sane defaults,
	 * IE entry is valid, not routed and masked, EQ data is set
	 * to the GIRQ number.
	 */
	for (i = 0; i < count; i++) {
		struct xive_ive *ive = xive_get_ive(x, base + i);

		ive->w = xive_set_field64(IVE_VALID, 0ul, 1) |
			 xive_set_field64(IVE_MASKED, 0ul, 1) |
			 xive_set_field64(IVE_EQ_DATA, 0ul, base + i);
	}

	unlock(&x->lock);
	return base;
}

void *xive_get_trigger_port(uint32_t girq)
{
	uint32_t idx = GIRQ_TO_IDX(girq);
	struct xive *x;

	/* Find XIVE on which the IVE resides */
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

		return x->esb_mmio + idx * XIVE_ESB_PAGE_SIZE;
	}
}

uint64_t xive_get_notify_port(uint32_t chip_id, uint32_t ent)
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
	switch(ent) {
	case XIVE_HW_SRC_PHBn(0):
		offset = 0x100;
		break;
	case XIVE_HW_SRC_PHBn(1):
		offset = 0x208;
		break;
	case XIVE_HW_SRC_PHBn(2):
		offset = 0x210;
		break;
	case XIVE_HW_SRC_PHBn(3):
		offset = 0x218;
		break;
	case XIVE_HW_SRC_PHBn(4):
		offset = 0x220;
		break;
	case XIVE_HW_SRC_PHBn(5):
		offset = 0x228;
		break;
	case XIVE_HW_SRC_PSI:
		offset = 0x230;
		break;
	default:
		assert(false);
		return 0;
	}

	/* Notify port is the second page of the IC BAR */
	return ((uint64_t)x->ic_base) + (1ul << x->ic_shift) + offset;
}

/* Manufacture the powerbus packet bits 32:63 */
__attrconst uint32_t xive_get_notify_base(uint32_t girq)
{
	return (GIRQ_TO_BLK(girq) << 28)  | GIRQ_TO_IDX(girq);
}

static bool xive_get_irq_targetting(uint32_t isn, uint32_t *out_target,
				    uint8_t *out_prio, uint32_t *out_lirq)
{
	struct xive_ive *ive;
	struct xive *x, *eq_x;
	struct xive_eq *eq;
	uint32_t eq_blk, eq_idx;
	uint32_t vp_blk __unused, vp_idx;
	uint32_t prio, server;
	bool is_escalation = GIRQ_IS_ESCALATION(isn);

	/* Find XIVE on which the IVE resides */
	x = xive_from_isn(isn);
	if (!x)
		return false;
	/* Grab the IVE */
	ive = xive_get_ive(x, isn);
	if (!ive)
		return false;
	if (!xive_get_field64(IVE_VALID, ive->w) && !is_escalation) {
		xive_err(x, "ISN %x lead to invalid IVE !\n", isn);
		return false;
	}

	if (out_lirq)
		*out_lirq = xive_get_field64(IVE_EQ_DATA, ive->w);

	/* Find the EQ and its xive instance */
	eq_blk = xive_get_field64(IVE_EQ_BLOCK, ive->w);
	eq_idx = xive_get_field64(IVE_EQ_INDEX, ive->w);
	eq_x = xive_from_vc_blk(eq_blk);

	/* This can fail if the interrupt hasn't been initialized yet
	 * but it should also be masked, so fail silently
	 */
	if (!eq_x)
		goto pick_default;
	eq = xive_get_eq(eq_x, eq_idx);
	if (!eq)
		goto pick_default;

	/* XXX Check valid and format 0 */

	/* No priority conversion, return the actual one ! */
	if (xive_get_field64(IVE_MASKED, ive->w))
		prio = 0xff;
	else
		prio = xive_get_field32(EQ_W7_F0_PRIORITY, eq->w7);
	if (out_prio)
		*out_prio = prio;

	vp_blk = xive_get_field32(EQ_W6_NVT_BLOCK, eq->w6);
	vp_idx = xive_get_field32(EQ_W6_NVT_INDEX, eq->w6);
	server = VP2PIR(vp_blk, vp_idx);

	if (out_target)
		*out_target = server;

	xive_vdbg(eq_x, "EQ info for ISN %x: prio=%d, server=0x%x (VP %x/%x)\n",
		  isn, prio, server, vp_blk, vp_idx);
	return true;

pick_default:
	xive_vdbg(eq_x, "EQ info for ISN %x: Using masked defaults\n", isn);

	if (out_prio)
		*out_prio = 0xff;
	/* Pick a random default, me will be fine ... */
	if (out_target)
		*out_target = mfspr(SPR_PIR);
	return true;
}

static inline bool xive_eq_for_target(uint32_t target, uint8_t prio,
				      uint32_t *out_eq_blk,
				      uint32_t *out_eq_idx)
{
	struct xive *x;
	struct xive_vp *vp;
	uint32_t vp_blk, vp_idx;
	uint32_t eq_blk, eq_idx;

	if (prio > XIVE_MAX_PRIO)
		return false;

	/* Get the VP block/index from the target word */
	if (!xive_decode_vp(target, &vp_blk, &vp_idx, NULL, NULL))
		return false;

	/* Grab the target VP's XIVE */
	x = xive_from_pc_blk(vp_blk);
	if (!x)
		return false;

	/* Find the VP structrure where we stashed the EQ number */
	vp = xive_get_vp(x, vp_idx);
	if (!vp)
		return false;

	/* Grab it, it's in the pressure relief interrupt field,
	 * top 4 bits are the block (word 1).
	 */
	eq_blk = be32_to_cpu(vp->w1) >> 28;
	eq_idx = be32_to_cpu(vp->w1) & 0x0fffffff;

	/* Currently the EQ block and VP block should be the same */
	if (eq_blk != vp_blk) {
		xive_err(x, "eq_blk != vp_blk (%d vs. %d) for target 0x%08x/%d\n",
			 eq_blk, vp_blk, target, prio);
		return false;
	}

	if (out_eq_blk)
		*out_eq_blk = eq_blk;
	if (out_eq_idx)
		*out_eq_idx = eq_idx + prio;

	return true;
}

static int64_t xive_set_irq_targetting(uint32_t isn, uint32_t target,
				       uint8_t prio, uint32_t lirq,
				       bool synchronous)
{
	struct xive *x;
	struct xive_ive *ive, new_ive;
	uint32_t eq_blk, eq_idx;
	bool is_escalation = GIRQ_IS_ESCALATION(isn);
	int64_t rc;

	/* Find XIVE on which the IVE resides */
	x = xive_from_isn(isn);
	if (!x)
		return OPAL_PARAMETER;
	/* Grab the IVE */
	ive = xive_get_ive(x, isn);
	if (!ive)
		return OPAL_PARAMETER;
	if (!xive_get_field64(IVE_VALID, ive->w) && !is_escalation) {
		xive_err(x, "ISN %x lead to invalid IVE !\n", isn);
		return OPAL_PARAMETER;
	}

	lock(&x->lock);

	/* If using emulation mode, fixup prio to the only supported one */
	if (xive_mode == XIVE_MODE_EMU && prio != 0xff)
		prio = XIVE_EMULATION_PRIO;

	/* Read existing IVE */
	new_ive = *ive;

	/* Are we masking ? */
	if (prio == 0xff && !is_escalation) {
		new_ive.w = xive_set_field64(IVE_MASKED, new_ive.w, 1);
		xive_vdbg(x, "ISN %x masked !\n", isn);

		/* Put prio 7 in the EQ */
		prio = XIVE_MAX_PRIO;
	} else {
		/* Unmasking */
		new_ive.w = xive_set_field64(IVE_MASKED, new_ive.w, 0);
		xive_vdbg(x, "ISN %x unmasked !\n", isn);

		/* For normal interrupt sources, keep track of which ones
		 * we ever enabled since the last reset
		 */
		if (!is_escalation)
			bitmap_set_bit(*x->int_enabled_map, GIRQ_TO_IDX(isn));
	}

	/* If prio isn't 0xff, re-target the IVE. First find the EQ
	 * correponding to the target
	 */
	if (prio != 0xff) {
		if (!xive_eq_for_target(target, prio, &eq_blk, &eq_idx)) {
			xive_err(x, "Can't find EQ for target/prio 0x%x/%d\n",
				 target, prio);
			unlock(&x->lock);
			return OPAL_PARAMETER;
		}

		/* Try to update it atomically to avoid an intermediary
		 * stale state
		 */
		new_ive.w = xive_set_field64(IVE_EQ_BLOCK, new_ive.w, eq_blk);
		new_ive.w = xive_set_field64(IVE_EQ_INDEX, new_ive.w, eq_idx);
	}
	new_ive.w = xive_set_field64(IVE_EQ_DATA, new_ive.w, lirq);

	xive_vdbg(x,"ISN %x routed to eq %x/%x lirq=%08x IVE=%016llx !\n",
		  isn, eq_blk, eq_idx, lirq, be64_to_cpu(new_ive.w));

	/* Updating the cache differs between real IVEs and escalation
	 * IVEs inside an EQ
	 */
	if (is_escalation) {
		rc = xive_escalation_ive_cache_update(x, x->block_id,
				GIRQ_TO_IDX(isn), &new_ive, synchronous);
	} else {
		sync();
		*ive = new_ive;
		rc = xive_ivc_scrub(x, x->block_id, GIRQ_TO_IDX(isn));
	}

	unlock(&x->lock);
	return rc;
}

static int64_t xive_source_get_xive(struct irq_source *is __unused,
				    uint32_t isn, uint16_t *server,
				    uint8_t *prio)
{
	uint32_t target_id;

	if (xive_get_irq_targetting(isn, &target_id, prio, NULL)) {
		*server = target_id << 2;
		return OPAL_SUCCESS;
	} else
		return OPAL_PARAMETER;
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

static int64_t xive_sync(struct xive *x)
{
	uint64_t r;
	void *p;

	lock(&x->lock);

	/* Second 2K range of second page */
	p = x->ic_base + (1 << x->ic_shift) + 0x800;

	/* TODO: Make this more fine grained */
	out_be64(p + (10 << 7), 0); /* Sync OS escalations */
	out_be64(p + (11 << 7), 0); /* Sync Hyp escalations */
	out_be64(p + (12 << 7), 0); /* Sync Redistribution */
	out_be64(p + ( 8 << 7), 0); /* Sync IPI */
	out_be64(p + ( 9 << 7), 0); /* Sync HW */

#define SYNC_MASK                \
	(VC_EQC_CONF_SYNC_IPI  | \
	 VC_EQC_CONF_SYNC_HW   | \
	 VC_EQC_CONF_SYNC_ESC1 | \
	 VC_EQC_CONF_SYNC_ESC2 | \
	 VC_EQC_CONF_SYNC_REDI)

	/* XXX Add timeout */
	for (;;) {
		r = xive_regr(x, VC_EQC_CONFIG);
		if ((r & SYNC_MASK) == SYNC_MASK)
			break;
		cpu_relax();
	}
	xive_regw(x, VC_EQC_CONFIG, r & ~SYNC_MASK);

	/* Workaround HW issue, read back before allowing a new sync */
	xive_regr(x, VC_GLOBAL_CONFIG);

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

	/* Let XIVE configure the EQ. We do the update without the
	 * synchronous flag, thus a cache update failure will result
	 * in us returning OPAL_BUSY
	 */
	rc = xive_set_irq_targetting(girq, vp, prio, lirq, false);
	if (rc)
		return rc;

	/* Do we need to update the mask ? */
	if (old_prio != prio && (old_prio == 0xff || prio == 0xff)) {
		/* The source has special variants of masking/unmasking */
		if (s->orig_ops && s->orig_ops->set_xive) {
			/* We don't pass as server on source ops ! Targetting
			 * is handled by the XIVE
			 */
			rc = s->orig_ops->set_xive(is, girq, 0, prio);
		} else if (update_esb) {
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

static int64_t xive_source_set_xive(struct irq_source *is,
				    uint32_t isn, uint16_t server, uint8_t prio)
{
	/*
	 * WARNING: There is an inherent race with the use of the
	 * mask bit in the EAS/IVT. When masked, interrupts are "lost"
	 * but their P/Q bits are still set. So when unmasking, one has
	 * to check the P bit and possibly trigger a resend.
	 *
	 * We "deal" with it by relying on the fact that the OS will
	 * lazy disable MSIs. Thus mask will only be called if the
	 * interrupt occurred while already logically masked. Thus
	 * losing subsequent occurrences is of no consequences, we just
	 * need to "cleanup" P and Q when unmasking.
	 *
	 * This needs to be documented in the OPAL APIs
	 */

	/* Unmangle server */
	server >>= 2;

	/* Set logical irq to match isn */
	return __xive_set_irq_config(is, isn, server, prio, isn, true, true);
}

static void __xive_source_eoi(struct irq_source *is, uint32_t isn)
{
	struct xive_src *s = container_of(is, struct xive_src, is);
	uint32_t idx = isn - s->esb_base;
	struct xive_ive *ive;
	void *mmio_base;
	uint64_t eoi_val;

	/* Grab the IVE */
	ive = s->xive->ivt_base;
	if (!ive)
		return;
	ive += GIRQ_TO_IDX(isn);

	/* XXX To fix the races with mask/unmask potentially causing
	 * multiple queue entries, we need to keep track of EOIs here,
	 * before the masked test below
	 */

	/* If it's invalid or masked, don't do anything */
	if (xive_get_field64(IVE_MASKED, ive->w) || !xive_get_field64(IVE_VALID, ive->w))
		return;

	/* Grab MMIO control address for that ESB */
	mmio_base = s->esb_mmio + (1ull << s->esb_shift) * idx;

	/* If the XIVE supports the new "store EOI facility, use it */
	if (s->flags & XIVE_SRC_STORE_EOI)
		out_be64(mmio_base + XIVE_ESB_STORE_EOI, 0);
	else {
		uint64_t offset;

		/* Otherwise for EOI, we use the special MMIO that does
		 * a clear of both P and Q and returns the old Q.
		 *
		 * This allows us to then do a re-trigger if Q was set
		 * rather than synthetizing an interrupt in software
		 */
		if (s->flags & XIVE_SRC_EOI_PAGE1)
			mmio_base += 1ull << (s->esb_shift - 1);

		/* LSIs don't need anything special, just EOI */
		if (s->flags & XIVE_SRC_LSI)
			in_be64(mmio_base);
		else {
			offset = XIVE_ESB_SET_PQ_00;
			eoi_val = in_be64(mmio_base + offset);
			xive_vdbg(s->xive, "ISN: %08x EOI=%llx\n",
				  isn, eoi_val);
			if (!(eoi_val & 1))
				return;

			/* Re-trigger always on page0 or page1 ? */
			out_be64(mmio_base + XIVE_ESB_STORE_TRIGGER, 0);
		}
	}
}

static void xive_source_eoi(struct irq_source *is, uint32_t isn)
{
	struct xive_src *s = container_of(is, struct xive_src, is);

	if (s->orig_ops && s->orig_ops->eoi)
		s->orig_ops->eoi(is, isn);
	else
		__xive_source_eoi(is, isn);
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

void xive_source_mask(struct irq_source *is, uint32_t isn)
{
	struct xive_src *s = container_of(is, struct xive_src, is);

	xive_update_irq_mask(s, isn - s->esb_base, true);
}

static const struct irq_source_ops xive_irq_source_ops = {
	.get_xive = xive_source_get_xive,
	.set_xive = xive_source_set_xive,
	.eoi = xive_source_eoi,
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

void xive_register_hw_source(uint32_t base, uint32_t count, uint32_t shift,
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

void xive_register_ipi_source(uint32_t base, uint32_t count, void *data,
			      const struct irq_source_ops *ops)
{
	struct xive_src *s;
	struct xive *x = xive_from_isn(base);
	uint32_t base_idx = GIRQ_TO_IDX(base);
	void *mmio_base;
	uint32_t flags = XIVE_SRC_EOI_PAGE1 | XIVE_SRC_TRIGGER_PAGE;

	assert(x);
	assert(base >= x->int_base && (base + count) <= x->int_ipi_top);

	s = malloc(sizeof(struct xive_src));
	assert(s);

	/* Store EOI supported on DD2.0 */
	if (XIVE_CAN_STORE_EOI(x))
		flags |= XIVE_SRC_STORE_EOI;

	/* Callbacks assume the MMIO base corresponds to the first
	 * interrupt of that source structure so adjust it
	 */
	mmio_base = x->esb_mmio + (1ul << XIVE_ESB_SHIFT) * base_idx;
	__xive_register_source(x, s, base, count, XIVE_ESB_SHIFT, mmio_base,
			       flags, false, data, ops);
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

	/* All supported P9 are revision 2 (Nimbus DD2) */
	switch (chip->type) {
	case PROC_CHIP_P9_NIMBUS:
		/* We should not be able to boot a P9N DD1 */
		assert((chip->ec_level & 0xf0) != 0x10);
		/* Fallthrough */
	case PROC_CHIP_P9_CUMULUS:
	case PROC_CHIP_P9P:
		break;
	default:
		assert(0);
	}

	xive_dbg(x, "Initializing block ID %d...\n", x->block_id);
	chip->xive = x;

	list_head_init(&x->donated_pages);

	/* Base interrupt numbers and allocator init */
	/* XXX Consider allocating half as many ESBs than MMIO space
	 * so that HW sources land outside of ESB space...
	 */
	x->int_base	= BLKIDX_TO_GIRQ(x->block_id, 0);
	x->int_max	= x->int_base + XIVE_INT_COUNT;
	x->int_hw_bot	= x->int_max;
	x->int_ipi_top	= x->int_base;

	/* Make sure we never hand out "2" as it's reserved for XICS emulation
	 * IPI returns. Generally start handing out at 0x10
	 */
	if (x->int_ipi_top < XIVE_INT_FIRST)
		x->int_ipi_top = XIVE_INT_FIRST;

	/* Allocate a few bitmaps */
	x->eq_map = local_alloc(x->chip_id, BITMAP_BYTES(XIVE_EQ_COUNT >> 3), PAGE_SIZE);
	assert(x->eq_map);
	memset(x->eq_map, 0, BITMAP_BYTES(XIVE_EQ_COUNT >> 3));

	/* Make sure we don't hand out 0 */
	bitmap_set_bit(*x->eq_map, 0);

	x->int_enabled_map = local_alloc(x->chip_id, BITMAP_BYTES(XIVE_INT_COUNT), PAGE_SIZE);
	assert(x->int_enabled_map);
	memset(x->int_enabled_map, 0, BITMAP_BYTES(XIVE_INT_COUNT));
	x->ipi_alloc_map = local_alloc(x->chip_id, BITMAP_BYTES(XIVE_INT_COUNT), PAGE_SIZE);
	assert(x->ipi_alloc_map);
	memset(x->ipi_alloc_map, 0, BITMAP_BYTES(XIVE_INT_COUNT));

	xive_dbg(x, "Handling interrupts [%08x..%08x]\n",
		 x->int_base, x->int_max - 1);

	/* Setup the BARs */
	if (!xive_configure_bars(x))
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

	/* Configure local tables in VSDs (forward ports will be
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
			       x->esb_mmio, flags, true, NULL, NULL);

	/* Register escalation sources */
	__xive_register_source(x, &x->esc_irqs,
			       MAKE_ESCALATION_GIRQ(x->block_id, 0),
			       XIVE_EQ_COUNT, XIVE_EQ_SHIFT,
			       x->eq_mmio, XIVE_SRC_EOI_PAGE1,
			       false, NULL, NULL);


	return x;
 fail:
	xive_err(x, "Initialization failed...\n");

	/* Should this be fatal ? */
	//assert(false);
	return NULL;
}

/*
 * XICS emulation
 */
static void xive_ipi_init(struct xive *x, struct cpu_thread *cpu)
{
	struct xive_cpu_state *xs = cpu->xstate;

	assert(xs);

	__xive_set_irq_config(&x->ipis.is, xs->ipi_irq, cpu->pir,
			      XIVE_EMULATION_PRIO, xs->ipi_irq,
			      true, true);
}

static void xive_ipi_eoi(struct xive *x, uint32_t idx)
{
	uint8_t *mm = x->esb_mmio + idx * XIVE_ESB_PAGE_SIZE;
	uint8_t eoi_val;

	/* For EOI, we use the special MMIO that does a clear of both
	 * P and Q and returns the old Q.
	 *
	 * This allows us to then do a re-trigger if Q was set rather
	 * than synthetizing an interrupt in software
	 */
	eoi_val = in_8(mm + PAGE_SIZE + XIVE_ESB_SET_PQ_00);
	if (eoi_val & 1) {
		out_8(mm + XIVE_ESB_STORE_TRIGGER, 0);
	}
}

static void xive_ipi_trigger(struct xive *x, uint32_t idx)
{
	uint8_t *mm = x->esb_mmio + idx * XIVE_ESB_PAGE_SIZE;

	xive_vdbg(x, "Trigger IPI 0x%x\n", idx);

	out_8(mm + XIVE_ESB_STORE_TRIGGER, 0);
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
		xive_regw(x, PC_THREAD_EN_REG0_CLR, PPC_BIT(bit));
		xive_regw(x, PC_THREAD_EN_REG0_SET, PPC_BIT(bit));

		/*
		 * To guarantee that the TIMA accesses will see the
		 * latest state of the enable register, add an extra
		 * load on PC_THREAD_EN_REG.
		 */
		enable = xive_regr(x, PC_THREAD_EN_REG0);
		if (!(enable & PPC_BIT(bit)))
			xive_cpu_err(c, "Failed to enable thread\n");
	} else {
		xive_regw(x, PC_THREAD_EN_REG1_CLR, PPC_BIT(bit));
		xive_regw(x, PC_THREAD_EN_REG1_SET, PPC_BIT(bit));

		/* Same as above */
		enable = xive_regr(x, PC_THREAD_EN_REG1);
		if (!(enable & PPC_BIT(bit)))
			xive_cpu_err(c, "Failed to enable thread\n");
	}
}

void xive_cpu_callin(struct cpu_thread *cpu)
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

#ifdef XIVE_DEBUG_INIT_CACHE_UPDATES
static bool xive_check_eq_update(struct xive *x, uint32_t idx, struct xive_eq *eq)
{
	struct xive_eq *eq_p = xive_get_eq(x, idx);
	struct xive_eq eq2;

	assert(eq_p);
	eq2 = *eq_p;
	if (memcmp(eq, &eq2, sizeof(struct xive_eq)) != 0) {
		xive_err(x, "EQ update mismatch idx %d\n", idx);
		xive_err(x, "want: %08x %08x %08x %08x\n",
			 be32_to_cpu(eq->w0), be32_to_cpu(eq->w1),
			 be32_to_cpu(eq->w2), be32_to_cpu(eq->w3));
		xive_err(x, "      %08x %08x %08x %08x\n",
			 be32_to_cpu(eq->w4), be32_to_cpu(eq->w5),
			 be32_to_cpu(eq->w6), be32_to_cpu(eq->w7));
		xive_err(x, "got : %08x %08x %08x %08x\n",
			 be32_to_cpu(eq2.w0), be32_to_cpu(eq2.w1),
			 be32_to_cpu(eq2.w2), be32_to_cpu(eq2.w3));
		xive_err(x, "      %08x %08x %08x %08x\n",
			 be32_to_cpu(eq2.w4), be32_to_cpu(eq2.w5),
			 be32_to_cpu(eq2.w6), be32_to_cpu(eq2.w7));
		return false;
	}
	return true;
}

static bool xive_check_vpc_update(struct xive *x, uint32_t idx, struct xive_vp *vp)
{
	struct xive_vp *vp_p = xive_get_vp(x, idx);
	struct xive_vp vp2;

	assert(vp_p);
	vp2 = *vp_p;
	if (memcmp(vp, &vp2, sizeof(struct xive_vp)) != 0) {
		xive_err(x, "VP update mismatch idx %d\n", idx);
		xive_err(x, "want: %08x %08x %08x %08x\n",
			 be32_to_cpu(vp->w0), be32_to_cpu(vp->w1),
			 be32_to_cpu(vp->w2), be32_to_cpu(vp->w3));
		xive_err(x, "      %08x %08x %08x %08x\n",
			 be32_to_cpu(vp->w4), be32_to_cpu(vp->w5),
			 be32_to_cpu(vp->w6), be32_to_cpu(vp->w7));
		xive_err(x, "got : %08x %08x %08x %08x\n",
			 be32_to_cpu(vp2.w0), be32_to_cpu(vp2.w1),
			 be32_to_cpu(vp2.w2), be32_to_cpu(vp2.w3));
		xive_err(x, "      %08x %08x %08x %08x\n",
			 be32_to_cpu(vp2.w4), be32_to_cpu(vp2.w5),
			 be32_to_cpu(vp2.w6), be32_to_cpu(vp2.w7));
		return false;
	}
	return true;
}
#else
static inline bool xive_check_eq_update(struct xive *x __unused,
					uint32_t idx __unused,
					struct xive_eq *eq __unused)
{
	return true;
}

static inline bool xive_check_vpc_update(struct xive *x __unused,
					 uint32_t idx __unused,
					 struct xive_vp *vp __unused)
{
	return true;
}
#endif

#ifdef XIVE_EXTRA_CHECK_INIT_CACHE
static void xive_special_cache_check(struct xive *x, uint32_t blk, uint32_t idx)
{
	struct xive_vp vp = {0};
	uint32_t i;

	for (i = 0; i < 1000; i++) {
		struct xive_vp *vp_m = xive_get_vp(x, idx);

		memset(vp_m, (~i) & 0xff, sizeof(*vp_m));
		sync();
		vp.w1 = cpu_to_be32((i << 16) | i);
		xive_vpc_cache_update(x, blk, idx, &vp, true);
		if (!xive_check_vpc_update(x, idx, &vp)) {
			xive_dbg(x, "Test failed at %d iterations\n", i);
			return;
		}
	}
	xive_dbg(x, "1000 iterations test success at %d/0x%x\n", blk, idx);
}
#else
static inline void xive_special_cache_check(struct xive *x __unused,
					    uint32_t blk __unused,
					    uint32_t idx __unused)
{
}
#endif

static void xive_setup_hw_for_emu(struct xive_cpu_state *xs)
{
	struct xive_eq eq;
	struct xive_vp vp;
	struct xive *x_eq, *x_vp;

	/* Grab the XIVE where the VP resides. It could be different from
	 * the local chip XIVE if not using block group mode
	 */
	x_vp = xive_from_pc_blk(xs->vp_blk);
	assert(x_vp);

	/* Grab the XIVE where the EQ resides. It will be the same as the
	 * VP one with the current provisioning but I prefer not making
	 * this code depend on it.
	 */
	x_eq = xive_from_vc_blk(xs->eq_blk);
	assert(x_eq);

	/* Initialize the structure */
	xive_init_emu_eq(xs->vp_blk, xs->vp_idx, &eq,
			 xs->eq_page, XIVE_EMULATION_PRIO);

	/* Use the cache watch to write it out */
	lock(&x_eq->lock);
	xive_eqc_cache_update(x_eq, xs->eq_blk, xs->eq_idx + XIVE_EMULATION_PRIO, &eq, true);
	xive_check_eq_update(x_eq, xs->eq_idx + XIVE_EMULATION_PRIO, &eq);

	/* Extra testing of cache watch & scrub facilities */
	xive_special_cache_check(x_vp, xs->vp_blk, xs->vp_idx);
	unlock(&x_eq->lock);

	/* Initialize/enable the VP */
	xive_init_default_vp(&vp, xs->eq_blk, xs->eq_idx);

	/* Use the cache watch to write it out */
	lock(&x_vp->lock);
	xive_vpc_cache_update(x_vp, xs->vp_blk, xs->vp_idx, &vp, true);
	xive_check_vpc_update(x_vp, xs->vp_idx, &vp);
	unlock(&x_vp->lock);
}

static void xive_init_cpu_emulation(struct xive_cpu_state *xs,
				    struct cpu_thread *cpu)
{
	struct xive *x;

	/* Setup HW EQ and VP */
	xive_setup_hw_for_emu(xs);

	/* Setup and unmask the IPI */
	xive_ipi_init(xs->xive, cpu);

	/* Initialize remaining state */
	xs->cppr = 0;
	xs->mfrr = 0xff;
	xs->eqbuf = xive_get_eq_buf(xs->vp_blk,
				    xs->eq_idx + XIVE_EMULATION_PRIO);
	assert(xs->eqbuf);
	memset(xs->eqbuf, 0, PAGE_SIZE);

	xs->eqptr = 0;
	xs->eqmsk = (PAGE_SIZE / 4) - 1;
	xs->eqgen = 0;
	x = xive_from_vc_blk(xs->eq_blk);
	assert(x);
	xs->eqmmio = x->eq_mmio + (xs->eq_idx + XIVE_EMULATION_PRIO) * XIVE_ESB_PAGE_SIZE;
}

static void xive_init_cpu_exploitation(struct xive_cpu_state *xs)
{
	struct xive_vp vp;
	struct xive *x_vp;

	/* Grab the XIVE where the VP resides. It could be different from
	 * the local chip XIVE if not using block group mode
	 */
	x_vp = xive_from_pc_blk(xs->vp_blk);
	assert(x_vp);

	/* Initialize/enable the VP */
	xive_init_default_vp(&vp, xs->eq_blk, xs->eq_idx);

	/* Use the cache watch to write it out */
	lock(&x_vp->lock);
	xive_vpc_cache_update(x_vp, xs->vp_blk, xs->vp_idx, &vp, true);
	unlock(&x_vp->lock);

	/* Clenaup remaining state */
	xs->cppr = 0;
	xs->mfrr = 0xff;
	xs->eqbuf = NULL;
	xs->eqptr = 0;
	xs->eqmsk = 0;
	xs->eqgen = 0;
	xs->eqmmio = NULL;
}

static void xive_configure_ex_special_bar(struct xive *x, struct cpu_thread *c)
{
	uint64_t xa, val;
	int64_t rc;

	xive_cpu_vdbg(c, "Setting up special BAR\n");
	xa = XSCOM_ADDR_P9_EX(pir_to_core_id(c->pir), P9X_EX_NCU_SPEC_BAR);
	val = (uint64_t)x->tm_base | P9X_EX_NCU_SPEC_BAR_ENABLE;
	if (x->tm_shift == 16)
		val |= P9X_EX_NCU_SPEC_BAR_256K;
	xive_cpu_vdbg(c, "NCU_SPEC_BAR_XA[%08llx]=%016llx\n", xa, val);
	rc = xscom_write(c->chip_id, xa, val);
	if (rc) {
		xive_cpu_err(c, "Failed to setup NCU_SPEC_BAR\n");
		/* XXXX  what do do now ? */
	}
}

void xive_late_init(void)
{
	struct cpu_thread *c;

	prlog(PR_INFO, "SLW: Configuring self-restore for NCU_SPEC_BAR\n");
	for_each_present_cpu(c) {
		if(cpu_is_thread0(c)) {
			struct proc_chip *chip = get_chip(c->chip_id);
			struct xive *x = chip->xive;
			uint64_t xa, val, rc;
			xa = XSCOM_ADDR_P9_EX(pir_to_core_id(c->pir),
				P9X_EX_NCU_SPEC_BAR);
			val = (uint64_t)x->tm_base | P9X_EX_NCU_SPEC_BAR_ENABLE;
			/* Bail out if wakeup engine has already failed */
			if ( wakeup_engine_state != WAKEUP_ENGINE_PRESENT) {
				prlog(PR_ERR, "XIVE p9_stop_api fail detected\n");
				break;
			}
			rc = p9_stop_save_scom((void *)chip->homer_base, xa, val,
				P9_STOP_SCOM_REPLACE, P9_STOP_SECTION_EQ_SCOM);
			if (rc) {
				xive_cpu_err(c, "p9_stop_api failed for NCU_SPEC_BAR rc=%lld\n",
				rc);
				wakeup_engine_state = WAKEUP_ENGINE_FAILED;
			}
		}
	}

}
static void xive_provision_cpu(struct xive_cpu_state *xs, struct cpu_thread *c)
{
	struct xive *x;
	void *p;

	/* Physical VPs are pre-allocated */
	xs->vp_blk = PIR2VP_BLK(c->pir);
	xs->vp_idx = PIR2VP_IDX(c->pir);

	/* For now we use identical block IDs for VC and PC but that might
	 * change. We allocate the EQs on the same XIVE as the VP.
	 */
	xs->eq_blk = xs->vp_blk;

	/* Grab the XIVE where the EQ resides. It could be different from
	 * the local chip XIVE if not using block group mode
	 */
	x = xive_from_vc_blk(xs->eq_blk);
	assert(x);

	/* Allocate a set of EQs for that VP */
	xs->eq_idx = xive_alloc_eq_set(x, true);
	assert(!XIVE_ALLOC_IS_ERR(xs->eq_idx));

	/* Provision one of the queues. Allocate the memory on the
	 * chip where the CPU resides
	 */
	p = local_alloc(c->chip_id, PAGE_SIZE, PAGE_SIZE);
	if (!p) {
		xive_err(x, "Failed to allocate EQ backing store\n");
		assert(false);
	}
	xs->eq_page = p;
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

	/* Allocate an IPI */
	xs->ipi_irq = xive_alloc_ipi_irqs(c->chip_id, 1, 1);

	xive_cpu_vdbg(c, "CPU IPI is irq %08x\n", xs->ipi_irq);

	/* Provision a VP and some EQDs for a physical CPU */
	xive_provision_cpu(xs, c);

	/* Initialize the XICS emulation related fields */
	xive_init_cpu_emulation(xs, c);
}

static void xive_init_cpu_properties(struct cpu_thread *cpu)
{
	struct cpu_thread *t;
	__be32 iprop[8][2] = { };
	uint32_t i;

	assert(cpu_thread_count <= 8);

	if (!cpu->node)
		return;
	for (i = 0; i < cpu_thread_count; i++) {
		t = (i == 0) ? cpu : find_cpu_by_pir(cpu->pir + i);
		if (!t)
			continue;
		iprop[i][0] = cpu_to_be32(t->xstate->ipi_irq);
		iprop[i][1] = 0; /* Edge */
	}
	dt_add_property(cpu->node, "interrupts", iprop, cpu_thread_count * 8);
	dt_add_property_cells(cpu->node, "interrupt-parent", get_ics_phandle());
}

#ifdef XIVE_DEBUG_DUPLICATES
static uint32_t xive_count_irq_copies(struct xive_cpu_state *xs, uint32_t ref)
{
	uint32_t i, irq;
	uint32_t cnt = 0;
	uint32_t pos = xs->eqptr;
	uint32_t gen = xs->eqgen;

	for (i = 0; i < 0x3fff; i++) {
		irq = xs->eqbuf[pos];
		if ((irq >> 31) == gen)
			break;
		if (irq == ref)
			cnt++;
		pos = (pos + 1) & xs->eqmsk;
		if (!pos)
			gen ^= 1;
	}
	return cnt;
}
#else
static inline uint32_t xive_count_irq_copies(struct xive_cpu_state *xs __unused,
					     uint32_t ref __unused)
{
	return 1;
}
#endif

static uint32_t xive_read_eq(struct xive_cpu_state *xs, bool just_peek)
{
	uint32_t cur, copies;

	xive_cpu_vdbg(this_cpu(), "  EQ %s... IDX=%x MSK=%x G=%d\n",
		      just_peek ? "peek" : "read",
		      xs->eqptr, xs->eqmsk, xs->eqgen);
	cur = xs->eqbuf[xs->eqptr];
	xive_cpu_vdbg(this_cpu(), "    cur: %08x [%08x %08x %08x ...]\n", cur,
		      xs->eqbuf[(xs->eqptr + 1) & xs->eqmsk],
		      xs->eqbuf[(xs->eqptr + 2) & xs->eqmsk],
		      xs->eqbuf[(xs->eqptr + 3) & xs->eqmsk]);
	if ((cur >> 31) == xs->eqgen)
		return 0;

	/* Debug: check for duplicate interrupts in the queue */
	copies = xive_count_irq_copies(xs, cur);
	if (copies > 1) {
		struct xive_eq *eq;

		prerror("Wow ! Dups of irq %x, found %d copies !\n",
			cur & 0x7fffffff, copies);
		prerror("[%08x > %08x %08x %08x %08x ...] eqgen=%x eqptr=%x jp=%d\n",
			xs->eqbuf[(xs->eqptr - 1) & xs->eqmsk],
			xs->eqbuf[(xs->eqptr + 0) & xs->eqmsk],
			xs->eqbuf[(xs->eqptr + 1) & xs->eqmsk],
			xs->eqbuf[(xs->eqptr + 2) & xs->eqmsk],
			xs->eqbuf[(xs->eqptr + 3) & xs->eqmsk],
			xs->eqgen, xs->eqptr, just_peek);
		lock(&xs->xive->lock);
		__xive_cache_scrub(xs->xive, xive_cache_eqc, xs->eq_blk,
				   xs->eq_idx + XIVE_EMULATION_PRIO,
				   false, false);
		unlock(&xs->xive->lock);
		eq = xive_get_eq(xs->xive, xs->eq_idx + XIVE_EMULATION_PRIO);
		prerror("EQ @%p W0=%08x W1=%08x qbuf @%p\n",
			eq, be32_to_cpu(eq->w0), be32_to_cpu(eq->w1), xs->eqbuf);
	}
	log_add(xs, LOG_TYPE_POPQ, 7, cur,
		xs->eqbuf[(xs->eqptr + 1) & xs->eqmsk],
		xs->eqbuf[(xs->eqptr + 2) & xs->eqmsk],
		copies,
		xs->eqptr, xs->eqgen, just_peek);
	if (!just_peek) {
		xs->eqptr = (xs->eqptr + 1) & xs->eqmsk;
		if (xs->eqptr == 0)
			xs->eqgen ^= 1;
		xs->total_irqs++;
	}
	return cur & 0x00ffffff;
}

static uint8_t xive_sanitize_cppr(uint8_t cppr)
{
	if (cppr == 0xff || cppr == 0)
		return cppr;
	else
		return XIVE_EMULATION_PRIO;
}

static inline uint8_t opal_xive_check_pending(struct xive_cpu_state *xs,
					      uint8_t cppr)
{
	uint8_t mask = (cppr > 7) ? 0xff : ~((0x100 >> cppr) - 1);

	return xs->pending & mask;
}

static void opal_xive_update_cppr(struct xive_cpu_state *xs, u8 cppr)
{
	/* Peform the update */
	xs->cppr = cppr;
	out_8(xs->tm_ring1 + TM_QW3_HV_PHYS + TM_CPPR, cppr);

	/* Trigger the IPI if it's still more favored than the CPPR
	 *
	 * This can lead to a bunch of spurrious retriggers if the
	 * IPI is queued up behind other interrupts but that's not
	 * a big deal and keeps the code simpler
	 */
	if (xs->mfrr < cppr)
		xive_ipi_trigger(xs->xive, GIRQ_TO_IDX(xs->ipi_irq));
}

static int64_t opal_xive_eoi(uint32_t xirr)
{
	struct cpu_thread *c = this_cpu();
	struct xive_cpu_state *xs = c->xstate;
	uint32_t isn = xirr & 0x00ffffff;
	struct xive *src_x;
	bool special_ipi = false;
	uint8_t cppr;

	/*
	 * In exploitation mode, this is supported as a way to perform
	 * an EOI via a FW calls. This can be needed to workaround HW
	 * implementation bugs for example. In this case interrupts will
	 * have the OPAL_XIVE_IRQ_EOI_VIA_FW flag set.
	 *
	 * In that mode the entire "xirr" argument is interpreterd as
	 * a global IRQ number (including the escalation bit), ther is
	 * no split between the top 8 bits for CPPR and bottom 24 for
	 * the interrupt number.
	 */
	if (xive_mode != XIVE_MODE_EMU)
		return irq_source_eoi(xirr) ? OPAL_SUCCESS : OPAL_PARAMETER;

	if (!xs)
		return OPAL_INTERNAL_ERROR;

	xive_cpu_vdbg(c, "EOI xirr=%08x cur_cppr=%d\n", xirr, xs->cppr);

	/* Limit supported CPPR values from OS */
	cppr = xive_sanitize_cppr(xirr >> 24);

	lock(&xs->lock);

	log_add(xs, LOG_TYPE_EOI, 3, isn, xs->eqptr, xs->eqgen);

	/* If this was our magic IPI, convert to IRQ number */
	if (isn == 2) {
		isn = xs->ipi_irq;
		special_ipi = true;
		xive_cpu_vdbg(c, "User EOI for IPI !\n");
	}

	/* First check if we have stuff in that queue. If we do, don't bother with
	 * doing an EOI on the EQ. Just mark that priority pending, we'll come
	 * back later.
	 *
	 * If/when supporting multiple queues we would have to check them all
	 * in ascending prio order up to the passed-in CPPR value (exclusive).
	 */
	if (xive_read_eq(xs, true)) {
		xive_cpu_vdbg(c, "  isn %08x, skip, queue non empty\n", xirr);
		xs->pending |= 1 << XIVE_EMULATION_PRIO;
	}
#ifndef EQ_ALWAYS_NOTIFY
	else {
		uint8_t eoi_val;

		/* Perform EQ level EOI. Only one EQ for now ...
		 *
		 * Note: We aren't doing an actual EOI. Instead we are clearing
		 * both P and Q and will re-check the queue if Q was set.
		 */
		eoi_val = in_8(xs->eqmmio + XIVE_ESB_SET_PQ_00);
		xive_cpu_vdbg(c, "  isn %08x, eoi_val=%02x\n", xirr, eoi_val);

		/* Q was set ? Check EQ again after doing a sync to ensure
		 * ordering.
		 */
		if (eoi_val & 1) {
			sync();
			if (xive_read_eq(xs, true))
				xs->pending |= 1 << XIVE_EMULATION_PRIO;
		}
	}
#endif

	/* Perform source level EOI if it's not our emulated MFRR IPI
	 * otherwise EOI ourselves
	 */
	src_x = xive_from_isn(isn);
	if (src_x) {
		uint32_t idx = GIRQ_TO_IDX(isn);

		/* Is it an IPI ? */
		if (special_ipi) {
			xive_ipi_eoi(src_x, idx);
		} else {
			/* Otherwise go through the source mechanism */
			xive_vdbg(src_x, "EOI of IDX %x in EXT range\n", idx);
			irq_source_eoi(isn);
		}
	} else {
		xive_cpu_err(c, "  EOI unknown ISN %08x\n", isn);
	}

	/* Finally restore CPPR */
	opal_xive_update_cppr(xs, cppr);

	xive_cpu_vdbg(c, "  pending=0x%x cppr=%d\n", xs->pending, cppr);

	unlock(&xs->lock);

	/* Return whether something is pending that is suitable for
	 * delivery considering the new CPPR value. This can be done
	 * without lock as these fields are per-cpu.
	 */
	return opal_xive_check_pending(xs, cppr) ? 1 : 0;
}

#ifdef XIVE_CHECK_MISROUTED_IPI
static void xive_dump_eq(uint32_t eq_blk, uint32_t eq_idx)
{
	struct cpu_thread *me = this_cpu();
	struct xive *x;
	struct xive_eq *eq;

	x = xive_from_vc_blk(eq_blk);
	if (!x)
		return;
	eq = xive_get_eq(x, eq_idx);
	if (!eq)
		return;
	xive_cpu_err(me, "EQ: %08x %08x %08x %08x (@%p)\n",
		     eq->w0, eq->w1, eq->w2, eq->w3, eq);
	xive_cpu_err(me, "    %08x %08x %08x %08x\n",
		     eq->w4, eq->w5, eq->w6, eq->w7);
}
static int64_t __opal_xive_dump_emu(struct xive_cpu_state *xs, uint32_t pir);

static bool check_misrouted_ipi(struct cpu_thread *me, uint32_t irq)
{
	struct cpu_thread *c;

	for_each_present_cpu(c) {
		struct xive_cpu_state *xs = c->xstate;
		struct xive_ive *ive;
		uint32_t ipi_target, i, eq_blk, eq_idx;
		struct proc_chip *chip;
		struct xive *x;

		if (!xs)
			continue;
		if (irq == xs->ipi_irq) {
			xive_cpu_err(me, "misrouted IPI 0x%x, should"
				     " be aimed at CPU 0x%x\n",
				     irq, c->pir);
			xive_cpu_err(me, " my eq_page=%p eqbuff=%p eq=0x%x/%x\n",
				     me->xstate->eq_page, me->xstate->eqbuf,
				     me->xstate->eq_blk, me->xstate->eq_idx + XIVE_EMULATION_PRIO);
			xive_cpu_err(me, "tgt eq_page=%p eqbuff=%p eq=0x%x/%x\n",
				     c->xstate->eq_page, c->xstate->eqbuf,
				     c->xstate->eq_blk, c->xstate->eq_idx + XIVE_EMULATION_PRIO);
			__opal_xive_dump_emu(me->xstate, me->pir);
			__opal_xive_dump_emu(c->xstate, c->pir);
			if (xive_get_irq_targetting(xs->ipi_irq, &ipi_target, NULL, NULL))
				xive_cpu_err(me, "target=%08x\n", ipi_target);
			else
				xive_cpu_err(me, "target=???\n");
				/* Find XIVE on which the IVE resides */
			x = xive_from_isn(irq);
			if (!x) {
				xive_cpu_err(me, "no xive attached\n");
				return true;
			}
			ive = xive_get_ive(x, irq);
			if (!ive) {
				xive_cpu_err(me, "no ive attached\n");
				return true;
			}
			xive_cpu_err(me, "ive=%016llx\n", be64_to_cpu(ive->w));
			for_each_chip(chip) {
				x = chip->xive;
				if (!x)
					continue;
				ive = x->ivt_base;
				for (i = 0; i < XIVE_INT_COUNT; i++) {
					if (xive_get_field64(IVE_EQ_DATA, ive[i].w) == irq) {
						eq_blk = xive_get_field64(IVE_EQ_BLOCK, ive[i].w);
						eq_idx = xive_get_field64(IVE_EQ_INDEX, ive[i].w);
						xive_cpu_err(me, "Found source: 0x%x ive=%016llx\n"
							     " eq 0x%x/%x",
							     BLKIDX_TO_GIRQ(x->block_id, i),
							     be64_to_cpu(ive[i].w), eq_blk, eq_idx);
						xive_dump_eq(eq_blk, eq_idx);
					}
				}
			}
			return true;
		}
	}
	return false;
}
#else
static inline bool check_misrouted_ipi(struct cpu_thread  *c __unused,
				       uint32_t irq __unused)
{
	return false;
}
#endif

static int64_t opal_xive_get_xirr(__be32 *out_xirr, bool just_poll)
{
	struct cpu_thread *c = this_cpu();
	struct xive_cpu_state *xs = c->xstate;
	uint16_t ack;
	uint8_t active, old_cppr;

	if (xive_mode != XIVE_MODE_EMU)
		return OPAL_WRONG_STATE;
	if (!xs)
		return OPAL_INTERNAL_ERROR;
	if (!out_xirr)
		return OPAL_PARAMETER;

	*out_xirr = 0;

	lock(&xs->lock);

	/*
	 * Due to the need to fetch multiple interrupts from the EQ, we
	 * need to play some tricks.
	 *
	 * The "pending" byte in "xs" keeps track of the priorities that
	 * are known to have stuff to read (currently we only use one).
	 *
	 * It is set in EOI and cleared when consumed here. We don't bother
	 * looking ahead here, EOI will do it.
	 *
	 * We do need to still do an ACK every time in case a higher prio
	 * exception occurred (though we don't do prio yet... right ? still
	 * let's get the basic design right !).
	 *
	 * Note that if we haven't found anything via ack, but did find
	 * something in the queue, we must also raise CPPR back.
	 */

	xive_cpu_vdbg(c, "get_xirr W01=%016llx W2=%08x\n",
		      __in_be64(xs->tm_ring1 + TM_QW3_HV_PHYS),
		      __in_be32(xs->tm_ring1 + TM_QW3_HV_PHYS + 8));

	/* Perform the HV Ack cycle */
	if (just_poll)
		ack = __in_be64(xs->tm_ring1 + TM_QW3_HV_PHYS) >> 48;
	else
		ack = __in_be16(xs->tm_ring1 + TM_SPC_ACK_HV_REG);
	sync();
	xive_cpu_vdbg(c, "get_xirr,%s=%04x\n", just_poll ? "POLL" : "ACK", ack);

	/* Capture the old CPPR which we will return with the interrupt */
	old_cppr = xs->cppr;

	switch(GETFIELD(TM_QW3_NSR_HE, (ack >> 8))) {
	case TM_QW3_NSR_HE_NONE:
		break;
	case TM_QW3_NSR_HE_POOL:
		break;
	case TM_QW3_NSR_HE_PHYS:
		/* Mark pending and keep track of the CPPR update */
		if (!just_poll && (ack & 0xff) != 0xff) {
			xs->cppr = ack & 0xff;
			xs->pending |= 1 << xs->cppr;
		}
		break;
	case TM_QW3_NSR_HE_LSI:
		break;
	}

	/* Calculate "active" lines as being the pending interrupts
	 * masked by the "old" CPPR
	 */
	active = opal_xive_check_pending(xs, old_cppr);

	log_add(xs, LOG_TYPE_XIRR, 6, old_cppr, xs->cppr, xs->pending, active,
		xs->eqptr, xs->eqgen);

#ifdef XIVE_PERCPU_LOG
	{
		struct xive_eq *eq;
		lock(&xs->xive->lock);
		__xive_cache_scrub(xs->xive, xive_cache_eqc, xs->eq_blk,
				   xs->eq_idx + XIVE_EMULATION_PRIO,
				   false, false);
		unlock(&xs->xive->lock);
		eq = xive_get_eq(xs->xive, xs->eq_idx + XIVE_EMULATION_PRIO);
		log_add(xs, LOG_TYPE_EQD, 2, be32_to_cpu(eq->w0), be32_to_cpu(eq->w1));
	}
#endif /* XIVE_PERCPU_LOG */

	xive_cpu_vdbg(c, "  cppr=%d->%d pending=0x%x active=%x\n",
		      old_cppr, xs->cppr, xs->pending, active);
	if (active) {
		/* Find highest pending */
		uint8_t prio = ffs(active) - 1;
		uint32_t val;

		/* XXX Use "p" to select queue */
		val = xive_read_eq(xs, just_poll);

		if (val && val < XIVE_INT_FIRST)
			xive_cpu_err(c, "Bogus interrupt 0x%x received !\n", val);

		/* Convert to magic IPI if needed */
		if (val == xs->ipi_irq)
			val = 2;
		if (check_misrouted_ipi(c, val))
			val = 2;

		*out_xirr = cpu_to_be32((old_cppr << 24) | val);

		/* If we are polling, that's it */
		if (just_poll)
			goto skip;

		/* Clear the pending bit. EOI will set it again if needed. We
		 * could check the queue but that's not really critical here.
		 */
		xs->pending &= ~(1 << prio);

		/* Spurrious IPB bit, nothing to fetch, bring CPPR back */
		if (!val)
			prio = old_cppr;

		/* We could have fetched a pending interrupt left over
		 * by a previous EOI, so the CPPR might need adjusting
		 * Also if we had a spurrious one as well.
		 */
		if (xs->cppr != prio) {
			xs->cppr = prio;
			out_8(xs->tm_ring1 + TM_QW3_HV_PHYS + TM_CPPR, prio);
			xive_cpu_vdbg(c, "  adjusted CPPR to %d\n", prio);
		}

		if (val)
			xive_cpu_vdbg(c, "  found irq, prio=%d\n", prio);

	} else {
		/* Nothing was active, this is a fluke, restore CPPR */
		opal_xive_update_cppr(xs, old_cppr);
		xive_cpu_vdbg(c, "  nothing active, restored CPPR to %d\n",
			      old_cppr);
	}
 skip:

	log_add(xs, LOG_TYPE_XIRR2, 5, xs->cppr, xs->pending,
		be32_to_cpu(*out_xirr), xs->eqptr, xs->eqgen);
	xive_cpu_vdbg(c, "  returning XIRR=%08x, pending=0x%x\n",
		      be32_to_cpu(*out_xirr), xs->pending);

	unlock(&xs->lock);

	return OPAL_SUCCESS;
}

static int64_t opal_xive_set_cppr(uint8_t cppr)
{
	struct cpu_thread *c = this_cpu();
	struct xive_cpu_state *xs = c->xstate;

	if (xive_mode != XIVE_MODE_EMU)
		return OPAL_WRONG_STATE;

	/* Limit supported CPPR values */
	cppr = xive_sanitize_cppr(cppr);

	if (!xs)
		return OPAL_INTERNAL_ERROR;
	xive_cpu_vdbg(c, "CPPR setting to %d\n", cppr);

	lock(&xs->lock);
	opal_xive_update_cppr(xs, cppr);
	unlock(&xs->lock);

	return OPAL_SUCCESS;
}

static int64_t opal_xive_set_mfrr(uint32_t cpu, uint8_t mfrr)
{
	struct cpu_thread *c = find_cpu_by_server(cpu);
	struct xive_cpu_state *xs;
	uint8_t old_mfrr;

	if (xive_mode != XIVE_MODE_EMU)
		return OPAL_WRONG_STATE;
	if (!c)
		return OPAL_PARAMETER;
	xs = c->xstate;
	if (!xs)
		return OPAL_INTERNAL_ERROR;

	lock(&xs->lock);
	old_mfrr = xs->mfrr;
	xive_cpu_vdbg(c, "  Setting MFRR to %x, old is %x\n", mfrr, old_mfrr);
	xs->mfrr = mfrr;
	if (old_mfrr > mfrr && mfrr < xs->cppr)
		xive_ipi_trigger(xs->xive, GIRQ_TO_IDX(xs->ipi_irq));
	unlock(&xs->lock);

	return OPAL_SUCCESS;
}

static uint64_t xive_convert_irq_flags(uint64_t iflags)
{
	uint64_t oflags = 0;

	if (iflags & XIVE_SRC_STORE_EOI)
		oflags |= OPAL_XIVE_IRQ_STORE_EOI;

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
				      __be64 *out_flags,
				      __be64 *out_eoi_page,
				      __be64 *out_trig_page,
				      __be32 *out_esb_shift,
				      __be32 *out_src_chip)
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
					__be64 *out_vp,
					uint8_t *out_prio,
					__be32 *out_lirq)
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
	 * a prio of FF, the IVT/EAS will be mased. In that case the
	 * races have to be handled by the OS.
	 *
	 * The exception to this rule is interrupts for which masking
	 * and unmasking is handled by firmware. In that case the ESB
	 * state isn't under OS control and will be dealt here. This
	 * is currently only the case of LSIs and on P9 DD1.0 only so
	 * isn't an issue.
	 */

	if (xive_mode != XIVE_MODE_EXPL)
		return OPAL_WRONG_STATE;

	return xive_set_irq_config(girq, vp, prio, lirq, false);
}

static int64_t opal_xive_get_queue_info(uint64_t vp, uint32_t prio,
					__be64 *out_qpage,
					__be64 *out_qsize,
					__be64 *out_qeoi_page,
					__be32 *out_escalate_irq,
					__be64 *out_qflags)
{
	uint32_t blk, idx;
	struct xive *x;
	struct xive_eq *eq;

	if (xive_mode != XIVE_MODE_EXPL)
		return OPAL_WRONG_STATE;

	if (!xive_eq_for_target(vp, prio, &blk, &idx))
		return OPAL_PARAMETER;

	x = xive_from_vc_blk(blk);
	if (!x)
		return OPAL_PARAMETER;

	eq = xive_get_eq(x, idx);
	if (!eq)
		return OPAL_PARAMETER;

	if (out_escalate_irq) {
		uint32_t esc_idx = idx;

		/* If escalations are routed to a single queue, fix up
		 * the escalation interrupt number here.
		 */
		if (xive_get_field32(EQ_W0_UNCOND_ESCALATE, eq->w0))
			esc_idx |= XIVE_ESCALATION_PRIO;

		*out_escalate_irq =
			cpu_to_be32(MAKE_ESCALATION_GIRQ(blk, esc_idx));
	}

	/* If this is a single-escalation gather queue, that's all
	 * there is to return
	 */
	if (xive_get_field32(EQ_W0_SILENT_ESCALATE, eq->w0)) {
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
		if (xive_get_field32(EQ_W0_ENQUEUE, eq->w0))
			*out_qpage = cpu_to_be64(((uint64_t)xive_get_field32(EQ_W2_OP_DESC_HI, eq->w2) << 32) | be32_to_cpu(eq->w3));
		else
			*out_qpage = 0;
	}
	if (out_qsize) {
		if (xive_get_field32(EQ_W0_ENQUEUE, eq->w0))
			*out_qsize = cpu_to_be64(xive_get_field32(EQ_W0_QSIZE, eq->w0) + 12);
		else
			*out_qsize = 0;
	}
	if (out_qeoi_page) {
		*out_qeoi_page =
			cpu_to_be64((uint64_t)x->eq_mmio + idx * XIVE_ESB_PAGE_SIZE);
	}
	if (out_qflags) {
		*out_qflags = 0;
		if (xive_get_field32(EQ_W0_VALID, eq->w0))
			*out_qflags |= cpu_to_be64(OPAL_XIVE_EQ_ENABLED);
		if (xive_get_field32(EQ_W0_UCOND_NOTIFY, eq->w0))
			*out_qflags |= cpu_to_be64(OPAL_XIVE_EQ_ALWAYS_NOTIFY);
		if (xive_get_field32(EQ_W0_ESCALATE_CTL, eq->w0))
			*out_qflags |= cpu_to_be64(OPAL_XIVE_EQ_ESCALATE);
	}

	return OPAL_SUCCESS;
}

static void xive_cleanup_eq(struct xive_eq *eq)
{
	eq->w0 = xive_set_field32(EQ_W0_FIRMWARE, 0, xive_get_field32(EQ_W0_FIRMWARE, eq->w0));
	eq->w1 = cpu_to_be32(EQ_W1_ESe_Q | EQ_W1_ESn_Q);
	eq->w2 = eq->w3 = eq->w4 = eq->w5 = eq->w6 = eq->w7 = 0;
}

static int64_t opal_xive_set_queue_info(uint64_t vp, uint32_t prio,
					uint64_t qpage,
					uint64_t qsize,
					uint64_t qflags)
{
	uint32_t blk, idx;
	struct xive *x;
	struct xive_eq *old_eq;
	struct xive_eq eq;
	uint32_t vp_blk, vp_idx;
	bool group;
	int64_t rc;

	if (xive_mode != XIVE_MODE_EXPL)
		return OPAL_WRONG_STATE;
	if (!xive_eq_for_target(vp, prio, &blk, &idx))
		return OPAL_PARAMETER;

	x = xive_from_vc_blk(blk);
	if (!x)
		return OPAL_PARAMETER;

	old_eq = xive_get_eq(x, idx);
	if (!old_eq)
		return OPAL_PARAMETER;

	/* If this is a silent escalation queue, it cannot be
	 * configured directly
	 */
	if (xive_get_field32(EQ_W0_SILENT_ESCALATE, old_eq->w0))
		return OPAL_PARAMETER;

	/* This shouldn't fail or xive_eq_for_target would have
	 * failed already
	 */
	if (!xive_decode_vp(vp, &vp_blk, &vp_idx, NULL, &group))
		return OPAL_PARAMETER;

	/*
	 * Make a local copy which we will later try to commit using
	 * the cache watch facility
	 */
	eq = *old_eq;

	if (qflags & OPAL_XIVE_EQ_ENABLED) {
		switch(qsize) {
			/* Supported sizes */
		case 12:
		case 16:
		case 21:
		case 24:
			eq.w3 = cpu_to_be32(((uint64_t)qpage) & EQ_W3_OP_DESC_LO);
			eq.w2 = cpu_to_be32((((uint64_t)qpage) >> 32) & EQ_W2_OP_DESC_HI);
			eq.w0 = xive_set_field32(EQ_W0_ENQUEUE, eq.w0, 1);
			eq.w0 = xive_set_field32(EQ_W0_QSIZE, eq.w0, qsize - 12);
			break;
		case 0:
			eq.w2 = eq.w3 = 0;
			eq.w0 = xive_set_field32(EQ_W0_ENQUEUE, eq.w0, 0);
			break;
		default:
			return OPAL_PARAMETER;
		}

		/* Ensure the priority and target are correctly set (they will
		 * not be right after allocation
		 */
		eq.w6 = xive_set_field32(EQ_W6_NVT_BLOCK, 0, vp_blk) |
			xive_set_field32(EQ_W6_NVT_INDEX, 0, vp_idx);
		eq.w7 = xive_set_field32(EQ_W7_F0_PRIORITY, 0, prio);
		/* XXX Handle group i bit when needed */

		/* Always notify flag */
		if (qflags & OPAL_XIVE_EQ_ALWAYS_NOTIFY)
			eq.w0 = xive_set_field32(EQ_W0_UCOND_NOTIFY, eq.w0, 1);
		else
			eq.w0 = xive_set_field32(EQ_W0_UCOND_NOTIFY, eq.w0, 0);

		/* Escalation flag */
		if (qflags & OPAL_XIVE_EQ_ESCALATE)
			eq.w0 = xive_set_field32(EQ_W0_ESCALATE_CTL, eq.w0, 1);
		else
			eq.w0 = xive_set_field32(EQ_W0_ESCALATE_CTL, eq.w0, 0);

		/* Unconditionally clear the current queue pointer, set
		 * generation to 1 and disable escalation interrupts.
		 */
		eq.w1 = xive_set_field32(EQ_W1_GENERATION, 0, 1) |
			xive_set_field32(EQ_W1_ES, 0, xive_get_field32(EQ_W1_ES, old_eq->w1));

		/* Enable. We always enable backlog for an enabled queue
		 * otherwise escalations won't work.
		 */
		eq.w0 = xive_set_field32(EQ_W0_VALID, eq.w0, 1);
		eq.w0 = xive_set_field32(EQ_W0_BACKLOG, eq.w0, 1);
	} else
		xive_cleanup_eq(&eq);

	/* Update EQ, non-synchronous */
	lock(&x->lock);
	rc = xive_eqc_cache_update(x, blk, idx, &eq, false);
	unlock(&x->lock);

	return rc;
}

static int64_t opal_xive_get_queue_state(uint64_t vp, uint32_t prio,
					 __be32 *out_qtoggle,
					 __be32 *out_qindex)
{
	uint32_t blk, idx;
	struct xive *x;
	struct xive_eq *eq;
	int64_t rc;

	if (xive_mode != XIVE_MODE_EXPL)
		return OPAL_WRONG_STATE;

	if (!out_qtoggle || !out_qindex ||
	    !xive_eq_for_target(vp, prio, &blk, &idx))
		return OPAL_PARAMETER;

	x = xive_from_vc_blk(blk);
	if (!x)
		return OPAL_PARAMETER;

	eq = xive_get_eq(x, idx);
	if (!eq)
		return OPAL_PARAMETER;

	/* Scrub the queue */
	lock(&x->lock);
	rc = xive_eqc_scrub(x, blk, idx);
	unlock(&x->lock);
	if (rc)
		return rc;

	/* We don't do disable queues */
	if (!xive_get_field32(EQ_W0_VALID, eq->w0))
		return OPAL_WRONG_STATE;

	*out_qtoggle = cpu_to_be32(xive_get_field32(EQ_W1_GENERATION, eq->w1));
	*out_qindex  = cpu_to_be32(xive_get_field32(EQ_W1_PAGE_OFF, eq->w1));

	return OPAL_SUCCESS;
}

static int64_t opal_xive_set_queue_state(uint64_t vp, uint32_t prio,
					 uint32_t qtoggle, uint32_t qindex)
{
	uint32_t blk, idx;
	struct xive *x;
	struct xive_eq *eq, new_eq;
	int64_t rc;

	if (xive_mode != XIVE_MODE_EXPL)
		return OPAL_WRONG_STATE;

	if (!xive_eq_for_target(vp, prio, &blk, &idx))
		return OPAL_PARAMETER;

	x = xive_from_vc_blk(blk);
	if (!x)
		return OPAL_PARAMETER;

	eq = xive_get_eq(x, idx);
	if (!eq)
		return OPAL_PARAMETER;

	/* We don't do disable queues */
	if (!xive_get_field32(EQ_W0_VALID, eq->w0))
		return OPAL_WRONG_STATE;

	new_eq = *eq;

	new_eq.w1 = xive_set_field32(EQ_W1_GENERATION, new_eq.w1, qtoggle);
	new_eq.w1 = xive_set_field32(EQ_W1_PAGE_OFF, new_eq.w1, qindex);

	lock(&x->lock);
	rc = xive_eqc_cache_update(x, blk, idx, &new_eq, false);
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
				     __be64 *out_flags,
				     __be64 *out_cam_value,
				     __be64 *out_report_cl_pair,
				     __be32 *out_chip_id)
{
	struct xive *x;
	struct xive_vp *vp;
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
		uint32_t eq_blk, eq_idx;
		struct xive_eq *eq;
		struct xive *eq_x;
		*out_flags = 0;

		/* We would like to a way to stash a SW bit in the VP to
		 * know whether silent escalation is enabled or not, but
		 * unlike what happens with EQs, the PC cache watch doesn't
		 * implement the reserved bit in the VPs... so we have to go
		 * look at EQ 7 instead.
		 */
		/* Grab EQ for prio 7 to check for silent escalation */
		if (!xive_eq_for_target(vp_id, XIVE_ESCALATION_PRIO,
					&eq_blk, &eq_idx))
			return OPAL_PARAMETER;

		eq_x = xive_from_vc_blk(eq_blk);
		if (!eq_x)
			return OPAL_PARAMETER;

		eq = xive_get_eq(x, eq_idx);
		if (!eq)
			return OPAL_PARAMETER;
		if (xive_get_field32(VP_W0_VALID, vp->w0))
			*out_flags |= cpu_to_be64(OPAL_XIVE_VP_ENABLED);
		if (xive_get_field32(EQ_W0_SILENT_ESCALATE, eq->w0))
			*out_flags |= cpu_to_be64(OPAL_XIVE_VP_SINGLE_ESCALATION);
	}

	if (out_cam_value)
		*out_cam_value = cpu_to_be64((blk << NVT_SHIFT) | idx);

	if (out_report_cl_pair) {
		*out_report_cl_pair = cpu_to_be64(((uint64_t)(be32_to_cpu(vp->w6) & 0x0fffffff)) << 32);
		*out_report_cl_pair |= cpu_to_be64(be32_to_cpu(vp->w7) & 0xffffff00);
	}

	if (out_chip_id)
		*out_chip_id = cpu_to_be32(xive_block_to_chip[blk]);

	return OPAL_SUCCESS;
}

static int64_t xive_setup_silent_gather(uint64_t vp_id, bool enable)
{
	uint32_t blk, idx, i;
	struct xive_eq *eq_orig;
	struct xive_eq eq;
	struct xive *x;
	int64_t rc;

	/* Get base EQ block */
	if (!xive_eq_for_target(vp_id, 0, &blk, &idx))
		return OPAL_PARAMETER;
	x = xive_from_vc_blk(blk);
	if (!x)
		return OPAL_PARAMETER;

	/* Grab prio 7 */
	eq_orig = xive_get_eq(x, idx + XIVE_ESCALATION_PRIO);
	if (!eq_orig)
		return OPAL_PARAMETER;

	/* If trying to enable silent gather, make sure prio 7 is not
	 * already enabled as a normal queue
	 */
	if (enable && xive_get_field32(EQ_W0_VALID, eq_orig->w0) &&
	    !xive_get_field32(EQ_W0_SILENT_ESCALATE, eq_orig->w0)) {
		xive_dbg(x, "Attempt at enabling silent gather but"
			 " prio 7 queue already in use\n");
		return OPAL_PARAMETER;
	}

	eq = *eq_orig;

	if (enable) {
		/* W0: Enabled and "s" set, no other bit */
		eq.w0 = xive_set_field32(EQ_W0_FIRMWARE, 0, xive_get_field32(EQ_W0_FIRMWARE, eq.w0)) |
			xive_set_field32(EQ_W0_VALID, 0, 1) |
			xive_set_field32(EQ_W0_SILENT_ESCALATE, 0, 1) |
			xive_set_field32(EQ_W0_ESCALATE_CTL, 0, 1) |
			xive_set_field32(EQ_W0_BACKLOG, 0, 1);

		/* W1: Mark ESn as 01, ESe as 00 */
		eq.w1 = xive_set_field32(EQ_W1_ESn_P, eq.w1, 0);
		eq.w1 = xive_set_field32(EQ_W1_ESn_Q, eq.w1, 1);
		eq.w1 = xive_set_field32(EQ_W1_ESe, eq.w1, 0);
	} else if (xive_get_field32(EQ_W0_SILENT_ESCALATE, eq.w0))
		xive_cleanup_eq(&eq);

	if (!memcmp(eq_orig, &eq, sizeof(eq)))
		rc = 0;
	else
		rc = xive_eqc_cache_update(x, blk, idx + XIVE_ESCALATION_PRIO,
					   &eq, false);
	if (rc)
		return rc;

	/* Mark/unmark all other prios with the new "u" bit and update
	 * escalation
	 */
	for (i = 0; i < NUM_INT_PRIORITIES; i++) {
		if (i == XIVE_ESCALATION_PRIO)
			continue;
		eq_orig = xive_get_eq(x, idx + i);
		if (!eq_orig)
			continue;
		eq = *eq_orig;
		if (enable) {
			/* Set new "u" bit */
			eq.w0 = xive_set_field32(EQ_W0_UNCOND_ESCALATE, eq.w0, 1);

			/* Re-route escalation interrupt (previous
			 * route is lost !) to the gather queue
			 */
			eq.w4 = xive_set_field32(EQ_W4_ESC_EQ_BLOCK, eq.w4, blk);
			eq.w4 = xive_set_field32(EQ_W4_ESC_EQ_INDEX, eq.w4, idx + XIVE_ESCALATION_PRIO);
		} else if (xive_get_field32(EQ_W0_UNCOND_ESCALATE, eq.w0)) {
			/* Clear the "u" bit, disable escalations if it was set */
			eq.w0 = xive_set_field32(EQ_W0_UNCOND_ESCALATE, eq.w0, 0);
			eq.w0 = xive_set_field32(EQ_W0_ESCALATE_CTL, eq.w0, 0);
		}
		if (!memcmp(eq_orig, &eq, sizeof(eq)))
			continue;
		rc = xive_eqc_cache_update(x, blk, idx + i, &eq, false);
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
	struct xive_vp *vp, vp_new;
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

	lock(&x->lock);

	vp_new = *vp;
	if (flags & OPAL_XIVE_VP_ENABLED) {
		vp_new.w0 = xive_set_field32(VP_W0_VALID, vp_new.w0, 1);
		vp_new.w6 = cpu_to_be32(report_cl_pair >> 32);
		vp_new.w7 = cpu_to_be32(report_cl_pair & 0xffffffff);

		if (flags & OPAL_XIVE_VP_SINGLE_ESCALATION)
			rc = xive_setup_silent_gather(vp_id, true);
		else
			rc = xive_setup_silent_gather(vp_id, false);
	} else {
		vp_new.w0 = vp_new.w6 = vp_new.w7 = 0;
		rc = xive_setup_silent_gather(vp_id, false);
	}

	if (rc) {
		if (rc != OPAL_BUSY)
			xive_dbg(x, "Silent gather setup failed with err %lld\n", rc);
		goto bail;
	}

	rc = xive_vpc_cache_update(x, blk, idx, &vp_new, false);
	if (rc)
		goto bail;

	/* When disabling, we scrub clean (invalidate the entry) so
	 * we can avoid cache ops in alloc/free
	 */
	if (!(flags & OPAL_XIVE_VP_ENABLED))
		xive_vpc_scrub_clean(x, blk, idx);

bail:
	unlock(&x->lock);
	return rc;
}

static int64_t opal_xive_get_vp_state(uint64_t vp_id, __be64 *out_state)
{
	struct xive *x;
	struct xive_vp *vp;
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
	rc = xive_vpc_scrub(x, blk, idx);
	unlock(&x->lock);
	if (rc)
		return rc;

	if (!xive_get_field32(VP_W0_VALID, vp->w0))
		return OPAL_WRONG_STATE;

	/*
	 * Return word4 and word5 which contain the saved HW thread
	 * context. The IPB register is all we care for now on P9.
	 */
	*out_state = cpu_to_be64((((uint64_t)be32_to_cpu(vp->w4)) << 32) | be32_to_cpu(vp->w5));

	return OPAL_SUCCESS;
}

static void xive_cleanup_cpu_tima(struct cpu_thread *c)
{
	struct xive_cpu_state *xs = c->xstate;
	struct xive *x = xs->xive;
	void *ind_tm_base = x->ic_base + (4 << x->ic_shift);
	uint8_t old_w2 __unused, w2 __unused;

	/* Reset the HW context */
	xive_reset_enable_thread(c);

	/* Setup indirect access to the corresponding thread */
	xive_regw(x, PC_TCTXT_INDIR0,
		  PC_TCTXT_INDIR_VALID |
		  SETFIELD(PC_TCTXT_INDIR_THRDID, 0ull, c->pir & 0xff));

	/* Workaround for HW issue: Need to read the above register
	 * back before doing the subsequent accesses
	 */
	xive_regr(x, PC_TCTXT_INDIR0);

	/* Set VT to 1 */
	old_w2 = in_8(ind_tm_base + TM_QW3_HV_PHYS + TM_WORD2);
	out_8(ind_tm_base + TM_QW3_HV_PHYS + TM_WORD2, 0x80);
	w2 = in_8(ind_tm_base + TM_QW3_HV_PHYS + TM_WORD2);

	/* Dump HV state */
	xive_cpu_vdbg(c, "[reset] VP TIMA VP=%x/%x W01=%016llx W2=%02x->%02x\n",
		      xs->vp_blk, xs->vp_idx,
		      in_be64(ind_tm_base + TM_QW3_HV_PHYS),
		      old_w2, w2);

	/* Reset indirect access */
	xive_regw(x, PC_TCTXT_INDIR0, 0);
}

static int64_t xive_vc_ind_cache_kill(struct xive *x, uint64_t type)
{
	uint64_t val;

	/* We clear the whole thing */
	xive_regw(x, VC_AT_MACRO_KILL_MASK, 0);
	xive_regw(x, VC_AT_MACRO_KILL, VC_KILL_VALID |
		  SETFIELD(VC_KILL_TYPE, 0ull, type));

	/* XXX SIMICS problem ? */
	if (chip_quirk(QUIRK_SIMICS))
		return 0;

	/* XXX Add timeout */
	for (;;) {
		val = xive_regr(x, VC_AT_MACRO_KILL);
		if (!(val & VC_KILL_VALID))
			break;
	}
	return 0;
}

static int64_t xive_pc_ind_cache_kill(struct xive *x)
{
	uint64_t val;

	/* We clear the whole thing */
	xive_regw(x, PC_AT_KILL_MASK, 0);
	xive_regw(x, PC_AT_KILL, PC_AT_KILL_VALID);

	/* XXX SIMICS problem ? */
	if (chip_quirk(QUIRK_SIMICS))
		return 0;

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

static void xive_cleanup_eq_ind(struct xive *x)
{
	int i;

	xive_dbg(x, "Cleaning up %d EQ ind entries...\n", x->eq_ind_count);
	for (i = 0; i < x->eq_ind_count; i++) {
		if (be64_to_cpu(x->eq_ind_base[i]) & VSD_FIRMWARE) {
			xive_dbg(x, " %04x ... skip (firmware)\n", i);
			continue;
		}
		if (x->eq_ind_base[i] != 0) {
			x->eq_ind_base[i] = 0;
			xive_dbg(x, " %04x ... cleaned\n", i);
		}
	}
	xive_vc_ind_cache_kill(x, VC_KILL_EQD);
}

static void xive_reset_one(struct xive *x)
{
	struct cpu_thread *c;
	bool eq_firmware;
	int i;

	xive_dbg(x, "Resetting one xive...\n");

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

	xive_dbg(x, "Resetting EQs...\n");

	/* Reset all allocated EQs and free the user ones */
	bitmap_for_each_one(*x->eq_map, XIVE_EQ_COUNT >> 3, i) {
		struct xive_eq eq0;
		struct xive_eq *eq;
		int j;

		if (i == 0)
			continue;
		eq_firmware = false;
		for (j = 0; j < NUM_INT_PRIORITIES; j++) {
			uint32_t idx = (i << 3) | j;

			eq = xive_get_eq(x, idx);
			if (!eq)
				continue;

			/* We need to preserve the firmware bit, otherwise
			 * we will incorrectly free the EQs that are reserved
			 * for the physical CPUs
			 */
			if (xive_get_field32(EQ_W0_VALID, eq->w0)) {
				if (!xive_get_field32(EQ_W0_FIRMWARE, eq->w0))
					xive_dbg(x, "EQ 0x%x:0x%x is valid at reset: %08x %08x\n",
						 x->block_id, idx, be32_to_cpu(eq->w0), be32_to_cpu(eq->w1));
				eq0 = *eq;
				xive_cleanup_eq(&eq0);
				xive_eqc_cache_update(x, x->block_id, idx, &eq0, true);
			}
			if (xive_get_field32(EQ_W0_FIRMWARE, eq->w0))
				eq_firmware = true;
		}
		if (!eq_firmware)
			bitmap_clr_bit(*x->eq_map, i);
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
	for (i = 0; i < XIVE_VP_COUNT; i++) {
		struct xive_vp *vp;
		struct xive_vp vp0 = {0};

		/* Ignore the physical CPU VPs */
		if (i >= XIVE_HW_VP_BASE &&
		    i < (XIVE_HW_VP_BASE + XIVE_HW_VP_COUNT))
			continue;

		/* Is the VP valid ? */
		vp = xive_get_vp(x, i);
		if (!vp || !xive_get_field32(VP_W0_VALID, vp->w0))
			continue;

		/* Clear it */
		xive_dbg(x, "VP 0x%x:0x%x is valid at reset\n", x->block_id, i);
		xive_vpc_cache_update(x, x->block_id, i, &vp0, true);
	}

	/* Forget about remaining donated pages */
	list_head_init(&x->donated_pages);

	/* And cleanup donated indirect VP and EQ pages */
	xive_cleanup_vp_ind(x);
	xive_cleanup_eq_ind(x);

	/* The rest must not be called with the lock held */
	unlock(&x->lock);

	/* Re-configure VPs and emulation */
	for_each_present_cpu(c) {
		struct xive_cpu_state *xs = c->xstate;

		if (c->chip_id != x->chip_id || !xs)
			continue;

		if (xive_mode == XIVE_MODE_EMU)
			xive_init_cpu_emulation(xs, c);
		else
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

void xive_cpu_reset(void)
{
	struct cpu_thread *c = this_cpu();
	struct xive_cpu_state *xs = c->xstate;

	xs->cppr = 0;
	out_8(xs->tm_ring1 + TM_QW3_HV_PHYS + TM_CPPR, 0);

	in_be64(xs->tm_ring1 + TM_SPC_PULL_POOL_CTX);
}

static int64_t __xive_reset(uint64_t version)
{
	struct proc_chip *chip;

	xive_mode = version;

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

	/* We reserve the whole range of VPs representing HW chips.
	 *
	 * These are 0x80..0xff, so order 7 starting at 0x80. This will
	 * reserve that range on each chip.
	 */
	assert(buddy_reserve(xive_vp_buddy, XIVE_HW_VP_BASE,
			     XIVE_THREADID_SHIFT));

	return OPAL_SUCCESS;
}

/* Called by fast reboot */
int64_t xive_reset(void)
{
	if (xive_mode == XIVE_MODE_NONE)
		return OPAL_SUCCESS;
	return __xive_reset(XIVE_MODE_EMU);
}

static int64_t opal_xive_reset(uint64_t version)
{
	prlog(PR_DEBUG, "XIVE reset, version: %d...\n", (int)version);

	if (version > 1)
		return OPAL_PARAMETER;

	return __xive_reset(version);
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
		uint32_t blk, idx, eq_blk, eq_idx;
		struct xive *x;
		struct xive_vp *vp;

		if (!xive_decode_vp(vp_id, &blk, &idx, NULL, NULL)) {
			prerror("XIVE: Couldn't decode VP id %u\n", vp_id);
			return OPAL_INTERNAL_ERROR;
		}
		x = xive_from_pc_blk(blk);
		if (!x) {
			prerror("XIVE: Instance not found for deallocated VP"
				" block %d\n", blk);
			return OPAL_INTERNAL_ERROR;
		}
		vp = xive_get_vp(x, idx);
		if (!vp) {
			prerror("XIVE: VP not found for deallocation !");
			return OPAL_INTERNAL_ERROR;
		}

		/* VP must be disabled */
		if (xive_get_field32(VP_W0_VALID, vp->w0)) {
			prlog(PR_ERR, "XIVE: freeing active VP %d\n", vp_id);
			return OPAL_XIVE_FREE_ACTIVE;
		}

		/* Not populated */
		if (vp->w1 == 0)
			continue;
		eq_blk = be32_to_cpu(vp->w1) >> 28;
		eq_idx = be32_to_cpu(vp->w1) & 0x0fffffff;

		lock(&x->lock);

		/* Ensure EQs are disabled and cleaned up. Ideally the caller
		 * should have done it but we double check it here
		 */
		for (j = 0; j < NUM_INT_PRIORITIES; j++) {
			struct xive *eq_x = xive_from_vc_blk(eq_blk);
			struct xive_eq eq, *orig_eq = xive_get_eq(eq_x, eq_idx + j);

			if (!xive_get_field32(EQ_W0_VALID, orig_eq->w0))
				continue;

			prlog(PR_WARNING, "XIVE: freeing VP %d with queue %d active\n",
			      vp_id, j);
			eq = *orig_eq;
			xive_cleanup_eq(&eq);
			xive_eqc_cache_update(x, eq_blk, eq_idx + j, &eq, true);
		}

		/* Mark it not populated so we don't try to free it again */
		vp->w1 = 0;

		if (eq_blk != blk) {
			prerror("XIVE: Block mismatch trying to free EQs\n");
			unlock(&x->lock);
			return OPAL_INTERNAL_ERROR;
		}

		xive_free_eq_set(x, eq_idx);
		unlock(&x->lock);
	}

	xive_free_vps(vp_base);

	return OPAL_SUCCESS;
}

static int64_t opal_xive_alloc_vp_block(uint32_t alloc_order)
{
	uint32_t vp_base, eqs, count, i;
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

	/* Allocate EQs and initialize VPs */
	count = 1 << alloc_order;
	for (i = 0; i < count; i++) {
		uint32_t vp_id = vp_base + i;
		uint32_t blk, idx;
		struct xive *x;
		struct xive_vp *vp;

		if (!xive_decode_vp(vp_id, &blk, &idx, NULL, NULL)) {
			prerror("XIVE: Couldn't decode VP id %u\n", vp_id);
			return OPAL_INTERNAL_ERROR;
		}
		x = xive_from_pc_blk(blk);
		if (!x) {
			prerror("XIVE: Instance not found for allocated VP"
				" block %d\n", blk);
			rc = OPAL_INTERNAL_ERROR;
			goto fail;
		}
		vp = xive_get_vp(x, idx);
		if (!vp) {
			prerror("XIVE: VP not found after allocation !");
			rc = OPAL_INTERNAL_ERROR;
			goto fail;
		}

		/* Allocate EQs, if fails, free the VPs and return */
		lock(&x->lock);
		eqs = xive_alloc_eq_set(x, false);
		unlock(&x->lock);
		if (XIVE_ALLOC_IS_ERR(eqs)) {
			if (eqs == XIVE_ALLOC_NO_IND)
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
		vp->w1 = cpu_to_be32((blk << 28) | eqs);
	}
	return vp_base;
 fail:
	opal_xive_free_vp_block(vp_base);

	return rc;
}

static int64_t xive_try_allocate_irq(struct xive *x)
{
	int idx, base_idx, max_count, girq;
	struct xive_ive *ive;

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

	/* Mark the IVE valid. Don't bother with the HW cache, it's
	 * still masked anyway, the cache will be updated when unmasked
	 * and configured.
	 */
	ive = xive_get_ive(x, girq);
	if (!ive) {
		bitmap_clr_bit(*x->ipi_alloc_map, idx);
		unlock(&x->lock);
		return OPAL_PARAMETER;
	}
	ive->w = xive_set_field64(IVE_VALID, 0ul, 1) |
		 xive_set_field64(IVE_MASKED, 0ul, 1) |
		 xive_set_field64(IVE_EQ_DATA, 0ul, girq);
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
	struct xive_ive *ive;
	uint32_t idx;

	if (xive_mode != XIVE_MODE_EXPL)
		return OPAL_WRONG_STATE;
	if (!x || !is)
		return OPAL_PARAMETER;

	idx = GIRQ_TO_IDX(girq);

	lock(&x->lock);

	ive = xive_get_ive(x, girq);
	if (!ive) {
		unlock(&x->lock);
		return OPAL_PARAMETER;
	}

	/* Mask the interrupt source */
	xive_update_irq_mask(s, girq - s->esb_base, true);

	/* Mark the IVE masked and invalid */
	ive->w = xive_set_field64(IVE_VALID, 0ul, 1) |
		 xive_set_field64(IVE_MASKED, 0ul, 1);
	xive_ivc_scrub(x, x->block_id, idx);

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
	void *ind_tm_base;
	uint64_t v0,v1;

	if (!c)
		return OPAL_PARAMETER;
	xs = c->xstate;
	if (!xs || !xs->tm_ring1)
		return OPAL_INTERNAL_ERROR;
	x = xs->xive;
	ind_tm_base = x->ic_base + (4 << x->ic_shift);

	lock(&x->lock);

	/* Setup indirect access to the corresponding thread */
	xive_regw(x, PC_TCTXT_INDIR0,
		  PC_TCTXT_INDIR_VALID |
		  SETFIELD(PC_TCTXT_INDIR_THRDID, 0ull, pir & 0xff));

	/* Workaround for HW issue: Need to read the above register
	 * back before doing the subsequent accesses
	 */
	xive_regr(x, PC_TCTXT_INDIR0);

	v0 = in_be64(ind_tm_base + offset);
	if (offset == TM_QW3_HV_PHYS) {
		v1 = in_8(ind_tm_base + offset + 8);
		v1 <<= 56;
	} else {
		v1 = in_be32(ind_tm_base + offset + 8);
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


	xive_regw(x, PC_TCTXT_INDIR0, 0);
	unlock(&x->lock);

	return OPAL_SUCCESS;
}

static int64_t opal_xive_dump_vp(uint32_t vp_id)
{
	uint32_t blk, idx;
	uint8_t order;
	bool group;
	struct xive *x;
	struct xive_vp *vp;
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

	xive_vpc_scrub_clean(x, blk, idx);

	vpw = ((uint32_t *)vp) + (group ? 8 : 0);
	prlog(PR_INFO, "VP[%08x]: 0..3: %08x %08x %08x %08x\n", vp_id,
	      vpw[0], vpw[1], vpw[2], vpw[3]);
	prlog(PR_INFO, "VP[%08x]: 4..7: %08x %08x %08x %08x\n", vp_id,
	      vpw[4], vpw[5], vpw[6], vpw[7]);
	unlock(&x->lock);

	return OPAL_SUCCESS;
}

static int64_t __opal_xive_dump_emu(struct xive_cpu_state *xs, uint32_t pir)
{
	struct xive_eq *eq;
	uint32_t ipi_target;
	uint8_t *mm, pq;

	prlog(PR_INFO, "CPU[%04x]: XIVE emulation state\n", pir);

	prlog(PR_INFO, "CPU[%04x]: cppr=%02x mfrr=%02x pend=%02x"
	      " prev_cppr=%02x total_irqs=%llx\n", pir,
	      xs->cppr, xs->mfrr, xs->pending, xs->prev_cppr, xs->total_irqs);

	prlog(PR_INFO, "CPU[%04x]: EQ IDX=%x MSK=%x G=%d [%08x %08x %08x > %08x %08x %08x %08x ...]\n",
	      pir,  xs->eqptr, xs->eqmsk, xs->eqgen,
	      xs->eqbuf[(xs->eqptr - 3) & xs->eqmsk],
	      xs->eqbuf[(xs->eqptr - 2) & xs->eqmsk],
	      xs->eqbuf[(xs->eqptr - 1) & xs->eqmsk],
	      xs->eqbuf[(xs->eqptr + 0) & xs->eqmsk],
	      xs->eqbuf[(xs->eqptr + 1) & xs->eqmsk],
	      xs->eqbuf[(xs->eqptr + 2) & xs->eqmsk],
	      xs->eqbuf[(xs->eqptr + 3) & xs->eqmsk]);

	mm = xs->xive->esb_mmio + GIRQ_TO_IDX(xs->ipi_irq) * XIVE_ESB_PAGE_SIZE;
	pq = in_8(mm + 0x10800);
	if (xive_get_irq_targetting(xs->ipi_irq, &ipi_target, NULL, NULL))
		prlog(PR_INFO, "CPU[%04x]: IPI #%08x PQ=%x target=%08x\n",
				pir, xs->ipi_irq, pq, ipi_target);
	else
		prlog(PR_INFO, "CPU[%04x]: IPI #%08x PQ=%x target=??\n",
				pir, xs->ipi_irq, pq);



	__xive_cache_scrub(xs->xive, xive_cache_eqc, xs->eq_blk,
			   xs->eq_idx + XIVE_EMULATION_PRIO,
			   false, false);
	eq = xive_get_eq(xs->xive, xs->eq_idx + XIVE_EMULATION_PRIO);
	prlog(PR_INFO, "CPU[%04x]: EQ @%p W0=%08x W1=%08x qbuf @%p\n",
	      pir, eq, be32_to_cpu(eq->w0), be32_to_cpu(eq->w1), xs->eqbuf);

	return OPAL_SUCCESS;
}

static int64_t opal_xive_dump_emu(uint32_t pir)
{
	struct cpu_thread *c = find_cpu_by_pir(pir);
	struct xive_cpu_state *xs;
	int64_t rc;

	if (!c)
		return OPAL_PARAMETER;

	xs = c->xstate;
	if (!xs) {
		prlog(PR_INFO, "  <none>\n");
		return OPAL_SUCCESS;
	}
	lock(&xs->lock);
	rc = __opal_xive_dump_emu(xs, pir);
	log_print(xs);
	unlock(&xs->lock);

	return rc;
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
	case XIVE_DUMP_EMU_STATE:
		return opal_xive_dump_emu(id);
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

void init_xive(void)
{
	struct dt_node *np;
	struct proc_chip *chip;
	struct cpu_thread *cpu;
	struct xive *one_xive;
	bool first = true;

	/* Look for xive nodes and do basic inits */
	dt_for_each_compatible(dt_root, np, "ibm,power9-xive-x") {
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

	xive_mode = XIVE_MODE_EMU;

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

	/* Initialize XICS emulation per-cpu structures */
	for_each_present_cpu(cpu) {
		xive_init_cpu(cpu);
	}
	/* Add interrupts propertie to each CPU node */
	for_each_present_cpu(cpu) {
		if (cpu_is_thread0(cpu))
			xive_init_cpu_properties(cpu);
	}

	/* Calling boot CPU */
	xive_cpu_callin(this_cpu());

	/* Register XICS emulation calls */
	opal_register(OPAL_INT_GET_XIRR, opal_xive_get_xirr, 2);
	opal_register(OPAL_INT_SET_CPPR, opal_xive_set_cppr, 1);
	opal_register(OPAL_INT_EOI, opal_xive_eoi, 1);
	opal_register(OPAL_INT_SET_MFRR, opal_xive_set_mfrr, 2);

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

