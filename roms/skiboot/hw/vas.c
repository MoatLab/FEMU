// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2018 IBM Corp. */

#include <skiboot.h>
#include <chip.h>
#include <phys-map.h>
#include <xscom.h>
#include <io.h>
#include <xive.h>
#include <interrupts.h>
#include <nvram.h>
#include <vas.h>

#define vas_err(__fmt,...)	prlog(PR_ERR,"VAS: " __fmt, ##__VA_ARGS__)

#ifdef VAS_VERBOSE_DEBUG
#define vas_vdbg(__x,__fmt,...)	prlog(PR_DEBUG,"VAS: " __fmt, ##__VA_ARGS__)
#else
#define vas_vdbg(__x,__fmt,...)	do { } while (0)
#endif

static int vas_initialized;

struct vas {
	uint32_t	chip_id;
	uint32_t	vas_id;
	uint64_t	xscom_base;
	uint64_t	wcbs;
	uint32_t	vas_irq;
	uint64_t	vas_port;
};

static inline void get_hvwc_mmio_bar(int chipid, uint64_t *start, uint64_t *len)
{
	phys_map_get(chipid, VAS_HYP_WIN, 0, start, len);
}

static inline void get_uwc_mmio_bar(int chipid, uint64_t *start, uint64_t *len)
{
	phys_map_get(chipid, VAS_USER_WIN, 0, start, len);
}

static inline uint64_t compute_vas_scom_addr(struct vas *vas, uint64_t reg)
{
	return vas->xscom_base + reg;
}

static int vas_scom_write(struct proc_chip *chip, uint64_t reg, uint64_t val)
{
	int rc;
	uint64_t addr;

	addr = compute_vas_scom_addr(chip->vas, reg);

	rc = xscom_write(chip->id, addr, val);
	if (rc != OPAL_SUCCESS) {
		vas_err("Error writing 0x%llx to 0x%llx, rc %d\n", val, addr,
				rc);
	}

	return rc;
}

/*
 * Return true if NX crypto/compression is enabled on this processor.
 *
 * On POWER8, NX-842 crypto and compression are allowed, but they do not
 * use VAS (return true).
 *
 * On POWER9, NX 842 and GZIP compressions use VAS but the PASTE instruction
 * and hence VAS is not enabled in following revisions:
 *
 *	- Nimbus DD1.X, DD2.01, DD2.1
 *	- Cumulus DD1.0
 *
 * Return false for these revisions. Return true otherwise.
 */
__attrconst inline bool vas_nx_enabled(void)
{
	uint32_t pvr;
	int major, minor;
	struct proc_chip *chip;

	chip = next_chip(NULL);

	pvr = mfspr(SPR_PVR);
	major = PVR_VERS_MAJ(pvr);
	minor = PVR_VERS_MIN(pvr);

	switch (chip->type) {
	case PROC_CHIP_P9_NIMBUS:
		return (major > 2 || (major == 2 && minor > 1));
	case PROC_CHIP_P9_CUMULUS:
		return (major > 1 || minor > 0);
	default:
		return true;
	}
}

/* Interface for NX - make sure VAS is fully initialized first */
__attrconst inline uint64_t vas_get_hvwc_mmio_bar(const int chipid)
{
	uint64_t addr;

	if (!vas_initialized)
		return 0ULL;

	get_hvwc_mmio_bar(chipid, &addr, NULL);

	return addr;
}

/* Interface for NX - make sure VAS is fully initialized first */
__attrconst uint64_t vas_get_wcbs_bar(int chipid)
{
	struct proc_chip *chip;

	if (!vas_initialized)
		return 0ULL;

	chip = get_chip(chipid);
	if (!chip)
		return 0ULL;

	return chip->vas->wcbs;
}

static int init_north_ctl(struct proc_chip *chip)
{
	uint64_t val = 0ULL;

	val = SETFIELD(VAS_64K_MODE_MASK, val, true);
	val = SETFIELD(VAS_ACCEPT_PASTE_MASK, val, true);
	val = SETFIELD(VAS_ENABLE_WC_MMIO_BAR, val, true);
	val = SETFIELD(VAS_ENABLE_UWC_MMIO_BAR, val, true);
	val = SETFIELD(VAS_ENABLE_RMA_MMIO_BAR, val, true);

	return vas_scom_write(chip, VAS_MISC_N_CTL, val);
}

/*
 * Ensure paste instructions are not accepted and MMIO BARs are disabled.
 */
static inline int reset_north_ctl(struct proc_chip *chip)
{
	return vas_scom_write(chip, VAS_MISC_N_CTL, 0ULL);
}

static void reset_fir(struct proc_chip *chip)
{
	vas_scom_write(chip, VAS_FIR0,		0x0000000000000000ULL);
	/* From VAS workbook */
	vas_scom_write(chip, VAS_FIR_MASK,	0x000001000001ffffULL);
	vas_scom_write(chip, VAS_FIR_ACTION0,	0xf800fdfc0001ffffull);
	vas_scom_write(chip, VAS_FIR_ACTION1,	0xf8fffefffffc8000ull);
}

/* VAS workbook: Section 1.3.3.1: Send Message w/ Paste Commands (cl_rma_w) */
/* P9 paste base address format */
#define	P9_RMA_LSMP_64K_SYS_ID		PPC_BITMASK(8, 12)
#define	P9_RMA_LSMP_64K_NODE_ID		PPC_BITMASK(15, 18)
#define	P9_RMA_LSMP_64K_CHIP_ID		PPC_BITMASK(19, 21)

/* Paste base address format (on P10 or later) */
#define RMA_FOREIGN_ADDR_ENABLE		PPC_BITMASK(8, 11)
#define RMA_TOPOLOGY_INDEX		PPC_BITMASK(15, 19)

#define	RMA_LSMP_WINID_START_BIT	32
#define	RMA_LSMP_WINID_NUM_BITS		16

/*
 * The start/base of the paste BAR is computed using the tables 1.1 through
 * 1.4 in Section 1.3.3.1 (Send Message w/Paste Commands (cl_rma_w)) of VAS
 * P9 Workbook.
 *
 * With 64K mode and Large SMP Mode the bits are used as follows:
 *
 *	Bits	Values		Comments
 *	--------------------------------------
 *	0:7	0b 0000_0000	Reserved
 *	8:12	0b 0000_1	System id/Foreign Index 0:4
 *	13:14	0b 00		Foreign Index 5:6
 *
 *	15:18	0 throuh 15	Node id (0 through 15)
 *	19:21	0 through 7	Chip id (0 throuh 7)
 *	22:23	0b 00		Unused, Foreign index 7:8
 *
 *	24:31	0b 0000_0000	RPN 0:7, Reserved
 *	32:47	0 through 64K	Send Window Id
 *	48:51	0b 0000		Spare
 *
 *	52	0b 0		Reserved
 *	53	0b 1		Report Enable (Set to 1 for NX).
 *	54	0b 0		Reserved
 *
 *	55:56	0b 00		Snoop Bus
 *	57:63	0b 0000_000	Reserved
 *
 * Except for a few bits, the small SMP mode computation is similar.
 *
 * TODO: Detect and compute address for small SMP mode.
 *
 * Example: For Node 0, Chip 0, Window id 4, Report Enable 1:
 *
 *    Byte0    Byte1    Byte2    Byte3    Byte4    Byte5    Byte6    Byte7
 *    00000000 00001000 00000000 00000000 00000000 00000100 00000100 00000000
 *                    |   || |            |               |      |
 *                    +-+-++++            +-------+-------+      v
 *                      |   |                      |          Report Enable
 *                      v   v                      v
 *                   Node   Chip               Window id 4
 *
 *    Thus the paste address for window id 4 is 0x00080000_00040400 and
 *    the _base_ paste address for Node 0 Chip 0 is 0x00080000_00000000.
 */

static void p9_get_rma_bar(int chipid, uint64_t *val)
{
	uint64_t v;

	v = 0ULL;
	v = SETFIELD(P9_RMA_LSMP_64K_SYS_ID, v, 1);
	v = SETFIELD(P9_RMA_LSMP_64K_NODE_ID, v, P9_GCID2NODEID(chipid));
	v = SETFIELD(P9_RMA_LSMP_64K_CHIP_ID, v, P9_GCID2CHIPID(chipid));

	*val = v;
}

/*
 * The start/base of the paste BAR is computed using the tables 1.1 through
 * 1.3 in Section 1.3.3.1 (Send Message w/Paste Commands (cl_rma_w)) of VAS
 * P10 Workbook.
 *
 * With 64K mode and Large SMP Mode the bits are used as follows:
 *
 *	Bits	Values		Comments
 *	--------------------------------------
 *	0:7	0b 0000_0000	Reserved
 *	8:11	0b 0001		Foreign Address Enable
 *	12	0b 0		SMF
 *	13:14	0b 00		Memory Select
 *
 *	15:19	0 throuh 16	Topology Index
 *	20:23	0b 0000		Chip Internal Address
 *
 *	24:31	0b 0000_0000	RPN 0:7, Reserved
 *	32:47	0 through 64K	Send Window Id
 *	48:51	0b 0000		Spare
 *
 *	52	0b 0		Reserved
 *	53	0b 1		Report Enable (Set to 1 for NX).
 *	54	0b 0		Reserved
 *
 *	55:56	0b 00		Snoop Bus
 *	57:63	0b 0000_000	Reserved
 *
 * Example: For Node 0, Chip 0, Window id 4, Report Enable 1:
 *
 *    Byte0    Byte1    Byte2    Byte3    Byte4    Byte5    Byte6    Byte7
 *    00000000 00010000 00000000 00000000 00000000 00000100 00000100 00000000
 *                      |   |             |               |      |
 *                      +---+             +-------+-------+      v
 *                        |                       |          Report Enable
 *                        v                       v
 *                 Topology Index            Window id 4
 *
 *    Thus the paste address for window id 4 is 0x00100000_00040400 and
 *    the _base_ paste address for Node 0 Chip 0 is 0x00100000_00000000.
 *
 * Note: Bit 11 (Foreign Address Enable) is set only for paste base address.
 *	 Not for VAS/NX RMA BAR. RA(0:12) = 0 for VAS/NX RMA BAR.
 */

static void get_rma_bar(struct proc_chip *chip, uint64_t *val)
{
	uint64_t v;

	v = 0ULL;
	v = SETFIELD(RMA_TOPOLOGY_INDEX, v, chip->primary_topology);

	*val = v;
}

/* Interface for NX - make sure VAS is fully initialized first */
__attrconst uint64_t vas_get_rma_bar(int chipid)
{
	struct proc_chip *chip;
	uint64_t addr;

	if (!vas_initialized)
		return 0ULL;

	chip = get_chip(chipid);
	if (!chip)
		return 0ULL;

	get_rma_bar(chip, &addr);

	return addr;
}

/*
 * Initialize RMA BAR on this chip to correspond to its node/chip id.
 * This will cause VAS to accept paste commands to targeted for this chip.
 * Initialize RMA Base Address Mask Register (BAMR) to its default value.
 */
static int init_rma(struct proc_chip *chip)
{
	int rc;
	uint64_t val;

	if (proc_gen == proc_gen_p9)
		p9_get_rma_bar(chip->id, &val);
	else
		get_rma_bar(chip, &val);

	rc = vas_scom_write(chip, VAS_RMA_BAR, val);
	if (rc)
		return rc;

	val = SETFIELD(VAS_RMA_BAMR_ADDR_MASK, 0ULL, 0xFFFC0000000ULL);

	return vas_scom_write(chip, VAS_RMA_BAMR, val);
}

/*
 * get_paste_bar():
 *
 * Compute and return the "paste base address region" for @chipid. This
 * BAR contains the "paste" addreses for all windows on the chip. Linux
 * uses this paste BAR to compute the hardware paste address of a (send)
 * window using:
 *
 * 	paste_addr = base + (winid << shift)
 *
 * where winid is the window index and shift is computed as:
 *
 *     start = RMA_LSMP_WINID_START_BIT;
 *     nbits = RMA_LSMP_WINID_NUM_BITS;
 *     shift = 63 - (start + nbits - 1);
 *
 * See also get_paste_bitfield() below, which is used to export the 'start'
 * and 'nbits' to Linux through the DT.
 *
 * Each chip supports VAS_WINDOWS_PER_CHIP (64K on Power9) windows. To
 * provide proper isolation, the paste address for each window is on a
 * separate page. Thus with a page size of 64K, the length of the paste
 * BAR for a chip is VAS_WINDOWS_PER_CHIP times 64K (or 4GB for Power9).
 *
 */
#define        VAS_PASTE_BAR_LEN       (1ULL << 32)    /* 4GB - see above */

static inline void get_paste_bar(int chipid, uint64_t *start, uint64_t *len)
{
	struct proc_chip *chip;
	uint64_t val;

	if (proc_gen == proc_gen_p9)
		p9_get_rma_bar(chipid, &val);
	else {
		chip = get_chip(chipid);
		if (!chip)
			return;

		get_rma_bar(chip, &val);

		/*
		 * RA(11) (Foreign Address Enable) is set only for paste
		 * base address.
		 */
		val = SETFIELD(RMA_FOREIGN_ADDR_ENABLE, val, 1);
	}

	*start = val;
	*len = VAS_PASTE_BAR_LEN;
}

/*
 * get_paste_bitfield():
 *
 * As explained in the function header for get_paste_bar(), the window
 * id is encoded in bits 32:47 of the paste address. Export this bitfield
 * to Linux via the device tree as a reg property (with start bit and
 * number of bits).
 */
static inline void get_paste_bitfield(uint64_t *start, uint64_t *n_bits)
{
	*start = (uint64_t)RMA_LSMP_WINID_START_BIT;
	*n_bits = (uint64_t)RMA_LSMP_WINID_NUM_BITS;
}

/*
 * Window Context MMIO (WCM) Region for each chip is assigned in the P9
 * MMIO MAP spreadsheet. Write this value to the SCOM address associated
 * with WCM_BAR.
 */
static int init_wcm(struct proc_chip *chip)
{
	uint64_t wcmbar;

	get_hvwc_mmio_bar(chip->id, &wcmbar, NULL);

	/*
	 * Write the entire WCMBAR address to the SCOM address. VAS will
	 * extract bits that it thinks are relevant i.e bits 8..38
	 */
	return vas_scom_write(chip, VAS_WCM_BAR, wcmbar);
}

/*
 * OS/User Window Context MMIO (UWCM) Region for each is assigned in the
 * P9 MMIO MAP spreadsheet. Write this value to the SCOM address associated
 * with UWCM_BAR.
 */
static int init_uwcm(struct proc_chip *chip)
{
	uint64_t uwcmbar;

	get_uwc_mmio_bar(chip->id, &uwcmbar, NULL);

	/*
	 * Write the entire UWCMBAR address to the SCOM address. VAS will
	 * extract bits that it thinks are relevant i.e bits 8..35.
	 */
	return vas_scom_write(chip, VAS_UWCM_BAR, uwcmbar);
}

static inline void free_wcbs(struct proc_chip *chip)
{
	if (chip->vas->wcbs) {
		free((void *)chip->vas->wcbs);
		chip->vas->wcbs = 0ULL;
	}
}

/*
 * VAS needs a backing store for the 64K window contexts on a chip.
 * (64K times 512 = 8MB). This region needs to be contiguous, so
 * allocate during early boot. Then write the allocated address to
 * the SCOM address for the Backing store BAR.
 */
static int alloc_init_wcbs(struct proc_chip *chip)
{
	int rc;
	uint64_t wcbs;
	size_t size;

	/* align to the backing store size */
	size = (size_t)VAS_WCBS_SIZE;
	wcbs = (uint64_t)local_alloc(chip->id, size, size);
	if (!wcbs) {
		vas_err("Unable to allocate memory for backing store\n");
		return -ENOMEM;
	}
	memset((void *)wcbs, 0ULL, size);

	/*
	 * Write entire WCBS_BAR address to the SCOM address. VAS will extract
	 * relevant bits.
	 */
	rc = vas_scom_write(chip, VAS_WCBS_BAR, wcbs);
	if (rc != OPAL_SUCCESS)
		goto out;

	chip->vas->wcbs = wcbs;
	return OPAL_SUCCESS;

out:
	free((void *)wcbs);
	return rc;
}

static struct vas *alloc_vas(uint32_t chip_id, uint32_t vas_id, uint64_t base)
{
	struct vas *vas;

	vas = zalloc(sizeof(struct vas));
	assert(vas);

	vas->chip_id = chip_id;
	vas->vas_id = vas_id;
	vas->xscom_base = base;

	return vas;
}

static void create_mm_dt_node(struct proc_chip *chip)
{
	struct dt_node *dn;
	struct vas *vas;
	const char *compat;
	uint64_t hvwc_start, hvwc_len;
	uint64_t uwc_start, uwc_len;
	uint64_t pbf_start, pbf_nbits;
	uint64_t pbar_start = 0, pbar_len = 0;

	vas = chip->vas;
	get_hvwc_mmio_bar(chip->id, &hvwc_start, &hvwc_len);
	get_uwc_mmio_bar(chip->id, &uwc_start, &uwc_len);
	get_paste_bar(chip->id, &pbar_start, &pbar_len);
	get_paste_bitfield(&pbf_start, &pbf_nbits);

	if (proc_gen == proc_gen_p9)
		compat = "ibm,power9-vas";
	else
		compat = "ibm,power10-vas";

	dn = dt_new_addr(dt_root, "vas", hvwc_start);

	dt_add_property_strings(dn, "compatible", compat,
					"ibm,vas");

	dt_add_property_u64s(dn, "reg", hvwc_start, hvwc_len,
					uwc_start, uwc_len,
					pbar_start, pbar_len,
					pbf_start, pbf_nbits);

	dt_add_property_cells(dn, "ibm,vas-id", vas->vas_id);
	dt_add_property_cells(dn, "ibm,chip-id", chip->id);
	if (vas->vas_irq) {
		dt_add_property_cells(dn, "interrupts", vas->vas_irq, 0);
		dt_add_property_cells(dn, "interrupt-parent",
					get_ics_phandle());
		dt_add_property_u64(dn, "ibm,vas-port", vas->vas_port);
	}
}

/*
 * Disable one VAS instance.
 *
 * Free memory and ensure chip does not accept paste instructions.
 */
static void disable_vas_inst(struct dt_node *np)
{
	struct proc_chip *chip;

	chip = get_chip(dt_get_chip_id(np));

	if (!chip->vas)
		return;

	free_wcbs(chip);

	reset_north_ctl(chip);
}

static void vas_setup_irq(struct proc_chip *chip)
{
	uint64_t port;
	uint32_t irq;

	irq = xive_alloc_ipi_irqs(chip->id, 1, 64);
	if (irq == XIVE_IRQ_ERROR) {
		vas_err("Failed to allocate interrupt sources for chipID %d\n",
				chip->id);
		return;
	}

	vas_vdbg("trigger port: 0x%p\n", xive_get_trigger_port(irq));

	port = (uint64_t)xive_get_trigger_port(irq);

	chip->vas->vas_irq = irq;
	chip->vas->vas_port = port;
}

/*
 * Initialize one VAS instance and enable it if @enable is true.
 */
static int init_vas_inst(struct dt_node *np, bool enable)
{
	uint32_t vas_id;
	uint64_t xscom_base;
	struct proc_chip *chip;

	chip = get_chip(dt_get_chip_id(np));
	vas_id = dt_prop_get_u32(np, "ibm,vas-id");
	xscom_base = dt_get_address(np, 0, NULL);

	chip->vas = alloc_vas(chip->id, vas_id, xscom_base);

	if (!enable) {
		reset_north_ctl(chip);
		return 0;
	}

	if (alloc_init_wcbs(chip))
		return -1;

	reset_fir(chip);

	if (init_wcm(chip) || init_uwcm(chip) || init_north_ctl(chip) ||
	    			init_rma(chip))
		return -1;

	/*
	 * Use NVRAM 'vas-user-space' config for backward compatibility
	 * to older kernels. Remove this option in future if not needed.
	 */
	if (nvram_query_eq_dangerous("vas-user-space", "enable"))
		vas_setup_irq(chip);

	create_mm_dt_node(chip);

	prlog(PR_INFO, "VAS: Initialized chip %d\n", chip->id);
	return 0;

}

void vas_init(void)
{
	bool enabled;
	struct dt_node *np;
	const char *compat;

	if (proc_gen == proc_gen_p9)
		compat = "ibm,power9-vas-x";
	else if (proc_gen == proc_gen_p10)
		compat = "ibm,power10-vas-x";
	else
		return;

	enabled = vas_nx_enabled();

	dt_for_each_compatible(dt_root, np, compat) {
		if (init_vas_inst(np, enabled))
			goto out;
	}

	vas_initialized = enabled;
	return;

out:
	dt_for_each_compatible(dt_root, np, compat)
		disable_vas_inst(np);

	vas_err("Disabled (failed initialization)\n");
	return;
}
