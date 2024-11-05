// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Low Pin Count (LPC) Bus.
 *
 * Copyright 2013-2019 IBM Corp.
 */

#define pr_fmt(fmt)	"LPC: " fmt

#include <skiboot.h>
#include <xscom.h>
#include <io.h>
#include <lock.h>
#include <chip.h>
#include <lpc.h>
#include <timebase.h>
#include <errorlog.h>
#include <opal-api.h>
#include <platform.h>
#include <psi.h>
#include <interrupts.h>

//#define DBG_IRQ(fmt...) prerror(fmt)
#define DBG_IRQ(fmt...) do { } while(0)

DEFINE_LOG_ENTRY(OPAL_RC_LPC_READ, OPAL_PLATFORM_ERR_EVT, OPAL_LPC,
		 OPAL_MISC_SUBSYSTEM, OPAL_PREDICTIVE_ERR_GENERAL,
		 OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_LPC_WRITE, OPAL_PLATFORM_ERR_EVT, OPAL_LPC,
		 OPAL_MISC_SUBSYSTEM, OPAL_PREDICTIVE_ERR_GENERAL,
		 OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_LPC_SYNC, OPAL_PLATFORM_ERR_EVT, OPAL_LPC,
		 OPAL_MISC_SUBSYSTEM, OPAL_PREDICTIVE_ERR_GENERAL,
		 OPAL_NA);

/* Used exclusively in manufacturing mode */
DEFINE_LOG_ENTRY(OPAL_RC_LPC_SYNC_PERF, OPAL_PLATFORM_ERR_EVT, OPAL_LPC,
		 OPAL_MISC_SUBSYSTEM, OPAL_UNRECOVERABLE_ERR_DEGRADE_PERF,
		 OPAL_NA);

#define ECCB_CTL	0 /* b0020 -> b00200 */
#define ECCB_STAT	2 /* b0022 -> b00210 */
#define ECCB_DATA	3 /* b0023 -> b00218 */

#define ECCB_CTL_MAGIC		0xd000000000000000ul
#define ECCB_CTL_DATASZ		PPC_BITMASK(4,7)
#define ECCB_CTL_READ		PPC_BIT(15)
#define ECCB_CTL_ADDRLEN	PPC_BITMASK(23,25)
#define 	ECCB_ADDRLEN_4B	0x4
#define ECCB_CTL_ADDR		PPC_BITMASK(32,63)

#define ECCB_STAT_PIB_ERR	PPC_BITMASK(0,5)
#define ECCB_STAT_RD_DATA	PPC_BITMASK(6,37)
#define ECCB_STAT_BUSY		PPC_BIT(44)
#define ECCB_STAT_ERRORS1	PPC_BITMASK(45,51)
#define ECCB_STAT_OP_DONE	PPC_BIT(52)
#define ECCB_STAT_ERRORS2	PPC_BITMASK(53,55)

#define ECCB_STAT_ERR_MASK	(ECCB_STAT_PIB_ERR | \
				 ECCB_STAT_ERRORS1 | \
				 ECCB_STAT_ERRORS2)

#define ECCB_TIMEOUT	1000000

/* OPB Master LS registers */
#define OPB_MASTER_LS_IRQ_STAT	0x50
#define OPB_MASTER_LS_IRQ_MASK	0x54
#define OPB_MASTER_LS_IRQ_POL	0x58
#define   OPB_MASTER_IRQ_LPC	       	0x00000800

/* LPC HC registers */
#define LPC_HC_FW_SEG_IDSEL	0x24
#define LPC_HC_FW_RD_ACC_SIZE	0x28
#define   LPC_HC_FW_RD_1B		0x00000000
#define   LPC_HC_FW_RD_2B		0x01000000
#define   LPC_HC_FW_RD_4B		0x02000000
#define   LPC_HC_FW_RD_16B		0x04000000
#define   LPC_HC_FW_RD_128B		0x07000000
#define LPC_HC_IRQSER_CTRL	0x30
#define   LPC_HC_IRQSER_EN		0x80000000
#define   LPC_HC_IRQSER_QMODE		0x40000000
#define   LPC_HC_IRQSER_START_MASK	0x03000000
#define   LPC_HC_IRQSER_START_4CLK	0x00000000
#define   LPC_HC_IRQSER_START_6CLK	0x01000000
#define   LPC_HC_IRQSER_START_8CLK	0x02000000
#define   LPC_HC_IRQSER_AUTO_CLEAR	0x00800000
#define LPC_HC_IRQMASK		0x34	/* same bit defs as LPC_HC_IRQSTAT */
#define LPC_HC_IRQSTAT		0x38
#define   LPC_HC_IRQ_SERIRQ0		0x80000000u /* all bits down to ... */
#define   LPC_HC_IRQ_SERIRQ16		0x00008000 /* IRQ16=IOCHK#, IRQ2=SMI# */
#define   LPC_HC_IRQ_SERIRQ_ALL		0xffff8000
#define   LPC_HC_IRQ_LRESET		0x00000400
#define   LPC_HC_IRQ_SYNC_ABNORM_ERR	0x00000080
#define   LPC_HC_IRQ_SYNC_NORESP_ERR	0x00000040
#define   LPC_HC_IRQ_SYNC_NORM_ERR	0x00000020
#define   LPC_HC_IRQ_SYNC_TIMEOUT_ERR	0x00000010
#define   LPC_HC_IRQ_TARG_TAR_ERR	0x00000008
#define   LPC_HC_IRQ_BM_TAR_ERR		0x00000004
#define   LPC_HC_IRQ_BM0_REQ		0x00000002
#define   LPC_HC_IRQ_BM1_REQ		0x00000001
#define   LPC_HC_IRQ_BASE_IRQS		(		     \
	LPC_HC_IRQ_LRESET |				     \
	LPC_HC_IRQ_SYNC_ABNORM_ERR |			     \
	LPC_HC_IRQ_SYNC_NORESP_ERR |			     \
	LPC_HC_IRQ_SYNC_NORM_ERR |			     \
	LPC_HC_IRQ_SYNC_TIMEOUT_ERR |			     \
	LPC_HC_IRQ_TARG_TAR_ERR |			     \
	LPC_HC_IRQ_BM_TAR_ERR)
#define LPC_HC_ERROR_ADDRESS	0x40

#define LPC_NUM_SERIRQ		17

enum {
	LPC_ROUTE_FREE = 0,
	LPC_ROUTE_OPAL,
	LPC_ROUTE_LINUX
};

struct lpc_error_entry {
	int64_t rc;
	const char *description;
};

struct lpcm {
	uint32_t		chip_id;
	uint32_t		xbase;
	void			*mbase;
	struct lock		lock;
	uint8_t			fw_idsel;
	uint8_t			fw_rdsz;
	struct list_head	clients;
	bool			has_serirq;
	uint8_t			sirq_routes[LPC_NUM_SERIRQ];
	bool			sirq_routed[LPC_NUM_SERIRQ];
	uint32_t		sirq_rmasks[4];
	uint8_t			sirq_ralloc[4];
	struct dt_node		*node;
};


#define	LPC_BUS_DEGRADED_PERF_THRESHOLD		5

struct lpc_client_entry {
	struct list_node node;
	const struct lpc_client *clt;
	uint32_t policy;
};

/* Default LPC bus */
static int32_t lpc_default_chip_id = -1;
static bool lpc_irqs_ready;

/*
 * These are expected to be the same on all chips and should probably
 * be read (or configured) dynamically. This is how things are configured
 * today on Tuletta.
 */
static uint32_t lpc_io_opb_base		= 0xd0010000;
static uint32_t lpc_mem_opb_base	= 0xe0000000;
static uint32_t lpc_fw_opb_base		= 0xf0000000;
static uint32_t lpc_reg_opb_base	= 0xc0012000;
static uint32_t opb_master_reg_base	= 0xc0010000;

static int64_t opb_mmio_write(struct lpcm *lpc, uint32_t addr, uint32_t data,
			      uint32_t sz)
{
	switch (sz) {
	case 1:
		out_8(lpc->mbase + addr, data);
		return OPAL_SUCCESS;
	case 2:
		out_be16(lpc->mbase + addr, data);
		return OPAL_SUCCESS;
	case 4:
		out_be32(lpc->mbase + addr, data);
		return OPAL_SUCCESS;
	}
	prerror("Invalid data size %d\n", sz);
	return OPAL_PARAMETER;
}

static int64_t opb_write(struct lpcm *lpc, uint32_t addr, uint32_t data,
			 uint32_t sz)
{
	uint64_t ctl = ECCB_CTL_MAGIC, stat;
	int64_t rc, tout;
	uint64_t data_reg;

	if (lpc->mbase)
		return opb_mmio_write(lpc, addr, data, sz);

	switch(sz) {
	case 1:
		data_reg = ((uint64_t)data) << 56;
		break;
	case 2:
		data_reg = ((uint64_t)data) << 48;
		break;
	case 4:
		data_reg = ((uint64_t)data) << 32;
		break;
	default:
		prerror("Invalid data size %d\n", sz);
		return OPAL_PARAMETER;
	}

	rc = xscom_write(lpc->chip_id, lpc->xbase + ECCB_DATA, data_reg);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_LPC_WRITE),
			"LPC: XSCOM write to ECCB DATA error %lld\n", rc);
		return rc;
	}

	ctl = SETFIELD(ECCB_CTL_DATASZ, ctl, sz);
	ctl = SETFIELD(ECCB_CTL_ADDRLEN, ctl, ECCB_ADDRLEN_4B);
	ctl = SETFIELD(ECCB_CTL_ADDR, ctl, addr);
	rc = xscom_write(lpc->chip_id, lpc->xbase + ECCB_CTL, ctl);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_LPC_WRITE),
			"LPC: XSCOM write to ECCB CTL error %lld\n", rc);
		return rc;
	}

	for (tout = 0; tout < ECCB_TIMEOUT; tout++) {
		rc = xscom_read(lpc->chip_id, lpc->xbase + ECCB_STAT,
				&stat);
		if (rc) {
			log_simple_error(&e_info(OPAL_RC_LPC_WRITE),
				"LPC: XSCOM read from ECCB STAT err %lld\n",
									rc);
			return rc;
		}
		if (stat & ECCB_STAT_OP_DONE) {
			if (stat & ECCB_STAT_ERR_MASK) {
				log_simple_error(&e_info(OPAL_RC_LPC_WRITE),
					"LPC: Error status: 0x%llx\n", stat);
				return OPAL_HARDWARE;
			}
			return OPAL_SUCCESS;
		}
		time_wait_nopoll(100);
	}
	log_simple_error(&e_info(OPAL_RC_LPC_WRITE), "LPC: Write timeout !\n");
	return OPAL_HARDWARE;
}

static int64_t opb_mmio_read(struct lpcm *lpc, uint32_t addr, uint32_t *data,
			     uint32_t sz)
{
	switch (sz) {
	case 1:
		*data = in_8(lpc->mbase + addr);
		return OPAL_SUCCESS;
	case 2:
		*data = in_be16(lpc->mbase + addr);
		return OPAL_SUCCESS;
	case 4:
		*data = in_be32(lpc->mbase + addr);
		return OPAL_SUCCESS;
	}
	prerror("Invalid data size %d\n", sz);
	return OPAL_PARAMETER;
}

static int64_t opb_read(struct lpcm *lpc, uint32_t addr, uint32_t *data,
		        uint32_t sz)
{
	uint64_t ctl = ECCB_CTL_MAGIC | ECCB_CTL_READ, stat;
	int64_t rc, tout;

	if (lpc->mbase)
		return opb_mmio_read(lpc, addr, data, sz);

	if (sz != 1 && sz != 2 && sz != 4) {
		prerror("Invalid data size %d\n", sz);
		return OPAL_PARAMETER;
	}

	ctl = SETFIELD(ECCB_CTL_DATASZ, ctl, sz);
	ctl = SETFIELD(ECCB_CTL_ADDRLEN, ctl, ECCB_ADDRLEN_4B);
	ctl = SETFIELD(ECCB_CTL_ADDR, ctl, addr);
	rc = xscom_write(lpc->chip_id, lpc->xbase + ECCB_CTL, ctl);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_LPC_READ),
			"LPC: XSCOM write to ECCB CTL error %lld\n", rc);
		return rc;
	}

	for (tout = 0; tout < ECCB_TIMEOUT; tout++) {
		rc = xscom_read(lpc->chip_id, lpc->xbase + ECCB_STAT,
				&stat);
		if (rc) {
			log_simple_error(&e_info(OPAL_RC_LPC_READ),
				"LPC: XSCOM read from ECCB STAT err %lld\n",
									rc);
			return rc;
		}
		if (stat & ECCB_STAT_OP_DONE) {
			uint32_t rdata = GETFIELD(ECCB_STAT_RD_DATA, stat);
			if (stat & ECCB_STAT_ERR_MASK) {
				log_simple_error(&e_info(OPAL_RC_LPC_READ),
					"LPC: Error status: 0x%llx\n", stat);
				return OPAL_HARDWARE;
			}
			switch(sz) {
			case 1:
				*data = rdata >> 24;
				break;
			case 2:
				*data = rdata >> 16;
				break;
			default:
				*data = rdata;
				break;
			}
			return 0;
		}
		time_wait_nopoll(100);
	}
	log_simple_error(&e_info(OPAL_RC_LPC_READ), "LPC: Read timeout !\n");
	return OPAL_HARDWARE;
}

static int64_t lpc_set_fw_idsel(struct lpcm *lpc, uint8_t idsel)
{
	uint32_t val;
	int64_t rc;

	if (idsel == lpc->fw_idsel)
		return OPAL_SUCCESS;
	if (idsel > 0xf)
		return OPAL_PARAMETER;

	rc = opb_read(lpc, lpc_reg_opb_base + LPC_HC_FW_SEG_IDSEL,
		      &val, 4);
	if (rc) {
		prerror("Failed to read HC_FW_SEG_IDSEL register !\n");
		return rc;
	}
	val = (val & 0xfffffff0) | idsel;
	rc = opb_write(lpc, lpc_reg_opb_base + LPC_HC_FW_SEG_IDSEL,
		       val, 4);
	if (rc) {
		prerror("Failed to write HC_FW_SEG_IDSEL register !\n");
		return rc;
	}
	lpc->fw_idsel = idsel;
	return OPAL_SUCCESS;
}

static int64_t lpc_set_fw_rdsz(struct lpcm *lpc, uint8_t rdsz)
{
	uint32_t val;
	int64_t rc;

	if (rdsz == lpc->fw_rdsz)
		return OPAL_SUCCESS;
	switch(rdsz) {
	case 1:
		val = LPC_HC_FW_RD_1B;
		break;
	case 2:
		val = LPC_HC_FW_RD_2B;
		break;
	case 4:
		val = LPC_HC_FW_RD_4B;
		break;
	default:
		/*
		 * The HW supports 16 and 128 via a buffer/cache
		 * but I have never exprimented with it and am not
		 * sure it works the way we expect so let's leave it
		 * at that for now
		 */
		return OPAL_PARAMETER;
	}
	rc = opb_write(lpc, lpc_reg_opb_base + LPC_HC_FW_RD_ACC_SIZE,
		       val, 4);
	if (rc) {
		prerror("Failed to write LPC_HC_FW_RD_ACC_SIZE !\n");
		return rc;
	}
	lpc->fw_rdsz = rdsz;
	return OPAL_SUCCESS;
}

static int64_t lpc_opb_prepare(struct lpcm *lpc,
			       enum OpalLPCAddressType addr_type,
			       uint32_t addr, uint32_t sz,
			       uint32_t *opb_base, bool is_write)
{
	uint32_t top = addr + sz;
	uint8_t fw_idsel;
	int64_t rc;

	/* Address wraparound */
	if (top < addr)
		return OPAL_PARAMETER;

	/*
	 * Bound check access and get the OPB base address for
	 * the window corresponding to the access type
	 */
	switch(addr_type) {
	case OPAL_LPC_IO:
		/* IO space is 64K */
		if (top > 0x10000)
			return OPAL_PARAMETER;
		/* And only supports byte accesses */
		if (sz != 1)
			return OPAL_PARAMETER;
		*opb_base = lpc_io_opb_base;
		break;
	case OPAL_LPC_MEM:
		/* MEM space is 256M */
		if (top > 0x10000000)
			return OPAL_PARAMETER;
		/* And only supports byte accesses */
		if (sz != 1)
			return OPAL_PARAMETER;
		*opb_base = lpc_mem_opb_base;
		break;
	case OPAL_LPC_FW:
		/*
		 * FW space is in segments of 256M controlled
		 * by IDSEL, make sure we don't cross segments
		 */
		*opb_base = lpc_fw_opb_base;
		fw_idsel = (addr >> 28);
		if (((top - 1) >> 28) != fw_idsel)
			return OPAL_PARAMETER;

		/* Set segment */
		rc = lpc_set_fw_idsel(lpc, fw_idsel);
		if (rc)
			return rc;
		/* Set read access size */
		if (!is_write) {
			rc = lpc_set_fw_rdsz(lpc, sz);
			if (rc)
				return rc;
		}
		break;
	default:
		return OPAL_PARAMETER;
	}
	return OPAL_SUCCESS;
}

#define LPC_ERROR_IDX(x) (__builtin_ffs(x) - 1 - 2)
#define LPC_ERROR(_sts, _rc, _description) \
	[LPC_ERROR_IDX(_sts)] = { _rc, _description }
static const struct lpc_error_entry lpc_error_table[] = {
	LPC_ERROR(LPC_HC_IRQ_BM_TAR_ERR, OPAL_WRONG_STATE, "Got bus master TAR error."),
	LPC_ERROR(LPC_HC_IRQ_TARG_TAR_ERR, OPAL_WRONG_STATE, "Got abnormal TAR error."),
	LPC_ERROR(LPC_HC_IRQ_SYNC_TIMEOUT_ERR, OPAL_TIMEOUT, "Got SYNC timeout error."),
	LPC_ERROR(LPC_HC_IRQ_SYNC_NORM_ERR, OPAL_WRONG_STATE, "Got SYNC normal error."),
	LPC_ERROR(LPC_HC_IRQ_SYNC_NORESP_ERR, OPAL_HARDWARE, "Got SYNC no-response error."),
	LPC_ERROR(LPC_HC_IRQ_SYNC_ABNORM_ERR, OPAL_WRONG_STATE, "Got SYNC abnormal error."),
};

static int64_t lpc_probe_prepare(struct lpcm *lpc)
{
	const uint32_t irqmask_addr = lpc_reg_opb_base + LPC_HC_IRQMASK;
	const uint32_t irqstat_addr = lpc_reg_opb_base + LPC_HC_IRQSTAT;
	uint32_t irqmask;
	int rc;

	rc = opb_read(lpc, irqmask_addr, &irqmask, 4);
	if (rc)
		return rc;

	irqmask &= ~LPC_HC_IRQ_SYNC_NORESP_ERR;
	rc = opb_write(lpc, irqmask_addr, irqmask, 4);
	if (rc)
		return rc;

	return opb_write(lpc, irqstat_addr, LPC_HC_IRQ_SYNC_NORESP_ERR, 4);
}

static int64_t lpc_probe_test(struct lpcm *lpc)
{
	const uint32_t irqmask_addr = lpc_reg_opb_base + LPC_HC_IRQMASK;
	const uint32_t irqstat_addr = lpc_reg_opb_base + LPC_HC_IRQSTAT;
	uint32_t irqmask, irqstat;
	int64_t idx;
	int rc;

	rc = opb_read(lpc, irqstat_addr, &irqstat, 4);
	if (rc)
		return rc;

	rc = opb_write(lpc, irqstat_addr, LPC_HC_IRQ_SYNC_NORESP_ERR, 4);
	if (rc)
		return rc;

	rc = opb_read(lpc, irqmask_addr, &irqmask, 4);
	if (rc)
		return rc;

	irqmask |= LPC_HC_IRQ_SYNC_NORESP_ERR;
	rc = opb_write(lpc, irqmask_addr, irqmask, 4);
	if (rc)
		return rc;

	if (!(irqstat & LPC_HC_IRQ_BASE_IRQS))
		return OPAL_SUCCESS;

	/* Ensure we can perform a valid lookup in the error table */
	idx = LPC_ERROR_IDX(irqstat);
	if (idx < 0 || idx >= ARRAY_SIZE(lpc_error_table)) {
		prerror("LPC bus error translation failed with status 0x%x\n",
			irqstat);
		return OPAL_PARAMETER;
	}

	rc = lpc_error_table[idx].rc;
	return rc;
}

static int64_t __lpc_write(struct lpcm *lpc, enum OpalLPCAddressType addr_type,
			   uint32_t addr, uint32_t data, uint32_t sz,
			   bool probe)
{
	uint32_t opb_base;
	int64_t rc;

	lock(&lpc->lock);
	if (probe) {
		rc = lpc_probe_prepare(lpc);
		if (rc)
			goto bail;
	}

	/*
	 * Convert to an OPB access and handle LPC HC configuration
	 * for FW accesses (IDSEL)
	 */
	rc = lpc_opb_prepare(lpc, addr_type, addr, sz, &opb_base, true);
	if (rc)
		goto bail;

	/* Perform OPB access */
	rc = opb_write(lpc, opb_base + addr, data, sz);
	if (rc)
		goto bail;

	if (probe)
		rc = lpc_probe_test(lpc);
 bail:
	unlock(&lpc->lock);
	return rc;
}

static int64_t __lpc_write_sanity(enum OpalLPCAddressType addr_type,
				  uint32_t addr, uint32_t data, uint32_t sz,
				  bool probe)
{
	struct proc_chip *chip;

	if (lpc_default_chip_id < 0)
		return OPAL_PARAMETER;
	chip = get_chip(lpc_default_chip_id);
	if (!chip || !chip->lpc)
		return OPAL_PARAMETER;
	return __lpc_write(chip->lpc, addr_type, addr, data, sz, probe);
}

int64_t lpc_write(enum OpalLPCAddressType addr_type, uint32_t addr,
		  uint32_t data, uint32_t sz)
{
	return __lpc_write_sanity(addr_type, addr, data, sz, false);
}

int64_t lpc_probe_write(enum OpalLPCAddressType addr_type, uint32_t addr,
			uint32_t data, uint32_t sz)
{
	return __lpc_write_sanity(addr_type, addr, data, sz, true);
}

/*
 * The "OPAL" variant add the emulation of 2 and 4 byte accesses using
 * byte accesses for IO and MEM space in order to be compatible with
 * existing Linux expectations
 */
static int64_t opal_lpc_write(uint32_t chip_id, enum OpalLPCAddressType addr_type,
			      uint32_t addr, uint32_t data, uint32_t sz)
{
	struct proc_chip *chip;
	int64_t rc;

	chip = get_chip(chip_id);
	if (!chip || !chip->lpc)
		return OPAL_PARAMETER;

	if (addr_type == OPAL_LPC_FW || sz == 1)
		return __lpc_write(chip->lpc, addr_type, addr, data, sz, false);
	while(sz--) {
		rc = __lpc_write(chip->lpc, addr_type, addr, data & 0xff, 1, false);
		if (rc)
			return rc;
		addr++;
		data >>= 8;
	}
	return OPAL_SUCCESS;
}

static int64_t __lpc_read(struct lpcm *lpc, enum OpalLPCAddressType addr_type,
			  uint32_t addr, uint32_t *data, uint32_t sz,
			  bool probe)
{
	uint32_t opb_base;
	int64_t rc;

	lock(&lpc->lock);
	if (probe) {
		rc = lpc_probe_prepare(lpc);
		if (rc)
			goto bail;
	}

	/*
	 * Convert to an OPB access and handle LPC HC configuration
	 * for FW accesses (IDSEL and read size)
	 */
	rc = lpc_opb_prepare(lpc, addr_type, addr, sz, &opb_base, false);
	if (rc)
		goto bail;

	/* Perform OPB access */
	rc = opb_read(lpc, opb_base + addr, data, sz);
	if (rc)
		goto bail;

	if (probe)
		rc = lpc_probe_test(lpc);
 bail:
	unlock(&lpc->lock);
	return rc;
}

static int64_t __lpc_read_sanity(enum OpalLPCAddressType addr_type,
				 uint32_t addr, uint32_t *data, uint32_t sz,
				 bool probe)
{
	struct proc_chip *chip;

	if (lpc_default_chip_id < 0)
		return OPAL_PARAMETER;
	chip = get_chip(lpc_default_chip_id);
	if (!chip || !chip->lpc)
		return OPAL_PARAMETER;
	return __lpc_read(chip->lpc, addr_type, addr, data, sz, probe);
}

int64_t lpc_read(enum OpalLPCAddressType addr_type, uint32_t addr,
		 uint32_t *data, uint32_t sz)
{
	return __lpc_read_sanity(addr_type, addr, data, sz, false);
}

int64_t lpc_probe_read(enum OpalLPCAddressType addr_type, uint32_t addr,
		       uint32_t *data, uint32_t sz)
{
	return __lpc_read_sanity(addr_type, addr, data, sz, true);
}

/*
 * The "OPAL" variant add the emulation of 2 and 4 byte accesses using
 * byte accesses for IO and MEM space in order to be compatible with
 * existing Linux expectations
 */
static int64_t opal_lpc_read(uint32_t chip_id, enum OpalLPCAddressType addr_type,
			     uint32_t addr, __be32 *data, uint32_t sz)
{
	struct proc_chip *chip;
	int64_t rc;
	uint32_t tmp;

	chip = get_chip(chip_id);
	if (!chip || !chip->lpc)
		return OPAL_PARAMETER;

	if (addr_type == OPAL_LPC_FW) {
		rc = __lpc_read(chip->lpc, addr_type, addr, &tmp, sz, false);
		if (rc)
			return rc;

	} else {
		tmp = 0;
		while (sz--) {
			uint32_t byte;

			rc = __lpc_read(chip->lpc, addr_type, addr, &byte, 1, false);
			if (rc)
				return rc;
			tmp = tmp | (byte << (8 * sz));
			addr++;
		}
	}

	*data = cpu_to_be32(tmp);

	return OPAL_SUCCESS;
}

bool lpc_present(void)
{
	return lpc_default_chip_id >= 0;
}

/* Called with LPC lock held */
static void lpc_setup_serirq(struct lpcm *lpc)
{
	struct lpc_client_entry *ent;
	uint32_t mask = LPC_HC_IRQ_BASE_IRQS;
	int rc;

	if (!lpc_irqs_ready)
		return;

	/* Collect serirq enable bits */
	list_for_each(&lpc->clients, ent, node)
		mask |= ent->clt->interrupts & LPC_HC_IRQ_SERIRQ_ALL;

	rc = opb_write(lpc, lpc_reg_opb_base + LPC_HC_IRQMASK, mask, 4);
	if (rc) {
		prerror("Failed to update irq mask\n");
		return;
	}
	DBG_IRQ("IRQ mask set to 0x%08x\n", mask);

	/* Enable the LPC interrupt in the OPB Master */
	opb_write(lpc, opb_master_reg_base + OPB_MASTER_LS_IRQ_POL, 0, 4);
	rc = opb_write(lpc, opb_master_reg_base + OPB_MASTER_LS_IRQ_MASK,
		       OPB_MASTER_IRQ_LPC, 4);
	if (rc)
		prerror("Failed to enable IRQs in OPB\n");

	/* Check whether we should enable serirq */
	if (mask & LPC_HC_IRQ_SERIRQ_ALL) {
		rc = opb_write(lpc, lpc_reg_opb_base + LPC_HC_IRQSER_CTRL,
			       LPC_HC_IRQSER_EN |
			       LPC_HC_IRQSER_START_4CLK |
			       /*
				* New mode bit for P9N DD2.0 (ignored otherwise)
				* when set we no longer have to manually clear
				* the SerIRQs on EOI.
				*/
			       LPC_HC_IRQSER_AUTO_CLEAR, 4);
		DBG_IRQ("SerIRQ enabled\n");
	} else {
		rc = opb_write(lpc, lpc_reg_opb_base + LPC_HC_IRQSER_CTRL,
			       0, 4);
		DBG_IRQ("SerIRQ disabled\n");
	}
	if (rc)
		prerror("Failed to configure SerIRQ\n");
	{
		u32 val;
		rc = opb_read(lpc, lpc_reg_opb_base + LPC_HC_IRQMASK, &val, 4);
		if (rc)
			prerror("Failed to readback mask");
		else
			DBG_IRQ("MASK READBACK=%x\n", val);

		rc = opb_read(lpc, lpc_reg_opb_base + LPC_HC_IRQSER_CTRL,
			      &val, 4);
		if (rc)
			prerror("Failed to readback ctrl");
		else
			DBG_IRQ("CTRL READBACK=%x\n", val);
	}
}

static void lpc_route_serirq(struct lpcm *lpc, uint32_t sirq,
			     uint32_t psi_idx)
{
	uint32_t reg, shift, val, psi_old;
	int64_t rc;

	psi_old = lpc->sirq_routes[sirq];
	lpc->sirq_rmasks[psi_old] &= ~(LPC_HC_IRQ_SERIRQ0 >> sirq);
	lpc->sirq_rmasks[psi_idx] |=  (LPC_HC_IRQ_SERIRQ0 >> sirq);
	lpc->sirq_routes[sirq] = psi_idx;
	lpc->sirq_routed[sirq] = true;

	/* We may not be ready yet ... */
	if (!lpc->has_serirq)
		return;

	if (sirq < 14) {
		reg = 0xc;
		shift = 4 + (sirq << 1);
	} else {
		reg = 0x8;
		shift = 8 + ((sirq - 14) << 1);
	}
	shift = 30-shift;
	rc = opb_read(lpc, opb_master_reg_base + reg, &val, 4);
	if (rc)
		return;
	val = val & ~(3 << shift);
	val |= (psi_idx & 3) << shift;
	opb_write(lpc, opb_master_reg_base + reg, val, 4);
}

static void lpc_alloc_route(struct lpcm *lpc, unsigned int irq,
			    unsigned int policy)
{
	unsigned int i, r, c;
	int route = -1;

	if (policy == IRQ_ATTR_TARGET_OPAL)
		r = LPC_ROUTE_OPAL;
	else
		r = LPC_ROUTE_LINUX;

	prlog(PR_DEBUG, "Routing irq %d, policy: %d (r=%d)\n",
	      irq, policy, r);

	/* Are we already routed ? */
	if (lpc->sirq_routed[irq] &&
	    r != lpc->sirq_ralloc[lpc->sirq_routes[irq]]) {
		prerror("irq %d has conflicting policies\n", irq);
		return;
	}

	/* First try to find a free route. Leave one for another
	 * policy though
	 */
	for (i = 0, c = 0; i < 4; i++) {
		/* Count routes with identical policy */
		if (lpc->sirq_ralloc[i] == r)
			c++;

		/* Use the route if it's free and there is no more
		 * than 3 existing routes with that policy
		 */
		if (lpc->sirq_ralloc[i] == LPC_ROUTE_FREE && c < 4) {
			lpc->sirq_ralloc[i] = r;
			route = i;
			break;
		}
	}

	/* If we couldn't get a free one, try to find an existing one
	 * with a matching policy
	 */
	for (i = 0; route < 0 && i < 4; i++) {
		if (lpc->sirq_ralloc[i] == r)
			route = i;
	}

	/* Still no route ? bail. That should never happen */
	if (route < 0) {
		prerror("Can't find a route for irq %d\n", irq);
		return;
	}

	/* Program route */
	lpc_route_serirq(lpc, irq, route);

	prlog(PR_DEBUG, "SerIRQ %d using route %d targetted at %s\n",
	      irq, route, r == LPC_ROUTE_LINUX ? "OS" : "OPAL");
}

unsigned int lpc_get_irq_policy(uint32_t chip_id, uint32_t psi_idx)
{
	struct proc_chip *c = get_chip(chip_id);

	if (!c || !c->lpc)
		return IRQ_ATTR_TARGET_LINUX;

	if (c->lpc->sirq_ralloc[psi_idx] == LPC_ROUTE_LINUX)
		return IRQ_ATTR_TARGET_LINUX;
	else
		return IRQ_ATTR_TARGET_OPAL | IRQ_ATTR_TYPE_LSI;
}

static void lpc_create_int_map(struct lpcm *lpc, struct dt_node *psi_node)
{
	__be32 map[LPC_NUM_SERIRQ * 5], *pmap;
	uint32_t i;

	if (!psi_node)
		return;
	pmap = map;
	for (i = 0; i < LPC_NUM_SERIRQ; i++) {
		if (!lpc->sirq_routed[i])
			continue;
		*(pmap++) = 0;
		*(pmap++) = 0;
		*(pmap++) = cpu_to_be32(i);
		*(pmap++) = cpu_to_be32(psi_node->phandle);
		*(pmap++) = cpu_to_be32(lpc->sirq_routes[i] + P9_PSI_IRQ_LPC_SIRQ0);
	}
	if (pmap == map)
		return;
	dt_add_property(lpc->node, "interrupt-map", map,
			(pmap - map) * sizeof(uint32_t));
	dt_add_property_cells(lpc->node, "interrupt-map-mask", 0, 0, 0xff);
	dt_add_property_cells(lpc->node, "#interrupt-cells", 1);
}

void lpc_finalize_interrupts(void)
{
	struct proc_chip *chip;

	lpc_irqs_ready = true;

	for_each_chip(chip) {
		if (chip->lpc && chip->psi &&
		    (chip->type == PROC_CHIP_P9_NIMBUS ||
		     chip->type == PROC_CHIP_P9_CUMULUS ||
		     chip->type == PROC_CHIP_P9P ||
		     chip->type == PROC_CHIP_P10))
			lpc_create_int_map(chip->lpc, chip->psi->node);
	}
}

static void lpc_init_interrupts_one(struct proc_chip *chip)
{
	struct lpcm *lpc = chip->lpc;
	int i, rc;

	lock(&lpc->lock);

	/* First mask them all */
	rc = opb_write(lpc, lpc_reg_opb_base + LPC_HC_IRQMASK, 0, 4);
	if (rc) {
		prerror("Failed to init interrutps\n");
		goto bail;
	}

	switch(chip->type) {
	case PROC_CHIP_P8_MURANO:
	case PROC_CHIP_P8_VENICE:
		/* On Murano/Venice, there is no SerIRQ, only enable error
		 * interrupts
		 */
		rc = opb_write(lpc, lpc_reg_opb_base + LPC_HC_IRQMASK,
			       LPC_HC_IRQ_BASE_IRQS, 4);
		if (rc) {
			prerror("Failed to set interrupt mask\n");
			goto bail;
		}
		opb_write(lpc, lpc_reg_opb_base + LPC_HC_IRQSER_CTRL, 0, 4);
		break;
	case PROC_CHIP_P8_NAPLES:
		/* On Naples, we support LPC interrupts, enable them based
		 * on what clients requests. This will setup the mask and
		 * enable processing
		 */
		lpc->has_serirq = true;
		lpc_setup_serirq(lpc);
		break;
	case PROC_CHIP_P9_NIMBUS:
	case PROC_CHIP_P9_CUMULUS:
	case PROC_CHIP_P9P:
	case PROC_CHIP_P10:
		/* On P9, we additionally setup the routing. */
		lpc->has_serirq = true;
		for (i = 0; i < LPC_NUM_SERIRQ; i++) {
			if (lpc->sirq_routed[i])
				lpc_route_serirq(lpc, i, lpc->sirq_routes[i]);
		}
		lpc_setup_serirq(lpc);
		break;
	default:
		;
	}
 bail:
	unlock(&lpc->lock);
}

void lpc_init_interrupts(void)
{
	struct proc_chip *chip;

	lpc_irqs_ready = true;

	for_each_chip(chip) {
		if (chip->lpc)
			lpc_init_interrupts_one(chip);
	}
}

static void lpc_dispatch_reset(struct lpcm *lpc)
{
	struct lpc_client_entry *ent;

	/* XXX We are going to hit this repeatedly while reset is
	 * asserted which might be sub-optimal. We should instead
	 * detect assertion and start a poller that will wait for
	 * de-assertion. We could notify clients of LPC being
	 * on/off rather than just reset
	 */

	prerror("Got LPC reset on chip 0x%x !\n", lpc->chip_id);

	/* Collect serirq enable bits */
	list_for_each(&lpc->clients, ent, node) {
		if (!ent->clt->reset)
			continue;
		unlock(&lpc->lock);
		ent->clt->reset(lpc->chip_id);
		lock(&lpc->lock);
	}

	/* Reconfigure serial interrupts */
	if (lpc->has_serirq)
		lpc_setup_serirq(lpc);
}

static void lpc_dispatch_err_irqs(struct lpcm *lpc, uint32_t irqs)
{
	const struct lpc_error_entry *err;
	static int lpc_bus_err_count;
	struct opal_err_info *info;
	uint32_t addr;
	int64_t idx;
	int rc;

	/* Write back to clear error interrupts, we clear SerIRQ later
	 * as they are handled as level interrupts
	 */
	rc = opb_write(lpc, lpc_reg_opb_base + LPC_HC_IRQSTAT,
		       LPC_HC_IRQ_BASE_IRQS, 4);
	if (rc)
		prerror("Failed to clear IRQ error latches !\n");

	if (irqs & LPC_HC_IRQ_LRESET) {
		lpc_dispatch_reset(lpc);
		return;
	}

	/* Ensure we can perform a valid lookup in the error table */
	idx = LPC_ERROR_IDX(irqs);
	if (idx < 0 || idx >= ARRAY_SIZE(lpc_error_table)) {
		prerror("LPC bus error translation failed with status 0x%x\n",
			irqs);
		return;
	}

	/* Find and report the error */
	err = &lpc_error_table[idx];
	lpc_bus_err_count++;
	if (manufacturing_mode && (lpc_bus_err_count > LPC_BUS_DEGRADED_PERF_THRESHOLD))
		info = &e_info(OPAL_RC_LPC_SYNC_PERF);
	else
		info = &e_info(OPAL_RC_LPC_SYNC);

	rc = opb_read(lpc, lpc_reg_opb_base + LPC_HC_ERROR_ADDRESS, &addr, 4);
	if (rc)
		log_simple_error(info, "LPC[%03x]: %s "
				 "Error reading error address register\n",
				 lpc->chip_id, err->description);
	else
		log_simple_error(info, "LPC[%03x]: %s Error address reg: "
				 "0x%08x\n",
				 lpc->chip_id, err->description, addr);
}

static void lpc_dispatch_ser_irqs(struct lpcm *lpc, uint32_t irqs,
				  bool clear_latch)
{
	struct lpc_client_entry *ent;
	uint32_t cirqs;
	int rc;

	irqs &= LPC_HC_IRQ_SERIRQ_ALL;

	/* Collect serirq enable bits */
	list_for_each(&lpc->clients, ent, node) {
		if (!ent->clt->interrupt)
			continue;
		cirqs = ent->clt->interrupts & irqs;
		if (cirqs) {
			unlock(&lpc->lock);
			ent->clt->interrupt(lpc->chip_id, cirqs);
			lock(&lpc->lock);
		}
	}

	/* Our SerIRQ are level sensitive, we clear the latch after
	 * we call the handler.
	 */
	if (!clear_latch)
		return;

	rc = opb_write(lpc, lpc_reg_opb_base + LPC_HC_IRQSTAT, irqs, 4);
	if (rc)
		prerror("Failed to clear SerIRQ latches !\n");
}

void lpc_interrupt(uint32_t chip_id)
{
	struct proc_chip *chip = get_chip(chip_id);
	struct lpcm *lpc;
	uint32_t irqs, opb_irqs;
	int rc;

	/* No initialized LPC controller on that chip */
	if (!chip || !chip->lpc)
		return;
	lpc = chip->lpc;

	lock(&lpc->lock);

	/* Grab OPB Master LS interrupt status */
	rc = opb_read(lpc, opb_master_reg_base + OPB_MASTER_LS_IRQ_STAT,
		      &opb_irqs, 4);
	if (rc) {
		prerror("Failed to read OPB IRQ state\n");
		unlock(&lpc->lock);
		return;
	}

	DBG_IRQ("OPB IRQ on chip 0x%x, oirqs=0x%08x\n", chip_id, opb_irqs);

	/* Check if it's an LPC interrupt */
	if (!(opb_irqs & OPB_MASTER_IRQ_LPC)) {
		/* Something we don't support ? Ack it anyway... */
		goto bail;
	}

	/* Handle the lpc interrupt source (errors etc...) */
	rc = opb_read(lpc, lpc_reg_opb_base + LPC_HC_IRQSTAT, &irqs, 4);
	if (rc) {
		prerror("Failed to read LPC IRQ state\n");
		goto bail;
	}

	DBG_IRQ("LPC IRQ on chip 0x%x, irqs=0x%08x\n", chip_id, irqs);

	/* Handle error interrupts */
	if (irqs & LPC_HC_IRQ_BASE_IRQS)
		lpc_dispatch_err_irqs(lpc, irqs);

	/* Handle SerIRQ interrupts */
	if (irqs & LPC_HC_IRQ_SERIRQ_ALL)
		lpc_dispatch_ser_irqs(lpc, irqs, true);
 bail:
	/* Ack it at the OPB level */
	opb_write(lpc, opb_master_reg_base + OPB_MASTER_LS_IRQ_STAT,
		  opb_irqs, 4);
	unlock(&lpc->lock);
}

void lpc_serirq(uint32_t chip_id, uint32_t index)
{
	struct proc_chip *chip = get_chip(chip_id);
	struct lpcm *lpc;
	uint32_t irqs, rmask;
	int rc;

	/* No initialized LPC controller on that chip */
	if (!chip || !chip->lpc)
		return;
	lpc = chip->lpc;

	lock(&lpc->lock);

	/* Handle the lpc interrupt source (errors etc...) */
	rc = opb_read(lpc, lpc_reg_opb_base + LPC_HC_IRQSTAT, &irqs, 4);
	if (rc) {
		prerror("Failed to read LPC IRQ state\n");
		goto bail;
	}
	rmask = lpc->sirq_rmasks[index];

	DBG_IRQ("IRQ on chip 0x%x, irqs=0x%08x rmask=0x%08x\n",
		chip_id, irqs, rmask);
	irqs &= rmask;

	/*
	 * Handle SerIRQ interrupts. Don't clear the latch,
	 * it will be done in our special EOI callback if
	 * necessary on DD1
	 */
	if (irqs)
		lpc_dispatch_ser_irqs(lpc, irqs, false);

 bail:
	unlock(&lpc->lock);
}

void lpc_all_interrupts(uint32_t chip_id)
{
	struct proc_chip *chip = get_chip(chip_id);
	struct lpcm *lpc;

	/* No initialized LPC controller on that chip */
	if (!chip || !chip->lpc)
		return;
	lpc = chip->lpc;

	/* Dispatch all */
	lock(&lpc->lock);
	lpc_dispatch_ser_irqs(lpc, LPC_HC_IRQ_SERIRQ_ALL, false);
	unlock(&lpc->lock);
}

static void lpc_init_chip_p8(struct dt_node *xn)
 {
	uint32_t gcid = dt_get_chip_id(xn);
	struct proc_chip *chip;
	struct lpcm *lpc;

	chip = get_chip(gcid);
	assert(chip);

	lpc = zalloc(sizeof(struct lpcm));
	assert(lpc);
	lpc->chip_id = gcid;
	lpc->xbase = dt_get_address(xn, 0, NULL);
	lpc->fw_idsel = 0xff;
	lpc->fw_rdsz = 0xff;
	lpc->node = xn;
	list_head_init(&lpc->clients);
	init_lock(&lpc->lock);

	if (lpc_default_chip_id < 0 ||
	    dt_has_node_property(xn, "primary", NULL)) {
		lpc_default_chip_id = gcid;
	}

	/* Mask all interrupts for now */
	opb_write(lpc, lpc_reg_opb_base + LPC_HC_IRQMASK, 0, 4);

	printf("LPC[%03x]: Initialized, access via XSCOM @0x%x\n",
	       gcid, lpc->xbase);

	dt_add_property(xn, "interrupt-controller", NULL, 0);
	dt_add_property_cells(xn, "#interrupt-cells", 1);
	assert(dt_prop_get_u32(xn, "#address-cells") == 2);

	chip->lpc = lpc;
}

static void lpc_init_chip_p9(struct dt_node *opb_node)
{
	uint32_t gcid = dt_get_chip_id(opb_node);
	struct dt_node *lpc_node;
	struct proc_chip *chip;
	struct lpcm *lpc;
	u64 addr;
	u32 val;

	chip = get_chip(gcid);
	assert(chip);

	/* Grab OPB base address */
	addr = dt_prop_get_cell(opb_node, "ranges", 1);
	addr <<= 32;
	addr |= dt_prop_get_cell(opb_node, "ranges", 2);

	/* Find the "lpc" child node */
	lpc_node = dt_find_compatible_node(opb_node, NULL, "ibm,power9-lpc");
	if (!lpc_node)
		return;

	lpc = zalloc(sizeof(struct lpcm));
	assert(lpc);
	lpc->chip_id = gcid;
	lpc->mbase = (void *)addr;
	lpc->fw_idsel = 0xff;
	lpc->fw_rdsz = 0xff;
	lpc->node = lpc_node;
	list_head_init(&lpc->clients);
	init_lock(&lpc->lock);

	if (lpc_default_chip_id < 0 ||
	    dt_has_node_property(opb_node, "primary", NULL)) {
		lpc_default_chip_id = gcid;
	}

	/* Mask all interrupts for now */
	opb_write(lpc, lpc_reg_opb_base + LPC_HC_IRQMASK, 0, 4);

	/* Clear any stale LPC bus errors */
	opb_write(lpc, lpc_reg_opb_base + LPC_HC_IRQSTAT,
		       LPC_HC_IRQ_BASE_IRQS, 4);

	/* Default with routing to PSI SerIRQ 0, this will be updated
	 * later when interrupts are initialized.
	 */
	opb_read(lpc, opb_master_reg_base + 8, &val, 4);
	val &= 0xff03ffff;
	opb_write(lpc, opb_master_reg_base + 8, val, 4);
	opb_read(lpc, opb_master_reg_base + 0xc, &val, 4);
	val &= 0xf0000000;
	opb_write(lpc, opb_master_reg_base + 0xc, val, 4);

	prlog(PR_INFO, "LPC[%03x]: Initialized\n", gcid);
	prlog(PR_DEBUG,"access via MMIO @%p\n", lpc->mbase);

	chip->lpc = lpc;
}

void lpc_init(void)
{
	struct dt_node *xn;
	bool has_lpc = false;

	/* Look for P9 first as the DT is compatile for both 8 and 9 */
	dt_for_each_compatible(dt_root, xn, "ibm,power9-lpcm-opb") {
		lpc_init_chip_p9(xn);
		has_lpc = true;
	}

	if (!has_lpc) {
		dt_for_each_compatible(dt_root, xn, "ibm,power8-lpc") {
			lpc_init_chip_p8(xn);
			has_lpc = true;
		}
	}
	if (lpc_default_chip_id >= 0)
		prlog(PR_DEBUG, "Default bus on chip 0x%x\n",
		      lpc_default_chip_id);

	if (has_lpc) {
		opal_register(OPAL_LPC_WRITE, opal_lpc_write, 5);
		opal_register(OPAL_LPC_READ, opal_lpc_read, 5);
	}
}

void lpc_used_by_console(void)
{
	struct proc_chip *chip;

	xscom_used_by_console();

	for_each_chip(chip) {
		struct lpcm *lpc = chip->lpc;
		if (lpc) {
			lpc->lock.in_con_path = true;
			lock(&lpc->lock);
			unlock(&lpc->lock);
		}
	}
}

bool lpc_ok(void)
{
	struct proc_chip *chip;

	if (lpc_default_chip_id < 0)
		return false;
	if (!xscom_ok())
		return false;
	chip = get_chip(lpc_default_chip_id);
	if (!chip->lpc)
		return false;
	return !lock_held_by_me(&chip->lpc->lock);
}

void lpc_register_client(uint32_t chip_id,
			 const struct lpc_client *clt,
			 uint32_t policy)
{
	struct lpc_client_entry *ent;
	struct proc_chip *chip;
	struct lpcm *lpc;
	bool has_routes;

	chip = get_chip(chip_id);
	assert(chip);
	lpc = chip->lpc;
	if (!lpc) {
		prerror("Attempt to register client on bad chip 0x%x\n",
			chip_id);
		return;
	}

	has_routes =
		chip->type == PROC_CHIP_P9_NIMBUS ||
		chip->type == PROC_CHIP_P9_CUMULUS ||
		chip->type == PROC_CHIP_P9P ||
		chip->type == PROC_CHIP_P10;

	if (policy != IRQ_ATTR_TARGET_OPAL && !has_routes) {
		prerror("Chip doesn't support OS interrupt policy\n");
		return;
	}

	ent = malloc(sizeof(*ent));
	assert(ent);
	ent->clt = clt;
	ent->policy = policy;
	lock(&lpc->lock);
	list_add(&lpc->clients, &ent->node);

	if (has_routes) {
		unsigned int i;
		for (i = 0; i < LPC_NUM_SERIRQ; i++)
			if (clt->interrupts & LPC_IRQ(i))
				lpc_alloc_route(lpc, i, policy);
	}

	if (lpc->has_serirq)
		lpc_setup_serirq(lpc);
	unlock(&lpc->lock);
}
