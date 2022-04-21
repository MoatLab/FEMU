// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2017 IBM Corp. */

#include <skiboot.h>
#include <xscom.h>
#include <lock.h>
#include <timebase.h>
#include <chip.h>
#include <fsi-master.h>

/*
 * FSI Masters sit on OPB busses behind PIB2OPB bridges
 *
 * There are two cMFSI behind two different bridges at
 * different XSCOM addresses. For now we don't have them in
 * the device-tree so we hard code the address
 */
#define PIB2OPB_MFSI0_ADDR	0x20000
#define PIB2OPB_MFSI1_ADDR	0x30000

/*
 * Bridge registers on XSCOM that allow generatoin
 * of OPB cycles
 */
#define PIB2OPB_REG_CMD		0x0
#define   OPB_CMD_WRITE		0x80000000
#define   OPB_CMD_READ		0x00000000
#define   OPB_CMD_8BIT		0x00000000
#define   OPB_CMD_16BIT		0x20000000
#define   OPB_CMD_32BIT		0x60000000
#define PIB2OPB_REG_STAT	0x1
#define   OPB_STAT_ANY_ERR	0x80000000
#define   OPB_STAT_ERR_OPB      0x7FEC0000
#define   OPB_STAT_ERRACK       0x00100000
#define   OPB_STAT_BUSY		0x00010000
#define   OPB_STAT_READ_VALID   0x00020000
#define   OPB_STAT_ERR_CMFSI    0x0000FC00
#define   OPB_STAT_ERR_HMFSI    0x000000FC
#define   OPB_STAT_ERR_BASE	(OPB_STAT_ANY_ERR | \
				 OPB_STAT_ERR_OPB | \
				 OPB_STAT_ERRACK)
#define PIB2OPB_REG_LSTAT	0x2
#define PIB2OPB_REG_RESET	0x4
#define PIB2OPB_REG_cRSIC	0x5
#define PIB2OPB_REG_cRSIM       0x6
#define PIB2OPB_REG_cRSIS	0x7
#define PIB2OPB_REG_hRSIC	0x8
#define PIB2OPB_REG_hRSIM	0x9
#define PIB2OPB_REG_hRSIS	0xA

/* Low level errors from OPB contain the status in the bottom 32-bit
 * and one of these in the top 32-bit
 */
#define OPB_ERR_XSCOM_ERR	0x100000000ull
#define OPB_ERR_TIMEOUT_ERR	0x200000000ull
#define OPB_ERR_BAD_OPB_ADDR	0x400000000ull

/*
 * PIB2OPB 0 has 2 MFSIs, cMFSI and hMFSI, PIB2OPB 1 only
 * has cMFSI
 */
#define cMFSI_OPB_PORTS_BASE	0x40000
#define cMFSI_OPB_REG_BASE	0x03000
#define hMFSI_OPB_PORTS_BASE	0x80000
#define hMFSI_OPB_REG_BASE	0x03400
#define MFSI_OPB_PORT_STRIDE	0x08000

/* MFSI control registers */
#define MFSI_REG_MSTAP(__n)	(0x0D0 + (__n) * 4)
#define MFSI_REG_MATRB0		0x1D8
#define MFSI_REG_MDTRB0		0x1DC
#define MFSI_REG_MESRB0		0x1D0
#define MFSI_REG_MAESP0		0x050
#define MFSI_REG_MAEB		0x070
#define MFSI_REG_MSCSB0		0x1D4

/* FSI Slave registers */
#define FSI_SLAVE_REGS		0x000800	/**< FSI Slave Register */
#define FSI_SMODE		(FSI_SLAVE_REGS | 0x00)
#define FSI_SLBUS		(FSI_SLAVE_REGS | 0x30)
#define FSI_SLRES		(FSI_SLAVE_REGS | 0x34)

#define FSI2PIB_ENGINE		0x001000	/**< FSI2PIB Engine (SCOM) */
#define FSI2PIB_RESET		(FSI2PIB_ENGINE | 0x18)
#define FSI2PIB_STATUS		(FSI2PIB_ENGINE | 0x1C)
#define FSI2PIB_COMPMASK	(FSI2PIB_ENGINE | 0x30)
#define FSI2PIB_TRUEMASK	(FSI2PIB_ENGINE | 0x34)

struct mfsi {
	uint32_t chip_id;
	uint32_t unit;
	uint32_t xscom_base;
	uint32_t ports_base;
	uint32_t reg_base;
	uint32_t err_bits;
};

#define mfsi_log(__lev, __m, __fmt, ...) \
	prlog(__lev, "MFSI %x:%x: " __fmt, __m->chip_id, __m->unit, ##__VA_ARGS__)
/*
 * Use a global FSI lock for now. Beware of re-entrancy
 * if we ever add support for normal chip XSCOM via FSI, in
 * which case we'll probably have to consider either per chip
 * lock (which can have AB->BA deadlock issues) or a re-entrant
 * global lock or something else. ...
 */
static struct lock fsi_lock = LOCK_UNLOCKED;

/*
 * OPB accessors
 */

/* We try up to 1.2ms for an OPB access */
#define MFSI_OPB_MAX_TRIES	1200

static uint64_t mfsi_opb_poll(struct mfsi *mfsi, uint32_t *read_data)
{
	unsigned long retries = MFSI_OPB_MAX_TRIES;
	uint64_t sval;
	uint32_t stat;
	int64_t rc;

	/* We try again every 10us for a bit more than 1ms */
	for (;;) {
		/* Read OPB status register */
		rc = xscom_read(mfsi->chip_id, mfsi->xscom_base + PIB2OPB_REG_STAT, &sval);
		if (rc) {
			/* Do something here ? */
			mfsi_log(PR_ERR, mfsi, "XSCOM error %lld read OPB STAT\n", rc);
			return OPB_ERR_XSCOM_ERR;
		}
		mfsi_log(PR_INSANE, mfsi, "  STAT=0x%16llx...\n", sval);

		stat = sval >> 32;

		/* Complete */
		if (!(stat & OPB_STAT_BUSY))
			break;
		if (retries-- == 0) {
			/* This isn't supposed to happen (HW timeout) */
			mfsi_log(PR_ERR, mfsi, "OPB POLL timeout !\n");
			return OPB_ERR_TIMEOUT_ERR | (stat & mfsi->err_bits);
		}
		time_wait_us(1);
	}

	/* Did we have an error ? */
	if (stat & mfsi->err_bits)
		return stat & mfsi->err_bits;

	if (read_data) {
		if (!(stat & OPB_STAT_READ_VALID)) {
			mfsi_log(PR_ERR, mfsi, "Read successful but no data !\n");

			/* What do do here ? can it actually happen ? */
			sval = 0xffffffff;
		}
		*read_data = sval & 0xffffffff;
	}

	return 0;
}

static uint64_t mfsi_opb_read(struct mfsi *mfsi, uint32_t opb_addr, uint32_t *data)
{
	uint64_t opb_cmd = OPB_CMD_READ | OPB_CMD_32BIT;
	int64_t rc;

	if (opb_addr > 0x00ffffff)
		return OPB_ERR_BAD_OPB_ADDR;

	opb_cmd |= opb_addr;
	opb_cmd <<= 32;

	mfsi_log(PR_INSANE, mfsi, "MFSI_OPB_READ: Writing 0x%16llx to XSCOM %x\n",
		 opb_cmd, mfsi->xscom_base);

	rc = xscom_write(mfsi->chip_id, mfsi->xscom_base + PIB2OPB_REG_CMD, opb_cmd);
	if (rc) {
		mfsi_log(PR_ERR, mfsi, "XSCOM error %lld writing OPB CMD\n", rc);
		return OPB_ERR_XSCOM_ERR;
	}
	return mfsi_opb_poll(mfsi, data);
}

static uint64_t mfsi_opb_write(struct mfsi *mfsi, uint32_t opb_addr, uint32_t data)
{
	uint64_t opb_cmd = OPB_CMD_WRITE | OPB_CMD_32BIT;
	int64_t rc;

	if (opb_addr > 0x00ffffff)
		return OPB_ERR_BAD_OPB_ADDR;

	opb_cmd |= opb_addr;
	opb_cmd <<= 32;
	opb_cmd |= data;

	mfsi_log(PR_INSANE, mfsi, "MFSI_OPB_WRITE: Writing 0x%16llx to XSCOM %x\n",
		 opb_cmd, mfsi->xscom_base);

	rc = xscom_write(mfsi->chip_id, mfsi->xscom_base + PIB2OPB_REG_CMD, opb_cmd);
	if (rc) {
		mfsi_log(PR_ERR, mfsi, "XSCOM error %lld writing OPB CMD\n", rc);
		return OPB_ERR_XSCOM_ERR;
	}
	return mfsi_opb_poll(mfsi, NULL);
}

static struct mfsi *mfsi_get(uint32_t chip_id, uint32_t unit)
{
	struct proc_chip *chip = get_chip(chip_id);
	struct mfsi *mfsi;

	if (!chip || unit > MFSI_hMFSI0)
		return NULL;
	mfsi = &chip->fsi_masters[unit];
	if (mfsi->xscom_base == 0)
		return NULL;
	return mfsi;
}

static int64_t mfsi_reset_pib2opb(struct mfsi *mfsi)
{
	uint64_t stat;
	int64_t rc;

	rc = xscom_write(mfsi->chip_id,
			 mfsi->xscom_base + PIB2OPB_REG_RESET, (1ul << 63));
	if (rc) {
		mfsi_log(PR_ERR, mfsi, "XSCOM error %lld resetting PIB2OPB\n", rc);
		return rc;
	}
	rc = xscom_write(mfsi->chip_id,
			 mfsi->xscom_base + PIB2OPB_REG_STAT, (1ul << 63));
	if (rc) {
		mfsi_log(PR_ERR, mfsi, "XSCOM error %lld resetting status\n", rc);
		return rc;
	}
	rc = xscom_read(mfsi->chip_id,
			mfsi->xscom_base + PIB2OPB_REG_STAT, &stat);
	if (rc) {
		mfsi_log(PR_ERR, mfsi, "XSCOM error %lld reading status\n", rc);
		return rc;
	}
	return 0;
}


static void mfsi_dump_pib2opb_state(struct mfsi *mfsi)
{
	uint64_t val;

	/* Dump a bunch of registers */
	if (xscom_read(mfsi->chip_id, mfsi->xscom_base + PIB2OPB_REG_CMD, &val))
		goto xscom_error;
	mfsi_log(PR_ERR, mfsi, " PIB2OPB CMD   = %016llx\n", val);
	if (xscom_read(mfsi->chip_id, mfsi->xscom_base + PIB2OPB_REG_STAT, &val))
		goto xscom_error;
	mfsi_log(PR_ERR, mfsi, " PIB2OPB STAT  = %016llx\n", val);
	if (xscom_read(mfsi->chip_id, mfsi->xscom_base + PIB2OPB_REG_LSTAT, &val))
		goto xscom_error;
	mfsi_log(PR_ERR, mfsi, " PIB2OPB LSTAT = %016llx\n", val);

	if (mfsi->unit == MFSI_cMFSI0 || mfsi->unit == MFSI_cMFSI1) {
		if (xscom_read(mfsi->chip_id, mfsi->xscom_base + PIB2OPB_REG_cRSIC, &val))
			goto xscom_error;
		mfsi_log(PR_ERR, mfsi, " PIB2OPB cRSIC = %016llx\n", val);
		if (xscom_read(mfsi->chip_id, mfsi->xscom_base + PIB2OPB_REG_cRSIM, &val))
			goto xscom_error;
		mfsi_log(PR_ERR, mfsi, " PIB2OPB cRSIM = %016llx\n", val);
		if (xscom_read(mfsi->chip_id, mfsi->xscom_base + PIB2OPB_REG_cRSIS, &val))
			goto xscom_error;
		mfsi_log(PR_ERR, mfsi, " PIB2OPB cRSIS = %016llx\n", val);
	} else if (mfsi->unit == MFSI_hMFSI0) {
		if (xscom_read(mfsi->chip_id, mfsi->xscom_base + PIB2OPB_REG_hRSIC, &val))
			goto xscom_error;
		mfsi_log(PR_ERR, mfsi, " PIB2OPB hRSIC = %016llx\n", val);
		if (xscom_read(mfsi->chip_id, mfsi->xscom_base + PIB2OPB_REG_hRSIM, &val))
			goto xscom_error;
		mfsi_log(PR_ERR, mfsi, " PIB2OPB hRSIM = %016llx\n", val);
		if (xscom_read(mfsi->chip_id, mfsi->xscom_base + PIB2OPB_REG_hRSIS, &val))
			goto xscom_error;
		mfsi_log(PR_ERR, mfsi, " PIB2OPB hRSIS = %016llx\n", val);
	}
	return;
 xscom_error:
	mfsi_log(PR_ERR, mfsi, "XSCOM error reading PIB2OPB registers\n");
}

static int64_t mfsi_dump_ctrl_regs(struct mfsi *mfsi)
{
	uint64_t opb_stat;
	uint32_t i;

	/* List of registers to dump (from HB) */
	static uint32_t dump_regs[] = {
		MFSI_REG_MATRB0,
		MFSI_REG_MDTRB0,
		MFSI_REG_MESRB0,
		MFSI_REG_MAESP0,
		MFSI_REG_MAEB,
		MFSI_REG_MSCSB0,
	};
	static const char *dump_regs_names[] = {
		"MFSI_REG_MATRB0",
		"MFSI_REG_MDTRB0",
		"MFSI_REG_MESRB0",
		"MFSI_REG_MAESP0",
		"MFSI_REG_MAEB  ",
		"MFSI_REG_MSCSB0",
	};
	for (i = 0; i < ARRAY_SIZE(dump_regs); i++) {
		uint32_t val;

		opb_stat = mfsi_opb_read(mfsi, mfsi->reg_base + dump_regs[i], &val);
		if (opb_stat) {
			/* Error on dump, give up */
			mfsi_log(PR_ERR, mfsi, " OPB stat 0x%016llx dumping reg %x\n",
				 opb_stat, dump_regs[i]);
			return OPAL_HARDWARE;
		}
		mfsi_log(PR_ERR, mfsi, " %s = %08x\n", dump_regs_names[i], val);
	}
	for (i = 0; i < 8; i++) {
		uint32_t val;

		opb_stat = mfsi_opb_read(mfsi, mfsi->reg_base + MFSI_REG_MSTAP(i), &val);
		if (opb_stat) {
			/* Error on dump, give up */
			mfsi_log(PR_ERR, mfsi, " OPB stat 0x%016llx dumping reg %x\n",
				 opb_stat, MFSI_REG_MSTAP(i));
			return OPAL_HARDWARE;
		}
		mfsi_log(PR_ERR, mfsi, " MFSI_REG_MSTAP%d = %08x\n", i, val);
	}
	return OPAL_SUCCESS;
}

static int64_t mfsi_master_cleanup(struct mfsi *mfsi, uint32_t port)
{
	uint64_t opb_stat;
	uint32_t port_base, compmask, truemask;

	/* Reset the bridge to clear up the residual errors */

	/* bit0 = Bridge: General reset */
	opb_stat = mfsi_opb_write(mfsi, mfsi->reg_base + MFSI_REG_MESRB0, 0x80000000u);
	if (opb_stat) {
		mfsi_log(PR_ERR, mfsi, " OPB stat 0x%016llx writing reset to MESRB0\n",
			 opb_stat);
		return OPAL_HARDWARE;
	}

	/* Calculate base address of port */
	port_base = mfsi->ports_base + port * MFSI_OPB_PORT_STRIDE;

	/* Perform error reset on Centaur fsi slave: */
	/*  write 0x4000000 to addr=834 */
	opb_stat = mfsi_opb_write(mfsi, port_base + FSI_SLRES, 0x04000000);
	if (opb_stat) {
		mfsi_log(PR_ERR, mfsi,
			 " OPB stat 0x%016llx writing reset to FSI slave\n",
			 opb_stat);
		return OPAL_HARDWARE;
	}

	/* Further step is to issue a PIB reset to the FSI2PIB engine
	 * in busy state, i.e. write arbitrary data to 101c
	 * (putcfam 1007) register of the previously failed FSI2PIB
	 * engine on Centaur.
	 *
	 * XXX BenH: Should that be done by the upper FSI XSCOM layer ?
	 */
	opb_stat = mfsi_opb_write(mfsi, port_base + FSI2PIB_STATUS, 0xFFFFFFFF);
	if (opb_stat) {
		mfsi_log(PR_ERR, mfsi,
			 " OPB stat 0x%016llx clearing FSI2PIB_STATUS\n",
			 opb_stat);
		return OPAL_HARDWARE;
	}

	/* Need to save/restore the true/comp masks or the FSP (PRD ?) will
	 * get annoyed
	 */
	opb_stat = mfsi_opb_read(mfsi, port_base + FSI2PIB_COMPMASK, &compmask);
	if (opb_stat) {
		mfsi_log(PR_ERR, mfsi,
			 " OPB stat 0x%016llx reading FSI2PIB_COMPMASK\n",
			 opb_stat);
		return OPAL_HARDWARE;
	}
	opb_stat = mfsi_opb_read(mfsi, port_base + FSI2PIB_TRUEMASK, &truemask);
	if (opb_stat) {
		mfsi_log(PR_ERR, mfsi,
			 " OPB stat 0x%016llx reading FSI2PIB_TRUEMASK\n",
			 opb_stat);
		return OPAL_HARDWARE;
	}

	/* Then, write arbitrary data to 1018  (putcfam 1006) to
	 * reset any pending FSI2PIB errors.
	 */
	opb_stat = mfsi_opb_write(mfsi, port_base + FSI2PIB_RESET, 0xFFFFFFFF);
	if (opb_stat) {
		mfsi_log(PR_ERR, mfsi,
			 " OPB stat 0x%016llx writing FSI2PIB_RESET\n",
			 opb_stat);
		return OPAL_HARDWARE;
	}

	/* Restore the true/comp masks */
	opb_stat = mfsi_opb_write(mfsi, port_base + FSI2PIB_COMPMASK, compmask);
	if (opb_stat) {
		mfsi_log(PR_ERR, mfsi,
			 " OPB stat 0x%016llx writing FSI2PIB_COMPMASK\n",
			 opb_stat);
		return OPAL_HARDWARE;
	}
	opb_stat = mfsi_opb_write(mfsi, port_base + FSI2PIB_TRUEMASK, truemask);
	if (opb_stat) {
		mfsi_log(PR_ERR, mfsi,
			 " OPB stat 0x%016llx writing FSI2PIB_TRUEMASK\n",
			 opb_stat);
		return OPAL_HARDWARE;
	}
	return OPAL_SUCCESS;
}

static int64_t mfsi_analyse_fsi_error(struct mfsi *mfsi)
{
	uint64_t opb_stat;
	uint32_t mesrb0;

	/* Most of the code below is adapted from HB. The main difference is
	 * that we don't gard
	 */

	/* Read MESRB0 */
	opb_stat = mfsi_opb_read(mfsi, mfsi->reg_base + MFSI_REG_MESRB0, &mesrb0);
	if (opb_stat) {
		mfsi_log(PR_ERR, mfsi, " OPB stat 0x%016llx reading MESRB0\n", opb_stat);
		return OPAL_HARDWARE;
	}
	mfsi_log(PR_ERR, mfsi, " MESRB0=%08x\n", mesrb0);

	/* bits 8:15 are internal parity errors in the master */
	if (mesrb0 & 0x00FF0000) {
		mfsi_log(PR_ERR, mfsi, " Master parity error !\n");
	} else {
		/* bits 0:3 are a specific error code */
		switch ((mesrb0 & 0xF0000000) >> 28) {
		case 0x1: /* OPB error	*/
		case 0x2: /* Invalid state of OPB state machine */
			/* error is inside the OPB logic */
			mfsi_log(PR_ERR, mfsi, " OPB logic error !\n");
			break;
		case 0x3: /* Port access error */
			/* probably some kind of code collision */
			/* could also be something weird in the chip */
			mfsi_log(PR_ERR, mfsi, " Port access error !\n");
			break;
		case 0x4: /* ID mismatch */
			mfsi_log(PR_ERR, mfsi, " Port ID mismatch !\n");
			break;
		case 0x6: /* port timeout error */
			mfsi_log(PR_ERR, mfsi, " Port timeout !\n");
			break;
		case 0x7: /* master timeout error */
			mfsi_log(PR_ERR, mfsi, " Master timeout !\n");
			break;
		case 0x9: /* Any error response from Slave */
			mfsi_log(PR_ERR, mfsi, " Slave error response !\n");
			break;
		case 0xC: /* bridge parity error */
			mfsi_log(PR_ERR, mfsi, " Bridge parity error !\n");
			break;
		case 0xB: /* protocol error */
			mfsi_log(PR_ERR, mfsi, " Protocol error !\n");
			break;
		case 0x8: /* master CRC error */
			mfsi_log(PR_ERR, mfsi, " Master CRC error !\n");
			break;
		case 0xA: /* Slave CRC error */
			mfsi_log(PR_ERR, mfsi, " Slave CRC error !\n");
			break;
		default:
			mfsi_log(PR_ERR, mfsi, " Unknown error !\n");
			break;
		}
	}
	return OPAL_SUCCESS;
}

static int64_t mfsi_handle_error(struct mfsi *mfsi, uint32_t port,
				 uint64_t opb_stat, uint32_t fsi_addr)
{
	int rc;
	bool found_root_cause = false;

	mfsi_log(PR_ERR, mfsi, "Access error on port %d, stat=%012llx\n",
		 port, opb_stat);

	/* First handle stat codes we synthetized */
	if (opb_stat & OPB_ERR_XSCOM_ERR)
		return OPAL_HARDWARE;
	if (opb_stat & OPB_ERR_BAD_OPB_ADDR)
		return OPAL_PARAMETER;

	/* Dump a bunch of regisers from PIB2OPB and reset it */
	mfsi_dump_pib2opb_state(mfsi);

	/* Reset PIB2OPB */
	mfsi_reset_pib2opb(mfsi);

	/* This one is not supposed to happen but ... */
	if (opb_stat & OPB_ERR_TIMEOUT_ERR)
		return OPAL_HARDWARE;

	/* Dump some FSI control registers */
	rc = mfsi_dump_ctrl_regs(mfsi);

	/* If that failed, reset PIB2OPB again and return */
	if (rc) {
		mfsi_dump_pib2opb_state(mfsi);
		mfsi_reset_pib2opb(mfsi);
		return OPAL_HARDWARE;
	}

	/* Now check for known root causes (from HB) */

	/* First check if it's a ctrl register access error and we got an OPB NACK,
	 * which means an out of bounds control reg
	 */
	if ((opb_stat & OPB_STAT_ERRACK) &&
	    ((fsi_addr & ~0x2ffu) == mfsi->reg_base)) {
		mfsi_log(PR_ERR, mfsi, " Error appears to be out of bounds reg %08x\n",
			 fsi_addr);
		found_root_cause = true;
	}
	/* Else check for other OPB errors */
	else if (opb_stat & OPB_STAT_ERR_OPB) {
		mfsi_log(PR_ERR, mfsi, " Error appears to be an OPB error\n");
		found_root_cause = true;
	}

	/* Root cause not found, dig into FSI logic */
	if (!found_root_cause) {
		rc = mfsi_analyse_fsi_error(mfsi);
		if (!rc) {
			/* If that failed too, reset the PIB2OPB again */
			mfsi_reset_pib2opb(mfsi);
		}
	}

	/* Cleanup MFSI master */
	mfsi_master_cleanup(mfsi, port);

	return OPAL_HARDWARE;
}

int64_t mfsi_read(uint32_t chip, uint32_t unit, uint32_t port,
		  uint32_t fsi_addr, uint32_t *data)
{
	struct mfsi *mfsi = mfsi_get(chip, unit);
	uint32_t port_addr;
	uint64_t opb_stat;
	int64_t rc = OPAL_SUCCESS;

	if (!mfsi || port > 7)
		return OPAL_PARAMETER;

	lock(&fsi_lock);

	/* Calculate port address */
	port_addr = mfsi->ports_base + port * MFSI_OPB_PORT_STRIDE;
	port_addr += fsi_addr;

	/* Perform OPB access */
	opb_stat = mfsi_opb_read(mfsi, port_addr, data);
	if (opb_stat)
		rc = mfsi_handle_error(mfsi, port, opb_stat, port_addr);

	unlock(&fsi_lock);

	return rc;
}

int64_t mfsi_write(uint32_t chip, uint32_t unit, uint32_t port,
		   uint32_t fsi_addr, uint32_t data)
{
	struct mfsi *mfsi = mfsi_get(chip, unit);
	uint32_t port_addr;
	uint64_t opb_stat;
	int64_t rc = OPAL_SUCCESS;

	if (!mfsi || port > 7)
		return OPAL_PARAMETER;

	lock(&fsi_lock);

	/* Calculate port address */
	port_addr = mfsi->ports_base + port * MFSI_OPB_PORT_STRIDE;
	port_addr += fsi_addr;

	/* Perform OPB access */
	opb_stat = mfsi_opb_write(mfsi, port_addr, data);
	if (opb_stat)
		rc = mfsi_handle_error(mfsi, port, opb_stat, port_addr);

	unlock(&fsi_lock);

	return rc;
}

static void mfsi_add(struct proc_chip *chip, struct mfsi *mfsi, uint32_t unit)
{
	mfsi->chip_id = chip->id;
	mfsi->unit = unit;

	/* We hard code everything for now */
	switch (unit) {
	case MFSI_cMFSI0:
		mfsi->xscom_base = PIB2OPB_MFSI0_ADDR;
		mfsi->ports_base = cMFSI_OPB_PORTS_BASE;
		mfsi->reg_base = cMFSI_OPB_REG_BASE;
		mfsi->err_bits = OPB_STAT_ERR_BASE | OPB_STAT_ERR_CMFSI;
		break;
	case MFSI_cMFSI1:
		mfsi->xscom_base = PIB2OPB_MFSI1_ADDR;
		mfsi->ports_base = cMFSI_OPB_PORTS_BASE;
		mfsi->reg_base = cMFSI_OPB_REG_BASE;
		mfsi->err_bits = OPB_STAT_ERR_BASE | OPB_STAT_ERR_CMFSI;
		break;
	case MFSI_hMFSI0:
		mfsi->xscom_base = PIB2OPB_MFSI0_ADDR;
		mfsi->ports_base = hMFSI_OPB_PORTS_BASE;
		mfsi->reg_base = hMFSI_OPB_REG_BASE;
		mfsi->err_bits = OPB_STAT_ERR_BASE | OPB_STAT_ERR_HMFSI;
		break;
	default:
		/* ??? */
		return;
	}

	/* Hardware Bug HW222712 on Murano DD1.0 causes the
	 * any_error bit to be un-clearable so we just
	 * have to ignore it. Additionally, HostBoot applies
	 * this to Venice too, though the comment there claims
	 * this is a Simics workaround.
	 *
	 * The doc says that bit can be safely ignored, so let's
	 * just not bother and always take it out.
	 */

	/* 16: cMFSI any-master-error */
	/* 24: hMFSI any-master-error */
	mfsi->err_bits &= 0xFFFF7F7F;

	mfsi_log(PR_INFO, mfsi, "Initialized\n");
}

void mfsi_init(void)
{
	struct proc_chip *chip;

	for_each_chip(chip) {
		chip->fsi_masters = zalloc(sizeof(struct mfsi) * 3);
		assert(chip->fsi_masters);
		mfsi_add(chip, &chip->fsi_masters[MFSI_cMFSI0], MFSI_cMFSI0);
		mfsi_add(chip, &chip->fsi_masters[MFSI_hMFSI0], MFSI_hMFSI0);
		mfsi_add(chip, &chip->fsi_masters[MFSI_cMFSI1], MFSI_cMFSI1);

	}
}

