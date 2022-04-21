// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Handle ChipTOD chip & configure core and CAPP timebases
 *
 * Copyright 2013-2019 IBM Corp.
 */

#define pr_fmt(fmt)	"CHIPTOD: " fmt

#include <skiboot.h>
#include <xscom.h>
#include <pci.h>
#include <chiptod.h>
#include <chip.h>
#include <io.h>
#include <cpu.h>
#include <timebase.h>
#include <opal-api.h>

/* TOD chip XSCOM addresses */
#define TOD_MASTER_PATH_CTRL		0x00040000 /* Master Path ctrl reg */
#define TOD_PRI_PORT0_CTRL		0x00040001 /* Primary port0 ctrl reg */
#define TOD_PRI_PORT1_CTRL		0x00040002 /* Primary port1 ctrl reg */
#define TOD_SEC_PORT0_CTRL		0x00040003 /* Secondary p0 ctrl reg */
#define TOD_SEC_PORT1_CTRL		0x00040004 /* Secondary p1 ctrl reg */
#define TOD_SLAVE_PATH_CTRL		0x00040005 /* Slave Path ctrl reg */
#define TOD_INTERNAL_PATH_CTRL		0x00040006 /* Internal Path ctrl reg */

/* -- TOD primary/secondary master/slave control register -- */
#define TOD_PSMS_CTRL			0x00040007
#define  TOD_PSMSC_PM_TOD_SELECT	PPC_BIT(1)  /* Primary Master TOD */
#define  TOD_PSMSC_PM_DRAW_SELECT	PPC_BIT(2)  /* Primary Master Drawer */
#define  TOD_PSMSC_SM_TOD_SELECT	PPC_BIT(9)  /* Secondary Master TOD */
#define  TOD_PSMSC_SM_DRAW_SELECT	PPC_BIT(10) /* Secondary Master Draw */

/* -- TOD primary/secondary master/slave status register -- */
#define TOD_STATUS			0x00040008
#define   TOD_ST_TOPOLOGY_SELECT	PPC_BITMASK(0, 2)
#define   TOD_ST_MPATH0_STEP_VALID	PPC_BIT(6)  /* MasterPath0 step valid */
#define   TOD_ST_MPATH1_STEP_VALID	PPC_BIT(7)  /* MasterPath1 step valid */
#define   TOD_ST_SPATH0_STEP_VALID	PPC_BIT(8)  /* SlavePath0 step valid */
#define   TOD_ST_SPATH1_STEP_VALID	PPC_BIT(10) /* SlavePath1 step valid */
/* Primary master/slave path select (0 = PATH_0, 1 = PATH_1) */
#define   TOD_ST_PRI_MPATH_SELECT	PPC_BIT(12) /* Primary MPath Select */
#define   TOD_ST_PRI_SPATH_SELECT	PPC_BIT(15) /* Primary SPath Select */
/* Secondary master/slave path select (0 = PATH_0, 1 = PATH_1) */
#define   TOD_ST_SEC_MPATH_SELECT	PPC_BIT(16) /* Secondary MPath Select */
#define   TOD_ST_SEC_SPATH_SELECT	PPC_BIT(19) /* Secondary SPath Select */
#define   TOD_ST_ACTIVE_MASTER		PPC_BIT(23)
#define   TOD_ST_BACKUP_MASTER		PPC_BIT(24)

/* TOD chip XSCOM addresses */
#define TOD_CHIP_CTRL			0x00040010 /* Chip control register */
#define TOD_TTYPE_0			0x00040011
#define TOD_TTYPE_1			0x00040012 /* PSS switch */
#define TOD_TTYPE_2			0x00040013 /* Enable step checkers */
#define TOD_TTYPE_3			0x00040014 /* Request TOD */
#define TOD_TTYPE_4			0x00040015 /* Send TOD */
#define TOD_TTYPE_5			0x00040016 /* Invalidate TOD */
#define TOD_CHIPTOD_TO_TB		0x00040017
#define TOD_LOAD_TOD_MOD		0x00040018
#define TOD_CHIPTOD_VALUE		0x00040020
#define TOD_CHIPTOD_LOAD_TB		0x00040021
#define TOD_CHIPTOD_FSM			0x00040024

/* -- TOD PIB Master reg -- */
#define TOD_PIB_MASTER			0x00040027
#define   TOD_PIBM_ADDR_CFG_MCAST	PPC_BIT(25)
#define   TOD_PIBM_ADDR_CFG_SLADDR	PPC_BITMASK(26, 31)
#define   TOD_PIBM_TTYPE4_SEND_MODE	PPC_BIT(32)
#define   TOD_PIBM_TTYPE4_SEND_ENBL	PPC_BIT(33)

/* -- TOD Error interrupt register -- */
#define TOD_ERROR			0x00040030
/* SYNC errors */
#define   TOD_ERR_CRMO_PARITY		PPC_BIT(0)
#define   TOD_ERR_OSC0_PARITY		PPC_BIT(1)
#define   TOD_ERR_OSC1_PARITY		PPC_BIT(2)
#define   TOD_ERR_PPORT0_CREG_PARITY	PPC_BIT(3)
#define   TOD_ERR_PPORT1_CREG_PARITY	PPC_BIT(4)
#define   TOD_ERR_SPORT0_CREG_PARITY	PPC_BIT(5)
#define   TOD_ERR_SPORT1_CREG_PARITY	PPC_BIT(6)
#define   TOD_ERR_SPATH_CREG_PARITY	PPC_BIT(7)
#define   TOD_ERR_IPATH_CREG_PARITY	PPC_BIT(8)
#define   TOD_ERR_PSMS_CREG_PARITY	PPC_BIT(9)
#define   TOD_ERR_CRITC_PARITY		PPC_BIT(13)
#define   TOD_ERR_MP0_STEP_CHECK	PPC_BIT(14)
#define   TOD_ERR_MP1_STEP_CHECK	PPC_BIT(15)
#define   TOD_ERR_PSS_HAMMING_DISTANCE	PPC_BIT(18)
#define	  TOD_ERR_DELAY_COMPL_PARITY	PPC_BIT(22)
/* CNTR errors */
#define   TOD_ERR_CTCR_PARITY		PPC_BIT(32)
#define   TOD_ERR_TOD_SYNC_CHECK	PPC_BIT(33)
#define   TOD_ERR_TOD_FSM_PARITY	PPC_BIT(34)
#define   TOD_ERR_TOD_REGISTER_PARITY	PPC_BIT(35)
#define   TOD_ERR_OVERFLOW_YR2042	PPC_BIT(36)
#define   TOD_ERR_TOD_WOF_LSTEP_PARITY	PPC_BIT(37)
#define   TOD_ERR_TTYPE0_RECVD		PPC_BIT(38)
#define   TOD_ERR_TTYPE1_RECVD		PPC_BIT(39)
#define   TOD_ERR_TTYPE2_RECVD		PPC_BIT(40)
#define   TOD_ERR_TTYPE3_RECVD		PPC_BIT(41)
#define   TOD_ERR_TTYPE4_RECVD		PPC_BIT(42)
#define   TOD_ERR_TTYPE5_RECVD		PPC_BIT(43)

/* -- TOD Error interrupt register -- */
#define TOD_ERROR_INJECT		0x00040031

/* PC unit PIB address which recieves the timebase transfer from TOD */
#define   PC_TOD			0x4A3

/* Local FIR EH.TPCHIP.TPC.LOCAL_FIR */
#define LOCAL_CORE_FIR		0x0104000C
#define LFIR_SWITCH_COMPLETE	PPC_BIT(18)

/* Number of iterations for the various timeouts */
#define TIMEOUT_LOOPS		20000000

/* TOD active Primary/secondary configuration */
#define TOD_PRI_CONF_IN_USE	0	/* Tod using primary topology*/
#define TOD_SEC_CONF_IN_USE	7	/* Tod using secondary topo */

/* Timebase State Machine error state */
#define TBST_STATE_ERROR	9

static enum chiptod_type {
	chiptod_unknown,
	chiptod_p8,
	chiptod_p9,
	chiptod_p10,
} chiptod_type;

enum chiptod_chip_role {
	chiptod_chip_role_UNKNOWN = -1,
	chiptod_chip_role_MDMT = 0,	/* Master Drawer Master TOD */
	chiptod_chip_role_MDST,		/* Master Drawer Slave TOD */
	chiptod_chip_role_SDMT,		/* Slave Drawer Master TOD */
	chiptod_chip_role_SDST,		/* Slave Drawer Slave TOD */
};

enum chiptod_chip_status {
	chiptod_active_master = 0,	/* Chip TOD is Active master */
	chiptod_backup_master = 1,	/* Chip TOD is backup master */
	chiptod_backup_disabled,	/* Chip TOD is backup but disabled */
};

struct chiptod_chip_config_info {
	int32_t id;				/* chip id */
	enum chiptod_chip_role role;		/* Chip role */
	enum chiptod_chip_status status;	/* active/backup/disabled */
};

static int32_t chiptod_primary = -1;
static int32_t chiptod_secondary = -1;
static enum chiptod_topology current_topology = chiptod_topo_unknown;

/*
 * chiptod_topology_info holds primary/secondary chip configuration info.
 * This info is initialized during chiptod_init(). This is an array of two:
 *	[0] = [chiptod_topo_primary] = Primary topology config info
 *	[1] = [chiptod_topo_secondary] = Secondary topology config info
 */
static struct chiptod_chip_config_info chiptod_topology_info[2];

/*
 * Array of TOD control registers that holds last known valid values.
 *
 * Cache chiptod control register values at following instances:
 * 1. Chiptod initialization
 * 2. After topology switch is complete.
 * 3. Upon receiving enable/disable topology request from FSP.
 *
 * Cache following chip TOD control registers:
 *   - Master Path control register (0x00040000)
 *   - Primary Port-0 control register (0x00040001)
 *   - Primary Port-1 control register (0x00040002)
 *   - Secondary Port-0 control register (0x00040003)
 *   - Secondary Port-1 control register (0x00040004)
 *   - Slave Path control register (0x00040005)
 *   - Internal Path control register (0x00040006)
 *   - Primary/secondary master/slave control register (0x00040007)
 *   - Chip control register (0x00040010)
 *
 * This data is used for restoring respective TOD registers to sane values
 * whenever parity errors are reported on these registers (through HMI).
 * The error_bit maps to corresponding bit from TOD error register that
 * reports parity error on respective TOD registers.
 */
static struct chiptod_tod_regs {
	/* error bit from TOD Error reg */
	const uint64_t	error_bit;

	/* xscom address of TOD register to be restored. */
	const uint64_t	xscom_addr;
	/* per chip cached value of TOD control registers to be restored. */
	struct {
		uint64_t	data;
		bool		valid;
	} val[MAX_CHIPS];
} chiptod_tod_regs[] = {
	{ TOD_ERR_CRMO_PARITY, TOD_MASTER_PATH_CTRL, { } },
	{ TOD_ERR_PPORT0_CREG_PARITY, TOD_PRI_PORT0_CTRL,  { } },
	{ TOD_ERR_PPORT1_CREG_PARITY, TOD_PRI_PORT1_CTRL, { } },
	{ TOD_ERR_SPORT0_CREG_PARITY, TOD_SEC_PORT0_CTRL, { } },
	{ TOD_ERR_SPORT1_CREG_PARITY, TOD_SEC_PORT1_CTRL, { } },
	{ TOD_ERR_SPATH_CREG_PARITY, TOD_SLAVE_PATH_CTRL, { } },
	{ TOD_ERR_IPATH_CREG_PARITY, TOD_INTERNAL_PATH_CTRL, { } },
	{ TOD_ERR_PSMS_CREG_PARITY, TOD_PSMS_CTRL, { } },
	{ TOD_ERR_CTCR_PARITY, TOD_CHIP_CTRL, { } },
};

/* The base TFMR value is the same for the whole machine
 * for now as far as I can tell
 */
static uint64_t base_tfmr;

/*
 * For now, we use a global lock for runtime chiptod operations,
 * eventually make this a per-core lock for wakeup rsync and
 * take all of them for RAS cases.
 */
static struct lock chiptod_lock = LOCK_UNLOCKED;
static bool chiptod_unrecoverable;

#define NUM_SYNC_RETRIES 10

static void _chiptod_cache_tod_regs(int32_t chip_id)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(chiptod_tod_regs); i++) {
		if (xscom_read(chip_id, chiptod_tod_regs[i].xscom_addr,
			&(chiptod_tod_regs[i].val[chip_id].data))) {
			prerror("XSCOM error reading 0x%08llx reg.\n",
					chiptod_tod_regs[i].xscom_addr);
			/* Invalidate this record and continue */
			chiptod_tod_regs[i].val[chip_id].valid = 0;
			continue;
		}
		chiptod_tod_regs[i].val[chip_id].valid = 1;
	}
}

static void chiptod_cache_tod_registers(void)
{
	struct proc_chip *chip;

	for_each_chip(chip)
		_chiptod_cache_tod_regs(chip->id);
}

static void print_topo_info(enum chiptod_topology topo)
{
	const char *role[] = { "Unknown", "MDMT", "MDST", "SDMT", "SDST" };
	const char *status[] = { "Unknown",
		"Active Master", "Backup Master", "Backup Master Disabled" };

	prlog(PR_DEBUG, "  Chip id: %d, Role: %s, Status: %s\n",
				chiptod_topology_info[topo].id,
				role[chiptod_topology_info[topo].role + 1],
				status[chiptod_topology_info[topo].status + 1]);
}

static void print_topology_info(void)
{
	const char *topo[] = { "Unknown", "Primary", "Secondary" };

	if (current_topology < 0)
		return;

	prlog(PR_DEBUG, "TOD Topology in Use: %s\n",
						topo[current_topology+1]);
	prlog(PR_DEBUG, "  Primary configuration:\n");
	print_topo_info(chiptod_topo_primary);
	prlog(PR_DEBUG, "  Secondary configuration:\n");
	print_topo_info(chiptod_topo_secondary);
}

static enum chiptod_topology query_current_topology(void)
{
	uint64_t tod_status;

	if (xscom_readme(TOD_STATUS, &tod_status)) {
		prerror("XSCOM error reading TOD_STATUS reg\n");
		return chiptod_topo_unknown;
	}

	/*
	 * Tod status register bit [0-2] tells configuration in use.
	 *	000 <= primary configuration in use
	 *	111 <= secondary configuration in use
	 */
	if ((tod_status & TOD_ST_TOPOLOGY_SELECT) == TOD_PRI_CONF_IN_USE)
		return chiptod_topo_primary;
	else
		return chiptod_topo_secondary;
}

static enum chiptod_chip_role
chiptod_get_chip_role(enum chiptod_topology topology, int32_t chip_id)
{
	uint64_t tod_ctrl;
	enum chiptod_chip_role role = chiptod_chip_role_UNKNOWN;

	if (chip_id < 0)
		return role;

	if (xscom_read(chip_id, TOD_PSMS_CTRL, &tod_ctrl)) {
		prerror("XSCOM error reading TOD_PSMS_CTRL\n");
		return chiptod_chip_role_UNKNOWN;
	}

	switch (topology) {
	case chiptod_topo_primary:
		if (tod_ctrl & TOD_PSMSC_PM_DRAW_SELECT) {
			if (tod_ctrl & TOD_PSMSC_PM_TOD_SELECT)
				role = chiptod_chip_role_MDMT;
			else
				role = chiptod_chip_role_MDST;
		} else {
			if (tod_ctrl & TOD_PSMSC_PM_TOD_SELECT)
				role = chiptod_chip_role_SDMT;
			else
				role = chiptod_chip_role_SDST;
		}
		break;
	case chiptod_topo_secondary:
		if (tod_ctrl & TOD_PSMSC_SM_DRAW_SELECT) {
			if (tod_ctrl & TOD_PSMSC_SM_TOD_SELECT)
				role = chiptod_chip_role_MDMT;
			else
				role = chiptod_chip_role_MDST;
		} else {
			if (tod_ctrl & TOD_PSMSC_SM_TOD_SELECT)
				role = chiptod_chip_role_SDMT;
			else
				role = chiptod_chip_role_SDST;
		}
		break;
	case chiptod_topo_unknown:
	default:
		break;
	}
	return role;
}

/*
 * Check and return the status of sync step network for a given
 * topology configuration.
 * Return values:
 *	true:	Sync Step network is running
 *	false:	Sync Step network is not running
 */
static bool chiptod_sync_step_check_running(enum chiptod_topology topology)
{
	uint64_t tod_status;
	enum chiptod_chip_role role;
	bool running = false;
	int32_t chip_id = chiptod_topology_info[topology].id;

	/* Sanity check */
	if (chip_id < 0)
		return false;

	if (xscom_read(chip_id, TOD_STATUS, &tod_status)) {
		prerror("XSCOM error reading TOD_STATUS reg\n");
		return false;
	}

	switch (topology) {
	case chiptod_topo_primary:
		/* Primary configuration */
		role = chiptod_topology_info[topology].role;
		if (role == chiptod_chip_role_MDMT) {
			/*
			 * Chip is using Master path.
			 * Check if it is using path_0/path_1 and then
			 * validity of that path.
			 *
			 * TOD_STATUS[12]: 0 = PATH_0, 1 = PATH_1
			 */
			if (tod_status & TOD_ST_PRI_MPATH_SELECT) {
				if (tod_status & TOD_ST_MPATH1_STEP_VALID)
					running = true;
			} else {
				if (tod_status & TOD_ST_MPATH0_STEP_VALID)
					running = true;
			}
		} else {
			/*
			 * Chip is using Slave path.
			 *
			 * TOD_STATUS[15]: 0 = PATH_0, 1 = PATH_1
			 */
			if (tod_status & TOD_ST_PRI_SPATH_SELECT) {
				if (tod_status & TOD_ST_SPATH1_STEP_VALID)
					running = true;
			} else {
				if (tod_status & TOD_ST_SPATH0_STEP_VALID)
					running = true;
			}
		}
		break;
	case chiptod_topo_secondary:
		/* Secondary configuration */
		role = chiptod_topology_info[topology].role;
		if (role == chiptod_chip_role_MDMT) {
			/*
			 * Chip is using Master path.
			 * Check if it is using path_0/path_1 and then
			 * validity of that path.
			 *
			 * TOD_STATUS[12]: 0 = PATH_0, 1 = PATH_1
			 */
			if (tod_status & TOD_ST_SEC_MPATH_SELECT) {
				if (tod_status & TOD_ST_MPATH1_STEP_VALID)
					running = true;
			} else {
				if (tod_status & TOD_ST_MPATH0_STEP_VALID)
					running = true;
			}
		} else {
			/*
			 * Chip is using Slave path.
			 *
			 * TOD_STATUS[15]: 0 = PATH_0, 1 = PATH_1
			 */
			if (tod_status & TOD_ST_SEC_SPATH_SELECT) {
				if (tod_status & TOD_ST_SPATH1_STEP_VALID)
					running = true;
			} else {
				if (tod_status & TOD_ST_SPATH0_STEP_VALID)
					running = true;
			}
		}
		break;
	default:
		break;
	}
	return running;
}

static enum chiptod_chip_status _chiptod_get_chip_status(int32_t chip_id)
{
	uint64_t tod_status;
	enum chiptod_chip_status status = -1;

	if (chip_id < 0)
		return chiptod_backup_disabled;

	if (xscom_read(chip_id, TOD_STATUS, &tod_status)) {
		prerror("XSCOM error reading TOD_STATUS reg\n");
		return status;
	}

	if (tod_status & TOD_ST_ACTIVE_MASTER)
		status = chiptod_active_master;
	else if (tod_status & TOD_ST_BACKUP_MASTER)
		status = chiptod_backup_master;

	return status;
}

static enum chiptod_chip_status
chiptod_get_chip_status(enum chiptod_topology topology)
{
	return _chiptod_get_chip_status(chiptod_topology_info[topology].id);
}

static void chiptod_update_topology(enum chiptod_topology topo)
{
	int32_t chip_id = chiptod_topology_info[topo].id;

	if (chip_id < 0)
		return;

	chiptod_topology_info[topo].role = chiptod_get_chip_role(topo, chip_id);
	chiptod_topology_info[topo].status = chiptod_get_chip_status(topo);

	/*
	 * If chip TOD on this topology is a backup master then check if
	 * sync/step network is running on this topology. If not,
	 * then mark status as backup not valid.
	 */
	if ((chiptod_topology_info[topo].status == chiptod_backup_master) &&
			!chiptod_sync_step_check_running(topo))
		chiptod_topology_info[topo].status = chiptod_backup_disabled;
}

static void chiptod_setup_base_tfmr(void)
{
	struct dt_node *cpu = this_cpu()->node;
	uint64_t core_freq, tod_freq;
	uint64_t mcbs;

	base_tfmr = SPR_TFMR_TB_ECLIPZ;

	/* Get CPU and TOD freqs in Hz */
	if (dt_has_node_property(cpu, "ibm,extended-clock-frequency", NULL))
		core_freq = dt_prop_get_u64(cpu, "ibm,extended-clock-frequency");
	else
		core_freq = dt_prop_get_u32(cpu, "clock-frequency");

	if (!core_freq) {
		prlog(PR_ERR, "CPU clock frequency is not set\n");
		abort();
	}

	tod_freq = 32000000;

	/* Calculate the "Max Cycles Between Steps" value according
	 * to the magic formula:
	 *
	 * mcbs = (core_freq * max_jitter_factor) / (4 * tod_freq) / 100;
	 *
	 * The max jitter factor is set to 240 based on what pHyp uses.
	 */
	mcbs = (core_freq * 240) / (4 * tod_freq) / 100;
	prlog(PR_INFO, "Calculated MCBS is 0x%llx"
	      " (Cfreq=%lld Tfreq=%lld)\n",
	      mcbs, core_freq, tod_freq);

	/* Bake that all into TFMR */
	base_tfmr = SETFIELD(SPR_TFMR_MAX_CYC_BET_STEPS, base_tfmr, mcbs);
	base_tfmr = SETFIELD(SPR_TFMR_N_CLKS_PER_STEP, base_tfmr, 0);
	base_tfmr = SETFIELD(SPR_TFMR_SYNC_BIT_SEL, base_tfmr, 4);
}

static bool chiptod_mod_tb(void)
{
	uint64_t tfmr = base_tfmr;
	uint64_t timeout = 0;

	/* Switch timebase to "Not Set" state */
	mtspr(SPR_TFMR, tfmr | SPR_TFMR_LOAD_TOD_MOD);
	do {
		if (++timeout >= (TIMEOUT_LOOPS*2)) {
			prerror("TB \"Not Set\" timeout\n");
			return false;
		}
		tfmr = mfspr(SPR_TFMR);
		if (tfmr & SPR_TFMR_TFMR_CORRUPT) {
			prerror("TB \"Not Set\" TFMR corrupt\n");
			return false;
		}
		if (GETFIELD(SPR_TFMR_TBST_ENCODED, tfmr) == 9) {
			prerror("TB \"Not Set\" TOD in error state\n");
			return false;
		}
	} while (tfmr & SPR_TFMR_LOAD_TOD_MOD);

	return true;
}

static bool chiptod_interrupt_check(void)
{
	uint64_t tfmr;
	uint64_t timeout = 0;

	do {
		if (++timeout >= TIMEOUT_LOOPS) {
			prerror("Interrupt check fail\n");
			return false;
		}
		tfmr = mfspr(SPR_TFMR);
		if (tfmr & SPR_TFMR_TFMR_CORRUPT) {
			prerror("Interrupt check TFMR corrupt !\n");
			return false;
		}
	} while (tfmr & SPR_TFMR_CHIP_TOD_INTERRUPT);

	return true;
}

static bool chiptod_running_check(uint32_t chip_id)
{
	uint64_t tval;

	if (xscom_read(chip_id, TOD_CHIPTOD_FSM, &tval)) {
		prerror("XSCOM error polling run\n");
		return false;
	}
	if (tval & 0x0800000000000000UL)
		return true;
	else
		return false;
}

static bool chiptod_poll_running(void)
{
	uint64_t timeout = 0;
	uint64_t tval;

	/* Chip TOD running check */
	do {
		if (++timeout >= TIMEOUT_LOOPS) {
			prerror("Running check fail timeout\n");
			return false;
		}
		if (xscom_readme(TOD_CHIPTOD_FSM, &tval)) {
			prerror("XSCOM error polling run\n");
			return false;
		}
	} while (!(tval & 0x0800000000000000UL));

	return true;
}

static bool chiptod_to_tb(void)
{
	uint32_t pir = this_cpu()->pir;
	uint64_t tval, tfmr;
	uint64_t timeout = 0;

	/* Tell the ChipTOD about our fabric address
	 *
	 * The pib_master value is calculated from the CPU core ID, given in
	 * the PIR. Because we have different core/thread arrangements in the
	 * PIR between p7 and p8, we need to do the calculation differently.
	 *
	 * p7: 0b00001 || 3-bit core id
	 * p8:  0b0001 || 4-bit core id
	 * p9:   0b001 || 5-bit core id
	 * p10:  0b001 || 5-bit core id
	 *
	 * However in P10 we don't use the core ID addressing, but rather core
	 * scom addressing mode, which appears to work better.
	 */

	if (xscom_readme(TOD_PIB_MASTER, &tval)) {
		prerror("XSCOM error reading PIB_MASTER\n");
		return false;
	}

	if (chiptod_type == chiptod_p10) {
		uint32_t core_id = pir_to_core_id(pir);

		if (this_cpu()->is_fused_core &&
				PVR_VERS_MAJ(mfspr(SPR_PVR)) == 2) {
			/* Workaround: must address the even small core. */
			core_id &= ~1;
		}

		tval = XSCOM_ADDR_P10_EC(core_id, PC_TOD);

		tval <<= 32; /* PIB slave address goes in PPC bits [0:31] */

		tval |= PPC_BIT(35); /* Enable SCOM addressing. */

	} else {
		uint64_t tvbits;

		if (chiptod_type == chiptod_p9) {
			tvbits = (pir >> 2) & 0x1f;
			tvbits |= 0x20;
		} else if (chiptod_type == chiptod_p8) {
			tvbits = (pir >> 3) & 0xf;
			tvbits |= 0x10;
		} else {
			tvbits = (pir >> 2) & 0x7;
			tvbits |= 0x08;
		}
		tval &= ~TOD_PIBM_ADDR_CFG_MCAST;
		tval = SETFIELD(TOD_PIBM_ADDR_CFG_SLADDR, tval, tvbits);
	}

	if (xscom_writeme(TOD_PIB_MASTER, tval)) {
		prerror("XSCOM error writing PIB_MASTER\n");
		return false;
	}

	/* Make us ready to get the TB from the chipTOD */
	mtspr(SPR_TFMR, base_tfmr | SPR_TFMR_MOVE_CHIP_TOD_TO_TB);

	/* Tell the ChipTOD to send it */
	if (xscom_writeme(TOD_CHIPTOD_TO_TB, PPC_BIT(0))) {
		prerror("XSCOM error writing CHIPTOD_TO_TB\n");
		return false;
	}

	/* Wait for it to complete */
	timeout = 0;
	do {
		if (++timeout >= TIMEOUT_LOOPS) {
			prerror("Chip to TB timeout\n");
			return false;
		}
		tfmr = mfspr(SPR_TFMR);
		if (tfmr & SPR_TFMR_TFMR_CORRUPT) {
			prerror("MoveToTB: corrupt TFMR !\n");
			return false;
		}
	} while (tfmr & SPR_TFMR_MOVE_CHIP_TOD_TO_TB);

	return true;
}

static bool chiptod_check_tb_running(void)
{
	/* We used to wait for two SYNC pulses in TFMR but that
	 * doesn't seem to occur in sim, so instead we use a
	 * method similar to what pHyp does which is to check for
	 * TFMR SPR_TFMR_TB_VALID and not SPR_TFMR_TFMR_CORRUPT
	 */
#if 0
	uint64_t tfmr, timeout;
	unsigned int i;

	for (i = 0; i < 2; i++) {
		tfmr = mfspr(SPR_TFMR);
		tfmr &= ~SPR_TFMR_TB_SYNC_OCCURED;
		mtspr(SPR_TFMR, tfmr);
		timeout = 0;
		do {
			if (++timeout >= TIMEOUT_LOOPS) {
				prerror("CHIPTOD: No sync pulses\n");
				return false;
			}
			tfmr = mfspr(SPR_TFMR);
		} while (!(tfmr & SPR_TFMR_TB_SYNC_OCCURED));
	}
#else
	uint64_t tfmr = mfspr(SPR_TFMR);

	return (tfmr & SPR_TFMR_TB_VALID) &&
		!(tfmr & SPR_TFMR_TFMR_CORRUPT);
#endif
	return true;
}

static bool chiptod_reset_tb_errors(void)
{
	uint64_t tfmr;
	unsigned long timeout = 0;

	/* Ask for automatic clear of errors */
	tfmr = base_tfmr | SPR_TFMR_CLEAR_TB_ERRORS;

	/* Additionally pHyp sets these (write-1-to-clear ?) */
	tfmr |= SPR_TFMR_TB_MISSING_SYNC;
	tfmr |= SPR_TFMR_TB_MISSING_STEP;
	tfmr |= SPR_TFMR_TB_RESIDUE_ERR;
	mtspr(SPR_TFMR, tfmr);

	/* We have to write "Clear TB Errors" again */
	tfmr = base_tfmr | SPR_TFMR_CLEAR_TB_ERRORS;
	mtspr(SPR_TFMR, tfmr);

	do {
		if (++timeout >= TIMEOUT_LOOPS) {
			/* Don't actually do anything on error for
			 * now ... not much we can do, panic maybe ?
			 */
			prerror("TB error reset timeout !\n");
			return false;
		}
		tfmr = mfspr(SPR_TFMR);
		if (tfmr & SPR_TFMR_TFMR_CORRUPT) {
			prerror("TB error reset: corrupt TFMR !\n");
			return false;
		}
	} while (tfmr & SPR_TFMR_CLEAR_TB_ERRORS);
	return true;
}

static void chiptod_cleanup_thread_tfmr(void)
{
	uint64_t tfmr = base_tfmr;

	tfmr |= SPR_TFMR_PURR_PARITY_ERR;
	tfmr |= SPR_TFMR_SPURR_PARITY_ERR;
	tfmr |= SPR_TFMR_DEC_PARITY_ERR;
	tfmr |= SPR_TFMR_TFMR_CORRUPT;
	tfmr |= SPR_TFMR_PURR_OVERFLOW;
	tfmr |= SPR_TFMR_SPURR_OVERFLOW;
	mtspr(SPR_TFMR, tfmr);
}

static void chiptod_reset_tod_errors(void)
{
	uint64_t terr;

	/*
	 * At boot, we clear the errors that the firmware is
	 * supposed to handle. List provided by the pHyp folks.
	 */

	terr = TOD_ERR_CRITC_PARITY;
	terr |= TOD_ERR_PSS_HAMMING_DISTANCE;
	terr |= TOD_ERR_DELAY_COMPL_PARITY;
	terr |= TOD_ERR_CTCR_PARITY;
	terr |= TOD_ERR_TOD_SYNC_CHECK;
	terr |= TOD_ERR_TOD_FSM_PARITY;
	terr |= TOD_ERR_TOD_REGISTER_PARITY;

	if (xscom_writeme(TOD_ERROR, terr)) {
		prerror("XSCOM error writing TOD_ERROR !\n");
		/* Not much we can do here ... abort ? */
	}
}

static void chiptod_sync_master(void *data)
{
	uint64_t initial_tb_value;
	bool *result = data;

	prlog(PR_DEBUG, "Master sync on CPU PIR 0x%04x...\n",
	      this_cpu()->pir);

	/* Apply base tfmr */
	mtspr(SPR_TFMR, base_tfmr);

	/* From recipe provided by pHyp folks, reset various errors
	 * before attempting the sync
	 */
	chiptod_reset_tb_errors();

	/* Cleanup thread tfmr bits */
	chiptod_cleanup_thread_tfmr();

	/* Reset errors in the chiptod itself */
	chiptod_reset_tod_errors();

	/* Switch timebase to "Not Set" state */
	if (!chiptod_mod_tb())
		goto error;
	prlog(PR_INSANE, "SYNC MASTER Step 2 TFMR=0x%016lx\n", mfspr(SPR_TFMR));

	/* Chip TOD step checkers enable */
	if (xscom_writeme(TOD_TTYPE_2, PPC_BIT(0))) {
		prerror("XSCOM error enabling steppers\n");
		goto error;
	}

	prlog(PR_INSANE, "SYNC MASTER Step 3 TFMR=0x%016lx\n", mfspr(SPR_TFMR));

	/* Chip TOD interrupt check */
	if (!chiptod_interrupt_check())
		goto error;
	prlog(PR_INSANE, "SYNC MASTER Step 4 TFMR=0x%016lx\n", mfspr(SPR_TFMR));

	/* Switch local chiptod to "Not Set" state */
	if (xscom_writeme(TOD_LOAD_TOD_MOD, PPC_BIT(0))) {
		prerror("XSCOM error sending LOAD_TOD_MOD\n");
		goto error;
	}

	/* Switch all remote chiptod to "Not Set" state */
	if (xscom_writeme(TOD_TTYPE_5, PPC_BIT(0))) {
		prerror("XSCOM error sending TTYPE_5\n");
		goto error;
	}

	/*
	 * Load the master's current timebase value into the Chip TOD
	 * network. This is so we have sane timestamps across the whole
	 * IPL process. The Chip TOD documentation says that the loaded
	 * value needs to be one STEP before a SYNC. In other words,
	 * set the low bits to 0x1ff0.
	 */
	initial_tb_value = (mftb() & ~0x1fff) | 0x1ff0;

	/* Chip TOD load initial value */
	if (xscom_writeme(TOD_CHIPTOD_LOAD_TB, initial_tb_value)) {
		prerror("XSCOM error setting init TB\n");
		goto error;
	}

	prlog(PR_INSANE, "SYNC MASTER Step 5 TFMR=0x%016lx\n", mfspr(SPR_TFMR));

	if (!chiptod_poll_running())
		goto error;
	prlog(PR_INSANE, "SYNC MASTER Step 6 TFMR=0x%016lx\n", mfspr(SPR_TFMR));

	/* Move chiptod value to core TB */
	if (!chiptod_to_tb())
		goto error;
	prlog(PR_INSANE, "SYNC MASTER Step 7 TFMR=0x%016lx\n", mfspr(SPR_TFMR));

	/* Send local chip TOD to all chips TOD */
	if (xscom_writeme(TOD_TTYPE_4, PPC_BIT(0))) {
		prerror("XSCOM error sending TTYPE_4\n");
		goto error;
	}

	/* Check if TB is running */
	if (!chiptod_check_tb_running())
		goto error;

	prlog(PR_INSANE, "Master sync completed, TB=%lx\n", mfspr(SPR_TBRL));

	/*
	 * A little delay to make sure the remote chips get up to
	 * speed before we start syncing them.
	 *
	 * We have to do it here because we know our TB is running
	 * while the boot thread TB might not yet.
	 */
	time_wait_ms(1);

	*result = true;
	return;
 error:
	prerror("Master sync failed! TFMR=0x%016lx,  retrying...\n", mfspr(SPR_TFMR));
	*result = false;
}

static void chiptod_sync_slave(void *data)
{
	bool *result = data;
	bool do_sync = false;

	/* Only get primaries, not threads */
	if (!this_cpu()->is_secondary)
		do_sync = true;

	if (chiptod_type == chiptod_p10 && this_cpu()->is_fused_core &&
			PVR_VERS_MAJ(mfspr(SPR_PVR)) == 2) {
		/* P10 DD2 fused core workaround, must sync on small cores */
		if (this_cpu() == this_cpu()->ec_primary)
			do_sync = true;
	}

	if (!do_sync) {
		/* Just cleanup the TFMR */
		chiptod_cleanup_thread_tfmr();
		*result = true;
		return;
	}

	prlog(PR_DEBUG, "Slave sync on CPU PIR 0x%04x...\n",
	      this_cpu()->pir);

	/* Apply base tfmr */
	mtspr(SPR_TFMR, base_tfmr);

	/* From recipe provided by pHyp folks, reset various errors
	 * before attempting the sync
	 */
	chiptod_reset_tb_errors();

	/* Cleanup thread tfmr bits */
	chiptod_cleanup_thread_tfmr();

	/* Switch timebase to "Not Set" state */
	if (!chiptod_mod_tb())
		goto error;
	prlog(PR_INSANE, "SYNC SLAVE Step 2 TFMR=0x%016lx\n", mfspr(SPR_TFMR));

	/* Chip TOD running check */
	if (!chiptod_poll_running())
		goto error;
	prlog(PR_INSANE, "SYNC SLAVE Step 3 TFMR=0x%016lx\n", mfspr(SPR_TFMR));

	/* Chip TOD interrupt check */
	if (!chiptod_interrupt_check())
		goto error;
	prlog(PR_INSANE, "SYNC SLAVE Step 4 TFMR=0x%016lx\n", mfspr(SPR_TFMR));

	/* Move chiptod value to core TB */
	if (!chiptod_to_tb())
		goto error;
	prlog(PR_INSANE, "SYNC SLAVE Step 5 TFMR=0x%016lx\n", mfspr(SPR_TFMR));

	/* Check if TB is running */
	if (!chiptod_check_tb_running())
		goto error;

	prlog(PR_INSANE, "Slave sync completed, TB=%lx\n", mfspr(SPR_TBRL));

	*result = true;
	return;
 error:
	prerror("Slave sync failed ! TFMR=0x%016lx, retrying...\n", mfspr(SPR_TFMR));
	*result = false;
}

bool chiptod_wakeup_resync(void)
{
	if (chiptod_primary < 0)
		return 0;

	lock(&chiptod_lock);

	/* Apply base tfmr */
	mtspr(SPR_TFMR, base_tfmr);

	/* From recipe provided by pHyp folks, reset various errors
	 * before attempting the sync
	 */
	chiptod_reset_tb_errors();

	/* Cleanup thread tfmr bits */
	chiptod_cleanup_thread_tfmr();

	/* Switch timebase to "Not Set" state */
	if (!chiptod_mod_tb())
		goto error;

	/* Move chiptod value to core TB */
	if (!chiptod_to_tb())
		goto error;

	unlock(&chiptod_lock);

	return true;
 error:
	prerror("Resync failed ! TFMR=0x%16lx\n", mfspr(SPR_TFMR));
	unlock(&chiptod_lock);
	return false;
}

/*
 * Fixup for p10 TOD bug workaround.
 *
 * The TOD may fail to start if all clocks in the system are derived from
 * the same reference oscillator.
 *
 * Avoiding this is pretty easy: Whenever we clear/reset the TOD registers,
 * make sure to init bits 26:31 of TOD_SLAVE_PATH_CTRL (0x40005) to 0b111111
 * instead of 0b000000. The value 0 in TOD_S_PATH_CTRL_REG(26:31) must be
 * avoided, and if it does get written it must be followed up by writing a
 * value of all ones to clean up the resulting bad state before the (nonzero)
 * final value can be written.
 */
static void fixup_tod_reg_value(struct chiptod_tod_regs *treg_entry)
{
	int32_t chip_id = this_cpu()->chip_id;

	if (proc_gen != proc_gen_p10)
		return;

	if (treg_entry->xscom_addr == TOD_SLAVE_PATH_CTRL)
		treg_entry->val[chip_id].data |= PPC_BITMASK(26,31);
}

static int __chiptod_recover_tod_errors(void)
{
	uint64_t terr;
	uint64_t treset = 0;
	int i, rc = -1;
	int32_t chip_id = this_cpu()->chip_id;

	/* Read TOD error register */
	if (xscom_readme(TOD_ERROR, &terr)) {
		prerror("XSCOM error reading TOD_ERROR reg\n");
		return 0;
	}
	/* Check for sync check error and recover */
	if ((terr & TOD_ERR_TOD_SYNC_CHECK) ||
		(terr & TOD_ERR_TOD_FSM_PARITY) ||
		(terr & TOD_ERR_CTCR_PARITY) ||
		(terr & TOD_ERR_PSS_HAMMING_DISTANCE) ||
		(terr & TOD_ERR_DELAY_COMPL_PARITY) ||
		(terr & TOD_ERR_TOD_REGISTER_PARITY)) {
		chiptod_reset_tod_errors();
		rc = 1;
	}

	/*
	 * Check for TOD control register parity errors and restore those
	 * registers with last saved valid values.
	 */
	for (i = 0; i < ARRAY_SIZE(chiptod_tod_regs); i++) {
		if (!(terr & chiptod_tod_regs[i].error_bit))
			continue;

		/* Check if we have valid last saved register value. */
		if (!chiptod_tod_regs[i].val[chip_id].valid) {
			prerror("Failed to restore TOD register: %08llx",
					chiptod_tod_regs[i].xscom_addr);
			return 0;
		}

		fixup_tod_reg_value(&chiptod_tod_regs[i]);

		prlog(PR_DEBUG, "Parity error, Restoring TOD register: "
				"%08llx = %016llx\n",
				chiptod_tod_regs[i].xscom_addr,
				chiptod_tod_regs[i].val[chip_id].data);
		if (xscom_writeme(chiptod_tod_regs[i].xscom_addr,
			chiptod_tod_regs[i].val[chip_id].data)) {
			prerror("XSCOM error writing 0x%08llx reg.\n",
					chiptod_tod_regs[i].xscom_addr);
			return 0;
		}
		treset |= chiptod_tod_regs[i].error_bit;
	}

	if (treset && (xscom_writeme(TOD_ERROR, treset))) {
		prerror("XSCOM error writing TOD_ERROR !\n");
		return 0;
	}
	/* We have handled all the TOD errors routed to hypervisor */
	if (treset)
		rc = 1;
	return rc;
}

int chiptod_recover_tod_errors(void)
{
	int rc;

	lock(&chiptod_lock);
	rc = __chiptod_recover_tod_errors();
	unlock(&chiptod_lock);
	return rc;
}

static int32_t chiptod_get_active_master(void)
{
	if (current_topology < 0)
		return -1;

	if (chiptod_topology_info[current_topology].status ==
							chiptod_active_master)
		return chiptod_topology_info[current_topology].id;
	return -1;
}

/* Return true if Active master TOD is running. */
static bool chiptod_master_running(void)
{
	int32_t active_master_chip;

	active_master_chip = chiptod_get_active_master();
	if (active_master_chip != -1) {
		if (chiptod_running_check(active_master_chip))
			return true;
	}
	return false;
}

static bool chiptod_set_ttype4_mode(struct proc_chip *chip, bool enable)
{
	uint64_t tval;

	/* Sanity check */
	if (!chip)
		return false;

	if (xscom_read(chip->id, TOD_PIB_MASTER, &tval)) {
		prerror("XSCOM error reading PIB_MASTER\n");
		return false;
	}

	if (enable) {
		/*
		 * Enable TTYPE4 send mode. This allows TOD to respond to
		 * TTYPE3 request.
		 */
		tval |= TOD_PIBM_TTYPE4_SEND_MODE;
		tval |= TOD_PIBM_TTYPE4_SEND_ENBL;
	} else {
		/* Disable TTYPE4 send mode. */
		tval &= ~TOD_PIBM_TTYPE4_SEND_MODE;
		tval &= ~TOD_PIBM_TTYPE4_SEND_ENBL;
	}

	if (xscom_write(chip->id, TOD_PIB_MASTER, tval)) {
		prerror("XSCOM error writing PIB_MASTER\n");
		return false;
	}
	return true;
}

/* Stop TODs on slave chips in backup topology. */
static void chiptod_stop_slave_tods(void)
{
	struct proc_chip *chip = NULL;
	enum chiptod_topology backup_topo;
	uint64_t terr = 0;

	/* Inject TOD sync check error on salve TODs to stop them. */
	terr |= TOD_ERR_TOD_SYNC_CHECK;

	if (current_topology == chiptod_topo_primary)
		backup_topo = chiptod_topo_secondary;
	else
		backup_topo = chiptod_topo_primary;

	for_each_chip(chip) {
		enum chiptod_chip_role role;

		/* Current chip TOD is already in stooped state */
		if (chip->id == this_cpu()->chip_id)
			continue;

		role = chiptod_get_chip_role(backup_topo, chip->id);

		/* Skip backup master chip TOD. */
		if (role == chiptod_chip_role_MDMT)
			continue;

		if (xscom_write(chip->id, TOD_ERROR_INJECT, terr))
			prerror("XSCOM error writing TOD_ERROR_INJ\n");

		if (chiptod_running_check(chip->id)) {
			prlog(PR_DEBUG,
			"Failed to stop TOD on slave CHIP [%d]\n",
								chip->id);
		}
	}
}

static bool is_topology_switch_required(void)
{
	int32_t active_master_chip;
	uint64_t tod_error;

	active_master_chip = chiptod_get_active_master();

	/* Check if TOD is running on Active master. */
	if (chiptod_master_running())
		return false;

	/*
	 * Check if sync/step network is running.
	 *
	 * If sync/step network is not running on current active topology
	 * then we need switch topology to recover from TOD error.
	 */
	if (!chiptod_sync_step_check_running(current_topology)) {
		prlog(PR_DEBUG, "Sync/Step network not running\n");
		return true;
	}

	/*
	 * Check if there is a step check error reported on
	 * Active master.
	 */
	if (xscom_read(active_master_chip, TOD_ERROR, &tod_error)) {
		prerror("XSCOM error reading TOD_ERROR reg\n");
		/*
		 * Can't do anything here. But we already found that
		 * sync/step network is running. Hence return false.
		 */
		return false;
	}

	if (tod_error & TOD_ERR_MP0_STEP_CHECK) {
		prlog(PR_DEBUG, "TOD step check error\n");
		return true;
	}

	return false;
}

static bool chiptod_backup_valid(void)
{
	enum chiptod_topology backup_topo;

	if (current_topology < 0)
		return false;

	if (current_topology == chiptod_topo_primary)
		backup_topo = chiptod_topo_secondary;
	else
		backup_topo = chiptod_topo_primary;

	if (chiptod_topology_info[backup_topo].status == chiptod_backup_master)
		return chiptod_sync_step_check_running(backup_topo);

	return false;
}

static void chiptod_topology_switch_complete(void)
{
	/*
	 * After the topology switch, we may have a non-functional backup
	 * topology, and we won't be able to recover from future TOD errors
	 * that requires topology switch. Someone needs to either fix it OR
	 * configure new functional backup topology.
	 *
	 * Bit 18 of the Pervasive FIR is used to signal that TOD error
	 * analysis needs to be performed. This allows FSP/PRD to
	 * investigate and re-configure new backup topology if required.
	 * Once new backup topology is configured and ready, FSP sends a
	 * mailbox command xE6, s/c 0x06, mod 0, to enable the backup
	 * topology.
	 *
	 * This isn't documented anywhere. This info is provided by FSP
	 * folks.
	 */
	if (xscom_writeme(LOCAL_CORE_FIR, LFIR_SWITCH_COMPLETE)) {
		prerror("XSCOM error writing LOCAL_CORE_FIR\n");
		return;
	}

	/* Save TOD control registers values. */
	chiptod_cache_tod_registers();

	prlog(PR_DEBUG, "Topology switch complete\n");
	print_topology_info();
}

/*
 * Sync up TOD with other chips and get TOD in running state.
 * Check if current topology is active and running. If not, then
 * trigger a topology switch.
 */
static int chiptod_start_tod(void)
{
	struct proc_chip *chip = NULL;

	/*  Do a topology switch if required. */
	if (is_topology_switch_required()) {
		int32_t mchip = chiptod_get_active_master();

		prlog(PR_DEBUG, "Need topology switch to recover\n");
		/*
		 * There is a failure in StepSync network in current
		 * active topology. TOD is not running on active master chip.
		 * We need to sync with backup master chip TOD.
		 * But before we do that we need to switch topology to make
		 * backup master as the new active master. Once we switch the
		 * topology we can then request TOD value from new active
		 * master. But make sure we move local chiptod to Not Set
		 * before requesting TOD value.
		 *
		 * Before triggering a topology switch, check if backup
		 * is valid and stop all slave TODs in backup topology.
		 */
		if (!chiptod_backup_valid()) {
			prerror("Backup master is not enabled. "
				"Can not do a topology switch.\n");
			goto error_out;
		}

		chiptod_stop_slave_tods();

		if (xscom_write(mchip, TOD_TTYPE_1, PPC_BIT(0))) {
			prerror("XSCOM error switching primary/secondary\n");
			goto error_out;
		}

		/* Update topology info. */
		current_topology = query_current_topology();
		chiptod_update_topology(chiptod_topo_primary);
		chiptod_update_topology(chiptod_topo_secondary);

		/*
		 * We just switched topologies to recover.
		 * Check if new master TOD is running.
		 */
		if (!chiptod_master_running()) {
			prerror("TOD is not running on new master.\n");
			goto error_out;
		}

		/*
		 * Enable step checkers on all Chip TODs
		 *
		 * During topology switch, step checkers are disabled
		 * on all Chip TODs by default. Enable them.
		 */
		if (xscom_writeme(TOD_TTYPE_2, PPC_BIT(0))) {
			prerror("XSCOM error enabling steppers\n");
			goto error_out;
		}

		chiptod_topology_switch_complete();
	}

	if (!chiptod_master_running()) {
		/*
		 * Active Master TOD is not running, which means it won't
		 * respond to TTYPE_3 request.
		 *
		 * Find a chip that has TOD in running state and configure
		 * it to respond to TTYPE_3 request.
		 */
		for_each_chip(chip) {
			if (chiptod_running_check(chip->id)) {
				if (chiptod_set_ttype4_mode(chip, true))
					break;
			}
		}
	}

	/* Switch local chiptod to "Not Set" state */
	if (xscom_writeme(TOD_LOAD_TOD_MOD, PPC_BIT(0))) {
		prerror("XSCOM error sending LOAD_TOD_MOD\n");
		goto error_out;
	}

	/*
	 * Request the current TOD value from another chip.
	 * This will move TOD in running state
	 */
	if (xscom_writeme(TOD_TTYPE_3, PPC_BIT(0))) {
		prerror("XSCOM error sending TTYPE_3\n");
		goto error_out;
	}

	/* Check if chip TOD is running. */
	if (!chiptod_poll_running())
		goto error_out;

	/* Restore the ttype4_mode. */
	chiptod_set_ttype4_mode(chip, false);
	return 1;

error_out:
	chiptod_unrecoverable = true;
	return 0;
}

static bool tfmr_recover_tb_errors(uint64_t tfmr)
{
	uint64_t tfmr_reset_error;
	unsigned long timeout = 0;

	/* Ask for automatic clear of errors */
	tfmr_reset_error = base_tfmr | SPR_TFMR_CLEAR_TB_ERRORS;

	/* Additionally pHyp sets these (write-1-to-clear ?) */
	if (tfmr & SPR_TFMR_TB_MISSING_SYNC)
		tfmr_reset_error |= SPR_TFMR_TB_MISSING_SYNC;

	if (tfmr & SPR_TFMR_TB_MISSING_STEP)
		tfmr_reset_error |= SPR_TFMR_TB_MISSING_STEP;

	/*
	 * write 1 to bit 45 to clear TB residue the error.
	 * TB register has already been reset to zero as part pre-recovery.
	 */
	if (tfmr & SPR_TFMR_TB_RESIDUE_ERR)
		tfmr_reset_error |= SPR_TFMR_TB_RESIDUE_ERR;

	if (tfmr & SPR_TFMR_FW_CONTROL_ERR)
		tfmr_reset_error |= SPR_TFMR_FW_CONTROL_ERR;

	if (tfmr & SPR_TFMR_TBST_CORRUPT)
		tfmr_reset_error |= SPR_TFMR_TBST_CORRUPT;

	mtspr(SPR_TFMR, tfmr_reset_error);

	/* We have to write "Clear TB Errors" again */
	tfmr_reset_error = base_tfmr | SPR_TFMR_CLEAR_TB_ERRORS;
	mtspr(SPR_TFMR, tfmr_reset_error);

	do {
		if (++timeout >= TIMEOUT_LOOPS) {
			prerror("TB error reset timeout !\n");
			return false;
		}
		tfmr = mfspr(SPR_TFMR);
		if (tfmr & SPR_TFMR_TFMR_CORRUPT) {
			prerror("TB error reset: corrupt TFMR !\n");
			return false;
		}
	} while (tfmr & SPR_TFMR_CLEAR_TB_ERRORS);
	return true;
}

bool tfmr_recover_local_errors(uint64_t tfmr)
{
	uint64_t tfmr_reset_errors = 0;

	if (tfmr & SPR_TFMR_DEC_PARITY_ERR) {
		/* Set DEC with all ones */
		mtspr(SPR_DEC, ~0);

		/* set bit 59 to clear TFMR DEC parity error. */
		tfmr_reset_errors |= SPR_TFMR_DEC_PARITY_ERR;
	}

	/*
	* Reset PURR/SPURR to recover. We also need help from KVM
	* layer to handle this change in PURR/SPURR. That needs
	* to be handled in kernel KVM layer. For now, to recover just
	* reset it.
	*/
	if (tfmr & SPR_TFMR_PURR_PARITY_ERR) {
		/* set PURR register with sane value or reset it. */
		mtspr(SPR_PURR, 0);

		/* set bit 57 to clear TFMR PURR parity error. */
		tfmr_reset_errors |= SPR_TFMR_PURR_PARITY_ERR;
	}

	if (tfmr & SPR_TFMR_SPURR_PARITY_ERR) {
		/* set PURR register with sane value or reset it. */
		mtspr(SPR_SPURR, 0);

		/* set bit 58 to clear TFMR PURR parity error. */
		tfmr_reset_errors |= SPR_TFMR_SPURR_PARITY_ERR;
	}

	/* Write TFMR twice to clear the error */
	mtspr(SPR_TFMR, base_tfmr | tfmr_reset_errors);
	mtspr(SPR_TFMR, base_tfmr | tfmr_reset_errors);

	/* Get fresh copy of TFMR */
	tfmr = mfspr(SPR_TFMR);

	/* Check if TFMR non-TB errors still present. */
	if (tfmr & tfmr_reset_errors) {
		prerror("TFMR non-TB error recovery failed! "
			"TFMR=0x%016lx\n", mfspr(SPR_TFMR));
		return false;
	}
	return true;
}

/*
 * TFMR parity error recovery as per pc_workbook:
 *	MT(TFMR) bits 11 and 60 are b’1’
 *	MT(HMER) all bits 1 except for bits 4,5
 */
bool recover_corrupt_tfmr(void)
{
	uint64_t tfmr;

	/* Get the base TFMR */
	tfmr = base_tfmr;

	/* Set bit 60 to clear TFMR parity error. */
	tfmr |= SPR_TFMR_TFMR_CORRUPT;
	mtspr(SPR_TFMR, tfmr);

	/* Write twice to clear the error */
	mtspr(SPR_TFMR, tfmr);

	/* Get fresh copy of TFMR */
	tfmr = mfspr(SPR_TFMR);

	/* Check if TFMR parity error still present. */
	if (tfmr & SPR_TFMR_TFMR_CORRUPT) {
		prerror("TFMR error recovery: corrupt TFMR !\n");
		return false;
	}

	/*
	 * Now that we have sane value in TFMR, check if Timebase machine
	 * state is in ERROR state. If yes, clear TB errors so that
	 * Timebase machine state changes to RESET state. Once in RESET state
	 * then we can then load TB with TOD value.
	 */
	if (GETFIELD(SPR_TFMR_TBST_ENCODED, tfmr) == TBST_STATE_ERROR) {
		if (!chiptod_reset_tb_errors())
			return false;
	}
	return true;
}

void tfmr_cleanup_core_errors(uint64_t tfmr)
{
	/* If HDEC is bad, clean it on all threads before we clear the
	 * error condition.
	 */
	if (tfmr & SPR_TFMR_HDEC_PARITY_ERROR)
		mtspr(SPR_HDEC, 0);

	/* If TB is invalid, clean it on all threads as well, it will be
	 * restored after the next rendez-vous
	 */
	if (!(tfmr & SPR_TFMR_TB_VALID)) {
		mtspr(SPR_TBWU, 0);
		mtspr(SPR_TBWU, 0);
	}
}

int tfmr_clear_core_errors(uint64_t tfmr)
{
	uint64_t tfmr_reset_errors = 0;

	/* return -1 if there is nothing to be fixed. */
	if (!(tfmr & SPR_TFMR_HDEC_PARITY_ERROR))
		return -1;

	tfmr_reset_errors |= SPR_TFMR_HDEC_PARITY_ERROR;

	/* Write TFMR twice to clear the error */
	mtspr(SPR_TFMR, base_tfmr | tfmr_reset_errors);
	mtspr(SPR_TFMR, base_tfmr | tfmr_reset_errors);

	return 1;
}

/*
 * Recover from TB and TOD errors.
 * Timebase register is per core and first thread that gets chance to
 * handle interrupt would fix actual TFAC errors and rest of the threads
 * from same core would see no errors. Return -1 if no errors have been
 * found. The caller (handle_hmi_exception) of this function would not
 * send an HMI event to host if return value is -1.
 *
 * Return values:
 *	0	<= Failed to recover from errors
 *	1	<= Successfully recovered from errors
 *	-1	<= No errors found. Errors are already been fixed.
 */
int chiptod_recover_tb_errors(bool *out_resynced)
{
	uint64_t tfmr;
	int rc = -1;

	*out_resynced = false;

	if (chiptod_primary < 0)
		return 0;

	lock(&chiptod_lock);

	/*
	 * Return if TOD is unrecoverable.
	 * The previous attempt to recover TOD has been failed.
	 */
	if (chiptod_unrecoverable) {
		rc = 0;
		goto error_out;
	}

	/* Get fresh copy of TFMR */
	tfmr = mfspr(SPR_TFMR);

	/*
	 * Check for TB errors.
	 * On Sync check error, bit 44 of TFMR is set. Check for it and
	 * clear it.
	 *
	 * In some rare situations we may have all TB errors already cleared,
	 * but TB stuck in waiting for new value from TOD with TFMR bit 18
	 * set to '1'. This uncertain state of TB would fail the process
	 * of getting TB back into running state. Get TB in clean initial
	 * state by clearing TB errors if TFMR[18] is set.
	 */
	if ((tfmr & SPR_TFMR_TB_MISSING_STEP) ||
		(tfmr & SPR_TFMR_TB_RESIDUE_ERR) ||
		(tfmr & SPR_TFMR_FW_CONTROL_ERR) ||
		(tfmr & SPR_TFMR_TBST_CORRUPT) ||
		(tfmr & SPR_TFMR_MOVE_CHIP_TOD_TO_TB) ||
		(tfmr & SPR_TFMR_TB_MISSING_SYNC)) {
		if (!tfmr_recover_tb_errors(tfmr)) {
			rc = 0;
			goto error_out;
		}
	}

	/*
	 * Check for TOD sync check error.
	 * On TOD errors, bit 51 of TFMR is set. If this bit is on then we
	 * need to fetch TOD error register and recover from TOD errors.
	 * Bit 33 of TOD error register indicates sync check error.
	 */
	if (tfmr & SPR_TFMR_CHIP_TOD_INTERRUPT)
		rc = __chiptod_recover_tod_errors();

	/* Check if TB is running. If not then we need to get it running. */
	if (!(tfmr & SPR_TFMR_TB_VALID)) {
		rc = 0;

		/* Place TB in Notset state. */
		if (!chiptod_mod_tb())
			goto error_out;

		/*
		 * Before we move TOD to core TB check if TOD is running.
		 * If not, then get TOD in running state.
		 */
		if (!chiptod_running_check(this_cpu()->chip_id))
			if (!chiptod_start_tod())
				goto error_out;

		/* Move chiptod value to core TB */
		if (!chiptod_to_tb())
			goto error_out;

		*out_resynced = true;

		/* We have successfully able to get TB running. */
		rc = 1;
	}

error_out:
	unlock(&chiptod_lock);
	return rc;
}

static int64_t opal_resync_timebase(void)
{
	/* Mambo and qemu doesn't simulate the chiptod */
	if (chip_quirk(QUIRK_NO_CHIPTOD))
		return OPAL_SUCCESS;

	if (!chiptod_wakeup_resync()) {
		prerror("OPAL: Resync timebase failed on CPU 0x%04x\n",
			this_cpu()->pir);
		return OPAL_HARDWARE;
	}
	return OPAL_SUCCESS;
}
opal_call(OPAL_RESYNC_TIMEBASE, opal_resync_timebase, 0);

static void chiptod_print_tb(void *data __unused)
{
	prlog(PR_DEBUG, "PIR 0x%04x TB=%lx\n", this_cpu()->pir,
				mfspr(SPR_TBRL));
}

static bool chiptod_probe(void)
{
	struct dt_node *np;

	dt_for_each_compatible(dt_root, np, "ibm,power-chiptod") {
		uint32_t chip;

		/* Old DT has chip-id in chiptod node, newer only in the
		 * parent xscom bridge
		 */
		chip = dt_get_chip_id(np);

		if (dt_has_node_property(np, "primary", NULL)) {
			chiptod_primary = chip;
			if (dt_node_is_compatible(np, "ibm,power8-chiptod"))
				chiptod_type = chiptod_p8;
			if (dt_node_is_compatible(np, "ibm,power9-chiptod"))
				chiptod_type = chiptod_p9;
			if (dt_node_is_compatible(np, "ibm,power10-chiptod"))
				chiptod_type = chiptod_p10;
		}

		if (dt_has_node_property(np, "secondary", NULL))
			chiptod_secondary = chip;

	}

	if (chiptod_type == chiptod_unknown) {
		prerror("Unknown TOD type !\n");
		return false;
	}

	return true;
}

static void chiptod_discover_new_backup(enum chiptod_topology topo)
{
	struct proc_chip *chip = NULL;

	/* Scan through available chips to find new backup master chip */
	for_each_chip(chip) {
		if (_chiptod_get_chip_status(chip->id) == chiptod_backup_master)
			break;
	}

	/* Found new backup master chip. Update the topology info */
	if (chip) {
		prlog(PR_DEBUG, "New backup master: CHIP [%d]\n",
								chip->id);

		if (topo == chiptod_topo_primary)
			chiptod_primary = chip->id;
		else
			chiptod_secondary = chip->id;
		chiptod_topology_info[topo].id = chip->id;
		chiptod_update_topology(topo);

		prlog(PR_DEBUG,
			"Backup topology configuration changed.\n");
		print_topology_info();
	}

	/*
	 * Topology configuration has changed. Save TOD control registers
	 * values.
	 */
	chiptod_cache_tod_registers();
}

/*
 * Enable/disable backup topology.
 * If request is to enable topology, then discover new backup master
 * chip and update the topology configuration info. If the request is
 * to disable topology, then mark the current backup topology as disabled.
 * Return error (-1) if the action is requested on currenlty active
 * topology.
 *
 * Return values:
 *	true	<= Success
 *	false	<= Topology is active and in use.
 */
bool chiptod_adjust_topology(enum chiptod_topology topo, bool enable)
{
	uint8_t rc = true;
	/*
	 * The FSP can only request that the currently inactive topology
	 * be disabled or enabled. If the requested topology is currently
	 * the active topology, then fail this request with a -1 (TOD
	 * topology in use) status as return code.
	 */
	lock(&chiptod_lock);
	if (topo == current_topology) {
		rc = false;
		goto out;
	}

	if (enable)
		chiptod_discover_new_backup(topo);
	else
		chiptod_topology_info[topo].status = chiptod_backup_disabled;
out:
	unlock(&chiptod_lock);
	return rc;
}

static void chiptod_init_topology_info(void)
{
	/* Find and update current topology in use. */
	current_topology = query_current_topology();

	/* Initialized primary topology chip config info */
	chiptod_topology_info[chiptod_topo_primary].id = chiptod_primary;
	chiptod_update_topology(chiptod_topo_primary);

	/* Initialized secondary topology chip config info */
	chiptod_topology_info[chiptod_topo_secondary].id = chiptod_secondary;
	chiptod_update_topology(chiptod_topo_secondary);

	/* Cache TOD control registers values. */
	chiptod_cache_tod_registers();
	print_topology_info();
}

void chiptod_init(void)
{
	struct cpu_thread *cpu0, *cpu;
	bool sres;
	int i;

	/* Mambo and qemu doesn't simulate the chiptod */
	if (chip_quirk(QUIRK_NO_CHIPTOD))
		return;

	op_display(OP_LOG, OP_MOD_CHIPTOD, 0);

	if (!chiptod_probe()) {
		prerror("Failed ChipTOD detection !\n");
		op_display(OP_FATAL, OP_MOD_CHIPTOD, 0);
		abort();
	}

	op_display(OP_LOG, OP_MOD_CHIPTOD, 1);

	/* Pick somebody on the primary */
	cpu0 = find_cpu_by_chip_id(chiptod_primary);

	/* Calculate the base TFMR value used for everybody */
	chiptod_setup_base_tfmr();

	prlog(PR_DEBUG, "Base TFMR=0x%016llx\n", base_tfmr);

	i = NUM_SYNC_RETRIES;
	do {
		/* Schedule master sync */
		sres = false;
		cpu_wait_job(cpu_queue_job(cpu0, "chiptod_sync_master",
				   chiptod_sync_master, &sres), true);
	} while (!sres && i--);

	if (!sres) {
		op_display(OP_FATAL, OP_MOD_CHIPTOD, 2);
		abort();
	}

	op_display(OP_LOG, OP_MOD_CHIPTOD, 2);

	/* Schedule slave sync */
	for_each_available_cpu(cpu) {
		/* Skip master */
		if (cpu == cpu0)
			continue;

		i = NUM_SYNC_RETRIES;
		do {
			/* Queue job */
			sres = false;
			cpu_wait_job(cpu_queue_job(cpu, "chiptod_sync_slave",
						   chiptod_sync_slave, &sres),
				     true);
		} while (!sres && i--);

		if (!sres) {
			op_display(OP_WARN, OP_MOD_CHIPTOD, 3|(cpu->pir << 8));
			prerror("CHIPTOD: Failed to sync PIR 0x%04x\n",
					this_cpu()->pir);

			/* Disable threads */
			cpu_disable_all_threads(cpu);
		}
		op_display(OP_LOG, OP_MOD_CHIPTOD, 3|(cpu->pir << 8));
	}

	/* Display TBs */
	for_each_available_cpu(cpu) {
		/* Only do primaries, not threads */
		if (cpu->is_secondary)
			continue;
		cpu_wait_job(cpu_queue_job(cpu, "chiptod_print_tb",
					   chiptod_print_tb, NULL), true);
	}

	chiptod_init_topology_info();
	op_display(OP_LOG, OP_MOD_CHIPTOD, 4);
}

/* CAPP timebase sync */

static bool chiptod_capp_reset_tb_errors(uint32_t chip_id,
					 uint32_t tfmr_addr,
					 uint32_t offset)
{
	uint64_t tfmr;
	unsigned long timeout = 0;

	/* Ask for automatic clear of errors */
	tfmr = base_tfmr | SPR_TFMR_CLEAR_TB_ERRORS;

	/* Additionally pHyp sets these (write-1-to-clear ?) */
	tfmr |= SPR_TFMR_TB_MISSING_SYNC;
	tfmr |= SPR_TFMR_TB_MISSING_STEP;
	tfmr |= SPR_TFMR_TB_RESIDUE_ERR;
	tfmr |= SPR_TFMR_TBST_CORRUPT;
	tfmr |= SPR_TFMR_TFMR_CORRUPT;

	/* Write CAPP TFMR */
	xscom_write(chip_id, tfmr_addr + offset, tfmr);

	/* We have to write "Clear TB Errors" again */
	tfmr = base_tfmr | SPR_TFMR_CLEAR_TB_ERRORS;
	/* Write CAPP TFMR */
	xscom_write(chip_id, tfmr_addr + offset, tfmr);

	do {
		if (++timeout >= TIMEOUT_LOOPS) {
			prerror("CAPP: TB error reset timeout !\n");
			return false;
		}
		/* Read CAPP TFMR */
		xscom_read(chip_id, tfmr_addr + offset, &tfmr);
		if (tfmr & SPR_TFMR_TFMR_CORRUPT) {
			prerror("CAPP: TB error reset: corrupt TFMR!\n");
			return false;
		}
	} while (tfmr & SPR_TFMR_CLEAR_TB_ERRORS);
	return true;
}

static bool chiptod_capp_mod_tb(uint32_t chip_id, uint32_t tfmr_addr,
				uint32_t offset)
{
	uint64_t timeout = 0;
	uint64_t tfmr;

	/* Switch CAPP timebase to "Not Set" state */
	tfmr = base_tfmr | SPR_TFMR_LOAD_TOD_MOD;
	xscom_write(chip_id, tfmr_addr + offset, tfmr);
	do {
		if (++timeout >= (TIMEOUT_LOOPS*2)) {
			prerror("CAPP: TB \"Not Set\" timeout\n");
			return false;
		}
		xscom_read(chip_id, tfmr_addr + offset, &tfmr);
		if (tfmr & SPR_TFMR_TFMR_CORRUPT) {
			prerror("CAPP: TB \"Not Set\" TFMR corrupt\n");
			return false;
		}
		if (GETFIELD(SPR_TFMR_TBST_ENCODED, tfmr) == 9) {
			prerror("CAPP: TB \"Not Set\" TOD in error state\n");
			return false;
		}
	} while (tfmr & SPR_TFMR_LOAD_TOD_MOD);

	return true;
}

static bool chiptod_wait_for_chip_sync(void)
{
	uint64_t tfmr;
	uint64_t timeout = 0;

	/* Read core TFMR, mask bit 42, write core TFMR back */
	tfmr = mfspr(SPR_TFMR);
	tfmr &= ~SPR_TFMR_TB_SYNC_OCCURED;
	mtspr(SPR_TFMR, tfmr);

	/* Read core TFMR until the TB sync occurred */
	do {
		if (++timeout >= TIMEOUT_LOOPS) {
			prerror("No sync pulses\n");
			return false;
		}
		tfmr = mfspr(SPR_TFMR);
	} while (!(tfmr & SPR_TFMR_TB_SYNC_OCCURED));
	return true;
}

static bool chiptod_capp_check_tb_running(uint32_t chip_id,
					  uint32_t tfmr_addr,
					  uint32_t offset)
{
	uint64_t tfmr;
	uint64_t timeout = 0;

	/* Read CAPP TFMR until TB becomes valid */
	do {
		if (++timeout >= (TIMEOUT_LOOPS*2)) {
			prerror("CAPP: TB Invalid!\n");
			return false;
		}
		xscom_read(chip_id, tfmr_addr + offset, &tfmr);
		if (tfmr & SPR_TFMR_TFMR_CORRUPT) {
			prerror("CAPP: TFMR corrupt!\n");
			return false;
		}
	} while (!(tfmr & SPR_TFMR_TB_VALID));
	return true;
}

bool chiptod_capp_timebase_sync(unsigned int chip_id, uint32_t tfmr_addr,
				uint32_t tb_addr, uint32_t offset)
{
	uint64_t tfmr;
	uint64_t capp_tb;
	int64_t delta;
	unsigned int retry = 0;

	/* Set CAPP TFMR to base tfmr value */
	xscom_write(chip_id, tfmr_addr + offset, base_tfmr);

	/* Reset CAPP TB errors before attempting the sync */
	if (!chiptod_capp_reset_tb_errors(chip_id, tfmr_addr, offset))
		return false;

	/* Switch CAPP TB to "Not Set" state */
	if (!chiptod_capp_mod_tb(chip_id, tfmr_addr, offset))
		return false;

	/* Sync CAPP TB with core TB, retry while difference > 16usecs */
	do {
		if (retry++ > 5) {
			prerror("CAPP: TB sync: giving up!\n");
			return false;
		}

		/* Make CAPP ready to get the TB, wait for chip sync */
		tfmr = base_tfmr | SPR_TFMR_MOVE_CHIP_TOD_TO_TB;
		xscom_write(chip_id, tfmr_addr + offset, tfmr);
		if (!chiptod_wait_for_chip_sync())
			return false;

		/* Set CAPP TB from core TB */
		xscom_write(chip_id, tb_addr + offset, mftb());

		/* Wait for CAPP TFMR tb_valid bit */
		if (!chiptod_capp_check_tb_running(chip_id, tfmr_addr, offset))
			return false;

		/* Read CAPP TB, read core TB, compare */
		xscom_read(chip_id, tb_addr + offset, &capp_tb);
		delta = mftb() - capp_tb;
		if (delta < 0)
			delta = -delta;
	} while (tb_to_usecs(delta) > 16);

	return true;
}
