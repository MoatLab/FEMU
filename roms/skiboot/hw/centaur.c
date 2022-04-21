// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Centaur memory buffer chip
 *
 * Copyright 2013-2017 IBM Corp.
 */

#include <skiboot.h>
#include <xscom.h>
#include <processor.h>
#include <device.h>
#include <chip.h>
#include <centaur.h>
#include <lock.h>
#include <fsi-master.h>
#include <timebase.h>

/*
 * Centaur chip IDs are using the XSCOM "partID" encoding
 * described in xscom.h. recap:
 *
 *     0b1000.0000.0000.0000.0000.00NN.NCCC.MMMM
 *     N=Node, C=Chip, M=Memory Channel
 *
 * We currently use FSI exclusively for centaur access. We can
 * start using MMIO on Centaur DD2.x when we have a way to handle
 * machine checks happening inside Sapphire which we don't at the
 * moment.
 */

/* Is that correct ? */
#define MAX_CENTAURS_PER_CHIP	8

/* Mark the centaur offline after this many consecutive errors */
#define CENTAUR_ERR_OFFLINE_THRESHOLD	10

/*
 * FSI2PIB register definitions (this could be moved out if we were to
 * support FSI master to other chips.
 */
#define FSI_DATA0_REG		0x1000
#define FSI_DATA1_REG		0x1004
#define FSI_CMD_REG		0x1008
#define   FSI_CMD_WR		0x80000000
#define   FSI_CMD_RD		0x00000000
#define FSI_ENG_RESET_REG	0x1018
#define FSI_STATUS_REG		0x101c
#define   FSI_STATUS_ABORT	0x00100000
#define   FSI_STATUS_ERRORS	0x00007000

/* Some Centaur XSCOMs we care about */
#define SCAC_CONFIG_REG		0x020115ce
#define SCAC_CONFIG_SET		0x020115cf
#define SCAC_CONFIG_CLR		0x020115d0
#define SCAC_ENABLE_MSK		PPC_BIT(0)

#define cent_log(__lev, __c, __fmt, ...)				\
	prlog(__lev, "CENTAUR %x: " __fmt, __c->part_id, ##__VA_ARGS__)

static int64_t centaur_fsiscom_complete(struct centaur_chip *centaur)
{
	int64_t rc;
	uint32_t stat;

	rc = mfsi_read(centaur->fsi_master_chip_id, centaur->fsi_master_engine,
		       centaur->fsi_master_port, FSI_STATUS_REG, &stat);
	if (rc) {
		cent_log(PR_ERR, centaur, "MFSI read error %lld reading STAT\n", rc);
		return rc;
	}
	if ((stat & (FSI_STATUS_ABORT | FSI_STATUS_ERRORS)) == 0)
		return OPAL_SUCCESS;

	cent_log(PR_ERR, centaur, "Remote FSI SCOM error, status=0x%08x\n", stat);

	/* All 1's ? Assume it's gone */
	if (stat == 0xffffffffu) {
		cent_log(PR_ERR, centaur, "Chip appears to be dead !\n");
		centaur->valid = false;

		/* Here, hostboot grabs a pile of FFDC from the FSI layer,
		 * we could do that too ...
		 */
		return OPAL_HARDWARE;
	}

	/* Here HB prints the GPx registers which I believe are only
	 * in the host (FSI master). We skip that for now, we don't have
	 * a good API to them
	 */

	/* Recovery sequence from HostBoot fsiscom.C
	 *  if SCOM fails and FSI Master displays "MasterTimeOut"
	 *     then 7,6  <covered by FSI driver>
	 *  else if SCOM fails and FSI2PIB Status shows PIB abort
	 *     then just perform unit reset (6) and wait 1 ms
	 *  else (PIB_abort='0' but PIB error is unequal 0)
	 *     then just perform unit reset (6) (wait not needed).
	 *
	 * Note: Waiting 1ms inside OPAL is a BIG NO NO !!! We have
	 * no choice but doing it at the moment but that will have
	 * to be fixed one way or another, possibly by returning some
	 * kind of busy status until the delay is expired.
	 */
	rc = mfsi_write(centaur->fsi_master_chip_id, centaur->fsi_master_engine,
			centaur->fsi_master_port, FSI_ENG_RESET_REG, 0);
	if (rc) {
		cent_log(PR_ERR, centaur, "MFSI write error %lld resetting SCOM engine\n",
			 rc);
	}
	return OPAL_HARDWARE;
}

static int64_t centaur_fsiscom_read(struct centaur_chip *centaur, uint32_t pcb_addr,
				    uint64_t *val)
{
	int64_t rc;
	uint32_t data0, data1;

	rc = mfsi_write(centaur->fsi_master_chip_id, centaur->fsi_master_engine,
			centaur->fsi_master_port, FSI_CMD_REG, pcb_addr | FSI_CMD_RD);
	if (rc) {
		cent_log(PR_ERR, centaur, "MFSI write error %lld writing CMD\n", rc);
		return rc;
	}

	rc = centaur_fsiscom_complete(centaur);
	if (rc)
		return rc;

	rc = mfsi_read(centaur->fsi_master_chip_id, centaur->fsi_master_engine,
		       centaur->fsi_master_port, FSI_DATA0_REG, &data0);
	if (rc) {
		cent_log(PR_ERR, centaur, "MFSI read error %lld reading DATA0\n", rc);
		return rc;
	}
	rc = mfsi_read(centaur->fsi_master_chip_id, centaur->fsi_master_engine,
		       centaur->fsi_master_port, FSI_DATA1_REG, &data1);
	if (rc) {
		cent_log(PR_ERR, centaur, "MFSI read error %lld readking DATA1\n", rc);
		return rc;
	}

	*val = (((uint64_t)data0) << 32) | data1;

	return OPAL_SUCCESS;
}

static int64_t centaur_fsiscom_write(struct centaur_chip *centaur, uint32_t pcb_addr,
				     uint64_t val)
{
	int64_t rc;

	rc = mfsi_write(centaur->fsi_master_chip_id, centaur->fsi_master_engine,
			centaur->fsi_master_port, FSI_DATA0_REG, hi32(val));
	if (rc) {
		cent_log(PR_ERR, centaur, "MFSI write error %lld writing DATA0\n", rc);
		return rc;
	}
	rc = mfsi_write(centaur->fsi_master_chip_id, centaur->fsi_master_engine,
			centaur->fsi_master_port, FSI_DATA1_REG, lo32(val));
	if (rc) {
		cent_log(PR_ERR, centaur, "MFSI write error %lld writing DATA1\n", rc);
		return rc;
	}
	rc = mfsi_write(centaur->fsi_master_chip_id, centaur->fsi_master_engine,
			centaur->fsi_master_port, FSI_CMD_REG, pcb_addr | FSI_CMD_WR);
	if (rc) {
		cent_log(PR_ERR, centaur, "MFSI write error %lld writing CMD\n", rc);
		return rc;
	}

	return centaur_fsiscom_complete(centaur);
}

struct centaur_chip *get_centaur(uint32_t part_id)
{
	uint32_t hchip_id, mchan;
	struct proc_chip *hchip;
	struct centaur_chip *centaur;

	if ((part_id >> 28) != 8) {
		prerror("CENTAUR: Invalid part ID 0x%x\n", part_id);
		return NULL;
	}
	hchip_id = (part_id & 0x0fffffff) >> 4;
	mchan = part_id & 0xf;

	hchip = get_chip(hchip_id);
	if (!hchip) {
		prerror("CENTAUR: Centaur 0x%x not found on non-existing chip 0%x\n",
			part_id, hchip_id);
		return NULL;
	}
	if (mchan >= MAX_CENTAURS_PER_CHIP) {
		prerror("CENTAUR: Centaur 0x%x channel out of bounds !\n", part_id);
		return NULL;
	}
	if (!hchip->centaurs) {
		prerror("CENTAUR: Centaur 0x%x not found on chip 0%x (no centaurs)\n",
			part_id, hchip_id);
		return NULL;
	}
	centaur = &hchip->centaurs[mchan];
	if (!centaur->valid) {
		prerror("CENTAUR: Centaur 0x%x not valid on chip 0%x\n",
			part_id, hchip_id);
		return NULL;
	}
	return centaur;
}

/*
 * Indirect XSCOM access functions. Copied from xscom.c, at a
 * latter date, we should merge these properly.
 */
static void centaur_xscom_handle_ind_error(struct centaur_chip *centaur,
					   uint64_t data, uint64_t pcb_addr,
					   bool is_write)
{
	unsigned int stat = GETFIELD(XSCOM_DATA_IND_ERR, data);
	bool timeout = !(data & XSCOM_DATA_IND_COMPLETE);

	/* XXX: Create error log entry ? */
	if (timeout)
		cent_log(PR_ERR, centaur,
			 "inddirect %s timeout, pcb_addr=0x%llx stat=0x%x\n",
			is_write ? "write" : "read", pcb_addr, stat);
	else
		cent_log(PR_ERR, centaur,
			 "indirect %s error, pcb_addr=0x%llx stat=0x%x\n",
			is_write ? "write" : "read", pcb_addr, stat);
}

static int centaur_xscom_ind_read(struct centaur_chip *centaur,
				  uint64_t pcb_addr, uint64_t *val)
{
	uint32_t addr;
	uint64_t data;
	int rc, retries;

	/* Write indirect address */
	addr = pcb_addr & 0x7fffffff;
	data = XSCOM_DATA_IND_READ |
		(pcb_addr & XSCOM_ADDR_IND_ADDR);
	rc = centaur_fsiscom_write(centaur, addr, data);
	if (rc)
		goto bail;

	/* Wait for completion */
	for (retries = 0; retries < XSCOM_IND_MAX_RETRIES; retries++) {
		rc = centaur_fsiscom_read(centaur, addr, &data);
		if (rc)
			goto bail;
		if ((data & XSCOM_DATA_IND_COMPLETE) &&
		    ((data & XSCOM_DATA_IND_ERR) == 0)) {
			*val = data & XSCOM_DATA_IND_DATA;
			break;
		}
		if ((data & XSCOM_DATA_IND_COMPLETE) ||
		    (retries >= XSCOM_IND_MAX_RETRIES)) {
			centaur_xscom_handle_ind_error(centaur, data, pcb_addr,
						       false);
			rc = OPAL_HARDWARE;
			goto bail;
		}
	}
 bail:
	if (rc)
		*val = (uint64_t)-1;
	return rc;
}

static int centaur_xscom_ind_write(struct centaur_chip *centaur,
				   uint64_t pcb_addr, uint64_t val)
{
	uint32_t addr;
	uint64_t data;
	int rc, retries;

	/* Write indirect address & data */
	addr = pcb_addr & 0x7fffffff;
	data = pcb_addr & XSCOM_ADDR_IND_ADDR;
	data |= val & XSCOM_ADDR_IND_DATA;

	rc = centaur_fsiscom_write(centaur, addr, data);
	if (rc)
		goto bail;

	/* Wait for completion */
	for (retries = 0; retries < XSCOM_IND_MAX_RETRIES; retries++) {
		rc = centaur_fsiscom_read(centaur, addr, &data);
		if (rc)
			goto bail;
		if ((data & XSCOM_DATA_IND_COMPLETE) &&
		    ((data & XSCOM_DATA_IND_ERR) == 0))
			break;
		if ((data & XSCOM_DATA_IND_COMPLETE) ||
		    (retries >= XSCOM_IND_MAX_RETRIES)) {
			centaur_xscom_handle_ind_error(centaur, data, pcb_addr,
						       true);
			rc = OPAL_HARDWARE;
			goto bail;
		}
	}
 bail:
	return rc;
}

static int64_t centaur_xscom_read(struct scom_controller *scom,
				  uint32_t id __unused, uint64_t pcb_addr,
				  uint64_t *val)
{
	struct centaur_chip *centaur = scom->private;
	int64_t rc;

	if (!centaur)
		return OPAL_PARAMETER;
	if (!centaur->online)
		return OPAL_XSCOM_CTR_OFFLINED;

	lock(&centaur->lock);
	if (pcb_addr & XSCOM_ADDR_IND_FLAG)
		rc = centaur_xscom_ind_read(centaur, pcb_addr, val);
	else
		rc = centaur_fsiscom_read(centaur, pcb_addr, val);

	/* We mark the centaur offline if we get too many errors on
	 * consecutive accesses
	 */
	if (rc) {
		centaur->error_count++;
		if (centaur->error_count > CENTAUR_ERR_OFFLINE_THRESHOLD) {
			centaur->online = false;
			/**
			 * @fwts-label CentaurOfflinedTooManyErrors
			 * @fwts-advice OPAL marked a Centaur (memory buffer)
			 * as offline due to CENTAUR_ERR_OFFLINE_THRESHOLD (10)
			 * consecutive errors on XSCOMs to this centaur.
			 * OPAL will now return OPAL_XSCOM_CTR_OFFLINED and not
			 * try any further XSCOMs. This is likely caused by
			 * some hardware issue or PRD recovery issue.
			 */
			prlog(PR_ERR, "CENTAUR: Offlined %x due to > %d consecutive XSCOM errors. No more XSCOMs to this centaur.\n",
			      id, CENTAUR_ERR_OFFLINE_THRESHOLD);
		}
	} else
		centaur->error_count = 0;
	unlock(&centaur->lock);

	return rc;
}

static int64_t centaur_xscom_write(struct scom_controller *scom,
				   uint32_t id __unused, uint64_t pcb_addr,
				   uint64_t val)
{
	struct centaur_chip *centaur = scom->private;
	int64_t rc;

	if (!centaur)
		return OPAL_PARAMETER;
	if (!centaur->online)
		return OPAL_XSCOM_CTR_OFFLINED;

	lock(&centaur->lock);
	if (pcb_addr & XSCOM_ADDR_IND_FLAG)
		rc = centaur_xscom_ind_write(centaur, pcb_addr, val);
	else
		rc = centaur_fsiscom_write(centaur, pcb_addr, val);

	/* We mark the centaur offline if we get too many errors on
	 * consecutive accesses
	 */
	if (rc) {
		centaur->error_count++;
		if (centaur->error_count > CENTAUR_ERR_OFFLINE_THRESHOLD)
			centaur->online = false;
	} else
		centaur->error_count = 0;
	unlock(&centaur->lock);

	return rc;
}

static bool centaur_check_id(struct centaur_chip *centaur)
{
	int64_t rc;
	uint64_t val;

	rc = centaur_fsiscom_read(centaur, 0xf000f, &val);
	if (rc) {
		cent_log(PR_ERR, centaur,
			 "   FSISCOM error %lld reading ID register\n",
			 rc);
		return false;
	}

	/* Extract CFAM id */
	val >>= 44;

	/* Identify chip */
	if ((val & 0xff) != 0xe9) {
		cent_log(PR_ERR, centaur,
			 "   CFAM ID 0x%02x is not a Centaur !\n",
			(unsigned int)(val & 0xff));
		return false;
	}

	/* Get EC level from CFAM ID */
	centaur->ec_level = ((val >> 16) & 0xf) << 4;
	centaur->ec_level |= (val >> 8) & 0xf;

	return true;
}

static bool centaur_add(uint32_t part_id, uint32_t mchip, uint32_t meng,
			uint32_t mport)
{
	uint32_t hchip_id, mchan;
	struct proc_chip *hchip;
	struct centaur_chip *centaur;

	if ((part_id >> 28) != 8) {
		prerror("CENTAUR: Invalid part ID 0x%x\n", part_id);
		return false;
	}
	hchip_id = (part_id & 0x0fffffff) >> 4;
	mchan = part_id & 0xf;

	printf("CENTAUR: Found centaur for chip 0x%x channel %d\n",
	       hchip_id, mchan);
	printf("CENTAUR:   FSI host: 0x%x cMFSI%d port %d\n",
	       mchip, meng, mport);

	hchip = get_chip(hchip_id);
	if (!hchip) {
		prerror("CENTAUR:   No such chip !!!\n");
		return false;
	}

	if (mchan >= MAX_CENTAURS_PER_CHIP) {
		prerror("CENTAUR:   Channel out of bounds !\n");
		return false;
	}

	if (!hchip->centaurs) {
		hchip->centaurs =
			zalloc(sizeof(struct centaur_chip) *
			       MAX_CENTAURS_PER_CHIP);
		assert(hchip->centaurs);
	}

	centaur = &hchip->centaurs[mchan];
	if (centaur->valid) {
		prerror("CENTAUR:   Duplicate centaur !\n");
		return false;
	}
	centaur->part_id = part_id;
	centaur->fsi_master_chip_id = mchip;
	centaur->fsi_master_port = mport;
	centaur->fsi_master_engine = meng ? MFSI_cMFSI1 : MFSI_cMFSI0;
	centaur->online = true;
	init_lock(&centaur->lock);
	list_head_init(&centaur->i2cms);

	if (!centaur_check_id(centaur))
		return false;

	centaur->scom.part_id = part_id;
	centaur->scom.private = centaur;
	centaur->scom.read = centaur_xscom_read;
	centaur->scom.write = centaur_xscom_write;
	scom_register(&centaur->scom);

	cent_log(PR_INFO, centaur, "Found DD%x.%x chip\n",
		       centaur->ec_level >> 4,
		       centaur->ec_level & 0xf);

	centaur->valid = true;
	return true;
}

/* Returns how long to wait for logic to stop in TB ticks or a negative
 * value on error
 */
int64_t centaur_disable_sensor_cache(uint32_t part_id)
{
	struct centaur_chip *centaur = get_centaur(part_id);
	int64_t rc = 0;
	uint64_t ctrl;

	if (!centaur)
		return false;

	lock(&centaur->lock);
	centaur->scache_disable_count++;
	if (centaur->scache_disable_count == 1) {
		centaur->scache_was_enabled = false;
		rc = centaur_fsiscom_read(centaur, SCAC_CONFIG_REG, &ctrl);
		if (rc)
			goto bail;
		centaur->scache_was_enabled = !!(ctrl & SCAC_ENABLE_MSK);
		rc = centaur_fsiscom_write(centaur, SCAC_CONFIG_CLR, SCAC_ENABLE_MSK);
		if (rc)
			goto bail;
		rc = msecs_to_tb(30);
	}
 bail:
	unlock(&centaur->lock);
	return rc;
}

int64_t centaur_enable_sensor_cache(uint32_t part_id)
{
	struct centaur_chip *centaur = get_centaur(part_id);
	int64_t rc = 0;

	if (!centaur)
		return false;

	lock(&centaur->lock);
	if (centaur->scache_disable_count == 0) {
		cent_log(PR_ERR, centaur, "Cache count going negative !\n");
		backtrace();
		goto bail;
	}
	centaur->scache_disable_count--;
	if (centaur->scache_disable_count == 0 && centaur->scache_was_enabled)
		rc = centaur_fsiscom_write(centaur, SCAC_CONFIG_SET, SCAC_ENABLE_MSK);
 bail:
	unlock(&centaur->lock);
	return rc;
}

void centaur_init(void)
{
	struct dt_node *cn;

	dt_for_each_compatible(dt_root, cn, "ibm,centaur") {
		uint32_t chip_id, mchip, meng, mport;

		chip_id = dt_prop_get_u32(cn, "ibm,chip-id");
		mchip = dt_prop_get_u32(cn, "ibm,fsi-master-chip-id");
		meng = dt_prop_get_cell(cn, "ibm,fsi-master-port", 0);
		mport = dt_prop_get_cell(cn, "ibm,fsi-master-port", 1);

		/*
		 * If adding the centaur succeeds, we expose it to
		 * Linux as a scom-controller
		 */
		if (centaur_add(chip_id, mchip, meng, mport))
			dt_add_property(cn, "scom-controller", NULL, 0);
	}
}
