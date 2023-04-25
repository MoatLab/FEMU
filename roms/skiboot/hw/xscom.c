// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * XSCOM driver
 *
 * Copyright 2013-2019 IBM Corp.
 */

#include <skiboot.h>
#include <xscom.h>
#include <io.h>
#include <processor.h>
#include <device.h>
#include <chip.h>
#include <centaur.h>
#include <errorlog.h>
#include <opal-api.h>
#include <timebase.h>
#include <nvram.h>

/* Mask of bits to clear in HMER before an access */
#define HMER_CLR_MASK	(~(SPR_HMER_XSCOM_FAIL | \
			   SPR_HMER_XSCOM_DONE | \
			   SPR_HMER_XSCOM_STATUS))

DEFINE_LOG_ENTRY(OPAL_RC_XSCOM_RW, OPAL_PLATFORM_ERR_EVT, OPAL_XSCOM,
		OPAL_CEC_HARDWARE, OPAL_PREDICTIVE_ERR_GENERAL,
		OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_XSCOM_INDIRECT_RW, OPAL_PLATFORM_ERR_EVT, OPAL_XSCOM,
		OPAL_CEC_HARDWARE, OPAL_PREDICTIVE_ERR_GENERAL,
		OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_XSCOM_RESET, OPAL_PLATFORM_ERR_EVT, OPAL_XSCOM,
		OPAL_CEC_HARDWARE, OPAL_PREDICTIVE_ERR_GENERAL,
		OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_XSCOM_BUSY, OPAL_PLATFORM_ERR_EVT, OPAL_XSCOM,
		OPAL_CEC_HARDWARE, OPAL_PREDICTIVE_ERR_GENERAL,
		OPAL_NA);

/* xscom details to trigger xstop */
static struct {
	uint64_t addr;
	uint64_t fir_bit;
} xstop_xscom;

/*
 * Locking notes:
 *
 * We used to have a per-target lock. However due to errata HW822317
 * we can have issues on the issuer side if multiple threads try to
 * send XSCOMs simultaneously (HMER responses get mixed up), so just
 * use a global lock instead
 */
static struct lock xscom_lock = LOCK_UNLOCKED;

static inline void *xscom_addr(uint32_t gcid, uint32_t pcb_addr)
{
	struct proc_chip *chip = get_chip(gcid);
	uint64_t addr;

	assert(chip);
	addr  = chip->xscom_base;
	if (proc_gen == proc_gen_p8) {
		addr |= ((uint64_t)pcb_addr << 4) & ~0xfful;
		addr |= (pcb_addr << 3) & 0x78;
	} else
		addr |= ((uint64_t)pcb_addr << 3);
	return (void *)addr;
}

static uint64_t xscom_wait_done(void)
{
	uint64_t hmer;

	do
		hmer = mfspr(SPR_HMER);
	while(!(hmer & SPR_HMER_XSCOM_DONE));

	/*
	 * HW822317: We need to read a second time as the actual
	 * status can be delayed by 1 cycle after DONE
	 */
	return mfspr(SPR_HMER);
}

static void xscom_reset(uint32_t gcid, bool need_delay)
{
	u64 hmer;
	uint32_t recv_status_reg, log_reg, err_reg;
	struct timespec ts;

	/* Clear errors in HMER */
	mtspr(SPR_HMER, HMER_CLR_MASK);

	/* Setup local and target scom addresses */
	if (proc_gen == proc_gen_p10) {
		recv_status_reg = 0x00090018;
		log_reg = 0x0090012;
		err_reg = 0x0090013;
	} else if (proc_gen == proc_gen_p9) {
		recv_status_reg = 0x00090018;
		log_reg = 0x0090012;
		err_reg = 0x0090013;
	} else {
		recv_status_reg = 0x202000f;
		log_reg = 0x2020007;
		err_reg = 0x2020009;
	}

	/* First we need to write 0 to a register on our chip */
	out_be64(xscom_addr(this_cpu()->chip_id, recv_status_reg), 0);
	hmer = xscom_wait_done();
	if (hmer & SPR_HMER_XSCOM_FAIL)
		goto fail;

	/* Then we need to clear those two other registers on the target */
	out_be64(xscom_addr(gcid, log_reg), 0);
	hmer = xscom_wait_done();
	if (hmer & SPR_HMER_XSCOM_FAIL)
		goto fail;
	out_be64(xscom_addr(gcid, err_reg), 0);
	hmer = xscom_wait_done();
	if (hmer & SPR_HMER_XSCOM_FAIL)
		goto fail;

	if (need_delay) {
		/*
		 * Its observed that sometimes immediate retry of
		 * XSCOM operation returns wrong data. Adding a
		 * delay for XSCOM reset to be effective. Delay of
		 * 10 ms is found to be working fine experimentally.
		 * FIXME: Replace 10ms delay by exact delay needed
		 * or other alternate method to confirm XSCOM reset
		 * completion, after checking from HW folks.
		 */
		ts.tv_sec = 0;
		ts.tv_nsec = 10 * 1000;
		nanosleep_nopoll(&ts, NULL);
	}
	return;
 fail:
	/* Fatal error resetting XSCOM */
	log_simple_error(&e_info(OPAL_RC_XSCOM_RESET),
		"XSCOM: Fatal error resetting engine after failed access !\n");

	/* XXX Generate error log ? attn ? panic ?
	 * If we decide to panic, change the above severity to PANIC
	 */
}

static int xscom_clear_error(uint32_t gcid, uint32_t pcb_addr)
{
	u64 hmer;
	uint32_t base_xscom_addr;
	uint32_t xscom_clear_reg = 0x20010800;

	/* only in case of p9 */
	if (proc_gen != proc_gen_p9)
		return 0;

/* xscom clear address range/mask */
#define XSCOM_CLEAR_RANGE_START		0x20010A00
#define XSCOM_CLEAR_RANGE_END		0x20010ABF
#define XSCOM_CLEAR_RANGE_MASK		0x200FFBFF

	/*
	 * Due to a hardware issue where core responding to scom was delayed
	 * due to thread reconfiguration, leaves the scom logic in a state
	 * where the subsequent scom to that core can get errors. This is
	 * affected for Core PC scom registers in the range of
	 * 20010A80-20010ABF.
	 *
	 * The solution is if a xscom timeout occurs to one of Core PC scom
	 * registers in the range of 20010A80-20010ABF, a clearing scom
	 * write is done to 0x20010800 with data of '0x00000000' which will
	 * also get a timeout but clears the scom logic errors. After the
	 * clearing write is done the original scom operation can be retried.
	 *
	 * The scom timeout is reported as status 0x4 (Invalid address)
	 * in HMER[21-23].
	 */

	base_xscom_addr = pcb_addr & XSCOM_CLEAR_RANGE_MASK;
	if (!((base_xscom_addr >= XSCOM_CLEAR_RANGE_START) &&
				(base_xscom_addr <= XSCOM_CLEAR_RANGE_END)))
		return 0;

	/*
	 * Reset the XSCOM or next scom operation will fail.
	 * We also need a small delay before we go ahead with clearing write.
	 * We have observed that without a delay the clearing write has reported
	 * a wrong status.
	 */
	xscom_reset(gcid, true);

	/* Clear errors in HMER */
	mtspr(SPR_HMER, HMER_CLR_MASK);

	/* Write 0 to clear the xscom logic errors on target chip */
	out_be64(xscom_addr(gcid, xscom_clear_reg), 0);
	hmer = xscom_wait_done();

	/*
	 * Above clearing xscom write will timeout and error out with
	 * invalid access as there is no register at that address. This
	 * xscom operation just helps to clear the xscom logic error.
	 *
	 * On failure, reset the XSCOM or we'll hang on the next access
	 */
	if (hmer & SPR_HMER_XSCOM_FAIL)
		xscom_reset(gcid, true);

	return 1;
}

static int64_t xscom_handle_error(uint64_t hmer, uint32_t gcid, uint32_t pcb_addr,
			      bool is_write, int64_t retries,
			      int64_t *xscom_clear_retries)
{
	unsigned int stat = GETFIELD(SPR_HMER_XSCOM_STATUS, hmer);
	int64_t rc = OPAL_HARDWARE;

	/* XXX Figure out error codes from doc and error
	 * recovery procedures
	 */
	switch(stat) {
	case 1:
		/*
		 * XSCOM engine is blocked, need to retry. Reset XSCOM
		 * engine after crossing retry threshold before
		 * retrying again.
		 */
		if (retries && !(retries  % XSCOM_BUSY_RESET_THRESHOLD)) {
			prlog(PR_NOTICE, "XSCOM: Busy even after %d retries, "
				"resetting XSCOM now. Total retries  = %lld\n",
				XSCOM_BUSY_RESET_THRESHOLD, retries);
			xscom_reset(gcid, true);

		}

		/* Log error if we have retried enough and its still busy */
		if (retries == XSCOM_BUSY_MAX_RETRIES)
			log_simple_error(&e_info(OPAL_RC_XSCOM_BUSY),
				"XSCOM: %s-busy error gcid=0x%x pcb_addr=0x%x "
				"stat=0x%x\n", is_write ? "write" : "read",
				gcid, pcb_addr, stat);
		return OPAL_XSCOM_BUSY;

	case 2: /* CPU is asleep, reset XSCOM engine and return */
		xscom_reset(gcid, false);
		return OPAL_XSCOM_CHIPLET_OFF;
	case 3: /* Partial good */
		rc = OPAL_XSCOM_PARTIAL_GOOD;
		break;
	case 4: /* Invalid address / address error */
		rc = OPAL_XSCOM_ADDR_ERROR;
		if (xscom_clear_error(gcid, pcb_addr)) {
			/* return busy if retries still pending. */
			if ((*xscom_clear_retries)--)
				return OPAL_XSCOM_BUSY;

			prlog(PR_DEBUG, "XSCOM: error recovery failed for "
				"gcid=0x%x pcb_addr=0x%x\n", gcid, pcb_addr);

		}
		break;
	case 5: /* Clock error */
		rc = OPAL_XSCOM_CLOCK_ERROR;
		break;
	case 6: /* Parity error  */
		rc = OPAL_XSCOM_PARITY_ERROR;
		break;
	case 7: /* Time out */
		rc = OPAL_XSCOM_TIMEOUT;
		break;
	}

	/*
	 * If we're in an XSCOM opal call then squash the error
	 * we assume that the caller (probably opal-prd) will
	 * handle logging it
	 */
	if (this_cpu()->current_token != OPAL_XSCOM_READ &&
	    this_cpu()->current_token != OPAL_XSCOM_WRITE) {
		log_simple_error(&e_info(OPAL_RC_XSCOM_RW),
			"XSCOM: %s error gcid=0x%x pcb_addr=0x%x stat=0x%x\n",
			is_write ? "write" : "read", gcid, pcb_addr, stat);
	}

	/* We need to reset the XSCOM or we'll hang on the next access */
	xscom_reset(gcid, false);

	/* Non recovered ... just fail */
	return rc;
}

static void xscom_handle_ind_error(uint64_t data, uint32_t gcid,
				   uint64_t pcb_addr, bool is_write)
{
	unsigned int stat = GETFIELD(XSCOM_DATA_IND_ERR, data);
	bool timeout = !(data & XSCOM_DATA_IND_COMPLETE);

	/* XXX: Create error log entry ? */
	if (timeout)
		log_simple_error(&e_info(OPAL_RC_XSCOM_INDIRECT_RW),
			"XSCOM: indirect %s timeout, gcid=0x%x pcb_addr=0x%llx"
			" stat=0x%x\n",
			is_write ? "write" : "read", gcid, pcb_addr, stat);
	else
		log_simple_error(&e_info(OPAL_RC_XSCOM_INDIRECT_RW),
			"XSCOM: indirect %s error, gcid=0x%x pcb_addr=0x%llx"
			" stat=0x%x\n",
			is_write ? "write" : "read", gcid, pcb_addr, stat);
}

static bool xscom_gcid_ok(uint32_t gcid)
{
	return get_chip(gcid) != NULL;
}

/* Determine if SCOM address is multicast */
static inline bool xscom_is_multicast_addr(uint32_t addr)
{
	return (((addr >> 30) & 0x1) == 0x1);
}

/*
 * Low level XSCOM access functions, perform a single direct xscom
 * access via MMIO
 */
static int __xscom_read(uint32_t gcid, uint32_t pcb_addr, uint64_t *val)
{
	uint64_t hmer;
	int64_t ret, retries;
	int64_t xscom_clear_retries = XSCOM_CLEAR_MAX_RETRIES;

	if (!xscom_gcid_ok(gcid)) {
		prerror("%s: invalid XSCOM gcid 0x%x\n", __func__, gcid);
		return OPAL_PARAMETER;
	}

	for (retries = 0; retries <= XSCOM_BUSY_MAX_RETRIES; retries++) {
		/* Clear status bits in HMER (HMER is special
		 * writing to it *ands* bits
		 */
		mtspr(SPR_HMER, HMER_CLR_MASK);

		/* Read value from SCOM */
		*val = in_be64(xscom_addr(gcid, pcb_addr));

		/* Wait for done bit */
		hmer = xscom_wait_done();

		/* Check for error */
		if (!(hmer & SPR_HMER_XSCOM_FAIL))
			return OPAL_SUCCESS;

		/* Handle error and possibly eventually retry */
		ret = xscom_handle_error(hmer, gcid, pcb_addr, false, retries,
				&xscom_clear_retries);
		if (ret != OPAL_BUSY)
			break;
	}

	/* Do not print error message for multicast SCOMS */
	if (xscom_is_multicast_addr(pcb_addr) && ret == OPAL_XSCOM_CHIPLET_OFF)
		return ret;

	/*
	 * Workaround on P9: PRD does operations it *knows* will fail with this
	 * error to work around a hardware issue where accesses via the PIB
	 * (FSI or OCC) work as expected, accesses via the ADU (what xscom goes
	 * through) do not. The chip logic will always return all FFs if there
	 * is any error on the scom.
	 */
	if (proc_gen == proc_gen_p9 && ret == OPAL_XSCOM_CHIPLET_OFF)
		return ret;

	/*
	 * If an OPAL call XSCOM read fails, then the OPAL-PRD will
	 * handle logging the error.  Hence just print an
	 * informational message here.
	 */
	if (this_cpu()->current_token == OPAL_XSCOM_READ)
		prlog(PR_INFO, "XSCOM: Read failed, ret =  %lld\n", ret);
	else
		prerror("XSCOM: Read failed, ret =  %lld\n", ret);

	return ret;
}

static int __xscom_write(uint32_t gcid, uint32_t pcb_addr, uint64_t val)
{
	uint64_t hmer;
	int64_t ret, retries = 0;
	int64_t xscom_clear_retries = XSCOM_CLEAR_MAX_RETRIES;

	if (!xscom_gcid_ok(gcid)) {
		prerror("%s: invalid XSCOM gcid 0x%x\n", __func__, gcid);
		return OPAL_PARAMETER;
	}

	for (retries = 0; retries <= XSCOM_BUSY_MAX_RETRIES; retries++) {
		/* Clear status bits in HMER (HMER is special
		 * writing to it *ands* bits
		 */
		mtspr(SPR_HMER, HMER_CLR_MASK);

		/* Write value to SCOM */
		out_be64(xscom_addr(gcid, pcb_addr), val);

		/* Wait for done bit */
		hmer = xscom_wait_done();

		/* Check for error */
		if (!(hmer & SPR_HMER_XSCOM_FAIL))
			return OPAL_SUCCESS;

		/* Handle error and possibly eventually retry */
		ret = xscom_handle_error(hmer, gcid, pcb_addr, true, retries,
				&xscom_clear_retries);
		if (ret != OPAL_BUSY)
			break;
	}

	/* Do not print error message for multicast SCOMS */
	if (xscom_is_multicast_addr(pcb_addr) && ret == OPAL_XSCOM_CHIPLET_OFF)
		return ret;

	/*
	 * Workaround on P9: PRD does operations it *knows* will fail with this
	 * error to work around a hardware issue where accesses via the PIB
	 * (FSI or OCC) work as expected, accesses via the ADU (what xscom goes
	 * through) do not. The chip logic will always return all FFs if there
	 * is any error on the scom.
	 */
	if (proc_gen == proc_gen_p9 && ret == OPAL_XSCOM_CHIPLET_OFF)
		return ret;
	/*
	 * If an OPAL call XSCOM write fails, then the OPAL-PRD will
	 * handle logging the error.  Hence just print an
	 * informational message here.
	 */
	if (this_cpu()->current_token == OPAL_XSCOM_WRITE)
		prlog(PR_INFO, "XSCOM: Write failed, ret =  %lld\n", ret);
	else
		prerror("XSCOM: Write failed, ret =  %lld\n", ret);

	return ret;
}

/*
 * Indirect XSCOM access functions
 */
static int xscom_indirect_read_form0(uint32_t gcid, uint64_t pcb_addr,
				     uint64_t *val)
{
	uint32_t addr;
	uint64_t data;
	int rc, retries;

	/* Write indirect address */
	addr = pcb_addr & 0x7fffffff;
	data = XSCOM_DATA_IND_READ |
		(pcb_addr & XSCOM_ADDR_IND_ADDR);
	rc = __xscom_write(gcid, addr, data);
	if (rc)
		goto bail;

	/* Wait for completion */
	for (retries = 0; retries < XSCOM_IND_MAX_RETRIES; retries++) {
		rc = __xscom_read(gcid, addr, &data);
		if (rc)
			goto bail;
		if ((data & XSCOM_DATA_IND_COMPLETE) &&
		    ((data & XSCOM_DATA_IND_ERR) == 0)) {
			*val = data & XSCOM_DATA_IND_DATA;
			break;
		}
		if ((data & XSCOM_DATA_IND_COMPLETE) ||
		    (retries >= XSCOM_IND_MAX_RETRIES)) {
			xscom_handle_ind_error(data, gcid, pcb_addr,
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

static int xscom_indirect_form(uint64_t pcb_addr)
{
	return (pcb_addr >> 60) & 1;
}

static int xscom_indirect_read(uint32_t gcid, uint64_t pcb_addr, uint64_t *val)
{
	uint64_t form = xscom_indirect_form(pcb_addr);

	if ((proc_gen >= proc_gen_p9) && (form == 1))
		return OPAL_UNSUPPORTED;

	return xscom_indirect_read_form0(gcid, pcb_addr, val);
}

static int xscom_indirect_write_form0(uint32_t gcid, uint64_t pcb_addr,
				      uint64_t val)
{
	uint32_t addr;
	uint64_t data;
	int rc, retries;

	/* Only 16 bit data with indirect */
	if (val & ~(XSCOM_ADDR_IND_DATA))
		return OPAL_PARAMETER;

	/* Write indirect address & data */
	addr = pcb_addr & 0x7fffffff;
	data = pcb_addr & XSCOM_ADDR_IND_ADDR;
	data |= val & XSCOM_ADDR_IND_DATA;

	rc = __xscom_write(gcid, addr, data);
	if (rc)
		goto bail;

	/* Wait for completion */
	for (retries = 0; retries < XSCOM_IND_MAX_RETRIES; retries++) {
		rc = __xscom_read(gcid, addr, &data);
		if (rc)
			goto bail;
		if ((data & XSCOM_DATA_IND_COMPLETE) &&
		    ((data & XSCOM_DATA_IND_ERR) == 0))
			break;
		if ((data & XSCOM_DATA_IND_COMPLETE) ||
		    (retries >= XSCOM_IND_MAX_RETRIES)) {
			xscom_handle_ind_error(data, gcid, pcb_addr,
					       true);
			rc = OPAL_HARDWARE;
			goto bail;
		}
	}
 bail:
	return rc;
}

static int xscom_indirect_write_form1(uint32_t gcid, uint64_t pcb_addr,
				      uint64_t val)
{
	uint32_t addr;
	uint64_t data;

	if (proc_gen < proc_gen_p9)
		return OPAL_UNSUPPORTED;
	if (val & ~(XSCOM_DATA_IND_FORM1_DATA))
		return OPAL_PARAMETER;

	/* Mangle address and data for form1 */
	addr = (pcb_addr & 0x000ffffffffUL);
	data = (pcb_addr & 0xfff00000000UL) << 20;
	data |= val;
	return __xscom_write(gcid, addr, data);
}

static int xscom_indirect_write(uint32_t gcid, uint64_t pcb_addr, uint64_t val)
{
	uint64_t form = xscom_indirect_form(pcb_addr);

	if ((proc_gen >= proc_gen_p9) && (form == 1))
		return xscom_indirect_write_form1(gcid, pcb_addr, val);

	return xscom_indirect_write_form0(gcid, pcb_addr, val);
}

static uint32_t xscom_decode_chiplet(uint32_t partid, uint64_t *pcb_addr)
{
	uint32_t gcid = (partid & 0x0fffffff) >> 4;
	uint32_t core = partid & 0xf;

	if (proc_gen >= proc_gen_p9) {
		/* XXX Not supported */
		*pcb_addr = 0;
	} else {
		*pcb_addr |= P8_EX_PCB_SLAVE_BASE;
		*pcb_addr |= core << 24;
	}

	return gcid;
}

void _xscom_lock(void)
{
	lock(&xscom_lock);
}

void _xscom_unlock(void)
{
	unlock(&xscom_lock);
}

/* sorted by the scom controller's partid */
static LIST_HEAD(scom_list);

int64_t scom_register(struct scom_controller *new)
{
	struct scom_controller *cur;

	list_for_each(&scom_list, cur, link) {
		if (cur->part_id == new->part_id) {
			prerror("Attempted to add duplicate scom, partid %x\n",
				new->part_id);
			return OPAL_BUSY;
		}

		if (cur->part_id > new->part_id) {
			list_add_before(&scom_list, &new->link, &cur->link);
			return 0;
		}
	}

	/* if we never find a larger partid then this is the largest */
	list_add_tail(&scom_list, &new->link);

	return 0;
}

static struct scom_controller *scom_find(uint32_t partid)
{
	struct scom_controller *cur;

	list_for_each(&scom_list, cur, link)
		if (partid == cur->part_id)
			return cur;

	return NULL;
}

static int64_t scom_read(struct scom_controller *scom, uint32_t partid,
			 uint64_t pcbaddr, uint64_t *val)
{
	int64_t rc = scom->read(scom, partid, pcbaddr, val);

	if (rc) {
		prerror("%s: to %x off: %llx rc = %lld\n",
			__func__, partid, pcbaddr, rc);
	}

	return rc;
}

static int64_t scom_write(struct scom_controller *scom, uint32_t partid,
			  uint64_t pcbaddr, uint64_t val)
{
	int64_t rc = scom->write(scom, partid, pcbaddr, val);

	if (rc) {
		prerror("%s: to %x off: %llx rc = %lld\n",
			__func__, partid, pcbaddr, rc);
	}

	return rc;
}

/*
 * External API
 */
int _xscom_read(uint32_t partid, uint64_t pcb_addr, uint64_t *val, bool take_lock)
{
	struct scom_controller *scom;
	uint32_t gcid;
	int rc;

	if (!opal_addr_valid(val))
		return OPAL_PARAMETER;

	/* Due to a bug in some versions of the PRD wrapper app, errors
	 * might not be properly forwarded to PRD, in which case the data
	 * set here will be used. Rather than a random value let's thus
	 * initialize the data to a known clean state.
	 */
	*val = 0xdeadbeefdeadbeefull;

	/* Handle part ID decoding */
	switch(partid >> 28) {
	case 0: /* Normal processor chip */
		gcid = partid;
		break;
	case 4: /* EX chiplet */
		gcid = xscom_decode_chiplet(partid, &pcb_addr);
		if (pcb_addr == 0)
			return OPAL_UNSUPPORTED;
		break;
	default:
		/* is it one of our hacks? */
		scom = scom_find(partid);
		if (scom)
			return scom_read(scom, partid, pcb_addr, val);

		/**
		 * @fwts-label XSCOMReadInvalidPartID
		 * @fwts-advice xscom_read was called with an invalid partid.
		 * There's likely a bug somewhere in the stack that's causing
		 * someone to try an xscom_read on something that isn't a
		 * processor, Centaur or EX chiplet.
		 */
		prerror("%s: invalid XSCOM partid 0x%x\n", __func__, partid);
		return OPAL_PARAMETER;
	}

	/* HW822317 requires us to do global locking */
	if (take_lock)
		lock(&xscom_lock);

	/* Direct vs indirect access */
	if (pcb_addr & XSCOM_ADDR_IND_FLAG)
		rc = xscom_indirect_read(gcid, pcb_addr, val);
	else
		rc = __xscom_read(gcid, pcb_addr & 0x7fffffff, val);

	/* Unlock it */
	if (take_lock)
		unlock(&xscom_lock);
	return rc;
}

static int64_t opal_xscom_read(uint32_t partid, uint64_t pcb_addr, __be64 *__val)
{
	uint64_t val;
	int64_t rc;

	rc = xscom_read(partid, pcb_addr, &val);
	*__val = cpu_to_be64(val);

	return rc;
}
opal_call(OPAL_XSCOM_READ, opal_xscom_read, 3);

int _xscom_write(uint32_t partid, uint64_t pcb_addr, uint64_t val, bool take_lock)
{
	struct scom_controller *scom;
	uint32_t gcid;
	int rc;

	/* Handle part ID decoding */
	switch(partid >> 28) {
	case 0: /* Normal processor chip */
		gcid = partid;
		break;
	case 4: /* EX chiplet */
		gcid = xscom_decode_chiplet(partid, &pcb_addr);
		break;
	default:
		/* is it one of our hacks? */
		scom = scom_find(partid);
		if (scom)
			return scom_write(scom, partid, pcb_addr, val);

		/**
		 * @fwts-label XSCOMWriteInvalidPartID
		 * @fwts-advice xscom_write was called with an invalid partid.
		 * There's likely a bug somewhere in the stack that's causing
		 * someone to try an xscom_write on something that isn't a
		 * processor, Centaur or EX chiplet.
		 */
		prerror("%s: invalid XSCOM partid 0x%x\n", __func__, partid);
		return OPAL_PARAMETER;
	}

	/* HW822317 requires us to do global locking */
	if (take_lock)
		lock(&xscom_lock);

	/* Direct vs indirect access */
	if (pcb_addr & XSCOM_ADDR_IND_FLAG)
		rc = xscom_indirect_write(gcid, pcb_addr, val);
	else
		rc = __xscom_write(gcid, pcb_addr & 0x7fffffff, val);

	/* Unlock it */
	if (take_lock)
		unlock(&xscom_lock);
	return rc;
}

static int64_t opal_xscom_write(uint32_t partid, uint64_t pcb_addr, uint64_t val)
{
	return xscom_write(partid, pcb_addr, val);
}
opal_call(OPAL_XSCOM_WRITE, opal_xscom_write, 3);

/*
 * Perform a xscom read-modify-write.
 */
int xscom_write_mask(uint32_t partid, uint64_t pcb_addr, uint64_t val, uint64_t mask)
{
	int rc;
	uint64_t old_val;

	rc = xscom_read(partid, pcb_addr, &old_val);
	if (rc)
		return rc;
	val = (old_val & ~mask) | (val & mask);
	return xscom_write(partid, pcb_addr, val);
}

int xscom_readme(uint64_t pcb_addr, uint64_t *val)
{
	return xscom_read(this_cpu()->chip_id, pcb_addr, val);
}

int xscom_writeme(uint64_t pcb_addr, uint64_t val)
{
	return xscom_write(this_cpu()->chip_id, pcb_addr, val);
}

int64_t xscom_read_cfam_chipid(uint32_t partid, uint32_t *chip_id)
{
	uint64_t val;
	int64_t rc = OPAL_SUCCESS;

	/* Mambo chip model lacks the f000f register, just make
	 * something up
	 */
	if (chip_quirk(QUIRK_NO_F000F)) {
		if (proc_gen == proc_gen_p10)
			val = 0x220DA04980000000UL; /* P10 DD2.0 */
		else if (proc_gen == proc_gen_p9)
			val = 0x203D104980000000UL; /* P9 Nimbus DD2.3 */
		else
			val = 0x221EF04980000000UL; /* P8 Murano DD2.1 */
	} else
		rc = xscom_read(partid, 0xf000f, &val);

	/* Extract CFAM id */
	if (rc == OPAL_SUCCESS)
		*chip_id = (uint32_t)(val >> 44);

	return rc;
}

static void xscom_init_chip_info(struct proc_chip *chip)
{
	uint32_t val;
	int64_t rc;

	rc = xscom_read_cfam_chipid(chip->id, &val);
	if (rc) {
		prerror("XSCOM: Error %lld reading 0xf000f register\n", rc);
		/* We leave chip type to UNKNOWN */
		return;
	}

	/* Identify chip */
	switch(val & 0xff) {
	case 0xef:
		chip->type = PROC_CHIP_P8_MURANO;
		assert(proc_gen == proc_gen_p8);
		break;
	case 0xea:
		chip->type = PROC_CHIP_P8_VENICE;
		assert(proc_gen == proc_gen_p8);
		break;
	case 0xd3:
		chip->type = PROC_CHIP_P8_NAPLES;
		assert(proc_gen == proc_gen_p8);
		break;
	case 0xd1:
		chip->type = PROC_CHIP_P9_NIMBUS;
		assert(proc_gen == proc_gen_p9);
		break;
	case 0xd4:
		chip->type = PROC_CHIP_P9_CUMULUS;
		assert(proc_gen == proc_gen_p9);
		break;
	case 0xd9:
		chip->type = PROC_CHIP_P9P;
		assert(proc_gen == proc_gen_p9);
		break;
	case 0xda:
		chip->type = PROC_CHIP_P10;
		assert(proc_gen == proc_gen_p10);
		break;
	default:
		printf("CHIP: Unknown chip type 0x%02x !!!\n",
		       (unsigned char)(val & 0xff));
	}

	/* Get EC level from CFAM ID */
	chip->ec_level = ((val >> 16) & 0xf) << 4;
	chip->ec_level |= (val >> 8) & 0xf;

	/*
	 * On P9, grab the ECID bits to differenciate
	 * DD1.01, 1.02, 2.00, etc...
	 */
	if (chip_quirk(QUIRK_MAMBO_CALLOUTS)) {
		chip->ec_rev = 0;
	} else if (proc_gen == proc_gen_p9) {
		uint64_t ecid2 = 0;
		uint8_t rev;
		xscom_read(chip->id, 0x18002, &ecid2);
		switch((ecid2 >> 45) & 7) {
		case 0:
			rev = 0;
			break;
		case 1:
			rev = 1;
			break;
		case 3:
			rev = 2;
			break;
		case 7:
			rev = 3;
			break;
		default:
			rev = 0;
		}
		prlog(PR_INFO,"P9 DD%i.%i%d detected\n", 0xf & (chip->ec_level >> 4),
		       chip->ec_level & 0xf, rev);
		chip->ec_rev = rev;
	} /* XXX P10 */
}

/*
* This function triggers xstop by writing to XSCOM.
* Machine would enter xstop state post completion of this.
*/
int64_t xscom_trigger_xstop(void)
{
	int rc = OPAL_UNSUPPORTED;
	bool xstop_disabled = false;

	if (nvram_query_eq_dangerous("opal-sw-xstop", "disable"))
		xstop_disabled = true;

	if (xstop_disabled) {
		prlog(PR_NOTICE, "Software initiated checkstop disabled.\n");
		return rc;
	}

	if (xstop_xscom.addr)
		rc = xscom_writeme(xstop_xscom.addr,
				PPC_BIT(xstop_xscom.fir_bit));

	return rc;
}

void xscom_init(void)
{
	struct dt_node *xn;
	const struct dt_property *p;

	dt_for_each_compatible(dt_root, xn, "ibm,xscom") {
		uint32_t gcid = dt_get_chip_id(xn);
		const struct dt_property *reg;
		struct proc_chip *chip;
		const char *chip_name;
		static const char *chip_names[] = {
			"UNKNOWN", "P8E", "P8", "P8NVL", "P9N", "P9C", "P9P",
			"P10",
		};

		chip = get_chip(gcid);
		assert(chip);

		/* XXX We need a proper address parsing. For now, we just
		 * "know" that we are looking at a u64
		 */
		reg = dt_find_property(xn, "reg");
		assert(reg);

		chip->xscom_base = dt_translate_address(xn, 0, NULL);

		/* Grab processor type and EC level */
		xscom_init_chip_info(chip);

		if (chip->type >= ARRAY_SIZE(chip_names))
			chip_name = "INVALID";
		else
			chip_name = chip_names[chip->type];

		/* We keep a "CHIP" prefix to make the log more user-friendly */
		prlog(PR_NOTICE, "CHIP: Chip ID %04x type: %s DD%x.%x%d\n",
		      gcid, chip_name, chip->ec_level >> 4,
		      chip->ec_level & 0xf, chip->ec_rev);
		prlog(PR_DEBUG, "XSCOM: Base address: 0x%llx\n", chip->xscom_base);
	}

	/* Collect details to trigger xstop via XSCOM write */
	p = dt_find_property(dt_root, "ibm,sw-checkstop-fir");
	if (p) {
		xstop_xscom.addr = dt_property_get_cell(p, 0);
		xstop_xscom.fir_bit = dt_property_get_cell(p, 1);
		prlog(PR_DEBUG, "XSTOP: XSCOM addr = 0x%llx, FIR bit = %lld\n",
		      xstop_xscom.addr, xstop_xscom.fir_bit);
	} else
		prlog(PR_DEBUG, "XSTOP: ibm,sw-checkstop-fir prop not found\n");
}

void xscom_used_by_console(void)
{
	xscom_lock.in_con_path = true;

	/*
	 * Some other processor might hold it without having
	 * disabled the console locally so let's make sure that
	 * is over by taking/releasing the lock ourselves
	 */
	lock(&xscom_lock);
	unlock(&xscom_lock);
}

bool xscom_ok(void)
{
	return !lock_held_by_me(&xscom_lock);
}
