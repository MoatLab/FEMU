// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * P8 i2c master
 *
 * Copyright 2013-2019 IBM Corp.
 */

#undef DEBUG

#include <opal.h>
#include <skiboot.h>
#include <mem_region-malloc.h>
#include <lock.h>
#include <chip.h>
#include <i2c.h>
#include <xscom.h>
#include <timebase.h>
#include <timer.h>
#include <opal-msg.h>
#include <errorlog.h>
#include <centaur.h>
#include <debug_descriptor.h>

DEFINE_LOG_ENTRY(OPAL_RC_I2C_INIT, OPAL_PLATFORM_ERR_EVT, OPAL_I2C,
		 OPAL_IO_SUBSYSTEM, OPAL_PREDICTIVE_ERR_DEGRADED_PERF,
		 OPAL_NA);
DEFINE_LOG_ENTRY(OPAL_RC_I2C_START_REQ, OPAL_INPUT_OUTPUT_ERR_EVT, OPAL_I2C,
		 OPAL_IO_SUBSYSTEM, OPAL_INFO, OPAL_NA);
DEFINE_LOG_ENTRY(OPAL_RC_I2C_TIMEOUT, OPAL_INPUT_OUTPUT_ERR_EVT, OPAL_I2C,
		 OPAL_IO_SUBSYSTEM, OPAL_INFO, OPAL_NA);
DEFINE_LOG_ENTRY(OPAL_RC_I2C_TRANSFER, OPAL_INPUT_OUTPUT_ERR_EVT, OPAL_I2C,
		 OPAL_IO_SUBSYSTEM, OPAL_INFO, OPAL_NA);
DEFINE_LOG_ENTRY(OPAL_RC_I2C_RESET, OPAL_INPUT_OUTPUT_ERR_EVT, OPAL_I2C,
		 OPAL_IO_SUBSYSTEM, OPAL_INFO, OPAL_NA);

#ifdef DEBUG
#define DBG(fmt...) prlog(PR_ERR, "I2C: " fmt)
#define I2C_TIMEOUT_IRQ_MS		100	/* 100ms/byte timeout */
#define I2C_TIMEOUT_POLL_MS		4000	/* 4s/byte timeout */
#else
#define DBG(fmt...) prlog(PR_TRACE, "I2C: " fmt)
#define I2C_TIMEOUT_IRQ_MS		1	/* 1ms/byte timeout */
#define I2C_TIMEOUT_POLL_MS		4000	/* 4s/byte timeout */
#endif

/* How long to keep the sensor cache disabled after an access
 * in milliseconds
 */
#define SENSOR_CACHE_EN_DELAY 10

#define USEC_PER_SEC		1000000
#define USEC_PER_MSEC		1000
#define I2C_RESET_DELAY_MS	5 /* 5 msecs */
#define I2C_FIFO_HI_LVL		4
#define I2C_FIFO_LO_LVL		4

/*
 * I2C registers set.
 * Below is the offset of registers from base which is stored in the
 * 'struct p8_i2c_master'
 */

/* I2C FIFO register */
#define I2C_FIFO_REG			0x4
#define I2C_FIFO			PPC_BITMASK(0, 7)

/* I2C command register */
#define I2C_CMD_REG			0x5
#define I2C_CMD_WITH_START		PPC_BIT(0)
#define I2C_CMD_WITH_ADDR		PPC_BIT(1)
#define I2C_CMD_READ_CONT		PPC_BIT(2)
#define I2C_CMD_WITH_STOP		PPC_BIT(3)
#define I2C_CMD_INTR_STEERING		PPC_BITMASK(6,7) /* P9 */
#define   I2C_CMD_INTR_STEER_HOST	1
#define   I2C_CMD_INTR_STEER_OCC	2
#define I2C_CMD_DEV_ADDR		PPC_BITMASK(8, 14)
#define I2C_CMD_READ_NOT_WRITE		PPC_BIT(15)
#define I2C_CMD_LEN_BYTES		PPC_BITMASK(16, 31)
#define I2C_MAX_TFR_LEN			0xfff0ull

/* I2C mode register */
#define I2C_MODE_REG			0x6
#define I2C_MODE_BIT_RATE_DIV		PPC_BITMASK(0, 15)
#define I2C_MODE_PORT_NUM		PPC_BITMASK(16, 21)
#define I2C_MODE_ENHANCED		PPC_BIT(28)
#define I2C_MODE_DIAGNOSTIC		PPC_BIT(29)
#define I2C_MODE_PACING_ALLOW		PPC_BIT(30)
#define I2C_MODE_WRAP			PPC_BIT(31)

/* I2C watermark register */
#define I2C_WATERMARK_REG		0x7
#define I2C_WATERMARK_HIGH		PPC_BITMASK(16, 19)
#define I2C_WATERMARK_LOW		PPC_BITMASK(24, 27)

/*
 * I2C interrupt mask and condition registers
 *
 * NB: The function of 0x9 and 0xa changes depending on whether you're reading
 *     or writing to them. When read they return the interrupt condition bits
 *     and on writes they update the interrupt mask register.
 *
 *  The bit definitions are the same for all the interrupt registers.
 */
#define I2C_INTR_MASK_REG		0x8

#define I2C_INTR_RAW_COND_REG 		0x9 /* read */
#define I2C_INTR_MASK_OR_REG		0x9 /* write*/

#define I2C_INTR_COND_REG 		0xa /* read */
#define I2C_INTR_MASK_AND_REG		0xa /* write */

#define I2C_INTR_ALL			PPC_BITMASK(16, 31)
#define I2C_INTR_INVALID_CMD		PPC_BIT(16)
#define I2C_INTR_LBUS_PARITY_ERR	PPC_BIT(17)
#define I2C_INTR_BKEND_OVERRUN_ERR	PPC_BIT(18)
#define I2C_INTR_BKEND_ACCESS_ERR	PPC_BIT(19)
#define I2C_INTR_ARBT_LOST_ERR		PPC_BIT(20)
#define I2C_INTR_NACK_RCVD_ERR		PPC_BIT(21)
#define I2C_INTR_DATA_REQ		PPC_BIT(22)
#define I2C_INTR_CMD_COMP		PPC_BIT(23)
#define I2C_INTR_STOP_ERR		PPC_BIT(24)
#define I2C_INTR_I2C_BUSY		PPC_BIT(25)
#define I2C_INTR_NOT_I2C_BUSY		PPC_BIT(26)
#define I2C_INTR_SCL_EQ_1		PPC_BIT(28)
#define I2C_INTR_SCL_EQ_0		PPC_BIT(29)
#define I2C_INTR_SDA_EQ_1		PPC_BIT(30)
#define I2C_INTR_SDA_EQ_0		PPC_BIT(31)

/* I2C status register */
#define I2C_RESET_I2C_REG		0xb
#define I2C_RESET_ERRORS		0xc
#define I2C_STAT_REG			0xb
#define I2C_STAT_INVALID_CMD		PPC_BIT(0)
#define I2C_STAT_LBUS_PARITY_ERR	PPC_BIT(1)
#define I2C_STAT_BKEND_OVERRUN_ERR	PPC_BIT(2)
#define I2C_STAT_BKEND_ACCESS_ERR	PPC_BIT(3)
#define I2C_STAT_ARBT_LOST_ERR		PPC_BIT(4)
#define I2C_STAT_NACK_RCVD_ERR		PPC_BIT(5)
#define I2C_STAT_DATA_REQ		PPC_BIT(6)
#define I2C_STAT_CMD_COMP		PPC_BIT(7)
#define I2C_STAT_STOP_ERR		PPC_BIT(8)
#define I2C_STAT_UPPER_THRS		PPC_BITMASK(9, 15)
#define I2C_STAT_ANY_I2C_INTR		PPC_BIT(16)
#define I2C_STAT_PORT_HISTORY_BUSY	PPC_BIT(19)
#define I2C_STAT_SCL_INPUT_LEVEL	PPC_BIT(20)
#define I2C_STAT_SDA_INPUT_LEVEL	PPC_BIT(21)
#define I2C_STAT_PORT_BUSY		PPC_BIT(22)
#define I2C_STAT_INTERFACE_BUSY         PPC_BIT(23)
#define I2C_STAT_FIFO_ENTRY_COUNT	PPC_BITMASK(24, 31)

#define I2C_STAT_ANY_ERR (I2C_STAT_INVALID_CMD | I2C_STAT_LBUS_PARITY_ERR | \
			  I2C_STAT_BKEND_OVERRUN_ERR | \
			  I2C_STAT_BKEND_ACCESS_ERR | I2C_STAT_ARBT_LOST_ERR | \
			  I2C_STAT_NACK_RCVD_ERR | I2C_STAT_STOP_ERR)


#define I2C_INTR_ACTIVE \
	((I2C_STAT_ANY_ERR >> 16) | I2C_INTR_CMD_COMP | I2C_INTR_DATA_REQ)

/* Pseudo-status used for timeouts */
#define I2C_STAT_PSEUDO_TIMEOUT		PPC_BIT(63)


/* I2C extended status register */
#define I2C_EXTD_STAT_REG		0xc
#define I2C_EXTD_STAT_FIFO_SIZE		PPC_BITMASK(0, 7)
#define I2C_EXTD_STAT_MSM_CURSTATE	PPC_BITMASK(11, 15)
#define I2C_EXTD_STAT_SCL_IN_SYNC	PPC_BIT(16)
#define I2C_EXTD_STAT_SDA_IN_SYNC	PPC_BIT(17)
#define I2C_EXTD_STAT_S_SCL		PPC_BIT(18)
#define I2C_EXTD_STAT_S_SDA		PPC_BIT(19)
#define I2C_EXTD_STAT_M_SCL		PPC_BIT(20)
#define I2C_EXTD_STAT_M_SDA		PPC_BIT(21)
#define I2C_EXTD_STAT_HIGH_WATER	PPC_BIT(22)
#define I2C_EXTD_STAT_LOW_WATER		PPC_BIT(23)
#define I2C_EXTD_STAT_I2C_BUSY		PPC_BIT(24)
#define I2C_EXTD_STAT_SELF_BUSY		PPC_BIT(25)
#define I2C_EXTD_STAT_I2C_VERSION	PPC_BITMASK(27, 31)

/* I2C residual front end/back end length */
#define I2C_RESIDUAL_LEN_REG		0xd
#define I2C_RESIDUAL_FRONT_END		PPC_BITMASK(0, 15)
#define I2C_RESIDUAL_BACK_END		PPC_BITMASK(16, 31)

/* Port busy register */
#define I2C_PORT_BUSY_REG		0xe
#define I2C_SET_S_SCL_REG		0xd
#define I2C_RESET_S_SCL_REG		0xf
#define I2C_SET_S_SDA_REG		0x10
#define I2C_RESET_S_SDA_REG		0x11

enum p8_i2c_master_type {
	I2C_POWER8,
	I2C_CENTAUR,
	MAX_I2C_TYPE,
};

struct p8_i2c_master {
	struct dt_node		*dt_node;
	struct lock		lock;		/* Lock to guard the members */
	enum p8_i2c_master_type	type;		/* P8 vs. Centaur */
	uint64_t		start_time;	/* Request start time */
	uint64_t		last_update;
	uint64_t		poll_interval;	/* Polling interval  */
	uint64_t		xscom_base;	/* xscom base of i2cm */
	uint32_t		fifo_size;	/* Maximum size of FIFO  */
	uint32_t		chip_id;	/* Chip the i2cm sits on */
	uint32_t		engine_id;	/* Engine# on chip */
	uint8_t			obuf[4];	/* Offset buffer */
	uint32_t		bytes_sent;
	bool			irq_ok;		/* Interrupt working ? */
	bool			occ_cache_dis;  /* I have disabled the cache */
	bool			occ_lock_acquired; /* Acquired lock from OCC */
	enum request_state {
		state_idle,
		state_occache_dis,
		state_offset,
		state_data,
		state_error,
		state_recovery,
	}			state;
	struct list_head	req_list;	/* Request queue head */
	struct timer		poller;
	struct timer		timeout;
	struct timer		recovery;
	struct timer		sensor_cache;
	uint8_t			recovery_pass;
	struct list_node	link;
	struct list_head	ports;
};

struct p8_i2c_master_port {
	struct i2c_bus		bus; /* Abstract bus struct for the client */
	struct p8_i2c_master	*master;
	uint32_t		port_num;
	uint32_t		bit_rate_div;	/* Divisor to set bus speed*/
	uint64_t		byte_timeout;	/* Timeout per byte */
	uint64_t		poll_interval;	/* Polling interval */
	struct list_node	link;
};

static int occ_i2c_unlock(struct p8_i2c_master *master);

static int64_t i2cm_read_reg(struct p8_i2c_master *m, int reg, uint64_t *val)
{
	return xscom_read(m->chip_id, m->xscom_base + reg, val);
}

static int64_t i2cm_write_reg(struct p8_i2c_master *m, int reg, uint64_t val)
{
	return xscom_write(m->chip_id, m->xscom_base + reg, val);
}

static void p8_i2c_print_debug_info(struct p8_i2c_master_port *port,
				    struct i2c_request *req, uint64_t end_time)
{
	struct p8_i2c_master *master = port->master;
	uint64_t cmd, mode, stat, estat, intm, intc;

	/* Print master and request structure bits */
	log_simple_error(&e_info(OPAL_RC_I2C_TRANSFER),
			 "I2C: Chip %08x Eng. %d Port %d--\n"
			 " xscom_base=0x%016llx\tstate=%d\tbytes_sent=%d\n",
			 master->chip_id, master->engine_id, port->port_num,
			 master->xscom_base, master->state, master->bytes_sent);

	log_simple_error(&e_info(OPAL_RC_I2C_TRANSFER), "I2C: Request info--\n"
			 " addr=0x%04x\toffset_bytes=%d\toffset=%d\tlen=%d\n",
			 req->dev_addr, req->offset_bytes, req->offset,
			 req->rw_len);

	log_simple_error(&e_info(OPAL_RC_I2C_TRANSFER), "I2C: "
			 " start_time=%016llx end_time=%016llx (duration=%016llx)\n",
			 master->start_time, end_time, end_time - master->start_time);

	/* initialise to some fake value in case of read errors */
	cmd = mode = stat = estat = intm = intc = 0xDEAD;

	/* Dump the current state of i2c registers */
	i2cm_read_reg(master, I2C_CMD_REG, &cmd);
	i2cm_read_reg(master, I2C_MODE_REG, &mode);
	i2cm_read_reg(master, I2C_MODE_REG, &mode);
	i2cm_read_reg(master, I2C_STAT_REG, &stat);
	i2cm_read_reg(master, I2C_EXTD_STAT_REG, &estat);
	i2cm_read_reg(master, I2C_INTR_MASK_REG, &intm);
	i2cm_read_reg(master, I2C_INTR_RAW_COND_REG, &intc);

	log_simple_error(&e_info(OPAL_RC_I2C_TRANSFER), "I2C: Register dump--\n"
			 "    cmd:0x%016llx\tmode:0x%016llx\tstat:0x%016llx\n"
			 "  estat:0x%016llx\tintm:0x%016llx\tintc:0x%016llx\n",
			 cmd, mode, stat, estat, intm, intc);

	log_simple_error(&e_info(OPAL_RC_I2C_TRANSFER),
		"I2C: Error bits set: %s%s%s%s%s%s%s\n",
		(stat & I2C_STAT_NACK_RCVD_ERR) ? "nack, " : "",
		(stat & I2C_STAT_INVALID_CMD) ? "cmd invalid, " : "",
		(stat & I2C_STAT_LBUS_PARITY_ERR) ? "interal parity, " : "",
		(stat & I2C_STAT_BKEND_OVERRUN_ERR) ? "backend overrun, " : "",
		(stat & I2C_STAT_BKEND_ACCESS_ERR) ? "backend access, " : "",
		(stat & I2C_STAT_ARBT_LOST_ERR) ? "arbitration loss, " : "",
		(stat & I2C_STAT_STOP_ERR) ? "stop error, " : "");
}

static bool p8_i2c_has_irqs(struct p8_i2c_master *master)
{
	struct proc_chip *chip;

	/* Centaur I2C doesn't have interrupts */
	if (master->type == I2C_CENTAUR)
		return false;

	chip = get_chip(master->chip_id);

	/* The i2c interrupts was only added to Murano DD2.1 and Venice
	 * DD2.0. When operating without interrupts, we need to bump the
	 * timeouts as we rely solely on the polls from Linux which can
	 * be up to 2s apart !
	 */
	if (proc_gen >= proc_gen_p9)
		return true;
	else if (chip->type == PROC_CHIP_P8_MURANO)
		return chip->ec_level >= 0x21;
	else if (chip->type == PROC_CHIP_P8_VENICE)
		return chip->ec_level >= 0x20;

	return true;
}

static int p8_i2c_enable_irqs(struct p8_i2c_master *master)
{
	int rc;

	/* enable interrupts we're interested in */
	rc = i2cm_write_reg(master, I2C_INTR_MASK_OR_REG, I2C_INTR_ACTIVE);
	if (rc)
		prlog(PR_ERR, "I2C: Failed to enable the interrupts\n");

	return rc;
}

static void p8_i2c_reset_timeout(struct p8_i2c_master *master,
		struct i2c_request *req)
{
	uint64_t now = mftb();

	master->last_update = now;
	schedule_timer_at(&master->timeout, now + msecs_to_tb(req->timeout));
}

static int p8_i2c_prog_watermark(struct p8_i2c_master *master)
{
	uint64_t watermark;
	int rc;

	rc = xscom_read(master->chip_id, master->xscom_base + I2C_WATERMARK_REG,
			&watermark);
	if (rc) {
		prlog(PR_ERR, "I2C: Failed to read the WATERMARK_REG\n");
		return rc;
	}

	/* Set the high/low watermark */
	watermark = SETFIELD(I2C_WATERMARK_HIGH, watermark, I2C_FIFO_HI_LVL);
	watermark = SETFIELD(I2C_WATERMARK_LOW, watermark, I2C_FIFO_LO_LVL);
	rc = xscom_write(master->chip_id, master->xscom_base +
			 I2C_WATERMARK_REG, watermark);
	if (rc)
		prlog(PR_ERR, "I2C: Failed to set high/low watermark level\n");

	return rc;
}

static int p8_i2c_prog_mode(struct p8_i2c_master_port *port, bool enhanced_mode)
{
	struct p8_i2c_master *master = port->master;
	uint64_t mode, omode;
	int rc;

	rc = xscom_read(master->chip_id, master->xscom_base +
			I2C_MODE_REG, &mode);
	if (rc) {
		prlog(PR_ERR, "I2C: Failed to read the MODE_REG\n");
		return rc;
	}
	omode = mode;
	mode = SETFIELD(I2C_MODE_PORT_NUM, mode, port->port_num);
	mode = SETFIELD(I2C_MODE_BIT_RATE_DIV, mode, port->bit_rate_div);
	if (enhanced_mode)
		mode |= I2C_MODE_ENHANCED;
	else
		mode &= ~I2C_MODE_ENHANCED;
	if (mode == omode)
		return 0;

	rc = xscom_write(master->chip_id, master->xscom_base + I2C_MODE_REG,
			 mode);
	if (rc)
		prlog(PR_ERR, "I2C: Failed to write the MODE_REG\n");

	return rc;
}

static void p8_i2c_complete_request(struct p8_i2c_master *master,
				    struct i2c_request *req, int ret)
{
	/* We only complete the current top level request */
	assert(req == list_top(&master->req_list, struct i2c_request, link));

	cancel_timer_async(&master->timeout);

	list_del(&req->link);
	master->state = state_idle;
	req->result = ret;
	req->req_state = i2c_req_done;

	/* Schedule re-enabling of sensor cache */
	if (master->occ_cache_dis)
		schedule_timer(&master->sensor_cache,
			       msecs_to_tb(SENSOR_CACHE_EN_DELAY));

	/* If we're done with i2c master, allow OCC to use it */
	if (master->occ_lock_acquired && list_empty(&master->req_list))
		occ_i2c_unlock(master);

	unlock(&master->lock);
	if (req->completion)
		req->completion(ret, req);
	/* req might have been freed at this point */
	lock(&master->lock);
}


static int p8_i2c_engine_reset(struct p8_i2c_master_port *port)
{
	struct p8_i2c_master *master = port->master;
	int rc;

	/* Reset the i2c engine */
	rc = xscom_write(master->chip_id, master->xscom_base +
			 I2C_RESET_I2C_REG, 0);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_I2C_RESET), "I2C: Failed "
				 "to reset the i2c engine\n");
		return rc;
	}

	/* Reprogram the watermark and mode */
	rc = p8_i2c_prog_watermark(port->master);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_I2C_RESET), "I2C: Failed to"
				 "program the WATERMARK_REG\n");
		return rc;
	}

	rc = p8_i2c_prog_mode(port, false);
	if (rc)
		log_simple_error(&e_info(OPAL_RC_I2C_RESET), "I2C: Failed to"
				 "program the MODE_REG\n");

	return rc;
}

static void p8_i2c_translate_error(struct i2c_request *req, uint64_t status)
{
	/* Assuming there are not more than one type of error simultaneously */
	if (status & I2C_STAT_NACK_RCVD_ERR)
		req->result = OPAL_I2C_NACK_RCVD;
	else if (status & I2C_STAT_INVALID_CMD)
		req->result = OPAL_I2C_INVALID_CMD;
	else if (status & I2C_STAT_LBUS_PARITY_ERR)
		req->result = OPAL_I2C_LBUS_PARITY;
	else if (status & I2C_STAT_BKEND_OVERRUN_ERR)
		req->result = OPAL_I2C_BKEND_OVERRUN;
	else if (status & I2C_STAT_BKEND_ACCESS_ERR)
		req->result = OPAL_I2C_BKEND_ACCESS;
	else if (status & I2C_STAT_ARBT_LOST_ERR)
		req->result = OPAL_I2C_ARBT_LOST;
	else if (status & I2C_STAT_STOP_ERR)
		req->result = OPAL_I2C_STOP_ERR;
	else if (status & I2C_STAT_PSEUDO_TIMEOUT)
		req->result = OPAL_I2C_TIMEOUT;
}

static int p8_i2c_reset_port(struct p8_i2c_master_port *p)
{
	struct p8_i2c_master *master = p->master;
	int reset_loops, rc;
	uint64_t status;

	/* FIXME: this should per per-port rather than per-master */
	master->state = state_error;

	/*
	 * Put the master into enhanced STOP mode when recovering the
	 * port. This causes the master to send additional STOP conditions
	 * to work around some particularly stupid I2C devices and it's
	 * required on secure I2C masters since they will not send a bare
	 * stop condition.
	 */
	rc = p8_i2c_prog_mode(p, true);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_I2C_RESET),
				 "I2C: Failed to enable enhanced mode\n");
		return -1;
	}

	rc = xscom_write(master->chip_id, master->xscom_base +
			 I2C_CMD_REG, I2C_CMD_WITH_STOP);
	if (rc)
		goto err;

	/* Wait for COMMAND COMPLETE */
	for (reset_loops = 0; reset_loops < 10; reset_loops++) {
		time_wait_ms(10);

		rc = xscom_read(master->chip_id,
				master->xscom_base + I2C_STAT_REG,
				&status);
		if (rc)
			goto err;

		if (status & I2C_STAT_CMD_COMP)
			break;
	}

	if (status & I2C_STAT_CMD_COMP)
		return 0;
err:
	prerror("I2C: Failed to reset c%de%dp%d\n",
		master->chip_id, master->engine_id, p->port_num);
	return -1;
}

static void p8_i2c_status_error(struct p8_i2c_master_port *port,
				struct i2c_request *req,
				uint64_t status, uint64_t end_time)
{
	struct p8_i2c_master *master = port->master;
	int rc;

	/* Display any error other than I2C_INTR_NACK_RCVD_ERR or
	 * timeout since getting NACK's is normal if Linux is probing
	 * the bus and timeouts will have already logged something.
	 */
	if (!(status & (I2C_STAT_NACK_RCVD_ERR | I2C_STAT_PSEUDO_TIMEOUT))) {
		log_simple_error(&e_info(OPAL_RC_I2C_TRANSFER),
				 "I2C: Transfer error occurred\n");
		p8_i2c_print_debug_info(port, req, end_time);
	} else if (status == I2C_STAT_PSEUDO_TIMEOUT) {
		log_simple_error(&e_info(OPAL_RC_I2C_TIMEOUT),
				 "I2C: request timed out!\n");
		p8_i2c_print_debug_info(port, req, end_time);
	}

	p8_i2c_translate_error(req, status);

	rc = p8_i2c_engine_reset(port);
	if (rc)
		goto exit;

	if (status & (I2C_STAT_LBUS_PARITY_ERR | I2C_STAT_ARBT_LOST_ERR |
		      I2C_STAT_STOP_ERR)) {
		/*
		 * Don't bother issuing a STOP command for those errors
		 * just get rid of the current request and start off with
		 * the fresh one in the list
		 */
		p8_i2c_complete_request(master, req, req->result);
	} else {
		if (p8_i2c_reset_port(port))
			goto exit;
		/* Enable the interrupt */
		p8_i2c_enable_irqs(master);
	}
	return;

exit:
	p8_i2c_complete_request(master, req, req->result);
}

static int p8_i2c_fifo_read(struct p8_i2c_master *master,
			    uint8_t *buf, uint32_t count)
{
	uint64_t fifo;
	uint32_t i;
	int rc = 0;

	for (i = 0; i < count; i++, buf++) {
		rc = xscom_read(master->chip_id, master->xscom_base +
				I2C_FIFO_REG, &fifo);
		if (rc) {
			log_simple_error(&e_info(OPAL_RC_I2C_TRANSFER),
					 "I2C: Failed to read the fifo\n");
			break;
		}

		*buf = GETFIELD(I2C_FIFO, fifo);
	}
	return rc;
}

static int p8_i2c_fifo_write(struct p8_i2c_master *master,
			     uint8_t *buf, uint32_t count)
{
	uint64_t fifo;
	uint32_t i;
	int rc = 0;

	for (i = 0; i < count; i++, buf++) {
		fifo = SETFIELD(I2C_FIFO, 0ull, *buf);
		rc = xscom_write(master->chip_id, master->xscom_base +
				 I2C_FIFO_REG, fifo);
		if (rc) {
			log_simple_error(&e_info(OPAL_RC_I2C_TRANSFER),
					 "I2C: Failed to write the fifo\n");
			break;
		}
	}
	return rc;
}

static void p8_i2c_status_data_request(struct p8_i2c_master *master,
				       struct i2c_request *req,
				       uint64_t status)
{
	uint32_t fifo_count, fifo_free, count;
	uint8_t *buf;
	int rc = 0;

	fifo_count = GETFIELD(I2C_STAT_FIFO_ENTRY_COUNT, status);
	fifo_free = master->fifo_size - fifo_count;

	DBG("Data request, state=%d fifo_count=%d/%d bytes_sent=%d\n",
	    master->state, fifo_count, master->fifo_size, master->bytes_sent);

	switch(master->state) {
	case state_offset:
		/* We assume the offset can always be written in one go */
		if (fifo_free < req->offset_bytes) {
			log_simple_error(&e_info(OPAL_RC_I2C_TRANSFER),
					 "I2C: Fifo too small for offset !\n");
			rc = OPAL_HARDWARE;
		} else {
			rc = p8_i2c_fifo_write(master, master->obuf,
					       req->offset_bytes);
		}

		/* For read, wait address phase to complete */
		if (rc || req->op != SMBUS_WRITE)
			break;

		/* For writes, transition to data phase now */
		master->state = state_data;
		fifo_free -= req->offset_bytes;
		/* Fall through */
	case state_data:
		/* Sanity check */
		if (master->bytes_sent >= req->rw_len) {
			log_simple_error(&e_info(OPAL_RC_I2C_TRANSFER), "I2C: "
					 "Data req with no data to send sent=%d "
					 "req=%d\n", master->bytes_sent,
					 req->rw_len);
			rc = OPAL_HARDWARE;
			break;
		}

		/* Get next chunk */
		buf = req->rw_buf + master->bytes_sent;
		count = req->rw_len - master->bytes_sent;

		/* Check direction */
		if (req->op == I2C_READ || req->op == SMBUS_READ) {
			if (count > fifo_count)
				count = fifo_count;
			rc = p8_i2c_fifo_read(master, buf, count);
		} else {
			if (count > fifo_free)
				count = fifo_free;
			rc = p8_i2c_fifo_write(master, buf, count);
		}
		if (rc == 0)
			master->bytes_sent += count;
		break;
	default:
		log_simple_error(&e_info(OPAL_RC_I2C_TRANSFER), "I2C: Invalid "
				 "state %d in data req !\n", master->state);
		rc = OPAL_WRONG_STATE;
	}

	if (rc) {
		p8_i2c_complete_request(master, req, rc);
	} else {
		p8_i2c_enable_irqs(master);
		p8_i2c_reset_timeout(master, req);
	}
}

static void p8_i2c_complete_offset(struct p8_i2c_master *master,
				   struct i2c_request *req)
{
	uint64_t cmd;
	int rc = 0;

	DBG("Completing offset phase\n");

	/* If it's a write, we should only get here for empty
	 * write commands
	 */
	if (req->op == SMBUS_WRITE && req->rw_len != 0) {
		log_simple_error(&e_info(OPAL_RC_I2C_TRANSFER), "I2C: Write "
				 "completion in offset state !\n");
		rc = OPAL_HARDWARE;
		goto complete;
	}

	/* Switch to data phase */
	master->state = state_data;

	/* If it's not a read command, or there are no data to read,
	 * then we complete the command
	 */
	if (req->op != SMBUS_READ || req->rw_len == 0)
		goto complete;

	/* Otherwise, let's start the data phase */
	cmd = I2C_CMD_WITH_START | I2C_CMD_WITH_ADDR |
		I2C_CMD_WITH_STOP | I2C_CMD_READ_NOT_WRITE;
	cmd = SETFIELD(I2C_CMD_DEV_ADDR, cmd, req->dev_addr);
	cmd = SETFIELD(I2C_CMD_LEN_BYTES, cmd, req->rw_len);
	cmd = SETFIELD(I2C_CMD_INTR_STEERING, cmd, I2C_CMD_INTR_STEER_HOST);

	DBG("Command: %016llx, state: %d\n", cmd, master->state);

	/* Send command */
	rc = xscom_write(master->chip_id, master->xscom_base + I2C_CMD_REG,
			 cmd);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_I2C_TRANSFER), "I2C: Failed "
				 "to write the CMD_REG\n");
		goto complete;
	}

	/* Enable the interrupts */
	p8_i2c_enable_irqs(master);
	p8_i2c_reset_timeout(master, req);
	return;

 complete:
	p8_i2c_complete_request(master, req, rc);
}

static void p8_i2c_status_cmd_completion(struct p8_i2c_master *master,
					 struct i2c_request *req,
					 uint64_t end_time __unused)
{
	int rc;

	DBG("Command completion, state=%d bytes_sent=%d\n",
	    master->state, master->bytes_sent);
	DBG("  start_time=%016llx end_time=%016llx (duration=%016llx)\n",
	    master->start_time, end_time, end_time - master->start_time);

	/* If we complete an offset, we probably need to transition
	 * do a data read, check if that all makes sense
	 */
	if (master->state == state_offset) {
		p8_i2c_complete_offset(master, req);
		return;
	}

	/* If we are not already in error state, check if we have
	 * completed our data transfer properly
	 */
	if (master->state != state_error && master->bytes_sent != req->rw_len) {
		log_simple_error(&e_info(OPAL_RC_I2C_TRANSFER), "I2C: Request "
				 "complete with residual data req=%d done=%d\n",
				 req->rw_len, master->bytes_sent);
		/* Should we error out here ? */
	}
	rc = master->state == state_error ? req->result : OPAL_SUCCESS;
	p8_i2c_complete_request(master, req, rc);
}

static void p8_i2c_check_status(struct p8_i2c_master *master)
{
	struct p8_i2c_master_port *port;
	uint64_t status, deadline, now;
	struct i2c_request *req;
	int rc;

	/*
	 * When idle or waiting for the occ to release the bus there's
	 * nothing to check. Also ignore recovery state, as the bus
	 * can be reset in that state, and a request can think it's
	 * complete when it just means the reset is complete.
	 * Error states are handled when starting a new request.
	 */
	if (master->state == state_idle || master->state == state_occache_dis ||
		master->state == state_recovery)
		return;

	/* A non-idle master should always have a pending request */
	req = list_top(&master->req_list, struct i2c_request, link);
	if (!req) {
		prerror("I2C: Master is not idle and has no pending request\n");
		return;
	}

	rc = i2cm_read_reg(master, I2C_STAT_REG, &status);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_I2C_TRANSFER),
			"I2C: Failed to read the STAT_REG\n");
		return;
	}

	/* mask interrupts while we're mucking with the master */
	rc = i2cm_write_reg(master, I2C_INTR_MASK_AND_REG, ~I2C_INTR_ALL);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_I2C_TRANSFER),
			"I2C: Failed to disable the interrupts\n");
		return;
	}

	/* Get port for current request */
	port = container_of(req->bus, struct p8_i2c_master_port, bus);
	now = mftb();

	deadline = master->last_update + msecs_to_tb(req->timeout);

	if (status & I2C_STAT_ANY_ERR)
		p8_i2c_status_error(port, req, status & I2C_STAT_ANY_ERR, now);
	else if (status & I2C_STAT_DATA_REQ)
		p8_i2c_status_data_request(master, req, status);
	else if (status & I2C_STAT_CMD_COMP)
		p8_i2c_status_cmd_completion(master, req, now);
	else if (tb_compare(now, deadline) == TB_AAFTERB)
		p8_i2c_status_error(port, req, I2C_STAT_PSEUDO_TIMEOUT, now);
	else
		p8_i2c_enable_irqs(master);
}

static int p8_i2c_check_initial_status(struct p8_i2c_master_port *port)
{
	struct p8_i2c_master *master = port->master;
	uint64_t status, estat;
	int rc;

	master->recovery_pass++;

	/* Read status register */
	rc = xscom_read(master->chip_id, master->xscom_base + I2C_STAT_REG,
			&status);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_I2C_START_REQ), "I2C: Failed "
				 "to read the STAT_REG\n");
		return rc;
	}

	rc = xscom_read(master->chip_id,
			master->xscom_base + I2C_EXTD_STAT_REG,
			&estat);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_I2C_START_REQ), "I2C: Failed "
				 "to read the EXTD_STAT_REG\n");
		return rc;
	}
	if (estat & (I2C_EXTD_STAT_I2C_BUSY | I2C_EXTD_STAT_SELF_BUSY)) {
		DBG("Initial estat busy ! %016llx\n", estat);
		/* Just a warning for now */
	}

	/* Nothing happened ? Go back */
	if (status & I2C_STAT_ANY_ERR) {
		log_simple_error(&e_info(OPAL_RC_I2C_START_REQ), "I2C: "
				 "Initial error status 0x%016llx\n", status);

		if (master->recovery_pass > 1) {
			log_simple_error(&e_info(OPAL_RC_I2C_START_REQ), "I2C: "
					 "Error stuck, aborting !!\n");
			return OPAL_HARDWARE;
		}

		/* Mark state as "recovery" to block any other activity */
		master->state = state_recovery;

		/* Reset the engine */
		p8_i2c_engine_reset(port);

		/* Delay 5ms for bus to settle */
		schedule_timer(&master->recovery, msecs_to_tb(5));
		return OPAL_BUSY;
	}

	/* Still busy ? */
	if (!(status & I2C_STAT_CMD_COMP)) {
		log_simple_error(&e_info(OPAL_RC_I2C_START_REQ), "I2C: Initial "
				 "command complete not set\n");

		if (master->recovery_pass > 5) {
			log_simple_error(&e_info(OPAL_RC_I2C_START_REQ), "I2C: "
					 "Command stuck, aborting !!\n");
			return OPAL_HARDWARE;
		}


		master->state = state_recovery;

		/* Delay 5ms for bus to settle */
		schedule_timer(&master->recovery, msecs_to_tb(5));
		return OPAL_BUSY;
	}

	master->recovery_pass = 0;
	return 0;
}

/*
 * On POWER9, the I2C may also wish to use some of the i2cm engines,
 * to do things like read sensor data. There's a couple of shared
 * registers with the OCC to negotiate locking of the i2cm engines.
 * See occ/src/occ_405/lock/lock.c
 */
static bool occ_uses_master(struct p8_i2c_master *master)
{
	/* OCC uses I2CM Engines 1,2 and 3, only on POWER9/10 */
	if (master->type == I2C_POWER8 && proc_gen >= proc_gen_p9)
		return master->engine_id >= 1;

	return false;
}

static uint32_t occflg;
#define OCCFLG_BASE  0
#define OCCFLG_CLEAR 1
#define OCCFLG_SET   2

static int occ_i2c_lock(struct p8_i2c_master *master)
{
	u64 occflags, busflag;
	int rc;

	if (!occ_uses_master(master) || !occflg)
		return 0;

	if (master->occ_lock_acquired)
		return 0;

	rc = xscom_read(master->chip_id, occflg, &occflags);
	if (rc) {
		prerror("I2C: Failed to read OCC FLAG register\n");
		return rc;
	}

	assert(master->engine_id > 0);

	busflag = PPC_BIT(16 + (master->engine_id - 1) * 2);

	DBG("I2C: c%de%d: occflags = %llx (locks = %x:%x:%x)\n",
		master->chip_id, master->engine_id, (u64) occflags,
		(u32) GETFIELD(PPC_BITMASK(16, 17), occflags),
		(u32) GETFIELD(PPC_BITMASK(18, 19), occflags),
		(u32) GETFIELD(PPC_BITMASK(20, 21), occflags));

	rc = xscom_write(master->chip_id, occflg + OCCFLG_SET, busflag);
	if (rc) {
		prerror("I2C: Failed to write OCC FLAG register\n");
		return rc;
	}

	/* If the OCC also has this bus locked then wait for IRQ */
	if (occflags & (busflag >> 1)) {
		DBG("I2C: c%de%d: Master in use by OCC\n",
			master->chip_id, master->engine_id);
		return 1;
	}

	master->occ_lock_acquired = true;

	return 0;
}

static int occ_i2c_unlock(struct p8_i2c_master *master)
{
	u64 busflag, occflags;
	int rc;

	if (!occ_uses_master(master) || !occflg)
		return 0;

	rc = xscom_read(master->chip_id, occflg, &occflags);
	if (rc) {
		prerror("I2C: Failed to read OCC Flag register\n");
		return rc;
	}

	busflag = PPC_BIT(16 + (master->engine_id - 1) * 2);

	if (!(occflags & busflag)) {
		DBG("I2C: spurious unlock for c%de%d already cleared (flags = %.16llx)",
			master->chip_id, master->engine_id, occflags);
	}

	rc = xscom_write(master->chip_id, occflg + OCCFLG_CLEAR, busflag);
	if (rc)
		prerror("I2C: Failed to write OCC Flag register\n");

	master->occ_lock_acquired = false;

	return rc;
}

static int p8_i2c_start_request(struct p8_i2c_master *master,
				struct i2c_request *req)
{
	struct p8_i2c_master_port *port;
	uint64_t cmd;
	int64_t rc;

	DBG("Starting req %d len=%d addr=%02x (offset=%x)\n",
	    req->op, req->rw_len, req->dev_addr, req->offset);

	/* Get port */
	port = container_of(req->bus, struct p8_i2c_master_port, bus);

	/* Check if we need to disable the OCC cache first */
	if (master->type == I2C_CENTAUR && !master->occ_cache_dis) {
		DBG("Disabling OCC cache...\n");
		rc = centaur_disable_sensor_cache(master->chip_id);

		if (rc < 0) {
			log_simple_error(&e_info(OPAL_RC_I2C_START_REQ),
					 "I2C: Failed "
					 "to disable the sensor cache\n");
			return rc;
		}
		master->occ_cache_dis = true;

		/* Do we need to wait ? */
		if (rc > 0) {
			DBG("Waiting %lld\n", rc);
			master->state = state_occache_dis;
			schedule_timer(&master->recovery, rc);
			return 0;
		}
	}

	/*
	 * on P9 we need to set the "I2C master using bit" so we don't
	 * conflict with the OCC's use of the i2c master.
	 */
	rc = occ_i2c_lock(master);
	if (rc < 0) {
		log_simple_error(&e_info(OPAL_RC_I2C_START_REQ),
				 "I2C: Failed to get I2CM lock from OCC\n");
		return rc;
	}
	if (rc > 0) {
		/* Wait for OCC IRQ */
		master->state = state_occache_dis;
		schedule_timer(&master->recovery, msecs_to_tb(10));
		return 0;
	}

	/* Convert the offset if needed */
	if (req->offset_bytes) {
		int i;

		for (i = 0; i < req->offset_bytes; i++) {
			uint8_t b;

			b = req->offset >> (8 * (req->offset_bytes - i - 1));
			master->obuf[i] = b;
		}
		DBG("Offset %d bytes: %02x %02x %02x %02x\n",
		    req->offset_bytes, master->obuf[0], master->obuf[1],
		    master->obuf[2], master->obuf[3]);
	}

	/* Program mode register */
	rc = p8_i2c_prog_mode(port, false);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_I2C_START_REQ), "I2C: Failed "
				 "to program the MODE_REG\n");
		return rc;
	}

	/* Check status */
	rc = p8_i2c_check_initial_status(port);
	if (rc != OPAL_BUSY)
		master->recovery_pass = 0;
	if (rc)
		return rc;

	/* program the watermark register */
	rc = p8_i2c_prog_watermark(master);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_I2C_INIT),
			 "I2C: Failed to program the WATERMARK_REG\n");
		return rc;
	}

	/* Initialize bytes_sent */
	master->bytes_sent = 0;

	/* Set up the command register */
	cmd = I2C_CMD_WITH_START | I2C_CMD_WITH_ADDR;
	cmd = SETFIELD(I2C_CMD_DEV_ADDR, cmd, req->dev_addr);
	cmd = SETFIELD(I2C_CMD_INTR_STEERING, cmd, I2C_CMD_INTR_STEER_HOST);
	switch (req->op) {
	case I2C_READ:
		cmd |= I2C_CMD_READ_NOT_WRITE;
		/* Fall through */
	case I2C_WRITE:
		cmd |= I2C_CMD_WITH_STOP;
		cmd = SETFIELD(I2C_CMD_LEN_BYTES, cmd, req->rw_len);
		master->state = state_data;
		break;
	case SMBUS_READ:
		cmd = SETFIELD(I2C_CMD_LEN_BYTES, cmd, req->offset_bytes);
		master->state = state_offset;
		break;
	case SMBUS_WRITE:
		cmd |= I2C_CMD_WITH_STOP;
		cmd = SETFIELD(I2C_CMD_LEN_BYTES, cmd,
				req->rw_len + req->offset_bytes);
		master->state = state_offset;
		break;
	default:
		return OPAL_PARAMETER;
	}
	DBG("Command: %016llx, state: %d\n", cmd, master->state);

	master->start_time = mftb();

	/* Send command */
	rc = xscom_write(master->chip_id, master->xscom_base + I2C_CMD_REG,
			 cmd);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_I2C_START_REQ), "I2C: Failed "
				 "to write the CMD_REG\n");
		return rc;
	}

	/* Enable the interrupts */
	p8_i2c_enable_irqs(master);

	/* Run a poll timer for boot cases or non-working interrupts
	 * cases
	 */
	if (!opal_booting() && master->irq_ok)
		master->poll_interval = TIMER_POLL;
	else
		master->poll_interval = port->poll_interval;
	schedule_timer(&master->poller, master->poll_interval);

	/* If we don't have a user-set timeout then use the master's default */
	if (!req->timeout)
		req->timeout = port->byte_timeout;

	/* Start the timeout */
	p8_i2c_reset_timeout(master, req);

	return OPAL_SUCCESS;
}

static void p8_i2c_check_work(struct p8_i2c_master *master)
{
	struct i2c_request *req;
	int rc;

	while (master->state == state_idle && !list_empty(&master->req_list)) {
		req = list_top(&master->req_list, struct i2c_request, link);
		rc = p8_i2c_start_request(master, req);
		if (rc) {
			/*
			 * If it didn't work the first three times then
			 * odds are it's not going to work on the 4th.
			 */
			if (rc && req->retries > 3)
				p8_i2c_complete_request(master, req, rc);
			else
				req->retries++;
		}
	}
}

/* OCC IRQ Handler for I2C Ownership Change*/
void p9_i2c_bus_owner_change(u32 chip_id)
{
	struct proc_chip *chip = get_chip(chip_id);
	struct p8_i2c_master *master = NULL;

	assert(chip);
	list_for_each(&chip->i2cms, master, link) {
		lock(&master->lock);

		/* spurious */
		if (master->state != state_occache_dis)
			goto done;

		/* Can we now lock this master? */
		if (occ_i2c_lock(master))
			goto done;

		/* clear the existing wait timer */
		cancel_timer_async(&master->recovery);

		/* re-start the request now that we own the master */
		master->state = state_idle;

		p8_i2c_check_work(master);
		p8_i2c_check_status(master);
done:
		unlock(&master->lock);
	}
}

static int p8_i2c_queue_request(struct i2c_request *req)
{
	struct i2c_bus *bus = req->bus;
	struct p8_i2c_master_port *port =
		container_of(bus, struct p8_i2c_master_port, bus);
	struct p8_i2c_master *master = port->master;
	int rc = 0;

	/* Parameter check */
	if (req->rw_len > I2C_MAX_TFR_LEN) {
		prlog(PR_ERR, "I2C: Too large transfer %d bytes\n", req->rw_len);
		return OPAL_PARAMETER;
	}

	if (req->offset_bytes > 4) {
		prlog(PR_ERR, "I2C: Invalid offset size %d\n", req->offset_bytes);
		return OPAL_PARAMETER;
	}
	lock(&master->lock);
	list_add_tail(&master->req_list, &req->link);
	p8_i2c_check_work(master);
	unlock(&master->lock);

	return rc;
}

static uint64_t p8_i2c_run_request(struct i2c_request *req)
{
	struct i2c_bus *bus = req->bus;
	struct p8_i2c_master_port *port =
		container_of(bus, struct p8_i2c_master_port, bus);
	struct p8_i2c_master *master = port->master;
	uint64_t poll_interval = 0;

	lock(&master->lock);
	p8_i2c_check_status(master);
	p8_i2c_check_work(master);
	poll_interval = master->poll_interval;
	unlock(&master->lock);

	return poll_interval;
}

static inline uint32_t p8_i2c_get_bit_rate_divisor(uint32_t lb_freq,
						   uint32_t bus_speed)
{
	assert(bus_speed > 0);
	return (((lb_freq / bus_speed) - 1) / 4);
}

static inline uint64_t p8_i2c_get_poll_interval(uint32_t bus_speed)
{
	uint64_t usec;

	assert(bus_speed > 0);

	/* Polling Interval = 8 * (1/bus_speed) * (1/10) -> convert to uSec */
	usec = ((8 * USEC_PER_SEC) / (10 * bus_speed));
	return usecs_to_tb(usec);
}

static void p8_i2c_timeout(struct timer *t __unused, void *data,
		uint64_t __unused now)
{
	struct p8_i2c_master *master = data;

	lock(&master->lock);

	DBG("timeout on c%de%d\n", master->chip_id, master->engine_id);

	/*
	 * Run through the usual status checks. It's possible to get spurious
	 * timeouts due to races between the interrupt/poller paths and the
	 * timeout handler. So we do all the checking, all the time.
	 */
	p8_i2c_check_status(master);
	p8_i2c_check_work(master);

	unlock(&master->lock);
}

static void p8_i2c_recover(struct timer *t __unused, void *data,
			   uint64_t now __unused)
{
	struct p8_i2c_master *master = data;

	lock(&master->lock);

	/*
	 * The recovery timer can race with the OCC interrupt. If the interrupt
	 * comes in just before this is called, then we'll get a spurious
	 * timeout which we need to ignore.
	 */
	if (master->state != state_recovery &&
		master->state != state_occache_dis) {
		unlock(&master->lock);
		return;
	}

	master->state = state_idle;

	/* We may or may not still have work pending, re-enable the sensor cache
	 * immediately if we don't (we just waited the recovery time so there is
	 * little point waiting longer).
	 */
	if (master->occ_cache_dis && list_empty(&master->req_list)) {
		DBG("Re-enabling OCC cache after recovery\n");
		centaur_enable_sensor_cache(master->chip_id);
		master->occ_cache_dis = false;
	}

	if (master->occ_lock_acquired && list_empty(&master->req_list))
		occ_i2c_unlock(master);

	/* Re-check for new work */
	p8_i2c_check_work(master);
	unlock(&master->lock);
}

static void p8_i2c_enable_scache(struct timer *t __unused, void *data,
				 uint64_t now __unused)
{
	struct p8_i2c_master *master = data;

	lock(&master->lock);

	/* Check if we are still idle */
	if (master->state == state_idle && master->occ_cache_dis) {
		DBG("Re-enabling OCC cache\n");
		centaur_enable_sensor_cache(master->chip_id);
		master->occ_cache_dis = false;
	}
	unlock(&master->lock);
}

static void p8_i2c_poll(struct timer *t __unused, void *data, uint64_t now)
{
	struct p8_i2c_master *master = data;

	/*
	 * This is called when the interrupt isn't functional or
	 * generally from the opal pollers, so fast while booting
	 * and slowly when Linux is up.
	 */

	/* Lockless fast bailout */
	if (master->state == state_idle)
		return;

	lock(&master->lock);
	p8_i2c_check_status(master);
	if (master->state != state_idle)
		schedule_timer_at(&master->poller, now + master->poll_interval);
	p8_i2c_check_work(master);
	unlock(&master->lock);
}

void p8_i2c_interrupt(uint32_t chip_id)
{
	struct proc_chip *chip = get_chip(chip_id);
	struct p8_i2c_master *master = NULL;

	assert(chip);
	list_for_each(&chip->i2cms, master, link) {

		/* Lockless fast bailout (shared interrupt) */
		if (master->state == state_idle)
			continue;

		lock(&master->lock);

		/* Run the state machine */
		p8_i2c_check_status(master);

		/* Check for new work */
		p8_i2c_check_work(master);

		unlock(&master->lock);
	}
}

static const char *compat[] = {
	"ibm,power8-i2cm",
	"ibm,centaur-i2cm"
};

static void p8_i2c_add_bus_prop(struct p8_i2c_master_port *port)
{
	const struct dt_property *c, *p;
	struct dt_node *np = port->bus.dt_node;
	char name[32];

	c = dt_find_property(np, "compatible");
	p = dt_find_property(np, "ibm,port-name");

	if (!c) {
		if (port->master->type == I2C_POWER8)
			dt_add_property_strings(np, "compatible",
						"ibm,power8-i2c-port",
						"ibm,opal-i2c");
		else if (port->master->type == I2C_CENTAUR)
			dt_add_property_strings(np, "compatible",
						"ibm,centaur-i2c-port",
						"ibm,opal-i2c");
	}

	if (!p) {
		if (port->master->type == I2C_POWER8)
			snprintf(name, sizeof(name), "p8_%08x_e%dp%d",
				 port->master->chip_id, port->master->engine_id,
				 port->port_num);
		else if (port->master->type == I2C_CENTAUR)
			snprintf(name, sizeof(name), "cen_%08x_e%dp%d",
				 port->master->chip_id, port->master->engine_id,
				 port->port_num);

		dt_add_property_string(np, "ibm,port-name", name);
	}
}

static struct p8_i2c_master_port *p8_i2c_init_one_port(struct p8_i2c_master *m,
				struct dt_node *n)
{
	struct p8_i2c_master_port *port;
	uint64_t def_timeout, lb_freq;
	uint32_t speed, div;

	port = zalloc(sizeof(*port));
	if (!port)
		return NULL;

	def_timeout = m->irq_ok ? I2C_TIMEOUT_IRQ_MS : I2C_TIMEOUT_POLL_MS;

	lb_freq = dt_prop_get_u32_def(m->dt_node, "clock-frequency", 150000000);
	speed = dt_prop_get_u32_def(n, "bus-frequency", 100000);
	div = p8_i2c_get_bit_rate_divisor(lb_freq, speed);

	/* p8-i2c stuff */
	port->master       = m;
	port->bit_rate_div = div;
	port->poll_interval = p8_i2c_get_poll_interval(speed);
	port->port_num     = dt_prop_get_u32(n, "reg");
	port->byte_timeout = dt_prop_get_u32_def(n, "timeout-ms", def_timeout);
	list_add_tail(&m->ports, &port->link);

	/* core i2c stuff */
	port->bus.dt_node   = n;
	port->bus.queue_req = p8_i2c_queue_request;
	port->bus.run_req   = p8_i2c_run_request;
	i2c_add_bus(&port->bus);

	/* add the bus name and compatible (if needed) */
	p8_i2c_add_bus_prop(port);

	prlog(PR_INFO, " P%d: <%s> %d kHz\n", port->port_num,
			(char *) dt_prop_get(n, "ibm,port-name"), speed / 1000);

	return port;
}

static struct p8_i2c_master *p8_i2c_init_one(struct dt_node *i2cm,
						enum p8_i2c_master_type type)
{
	struct p8_i2c_master *master;
	struct list_head *chip_list;
	struct dt_node *i2cm_port;
	uint64_t ex_stat;
	uint32_t lb_freq;
	int64_t rc;

	master = zalloc(sizeof(*master));
	if (!master) {
		log_simple_error(&e_info(OPAL_RC_I2C_INIT),
				 "I2C: Failed to allocate master "
				 "structure\n");
		return NULL;
	}
	master->type = type;

	/* Local bus speed in Hz */
	lb_freq = dt_prop_get_u32(i2cm, "clock-frequency");

	/* Initialise the i2c master structure */
	master->state = state_idle;
	master->chip_id = dt_get_chip_id(i2cm);
	master->engine_id = dt_prop_get_u32(i2cm, "chip-engine#");
	master->xscom_base = dt_get_address(i2cm, 0, NULL);
	master->dt_node = i2cm;
	if (master->type == I2C_CENTAUR) {
		struct centaur_chip *centaur = get_centaur(master->chip_id);
		if (centaur == NULL) {
			log_simple_error(&e_info(OPAL_RC_I2C_INIT),
					 "I2C: Failed to get centaur 0x%x ",
					 master->chip_id);
			free(master);
			return NULL;
		}
		chip_list = &centaur->i2cms;

		/* Detect bad device-tree from HostBoot giving us bogus
		 * i2c masters
		 */
		if (master->engine_id > 0) {
			prlog(PR_ERR, "I2C: Skipping Centaur Master #1\n");
			free(master);
			return NULL;
		}
	} else {
		struct proc_chip *chip = get_chip(master->chip_id);
		assert(chip);
		chip_list = &chip->i2cms;
	}
	init_timer(&master->timeout, p8_i2c_timeout, master);
	init_timer(&master->poller, p8_i2c_poll, master);
	init_timer(&master->recovery, p8_i2c_recover, master);
	init_timer(&master->sensor_cache, p8_i2c_enable_scache, master);

	master->irq_ok = p8_i2c_has_irqs(master);

	prlog(PR_INFO, "I2C: Chip %08x Eng. %d Clock %d Mhz %s\n",
	      master->chip_id, master->engine_id, lb_freq / 1000000,
	      master->irq_ok ? "" : "(no interrupt)");

	/* Disable OCC cache during inits */
	if (master->type == I2C_CENTAUR) {
		rc = centaur_disable_sensor_cache(master->chip_id);
		if (rc < 0) {
			log_simple_error(&e_info(OPAL_RC_I2C_INIT), "I2C: "
					 "Error %lld disabling sensor cache\n",
					 rc);
			/* Ignore error and move on ... */
		} else
			time_wait(rc);
	}
	rc = xscom_read(master->chip_id, master->xscom_base +
			I2C_EXTD_STAT_REG, &ex_stat);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_I2C_INIT), "I2C: "
				 "Failed to read EXTD_STAT_REG\n");
		if (master->type == I2C_CENTAUR)
			centaur_enable_sensor_cache(master->chip_id);

		free(master);
		return NULL;
	}

	master->fifo_size = GETFIELD(I2C_EXTD_STAT_FIFO_SIZE, ex_stat);
	list_head_init(&master->req_list);
	list_head_init(&master->ports);

	/* Re-enable the sensor cache, we aren't touching HW anymore */
	if (master->type == I2C_CENTAUR)
		centaur_enable_sensor_cache(master->chip_id);

	/* Add master to chip's list */
	list_add_tail(chip_list, &master->link);

	/* initialise ports */
	dt_for_each_child(i2cm, i2cm_port)
		p8_i2c_init_one_port(master, i2cm_port);

	return master;
}

void p8_i2c_init(void)
{
	struct dt_node *i2cm;
	int i;

	/* setup the handshake reg */
	if (proc_gen <= proc_gen_p9)
		occflg = 0x6C08A;
	else if (proc_gen == proc_gen_p10)
		occflg = 0x6C0AC;
	else
		return;

	prlog(PR_INFO, "I2C: OCC flag reg: %x\n", occflg);

	for (i = 0; i < MAX_I2C_TYPE; i++) {
		dt_for_each_compatible(dt_root, i2cm, compat[i])
			p8_i2c_init_one(i2cm, i);
	}
}

struct i2c_bus *p8_i2c_find_bus_by_port(uint32_t chip_id, int eng, int port_num)
{
	struct proc_chip *chip = get_chip(chip_id);
	struct p8_i2c_master *m, *master = NULL;
	struct p8_i2c_master_port *port;

	if (!chip)
		return NULL;

	list_for_each(&chip->i2cms, m, link) {
		if (m->engine_id == eng) {
			master = m;
			break;
		}
	}

	if (!master)
		return NULL;

	list_for_each(&master->ports, port, link)
		if (port->port_num == port_num)
			return &port->bus;

	return NULL;
}

/* Adds a new i2c port to the DT and initialises it */
struct i2c_bus *p8_i2c_add_bus(uint32_t chip_id, int eng_id, int port_id,
				uint32_t bus_speed)
{
	struct proc_chip *c = get_chip(chip_id);
	struct p8_i2c_master *m, *master = NULL;
	struct p8_i2c_master_port *port;
	struct dt_node *pn;

	if (!c) {
		prerror("I2C: Unable to add i2c bus: c%de%dp%d: chip doesn't exist\n",
			chip_id, eng_id, port_id);
		return NULL;
	}

	list_for_each(&c->i2cms, m, link) {
		if (m->engine_id == eng_id) {
			master = m;
			break;
		}
	}

	if (!master) {
		struct dt_node *mn;

		mn = p8_i2c_add_master_node(c->devnode, eng_id);
		if (!mn) {
			prerror("I2C: Unable to add DT node for I2CM c%xe%d\n",
					chip_id, eng_id);
			return NULL;
		}

		master = p8_i2c_init_one(mn, I2C_POWER8);
		if (!master) {
			prerror("I2C: Unable to initialise I2CM c%xe%d\n",
					chip_id, eng_id);
			return NULL;
		}
	}

	list_for_each(&master->ports, port, link)
		if (port->port_num == port_id)
			return &port->bus;

	pn = __p8_i2c_add_port_node(master->dt_node, port_id, bus_speed);
	if (!pn) {
		prerror("I2C: Unable to add dt node for bus c%xe%dp%d\n",
					chip_id, eng_id, port_id);
		return NULL;
	}

	port = p8_i2c_init_one_port(master, pn);
	if (!port) {
		prerror("I2C: Unable to init bus c%xe%dp%d\n",
					chip_id, eng_id, port_id);
		return NULL;
	}

	return &port->bus;
}
