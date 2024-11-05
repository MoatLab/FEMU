// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * I2C
 *
 * Copyright 2013-2019 IBM Corp.
 */

#include <skiboot.h>
#include <i2c.h>
#include <opal.h>
#include <device.h>
#include <opal-msg.h>
#include <timebase.h>
#include <processor.h>
#include <timer.h>
#include <trace.h>

static LIST_HEAD(i2c_bus_list);

/* Used to assign OPAL IDs */
static uint32_t i2c_next_bus;

void i2c_add_bus(struct i2c_bus *bus)
{
	bus->opal_id = ++i2c_next_bus;
	dt_add_property_cells(bus->dt_node, "ibm,opal-id", bus->opal_id);

	list_add_tail(&i2c_bus_list, &bus->link);
}

struct i2c_bus *i2c_find_bus_by_id(uint32_t opal_id)
{
	struct i2c_bus *bus;

	list_for_each(&i2c_bus_list, bus, link) {
		if (bus->opal_id == opal_id)
			return bus;
	}
	return NULL;
}

static inline void i2c_trace_req(struct i2c_request *req, int rc)
{
	struct trace_i2c t;

	memset(&t, 0, sizeof(t));

	t.bus = req->bus->opal_id;
	t.type = req->op | (req->offset_bytes << 4);
	t.i2c_addr = req->dev_addr;
	t.smbus_reg = req->offset & 0xffff; // FIXME: log whole offset
	t.size = req->rw_len;
	t.rc = rc;

	/* FIXME: trace should not be a union... */
	trace_add((void *)&t, TRACE_I2C, sizeof(t));
}

int64_t i2c_queue_req(struct i2c_request *req)
{
	int64_t ret = req->bus->queue_req(req);

	i2c_trace_req(req, OPAL_ASYNC_COMPLETION);

	if (!ret)
		req->req_state = i2c_req_queued;
	return ret;
}

static void opal_i2c_request_complete(int rc, struct i2c_request *req)
{
	uint64_t token = (uint64_t)(unsigned long)req->user_data;

	opal_queue_msg(OPAL_MSG_ASYNC_COMP, NULL, NULL,
			cpu_to_be64(token),
			cpu_to_be64(rc));
	i2c_trace_req(req, rc);

	free(req);
}

static int opal_i2c_request(uint64_t async_token, uint32_t bus_id,
			    struct opal_i2c_request *oreq)
{
	struct i2c_bus *bus = NULL;
	struct i2c_request *req;
	int rc;

	if (!opal_addr_valid(oreq))
		return OPAL_PARAMETER;

	if (oreq->flags & OPAL_I2C_ADDR_10)
		return OPAL_UNSUPPORTED;

	bus = i2c_find_bus_by_id(bus_id);
	if (!bus) {
		/**
		 * @fwts-label I2CInvalidBusID
		 * @fwts-advice opal_i2c_request was passed an invalid bus
		 * ID. This has likely come from the OS rather than OPAL
		 * and thus could indicate an OS bug rather than an OPAL
		 * bug.
		 */
		prlog(PR_ERR, "I2C: Invalid 'bus_id' passed to the OPAL\n");
		return OPAL_PARAMETER;
	}

	req = zalloc(sizeof(*req));
	if (!req) {
		/**
		 * @fwts-label I2CFailedAllocation
		 * @fwts-advice OPAL failed to allocate memory for an
		 * i2c_request. This points to an OPAL bug as OPAL ran
		 * out of memory and this should never happen.
		 */
		prlog(PR_ERR, "I2C: Failed to allocate 'i2c_request'\n");
		return OPAL_NO_MEM;
	}

	switch(oreq->type) {
	case OPAL_I2C_RAW_READ:
		req->op = I2C_READ;
		break;
	case OPAL_I2C_RAW_WRITE:
		req->op = I2C_WRITE;
		break;
	case OPAL_I2C_SM_READ:
		req->op = SMBUS_READ;
		req->offset = be32_to_cpu(oreq->subaddr);
		req->offset_bytes = oreq->subaddr_sz;
		break;
	case OPAL_I2C_SM_WRITE:
		req->op = SMBUS_WRITE;
		req->offset = be32_to_cpu(oreq->subaddr);
		req->offset_bytes = oreq->subaddr_sz;
		break;
	default:
		free(req);
		return OPAL_PARAMETER;
	}
	req->dev_addr = be16_to_cpu(oreq->addr);
	req->rw_len = be32_to_cpu(oreq->size);
	req->rw_buf = (void *)be64_to_cpu(oreq->buffer_ra);
	req->completion = opal_i2c_request_complete;
	req->user_data = (void *)(unsigned long)async_token;
	req->bus = bus;

	if (i2c_check_quirk(req, &rc)) {
		free(req);
		return rc;
	}

	/* Finally, queue the OPAL i2c request and return */
	rc = i2c_queue_req(req);
	if (rc) {
		free(req);
		return rc;
	}

	return OPAL_ASYNC_COMPLETION;
}
opal_call(OPAL_I2C_REQUEST, opal_i2c_request, 3);

#define MAX_NACK_RETRIES		 2
#define REQ_COMPLETE_POLLING		 5  /* Check if req is complete
					       in 5ms interval */
int64_t i2c_request_sync(struct i2c_request *req)
{
	uint64_t timer_period = msecs_to_tb(5), timer_count;
	uint64_t time_to_wait = 0;
	int64_t rc, waited, retries;
	size_t i, count;
	char buf[17]; /* 8 bytes in hex + NUL */

	for (retries = 0; retries <= MAX_NACK_RETRIES; retries++) {
		waited = 0;
		timer_count = 0;

		i2c_queue_req(req);

		do {
			time_to_wait = i2c_run_req(req);
			if (!time_to_wait)
				time_to_wait = REQ_COMPLETE_POLLING;
			time_wait(time_to_wait);
			waited += time_to_wait;
			timer_count += time_to_wait;
			if (timer_count > timer_period) {
				/*
				 * The above request may be relying on
				 * timers to complete, yet there may
				 * not be called, especially during
				 * opal init. We could be looping here
				 * forever. So explicitly check the
				 * timers once in a while
				 */
				check_timers(false);
				timer_count = 0;
			}
		} while (req->req_state != i2c_req_done);

		lwsync();
		rc = req->result;

		/* retry on NACK, otherwise exit */
		if (rc != OPAL_I2C_NACK_RCVD)
			break;
		req->req_state = i2c_req_new;
	}

	i2c_trace_req(req, rc);
	count = 0;
	for (i = 0; i < req->rw_len && count < sizeof(buf); i++) {
		count += snprintf(buf+count, sizeof(buf)-count, "%02x",
				*(unsigned char *)(req->rw_buf+i));
	}

	prlog(PR_DEBUG, "I2C: %s req op=%x offset=%x buf=%s buflen=%d "
	      "delay=%lu/%lld rc=%lld\n",
	      (rc) ? "!!!!" : "----", req->op, req->offset,
	      buf, req->rw_len, tb_to_msecs(waited), req->timeout, rc);

	return rc;
}

/**
 * i2c_request_send - send request to i2c bus synchronously
 * @bus_id: i2c bus id
 * @dev_addr: address of the device
 * @read_write: SMBUS_READ or SMBUS_WRITE
 * @offset: any of the I2C interface offset defined
 * @offset_bytes: offset size in bytes
 * @buf: data to be read or written
 * @buflen: buf length
 * @timeout: request timeout in milliseconds
 *
 * Send an I2C request to a device synchronously
 *
 * Returns: Zero on success otherwise a negative error code
 */
int64_t i2c_request_send(int bus_id, int dev_addr, int read_write,
		     uint32_t offset, uint32_t offset_bytes, void* buf,
		     size_t buflen, int timeout)
{
	struct i2c_request *req;
	struct i2c_bus *bus;
	int64_t rc;

	bus = i2c_find_bus_by_id(bus_id);
	if (!bus) {
		/**
		 * @fwts-label I2CInvalidBusID
		 * @fwts-advice i2c_request_send was passed an invalid bus
		 * ID. This indicates a bug.
		 */
		prlog(PR_ERR, "I2C: Invalid bus_id=%x\n", bus_id);
		return OPAL_PARAMETER;
	}

	req = zalloc(sizeof(*req));
	if (!req) {
		/**
		 * @fwts-label I2CAllocationFailed
		 * @fwts-advice OPAL failed to allocate memory for an
		 * i2c_request. This points to an OPAL bug as OPAL run out of
		 * memory and this should never happen.
		 */
		prlog(PR_ERR, "I2C: allocating i2c_request failed\n");
		return OPAL_INTERNAL_ERROR;
	}

	req->bus	= bus;
	req->dev_addr   = dev_addr;
	req->op         = read_write;
	req->offset     = offset;
	req->offset_bytes = offset_bytes;
	req->rw_buf     = (void*) buf;
	req->rw_len     = buflen;
	req->timeout    = timeout;

	rc = i2c_request_sync(req);

	free(req);
	if (rc)
		return OPAL_HARDWARE;

	return OPAL_SUCCESS;
}
