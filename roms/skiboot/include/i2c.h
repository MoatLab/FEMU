// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#ifndef __I2C_H
#define __I2C_H

struct i2c_request;

struct i2c_bus {
	struct list_node	link;
	struct dt_node		*dt_node;
	uint32_t		opal_id;
	int			(*queue_req)(struct i2c_request *req);
	uint64_t		(*run_req)(struct i2c_request *req);
	int			(*check_quirk)(void *data, struct i2c_request *req, int *rc);
	void			*check_quirk_data;
};

/*
 * I2C specific OPAL error codes:
 *
 * OPAL_I2C_TIMEOUT		I2C request timed out
 * OPAL_I2C_INVALID_CMD		New command given when old not completed yet
 * OPAL_I2C_LBUS_PARITY		Local bus parity error
 * OPAL_I2C_BKEND_OVERRUN	Writing/reading into full/empty fifo respectively
 * OPAL_I2C_BKEND_ACCESS	Writing/reading more data than requested
 * OPAL_I2C_ARBT_LOST		I2C bus is held by some other master
 * OPAL_I2C_NACK_RCVD		Slave is not responding back with the ACK
 * OPAL_I2C_STOP_ERR		Did not able to send the STOP condtion on bus
 */

struct i2c_request {
	struct list_node	link;
	struct i2c_bus		*bus;
	enum i2c_operation {
		I2C_READ,	/* RAW read from the device without offset */
		I2C_WRITE,	/* RAW write to the device without offset */
		SMBUS_READ,	/* SMBUS protocol read from the device */
		SMBUS_WRITE,	/* SMBUS protocol write to the device */
	} op;
	int			result;		/* OPAL i2c error code */
	uint32_t		dev_addr;	/* Slave device address */
	uint32_t		offset_bytes;	/* Internal device offset */
	uint32_t		offset;		/* Internal device offset */
	uint32_t		rw_len;		/* Length of the data request */
	void			*rw_buf;	/* Data request buffer */
	enum i2c_request_state {
		i2c_req_new,	/* un-initialised */
		i2c_req_queued, /* waiting in the queue */
		i2c_req_done,   /* request has been completed */
	} req_state;

	void			(*completion)(	/* Completion callback */
					      int rc, struct i2c_request *req);
	void			*user_data;	/* Client data */
	int			retries;
	uint64_t		timeout;	/* in ms */
};

/* Generic i2c */
extern void i2c_add_bus(struct i2c_bus *bus);
extern struct i2c_bus *i2c_find_bus_by_id(uint32_t opal_id);

/* not generic, but useful */
struct i2c_bus *p8_i2c_find_bus_by_port(uint32_t chip_id, int eng, int port_id);
struct dt_node *p8_i2c_add_master_node(struct dt_node *xscom, int eng_id);
struct dt_node *__p8_i2c_add_port_node(struct dt_node *master, int port_id,
					uint32_t bus_speed);
struct dt_node *p8_i2c_add_port_node(struct dt_node *xscom, int eng_id,
					int port_id, uint32_t bus_freq);

struct i2c_bus *p8_i2c_add_bus(uint32_t chip_id, int eng_id, int port_id,
					uint32_t bus_speed);

int64_t i2c_queue_req(struct i2c_request *req);

static inline uint64_t i2c_run_req(struct i2c_request *req)
{
	if (req->bus->run_req)
		return req->bus->run_req(req);
	return 0;
}

static inline int i2c_check_quirk(struct i2c_request *req, int *rc)
{
	if (req->bus->check_quirk)
		return req->bus->check_quirk(req->bus->check_quirk_data, req, rc);
	return 0;
}

/* I2C synchronous request API */
int64_t i2c_request_sync(struct i2c_request *req);
int64_t i2c_request_send(int bus_id, int dev_addr, int read_write,
		     uint32_t offset, uint32_t offset_bytes, void* buf,
		     size_t buflen, int timeout);

/* P8 implementation details */
extern void p8_i2c_init(void);
extern void p8_i2c_interrupt(uint32_t chip_id);

/* P9 I2C Ownership Change OCC interrupt handler */
extern void p9_i2c_bus_owner_change(u32 chip_id);

#endif /* __I2C_H */
