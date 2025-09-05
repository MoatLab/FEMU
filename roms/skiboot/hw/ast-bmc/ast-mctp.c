// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
// Copyright 2022 IBM Corp.

#define pr_fmt(fmt) "AST-MCTP: " fmt

#include <lock.h>
#include <lpc.h>
#include <interrupts.h>
#include <timer.h>
#include <timebase.h>
#include <debug_descriptor.h>
#include <device.h>
#include <ast.h>
#include <console.h>
#include <pldm.h>
#include <libmctp.h>
#include <libmctp-cmds.h>
#include <libmctp-log.h>
#include <libmctp-astlpc.h>

static struct mctp *mctp;
static struct mctp_binding_astlpc *astlpc;
static struct astlpc_ops_data *ops_data;
static struct lock mctp_lock = LOCK_UNLOCKED;

/* Keyboard Controller Style (KCS) data register address */
#define KCS_DATA_REG 0xca2

/* Keyboard Controller Style (KCS) status register address */
#define KCS_STATUS_REG 0xca3

#define KCS_STATUS_BMC_READY 0x80
#define KCS_STATUS_OBF       0x01

#define HOST_MAX_INCOMING_MESSAGE_ALLOCATION 131072
#define DESIRED_MTU 32768

#define TX_POLL_MAX 5

/*
 * The AST LPC binding is described here:
 *
 * https://github.com/openbmc/libmctp/blob/master/docs/bindings/vendor-ibm-astlpc.md
 *
 * Most of the binding is implemented in libmctp, but we need to provide
 * accessors for the LPC FW space (for the packet buffer) and for the KCS
 * peripheral (for the interrupt mechanism).
 */

struct astlpc_ops_data {
	uint16_t kcs_data_addr; /* LPC IO space offset for the data register */
	uint16_t kcs_stat_addr;

	/* address of the packet exchange buffer in FW space */
	uint32_t lpc_fw_addr;
};

static int astlpc_kcs_reg_read(void *binding_data,
			       enum mctp_binding_astlpc_kcs_reg reg,
			       uint8_t *val)
{
	struct astlpc_ops_data *ops_data = binding_data;
	uint32_t addr;

	if (reg == MCTP_ASTLPC_KCS_REG_STATUS)
		addr = ops_data->kcs_stat_addr;
	else if (reg == MCTP_ASTLPC_KCS_REG_DATA)
		addr = ops_data->kcs_data_addr;
	else
		return OPAL_PARAMETER;

	*val = lpc_inb(addr);

	return OPAL_SUCCESS;
}

static int astlpc_kcs_reg_write(void *binding_data,
				enum mctp_binding_astlpc_kcs_reg reg,
				uint8_t val)
{
	struct astlpc_ops_data *ops_data = binding_data;
	uint32_t addr;

	prlog(PR_TRACE, "%s 0x%hhx to %s\n",
			__func__, val, reg ? "status" : "data");

	if (reg == MCTP_ASTLPC_KCS_REG_STATUS)
		addr = ops_data->kcs_stat_addr;
	else if (reg == MCTP_ASTLPC_KCS_REG_DATA)
		addr = ops_data->kcs_data_addr;
	else
		return OPAL_PARAMETER;

	lpc_outb(val, addr);

	return OPAL_SUCCESS;
}

static int astlpc_read(void *binding_data, void *buf, long offset,
		       size_t len)
{
	struct astlpc_ops_data *ops_data = binding_data;

	prlog(PR_TRACE, "%s %zu bytes from 0x%lx (lpc: 0x%lx)\n",
			__func__, len, offset,
			ops_data->lpc_fw_addr + offset);
	return lpc_fw_read(ops_data->lpc_fw_addr + offset, buf, len);
}

static int astlpc_write(void *binding_data, const void *buf,
			long offset, size_t len)
{
	struct astlpc_ops_data *ops_data = binding_data;

	prlog(PR_TRACE, "%s %zu bytes to offset 0x%lx (lpc: 0x%lx)\n",
			__func__, len, offset,
			ops_data->lpc_fw_addr + offset);
	return lpc_fw_write(ops_data->lpc_fw_addr + offset, buf, len);
}

static const struct mctp_binding_astlpc_ops astlpc_ops = {
	.kcs_read = astlpc_kcs_reg_read,
	.kcs_write = astlpc_kcs_reg_write,
	.lpc_read = astlpc_read,
	.lpc_write = astlpc_write,
};

/* we need a poller to crank the mctp state machine during boot */
static void astlpc_poller(void *data)
{
	struct mctp_binding_astlpc *astlpc = (struct mctp_binding_astlpc *)data;

	if (astlpc)
		mctp_astlpc_poll(astlpc);
}

/* at runtime the interrupt should handle it */
static void astlpc_interrupt(uint32_t chip_id __unused,
			     uint32_t irq_msk __unused)
{
	if (astlpc)
		mctp_astlpc_poll(astlpc);
}

static struct lpc_client kcs_lpc_client = {
	.reset = NULL,
	.interrupt = astlpc_interrupt,
};

static void drain_odr(struct astlpc_ops_data *ops_data)
{
	uint8_t kcs_status, kcs_data;
	uint8_t drain_counter = 255;

	astlpc_kcs_reg_read(ops_data, MCTP_ASTLPC_KCS_REG_STATUS, &kcs_status);

	while (--drain_counter && (kcs_status & KCS_STATUS_OBF)) {
		astlpc_kcs_reg_read(ops_data, MCTP_ASTLPC_KCS_REG_DATA, &kcs_data);
		time_wait_ms(5);
		astlpc_kcs_reg_read(ops_data, MCTP_ASTLPC_KCS_REG_STATUS, &kcs_status);
	}
}

static int astlpc_binding(void)
{
	struct mctp_bus *bus;
	int counter = 0;

	ops_data = zalloc(sizeof(struct astlpc_ops_data));
	if (!ops_data)
		return OPAL_NO_MEM;

	/*
	 * Current OpenBMC systems put the MCTP buffer 1MB down from
	 * the end of the LPC FW range.
	 *
	 * The size of the FW range is: 0x1000_0000 so the window be at:
	 *
	 *   0x1000_0000 - 2**20 == 0xff00000
	 */
	ops_data->lpc_fw_addr = 0xff00000;

	/* values chosen by the OpenBMC driver */
	ops_data->kcs_data_addr = KCS_DATA_REG;
	ops_data->kcs_stat_addr = KCS_STATUS_REG;

	/* Initialise the binding */
	astlpc = mctp_astlpc_init(MCTP_BINDING_ASTLPC_MODE_HOST,
				  DESIRED_MTU,
				  NULL,
				  &astlpc_ops,
				  ops_data);
	if (!astlpc) {
		prlog(PR_ERR, "binding init failed\n");
		return OPAL_HARDWARE;
	}

	/* Read and discard any potentially stale messages in the ODR */
	drain_odr(ops_data);

	/* Register the binding to the LPC bus we are using for this
	 * MCTP configuration.
	 */
	if (mctp_register_bus(mctp,
			      mctp_binding_astlpc_core(astlpc),
			      HOST_EID)) {
		prlog(PR_ERR, "failed to register bus\n");
		goto err;
	}

	/* lpc/kcs status register poller */
	opal_add_poller(astlpc_poller, astlpc);

	/* Don't start sending messages to the BMC until the bus has
	 * been registered and tx has been enabled
	 */
	bus = mctp_binding_astlpc_core(astlpc)->bus;

	while ((bus == NULL) ||
	      (mctp_bus_get_state(bus) == mctp_bus_state_constructed)) {
		if (++counter >= 1000) {
			prlog(PR_ERR, "failed to initialize MCTP channel\n");
			goto err;
		}
		time_wait_ms(5);

		/* Update bus pointer if it is a nullptr */
		if (bus == NULL)
			bus = mctp_binding_astlpc_core(astlpc)->bus;
	}

	return OPAL_SUCCESS;

err:
	mctp_astlpc_destroy(astlpc);
	free(ops_data);

	return OPAL_HARDWARE;
}

static void *mctp_malloc(size_t size) { return malloc(size); }
static void mctp_free(void *ptr) { return free(ptr); }
static void *mctp_realloc(void *ptr, size_t size)
{
	return realloc(ptr, size);
}

#ifdef AST_MCTP_DEBUG
char buffer[320];
static void mctp_log(int log_lvl, const char *fmt, va_list va)
{
	snprintf(buffer, sizeof(buffer), "%s\n", fmt);
	vprlog(log_lvl, buffer, va);
}
#endif

int ast_mctp_message_tx(bool tag_owner, uint8_t msg_tag,
			uint8_t *msg, int msg_len)
{
	unsigned long stop_time;
	int rc = OPAL_SUCCESS;

	lock(&mctp_lock);

	rc = mctp_message_tx(mctp, BMC_EID, tag_owner, msg_tag,
			     msg, msg_len);
	unlock(&mctp_lock);

	/* do not poll when we respond to a BMC request */
	if (tag_owner)
		return rc;

	/* read the Rx_complete command out of the ODR */
	stop_time = mftb() + msecs_to_tb(TX_POLL_MAX);
	while (mftb() < stop_time && !mctp_astlpc_tx_done(astlpc))
		mctp_astlpc_poll(astlpc);

	return rc;
}

static void message_rx(uint8_t eid, bool tag_owner,
		       uint8_t msg_tag, void *data __unused,
		       void *vmsg, size_t len)
{
	uint8_t *msg = (uint8_t *)vmsg;

	prlog(PR_TRACE, "message received: msg type: %x, len %zd"
			" (eid: %d), rx tag %d owner %d\n",
			 *msg, len, eid, tag_owner, msg_tag);

	/* The first byte defines the type of MCTP packet payload
	 * contained in the message data portion of the MCTP message.
	 * (See DSP0236 for more details about MCTP packet fields).
	 * For now we only support PLDM over MCTP.
	 */
	switch (*msg) {
	case MCTP_MSG_TYPE_PLDM:
		/* handle the PLDM message */
		pldm_mctp_message_rx(eid, tag_owner, msg_tag,
				     msg + sizeof(uint8_t),
				     len - sizeof(uint8_t));
		break;
	default:
		prlog(PR_ERR, "%s - not a pldm message type (type: %x)\n",
			      __func__, *msg);
	}
}

/*
 * Initialize mctp binding for hbrt and provide interfaces for sending
 * and receiving mctp messages.
 */
int ast_mctp_init(void)
{
	uint32_t kcs_serial_irq;
	struct dt_node *n;

	/* Search mctp node */
	n = dt_find_compatible_node(dt_root, NULL, "mctp");
	if (!n) {
		prlog(PR_ERR, "No MCTP device\n");
		return OPAL_PARAMETER;
	}

	/* skiboot's malloc/free/realloc are macros so they need
	 * wrappers
	 */
	mctp_set_alloc_ops(mctp_malloc, mctp_free, mctp_realloc);

	/*
	 * /-----\                                        /---------\
	 * | bmc | (eid: 8) <- lpc pcie / kcs -> (eid: 9) | skiboot |
	 * \-----/                                        \---------/
	 */
	mctp = mctp_init();
	if (!mctp) {
		prlog(PR_ERR, "mctp init failed\n");
		return OPAL_HARDWARE;
	}

#ifdef AST_MCTP_DEBUG
	/* Setup the trace hook */
	mctp_set_log_custom(mctp_log);
#endif

	/* Set the max message size to be large enough */
	mctp_set_max_message_size(mctp, HOST_MAX_INCOMING_MESSAGE_ALLOCATION);

	/* Setup the message rx callback */
	mctp_set_rx_all(mctp, message_rx, NULL);

	/* Initialize the binding */
	if (astlpc_binding())
		goto err;

	/* register an lpc client so we get an interrupt */
	kcs_serial_irq = dt_prop_get_u32(n, "interrupts");
	kcs_lpc_client.interrupts = LPC_IRQ(kcs_serial_irq);
	lpc_register_client(dt_get_chip_id(n), &kcs_lpc_client, "lpc-mctp",
				IRQ_ATTR_TARGET_OPAL);

	return OPAL_SUCCESS;

err:
	prlog(PR_ERR, "Unable to initialize MCTP\n");
	mctp_destroy(mctp);
	mctp = NULL;

	return OPAL_HARDWARE;
}

void ast_mctp_exit(void)
{
	if (astlpc) {
		mctp_astlpc_destroy(astlpc);
		astlpc = NULL;
	}

	if (mctp) {
		mctp_destroy(mctp);
		mctp = NULL;
	}
}
