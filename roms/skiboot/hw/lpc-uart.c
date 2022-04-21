// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Serial port hanging off LPC
 *
 * Copyright 2013-2019 IBM Corp.
 */

#include <skiboot.h>
#include <lpc.h>
#include <console.h>
#include <opal.h>
#include <device.h>
#include <interrupts.h>
#include <processor.h>
#include <errorlog.h>
#include <trace.h>
#include <timebase.h>
#include <cpu.h>
#include <chip.h>
#include <io.h>
#include <nvram.h>

DEFINE_LOG_ENTRY(OPAL_RC_UART_INIT, OPAL_PLATFORM_ERR_EVT, OPAL_UART,
		 OPAL_CEC_HARDWARE, OPAL_PREDICTIVE_ERR_GENERAL,
		 OPAL_NA);

/* UART reg defs */
#define REG_RBR		0
#define REG_THR		0
#define REG_DLL		0
#define REG_IER		1
#define REG_DLM		1
#define REG_FCR		2
#define REG_IIR		2
#define REG_LCR		3
#define REG_MCR		4
#define REG_LSR		5
#define REG_MSR		6
#define REG_SCR		7

#define LSR_DR		0x01  /* Data ready */
#define LSR_OE		0x02  /* Overrun */
#define LSR_PE		0x04  /* Parity error */
#define LSR_FE		0x08  /* Framing error */
#define LSR_BI		0x10  /* Break */
#define LSR_THRE	0x20  /* Xmit holding register empty */
#define LSR_TEMT	0x40  /* Xmitter empty */
#define LSR_ERR		0x80  /* Error */

#define LCR_DLAB 	0x80  /* DLL access */

#define IER_RX		0x01
#define IER_THRE	0x02
#define IER_ALL		0x0f

static struct lock uart_lock = LOCK_UNLOCKED;
static struct dt_node *uart_node;
static uint32_t uart_base;
static uint64_t uart_tx_full_time;
static bool has_irq = false, irq_ok, rx_full, tx_full;
static uint8_t tx_room;
static uint8_t cached_ier;
static void *mmio_uart_base;
static int uart_console_policy = UART_CONSOLE_OPAL;
static int lpc_irq = -1;

void uart_set_console_policy(int policy)
{
	uart_console_policy = policy;
}

static void uart_trace(u8 ctx, u8 cnt, u8 irq_state, u8 in_count)
{
	union trace t;

	t.uart.ctx = ctx;
	t.uart.cnt = cnt;
	t.uart.irq_state = irq_state;
	t.uart.in_count = cpu_to_be16(in_count);
	trace_add(&t, TRACE_UART, sizeof(struct trace_uart));
}

static inline uint8_t uart_read(unsigned int reg)
{
	if (mmio_uart_base)
		return in_8(mmio_uart_base + reg);
	else
		return lpc_inb(uart_base + reg);
}

static inline void uart_write(unsigned int reg, uint8_t val)
{
	if (mmio_uart_base)
		out_8(mmio_uart_base + reg, val);
	else
		lpc_outb(val, uart_base + reg);
}

static bool uart_check_tx_room(void)
{
	if (tx_room)
		return true;

	if (uart_read(REG_LSR) & LSR_THRE) {
		/* FIFO is 16 entries */
		tx_room = 16;
		tx_full = false;
		return true;
	}

	return false;
}

/* Must be called with UART lock held */
static void uart_write_thr(uint8_t val)
{
	uart_write(REG_THR, val);

	tx_room--;
	if (tx_room == 0) {
		if (!uart_check_tx_room())
			uart_tx_full_time = mftb();
	}
}

static bool uart_timed_out(unsigned long msecs)
{
	if (uart_check_tx_room())
		return false;

	if (chip_quirk(QUIRK_SLOW_SIM))
		msecs *= 5;

	if (tb_compare(mftb(), uart_tx_full_time + msecs_to_tb(msecs)) == TB_AAFTERB)
		return true;

	return false;
}

static bool uart_wait_tx_room(void)
{
	if (uart_check_tx_room())
		return true;

	smt_lowest();
	while (!uart_check_tx_room()) {
		if (uart_timed_out(100)) {
			smt_medium();
			return false;
		}
	}
	smt_medium();

	return true;
}

static void uart_update_ier(void)
{
	uint8_t ier = 0;

	if (!has_irq)
		return;

	/* If we have never got an interrupt, enable them all,
	 * the first interrupt received will tell us if interrupts
	 * are functional (some boards are missing an EC or FPGA
	 * programming causing LPC interrupts not to work).
	 */
	if (!irq_ok)
		ier = IER_ALL;
	if (!rx_full)
		ier |= IER_RX;
	if (tx_full)
		ier |= IER_THRE;
	if (ier != cached_ier) {
		uart_write(REG_IER, ier);
		cached_ier = ier;
	}
}

bool uart_enabled(void)
{
	return mmio_uart_base || uart_base;
}

/*
 * Internal console driver (output only)
 */
static size_t uart_con_write(const char *buf, size_t len)
{
	size_t written = 0;

	/* If LPC bus is bad, we just swallow data */
	if (!lpc_ok() && !mmio_uart_base)
		return len;

	lock(&uart_lock);
	while (written < len) {
		if (!uart_wait_tx_room())
			break;

		uart_write_thr(buf[written++]);
	}

	if (!written && uart_timed_out(1000)) {
		unlock(&uart_lock);
		return len; /* swallow data */
	}

	unlock(&uart_lock);

	return written;
}

static struct con_ops uart_con_driver = {
	.write = uart_con_write,
};

/*
 * OPAL console driver
 */

/*
 * We implement a simple buffer to buffer input data as some bugs in
 * Linux make it fail to read fast enough after we get an interrupt.
 *
 * We use it on non-interrupt operations as well while at it because
 * it doesn't cost us much and might help in a few cases where Linux
 * is calling opal_poll_events() but not actually reading.
 *
 * Most of the time I expect we'll flush it completely to Linux into
 * it's tty flip buffers so I don't bother with a ring buffer.
 */
#define IN_BUF_SIZE	0x1000
static uint8_t	*in_buf;
static uint32_t	in_count;

/*
 * We implement a ring buffer for output data as well to speed things
 * up a bit. This allows us to have interrupt driven sends. This is only
 * for the output data coming from the OPAL API, not the internal one
 * which is already bufferred.
 */
#define OUT_BUF_SIZE	0x1000
static uint8_t *out_buf;
static uint32_t out_buf_prod;
static uint32_t out_buf_cons;

/* Asynchronous flush, uart_lock must be held */
static int64_t uart_con_flush(void)
{
	bool tx_was_full = tx_full;
	uint32_t out_buf_cons_initial = out_buf_cons;

	while(out_buf_prod != out_buf_cons) {
		if (tx_room == 0) {
			/*
			 * If the interrupt is not functional,
			 * we force a full synchronous flush,
			 * otherwise the Linux console isn't
			 * usable (too slow).
			 */
			if (irq_ok)
				uart_check_tx_room();
			else
				uart_wait_tx_room();
		}
		if (tx_room == 0) {
			tx_full = true;
			break;
		}

		uart_write_thr(out_buf[out_buf_cons++]);
		out_buf_cons %= OUT_BUF_SIZE;
	}
	if (tx_full != tx_was_full)
		uart_update_ier();
	if (out_buf_prod != out_buf_cons) {
		/* Return busy if nothing was flushed this call */
		if (out_buf_cons == out_buf_cons_initial) {
			if (uart_timed_out(1000))
				return OPAL_TIMEOUT;
			return OPAL_BUSY;
		}
		/* Return partial if there's more to flush */
		return OPAL_PARTIAL;
	}

	return OPAL_SUCCESS;
}

static uint32_t uart_tx_buf_space(void)
{
	return OUT_BUF_SIZE - 1 -
		(out_buf_prod + OUT_BUF_SIZE - out_buf_cons) % OUT_BUF_SIZE;
}

static int64_t uart_opal_write(int64_t term_number, __be64 *__length,
			       const uint8_t *buffer)
{
	size_t written = 0, len = be64_to_cpu(*__length);
	int64_t ret = OPAL_SUCCESS;

	if (term_number != 0)
		return OPAL_PARAMETER;

	lock(&uart_lock);

	/* Copy data to out buffer */
	while (uart_tx_buf_space() && len--) {
		out_buf[out_buf_prod++] = *(buffer++);
		out_buf_prod %= OUT_BUF_SIZE;
		written++;
	}

	/* Flush out buffer again */
	uart_con_flush();

	if (!written && uart_timed_out(1000))
		ret = OPAL_TIMEOUT;
	unlock(&uart_lock);

	*__length = cpu_to_be64(written);

	return ret;
}

static int64_t uart_opal_write_buffer_space(int64_t term_number,
					    __be64 *__length)
{
	int64_t ret = OPAL_SUCCESS;
	int64_t tx_buf_len;

	if (term_number != 0)
		return OPAL_PARAMETER;

	lock(&uart_lock);
	tx_buf_len = uart_tx_buf_space();

	if ((tx_buf_len < be64_to_cpu(*__length)) && uart_timed_out(1000))
		ret = OPAL_TIMEOUT;

	*__length = cpu_to_be64(tx_buf_len);
	unlock(&uart_lock);

	return ret;
}

/* Must be called with UART lock held */
static void uart_read_to_buffer(void)
{
	/* As long as there is room in the buffer */
	while(in_count < IN_BUF_SIZE) {
		/* Read status register */
		uint8_t lsr = uart_read(REG_LSR);

		/* Nothing to read ... */
		if ((lsr & LSR_DR) == 0)
			break;

		/* Read and add to buffer */
		in_buf[in_count++] = uart_read(REG_RBR);
	}

	/* If the buffer is full disable the interrupt */
	rx_full = (in_count == IN_BUF_SIZE);
	uart_update_ier();
}

static void uart_adjust_opal_event(void)
{
	if (in_count)
		opal_update_pending_evt(OPAL_EVENT_CONSOLE_INPUT,
					OPAL_EVENT_CONSOLE_INPUT);
	else
		opal_update_pending_evt(OPAL_EVENT_CONSOLE_INPUT, 0);
}

/* This is called with the console lock held */
static int64_t uart_opal_read(int64_t term_number, __be64 *__length,
			      uint8_t *buffer)
{
	size_t req_count = be64_to_cpu(*__length), read_cnt = 0;
	uint8_t lsr = 0;

	if (term_number != 0)
		return OPAL_PARAMETER;
	if (!in_buf)
		return OPAL_INTERNAL_ERROR;

	lock(&uart_lock);

	/* Read from buffer first */
	if (in_count) {
		read_cnt = in_count;
		if (req_count < read_cnt)
			read_cnt = req_count;
		memcpy(buffer, in_buf, read_cnt);
		req_count -= read_cnt;
		if (in_count != read_cnt)
			memmove(in_buf, in_buf + read_cnt, in_count - read_cnt);
		in_count -= read_cnt;
	}

	/*
	 * If there's still room in the user buffer, read from the UART
	 * directly
	 */
	while(req_count) {
		lsr = uart_read(REG_LSR);
		if ((lsr & LSR_DR) == 0)
			break;
		buffer[read_cnt++] = uart_read(REG_RBR);
		req_count--;
	}

	/* Finally, flush whatever's left in the UART into our buffer */
	uart_read_to_buffer();

	uart_trace(TRACE_UART_CTX_READ, read_cnt, tx_full, in_count);

	unlock(&uart_lock);

	/* Adjust the OPAL event */
	uart_adjust_opal_event();

	*__length = cpu_to_be64(read_cnt);
	return OPAL_SUCCESS;
}

static int64_t uart_opal_flush(int64_t term_number)
{
	int64_t rc;

	if (term_number != 0)
		return OPAL_PARAMETER;

	lock(&uart_lock);
	rc = uart_con_flush();
	unlock(&uart_lock);

	return rc;
}

static void __uart_do_poll(u8 trace_ctx)
{
	if (!in_buf)
		return;

	lock(&uart_lock);
	uart_read_to_buffer();
	uart_con_flush();
	uart_trace(trace_ctx, 0, tx_full, in_count);
	unlock(&uart_lock);

	uart_adjust_opal_event();
}

static void uart_console_poll(void *data __unused)
{
	__uart_do_poll(TRACE_UART_CTX_POLL);
}

static void uart_irq(uint32_t chip_id __unused, uint32_t irq_mask __unused)
{
	if (!irq_ok) {
		prlog(PR_DEBUG, "UART: IRQ functional !\n");
		irq_ok = true;
	}
	__uart_do_poll(TRACE_UART_CTX_IRQ);
}

/*
 * Common setup/inits
 */

static void uart_setup_os_passthrough(void)
{
	char *path;

	static struct lpc_client uart_lpc_os_client = {
		.reset = NULL,
		.interrupt = NULL,
		.interrupts = 0
	};

	dt_add_property_strings(uart_node, "status", "ok");
	path = dt_get_path(uart_node);
	dt_add_property_string(dt_chosen, "linux,stdout-path", path);
	free(path);

	/* Setup LPC client for OS interrupts */
	if (lpc_irq >= 0) {
		uint32_t chip_id = dt_get_chip_id(uart_node);
		uart_lpc_os_client.interrupts = LPC_IRQ(lpc_irq);
		lpc_register_client(chip_id, &uart_lpc_os_client,
				    IRQ_ATTR_TARGET_LINUX);
	}
	prlog(PR_DEBUG, "UART: Enabled as OS pass-through\n");
}

static void uart_setup_opal_console(void)
{
	static struct lpc_client uart_lpc_opal_client = {
		.interrupt = uart_irq,
	};

	/* Add the opal console node */
	add_opal_console_node(0, "raw", OUT_BUF_SIZE);

	dt_add_property_string(dt_chosen, "linux,stdout-path",
			       "/ibm,opal/consoles/serial@0");

	/*
	 * We mark the UART as reserved since we don't want the
	 * kernel to start using it with its own 8250 driver
	 */
	dt_add_property_strings(uart_node, "status", "reserved");

	/* Allocate an input buffer */
	in_buf = zalloc(IN_BUF_SIZE);
	out_buf = zalloc(OUT_BUF_SIZE);

	/* Setup LPC client for OPAL interrupts */
	if (lpc_irq >= 0) {
		uint32_t chip_id = dt_get_chip_id(uart_node);
		uart_lpc_opal_client.interrupts = LPC_IRQ(lpc_irq);
		lpc_register_client(chip_id, &uart_lpc_opal_client,
				    IRQ_ATTR_TARGET_OPAL);
		has_irq = true;
	}

	/*
	 * If the interrupt is enabled, turn on RX interrupts (and
	 * only these for now
	 */
	tx_full = rx_full = false;
	uart_update_ier();

	/* Start console poller */
	opal_add_poller(uart_console_poll, NULL);
}

static void uart_init_opal_console(void)
{
	const char *nv_policy;

	/* Update the policy if the corresponding nvram variable
	 * is present
	 */
	nv_policy = nvram_query_dangerous("uart-con-policy");
	if (nv_policy) {
		if (!strcmp(nv_policy, "opal"))
			uart_console_policy = UART_CONSOLE_OPAL;
		else if (!strcmp(nv_policy, "os"))
			uart_console_policy = UART_CONSOLE_OS;
		else
			prlog(PR_WARNING,
			      "UART: Unknown console policy in NVRAM: %s\n",
			      nv_policy);
	}
	if (uart_console_policy == UART_CONSOLE_OPAL)
		uart_setup_opal_console();
	else
		uart_setup_os_passthrough();
}

struct opal_con_ops uart_opal_con = {
	.name = "OPAL UART console",
	.init = uart_init_opal_console,
	.read = uart_opal_read,
	.write = uart_opal_write,
	.space = uart_opal_write_buffer_space,
	.flush = uart_opal_flush,
};

static bool uart_init_hw(unsigned int speed, unsigned int clock)
{
	unsigned int dll = (clock / 16) / speed;

	/* Clear line control */
	uart_write(REG_LCR, 0x00);

	/* Check if the UART responds */
	uart_write(REG_IER, 0x01);
	if (uart_read(REG_IER) != 0x01)
		goto detect_fail;
	uart_write(REG_IER, 0x00);
	if (uart_read(REG_IER) != 0x00)
		goto detect_fail;

	uart_write(REG_LCR, LCR_DLAB);
	uart_write(REG_DLL, dll & 0xff);
	uart_write(REG_DLM, dll >> 8);
	uart_write(REG_LCR, 0x03); /* 8N1 */
	uart_write(REG_MCR, 0x03); /* RTS/DTR */
	uart_write(REG_FCR, 0x07); /* clear & en. fifos */

	/*
	 * On some UART implementations[1], we have observed that characters
	 * written to the UART during early boot (where no RX path is used,
	 * so we don't read from RBR) can cause a character timeout interrupt
	 * once we eventually enable interrupts through the IER. This
	 * interrupt can only be cleared by reading from RBR (even though we've
	 * cleared the RX FIFO!).
	 *
	 * Unfortunately though, the LCR[DR] bit does *not* indicate that there
	 * are characters to be read from RBR, so we may never read it, so the
	 * interrupt continuously fires.
	 *
	 * So, manually clear the timeout interrupt by reading the RBR here.
	 * We discard the read data, but that shouldn't matter as we've just
	 * reset the FIFO anyway.
	 *
	 * 1: seen on the AST2500 SUART. I assume this applies to 2400 too.
	 */
	uart_read(REG_RBR);

	return true;

 detect_fail:
	prerror("UART: Presence detect failed !\n");
	return false;
}

/*
 * early_uart_init() is similar to uart_init() in that it configures skiboot
 * console log to output via a UART. The main differences are that the early
 * version only works with MMIO UARTs and will not setup interrupts or locks.
 */
void early_uart_init(void)
{
	struct dt_node *uart_node;
	u32 clk, baud;

	uart_node = dt_find_compatible_node(dt_root, NULL, "ns16550");
	if (!uart_node)
		return;

	/* Try translate the address, if this fails then it's not a MMIO UART */
	mmio_uart_base = (void *) dt_translate_address(uart_node, 0, NULL);
	if (!mmio_uart_base)
		return;

	clk = dt_prop_get_u32(uart_node, "clock-frequency");
	baud = dt_prop_get_u32(uart_node, "current-speed");

	if (uart_init_hw(baud, clk)) {
		set_console(&uart_con_driver);
		prlog(PR_DEBUG, "UART: Using UART at %p\n", mmio_uart_base);
	} else {
		prerror("UART: Early init failed!");
		mmio_uart_base = NULL;
	}
}

void uart_init(void)
{
	const struct dt_property *prop;
	struct dt_node *n;
	char *path __unused;
	const be32 *irqp;

	/* Clean up after early_uart_init() */
	mmio_uart_base = NULL;

	/* UART lock is in the console path and thus must block
	 * printf re-entrancy
	 */
	uart_lock.in_con_path = true;

	/* We support only one */
	uart_node = n = dt_find_compatible_node(dt_root, NULL, "ns16550");
	if (!n)
		return;

	/* Read the interrupts property if any */
	irqp = dt_prop_get_def(n, "interrupts", NULL);

	/* Now check if the UART is on the root bus. This is the case of
	 * directly mapped UARTs in simulation environments
	 */
	if (n->parent == dt_root) {
		printf("UART: Found at root !\n");
		mmio_uart_base = (void *)dt_translate_address(n, 0, NULL);
		if (!mmio_uart_base) {
			printf("UART: Failed to translate address !\n");
			return;
		}

		/* If it has an interrupt properly, we consider this to be
		 * a direct XICS/XIVE interrupt
		 */
		if (irqp)
			has_irq = true;

	} else {
		if (!lpc_present())
			return;

		/* Get IO base */
		prop = dt_find_property(n, "reg");
		if (!prop) {
			log_simple_error(&e_info(OPAL_RC_UART_INIT),
					 "UART: Can't find reg property\n");
			return;
		}
		if (dt_property_get_cell(prop, 0) != OPAL_LPC_IO) {
			log_simple_error(&e_info(OPAL_RC_UART_INIT),
					 "UART: Only supports IO addresses\n");
			return;
		}
		uart_base = dt_property_get_cell(prop, 1);

		if (irqp) {
			lpc_irq = be32_to_cpu(*irqp);
			prlog(PR_DEBUG, "UART: Using LPC IRQ %d\n", lpc_irq);
		}
	}


	if (!uart_init_hw(dt_prop_get_u32(n, "current-speed"),
			  dt_prop_get_u32(n, "clock-frequency"))) {
		prerror("UART: Initialization failed\n");
		dt_add_property_strings(n, "status", "bad");
		return;
	}

	/*
	 * Mark LPC used by the console (will mark the relevant
	 * locks to avoid deadlocks when flushing the console)
	 */
	lpc_used_by_console();

	/* Install console backend for printf() */
	set_console(&uart_con_driver);
}

