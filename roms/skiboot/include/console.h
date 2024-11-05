// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2018 IBM Corp. */

#ifndef __CONSOLE_H
#define __CONSOLE_H

#include "unistd.h"

/*
 * Our internal console uses the format of BML new-style in-memory
 * console and supports input for setups without a physical console
 * facility or FSP.
 *
 * (This is v3 of the format, the previous one sucked)
 */
struct memcons {
	__be64 magic;
#define MEMCONS_MAGIC	0x6630696567726173LL
	__be64 obuf_phys;
	__be64 ibuf_phys;
	__be32 obuf_size;
	__be32 ibuf_size;
	__be32 out_pos;
#define MEMCONS_OUT_POS_WRAP	0x80000000u
#define MEMCONS_OUT_POS_MASK	0x00ffffffu
	__be32 in_prod;
	__be32 in_cons;
};

extern struct memcons memcons;

#define INMEM_CON_IN_LEN	16
#define INMEM_CON_OUT_LEN	(INMEM_CON_LEN - INMEM_CON_IN_LEN)

/* Console driver */
struct con_ops {
	size_t (*write)(const char *buf, size_t len);
	size_t (*read)(char *buf, size_t len);
	bool (*poll_read)(void);
};

struct opal_con_ops {
	const char *name;

	/*
	 * OPAL console driver specific init function.
	 */
	void (*init)(void);

	int64_t (*write)(int64_t term, __be64 *__len, const uint8_t *buf);
	int64_t (*read)(int64_t term, __be64 *__len, uint8_t *buf);

	/*
	 * returns the amount of space available in the console write buffer
	 */
	int64_t (*space)(int64_t term_number, __be64 *__length);

	/*
	 * Forces the write buffer to be flushed by the driver
	 */
	int64_t (*flush)(int64_t term_number);
};

extern bool flush_console(void);

extern void set_console(struct con_ops *driver);
extern void set_opal_console(struct opal_con_ops *driver);
extern void init_opal_console(void);

extern void console_complete_flush(void);

extern size_t mambo_console_write(const char *buf, size_t count);
extern void enable_mambo_console(void);

ssize_t console_write(bool flush_to_drivers, const void *buf, size_t count);

extern void clear_console(void);
extern void memcons_add_properties(void);
extern void dummy_console_add_nodes(void);

struct dt_node *add_opal_console_node(int index, const char *type,
	uint32_t write_buffer_size);

/* OPAL console drivers */
extern struct opal_con_ops uart_opal_con;
extern struct opal_con_ops fsp_opal_con;
extern struct opal_con_ops dummy_opal_con;

void mprintf(const char *fmt, ...);

#endif /* __CONSOLE_H */
