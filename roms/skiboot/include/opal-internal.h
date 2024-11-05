// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Internal header for OPAL API related things in skiboot
 *
 * Copyright 2013-2019 IBM Corp.
 */

#ifndef __OPAL_INTERNAL_H
#define __OPAL_INTERNAL_H


#include <skiboot.h>

/* An opal table entry */
struct opal_table_entry {
	void	*func;
	u32	token;
	u32	nargs;
};

#ifdef __CHECKER__
#define __opal_func_test_arg(__func, __nargs) 0
#else
#define __opal_func_test_arg(__func, __nargs) 				\
	sizeof(__func( __test_args##__nargs ))
#endif

#define opal_call(__tok, __func, __nargs)				\
static struct opal_table_entry __e_##__func __used __section(".opal_table") = \
{ .func = __func, .token = __tok,					\
  .nargs = __nargs + 0 * __opal_func_test_arg(__func, __nargs) }

/* Make sure function takes args they claim.  Look away now... */
#define __test_args0
#define __test_args1 0
#define __test_args2 0,0
#define __test_args3 0,0,0
#define __test_args4 0,0,0,0
#define __test_args5 0,0,0,0,0
#define __test_args6 0,0,0,0,0,0
#define __test_args7 0,0,0,0,0,0,0

extern struct opal_table_entry __opal_table_start[];
extern struct opal_table_entry __opal_table_end[];

extern uint64_t opal_pending_events;

extern struct dt_node *opal_node;

extern void opal_table_init(void);
extern void opal_update_pending_evt(uint64_t evt_mask, uint64_t evt_values);
uint64_t opal_dynamic_event_alloc(void);
void opal_dynamic_event_free(uint64_t event);
extern void add_opal_node(void);

#define opal_register(token, func, nargs)				\
	__opal_register((token) + 0*__opal_func_test_arg(func, nargs),	\
			(func), (nargs))
extern void __opal_register(uint64_t token, void *func, unsigned num_args);

int64_t opal_quiesce(uint32_t shutdown_type, int32_t cpu);

/* Warning: no locking at the moment, do at init time only
 *
 * XXX TODO: Add the big RCU-ish "opal API lock" to protect us here
 * which will also be used for other things such as runtime updates
 */
extern void opal_add_poller(void (*poller)(void *data), void *data);
extern void opal_del_poller(void (*poller)(void *data));
extern void opal_run_pollers(void);

/*
 * Warning: no locking, only call that from the init processor
 */
extern void opal_add_host_sync_notifier(bool (*notify)(void *data), void *data);
extern void opal_del_host_sync_notifier(bool (*notify)(void *data), void *data);

/*
 * Opal internal function prototype
 */
struct OpalHMIEvent;
extern int occ_msg_queue_occ_reset(void);

extern unsigned long top_of_ram;

/*
 * Returns true if the address is valid, false otherwise
 *
 * Checks if the passed address belongs to real address space
 * or 0xc000... kernel address space. It also checks that
 * addr <= total physical memory. The magic value 60 comes
 * from 60 bit real address mentioned in section 5.7 of the
 * Power ISA (Book 3S).
 */
static inline bool opal_addr_valid(const void *addr)
{
	unsigned long val = (unsigned long)addr;
	if ((val >> 60) != 0xc && (val >> 60) != 0x0)
		return false;
	val &= ~0xf000000000000000UL;
	if (val > top_of_ram)
		return false;
	return true;
}

#endif /* __OPAL_INTERNAL_H */
