// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Base support for OPAL calls
 *
 * Copyright 2013-2019 IBM Corp.
 */

#include <skiboot.h>
#include <opal.h>
#include <stack.h>
#include <lock.h>
#include <fsp.h>
#include <cpu.h>
#include <interrupts.h>
#include <op-panel.h>
#include <device.h>
#include <console.h>
#include <trace.h>
#include <timebase.h>
#include <affinity.h>
#include <opal-msg.h>
#include <timer.h>
#include <elf-abi.h>
#include <errorlog.h>
#include <occ.h>

/* Pending events to signal via opal_poll_events */
uint64_t opal_pending_events;

/* OPAL dispatch table defined in head.S */
extern const uint64_t opal_branch_table[];

/* Number of args expected for each call. */
static const u8 opal_num_args[OPAL_LAST+1];

/* OPAL anchor node */
struct dt_node *opal_node;

/* mask of dynamic vs fixed events; opal_allocate_dynamic_event will
 * only allocate from this range */
static const uint64_t opal_dynamic_events_mask = 0xffffffff00000000ul;
static uint64_t opal_dynamic_events;

extern uint32_t attn_trigger;
extern uint32_t hir_trigger;


void opal_table_init(void)
{
	struct opal_table_entry *s = __opal_table_start;
	struct opal_table_entry *e = __opal_table_end;

	prlog(PR_DEBUG, "OPAL table: %p .. %p, branch table: %p\n",
	      s, e, opal_branch_table);
	while(s < e) {
		((uint64_t *)opal_branch_table)[s->token] = function_entry_address(s->func);
		((u8 *)opal_num_args)[s->token] = s->nargs;
		s++;
	}
}

/* Called from head.S, thus no prototype */
long opal_bad_token(uint64_t token);

long opal_bad_token(uint64_t token)
{
	/**
	 * @fwts-label OPALBadToken
	 * @fwts-advice OPAL was called with a bad token. On POWER8 and
	 * earlier, Linux kernels had a bug where they wouldn't check
	 * if firmware supported particular OPAL calls before making them.
	 * It is, in fact, harmless for these cases. On systems newer than
	 * POWER8, this should never happen and indicates a kernel bug
	 * where OPAL_CHECK_TOKEN isn't being called where it should be.
	 */
	prlog(PR_ERR, "OPAL: Called with bad token %lld !\n", token);

	return OPAL_PARAMETER;
}

#ifdef OPAL_TRACE_ENTRY
static void opal_trace_entry(struct stack_frame *eframe __unused)
{
	union trace t;
	unsigned nargs, i;

	if (eframe->gpr[0] > OPAL_LAST)
		nargs = 0;
	else
		nargs = opal_num_args[eframe->gpr[0]];

	t.opal.token = cpu_to_be64(eframe->gpr[0]);
	t.opal.lr = cpu_to_be64(eframe->lr);
	t.opal.sp = cpu_to_be64(eframe->gpr[1]);
	for(i=0; i<nargs; i++)
		t.opal.r3_to_11[i] = cpu_to_be64(eframe->gpr[3+i]);

	trace_add(&t, TRACE_OPAL, offsetof(struct trace_opal, r3_to_11[nargs]));
}
#endif

/*
 * opal_quiesce_state is used as a lock. Don't use an actual lock to avoid
 * lock busting.
 */
static uint32_t opal_quiesce_state;	/* 0 or QUIESCE_HOLD/QUIESCE_REJECT */
static int32_t opal_quiesce_owner;	/* PIR */
static int32_t opal_quiesce_target;	/* -1 or PIR */

static int64_t opal_check_token(uint64_t token);

/* Called from head.S, thus no prototype */
int64_t opal_entry_check(struct stack_frame *eframe);

int64_t opal_entry_check(struct stack_frame *eframe)
{
	struct cpu_thread *cpu = this_cpu();
	uint64_t token = eframe->gpr[0];

	if (cpu->pir != mfspr(SPR_PIR)) {
		printf("CPU MISMATCH ! PIR=%04lx cpu @%p -> pir=%04x token=%llu\n",
		       mfspr(SPR_PIR), cpu, cpu->pir, token);
		abort();
	}

#ifdef OPAL_TRACE_ENTRY
	opal_trace_entry(eframe);
#endif

	if (!opal_check_token(token))
		return opal_bad_token(token);

	if (!opal_quiesce_state && cpu->in_opal_call > 1) {
		disable_fast_reboot("Kernel re-entered OPAL");
		switch (token) {
		case OPAL_CONSOLE_READ:
		case OPAL_CONSOLE_WRITE:
		case OPAL_CONSOLE_WRITE_BUFFER_SPACE:
		case OPAL_CONSOLE_FLUSH:
		case OPAL_POLL_EVENTS:
		case OPAL_CHECK_TOKEN:
		case OPAL_CEC_REBOOT:
		case OPAL_CEC_REBOOT2:
		case OPAL_SIGNAL_SYSTEM_RESET:
			break;
		default:
			printf("CPU ATTEMPT TO RE-ENTER FIRMWARE! PIR=%04lx cpu @%p -> pir=%04x token=%llu\n",
			       mfspr(SPR_PIR), cpu, cpu->pir, token);
			if (cpu->in_opal_call > 2) {
				printf("Emergency stack is destroyed, can't continue.\n");
				abort();
			}
			return OPAL_INTERNAL_ERROR;
		}
	}

	cpu->entered_opal_call_at = mftb();
	return OPAL_SUCCESS;
}

int64_t opal_exit_check(int64_t retval, struct stack_frame *eframe);

int64_t opal_exit_check(int64_t retval, struct stack_frame *eframe)
{
	struct cpu_thread *cpu = this_cpu();
	uint64_t token = eframe->gpr[0];
	uint64_t now = mftb();
	uint64_t call_time = tb_to_msecs(now - cpu->entered_opal_call_at);

	if (!cpu->in_opal_call) {
		disable_fast_reboot("Un-accounted firmware entry");
		printf("CPU UN-ACCOUNTED FIRMWARE ENTRY! PIR=%04lx cpu @%p -> pir=%04x token=%llu retval=%lld\n",
		       mfspr(SPR_PIR), cpu, cpu->pir, token, retval);
		cpu->in_opal_call++; /* avoid exit path underflowing */
	} else {
		if (cpu->in_opal_call > 2) {
			printf("Emergency stack is destroyed, can't continue.\n");
			abort();
		}
		if (!list_empty(&cpu->locks_held)) {
			prlog(PR_ERR, "OPAL exiting with locks held, pir=%04x token=%llu retval=%lld\n",
			      cpu->pir, token, retval);
			drop_my_locks(true);
		}
	}

	if (call_time > 100 && token != OPAL_RESYNC_TIMEBASE) {
		prlog((call_time < 1000) ? PR_DEBUG : PR_WARNING,
		      "Spent %llu msecs in OPAL call %llu!\n",
		      call_time, token);
	}

	cpu->current_token = 0;

	return retval;
}

int64_t opal_quiesce(uint32_t quiesce_type, int32_t cpu_target)
{
	struct cpu_thread *cpu = this_cpu();
	struct cpu_thread *target = NULL;
	struct cpu_thread *c;
	uint64_t end;
	bool stuck = false;

	if (cpu_target >= 0) {
		target = find_cpu_by_server(cpu_target);
		if (!target)
			return OPAL_PARAMETER;
	} else if (cpu_target != -1) {
		return OPAL_PARAMETER;
	}

	if (quiesce_type == QUIESCE_HOLD || quiesce_type == QUIESCE_REJECT) {
		if (cmpxchg32(&opal_quiesce_state, 0, quiesce_type) != 0) {
			if (opal_quiesce_owner != cpu->pir) {
				/*
				 * Nested is allowed for now just for
				 * internal uses, so an error is returned
				 * for OS callers, but no error message
				 * printed if we are nested.
				 */
				printf("opal_quiesce already quiescing\n");
			}
			return OPAL_BUSY;
		}
		opal_quiesce_owner = cpu->pir;
		opal_quiesce_target = cpu_target;
	}

	if (opal_quiesce_owner != cpu->pir) {
		printf("opal_quiesce CPU does not own quiesce state (must call QUIESCE_HOLD or QUIESCE_REJECT)\n");
		return OPAL_BUSY;
	}

	/* Okay now we own the quiesce state */

	if (quiesce_type == QUIESCE_RESUME ||
			quiesce_type == QUIESCE_RESUME_FAST_REBOOT) {
		bust_locks = false;
		sync(); /* release barrier vs opal entry */
		if (target) {
			target->quiesce_opal_call = 0;
		} else {
			for_each_cpu(c) {
				if (quiesce_type == QUIESCE_RESUME_FAST_REBOOT)
					c->in_opal_call = 0;

				if (c == cpu) {
					assert(!c->quiesce_opal_call);
					continue;
				}
				c->quiesce_opal_call = 0;
			}
		}
		sync();
		opal_quiesce_state = 0;
		return OPAL_SUCCESS;
	}

	if (quiesce_type == QUIESCE_LOCK_BREAK) {
		if (opal_quiesce_target != -1) {
			printf("opal_quiesce has not quiesced all CPUs (must target -1)\n");
			return OPAL_BUSY;
		}
		bust_locks = true;
		return OPAL_SUCCESS;
	}

	if (target) {
		target->quiesce_opal_call = quiesce_type;
	} else {
		for_each_cpu(c) {
			if (c == cpu)
				continue;
			c->quiesce_opal_call = quiesce_type;
		}
	}

	sync(); /* Order stores to quiesce_opal_call vs loads of in_opal_call */

	end = mftb() + msecs_to_tb(1000);

	smt_lowest();
	if (target) {
		while (target->in_opal_call) {
			if (tb_compare(mftb(), end) == TB_AAFTERB) {
				printf("OPAL quiesce CPU:%04x stuck in OPAL\n", target->pir);
				stuck = true;
				break;
			}
			barrier();
		}
	} else {
		for_each_cpu(c) {
			if (c == cpu)
				continue;
			while (c->in_opal_call) {
				if (tb_compare(mftb(), end) == TB_AAFTERB) {
					printf("OPAL quiesce CPU:%04x stuck in OPAL\n", c->pir);
					stuck = true;
					break;
				}
				barrier();
			}
		}
	}
	smt_medium();
	sync(); /* acquire barrier vs opal entry */

	if (stuck) {
		printf("OPAL quiesce could not kick all CPUs out of OPAL\n");
		return OPAL_PARTIAL;
	}

	return OPAL_SUCCESS;
}
opal_call(OPAL_QUIESCE, opal_quiesce, 2);

void __opal_register(uint64_t token, void *func, unsigned int nargs)
{
	assert(token <= OPAL_LAST);

	((uint64_t *)opal_branch_table)[token] = function_entry_address(func);
	((u8 *)opal_num_args)[token] = nargs;
}

/*
 * add_opal_firmware_exports_node: adds properties to the device-tree which
 * the OS will then change into sysfs nodes.
 * The properties must be placed under /ibm,opal/firmware/exports.
 * The new sysfs nodes are created under /opal/exports.
 * To be correctly exported the properties must contain:
 * 	name
 * 	base memory location (u64)
 * 	size 		     (u64)
 */
static void add_opal_firmware_exports_node(struct dt_node *node)
{
	struct dt_node *exports = dt_new(node, "exports");
	uint64_t sym_start = (uint64_t)__sym_map_start;
	uint64_t sym_size = (uint64_t)__sym_map_end - sym_start;

	/*
	 * These property names will be used by Linux as the user-visible file
	 * name, so make them meaningful if possible. We use _ as the separator
	 * here to remain consistent with existing file names in /sys/opal.
	 */
	dt_add_property_u64s(exports, "symbol_map", sym_start, sym_size);
	dt_add_property_u64s(exports, "hdat_map", SPIRA_HEAP_BASE,
				SPIRA_HEAP_SIZE);
#ifdef SKIBOOT_GCOV
	dt_add_property_u64s(exports, "gcov", SKIBOOT_BASE,
				HEAP_BASE - SKIBOOT_BASE);
#endif
}

static void add_opal_firmware_node(void)
{
	struct dt_node *firmware = dt_new(opal_node, "firmware");
	uint64_t sym_start = (uint64_t)__sym_map_start;
	uint64_t sym_size = (uint64_t)__sym_map_end - sym_start;

	dt_add_property_string(firmware, "compatible", "ibm,opal-firmware");
	dt_add_property_string(firmware, "name", "firmware");
	dt_add_property_string(firmware, "version", version);
	/*
	 * As previous OS versions use symbol-map located at
	 * /ibm,opal/firmware we will keep a copy of symbol-map here
	 * for backwards compatibility
	 */
	dt_add_property_u64s(firmware, "symbol-map", sym_start, sym_size);

	add_opal_firmware_exports_node(firmware);
}

void add_opal_node(void)
{
	uint64_t base, entry, size;
	extern uint32_t opal_entry;
	extern uint32_t boot_entry;
	struct dt_node *opal_event;

	/* XXX TODO: Reorg this. We should create the base OPAL
	 * node early on, and have the various sub modules populate
	 * their own entries (console etc...)
	 *
	 * The logic of which console backend to use should be
	 * extracted
	 */

	entry = (uint64_t)&opal_entry;
	base = SKIBOOT_BASE;
	size = (CPU_STACKS_BASE +
		(uint64_t)(cpu_max_pir + 1) * STACK_SIZE) - SKIBOOT_BASE;

	opal_node = dt_new_check(dt_root, "ibm,opal");
	dt_add_property_cells(opal_node, "#address-cells", 0);
	dt_add_property_cells(opal_node, "#size-cells", 0);

	if (proc_gen < proc_gen_p9)
		dt_add_property_strings(opal_node, "compatible", "ibm,opal-v2",
					"ibm,opal-v3");
	else
		dt_add_property_strings(opal_node, "compatible", "ibm,opal-v3");

	dt_add_property_cells(opal_node, "opal-msg-async-num", OPAL_MAX_ASYNC_COMP);
	dt_add_property_cells(opal_node, "opal-msg-size", OPAL_MSG_SIZE);
	dt_add_property_u64(opal_node, "opal-base-address", base);
	dt_add_property_u64(opal_node, "opal-entry-address", entry);
	dt_add_property_u64(opal_node, "opal-boot-address", (uint64_t)&boot_entry);
	dt_add_property_u64(opal_node, "opal-runtime-size", size);

	/* Add irqchip interrupt controller */
	opal_event = dt_new(opal_node, "event");
	dt_add_property_strings(opal_event, "compatible", "ibm,opal-event");
	dt_add_property_cells(opal_event, "#interrupt-cells", 0x1);
	dt_add_property(opal_event, "interrupt-controller", NULL, 0);

	add_opal_firmware_node();
	add_associativity_ref_point();
	memcons_add_properties();
}

static struct lock evt_lock = LOCK_UNLOCKED;

void opal_update_pending_evt(uint64_t evt_mask, uint64_t evt_values)
{
	uint64_t new_evts;

	lock(&evt_lock);
	new_evts = (opal_pending_events & ~evt_mask) | evt_values;
	if (opal_pending_events != new_evts) {
		uint64_t tok;

#ifdef OPAL_TRACE_EVT_CHG
		printf("OPAL: Evt change: 0x%016llx -> 0x%016llx\n",
		       opal_pending_events, new_evts);
#endif
		/*
		 * If an event gets *set* while we are in a different call chain
		 * than opal_handle_interrupt() or opal_handle_hmi(), then we
		 * artificially generate an interrupt (OCC interrupt specifically)
		 * to ensure that Linux properly broadcast the event change internally
		 */
		if ((new_evts & ~opal_pending_events) != 0) {
			tok = this_cpu()->current_token;
			if (tok != OPAL_HANDLE_INTERRUPT && tok != OPAL_HANDLE_HMI)
				occ_send_dummy_interrupt();
		}
		opal_pending_events = new_evts;
	}
	unlock(&evt_lock);
}

uint64_t opal_dynamic_event_alloc(void)
{
	uint64_t new_event;
	int n;

	lock(&evt_lock);

	/* Create the event mask. This set-bit will be within the event mask
	 * iff there are free events, or out of the mask if there are no free
	 * events. If opal_dynamic_events is all ones (ie, all events are
	 * dynamic, and allocated), then ilog2 will return -1, and we'll have a
	 * zero mask.
	 */
	n = ilog2(~opal_dynamic_events);
	new_event = 1ull << n;

	/* Ensure we're still within the allocatable dynamic events range */
	if (new_event & opal_dynamic_events_mask)
		opal_dynamic_events |= new_event;
	else
		new_event = 0;

	unlock(&evt_lock);
	return new_event;
}

void opal_dynamic_event_free(uint64_t event)
{
	lock(&evt_lock);
	opal_dynamic_events &= ~event;
	unlock(&evt_lock);
}

static uint64_t opal_test_func(uint64_t arg)
{
	printf("OPAL: Test function called with arg 0x%llx\n", arg);

	return 0xfeedf00d;
}
opal_call(OPAL_TEST, opal_test_func, 1);

struct opal_poll_entry {
	struct list_node	link;
	void			(*poller)(void *data);
	void			*data;
};

static struct list_head opal_pollers = LIST_HEAD_INIT(opal_pollers);
static struct lock opal_poll_lock = LOCK_UNLOCKED;

void opal_add_poller(void (*poller)(void *data), void *data)
{
	struct opal_poll_entry *ent;

	ent = zalloc(sizeof(struct opal_poll_entry));
	assert(ent);
	ent->poller = poller;
	ent->data = data;
	lock(&opal_poll_lock);
	list_add_tail(&opal_pollers, &ent->link);
	unlock(&opal_poll_lock);
}

void opal_del_poller(void (*poller)(void *data))
{
	struct opal_poll_entry *ent;

	/* XXX This is currently unused. To solve various "interesting"
	 * locking issues, the pollers are run locklessly, so if we were
	 * to free them, we would have to be careful, using something
	 * akin to RCU to synchronize with other OPAL entries. For now
	 * if anybody uses it, print a warning and leak the entry, don't
	 * free it.
	 */
	/**
	 * @fwts-label UnsupportedOPALdelpoller
	 * @fwts-advice Currently removing a poller is DANGEROUS and
	 * MUST NOT be done in production firmware.
	 */
	prlog(PR_ALERT, "WARNING: Unsupported opal_del_poller."
	      " Interesting locking issues, don't call this.\n");

	lock(&opal_poll_lock);
	list_for_each(&opal_pollers, ent, link) {
		if (ent->poller == poller) {
			list_del(&ent->link);
			/* free(ent); */
			break;
		}
	}
	unlock(&opal_poll_lock);
}

void opal_run_pollers(void)
{
	static int pollers_with_lock_warnings = 0;
	static int poller_recursion = 0;
	struct opal_poll_entry *poll_ent;
	bool was_in_poller;

	/* Don't re-enter on this CPU, unless it was an OPAL re-entry */
	if (this_cpu()->in_opal_call == 1 && this_cpu()->in_poller) {

		/**
		 * @fwts-label OPALPollerRecursion
		 * @fwts-advice Recursion detected in opal_run_pollers(). This
		 * indicates a bug in OPAL where a poller ended up running
		 * pollers, which doesn't lead anywhere good.
		 */
		poller_recursion++;
		if (poller_recursion <= 16) {
			disable_fast_reboot("Poller recursion detected.");
			prlog(PR_ERR, "OPAL: Poller recursion detected.\n");
			backtrace();

		}

		if (poller_recursion == 16)
			prlog(PR_ERR, "OPAL: Squashing future poller recursion warnings (>16).\n");

		return;
	}
	was_in_poller = this_cpu()->in_poller;
	this_cpu()->in_poller = true;

	if (!list_empty(&this_cpu()->locks_held) && pollers_with_lock_warnings < 64) {
		/**
		 * @fwts-label OPALPollerWithLock
		 * @fwts-advice opal_run_pollers() was called with a lock
		 * held, which could lead to deadlock if not excessively
		 * lucky/careful.
		 */
		prlog(PR_ERR, "Running pollers with lock held !\n");
		dump_locks_list();
		backtrace();
		pollers_with_lock_warnings++;
		if (pollers_with_lock_warnings == 64) {
			/**
			 * @fwts-label OPALPollerWithLock64
			 * @fwts-advice Your firmware is buggy, see the 64
			 * messages complaining about opal_run_pollers with
			 * lock held.
			 */
			prlog(PR_ERR, "opal_run_pollers with lock run 64 "
			      "times, disabling warning.\n");
		}
	}

	/* We run the timers first */
	check_timers(false);

	/* The pollers are run lokelessly, see comment in opal_del_poller */
	list_for_each(&opal_pollers, poll_ent, link)
		poll_ent->poller(poll_ent->data);

	/* Disable poller flag */
	this_cpu()->in_poller = was_in_poller;

	/* On debug builds, print max stack usage */
	check_stacks();
}

static int64_t opal_poll_events(__be64 *outstanding_event_mask)
{

	if (!opal_addr_valid(outstanding_event_mask))
		return OPAL_PARAMETER;

	/* Check if we need to trigger an attn for test use */
	if (attn_trigger == 0xdeadbeef) {
		prlog(PR_EMERG, "Triggering attn\n");
		assert(false);
	}

	opal_run_pollers();

	if (outstanding_event_mask)
		*outstanding_event_mask = cpu_to_be64(opal_pending_events);

	return OPAL_SUCCESS;
}
opal_call(OPAL_POLL_EVENTS, opal_poll_events, 1);

static int64_t opal_check_token(uint64_t token)
{
	if (token > OPAL_LAST)
		return OPAL_TOKEN_ABSENT;

	if (opal_branch_table[token])
		return OPAL_TOKEN_PRESENT;

	return OPAL_TOKEN_ABSENT;
}
opal_call(OPAL_CHECK_TOKEN, opal_check_token, 1);

struct opal_sync_entry {
	struct list_node	link;
	bool			(*notify)(void *data);
	void			*data;
};

static struct list_head opal_syncers = LIST_HEAD_INIT(opal_syncers);

void opal_add_host_sync_notifier(bool (*notify)(void *data), void *data)
{
	struct opal_sync_entry *ent;

	ent = zalloc(sizeof(struct opal_sync_entry));
	assert(ent);
	ent->notify = notify;
	ent->data = data;
	list_add_tail(&opal_syncers, &ent->link);
}

/*
 * Remove a host sync notifier for given callback and data
 */
void opal_del_host_sync_notifier(bool (*notify)(void *data), void *data)
{
	struct opal_sync_entry *ent;

	list_for_each(&opal_syncers, ent, link) {
		if (ent->notify == notify && ent->data == data) {
			list_del(&ent->link);
			free(ent);
			return;
		}
	}
}

/*
 * OPAL call to handle host kexec'ing scenario
 */
static int64_t opal_sync_host_reboot(void)
{
	struct opal_sync_entry *ent, *nxt;
	int ret = OPAL_SUCCESS;

	list_for_each_safe(&opal_syncers, ent, nxt, link)
		if (! ent->notify(ent->data))
			ret = OPAL_BUSY_EVENT;

	return ret;
}
opal_call(OPAL_SYNC_HOST_REBOOT, opal_sync_host_reboot, 0);
