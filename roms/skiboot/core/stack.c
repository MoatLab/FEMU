// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Create/Print backtraces, check stack usage etc.
 *
 * Copyright 2013-2019 IBM Corp.
 */

#include <skiboot.h>
#include <processor.h>
#include <cpu.h>
#include <stack.h>
#include <mem_region.h>
#include <unistd.h>
#include <lock.h>

#define STACK_BUF_ENTRIES	60
static struct bt_entry bt_buf[STACK_BUF_ENTRIES];

/* Dumps backtrace to buffer */
static void __nomcount __backtrace_create(struct bt_entry *entries,
				 unsigned int max_ents,
				 struct bt_metadata *metadata,
				 struct stack_frame *eframe)
{
	unsigned long *fp = (unsigned long *)eframe;
	unsigned long top_adj = top_of_ram;

	/* Assume one stack for early backtraces */
	if (top_of_ram == SKIBOOT_BASE + SKIBOOT_SIZE)
		top_adj = top_of_ram + STACK_SIZE;

	metadata->ents = 0;
	while (max_ents) {
		fp = (unsigned long *)fp[0];
		if (!fp || (unsigned long)fp > top_adj)
			break;
		eframe = (struct stack_frame *)fp;
		if (eframe->magic == STACK_INT_MAGIC) {
			entries->exception_type = eframe->type;
			entries->exception_pc = eframe->pc;
		} else {
			entries->exception_type = 0;
		}
		entries->sp = (unsigned long)fp;
		entries->pc = fp[2];
		entries++;
		metadata->ents++;
		max_ents--;
	}

	metadata->r1_caller = eframe->gpr[1];

	if (fp)
		metadata->token = eframe->gpr[0];
	else
		metadata->token = -1UL;

	metadata->pir = mfspr(SPR_PIR);
}

void __nomcount backtrace_create(struct bt_entry *entries,
				 unsigned int max_ents,
				 struct bt_metadata *metadata)
{
	unsigned long *fp = __builtin_frame_address(0);
	struct stack_frame *eframe = (struct stack_frame *)fp;

	__backtrace_create(entries, max_ents, metadata, eframe);
}

void backtrace_print(struct bt_entry *entries, struct bt_metadata *metadata,
		     char *out_buf, unsigned int *len, bool symbols)
{
	static char bt_text_buf[4096];
	int i, l = 0, max;
	char *buf = out_buf;
	unsigned long bottom, top, normal_top, tbot, ttop;
	char mark;

	if (!out_buf) {
		buf = bt_text_buf;
		max = sizeof(bt_text_buf) - 16;
	} else
		max = *len - 1;

	bottom = cpu_stack_bottom(metadata->pir);
	normal_top = cpu_stack_top(metadata->pir);
	top = cpu_emergency_stack_top(metadata->pir);
	tbot = SKIBOOT_BASE;
	ttop = (unsigned long)&_etext;

	l += snprintf(buf, max, "CPU %04lx Backtrace:\n", metadata->pir);
	for (i = 0; i < metadata->ents && l < max; i++) {
		if (entries->sp < bottom || entries->sp > top)
			mark = '!';
		else if (entries->sp > normal_top)
			mark = 'E';
		else if (entries->pc < tbot || entries->pc > ttop)
			mark = '*';
		else
			mark = ' ';
		l += snprintf(buf + l, max - l,
			      " S: %016lx R: %016lx %c ",
			      entries->sp, entries->pc, mark);
		if (symbols)
			l += snprintf_symbol(buf + l, max - l, entries->pc);
		l += snprintf(buf + l, max - l, "\n");
		if (entries->exception_type) {
			l += snprintf(buf + l, max - l,
				      " --- Interrupt 0x%lx at %016lx ---\n",
				      entries->exception_type, entries->exception_pc);
		}
		entries++;
	}
	if (metadata->token <= OPAL_LAST)
		l += snprintf(buf + l, max - l,
			      " --- OPAL call token: 0x%lx caller R1: 0x%016lx ---\n",
			      metadata->token, metadata->r1_caller);
	else if (metadata->token == -1UL)
		l += snprintf(buf + l, max - l, " --- OPAL boot ---\n");
	if (!out_buf)
		write(stdout->fd, bt_text_buf, l);
	buf[l++] = 0;
	if (len)
		*len = l;
}

/*
 * To ensure that we always get backtrace output we bypass the usual console
 * locking paths. The downside is that when multiple threads need to print
 * a backtrace they garble each other. To prevent this we use a seperate
 * lock to serialise printing of the dumps.
 */
static struct lock bt_lock = LOCK_UNLOCKED;

void backtrace(void)
{
	struct bt_metadata metadata;

	lock(&bt_lock);

	backtrace_create(bt_buf, STACK_BUF_ENTRIES, &metadata);
	backtrace_print(bt_buf, &metadata, NULL, NULL, true);

	unlock(&bt_lock);
}

void backtrace_r1(uint64_t r1)
{
	struct bt_metadata metadata;

	lock(&bt_lock);

	__backtrace_create(bt_buf, STACK_BUF_ENTRIES, &metadata, (struct stack_frame *)r1);
	backtrace_print(bt_buf, &metadata, NULL, NULL, true);

	unlock(&bt_lock);
}

void __nomcount __stack_chk_fail(void);
void __nomcount __stack_chk_fail(void)
{
	static bool failed_once;

	if (failed_once)
		return;
	failed_once = true;
	prlog(PR_EMERG, "Stack corruption detected !\n");
	abort();
}

#ifdef STACK_CHECK_ENABLED

static int64_t lowest_stack_mark = LONG_MAX;
static struct lock stack_check_lock = LOCK_UNLOCKED;

void __nomcount __mcount_stack_check(uint64_t sp, uint64_t lr);
void __nomcount __mcount_stack_check(uint64_t sp, uint64_t lr)
{
	struct cpu_thread *c = this_cpu();
	uint64_t base = (uint64_t)c;
	uint64_t bot = base + sizeof(struct cpu_thread);
	int64_t mark = sp - bot;
	uint64_t top = base + NORMAL_STACK_SIZE;

	/*
	 * Don't check the emergency stack just yet.
	 */
	if (c->in_opal_call > 1)
		return;

	/*
	 * Don't re-enter on this CPU or don't enter at all if somebody
	 * has spotted an overflow
	 */
	if (c->in_mcount)
		return;
	c->in_mcount = true;

	/* Capture lowest stack for this thread */
	if (mark < c->stack_bot_mark) {
		lock(&stack_check_lock);
		c->stack_bot_mark = mark;
		c->stack_bot_pc = lr;
		c->stack_bot_tok = c->current_token;
		backtrace_create(c->stack_bot_bt, CPU_BACKTRACE_SIZE,
				 &c->stack_bot_bt_metadata);
		unlock(&stack_check_lock);

		if (mark < STACK_WARNING_GAP) {
			prlog(PR_EMERG, "CPU %04x Stack usage danger !"
			      " pc=%08llx sp=%08llx (gap=%lld) token=%lld\n",
			      c->pir, lr, sp, mark, c->current_token);
		}
	}

	/* Stack is within bounds? */
	if (sp >= (bot + STACK_SAFETY_GAP) && sp < top) {
		c->in_mcount = false;
		return;
	}
	
	prlog(PR_EMERG, "CPU %04x Stack overflow detected !"
	      " pc=%08llx sp=%08llx (gap=%lld) token=%lld\n",
	      c->pir, lr, sp, mark, c->current_token);
	abort();
}

void check_stacks(void)
{
	struct cpu_thread *c, *lowest = NULL;

	/* We should never call that from mcount */
	assert(!this_cpu()->in_mcount);

	/* Mark ourselves "in_mcount" to avoid deadlock on stack
	 * check lock
	 */
	this_cpu()->in_mcount = true;

	for_each_cpu(c) {
		if (!c->stack_bot_mark ||
		    c->stack_bot_mark >= lowest_stack_mark)
			continue;
		lock(&stack_check_lock);
		if (c->stack_bot_mark < lowest_stack_mark) {
			lowest = c;
			lowest_stack_mark = c->stack_bot_mark;
		}
		unlock(&stack_check_lock);
	}
	if (lowest) {
		lock(&bt_lock);
		prlog(PR_NOTICE, "CPU %04x lowest stack mark %lld bytes left"
		      " pc=%08llx token=%lld\n",
		      lowest->pir, lowest->stack_bot_mark, lowest->stack_bot_pc,
		      lowest->stack_bot_tok);
		backtrace_print(lowest->stack_bot_bt,
				&lowest->stack_bot_bt_metadata,
				NULL, NULL, true);
		unlock(&bt_lock);
	}

	this_cpu()->in_mcount = false;
}
#endif /* STACK_CHECK_ENABLED */
