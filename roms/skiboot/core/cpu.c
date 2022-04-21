// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Code to manage and manipulate CPUs
 *
 * Copyright 2013-2019 IBM Corp.
 */

#include <skiboot.h>
#include <cpu.h>
#include <device.h>
#include <mem_region.h>
#include <opal.h>
#include <stack.h>
#include <trace.h>
#include <affinity.h>
#include <chip.h>
#include <timebase.h>
#include <interrupts.h>
#include <ccan/str/str.h>
#include <ccan/container_of/container_of.h>
#include <xscom.h>

/* The cpu_threads array is static and indexed by PIR in
 * order to speed up lookup from asm entry points
 */
struct cpu_stack {
	union {
		uint8_t	stack[STACK_SIZE];
		struct cpu_thread cpu;
	};
} __align(STACK_SIZE);

static struct cpu_stack * const cpu_stacks = (struct cpu_stack *)CPU_STACKS_BASE;
unsigned int cpu_thread_count;
unsigned int cpu_max_pir;
struct cpu_thread *boot_cpu;
static struct lock reinit_lock = LOCK_UNLOCKED;
static bool hile_supported;
static bool radix_supported;
static unsigned long hid0_hile;
static unsigned long hid0_attn;
static bool sreset_enabled;
static bool ipi_enabled;
static bool pm_enabled;
static bool current_hile_mode = HAVE_LITTLE_ENDIAN;
static bool current_radix_mode = true;
static bool tm_suspend_enabled;

unsigned long cpu_secondary_start __force_data = 0;

struct cpu_job {
	struct list_node	link;
	void			(*func)(void *data);
	void			*data;
	const char		*name;
	bool			complete;
	bool		        no_return;
};

/* attribute const as cpu_stacks is constant. */
unsigned long __attrconst cpu_stack_bottom(unsigned int pir)
{
	return ((unsigned long)&cpu_stacks[pir]) +
		sizeof(struct cpu_thread) + STACK_SAFETY_GAP;
}

unsigned long __attrconst cpu_stack_top(unsigned int pir)
{
	/* This is the top of the normal stack. */
	return ((unsigned long)&cpu_stacks[pir]) +
		NORMAL_STACK_SIZE - STACK_TOP_GAP;
}

unsigned long __attrconst cpu_emergency_stack_top(unsigned int pir)
{
	/* This is the top of the emergency stack, above the normal stack. */
	return ((unsigned long)&cpu_stacks[pir]) +
		NORMAL_STACK_SIZE + EMERGENCY_STACK_SIZE - STACK_TOP_GAP;
}

void __nomcount cpu_relax(void)
{
	/* Relax a bit to give sibling threads some breathing space */
	smt_lowest();
	asm volatile("nop; nop; nop; nop;\n"
		     "nop; nop; nop; nop;\n"
		     "nop; nop; nop; nop;\n"
		     "nop; nop; nop; nop;\n");
	smt_medium();
	barrier();
}

static void cpu_wake(struct cpu_thread *cpu)
{
	/* Is it idle ? If not, no need to wake */
	sync();
	if (!cpu->in_idle)
		return;

	if (proc_gen == proc_gen_p8) {
		/* Poke IPI */
		icp_kick_cpu(cpu);
	} else if (proc_gen == proc_gen_p9 || proc_gen == proc_gen_p10) {
		p9_dbell_send(cpu->pir);
	}
}

/*
 * If chip_id is >= 0, schedule the job on that node.
 * Otherwise schedule the job anywhere.
 */
static struct cpu_thread *cpu_find_job_target(int32_t chip_id)
{
	struct cpu_thread *cpu, *best, *me = this_cpu();
	uint32_t best_count;

	/* We try to find a target to run a job. We need to avoid
	 * a CPU that has a "no return" job on its queue as it might
	 * never be able to process anything.
	 *
	 * Additionally we don't check the list but the job count
	 * on the target CPUs, since that is decremented *after*
	 * a job has been completed.
	 */


	/* First we scan all available primary threads
	 */
	for_each_available_cpu(cpu) {
		if (chip_id >= 0 && cpu->chip_id != chip_id)
			continue;
		if (cpu == me || !cpu_is_thread0(cpu) || cpu->job_has_no_return)
			continue;
		if (cpu->job_count)
			continue;
		lock(&cpu->job_lock);
		if (!cpu->job_count)
			return cpu;
		unlock(&cpu->job_lock);
	}

	/* Now try again with secondary threads included and keep
	 * track of the one with the less jobs queued up. This is
	 * done in a racy way, but it's just an optimization in case
	 * we are overcommitted on jobs. Could could also just pick
	 * a random one...
	 */
	best = NULL;
	best_count = -1u;
	for_each_available_cpu(cpu) {
		if (chip_id >= 0 && cpu->chip_id != chip_id)
			continue;
		if (cpu == me || cpu->job_has_no_return)
			continue;
		if (!best || cpu->job_count < best_count) {
			best = cpu;
			best_count = cpu->job_count;
		}
		if (cpu->job_count)
			continue;
		lock(&cpu->job_lock);
		if (!cpu->job_count)
			return cpu;
		unlock(&cpu->job_lock);
	}

	/* We haven't found anybody, do we have a bestie ? */
	if (best) {
		lock(&best->job_lock);
		return best;
	}

	/* Go away */
	return NULL;
}

/* job_lock is held, returns with it released */
static void queue_job_on_cpu(struct cpu_thread *cpu, struct cpu_job *job)
{
	/* That's bad, the job will never run */
	if (cpu->job_has_no_return) {
		prlog(PR_WARNING, "WARNING ! Job %s scheduled on CPU 0x%x"
		      " which has a no-return job on its queue !\n",
		      job->name, cpu->pir);
		backtrace();
	}
	list_add_tail(&cpu->job_queue, &job->link);
	if (job->no_return)
		cpu->job_has_no_return = true;
	else
		cpu->job_count++;
	if (pm_enabled)
		cpu_wake(cpu);
	unlock(&cpu->job_lock);
}

struct cpu_job *__cpu_queue_job(struct cpu_thread *cpu,
				const char *name,
				void (*func)(void *data), void *data,
				bool no_return)
{
	struct cpu_job *job;

#ifdef DEBUG_SERIALIZE_CPU_JOBS
	if (cpu == NULL)
		cpu = this_cpu();
#endif

	if (cpu && !cpu_is_available(cpu)) {
		prerror("CPU: Tried to queue job on unavailable CPU 0x%04x\n",
			cpu->pir);
		return NULL;
	}

	job = zalloc(sizeof(struct cpu_job));
	if (!job)
		return NULL;
	job->func = func;
	job->data = data;
	job->name = name;
	job->complete = false;
	job->no_return = no_return;

	/* Pick a candidate. Returns with target queue locked */
	if (cpu == NULL)
		cpu = cpu_find_job_target(-1);
	else if (cpu != this_cpu())
		lock(&cpu->job_lock);
	else
		cpu = NULL;

	/* Can't be scheduled, run it now */
	if (cpu == NULL) {
		if (!this_cpu()->job_has_no_return)
			this_cpu()->job_has_no_return = no_return;
		func(data);
		job->complete = true;
		return job;
	}

	queue_job_on_cpu(cpu, job);

	return job;
}

struct cpu_job *cpu_queue_job_on_node(uint32_t chip_id,
				const char *name,
				void (*func)(void *data), void *data)
{
	struct cpu_thread *cpu;
	struct cpu_job *job;

	job = zalloc(sizeof(struct cpu_job));
	if (!job)
		return NULL;
	job->func = func;
	job->data = data;
	job->name = name;
	job->complete = false;
	job->no_return = false;

	/* Pick a candidate. Returns with target queue locked */
	cpu = cpu_find_job_target(chip_id);

	/* Can't be scheduled... */
	if (cpu == NULL) {
		cpu = this_cpu();
		if (cpu->chip_id == chip_id) {
			/* Run it now if we're the right node. */
			func(data);
			job->complete = true;
			return job;
		}
		/* Otherwise fail. */
		free(job);
		return NULL;
	}

	queue_job_on_cpu(cpu, job);

	return job;
}

bool cpu_poll_job(struct cpu_job *job)
{
	lwsync();
	return job->complete;
}

void cpu_wait_job(struct cpu_job *job, bool free_it)
{
	unsigned long time_waited = 0;

	if (!job)
		return;

	while (!job->complete) {
		/* This will call OPAL pollers for us */
		time_wait_ms(10);
		time_waited += 10;
		lwsync();
		if ((time_waited % 30000) == 0) {
			prlog(PR_INFO, "cpu_wait_job(%s) for %lums\n",
			      job->name, time_waited);
			backtrace();
		}
	}
	lwsync();

	if (time_waited > 1000)
		prlog(PR_DEBUG, "cpu_wait_job(%s) for %lums\n",
		      job->name, time_waited);

	if (free_it)
		free(job);
}

bool cpu_check_jobs(struct cpu_thread *cpu)
{
	return !list_empty_nocheck(&cpu->job_queue);
}

void cpu_process_jobs(void)
{
	struct cpu_thread *cpu = this_cpu();
	struct cpu_job *job = NULL;
	void (*func)(void *);
	void *data;

	sync();
	if (!cpu_check_jobs(cpu))
		return;

	lock(&cpu->job_lock);
	while (true) {
		bool no_return;

		job = list_pop(&cpu->job_queue, struct cpu_job, link);
		if (!job)
			break;

		func = job->func;
		data = job->data;
		no_return = job->no_return;
		unlock(&cpu->job_lock);
		prlog(PR_TRACE, "running job %s on %x\n", job->name, cpu->pir);
		if (no_return)
			free(job);
		func(data);
		if (!list_empty(&cpu->locks_held)) {
			if (no_return)
				prlog(PR_ERR, "OPAL no-return job returned with"
				      "locks held!\n");
			else
				prlog(PR_ERR, "OPAL job %s returning with locks held\n",
				      job->name);
			drop_my_locks(true);
		}
		lock(&cpu->job_lock);
		if (!no_return) {
			cpu->job_count--;
			lwsync();
			job->complete = true;
		}
	}
	unlock(&cpu->job_lock);
}

enum cpu_wake_cause {
	cpu_wake_on_job,
	cpu_wake_on_dec,
};

static unsigned int cpu_idle_p8(enum cpu_wake_cause wake_on)
{
	uint64_t lpcr = mfspr(SPR_LPCR) & ~SPR_LPCR_P8_PECE;
	struct cpu_thread *cpu = this_cpu();
	unsigned int vec = 0;

	if (!pm_enabled) {
		prlog_once(PR_DEBUG, "cpu_idle_p8 called pm disabled\n");
		return vec;
	}

	/* Clean up ICP, be ready for IPIs */
	icp_prep_for_pm();

	/* Synchronize with wakers */
	if (wake_on == cpu_wake_on_job) {
		/* Mark ourselves in idle so other CPUs know to send an IPI */
		cpu->in_idle = true;
		sync();

		/* Check for jobs again */
		if (cpu_check_jobs(cpu) || !pm_enabled)
			goto skip_sleep;

		/* Setup wakup cause in LPCR: EE (for IPI) */
		lpcr |= SPR_LPCR_P8_PECE2;
		mtspr(SPR_LPCR, lpcr);

	} else {
		/* Mark outselves sleeping so cpu_set_pm_enable knows to
		 * send an IPI
		 */
		cpu->in_sleep = true;
		sync();

		/* Check if PM got disabled */
		if (!pm_enabled)
			goto skip_sleep;

		/* EE and DEC */
		lpcr |= SPR_LPCR_P8_PECE2 | SPR_LPCR_P8_PECE3;
		mtspr(SPR_LPCR, lpcr);
	}
	isync();

	/* Enter nap */
	vec = enter_p8_pm_state(false);

skip_sleep:
	/* Restore */
	sync();
	cpu->in_idle = false;
	cpu->in_sleep = false;
	reset_cpu_icp();

	return vec;
}

static unsigned int cpu_idle_p9(enum cpu_wake_cause wake_on)
{
	uint64_t lpcr = mfspr(SPR_LPCR) & ~SPR_LPCR_P9_PECE;
	uint64_t psscr;
	struct cpu_thread *cpu = this_cpu();
	unsigned int vec = 0;

	if (!pm_enabled) {
		prlog(PR_DEBUG, "cpu_idle_p9 called on cpu 0x%04x with pm disabled\n", cpu->pir);
		return vec;
	}

	/* Synchronize with wakers */
	if (wake_on == cpu_wake_on_job) {
		/* Mark ourselves in idle so other CPUs know to send an IPI */
		cpu->in_idle = true;
		sync();

		/* Check for jobs again */
		if (cpu_check_jobs(cpu) || !pm_enabled)
			goto skip_sleep;

		/* HV DBELL for IPI */
		lpcr |= SPR_LPCR_P9_PECEL1;
	} else {
		/* Mark outselves sleeping so cpu_set_pm_enable knows to
		 * send an IPI
		 */
		cpu->in_sleep = true;
		sync();

		/* Check if PM got disabled */
		if (!pm_enabled)
			goto skip_sleep;

		/* HV DBELL and DEC */
		lpcr |= SPR_LPCR_P9_PECEL1 | SPR_LPCR_P9_PECEL3;
	}

	mtspr(SPR_LPCR, lpcr);
	isync();

	if (sreset_enabled) {
		/* stop with EC=1 (sreset) and ESL=1 (enable thread switch). */
		/* PSSCR SD=0 ESL=1 EC=1 PSSL=0 TR=3 MTL=0 RL=1 */
		psscr = PPC_BIT(42) | PPC_BIT(43) |
			PPC_BITMASK(54, 55) | PPC_BIT(63);
		vec = enter_p9_pm_state(psscr);
	} else {
		/* stop with EC=0 (resumes) which does not require sreset. */
		/* PSSCR SD=0 ESL=0 EC=0 PSSL=0 TR=3 MTL=0 RL=1 */
		psscr = PPC_BITMASK(54, 55) | PPC_BIT(63);
		enter_p9_pm_lite_state(psscr);
	}

	/* Clear doorbell */
	p9_dbell_receive();

 skip_sleep:
	/* Restore */
	sync();
	cpu->in_idle = false;
	cpu->in_sleep = false;

	return vec;
}

static void cpu_idle_pm(enum cpu_wake_cause wake_on)
{
	unsigned int vec;

	switch(proc_gen) {
	case proc_gen_p8:
		vec = cpu_idle_p8(wake_on);
		break;
	case proc_gen_p9:
		vec = cpu_idle_p9(wake_on);
		break;
	case proc_gen_p10:
		vec = cpu_idle_p9(wake_on);
		break;
	default:
		vec = 0;
		prlog_once(PR_DEBUG, "cpu_idle_pm called with bad processor type\n");
		break;
	}

	if (vec == 0x100) {
		unsigned long srr1 = mfspr(SPR_SRR1);

		switch (srr1 & SPR_SRR1_PM_WAKE_MASK) {
		case SPR_SRR1_PM_WAKE_SRESET:
			exception_entry_pm_sreset();
			break;
		default:
			break;
		}
		mtmsrd(MSR_RI, 1);

	} else if (vec == 0x200) {
		exception_entry_pm_mce();
		enable_machine_check();
		mtmsrd(MSR_RI, 1);
	}
}

void cpu_idle_job(void)
{
	if (pm_enabled) {
		cpu_idle_pm(cpu_wake_on_job);
	} else {
		struct cpu_thread *cpu = this_cpu();

		smt_lowest();
		/* Check for jobs again */
		while (!cpu_check_jobs(cpu)) {
			if (pm_enabled)
				break;
			cpu_relax();
			barrier();
		}
		smt_medium();
	}
}

void cpu_idle_delay(unsigned long delay)
{
	unsigned long now = mftb();
	unsigned long end = now + delay;
	unsigned long min_pm = usecs_to_tb(10);

	if (pm_enabled && delay > min_pm) {
pm:
		for (;;) {
			if (delay >= 0x7fffffff)
				delay = 0x7fffffff;
			mtspr(SPR_DEC, delay);

			cpu_idle_pm(cpu_wake_on_dec);

			now = mftb();
			if (tb_compare(now, end) == TB_AAFTERB)
				break;
			delay = end - now;
			if (!(pm_enabled && delay > min_pm))
				goto no_pm;
		}
	} else {
no_pm:
		smt_lowest();
		for (;;) {
			now = mftb();
			if (tb_compare(now, end) == TB_AAFTERB)
				break;
			delay = end - now;
			if (pm_enabled && delay > min_pm) {
				smt_medium();
				goto pm;
			}
		}
		smt_medium();
	}
}

static void cpu_pm_disable(void)
{
	struct cpu_thread *cpu;
	unsigned int timeout;

	pm_enabled = false;
	sync();

	if (proc_gen == proc_gen_p8) {
		for_each_available_cpu(cpu) {
			while (cpu->in_sleep || cpu->in_idle) {
				icp_kick_cpu(cpu);
				cpu_relax();
			}
		}
	} else if (proc_gen == proc_gen_p9 || proc_gen == proc_gen_p10) {
		for_each_available_cpu(cpu) {
			if (cpu->in_sleep || cpu->in_idle)
				p9_dbell_send(cpu->pir);
		}

		/*  This code is racy with cpus entering idle, late ones miss the dbell */

		smt_lowest();
		for_each_available_cpu(cpu) {
			timeout = 0x08000000;
			while ((cpu->in_sleep || cpu->in_idle) && --timeout)
				barrier();
			if (!timeout) {
				prlog(PR_DEBUG, "cpu_pm_disable TIMEOUT on cpu 0x%04x to exit idle\n",
				      cpu->pir);
                                p9_dbell_send(cpu->pir);
                        }
		}
		smt_medium();
	}
}

void cpu_set_sreset_enable(bool enabled)
{
	if (sreset_enabled == enabled)
		return;

	if (proc_gen == proc_gen_p8) {
		/* Public P8 Mambo has broken NAP */
		if (chip_quirk(QUIRK_MAMBO_CALLOUTS))
			return;

		sreset_enabled = enabled;
		sync();

		if (!enabled) {
			cpu_pm_disable();
		} else {
			if (ipi_enabled)
				pm_enabled = true;
		}

	} else if (proc_gen == proc_gen_p9 || proc_gen == proc_gen_p10) {
		sreset_enabled = enabled;
		sync();
		/*
		 * Kick everybody out of PM so they can adjust the PM
		 * mode they are using (EC=0/1).
		 */
		cpu_pm_disable();
		if (ipi_enabled)
			pm_enabled = true;
	}
}

void cpu_set_ipi_enable(bool enabled)
{
	if (ipi_enabled == enabled)
		return;

	if (proc_gen == proc_gen_p8) {
		ipi_enabled = enabled;
		sync();
		if (!enabled) {
			cpu_pm_disable();
		} else {
			if (sreset_enabled)
				pm_enabled = true;
		}

	} else if (proc_gen == proc_gen_p9 || proc_gen == proc_gen_p10) {
		ipi_enabled = enabled;
		sync();
		if (!enabled)
			cpu_pm_disable();
		else
			pm_enabled = true;
	}
}

void cpu_process_local_jobs(void)
{
	struct cpu_thread *cpu = first_available_cpu();

	while (cpu) {
		if (cpu != this_cpu())
			return;

		cpu = next_available_cpu(cpu);
	}

	if (!cpu)
		cpu = first_available_cpu();

	/* No CPU to run on, just run synchro */
	if (cpu == this_cpu()) {
		prlog_once(PR_DEBUG, "Processing jobs synchronously\n");
		cpu_process_jobs();
		opal_run_pollers();
	}
}


struct dt_node *get_cpu_node(u32 pir)
{
	struct cpu_thread *t = find_cpu_by_pir(pir);

	return t ? t->node : NULL;
}

/* This only covers primary, active cpus */
struct cpu_thread *find_cpu_by_chip_id(u32 chip_id)
{
	struct cpu_thread *t;

	for_each_available_cpu(t) {
		if (t->is_secondary)
			continue;
		if (t->chip_id == chip_id)
			return t;
	}
	return NULL;
}

struct cpu_thread *find_cpu_by_node(struct dt_node *cpu)
{
	struct cpu_thread *t;

	for_each_available_cpu(t) {
		if (t->node == cpu)
			return t;
	}
	return NULL;
}

struct cpu_thread *find_cpu_by_pir(u32 pir)
{
	if (pir > cpu_max_pir)
		return NULL;
	return &cpu_stacks[pir].cpu;
}

struct cpu_thread __nomcount *find_cpu_by_pir_nomcount(u32 pir)
{
	if (pir > cpu_max_pir)
		return NULL;
	return &cpu_stacks[pir].cpu;
}

struct cpu_thread *find_cpu_by_server(u32 server_no)
{
	struct cpu_thread *t;

	for_each_cpu(t) {
		if (t->server_no == server_no)
			return t;
	}
	return NULL;
}

struct cpu_thread *next_cpu(struct cpu_thread *cpu)
{
	struct cpu_stack *s;
	unsigned int index = 0;

	if (cpu != NULL) {
		s = container_of(cpu, struct cpu_stack, cpu);
		index = s - cpu_stacks + 1;
	}
	for (; index <= cpu_max_pir; index++) {
		cpu = &cpu_stacks[index].cpu;
		if (cpu->state != cpu_state_no_cpu)
			return cpu;
	}
	return NULL;
}

struct cpu_thread *first_cpu(void)
{
	return next_cpu(NULL);
}

struct cpu_thread *next_available_cpu(struct cpu_thread *cpu)
{
	do {
		cpu = next_cpu(cpu);
	} while(cpu && !cpu_is_available(cpu));

	return cpu;
}

struct cpu_thread *first_available_cpu(void)
{
	return next_available_cpu(NULL);
}

struct cpu_thread *next_present_cpu(struct cpu_thread *cpu)
{
	do {
		cpu = next_cpu(cpu);
	} while(cpu && !cpu_is_present(cpu));

	return cpu;
}

struct cpu_thread *first_present_cpu(void)
{
	return next_present_cpu(NULL);
}

struct cpu_thread *next_ungarded_cpu(struct cpu_thread *cpu)
{
	do {
		cpu = next_cpu(cpu);
	} while(cpu && cpu->state == cpu_state_unavailable);

	return cpu;
}

struct cpu_thread *first_ungarded_cpu(void)
{
	return next_ungarded_cpu(NULL);
}

struct cpu_thread *next_ungarded_primary(struct cpu_thread *cpu)
{
	do {
		cpu = next_ungarded_cpu(cpu);
	} while (cpu && !(cpu == cpu->primary || cpu == cpu->ec_primary));

	return cpu;
}

struct cpu_thread *first_ungarded_primary(void)
{
	return next_ungarded_primary(NULL);
}

u8 get_available_nr_cores_in_chip(u32 chip_id)
{
	struct cpu_thread *core;
	u8 nr_cores = 0;

	for_each_available_core_in_chip(core, chip_id)
		nr_cores++;

	return nr_cores;
}

struct cpu_thread *next_available_core_in_chip(struct cpu_thread *core,
					       u32 chip_id)
{
	do {
		core = next_cpu(core);
	} while(core && (!cpu_is_available(core) ||
			 core->chip_id != chip_id ||
			 core->is_secondary));
	return core;
}

struct cpu_thread *first_available_core_in_chip(u32 chip_id)
{
	return next_available_core_in_chip(NULL, chip_id);
}

uint32_t cpu_get_core_index(struct cpu_thread *cpu)
{
	return pir_to_fused_core_id(cpu->pir);
}

void cpu_remove_node(const struct cpu_thread *t)
{
	struct dt_node *i;

	/* Find this cpu node */
	dt_for_each_node(dt_root, i) {
		const struct dt_property *p;

		if (!dt_has_node_property(i, "device_type", "cpu"))
			continue;
		p = dt_find_property(i, "ibm,pir");
		if (!p)
			continue;
		if (dt_property_get_cell(p, 0) == t->pir) {
			dt_free(i);
			return;
		}
	}
	prerror("CPU: Could not find cpu node %i to remove!\n", t->pir);
	abort();
}

void cpu_disable_all_threads(struct cpu_thread *cpu)
{
	unsigned int i;
	struct dt_property *p;

	for (i = 0; i <= cpu_max_pir; i++) {
		struct cpu_thread *t = &cpu_stacks[i].cpu;

		if (t->primary == cpu->primary)
			t->state = cpu_state_disabled;

	}

	/* Mark this core as bad so that Linux kernel don't use this CPU. */
	prlog(PR_DEBUG, "CPU: Mark CPU bad (PIR 0x%04x)...\n", cpu->pir);
	p = __dt_find_property(cpu->node, "status");
	if (p)
		dt_del_property(cpu->node, p);

	dt_add_property_string(cpu->node, "status", "bad");

	/* XXX Do something to actually stop the core */
}

static void init_cpu_thread(struct cpu_thread *t,
			    enum cpu_thread_state state,
			    unsigned int pir)
{
	/* offset within cpu_thread to prevent stack_guard clobber */
	const size_t guard_skip = container_off_var(t, stack_guard) +
		sizeof(t->stack_guard);

	memset(((void *)t) + guard_skip, 0, sizeof(struct cpu_thread) - guard_skip);
	init_lock(&t->dctl_lock);
	init_lock(&t->job_lock);
	list_head_init(&t->job_queue);
	list_head_init(&t->locks_held);
	t->stack_guard = STACK_CHECK_GUARD_BASE ^ pir;
	t->state = state;
	t->pir = pir;
#ifdef STACK_CHECK_ENABLED
	t->stack_bot_mark = LONG_MAX;
#endif
	t->is_fused_core = is_fused_core(mfspr(SPR_PVR));
	assert(pir == container_of(t, struct cpu_stack, cpu) - cpu_stacks);
}

static void enable_attn(void)
{
	unsigned long hid0;

	hid0 = mfspr(SPR_HID0);
	hid0 |= hid0_attn;
	set_hid0(hid0);
}

static void disable_attn(void)
{
	unsigned long hid0;

	hid0 = mfspr(SPR_HID0);
	hid0 &= ~hid0_attn;
	set_hid0(hid0);
}

extern void __trigger_attn(void);
void trigger_attn(void)
{
	enable_attn();
	__trigger_attn();
}

static void init_hid(void)
{
	/* attn is enabled even when HV=0, so make sure it's off */
	disable_attn();
}

void __nomcount pre_init_boot_cpu(void)
{
	struct cpu_thread *cpu = this_cpu();

	/* We skip the stack guard ! */
	memset(((void *)cpu) + 8, 0, sizeof(struct cpu_thread) - 8);
}

void init_boot_cpu(void)
{
	unsigned int pir, pvr;

	pir = mfspr(SPR_PIR);
	pvr = mfspr(SPR_PVR);

	/* Get CPU family and other flags based on PVR */
	switch(PVR_TYPE(pvr)) {
	case PVR_TYPE_P8E:
	case PVR_TYPE_P8:
		proc_gen = proc_gen_p8;
		hile_supported = PVR_VERS_MAJ(mfspr(SPR_PVR)) >= 2;
		hid0_hile = SPR_HID0_POWER8_HILE;
		hid0_attn = SPR_HID0_POWER8_ENABLE_ATTN;
		break;
	case PVR_TYPE_P8NVL:
		proc_gen = proc_gen_p8;
		hile_supported = true;
		hid0_hile = SPR_HID0_POWER8_HILE;
		hid0_attn = SPR_HID0_POWER8_ENABLE_ATTN;
		break;
	case PVR_TYPE_P9:
	case PVR_TYPE_P9P:
		proc_gen = proc_gen_p9;
		hile_supported = true;
		radix_supported = true;
		hid0_hile = SPR_HID0_POWER9_HILE;
		hid0_attn = SPR_HID0_POWER9_ENABLE_ATTN;
		break;
	case PVR_TYPE_P10:
		proc_gen = proc_gen_p10;
		hile_supported = true;
		radix_supported = true;
		hid0_hile = SPR_HID0_POWER10_HILE;
		hid0_attn = SPR_HID0_POWER10_ENABLE_ATTN;
		break;
	default:
		proc_gen = proc_gen_unknown;
	}

	/* Get a CPU thread count based on family */
	switch(proc_gen) {
	case proc_gen_p8:
		cpu_thread_count = 8;
		prlog(PR_INFO, "CPU: P8 generation processor"
		      " (max %d threads/core)\n", cpu_thread_count);
		break;
	case proc_gen_p9:
		if (is_fused_core(pvr))
			cpu_thread_count = 8;
		else
			cpu_thread_count = 4;
		prlog(PR_INFO, "CPU: P9 generation processor"
		      " (max %d threads/core)\n", cpu_thread_count);
		break;
	case proc_gen_p10:
		if (is_fused_core(pvr))
			cpu_thread_count = 8;
		else
			cpu_thread_count = 4;
		prlog(PR_INFO, "CPU: P10 generation processor"
		      " (max %d threads/core)\n", cpu_thread_count);
		break;
	default:
		prerror("CPU: Unknown PVR, assuming 1 thread\n");
		cpu_thread_count = 1;
	}

	if (is_power9n(pvr) && (PVR_VERS_MAJ(pvr) == 1)) {
		prerror("CPU: POWER9N DD1 is not supported\n");
		abort();
	}

	prlog(PR_DEBUG, "CPU: Boot CPU PIR is 0x%04x PVR is 0x%08x\n",
	      pir, pvr);

	/*
	 * Adjust top of RAM to include the boot CPU stack. If we have less
	 * RAM than this, it's not possible to boot.
	 */
	cpu_max_pir = pir;
	top_of_ram += (cpu_max_pir + 1) * STACK_SIZE;

	/* Setup boot CPU state */
	boot_cpu = &cpu_stacks[pir].cpu;
	init_cpu_thread(boot_cpu, cpu_state_active, pir);
	init_boot_tracebuf(boot_cpu);
	assert(this_cpu() == boot_cpu);
	init_hid();
}

static void enable_large_dec(bool on)
{
	u64 lpcr = mfspr(SPR_LPCR);

	if (on)
		lpcr |= SPR_LPCR_P9_LD;
	else
		lpcr &= ~SPR_LPCR_P9_LD;

	mtspr(SPR_LPCR, lpcr);
	isync();
}

#define HIGH_BIT (1ull << 63)

static int find_dec_bits(void)
{
	int bits = 65; /* we always decrement once */
	u64 mask = ~0ull;

	if (proc_gen < proc_gen_p9)
		return 32;

	/* The ISA doesn't specify the width of the decrementer register so we
	 * need to discover it. When in large mode (LPCR.LD = 1) reads from the
	 * DEC SPR are sign extended to 64 bits and writes are truncated to the
	 * physical register width. We can use this behaviour to detect the
	 * width by starting from an all 1s value and left shifting until we
	 * read a value from the DEC with it's high bit cleared.
	 */

	enable_large_dec(true);

	do {
		bits--;
		mask = mask >> 1;
		mtspr(SPR_DEC, mask);
	} while (mfspr(SPR_DEC) & HIGH_BIT);

	enable_large_dec(false);

	prlog(PR_DEBUG, "CPU: decrementer bits %d\n", bits);
	return bits;
}

static void init_tm_suspend_mode_property(void)
{
	struct dt_node *node;

	/* If we don't find anything, assume TM suspend is enabled */
	tm_suspend_enabled = true;

	node = dt_find_by_path(dt_root, "/ibm,opal/fw-features/tm-suspend-mode");
	if (!node)
		return;

	if (dt_find_property(node, "disabled"))
		tm_suspend_enabled = false;
}

void init_cpu_max_pir(void)
{
	struct dt_node *cpus, *cpu;

	cpus = dt_find_by_path(dt_root, "/cpus");
	assert(cpus);

	/* Iterate all CPUs in the device-tree */
	dt_for_each_child(cpus, cpu) {
		unsigned int pir, server_no;

		/* Skip cache nodes */
		if (strcmp(dt_prop_get(cpu, "device_type"), "cpu"))
			continue;

		server_no = dt_prop_get_u32(cpu, "reg");

		/* If PIR property is absent, assume it's the same as the
		 * server number
		 */
		pir = dt_prop_get_u32_def(cpu, "ibm,pir", server_no);

		if (cpu_max_pir < pir + cpu_thread_count - 1)
			cpu_max_pir = pir + cpu_thread_count - 1;
	}

	prlog(PR_DEBUG, "CPU: New max PIR set to 0x%x\n", cpu_max_pir);
}

/*
 * Set cpu->state to cpu_state_no_cpu for all secondaries, before the dt is
 * parsed and they will be flipped to present as populated CPUs are found.
 *
 * Some configurations (e.g., with memory encryption) will not zero system
 * memory at boot, so can't rely on cpu->state to be zero (== cpu_state_no_cpu).
 */
static void mark_all_secondary_cpus_absent(void)
{
	unsigned int pir;
	struct cpu_thread *cpu;

	for (pir = 0; pir <= cpu_max_pir; pir++) {
		cpu = &cpu_stacks[pir].cpu;
		if (cpu == boot_cpu)
			continue;
		cpu->state = cpu_state_no_cpu;
	}
}

void init_all_cpus(void)
{
	struct dt_node *cpus, *cpu;
	unsigned int pir, thread;
	int dec_bits = find_dec_bits();

	cpus = dt_find_by_path(dt_root, "/cpus");
	assert(cpus);

	init_tm_suspend_mode_property();

	mark_all_secondary_cpus_absent();

	/* Iterate all CPUs in the device-tree */
	dt_for_each_child(cpus, cpu) {
		unsigned int server_no, chip_id, threads;
		enum cpu_thread_state state;
		const struct dt_property *p;
		struct cpu_thread *t, *pt0, *pt1;

		/* Skip cache nodes */
		if (strcmp(dt_prop_get(cpu, "device_type"), "cpu"))
			continue;

		server_no = dt_prop_get_u32(cpu, "reg");

		/* If PIR property is absent, assume it's the same as the
		 * server number
		 */
		pir = dt_prop_get_u32_def(cpu, "ibm,pir", server_no);

		/* We should always have an ibm,chip-id property */
		chip_id = dt_get_chip_id(cpu);

		/* Only use operational CPUs */
		if (!strcmp(dt_prop_get(cpu, "status"), "okay")) {
			state = cpu_state_present;
			get_chip(chip_id)->ex_present = true;
		} else {
			state = cpu_state_unavailable;
		}

		prlog(PR_INFO, "CPU: CPU from DT PIR=0x%04x Server#=0x%x"
		      " State=%d\n", pir, server_no, state);

		/* Check max PIR */
		if (cpu_max_pir < (pir + cpu_thread_count - 1)) {
			prlog(PR_WARNING, "CPU: CPU potentially out of range"
			      "PIR=0x%04x MAX=0x%04x !\n",
			      pir, cpu_max_pir);
			continue;
		}

		/* Setup thread 0 */
		assert(pir <= cpu_max_pir);
		t = pt0 = &cpu_stacks[pir].cpu;
		if (t != boot_cpu) {
			init_cpu_thread(t, state, pir);
			/* Each cpu gets its own later in init_trace_buffers */
			t->trace = boot_cpu->trace;
		}
		if (t->is_fused_core)
			pt1 = &cpu_stacks[pir + 1].cpu;
		else
			pt1 = pt0;
		t->server_no = server_no;
		t->primary = t->ec_primary = t;
		t->node = cpu;
		t->chip_id = chip_id;
		t->icp_regs = NULL; /* Will be set later */
#ifdef DEBUG_LOCKS
		t->requested_lock = NULL;
#endif
		t->core_hmi_state = 0;
		t->core_hmi_state_ptr = &t->core_hmi_state;

		/* Add associativity properties */
		add_core_associativity(t);

		/* Add the decrementer width property */
		dt_add_property_cells(cpu, "ibm,dec-bits", dec_bits);

		if (t->is_fused_core)
			dt_add_property(t->node, "ibm,fused-core", NULL, 0);

		/* Iterate threads */
		p = dt_find_property(cpu, "ibm,ppc-interrupt-server#s");
		if (!p)
			continue;
		threads = p->len / 4;
		if (threads > cpu_thread_count) {
			prlog(PR_WARNING, "CPU: Threads out of range for PIR 0x%04x"
			      " threads=%d max=%d\n",
			      pir, threads, cpu_thread_count);
			threads = cpu_thread_count;
		}
		for (thread = 1; thread < threads; thread++) {
			prlog(PR_TRACE, "CPU:   secondary thread %d found\n",
			      thread);
			t = &cpu_stacks[pir + thread].cpu;
			init_cpu_thread(t, state, pir + thread);
			t->trace = boot_cpu->trace;
			t->server_no = dt_property_get_cell(p, thread);
			t->is_secondary = true;
			t->is_fused_core = pt0->is_fused_core;
			t->primary = pt0;
			t->ec_primary = (thread & 1) ? pt1 : pt0;
			t->node = cpu;
			t->chip_id = chip_id;
			t->core_hmi_state_ptr = &pt0->core_hmi_state;
		}
		prlog(PR_INFO, "CPU:  %d secondary threads\n", thread);
	}
}

void cpu_bringup(void)
{
	struct cpu_thread *t;
	uint32_t count = 0;

	prlog(PR_INFO, "CPU: Setting up secondary CPU state\n");

	op_display(OP_LOG, OP_MOD_CPU, 0x0000);

	/* Tell everybody to chime in ! */
	prlog(PR_INFO, "CPU: Calling in all processors...\n");
	cpu_secondary_start = 1;
	sync();

	op_display(OP_LOG, OP_MOD_CPU, 0x0002);

	for_each_cpu(t) {
		if (t->state != cpu_state_present &&
		    t->state != cpu_state_active)
			continue;

		/* Add a callin timeout ?  If so, call cpu_remove_node(t). */
		while (t->state != cpu_state_active) {
			smt_lowest();
			sync();
		}
		smt_medium();
		count++;
	}

	prlog(PR_NOTICE, "CPU: All %d processors called in...\n", count);

	op_display(OP_LOG, OP_MOD_CPU, 0x0003);
}

void cpu_callin(struct cpu_thread *cpu)
{
	sync();
	cpu->state = cpu_state_active;
	sync();

	cpu->job_has_no_return = false;
	if (cpu_is_thread0(cpu))
		init_hid();
}

static void opal_start_thread_job(void *data)
{
	cpu_give_self_os();

	/* We do not return, so let's mark the job as
	 * complete
	 */
	start_kernel_secondary((uint64_t)data);
}

static int64_t opal_start_cpu_thread(uint64_t server_no, uint64_t start_address)
{
	struct cpu_thread *cpu;
	struct cpu_job *job;

	if (!opal_addr_valid((void *)start_address))
		return OPAL_PARAMETER;

	cpu = find_cpu_by_server(server_no);
	if (!cpu) {
		prerror("OPAL: Start invalid CPU 0x%04llx !\n", server_no);
		return OPAL_PARAMETER;
	}
	prlog(PR_DEBUG, "OPAL: Start CPU 0x%04llx (PIR 0x%04x) -> 0x%016llx\n",
	       server_no, cpu->pir, start_address);

	lock(&reinit_lock);
	if (!cpu_is_available(cpu)) {
		unlock(&reinit_lock);
		prerror("OPAL: CPU not active in OPAL !\n");
		return OPAL_WRONG_STATE;
	}
	if (cpu->in_reinit) {
		unlock(&reinit_lock);
		prerror("OPAL: CPU being reinitialized !\n");
		return OPAL_WRONG_STATE;
	}
	job = __cpu_queue_job(cpu, "start_thread",
			      opal_start_thread_job, (void *)start_address,
			      true);
	unlock(&reinit_lock);
	if (!job) {
		prerror("OPAL: Failed to create CPU start job !\n");
		return OPAL_INTERNAL_ERROR;
	}
	return OPAL_SUCCESS;
}
opal_call(OPAL_START_CPU, opal_start_cpu_thread, 2);

static int64_t opal_query_cpu_status(uint64_t server_no, uint8_t *thread_status)
{
	struct cpu_thread *cpu;

	if (!opal_addr_valid(thread_status))
		return OPAL_PARAMETER;

	cpu = find_cpu_by_server(server_no);
	if (!cpu) {
		prerror("OPAL: Query invalid CPU 0x%04llx !\n", server_no);
		return OPAL_PARAMETER;
	}
	if (!cpu_is_available(cpu) && cpu->state != cpu_state_os) {
		prerror("OPAL: CPU not active in OPAL nor OS !\n");
		return OPAL_PARAMETER;
	}
	switch(cpu->state) {
	case cpu_state_os:
		*thread_status = OPAL_THREAD_STARTED;
		break;
	case cpu_state_active:
		/* Active in skiboot -> inactive in OS */
		*thread_status = OPAL_THREAD_INACTIVE;
		break;
	default:
		*thread_status = OPAL_THREAD_UNAVAILABLE;
	}

	return OPAL_SUCCESS;
}
opal_call(OPAL_QUERY_CPU_STATUS, opal_query_cpu_status, 2);

static int64_t opal_return_cpu(void)
{
	prlog(PR_DEBUG, "OPAL: Returning CPU 0x%04x\n", this_cpu()->pir);

	this_cpu()->in_opal_call--;
	if (this_cpu()->in_opal_call != 0) {
		printf("OPAL in_opal_call=%u\n", this_cpu()->in_opal_call);
	}

	__secondary_cpu_entry();

	return OPAL_HARDWARE; /* Should not happen */
}
opal_call(OPAL_RETURN_CPU, opal_return_cpu, 0);

struct hid0_change_req {
	uint64_t clr_bits;
	uint64_t set_bits;
};

static void cpu_change_hid0(void *__req)
{
	struct hid0_change_req *req = __req;
	unsigned long hid0, new_hid0;

	hid0 = new_hid0 = mfspr(SPR_HID0);
	new_hid0 &= ~req->clr_bits;
	new_hid0 |= req->set_bits;
	prlog(PR_DEBUG, "CPU: [%08x] HID0 change 0x%016lx -> 0x%016lx\n",
		this_cpu()->pir, hid0, new_hid0);
	set_hid0(new_hid0);
}

static int64_t cpu_change_all_hid0(struct hid0_change_req *req)
{
	struct cpu_thread *cpu;
	struct cpu_job **jobs;

	jobs = zalloc(sizeof(struct cpu_job *) * (cpu_max_pir + 1));
	assert(jobs);

	for_each_available_cpu(cpu) {
		if (!cpu_is_thread0(cpu) && !cpu_is_core_chiplet_primary(cpu))
			continue;
		if (cpu == this_cpu())
			continue;
		jobs[cpu->pir] = cpu_queue_job(cpu, "cpu_change_hid0",
						cpu_change_hid0, req);
	}

	/* this cpu */
	cpu_change_hid0(req);

	for_each_available_cpu(cpu) {
		if (jobs[cpu->pir])
			cpu_wait_job(jobs[cpu->pir], true);
	}

	free(jobs);

	return OPAL_SUCCESS;
}

void cpu_set_hile_mode(bool hile)
{
	struct hid0_change_req req;

	if (hile == current_hile_mode)
		return;

	if (hile) {
		req.clr_bits = 0;
		req.set_bits = hid0_hile;
	} else {
		req.clr_bits = hid0_hile;
		req.set_bits = 0;
	}
	cpu_change_all_hid0(&req);
	current_hile_mode = hile;
}

static void cpu_cleanup_one(void *param __unused)
{
	mtspr(SPR_AMR, 0);
	mtspr(SPR_IAMR, 0);
	mtspr(SPR_PCR, 0);
}

static int64_t cpu_cleanup_all(void)
{
	struct cpu_thread *cpu;
	struct cpu_job **jobs;

	jobs = zalloc(sizeof(struct cpu_job *) * (cpu_max_pir + 1));
	assert(jobs);

	for_each_available_cpu(cpu) {
		if (cpu == this_cpu())
			continue;
		jobs[cpu->pir] = cpu_queue_job(cpu, "cpu_cleanup",
						cpu_cleanup_one, NULL);
	}

	/* this cpu */
	cpu_cleanup_one(NULL);

	for_each_available_cpu(cpu) {
		if (jobs[cpu->pir])
			cpu_wait_job(jobs[cpu->pir], true);
	}

	free(jobs);


	return OPAL_SUCCESS;
}

void cpu_fast_reboot_complete(void)
{
	/* Fast reboot will have set HID0:HILE to skiboot endian */
	current_hile_mode = HAVE_LITTLE_ENDIAN;

	/* and set HID0:RADIX */
	if (proc_gen == proc_gen_p9)
		current_radix_mode = true;
}

static int64_t opal_reinit_cpus(uint64_t flags)
{
	struct hid0_change_req req = { 0, 0 };
	struct cpu_thread *cpu;
	int64_t rc = OPAL_SUCCESS;
	int i;

	prlog(PR_DEBUG, "OPAL: CPU re-init with flags: 0x%llx\n", flags);

	if (flags & OPAL_REINIT_CPUS_HILE_LE)
		prlog(PR_INFO, "OPAL: Switch to little-endian OS\n");
	else if (flags & OPAL_REINIT_CPUS_HILE_BE)
		prlog(PR_INFO, "OPAL: Switch to big-endian OS\n");

 again:
	lock(&reinit_lock);

	for (cpu = first_cpu(); cpu; cpu = next_cpu(cpu)) {
		if (cpu == this_cpu() || cpu->in_reinit)
			continue;
		if (cpu->state == cpu_state_os) {
			unlock(&reinit_lock);
			/*
			 * That might be a race with return CPU during kexec
			 * where we are still, wait a bit and try again
			 */
			for (i = 0; (i < 1000) &&
				     (cpu->state == cpu_state_os); i++) {
				time_wait_ms(1);
			}
			if (cpu->state == cpu_state_os) {
				prerror("OPAL: CPU 0x%x not in OPAL !\n", cpu->pir);
				return OPAL_WRONG_STATE;
			}
			goto again;
		}
		cpu->in_reinit = true;
	}
	/*
	 * Now we need to mark ourselves "active" or we'll be skipped
	 * by the various "for_each_active_..." calls done by slw_reinit()
	 */
	this_cpu()->state = cpu_state_active;
	this_cpu()->in_reinit = true;
	unlock(&reinit_lock);

	/*
	 * This cleans up a few things left over by Linux
	 * that can cause problems in cases such as radix->hash
	 * transitions. Ideally Linux should do it but doing it
	 * here works around existing broken kernels.
	 */
	cpu_cleanup_all();

	/* If HILE change via HID0 is supported ... */
	if (hile_supported &&
	    (flags & (OPAL_REINIT_CPUS_HILE_BE |
		      OPAL_REINIT_CPUS_HILE_LE))) {
		bool hile = !!(flags & OPAL_REINIT_CPUS_HILE_LE);

		flags &= ~(OPAL_REINIT_CPUS_HILE_BE | OPAL_REINIT_CPUS_HILE_LE);
		if (hile != current_hile_mode) {
			if (hile)
				req.set_bits |= hid0_hile;
			else
				req.clr_bits |= hid0_hile;
			current_hile_mode = hile;
		}
	}

	/* If MMU mode change is supported */
	if (radix_supported &&
	    (flags & (OPAL_REINIT_CPUS_MMU_HASH |
		      OPAL_REINIT_CPUS_MMU_RADIX))) {
		bool radix = !!(flags & OPAL_REINIT_CPUS_MMU_RADIX);

		flags &= ~(OPAL_REINIT_CPUS_MMU_HASH |
			   OPAL_REINIT_CPUS_MMU_RADIX);

		if (proc_gen == proc_gen_p9 && radix != current_radix_mode) {
			if (radix)
				req.set_bits |= SPR_HID0_POWER9_RADIX;
			else
				req.clr_bits |= SPR_HID0_POWER9_RADIX;

			current_radix_mode = radix;
		}
	}

	/* Cleanup the TLB. We do that unconditionally, this works
	 * around issues where OSes fail to invalidate the PWC in Radix
	 * mode for example. This only works on P9 and later, but we
	 * also know we don't have a problem with Linux cleanups on
	 * P8 so this isn't a problem. If we wanted to cleanup the
	 * TLB on P8 as well, we'd have to use jobs to do it locally
	 * on each CPU.
	 */
	 cleanup_global_tlb();

	 /* Apply HID bits changes if any */
	if (req.set_bits || req.clr_bits)
		cpu_change_all_hid0(&req);

	if (flags & OPAL_REINIT_CPUS_TM_SUSPEND_DISABLED) {
		flags &= ~OPAL_REINIT_CPUS_TM_SUSPEND_DISABLED;

		if (tm_suspend_enabled)
			rc = OPAL_UNSUPPORTED;
		else
			rc = OPAL_SUCCESS;
	}

	/* Handle P8 DD1 SLW reinit */
	if (flags != 0 && proc_gen == proc_gen_p8 && !hile_supported)
		rc = slw_reinit(flags);
	else if (flags != 0)
		rc = OPAL_UNSUPPORTED;

	/* And undo the above */
	lock(&reinit_lock);
	this_cpu()->state = cpu_state_os;
	for (cpu = first_cpu(); cpu; cpu = next_cpu(cpu))
		cpu->in_reinit = false;
	unlock(&reinit_lock);

	return rc;
}
opal_call(OPAL_REINIT_CPUS, opal_reinit_cpus, 1);

#define NMMU_XLAT_CTL_PTCR 0xb
static int64_t nmmu_set_ptcr(uint64_t chip_id, struct dt_node *node, uint64_t ptcr)
{
	uint32_t nmmu_base_addr;

	nmmu_base_addr = dt_get_address(node, 0, NULL);
	return xscom_write(chip_id, nmmu_base_addr + NMMU_XLAT_CTL_PTCR, ptcr);
}

/*
 * Setup the the Nest MMU PTCR register for all chips in the system or
 * the specified chip id.
 *
 * The PTCR value may be overwritten so long as all users have been
 * quiesced. If it is set to an invalid memory address the system will
 * checkstop if anything attempts to use it.
 *
 * Returns OPAL_UNSUPPORTED if no nest mmu was found.
 */
static int64_t opal_nmmu_set_ptcr(uint64_t chip_id, uint64_t ptcr)
{
	struct dt_node *node;
	int64_t rc = OPAL_UNSUPPORTED;

	if (chip_id == -1ULL)
		dt_for_each_compatible(dt_root, node, "ibm,power9-nest-mmu") {
			chip_id = dt_get_chip_id(node);
			if ((rc = nmmu_set_ptcr(chip_id, node, ptcr)))
				return rc;
		}
	else
		dt_for_each_compatible_on_chip(dt_root, node, "ibm,power9-nest-mmu", chip_id)
			if ((rc = nmmu_set_ptcr(chip_id, node, ptcr)))
				return rc;

	return rc;
}
opal_call(OPAL_NMMU_SET_PTCR, opal_nmmu_set_ptcr, 2);

static void _exit_uv_mode(void *data __unused)
{
	prlog(PR_DEBUG, "Exit uv mode on cpu pir 0x%04x\n", this_cpu()->pir);
	/* HW has smfctrl shared between threads but on Mambo it is per-thread */
	if (chip_quirk(QUIRK_MAMBO_CALLOUTS))
		exit_uv_mode(1);
	else
		exit_uv_mode(cpu_is_thread0(this_cpu()));
}

void cpu_disable_pef(void)
{
	struct cpu_thread *cpu;
	struct cpu_job **jobs;

	if (!(mfmsr() & MSR_S)) {
		prlog(PR_DEBUG, "UV mode off on cpu pir 0x%04x\n", this_cpu()->pir);
		return;
	}

	jobs = zalloc(sizeof(struct cpu_job *) * (cpu_max_pir + 1));
	assert(jobs);

	/* Exit uv mode on all secondary threads before touching
	 * smfctrl on thread 0 */
	for_each_available_cpu(cpu) {
		if (cpu == this_cpu())
			continue;

		if (!cpu_is_thread0(cpu))
			jobs[cpu->pir] = cpu_queue_job(cpu, "exit_uv_mode",
					_exit_uv_mode, NULL);
	}

	for_each_available_cpu(cpu)
		if (jobs[cpu->pir]) {
			cpu_wait_job(jobs[cpu->pir], true);
			jobs[cpu->pir] = NULL;
		}

	/* Exit uv mode and disable smfctrl on primary threads */
	for_each_available_cpu(cpu) {
		if (cpu == this_cpu())
			continue;

		if (cpu_is_thread0(cpu))
			jobs[cpu->pir] = cpu_queue_job(cpu, "exit_uv_mode",
					_exit_uv_mode, NULL);
	}

	for_each_available_cpu(cpu)
		if (jobs[cpu->pir])
			cpu_wait_job(jobs[cpu->pir], true);

	free(jobs);

	_exit_uv_mode(NULL);
}
