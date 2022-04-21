// SPDX-License-Identifier: Apache-2.0
/* Copyright 2013-2019 IBM Corp. */

#ifndef __CPU_H
#define __CPU_H

#include <processor.h>
#include <ccan/list/list.h>
#include <lock.h>
#include <device.h>
#include <opal.h>
#include <stack.h>
#include <timer.h>

/*
 * cpu_thread is our internal structure representing each
 * thread in the system
 */

enum cpu_thread_state {
	cpu_state_no_cpu	= 0,	/* Nothing there */
	cpu_state_unknown,		/* In PACA, not called in yet */
	cpu_state_unavailable,		/* Not available */
	cpu_state_fast_reboot_entry,	/* Called back into OPAL, real mode */
	cpu_state_present,		/* Assumed to spin in asm entry */
	cpu_state_active,		/* Secondary called in */
	cpu_state_os,			/* Under OS control */
	cpu_state_disabled,		/* Disabled by us due to error */
	cpu_state_rvwinkle,		/* Doing an rvwinkle cycle */
};

struct cpu_job;
struct xive_cpu_state;

struct cpu_thread {
	/*
	 * "stack_guard" must be at offset 0 to match the
	 * -mstack-protector-guard-offset=0 statement in the Makefile
	 */
	uint64_t			stack_guard;
	uint32_t			pir;
	uint32_t			server_no;
	uint32_t			chip_id;
	bool				is_secondary;
	bool				is_fused_core;
	struct cpu_thread		*primary;
	struct cpu_thread		*ec_primary;
	enum cpu_thread_state		state;
	struct dt_node			*node;
	struct trace_info		*trace;
	uint64_t			save_r1;
	void				*icp_regs;
	uint32_t			in_opal_call;
	uint32_t			quiesce_opal_call;
	uint64_t entered_opal_call_at;
	uint32_t			con_suspend;
	struct list_head		locks_held;
	bool				con_need_flush;
	bool				in_mcount;
	bool				in_poller;
	bool				in_reinit;
	bool				in_fast_sleep;
	bool				in_sleep;
	bool				in_idle;
	uint32_t			hbrt_spec_wakeup; /* primary only */
	uint64_t			save_l2_fir_action1;
	uint64_t			current_token;
#ifdef STACK_CHECK_ENABLED
	int64_t				stack_bot_mark;
	uint64_t			stack_bot_pc;
	uint64_t			stack_bot_tok;
#define CPU_BACKTRACE_SIZE	60
	struct bt_entry			stack_bot_bt[CPU_BACKTRACE_SIZE];
	struct bt_metadata		stack_bot_bt_metadata;
#endif
	struct lock			job_lock;
	struct list_head		job_queue;
	uint32_t			job_count;
	bool				job_has_no_return;
	/*
	 * Per-core mask tracking for threads in HMI handler and
	 * a cleanup done bit.
	 *	[D][TTTTTTTT]
	 *
	 * The member 'core_hmi_state' is primary only.
	 * The 'core_hmi_state_ptr' member from all secondry cpus will point
	 * to 'core_hmi_state' member in primary cpu.
	 */
	uint32_t			core_hmi_state; /* primary only */
	uint32_t			*core_hmi_state_ptr;
	bool				tb_invalid;
	bool				tb_resynced;

	/* For use by XICS emulation on XIVE */
	struct xive_cpu_state		*xstate;

	/*
	 * For direct controls scoms, including special wakeup.
	 */
	struct lock			dctl_lock; /* primary only */
	bool				dctl_stopped; /* per thread */
	uint32_t			special_wakeup_count; /* primary */

	/*
	 * For reading DTS sensors async
	 */
	struct lock			dts_lock;
	struct timer			dts_timer;
	__be64				*sensor_data;
	u32				sensor_attr;
	u32				token;
	bool				dts_read_in_progress;

#ifdef DEBUG_LOCKS
	/* The lock requested by this cpu, used for deadlock detection */
	struct lock			*requested_lock;
#endif
};

/* This global is set to 1 to allow secondaries to callin,
 * typically set after the primary has allocated the cpu_thread
 * array and stacks
 */
extern unsigned long cpu_secondary_start;

/* Max PIR in the system */
extern unsigned int cpu_max_pir;

/* Max # of threads per core */
extern unsigned int cpu_thread_count;

/* Boot CPU. */
extern struct cpu_thread *boot_cpu;

extern void __nomcount cpu_relax(void);

/* Initialize CPUs */
void pre_init_boot_cpu(void);
void init_boot_cpu(void);
void init_cpu_max_pir(void);
void init_all_cpus(void);

/* This brings up our secondaries */
extern void cpu_bringup(void);

/* This is called by secondaries as they call in */
extern void cpu_callin(struct cpu_thread *cpu);

/* For cpus which fail to call in. */
extern void cpu_remove_node(const struct cpu_thread *t);

/* Find CPUs using different methods */
extern struct cpu_thread *find_cpu_by_chip_id(u32 chip_id);
extern struct cpu_thread *find_cpu_by_node(struct dt_node *cpu);
extern struct cpu_thread *find_cpu_by_server(u32 server_no);
extern struct cpu_thread *find_cpu_by_pir(u32 pir);

/* Used for lock internals to avoid re-entrancy */
extern struct cpu_thread __nomcount *find_cpu_by_pir_nomcount(u32 pir);

extern struct dt_node *get_cpu_node(u32 pir);

/* Iterator */
extern struct cpu_thread *first_cpu(void);
extern struct cpu_thread *next_cpu(struct cpu_thread *cpu);

/* WARNING: CPUs that have been picked up by the OS are no longer
 *          appearing as available and can not have jobs scheduled
 *          on them. Essentially that means that after the OS is
 *          fully started, all CPUs are seen as unavailable from
 *          this API standpoint.
 */

static inline bool cpu_is_present(struct cpu_thread *cpu)
{
	return cpu->state >= cpu_state_present;
}

static inline bool cpu_is_available(struct cpu_thread *cpu)
{
	return cpu->state == cpu_state_active ||
		cpu->state == cpu_state_rvwinkle;
}

extern struct cpu_thread *first_available_cpu(void);
extern struct cpu_thread *next_available_cpu(struct cpu_thread *cpu);
extern struct cpu_thread *first_present_cpu(void);
extern struct cpu_thread *next_present_cpu(struct cpu_thread *cpu);
extern struct cpu_thread *first_ungarded_cpu(void);
extern struct cpu_thread *next_ungarded_cpu(struct cpu_thread *cpu);
extern struct cpu_thread *first_ungarded_primary(void);
extern struct cpu_thread *next_ungarded_primary(struct cpu_thread *cpu);

#define for_each_cpu(cpu)	\
	for (cpu = first_cpu(); cpu; cpu = next_cpu(cpu))

#define for_each_available_cpu(cpu)	\
	for (cpu = first_available_cpu(); cpu; cpu = next_available_cpu(cpu))

#define for_each_present_cpu(cpu)	\
	for (cpu = first_present_cpu(); cpu; cpu = next_present_cpu(cpu))

#define for_each_ungarded_cpu(cpu)				\
	for (cpu = first_ungarded_cpu(); cpu; cpu = next_ungarded_cpu(cpu))

#define for_each_ungarded_primary(cpu)				\
	for (cpu = first_ungarded_primary(); cpu; cpu = next_ungarded_primary(cpu))

extern struct cpu_thread *first_available_core_in_chip(u32 chip_id);
extern struct cpu_thread *next_available_core_in_chip(struct cpu_thread *cpu, u32 chip_id);
extern u8 get_available_nr_cores_in_chip(u32 chip_id);

#define for_each_available_core_in_chip(core, chip_id)	\
	for (core = first_available_core_in_chip(chip_id); core; \
		core = next_available_core_in_chip(core, chip_id))

/* Return the caller CPU (only after init_cpu_threads) */
#ifndef __TEST__
register struct cpu_thread *__this_cpu asm("r16");
#else
struct cpu_thread *__this_cpu;
#endif

static inline __nomcount struct cpu_thread *this_cpu(void)
{
	return __this_cpu;
}

/*
 * Note: On POWER9 fused core, cpu_get_thread_index() and cpu_get_core_index()
 * return respectively the thread number within a fused core (0..7) and
 * the fused core number. If you want the EC (small core) number, you have
 * to use the low level pir_to_core_id() and pir_to_thread_id().
 */
/* Get the thread # of a cpu within the core */
static inline uint32_t cpu_get_thread_index(struct cpu_thread *cpu)
{
	return cpu->pir - cpu->primary->pir;
}

/* Get the core # of a cpu within the core */
extern uint32_t cpu_get_core_index(struct cpu_thread *cpu);

/* Get the PIR of thread 0 of the same core */
static inline uint32_t cpu_get_thread0(struct cpu_thread *cpu)
{
	return cpu->primary->pir;
}

static inline bool cpu_is_thread0(struct cpu_thread *cpu)
{
	return cpu->primary == cpu;
}

static inline bool cpu_is_core_chiplet_primary(struct cpu_thread *cpu)
{
	return cpu->is_fused_core & (cpu_get_thread_index(cpu) == 1);
}

static inline bool cpu_is_sibling(struct cpu_thread *cpu1,
				  struct cpu_thread *cpu2)
{
	return cpu1->primary == cpu2->primary;
}

/* Called when some error condition requires disabling a core */
void cpu_disable_all_threads(struct cpu_thread *cpu);

/* Allocate & queue a job on target CPU */
extern struct cpu_job *__cpu_queue_job(struct cpu_thread *cpu,
				       const char *name,
				       void (*func)(void *data), void *data,
				       bool no_return);

static inline struct cpu_job *cpu_queue_job(struct cpu_thread *cpu,
					    const char *name,
					    void (*func)(void *data),
					    void *data)
{
	return __cpu_queue_job(cpu, name, func, data, false);
}

extern struct cpu_job *cpu_queue_job_on_node(uint32_t chip_id,
				       const char *name,
				       void (*func)(void *data), void *data);


/* Poll job status, returns true if completed */
extern bool cpu_poll_job(struct cpu_job *job);

/* Synchronously wait for a job to complete, this will
 * continue handling the FSP mailbox if called from the
 * boot CPU. Set free_it to free it automatically.
 */
extern void cpu_wait_job(struct cpu_job *job, bool free_it);

/* Called by init to process jobs */
extern void cpu_process_jobs(void);
/* Fallback to running jobs synchronously for global jobs */
extern void cpu_process_local_jobs(void);
/* Check if there's any job pending */
bool cpu_check_jobs(struct cpu_thread *cpu);

/* Set/clear HILE on all CPUs */
void cpu_set_hile_mode(bool hile);

/* OPAL sreset vector in place at 0x100 */
void cpu_set_sreset_enable(bool sreset_enabled);

/* IPI for PM modes is enabled */
void cpu_set_ipi_enable(bool sreset_enabled);

static inline void cpu_give_self_os(void)
{
	__this_cpu->state = cpu_state_os;
}

extern unsigned long __attrconst cpu_stack_bottom(unsigned int pir);
extern unsigned long __attrconst cpu_stack_top(unsigned int pir);
extern unsigned long __attrconst cpu_emergency_stack_top(unsigned int pir);

extern void cpu_idle_job(void);
extern void cpu_idle_delay(unsigned long delay);

extern void cpu_fast_reboot_complete(void);

int dctl_set_special_wakeup(struct cpu_thread *t);
int dctl_clear_special_wakeup(struct cpu_thread *t);
int dctl_core_is_gated(struct cpu_thread *t);

extern void exit_uv_mode(int);
void cpu_disable_pef(void);

#endif /* __CPU_H */
