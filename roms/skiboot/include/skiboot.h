// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#ifndef __SKIBOOT_H
#define __SKIBOOT_H

#include <compiler.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <bitutils.h>
#include <types.h>

#include <ccan/container_of/container_of.h>
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <ccan/build_assert/build_assert.h>
#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>
#include <ccan/str/str.h>

#include <libflash/blocklevel.h>

#include <mem-map.h>
#include <op-panel.h>
#include <platform.h>

/* Special ELF sections */
#define __force_data		__section(".force.data")

struct mem_region;
extern struct mem_region *mem_region_next(struct mem_region *region);

/* Misc linker script symbols */
extern char _start[];
extern char _head_end[];
extern char _stext[];
extern char _etext[];
extern char __sym_map_end[];
extern char _romem_end[];

#ifndef __TESTING__
/* Readonly section start and end. */
extern char __rodata_start[], __rodata_end[];

static inline bool is_rodata(const void *p)
{
	return ((const char *)p >= __rodata_start && (const char *)p < __rodata_end);
}
#else
static inline bool is_rodata(const void *p)
{
	return false;
}
#endif

/* Console logging
 * Update console_get_level() if you add here
 */
#define PR_EMERG	0
#define PR_ALERT	1
#define PR_CRIT		2
#define PR_ERR		3
#define PR_WARNING	4
#define PR_NOTICE	5
#define PR_PRINTF	PR_NOTICE
#define PR_INFO		6
#define PR_DEBUG	7
#define PR_TRACE	8
#define PR_INSANE	9

#ifndef pr_fmt
#define pr_fmt(fmt) fmt
#endif

void _prlog(int log_level, const char* fmt, ...) __attribute__((format (printf, 2, 3)));
#define prlog(l, f, ...) do { _prlog(l, pr_fmt(f), ##__VA_ARGS__); } while(0)
#define prerror(fmt...)	do { prlog(PR_ERR, fmt); } while(0)
#define prlog_once(arg, ...)	 		\
({						\
	static bool __prlog_once = false;	\
	if (!__prlog_once) {			\
		__prlog_once = true;		\
		prlog(arg, ##__VA_ARGS__);	\
	}					\
})

/* Location codes  -- at most 80 chars with null termination */
#define LOC_CODE_SIZE	80

/* Processor generation */
enum proc_gen {
	proc_gen_unknown,
	proc_gen_p8,
	proc_gen_p9,
	proc_gen_p10,
};
extern enum proc_gen proc_gen;

extern unsigned int pcie_max_link_speed;

/* Convert a 4-bit number to a hex char */
extern char __attrconst tohex(uint8_t nibble);

#ifndef __TEST__
/* Bit position of the most significant 1-bit (LSB=0, MSB=63) */
static inline int ilog2(unsigned long val)
{
	int left_zeros;

	asm volatile ("cntlzd %0,%1" : "=r" (left_zeros) : "r" (val));

	return 63 - left_zeros;
}

static inline bool is_pow2(unsigned long val)
{
	return val == (1ul << ilog2(val));
}
#endif

#define lo32(x)	((x) & 0xffffffff)
#define hi32(x)	(((x) >> 32) & 0xffffffff)

/* WARNING: _a *MUST* be a power of two */
#define ALIGN_UP(_v, _a)	(((_v) + (_a) - 1) & ~((_a) - 1))
#define ALIGN_DOWN(_v, _a)	((_v) & ~((_a) - 1))

/* TCE alignment */
#define TCE_SHIFT	12
#define TCE_PSIZE	(1ul << 12)
#define TCE_MASK	(TCE_PSIZE - 1)

/* Not the greatest variants but will do for now ... */
#define MIN(a, b)	((a) < (b) ? (a) : (b))
#define MAX(a, b)	((a) > (b) ? (a) : (b))

/* PCI Geographical Addressing */
#define PCI_BUS_NUM(bdfn)	(((bdfn) >> 8) & 0xff)
#define PCI_DEV(bdfn)		(((bdfn) >> 3) & 0x1f)
#define PCI_FUNC(bdfn)		((bdfn) & 0x07)

/*
 * To help the FSP to distinguish between physical address and TCE mapped address.
 * Also to help hostboot to distinguish physical and relative address.
 */
#define HRMOR_BIT (1ul << 63)

/* Clean the stray high bit which the FSP inserts: we only have 52 bits real */
static inline u64 cleanup_addr(u64 addr)
{
	return addr & ((1ULL << 52) - 1);
}

/* Start the kernel */
extern void start_kernel(uint64_t entry, void* fdt,
			 uint64_t mem_top) __noreturn;
extern void start_kernel32(uint64_t entry, void* fdt,
			   uint64_t mem_top) __noreturn;
extern void start_kernel_secondary(uint64_t entry) __noreturn;

/* Get description of machine from HDAT and create device-tree */
extern int parse_hdat(bool is_opal);

struct dt_node;

/* Add /cpus/features node for boot environment that passes an fdt */
extern void dt_add_cpufeatures(struct dt_node *root);

/* Root of device tree. */
extern struct dt_node *dt_root;

/* Full skiboot version number (possibly includes gitid). */
extern const char version[];

/* Debug support */
extern char __sym_map_start[];
extern char __sym_map_end[];
extern size_t snprintf_symbol(char *buf, size_t len, uint64_t addr);

/* Direct controls */
extern void direct_controls_init(void);
extern int64_t opal_signal_system_reset(int cpu_nr);

/* Fast reboot support */
extern void disable_fast_reboot(const char *reason);
extern void add_fast_reboot_dt_entries(void);
extern void fast_reboot(void);
extern void __noreturn __secondary_cpu_entry(void);
extern void __noreturn load_and_boot_kernel(bool is_reboot);
extern void cleanup_local_tlb(void);
extern void cleanup_global_tlb(void);
extern void init_shared_sprs(void);
extern void init_replicated_sprs(void);
extern bool start_preload_kernel(void);
extern void copy_exception_vectors(void);
extern void copy_sreset_vector(void);
extern void copy_sreset_vector_fast_reboot(void);
extern void patch_traps(bool enable);

/* Various probe routines, to replace with an initcall system */
extern void probe_phb3(void);
extern void probe_phb4(void);
extern int preload_capp_ucode(void);
extern void preload_io_vpd(void);
extern void probe_npu(void);
extern void probe_npu2(void);
extern void probe_npu3(void);
extern void uart_init(void);
extern void mbox_init(void);
extern void early_uart_init(void);
extern void homer_init(void);
extern void slw_init(void);
extern void add_cpu_idle_state_properties(void);
extern void lpc_rtc_init(void);

/* flash support */
struct flash_chip;
extern int flash_register(struct blocklevel_device *bl);
extern int flash_start_preload_resource(enum resource_id id, uint32_t subid,
					void *buf, size_t *len);
extern int flash_resource_loaded(enum resource_id id, uint32_t idx);
extern bool flash_reserve(void);
extern void flash_release(void);
extern bool flash_unregister(void);
#define FLASH_SUBPART_ALIGNMENT 0x1000
#define FLASH_SUBPART_HEADER_SIZE FLASH_SUBPART_ALIGNMENT
extern int flash_subpart_info(void *part_header, uint32_t header_len,
			      uint32_t part_size, uint32_t *part_actual,
			      uint32_t subid, uint32_t *offset,
			      uint32_t *size);
extern void flash_fw_version_preload(void);
extern void flash_dt_add_fw_version(void);
extern const char *flash_map_resource_name(enum resource_id id);
extern int flash_secboot_info(uint32_t *total_size);
extern int flash_secboot_read(void *dst, uint32_t src, uint32_t len);
extern int flash_secboot_write(uint32_t dst, void *src, uint32_t len);

/*
 * Decompression routines
 *
 * The below structure members are needed for the xz library routines,
 *   src: Source address (The compressed binary)
 *   src_size: Source size
 *   dst: Destination address (The memory area where the `src` will be
 *        decompressed)
 *   dst_size: Destination size
 */
struct xz_decompress {
	void *dst;
	void *src;
	size_t dst_size;
	size_t src_size;
	/* The status of the decompress process:
	     - OPAL_PARTIAL: if the job is in progress
	     - OPAL_SUCCESS: if the job is successful
	     - OPAL_NO_MEM: memory allocation failure
	     - OPAL_PARAMETER: If any of the above (src, dst..) are invalid or
	     if xz decompress fails. In which case the caller should check the
	     xz_error for failure reason.
	 */
	int status;
	int xz_error;
	/* The decompression job, this will be freed if the caller uses
	 * `wait_xz_decompression` function, in any other case its the
	 * responsibility of caller to free the allocation job.  */
	struct cpu_job *job;
};

extern void xz_start_decompress(struct xz_decompress *);
extern void wait_xz_decompress(struct xz_decompress *);

/* NVRAM support */
extern void nvram_init(void);
extern void nvram_read_complete(bool success);

/* UART stuff */
enum {
	UART_CONSOLE_OPAL,
	UART_CONSOLE_OS
};
extern void uart_set_console_policy(int policy);
extern bool uart_enabled(void);

/* PRD */
extern void prd_psi_interrupt(uint32_t proc);
extern void prd_tmgt_interrupt(uint32_t proc);
extern void prd_occ_reset(uint32_t proc);
extern void prd_sbe_passthrough(uint32_t proc);
extern void prd_init(void);
extern void prd_register_reserved_memory(void);
extern void prd_fsp_occ_reset(uint32_t proc);
extern void prd_fsp_occ_load_start(u32 proc);
extern void prd_fw_resp_fsp_response(int status);
extern int  prd_hbrt_fsp_msg_notify(void *data, u32 dsize);

/* Flatten device-tree */
extern void *create_dtb(const struct dt_node *root, bool exclusive);

/* Track failure in Wakup engine */
enum wakeup_engine_states {
	WAKEUP_ENGINE_NOT_PRESENT,
	WAKEUP_ENGINE_PRESENT,
	WAKEUP_ENGINE_FAILED
};
extern enum wakeup_engine_states wakeup_engine_state;
extern bool has_deep_states;
extern void nx_p9_rng_late_init(void);



/* SLW reinit function for switching core settings */
extern int64_t slw_reinit(uint64_t flags);

/* Patch SPR in SLW image */
extern int64_t opal_slw_set_reg(uint64_t cpu_pir, uint64_t sprn, uint64_t val);

extern void fast_sleep_exit(void);

/* Fallback fake RTC */
extern void fake_rtc_init(void);

/* Exceptions */
struct stack_frame;
extern void exception_entry(struct stack_frame *stack);
extern void exception_entry_pm_sreset(void);
extern void __noreturn exception_entry_pm_mce(void);

/* Assembly in head.S */
extern void disable_machine_check(void);
extern void enable_machine_check(void);
extern unsigned int enter_p8_pm_state(bool winkle);
extern unsigned int enter_p9_pm_state(uint64_t psscr);
extern void enter_p9_pm_lite_state(uint64_t psscr);
extern uint32_t reset_patch_start;
extern uint32_t reset_patch_end;
extern uint32_t reset_fast_reboot_patch_start;
extern uint32_t reset_fast_reboot_patch_end;

/* Fallback fake NVRAM */
extern int fake_nvram_info(uint32_t *total_size);
extern int fake_nvram_start_read(void *dst, uint32_t src, uint32_t len);
extern int fake_nvram_write(uint32_t offset, void *src, uint32_t size);

#endif /* __SKIBOOT_H */
