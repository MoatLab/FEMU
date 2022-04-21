// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * skiboot C entry point
 *
 * Copyright 2013-2019 IBM Corp.
 */

#include <skiboot.h>
#include <psi.h>
#include <chiptod.h>
#include <nx.h>
#include <cpu.h>
#include <processor.h>
#include <xscom.h>
#include <opal.h>
#include <opal-msg.h>
#include <elf.h>
#include <elf-abi.h>
#include <io.h>
#include <cec.h>
#include <device.h>
#include <pci.h>
#include <lpc.h>
#include <i2c.h>
#include <chip.h>
#include <interrupts.h>
#include <mem_region.h>
#include <trace.h>
#include <console.h>
#include <fsi-master.h>
#include <centaur.h>
#include <ocmb.h>
#include <libfdt/libfdt.h>
#include <timer.h>
#include <ipmi.h>
#include <sensor.h>
#include <xive.h>
#include <nvram.h>
#include <vas.h>
#include <libstb/secureboot.h>
#include <libstb/trustedboot.h>
#include <phys-map.h>
#include <imc.h>
#include <dts.h>
#include <dio-p9.h>
#include <sbe-p9.h>
#include <debug_descriptor.h>
#include <occ.h>
#include <opal-dump.h>
#include <xscom-p10-regs.h>

enum proc_gen proc_gen;
unsigned int pcie_max_link_speed;
bool pci_tracing;
bool verbose_eeh;
extern const char version[];

static uint64_t kernel_entry;
static size_t kernel_size;
static bool kernel_32bit;

/* We backup the previous vectors here before copying our own */
static uint8_t old_vectors[EXCEPTION_VECTORS_END];

#ifdef DEBUG
#define DEBUG_STR "-debug"
#else
#define DEBUG_STR ""
#endif

#ifdef SKIBOOT_GCOV
void skiboot_gcov_done(void);
#endif

struct debug_descriptor debug_descriptor = {
	.eye_catcher	= "OPALdbug",
	.version	= CPU_TO_BE32(DEBUG_DESC_VERSION),
	.state_flags	= 0,
	.memcons_phys	= 0, /* cpu_to_be64(&memcons) can't init constant */
	.trace_mask	= 0, /* All traces disabled by default */
	/* console log level:
	 *   high 4 bits in memory, low 4 bits driver (e.g. uart). */
#ifdef DEBUG
	.console_log_levels = (PR_TRACE << 4) | PR_DEBUG,
#else
	.console_log_levels = (PR_DEBUG << 4) | PR_NOTICE,
#endif
};

static void checksum_romem(void);

static bool try_load_elf64_le(struct elf_hdr *header)
{
	struct elf64le_hdr *kh = (struct elf64le_hdr *)header;
	uint64_t load_base = (uint64_t)kh;
	struct elf64le_phdr *ph;
	unsigned int i;

	printf("INIT: 64-bit LE kernel discovered\n");

	/* Look for a loadable program header that has our entry in it
	 *
	 * Note that we execute the kernel in-place, we don't actually
	 * obey the load informations in the headers. This is expected
	 * to work for the Linux Kernel because it's a fairly dumb ELF
	 * but it will not work for any ELF binary.
	 */
	ph = (struct elf64le_phdr *)(load_base + le64_to_cpu(kh->e_phoff));
	for (i = 0; i < le16_to_cpu(kh->e_phnum); i++, ph++) {
		if (le32_to_cpu(ph->p_type) != ELF_PTYPE_LOAD)
			continue;
		if (le64_to_cpu(ph->p_vaddr) > le64_to_cpu(kh->e_entry) ||
		    (le64_to_cpu(ph->p_vaddr) + le64_to_cpu(ph->p_memsz)) <
		    le64_to_cpu(kh->e_entry))
			continue;

		/* Get our entry */
		kernel_entry = le64_to_cpu(kh->e_entry) -
			le64_to_cpu(ph->p_vaddr) + le64_to_cpu(ph->p_offset);
		break;
	}

	if (!kernel_entry) {
		prerror("INIT: Failed to find kernel entry !\n");
		return false;
	}
	kernel_entry += load_base;
	kernel_32bit = false;

	kernel_size = le64_to_cpu(kh->e_shoff) +
		((uint32_t)le16_to_cpu(kh->e_shentsize) *
		 (uint32_t)le16_to_cpu(kh->e_shnum));

	prlog(PR_DEBUG, "INIT: 64-bit kernel entry at 0x%llx, size 0x%lx\n",
	      kernel_entry, kernel_size);

	return true;
}

static bool try_load_elf64(struct elf_hdr *header)
{
	struct elf64be_hdr *kh = (struct elf64be_hdr *)header;
	struct elf64le_hdr *khle = (struct elf64le_hdr *)header;
	uint64_t load_base = (uint64_t)kh;
	struct elf64be_phdr *ph;
	struct elf64be_shdr *sh;
	unsigned int i;

	/* Check it's a ppc64 LE ELF */
	if (khle->ei_ident == ELF_IDENT		&&
	    khle->ei_data == ELF_DATA_LSB	&&
	    le16_to_cpu(khle->e_machine) == ELF_MACH_PPC64) {
		return try_load_elf64_le(header);
	}

	/* Check it's a ppc64 ELF */
	if (kh->ei_ident != ELF_IDENT		||
	    kh->ei_data != ELF_DATA_MSB		||
	    be16_to_cpu(kh->e_machine) != ELF_MACH_PPC64) {
		prerror("INIT: Kernel doesn't look like an ppc64 ELF\n");
		return false;
	}

	/* Look for a loadable program header that has our entry in it
	 *
	 * Note that we execute the kernel in-place, we don't actually
	 * obey the load informations in the headers. This is expected
	 * to work for the Linux Kernel because it's a fairly dumb ELF
	 * but it will not work for any ELF binary.
	 */
	ph = (struct elf64be_phdr *)(load_base + be64_to_cpu(kh->e_phoff));
	for (i = 0; i < be16_to_cpu(kh->e_phnum); i++, ph++) {
		if (be32_to_cpu(ph->p_type) != ELF_PTYPE_LOAD)
			continue;
		if (be64_to_cpu(ph->p_vaddr) > be64_to_cpu(kh->e_entry) ||
		    (be64_to_cpu(ph->p_vaddr) + be64_to_cpu(ph->p_memsz)) <
		    be64_to_cpu(kh->e_entry))
			continue;

		/* Get our entry */
		kernel_entry = be64_to_cpu(kh->e_entry) -
			be64_to_cpu(ph->p_vaddr) + be64_to_cpu(ph->p_offset);
		break;
	}

	if (!kernel_entry) {
		prerror("INIT: Failed to find kernel entry !\n");
		return false;
	}

	/* For the normal big-endian ELF ABI, the kernel entry points
	 * to a function descriptor in the data section. Linux instead
	 * has it point directly to code. Test whether it is pointing
	 * into an executable section or not to figure this out. Default
	 * to assuming it obeys the ABI.
	 */
	sh = (struct elf64be_shdr *)(load_base + be64_to_cpu(kh->e_shoff));
	for (i = 0; i < be16_to_cpu(kh->e_shnum); i++, sh++) {
		if (be64_to_cpu(sh->sh_addr) <= be64_to_cpu(kh->e_entry) &&
		    (be64_to_cpu(sh->sh_addr) + be64_to_cpu(sh->sh_size)) >
		    be64_to_cpu(kh->e_entry))
			break;
	}

	if (i == be16_to_cpu(kh->e_shnum) ||
			!(be64_to_cpu(sh->sh_flags) & ELF_SFLAGS_X)) {
		kernel_entry = *(uint64_t *)(kernel_entry + load_base);
		kernel_entry = kernel_entry -
			be64_to_cpu(ph->p_vaddr) + be64_to_cpu(ph->p_offset);
	}

	kernel_entry += load_base;
	kernel_32bit = false;

	kernel_size = be64_to_cpu(kh->e_shoff) +
		((uint32_t)be16_to_cpu(kh->e_shentsize) *
		 (uint32_t)be16_to_cpu(kh->e_shnum));

	printf("INIT: 64-bit kernel entry at 0x%llx, size 0x%lx\n",
	       kernel_entry, kernel_size);

	return true;
}

static bool try_load_elf32_le(struct elf_hdr *header)
{
	struct elf32le_hdr *kh = (struct elf32le_hdr *)header;
	uint64_t load_base = (uint64_t)kh;
	struct elf32le_phdr *ph;
	unsigned int i;

	printf("INIT: 32-bit LE kernel discovered\n");

	/* Look for a loadable program header that has our entry in it
	 *
	 * Note that we execute the kernel in-place, we don't actually
	 * obey the load informations in the headers. This is expected
	 * to work for the Linux Kernel because it's a fairly dumb ELF
	 * but it will not work for any ELF binary.
	 */
	ph = (struct elf32le_phdr *)(load_base + le32_to_cpu(kh->e_phoff));
	for (i = 0; i < le16_to_cpu(kh->e_phnum); i++, ph++) {
		if (le32_to_cpu(ph->p_type) != ELF_PTYPE_LOAD)
			continue;
		if (le32_to_cpu(ph->p_vaddr) > le32_to_cpu(kh->e_entry) ||
		    (le32_to_cpu(ph->p_vaddr) + le32_to_cpu(ph->p_memsz)) <
		    le32_to_cpu(kh->e_entry))
			continue;

		/* Get our entry */
		kernel_entry = le32_to_cpu(kh->e_entry) -
			le32_to_cpu(ph->p_vaddr) + le32_to_cpu(ph->p_offset);
		break;
	}

	if (!kernel_entry) {
		prerror("INIT: Failed to find kernel entry !\n");
		return false;
	}

	kernel_entry += load_base;
	kernel_32bit = true;

	printf("INIT: 32-bit kernel entry at 0x%llx\n", kernel_entry);

	return true;
}

static bool try_load_elf32(struct elf_hdr *header)
{
	struct elf32be_hdr *kh = (struct elf32be_hdr *)header;
	struct elf32le_hdr *khle = (struct elf32le_hdr *)header;
	uint64_t load_base = (uint64_t)kh;
	struct elf32be_phdr *ph;
	unsigned int i;

	/* Check it's a ppc32 LE ELF */
	if (khle->ei_ident == ELF_IDENT		&&
	    khle->ei_data == ELF_DATA_LSB	&&
	    le16_to_cpu(khle->e_machine) == ELF_MACH_PPC32) {
		return try_load_elf32_le(header);
	}

	/* Check it's a ppc32 ELF */
	if (kh->ei_ident != ELF_IDENT		||
	    kh->ei_data != ELF_DATA_MSB		||
	    be16_to_cpu(kh->e_machine) != ELF_MACH_PPC32) {
		prerror("INIT: Kernel doesn't look like an ppc32 ELF\n");
		return false;
	}

	/* Look for a loadable program header that has our entry in it
	 *
	 * Note that we execute the kernel in-place, we don't actually
	 * obey the load informations in the headers. This is expected
	 * to work for the Linux Kernel because it's a fairly dumb ELF
	 * but it will not work for any ELF binary.
	 */
	ph = (struct elf32be_phdr *)(load_base + be32_to_cpu(kh->e_phoff));
	for (i = 0; i < be16_to_cpu(kh->e_phnum); i++, ph++) {
		if (be32_to_cpu(ph->p_type) != ELF_PTYPE_LOAD)
			continue;
		if (be32_to_cpu(ph->p_vaddr) > be32_to_cpu(kh->e_entry) ||
		    (be32_to_cpu(ph->p_vaddr) + be32_to_cpu(ph->p_memsz)) <
		    be32_to_cpu(kh->e_entry))
			continue;

		/* Get our entry */
		kernel_entry = be32_to_cpu(kh->e_entry) -
			be32_to_cpu(ph->p_vaddr) + be32_to_cpu(ph->p_offset);
		break;
	}

	if (!kernel_entry) {
		prerror("INIT: Failed to find kernel entry !\n");
		return false;
	}

	kernel_entry += load_base;
	kernel_32bit = true;

	printf("INIT: 32-bit kernel entry at 0x%llx\n", kernel_entry);

	return true;
}

extern char __builtin_kernel_start[];
extern char __builtin_kernel_end[];
extern uint64_t boot_offset;

static size_t initramfs_size;

bool start_preload_kernel(void)
{
	int loaded;

	/* Try to load an external kernel payload through the platform hooks */
	kernel_size = KERNEL_LOAD_SIZE;
	loaded = start_preload_resource(RESOURCE_ID_KERNEL,
					RESOURCE_SUBID_NONE,
					KERNEL_LOAD_BASE,
					&kernel_size);
	if (loaded != OPAL_SUCCESS) {
		printf("INIT: platform start load kernel failed\n");
		kernel_size = 0;
		return false;
	}

	initramfs_size = INITRAMFS_LOAD_SIZE;
	loaded = start_preload_resource(RESOURCE_ID_INITRAMFS,
					RESOURCE_SUBID_NONE,
					INITRAMFS_LOAD_BASE, &initramfs_size);
	if (loaded != OPAL_SUCCESS) {
		printf("INIT: platform start load initramfs failed\n");
		initramfs_size = 0;
		return false;
	}

	return true;
}

static bool load_kernel(void)
{
	void *stb_container = NULL;
	struct elf_hdr *kh;
	int loaded;

	prlog(PR_NOTICE, "INIT: Waiting for kernel...\n");

	loaded = wait_for_resource_loaded(RESOURCE_ID_KERNEL,
					  RESOURCE_SUBID_NONE);

	if (loaded != OPAL_SUCCESS) {
		printf("INIT: platform wait for kernel load failed\n");
		kernel_size = 0;
	}

	/* Try embedded kernel payload */
	if (!kernel_size) {
		kernel_size = __builtin_kernel_end - __builtin_kernel_start;
		if (kernel_size) {
			/* Move the built-in kernel up */
			uint64_t builtin_base =
				((uint64_t)__builtin_kernel_start) -
				SKIBOOT_BASE + boot_offset;
			printf("Using built-in kernel\n");
			memmove(KERNEL_LOAD_BASE, (void*)builtin_base,
				kernel_size);
		}
	}

	if (dt_has_node_property(dt_chosen, "kernel-base-address", NULL)) {
		kernel_entry = dt_prop_get_u64(dt_chosen,
					       "kernel-base-address");
		prlog(PR_DEBUG, "INIT: Kernel image at 0x%llx\n", kernel_entry);
		kh = (struct elf_hdr *)kernel_entry;
		/*
		 * If the kernel is at 0, restore it as it was overwritten
		 * by our vectors.
		 */
		if (kernel_entry < EXCEPTION_VECTORS_END) {
			cpu_set_sreset_enable(false);
			memcpy_null(NULL, old_vectors, EXCEPTION_VECTORS_END);
			sync_icache();
		} else {
			/* Hack for STB in Mambo, assume at least 4kb in mem */
			if (!kernel_size)
				kernel_size = SECURE_BOOT_HEADERS_SIZE;
			if (stb_is_container((void*)kernel_entry, kernel_size)) {
				stb_container = (void*)kernel_entry;
				kh = (struct elf_hdr *) (kernel_entry + SECURE_BOOT_HEADERS_SIZE);
			} else
				kh = (struct elf_hdr *) (kernel_entry);
		}
	} else {
		if (!kernel_size) {
			printf("INIT: Assuming kernel at %p\n",
			       KERNEL_LOAD_BASE);
			/* Hack for STB in Mambo, assume at least 4kb in mem */
			kernel_size = SECURE_BOOT_HEADERS_SIZE;
			kernel_entry = (uint64_t)KERNEL_LOAD_BASE;
		}
		if (stb_is_container(KERNEL_LOAD_BASE, kernel_size)) {
			stb_container = KERNEL_LOAD_BASE;
			kh = (struct elf_hdr *) (KERNEL_LOAD_BASE + SECURE_BOOT_HEADERS_SIZE);
		} else
			kh = (struct elf_hdr *) (KERNEL_LOAD_BASE);

	}

	prlog(PR_DEBUG,
	      "INIT: Kernel loaded, size: %zu bytes (0 = unknown preload)\n",
	      kernel_size);

	if (kh->ei_ident != ELF_IDENT) {
		prerror("INIT: ELF header not found. Assuming raw binary.\n");
		return true;
	}

	if (kh->ei_class == ELF_CLASS_64) {
		if (!try_load_elf64(kh))
			return false;
	} else if (kh->ei_class == ELF_CLASS_32) {
		if (!try_load_elf32(kh))
			return false;
	} else {
		prerror("INIT: Neither ELF32 not ELF64 ?\n");
		return false;
	}

	if (chip_quirk(QUIRK_MAMBO_CALLOUTS)) {
		secureboot_verify(RESOURCE_ID_KERNEL,
				  stb_container,
				  SECURE_BOOT_HEADERS_SIZE + kernel_size);
		trustedboot_measure(RESOURCE_ID_KERNEL,
				    stb_container,
				    SECURE_BOOT_HEADERS_SIZE + kernel_size);
	}

	return true;
}

static void load_initramfs(void)
{
	uint64_t *initramfs_start;
	void *stb_container = NULL;
	int loaded;

	loaded = wait_for_resource_loaded(RESOURCE_ID_INITRAMFS,
					  RESOURCE_SUBID_NONE);

	if (loaded != OPAL_SUCCESS || !initramfs_size)
		return;

	if (stb_is_container(INITRAMFS_LOAD_BASE, initramfs_size)) {
		stb_container = INITRAMFS_LOAD_BASE;
		initramfs_start = INITRAMFS_LOAD_BASE + SECURE_BOOT_HEADERS_SIZE;
	} else {
		initramfs_start = INITRAMFS_LOAD_BASE;
	}

	dt_check_del_prop(dt_chosen, "linux,initrd-start");
	dt_check_del_prop(dt_chosen, "linux,initrd-end");

	printf("INIT: Initramfs loaded, size: %zu bytes\n", initramfs_size);

	dt_add_property_u64(dt_chosen, "linux,initrd-start",
			(uint64_t)initramfs_start);
	dt_add_property_u64(dt_chosen, "linux,initrd-end",
			(uint64_t)initramfs_start + initramfs_size);

	if (chip_quirk(QUIRK_MAMBO_CALLOUTS)) {
		secureboot_verify(RESOURCE_ID_INITRAMFS,
				  stb_container,
				  SECURE_BOOT_HEADERS_SIZE + initramfs_size);
		trustedboot_measure(RESOURCE_ID_INITRAMFS,
				    stb_container,
				    SECURE_BOOT_HEADERS_SIZE + initramfs_size);
	}
}

static void cpu_disable_ME_RI_one(void *param __unused)
{
	disable_machine_check();
	mtmsrd(0, 1);
}

static int64_t cpu_disable_ME_RI_all(void)
{
	struct cpu_thread *cpu;
	struct cpu_job **jobs;

	jobs = zalloc(sizeof(struct cpu_job *) * (cpu_max_pir + 1));
	assert(jobs);

	for_each_available_cpu(cpu) {
		if (cpu == this_cpu())
			continue;
		jobs[cpu->pir] = cpu_queue_job(cpu, "cpu_disable_ME_RI",
						cpu_disable_ME_RI_one, NULL);
	}

	/* this cpu */
	cpu_disable_ME_RI_one(NULL);

	for_each_available_cpu(cpu) {
		if (jobs[cpu->pir])
			cpu_wait_job(jobs[cpu->pir], true);
	}

	free(jobs);

	return OPAL_SUCCESS;
}

static void *fdt;

void __noreturn load_and_boot_kernel(bool is_reboot)
{
	const struct dt_property *memprop;
	const char *cmdline, *stdoutp;
	uint64_t mem_top;

	memprop = dt_find_property(dt_root, DT_PRIVATE "maxmem");
	if (memprop)
		mem_top = (u64)dt_property_get_cell(memprop, 0) << 32
			| dt_property_get_cell(memprop, 1);
	else /* XXX HB hack, might want to calc it */
		mem_top = 0x40000000;

	op_display(OP_LOG, OP_MOD_INIT, 0x000A);

	/* Load kernel LID */
	if (!load_kernel()) {
		op_display(OP_FATAL, OP_MOD_INIT, 1);
		abort();
	}

	load_initramfs();

	trustedboot_exit_boot_services();

	ipmi_set_fw_progress_sensor(IPMI_FW_OS_BOOT);


	if (!is_reboot) {
		/* We wait for the nvram read to complete here so we can
		 * grab stuff from there such as the kernel arguments
		 */
		nvram_wait_for_load();

		if (!occ_sensors_init())
			dts_sensor_create_nodes(sensor_node);

	} else {
		/* fdt will be rebuilt */
		free(fdt);
		fdt = NULL;

		nvram_reinit();
		occ_pstates_init();
	}

	/* Use nvram bootargs over device tree */
	cmdline = nvram_query_safe("bootargs");
	if (cmdline) {
		dt_check_del_prop(dt_chosen, "bootargs");
		dt_add_property_string(dt_chosen, "bootargs", cmdline);
		prlog(PR_DEBUG, "INIT: Command line from NVRAM: %s\n",
		      cmdline);
	}

	op_display(OP_LOG, OP_MOD_INIT, 0x000B);

	add_fast_reboot_dt_entries();

	if (platform.finalise_dt)
		platform.finalise_dt(is_reboot);

	/* Create the device tree blob to boot OS. */
	fdt = create_dtb(dt_root, false);
	if (!fdt) {
		op_display(OP_FATAL, OP_MOD_INIT, 2);
		abort();
	}

	op_display(OP_LOG, OP_MOD_INIT, 0x000C);

	mem_dump_free();

	/* Dump the selected console */
	stdoutp = dt_prop_get_def(dt_chosen, "linux,stdout-path", NULL);
	prlog(PR_DEBUG, "INIT: stdout-path: %s\n", stdoutp ? stdoutp : "");

	fdt_set_boot_cpuid_phys(fdt, this_cpu()->pir);

	/* Check there is something there before we branch to it */
	if (*(uint32_t *)kernel_entry == 0) {
		prlog(PR_EMERG, "FATAL: Kernel is zeros, can't execute!\n");
		assert(0);
	}

	if (platform.exit)
		platform.exit();

	/* Take processors out of nap */
	cpu_set_sreset_enable(false);
	cpu_set_ipi_enable(false);

	printf("INIT: Starting kernel at 0x%llx, fdt at %p %u bytes\n",
	       kernel_entry, fdt, fdt_totalsize(fdt));

	/* Disable machine checks on all */
	cpu_disable_ME_RI_all();

	patch_traps(false);
	cpu_set_hile_mode(false); /* Clear HILE on all CPUs */

	/* init MPIPL */
	if (!is_reboot)
		opal_mpipl_init();

	checksum_romem();

	debug_descriptor.state_flags |= OPAL_BOOT_COMPLETE;

	cpu_give_self_os();

	if (kernel_32bit)
		start_kernel32(kernel_entry, fdt, mem_top);
	start_kernel(kernel_entry, fdt, mem_top);
}

static void storage_keys_fixup(void)
{
	struct dt_node *cpus, *n;

	cpus = dt_find_by_path(dt_root, "/cpus");
	assert(cpus);

	if (proc_gen == proc_gen_unknown)
		return;

	dt_for_each_child(cpus, n) {
		/* There may be cache nodes in /cpus. */
		if (!dt_has_node_property(n, "device_type", "cpu") ||
		    dt_has_node_property(n, "ibm,processor-storage-keys", NULL))
			continue;

		/*
		 * skiboot supports p8 & p9, both of which support the IAMR, and
		 * both of which support 32 keys. So advertise 32 keys for data
		 * accesses and 32 for instruction accesses.
		 */
		dt_add_property_cells(n, "ibm,processor-storage-keys", 32, 32);
	}
}

static void dt_fixups(void)
{
	struct dt_node *n;
	struct dt_node *primary_lpc = NULL;

	/* lpc node missing #address/size cells. Also pick one as
	 * primary for now (TBD: How to convey that from HB)
	 */
	dt_for_each_compatible(dt_root, n, "ibm,power8-lpc") {
		if (!primary_lpc || dt_has_node_property(n, "primary", NULL))
			primary_lpc = n;
		if (dt_has_node_property(n, "#address-cells", NULL))
			break;
		dt_add_property_cells(n, "#address-cells", 2);
		dt_add_property_cells(n, "#size-cells", 1);
		dt_add_property_strings(n, "status", "ok");
	}

	/* Missing "primary" property in LPC bus */
	if (primary_lpc && !dt_has_node_property(primary_lpc, "primary", NULL))
		dt_add_property(primary_lpc, "primary", NULL, 0);

	/* Missing "scom-controller" */
	dt_for_each_compatible(dt_root, n, "ibm,xscom") {
		if (!dt_has_node_property(n, "scom-controller", NULL))
			dt_add_property(n, "scom-controller", NULL, 0);
	}

	storage_keys_fixup();
}

static void add_arch_vector(void)
{
	/**
	 * vec5 = a PVR-list : Number-of-option-vectors :
	 *	  option-vectors[Number-of-option-vectors + 1]
	 */
	uint8_t vec5[] = {0x05, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00};

	if (dt_has_node_property(dt_chosen, "ibm,architecture-vec-5", NULL))
		return;

	dt_add_property(dt_chosen, "ibm,architecture-vec-5",
			vec5, sizeof(vec5));
}

static void dt_init_misc(void)
{
	/* Check if there's a /chosen node, if not, add one */
	dt_chosen = dt_find_by_path(dt_root, "/chosen");
	if (!dt_chosen)
		dt_chosen = dt_new(dt_root, "chosen");
	assert(dt_chosen);

	/* Add IBM architecture vectors if needed */
	add_arch_vector();

	/* Add the "OPAL virtual ICS*/
	add_ics_node();

	/* Additional fixups. TODO: Move into platform */
	dt_fixups();
}

static u8 console_get_level(const char *s)
{
	if (strcmp(s, "emerg") == 0)
		return PR_EMERG;
	if (strcmp(s, "alert") == 0)
		return PR_ALERT;
	if (strcmp(s, "crit") == 0)
		return PR_CRIT;
	if (strcmp(s, "err") == 0)
		return PR_ERR;
	if (strcmp(s, "warning") == 0)
		return PR_WARNING;
	if (strcmp(s, "notice") == 0)
		return PR_NOTICE;
	if (strcmp(s, "printf") == 0)
		return PR_PRINTF;
	if (strcmp(s, "info") == 0)
		return PR_INFO;
	if (strcmp(s, "debug") == 0)
		return PR_DEBUG;
	if (strcmp(s, "trace") == 0)
		return PR_TRACE;
	if (strcmp(s, "insane") == 0)
		return PR_INSANE;
	/* Assume it's a number instead */
	return atoi(s);
}

static void console_log_level(void)
{
	const char *s;
	u8 level;

	/* console log level:
	 *   high 4 bits in memory, low 4 bits driver (e.g. uart). */
	s = nvram_query_safe("log-level-driver");
	if (s) {
		level = console_get_level(s);
		debug_descriptor.console_log_levels =
			(debug_descriptor.console_log_levels & 0xf0 ) |
			(level & 0x0f);
		prlog(PR_NOTICE, "console: Setting driver log level to %i\n",
		      level & 0x0f);
	}
	s = nvram_query_safe("log-level-memory");
	if (s) {
		level = console_get_level(s);
		debug_descriptor.console_log_levels =
			(debug_descriptor.console_log_levels & 0x0f ) |
			((level & 0x0f) << 4);
		prlog(PR_NOTICE, "console: Setting memory log level to %i\n",
		      level & 0x0f);
	}
}

typedef void (*ctorcall_t)(void);

static void __nomcount do_ctors(void)
{
	extern ctorcall_t __ctors_start[], __ctors_end[];
	ctorcall_t *call;

	for (call = __ctors_start; call < __ctors_end; call++)
		(*call)();
}

#ifdef ELF_ABI_v2
static void setup_branch_null_catcher(void)
{
	asm volatile(							\
		".section .rodata"				"\n\t"	\
		"3:	.string	\"branch to NULL\""		"\n\t"	\
		".previous"					"\n\t"	\
		".section .trap_table,\"aw\""			"\n\t"	\
		".llong	0"					"\n\t"	\
		".llong	3b"					"\n\t"	\
		".previous"					"\n\t"	\
		);
}
#else
static void branch_null(void)
{
	assert(0);
}

static void setup_branch_null_catcher(void)
{
       void (*bn)(void) = branch_null;

       /*
        * FIXME: This copies the function descriptor (16 bytes) for
        * ABI v1 (ie. big endian).  This will be broken if we ever
        * move to ABI v2 (ie little endian)
        */
       memcpy_null((void *)0, bn, 16);
}
#endif

void copy_sreset_vector(void)
{
	uint32_t *src, *dst;

	/* Copy the reset code over the entry point. */
	src = &reset_patch_start;
	dst = (uint32_t *)0x100;
	while(src < &reset_patch_end)
		*(dst++) = *(src++);
	sync_icache();
}

void copy_sreset_vector_fast_reboot(void)
{
	uint32_t *src, *dst;

	/* Copy the reset code over the entry point. */
	src = &reset_fast_reboot_patch_start;
	dst = (uint32_t *)0x100;
	while(src < &reset_fast_reboot_patch_end)
		*(dst++) = *(src++);
	sync_icache();
}

void copy_exception_vectors(void)
{
	/* Copy from 0x100 to EXCEPTION_VECTORS_END, avoid below 0x100 as
	 * this is the boot flag used by CPUs still potentially entering
	 * skiboot.
	 */
	memcpy((void *)0x100, (void *)(SKIBOOT_BASE + 0x100),
			EXCEPTION_VECTORS_END - 0x100);
	sync_icache();
}

/*
 * When skiboot owns the exception vectors, patch in 'trap' for assert fails.
 * Otherwise use assert_fail()
 */
void patch_traps(bool enable)
{
	struct trap_table_entry *tte;

	for (tte = __trap_table_start; tte < __trap_table_end; tte++) {
		uint32_t *insn;

		insn = (uint32_t *)tte->address;
		if (enable) {
			*insn = PPC_INST_TRAP;
		} else {
			*insn = PPC_INST_NOP;
		}
	}

	sync_icache();
}

static void per_thread_sanity_checks(void)
{
	struct cpu_thread *cpu = this_cpu();

	/**
	 * @fwts-label NonZeroHRMOR
	 * @fwts-advice The contents of the hypervisor real mode offset register
	 * (HRMOR) is bitwise orded with the address of any hypervisor real mode
	 * (i.e Skiboot) memory accesses. Skiboot does not support operating
	 * with a non-zero HRMOR and setting it will break some things (e.g
	 * XSCOMs) in hard-to-debug ways.
	 */
	assert(mfspr(SPR_HRMOR) == 0);

	/**
	 * @fwts-label UnknownSecondary
	 * @fwts-advice The boot CPU attampted to call in a secondary thread
	 * without initialising the corresponding cpu_thread structure. This may
	 * happen if the HDAT or devicetree reports too few threads or cores for
	 * this processor.
	 */
	assert(cpu->state != cpu_state_no_cpu);
}

void pci_nvram_init(void)
{
	const char *nvram_speed;

	verbose_eeh = nvram_query_eq_safe("pci-eeh-verbose", "true");
	if (verbose_eeh)
		prlog(PR_INFO, "PHB: Verbose EEH enabled\n");

	pcie_max_link_speed = 0;

	nvram_speed = nvram_query_dangerous("pcie-max-link-speed");
	if (nvram_speed) {
		pcie_max_link_speed = atoi(nvram_speed);
		prlog(PR_NOTICE, "PHB: NVRAM set max link speed to GEN%i\n",
		      pcie_max_link_speed);
	}

	pci_tracing = nvram_query_eq_safe("pci-tracing", "true");
}

static uint32_t mem_csum(void *_p, void *_e)
{
	size_t len = _e - _p;
	uint32_t *p = _p;
	uint32_t v1 = 0, v2 = 0;
	uint32_t csum;
	unsigned int i;

	for (i = 0; i < len; i += 4) {
		uint32_t v = *p++;
		v1 += v;
		v2 += v1;
	}

	csum = v1 ^ v2;

	return csum;
}

static uint32_t romem_csum;

static void checksum_romem(void)
{
	uint32_t csum;

	romem_csum = 0;
	if (chip_quirk(QUIRK_SLOW_SIM))
		return;

	csum = mem_csum(_start, _head_end);
	romem_csum ^= csum;

	csum = mem_csum(_stext, _romem_end);
	romem_csum ^= csum;

	csum = mem_csum(__builtin_kernel_start, __builtin_kernel_end);
	romem_csum ^= csum;
}

bool verify_romem(void)
{
	uint32_t old = romem_csum;
	checksum_romem();
	if (old != romem_csum) {
		romem_csum = old;
		prlog(PR_NOTICE, "OPAL checksums did not match\n");
		return false;
	}
	return true;
}

static void mask_pc_system_xstop(void)
{
        struct cpu_thread *cpu;
        uint32_t chip_id, core_id;
        int rc;

	if (proc_gen != proc_gen_p10)
                return;

	if (chip_quirk(QUIRK_MAMBO_CALLOUTS))
		return;

        /*
         * On P10 Mask PC system checkstop (bit 28). This is needed
         * for HW570622. We keep processor recovery disabled via
         * HID[5] and mask the checkstop that it can cause. CME does
         * the recovery handling for us.
         */
        for_each_cpu(cpu) {
                chip_id = cpu->chip_id;
                core_id = pir_to_core_id(cpu->pir);

                rc = xscom_write(chip_id,
                                 XSCOM_ADDR_P10_EC(core_id, P10_CORE_FIRMASK_OR),
                                 PPC_BIT(28));
                if (rc)
                        prerror("Error setting FIR MASK rc:%d on PIR:%x\n",
                                rc, cpu->pir);
        }
}


/* Called from head.S, thus no prototype. */
void __noreturn __nomcount  main_cpu_entry(const void *fdt);

void __noreturn __nomcount main_cpu_entry(const void *fdt)
{
	/*
	 * WARNING: At this point. the timebases have
	 * *not* been synchronized yet. Do not use any timebase
	 * related functions for timeouts etc... unless you can cope
	 * with the speed being some random core clock divider and
	 * the value jumping backward when the synchronization actually
	 * happens (in chiptod_init() below).
	 *
	 * Also the current cpu_thread() struct is not initialized
	 * either so we need to clear it out first thing first (without
	 * putting any other useful info in there jus yet) otherwise
	 * printf an locks are going to play funny games with "con_suspend"
	 */
	pre_init_boot_cpu();

	/*
	 * Point to our mem console
	 */
	debug_descriptor.memcons_phys = cpu_to_be64((uint64_t)&memcons);

	/*
	 * Before first printk, ensure console buffer is clear or
	 * reading tools might think it has wrapped
	 */
	clear_console();

	/* Backup previous vectors as this could contain a kernel
	 * image.
	 */
	memcpy_null(old_vectors, NULL, EXCEPTION_VECTORS_END);

	/*
	 * Some boot firmwares enter OPAL with MSR[ME]=1, as they presumably
	 * handle machine checks until we take over. As we overwrite the
	 * previous exception vectors with our own handlers, disable MSR[ME].
	 * This could be done atomically by patching in a branch then patching
	 * it out last, but that's a lot of effort.
	 */
	disable_machine_check();

	/* Copy all vectors down to 0 */
	copy_exception_vectors();

	/* Enable trap based asserts */
	patch_traps(true);

	/*
	 * Enable MSR[ME] bit so we can take MCEs. We don't currently
	 * recover, but we print some useful information.
	 */
	enable_machine_check();
	mtmsrd(MSR_RI, 1);

	/* Setup a NULL catcher to catch accidental NULL ptr calls */
	setup_branch_null_catcher();

	/* Call library constructors */
	do_ctors();

	prlog(PR_NOTICE, "OPAL %s%s starting...\n", version, DEBUG_STR);

	prlog(PR_DEBUG, "initial console log level: memory %d, driver %d\n",
	       (debug_descriptor.console_log_levels >> 4),
	       (debug_descriptor.console_log_levels & 0x0f));
	prlog(PR_TRACE, "OPAL is Powered By Linked-List Technology.\n");

#ifdef SKIBOOT_GCOV
	skiboot_gcov_done();
#endif

	/* Initialize boot cpu's cpu_thread struct */
	init_boot_cpu();

	/* Now locks can be used */
	init_locks();

	/* Create the OPAL call table early on, entries can be overridden
	 * later on (FSP console code for example)
	 */
	opal_table_init();

	/* Init the physical map table so we can start mapping things */
	phys_map_init(mfspr(SPR_PVR));

	/*
	 * If we are coming in with a flat device-tree, we expand it
	 * now. Else look for HDAT and create a device-tree from them
	 *
	 * Hack alert: When entering via the OPAL entry point, fdt
	 * is set to -1, we record that and pass it to parse_hdat
	 */

	dt_root = dt_new_root("");

	if (fdt == (void *)-1ul) {
		if (parse_hdat(true) < 0)
			abort();
	} else if (fdt == NULL) {
		if (parse_hdat(false) < 0)
			abort();
	} else {
		dt_expand(fdt);
	}
	dt_add_cpufeatures(dt_root);

	/* Now that we have a full devicetree, verify that we aren't on fire. */
	per_thread_sanity_checks();

	/*
	 * From there, we follow a fairly strict initialization order.
	 *
	 * First we need to build up our chip data structures and initialize
	 * XSCOM which will be needed for a number of susbequent things.
	 *
	 * We want XSCOM available as early as the platform probe in case the
	 * probe requires some HW accesses.
	 *
	 * We also initialize the FSI master at that point in case we need
	 * to access chips via that path early on.
	 */
	init_chips();

	xscom_init();
	mfsi_init();

	/*
	 * Direct controls facilities provides some controls over CPUs
	 * using scoms.
	 */
	direct_controls_init();

	/*
	 * Put various bits & pieces in device-tree that might not
	 * already be there such as the /chosen node if not there yet,
	 * the ICS node, etc... This can potentially use XSCOM
	 */
	dt_init_misc();

	/*
	 * Initialize LPC (P8 and beyond) so we can get to UART, BMC and
	 * other system controller. This is done before probe_platform
	 * so that the platform probing code can access an external
	 * BMC if needed.
	 */
	lpc_init();

	/*
	 * This should be done before mem_region_init, so the stack
	 * region length can be set according to the maximum PIR.
	 */
	init_cpu_max_pir();

	/*
	 * Now, we init our memory map from the device-tree, and immediately
	 * reserve areas which we know might contain data coming from
	 * HostBoot. We need to do these things before we start doing
	 * allocations outside of our heap, such as chip local allocs,
	 * otherwise we might clobber those data.
	 */
	mem_region_init();

	/*
	 * Reserve memory required to capture OPAL dump. This should be done
	 * immediately after mem_region_init to avoid any clash with local
	 * memory allocation.
	 */
	opal_mpipl_reserve_mem();

	/* Reserve HOMER and OCC area */
	homer_init();

	/* Initialize the rest of the cpu thread structs */
	init_all_cpus();
	if (proc_gen == proc_gen_p9 || proc_gen == proc_gen_p10)
		cpu_set_ipi_enable(true);

        /* Once all CPU are up apply this workaround */
        mask_pc_system_xstop();

	/* Add the /opal node to the device-tree */
	add_opal_node();

	/*
	 * We probe the platform now. This means the platform probe gets
	 * the opportunity to reserve additional areas of memory if needed.
	 *
	 * Note: Timebases still not synchronized.
	 */
	probe_platform();

	/* Allocate our split trace buffers now. Depends add_opal_node() */
	init_trace_buffers();

	/* On P8, get the ICPs and make sure they are in a sane state */
	init_interrupts();
	if (proc_gen == proc_gen_p8)
		cpu_set_ipi_enable(true);

	/* On P9 and P10, initialize XIVE */
	if (proc_gen == proc_gen_p9)
		init_xive();
	else if (proc_gen == proc_gen_p10)
		xive2_init();

	/* Grab centaurs from device-tree if present (only on FSP-less) */
	centaur_init();

	/* initialize ocmb scom-controller */
	ocmb_init();

	/* Initialize PSI (depends on probe_platform being called) */
	psi_init();

	/* Initialize/enable LPC interrupts. This must be done after the
	 * PSI interface has been initialized since it serves as an interrupt
	 * source for LPC interrupts.
	 */
	lpc_init_interrupts();

	/* Call in secondary CPUs */
	cpu_bringup();

	/* We can now overwrite the 0x100 vector as we are no longer being
	 * entered there.
	 */
	copy_sreset_vector();

	/* We can now do NAP mode */
	cpu_set_sreset_enable(true);

	/*
	 * Synchronize time bases. Prior to chiptod_init() the timebase
	 * is free-running at a frequency based on the core clock rather
	 * than being synchronised to the ChipTOD network. This means
	 * that the timestamps in early boot might be a little off compared
	 * to wall clock time.
	 */
	chiptod_init();

	/* Initialize P9 DIO */
	p9_dio_init();

	/*
	 * SBE uses TB value for scheduling timer. Hence init after
	 * chiptod init
	 */
	p9_sbe_init();

	/* Initialize i2c */
	p8_i2c_init();

	/* Register routine to dispatch and read sensors */
	sensor_init();

        /*
	 * Initialize the opal messaging before platform.init as we are
	 * getting request to queue occ load opal message when host services
	 * got load occ request from FSP
	 */
        opal_init_msg();

	/*
	 * We have initialized the basic HW, we can now call into the
	 * platform to perform subsequent inits, such as establishing
	 * communication with the FSP or starting IPMI.
	 */
	if (platform.init)
		platform.init();

	/* Read in NVRAM and set it up */
	nvram_init();

	/* Set the console level */
	console_log_level();

	/* Secure/Trusted Boot init. We look for /ibm,secureboot in DT */
	secureboot_init();
	trustedboot_init();

	/* Secure variables init, handled by platform */
	if (platform.secvar_init && is_fw_secureboot())
		platform.secvar_init();

	/*
	 * BMC platforms load version information from flash after
	 * secure/trustedboot init.
	 */
	if (platform.bmc)
		flash_fw_version_preload();

        /* preload the IMC catalog dtb */
        imc_catalog_preload();

	/* Install the OPAL Console handlers */
	init_opal_console();

	/*
	 * Some platforms set a flag to wait for SBE validation to be
	 * performed by the BMC. If this occurs it leaves the SBE in a
	 * bad state and the system will reboot at this point.
	 */
	if (platform.seeprom_update)
		platform.seeprom_update();

	/* Init SLW related stuff, including fastsleep */
	slw_init();

	op_display(OP_LOG, OP_MOD_INIT, 0x0002);

	/*
	 * On some POWER9 BMC systems, we need to initialise the OCC
	 * before the NPU to facilitate NVLink/OpenCAPI presence
	 * detection, so we set it up as early as possible. On FSP
	 * systems, Hostboot starts booting the OCC later, so we delay
	 * OCC initialisation as late as possible to give it the
	 * maximum time to boot up.
	 */
	if (platform.bmc)
		occ_pstates_init();

	pci_nvram_init();

	preload_capp_ucode();
	start_preload_kernel();

	/* Catalog decompression routine */
	imc_decompress_catalog();

	/* Virtual Accelerator Switchboard */
	vas_init();

	/* NX init */
	nx_init();

	/* Probe PHB3 on P8 */
	probe_phb3();

	/* Probe PHB4 on P9 and PHB5 on P10 */
	probe_phb4();

	/* Probe NPUs */
	probe_npu();
	probe_npu2();
	probe_npu3();

	/* Initialize PCI */
	pci_init_slots();

	/* Add OPAL timer related properties */
	late_init_timers();

	/* Setup ibm,firmware-versions if able */
	if (platform.bmc) {
		flash_dt_add_fw_version();
		ipmi_dt_add_bmc_info();
	}

	ipmi_set_fw_progress_sensor(IPMI_FW_PCI_INIT);

	/*
	 * These last few things must be done as late as possible
	 * because they rely on various other things having been setup,
	 * for example, add_opal_interrupts() will add all the interrupt
	 * sources that are going to the firmware. We can't add a new one
	 * after that call. Similarly, the mem_region calls will construct
	 * the reserve maps in the DT so we shouldn't affect the memory
	 * regions after that
	 */

	/* Create the LPC bus interrupt-map on P9 */
	lpc_finalize_interrupts();

	/* Add the list of interrupts going to OPAL */
	add_opal_interrupts();

	/* Init In-Memory Collection related stuff (load the IMC dtb into memory) */
	imc_init();

	/* Disable protected execution facility in BML */
	cpu_disable_pef();

	/* export the trace buffers */
	trace_add_dt_props();

	/* Now release parts of memory nodes we haven't used ourselves... */
	mem_region_release_unused();

	/* ... and add remaining reservations to the DT */
	mem_region_add_dt_reserved();

	/*
	 * Update /ibm,secureboot/ibm,cvc/memory-region to point to
	 * /reserved-memory/secure-crypt-algo-code instead of
	 * /ibm,hostboot/reserved-memory/secure-crypt-algo-code.
	 */
	cvc_update_reserved_memory_phandle();

	prd_register_reserved_memory();

	load_and_boot_kernel(false);
}

void __noreturn __secondary_cpu_entry(void)
{
	struct cpu_thread *cpu = this_cpu();

	/* Secondary CPU called in */
	cpu_callin(cpu);

	enable_machine_check();
	mtmsrd(MSR_RI, 1);

	/* Some XIVE setup */
	if (proc_gen == proc_gen_p9)
		xive_cpu_callin(cpu);
	else if (proc_gen == proc_gen_p10)
		xive2_cpu_callin(cpu);

	/* Wait for work to do */
	while(true) {
		if (cpu_check_jobs(cpu))
			cpu_process_jobs();
		else
			cpu_idle_job();
	}
}

/* Called from head.S, thus no prototype. */
void __noreturn __nomcount secondary_cpu_entry(void);

void __noreturn __nomcount secondary_cpu_entry(void)
{
	struct cpu_thread *cpu = this_cpu();

	per_thread_sanity_checks();

	prlog(PR_DEBUG, "INIT: CPU PIR 0x%04x called in\n", cpu->pir);

	__secondary_cpu_entry();
}
