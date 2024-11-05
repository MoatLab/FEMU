// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Given a hdata dump, output the device tree.
 *
 * Copyright 2013-2020 IBM Corp.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <mem_region-malloc.h>

#include <interrupts.h>
#include <bitutils.h>

#include <skiboot-valgrind.h>

#include "../../libfdt/fdt.c"
#include "../../libfdt/fdt_ro.c"
#include "../../libfdt/fdt_sw.c"
#include "../../libfdt/fdt_strerror.c"

struct dt_node *opal_node;

/* Our actual map. */
static void *spira_heap;
static off_t spira_heap_size;
static uint64_t base_addr;

/* Override ntuple_addr. */
#define ntuple_addr ntuple_addr
struct spira_ntuple;
static void *ntuple_addr(const struct spira_ntuple *n);

/* Stuff which core expects. */
struct cpu_thread *my_fake_cpu;
static struct cpu_thread *this_cpu(void)
{
	return my_fake_cpu;
}

unsigned long tb_hz = 512000000;

/* Don't include processor-specific stuff. */
#define __PROCESSOR_H
/* PVR bits */
#define SPR_PVR_TYPE			0xffff0000
#define SPR_PVR_VERS_MAJ		0x00000f00
#define SPR_PVR_VERS_MIN		0x000000ff

#define PVR_TYPE(_pvr)		GETFIELD(SPR_PVR_TYPE, _pvr)
#define PVR_VERS_MAJ(_pvr)	GETFIELD(SPR_PVR_VERS_MAJ, _pvr)
#define PVR_VERS_MIN(_pvr)	GETFIELD(SPR_PVR_VERS_MIN, _pvr)

/* PVR definitions - copied from skiboot include/processor.h */
#define PVR_TYPE_P8E	0x004b
#define PVR_TYPE_P8	0x004d
#define PVR_TYPE_P8NVL	0x004c
#define PVR_TYPE_P9	0x004e
#define PVR_TYPE_P9P	0x004f
#define PVR_TYPE_P10	0x0080
#define PVR_P8E		0x004b0201
#define PVR_P8		0x004d0200
#define PVR_P8NVL	0x004c0100
#define PVR_P9		0x004e0200
#define PVR_P9P		0x004f0100
#define PVR_P10		0x00800100

#define SPR_PVR		0x11f	/* RO: Processor version register */

#define MSR_SF		0x8000000000000000ULL
#define MSR_HV		0x1000000000000000ULL

#define __CPU_H
struct cpu_thread {
	uint32_t			pir;
	uint32_t			chip_id;
	bool				is_fused_core;
};
struct cpu_job *__cpu_queue_job(struct cpu_thread *cpu,
				const char *name,
				void (*func)(void *data), void *data,
				bool no_return);
void cpu_wait_job(struct cpu_job *job, bool free_it);
void cpu_process_local_jobs(void);
struct cpu_job *cpu_queue_job_on_node(uint32_t chip_id,
				       const char *name,
				       void (*func)(void *data), void *data);
static inline struct cpu_job *cpu_queue_job(struct cpu_thread *cpu,
					    const char *name,
					    void (*func)(void *data),
					    void *data)
{
	return __cpu_queue_job(cpu, name, func, data, false);
}

struct cpu_thread __boot_cpu, *boot_cpu = &__boot_cpu;
static unsigned long fake_pvr = PVR_P8;

unsigned int cpu_thread_count = 8;

static inline unsigned long mfspr(unsigned int spr)
{
	assert(spr == SPR_PVR);
	return fake_pvr;
}

struct dt_node *add_ics_node(void)
{
	return NULL;
}

// Copied from processor.h:
static inline bool is_power9n(uint32_t version)
{
	if (PVR_TYPE(version) != PVR_TYPE_P9)
		return false;
	/*
	 * Bit 13 tells us:
	 *   0 = Scale out (aka Nimbus)
	 *   1 = Scale up  (aka Cumulus)
	 */
	if ((version >> 13) & 1)
		return false;
	return true;
}

#include <config.h>
#include <bitutils.h>

/* Your pointers won't be correct, that's OK. */
#define spira_check_ptr spira_check_ptr

static bool spira_check_ptr(const void *ptr, const char *file, unsigned int line);

/* should probably check this */
#define BITS_PER_LONG 64
/* not used, just needs to exist */
#define cpu_max_pir 0x7

#include "../cpu-common.c"
#include "../fsp.c"
#include "../hdif.c"
#include "../iohub.c"
#include "../memory.c"
#include "../pcia.c"
#include "../spira.c"
#include "../vpd.c"
#include "../vpd-common.c"
#include "../slca.c"
#include "../hostservices.c"
#include "../i2c.c"
#include "../tpmrel.c"
#include "../../core/vpd.c"
#include "../../core/device.c"
#include "../../core/chip.c"
#include "../../test/dt_common.c"
#include "../../core/fdt.c"
#include "../../hw/phys-map.c"
#include "../../core/mem_region.c"

#include <err.h>

#include <op-panel.h>

bool fsp_present()
{
	return false;
}

void op_display(enum op_severity s, enum op_module m, uint16_t code)
{
	fprintf(stderr, "op_panel Severity: 0x%x (%s), module %x, %x\n",
		s, (s == OP_FATAL) ? "FATAL" : "non-fatal",
		m, code);
	if (s == OP_FATAL)
		exit(EXIT_FAILURE);
}

char __rodata_start[1], __rodata_end[1];

enum proc_gen proc_gen = proc_gen_p8;

static bool spira_check_ptr(const void *ptr, const char *file, unsigned int line)
{
	if (!ptr)
		return false;
	/* we fake the SPIRA pointer as it's relative to where it was loaded
	 * on real hardware */
	(void)file;
	(void)line;
	return true;
}

static void *ntuple_addr(const struct spira_ntuple *n)
{
	uint64_t addr = be64_to_cpu(n->addr);
	if (n->addr == 0)
		return NULL;
	if (addr < base_addr) {
		fprintf(stderr, "assert failed: addr >= base_addr (%"PRIu64" >= %"PRIu64")\n", addr, base_addr);
		exit(EXIT_FAILURE);
	}
	if (addr >= base_addr + spira_heap_size) {
		fprintf(stderr, "assert failed: addr not in spira_heap\n");
		exit(EXIT_FAILURE);
	}
	return spira_heap + ((unsigned long)addr - base_addr);
}

/* Make sure valgrind knows these are undefined bytes. */
static void undefined_bytes(void *p, size_t len)
{
	VALGRIND_MAKE_MEM_UNDEFINED(p, len);
}

static u32 hash_prop(const struct dt_property *p)
{
	u32 i, hash = 0;

	/* a stupid checksum */
	for (i = 0; i < p->len; i++)
		hash += (((signed char)p->prop[i] & ~0x10) + 1) * i;

	return hash;
}

/*
 * This filters out VPD blobs and other annoyances from the devicetree output.
 * We don't actually care about the contents of the blob, we just want to make
 * sure it's there and that we aren't accidently corrupting the contents.
 */
static void squash_blobs(struct dt_node *root)
{
	struct dt_node *n;
	struct dt_property *p;

	list_for_each(&root->properties, p, list) {
		if (strstarts(p->name, DT_PRIVATE))
			continue;

		/*
		 * Consider any property larger than 512 bytes a blob that can
		 * be removed. This number was picked out of thin in so don't
		 * feel bad about changing it.
		 */
		if (p->len > 512) {
			u32 hash = hash_prop(p);
			u32 *val = (u32 *) p->prop;

			/* Add a sentinel so we know it was truncated */
			val[0] = cpu_to_be32(0xcafebeef);
			val[1] = cpu_to_be32(p->len);
			val[2] = cpu_to_be32(hash);
			p->len = 3 * sizeof(u32);
		}
	}

	list_for_each(&root->children, n, list)
		squash_blobs(n);
}

static void dump_hdata_fdt(struct dt_node *root)
{
	struct dt_node *n;
	void *fdt_blob;

	/* delete some properties that hardcode pointers */
	dt_for_each_node(dt_root, n) {
		struct dt_property *base;

		/*
		 * sml-base is a raw pointer into the HDAT area so it changes
		 * on each execution of hdata_to_dt. Work around this by
		 * zeroing it.
		 */
		base = __dt_find_property(n, "linux,sml-base");
		if (base)
			memset(base->prop, 0, base->len);
	}

	fdt_blob = create_dtb(root, false);

	if (!fdt_blob) {
		fprintf(stderr, "Unable to make flattened DT, no FDT written\n");
		return;
	}

	fwrite(fdt_blob, fdt_totalsize(fdt_blob), 1, stdout);

	free(fdt_blob);
}

int main(int argc, char *argv[])
{
	int fd, r, i = 0, opt_count = 0;
	bool verbose = false, quiet = false, new_spira = false, blobs = false;

	while (argv[++i]) {
		if (strcmp(argv[i], "-v") == 0) {
			verbose = true;
			opt_count++;
		} else if (strcmp(argv[i], "-q") == 0) {
			quiet = true;
			opt_count++;
		} else if (strcmp(argv[i], "-s") == 0) {
			new_spira = true;
			opt_count++;
		} else if (strcmp(argv[i], "-b") == 0) {
			blobs = true;
			opt_count++;
		} else if (strcmp(argv[i], "-8E") == 0) {
			fake_pvr = PVR_P8E;
			proc_gen = proc_gen_p8;
			opt_count++;
		} else if (strcmp(argv[i], "-8") == 0) {
			fake_pvr = PVR_P8;
			proc_gen = proc_gen_p8;
			opt_count++;
		} else if (strcmp(argv[i], "-9") == 0) {
			fake_pvr = PVR_P9;
			proc_gen = proc_gen_p9;
			opt_count++;
		} else if (strcmp(argv[i], "-9P") == 0) {
			fake_pvr = PVR_P9P;
			proc_gen = proc_gen_p9;
			opt_count++;
		} else if (strcmp(argv[i], "-10") == 0) {
			fake_pvr = PVR_P10;
			proc_gen = proc_gen_p10;
			opt_count++;
		}
	}

	argc -= opt_count;
	argv += opt_count;
	if (argc != 3) {
		errx(1, "Converts HDAT dumps to DTB.\n"
		     "\n"
		     "Usage:\n"
		     "	hdata <opts> <spira-dump> <heap-dump>\n"
		     "	hdata <opts> -s <spirah-dump> <spiras-dump>\n"
		     "Options: \n"
		     "	-v Verbose\n"
		     "	-q Quiet mode\n"
		     "	-b Keep blobs in the output\n"
		     "\n"
		     "  -8 Force PVR to POWER8\n"
		     "  -8E Force PVR to POWER8E\n"
		     "  -9 Force PVR to POWER9 (nimbus)\n"
		     "  -9P Force PVR to POWER9P (Axone)\n"
		     "  -10 Force PVR to POWER10\n"
		     "\n"
		     "When no PVR is specified -8 is assumed"
		     "\n"
		     "Pipe to 'dtc -I dtb -O dts' for human readable output\n");
	}

	/* We don't have phys mapping for P8 */
	if (proc_gen != proc_gen_p8)
		phys_map_init(fake_pvr);

	/* Copy in spira dump (assumes little has changed!). */
	if (new_spira) {
		fd = open(argv[1], O_RDONLY);
		if (fd < 0)
			err(1, "opening %s", argv[1]);
		r = read(fd, &spirah, sizeof(spirah));
		if (r < sizeof(spirah.hdr))
			err(1, "reading %s gave %i", argv[1], r);
		if (verbose)
			printf("verbose: read spirah %u bytes\n", r);
		close(fd);

		undefined_bytes((void *)&spirah + r, sizeof(spirah) - r);

		base_addr = be64_to_cpu(spirah.ntuples.hs_data_area.addr);
	} else {
		fd = open(argv[1], O_RDONLY);
		if (fd < 0)
			err(1, "opening %s", argv[1]);
		r = read(fd, &spira, sizeof(spira));
		if (r < sizeof(spira.hdr))
			err(1, "reading %s gave %i", argv[1], r);
		if (verbose)
			printf("verbose: read spira %u bytes\n", r);
		close(fd);

		undefined_bytes((void *)&spira + r, sizeof(spira) - r);

		base_addr = be64_to_cpu(spira.ntuples.heap.addr);
	}

	if (!base_addr)
		errx(1, "Invalid base addr");
	if (verbose)
		printf("verbose: map.base_addr = %llx\n", (long long)base_addr);

	fd = open(argv[2], O_RDONLY);
	if (fd < 0)
		err(1, "opening %s", argv[2]);
	spira_heap_size = lseek(fd, 0, SEEK_END);
	if (spira_heap_size < 0)
		err(1, "lseek on %s", argv[2]);
	spira_heap = mmap(NULL, spira_heap_size, PROT_READ, MAP_SHARED, fd, 0);
	if (spira_heap == MAP_FAILED)
		err(1, "mmaping %s", argv[3]);
	if (verbose)
		printf("verbose: mapped %zu at %p\n",
		       spira_heap_size, spira_heap);
	close(fd);

	if (new_spira)
		spiras = (struct spiras *)spira_heap;

	if (quiet) {
		fclose(stdout);
		fclose(stderr);
	}

	dt_root = dt_new_root("");

	if(parse_hdat(false) < 0) {
		fprintf(stderr, "FATAL ERROR parsing HDAT\n");
		dt_free(dt_root);
		exit(EXIT_FAILURE);
	}

	mem_region_init();
	mem_region_release_unused();

	if (!blobs)
		squash_blobs(dt_root);

	if (!quiet)
		dump_hdata_fdt(dt_root);

	dt_free(dt_root);
	return 0;
}
