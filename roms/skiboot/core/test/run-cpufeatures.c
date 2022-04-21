// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2019 IBM Corp.
 */

#include <skiboot.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

/* Override this for testing. */
#define is_rodata(p) fake_is_rodata(p)

char __rodata_start[16];
#define __rodata_end (__rodata_start + sizeof(__rodata_start))

static inline bool fake_is_rodata(const void *p)
{
	return ((char *)p >= __rodata_start && (char *)p < __rodata_end);
}

#define zalloc(bytes) calloc((bytes), 1)

#include "../device.c"
#include <assert.h>
#include "../../test/dt_common.c"

#define __TEST__

static inline unsigned long mfspr(unsigned int spr);

#include <ccan/str/str.c>

#include "../cpufeatures.c"

static unsigned long fake_pvr = PVR_TYPE_P8;

static inline unsigned long mfspr(unsigned int spr)
{
	assert(spr == SPR_PVR);
	return fake_pvr;
}

int main(void)
{
	struct dt_node *dt_root;

	dt_root = dt_new_root("");
	dt_add_cpufeatures(dt_root);
	dump_dt(dt_root, 0, true);
	dt_free(dt_root);

	fake_pvr = (PVR_TYPE_P8E << 16) | 0x100; // P8E DD1.0
	dt_root = dt_new_root("");
	dt_add_cpufeatures(dt_root);
	dump_dt(dt_root, 0, false);
	assert(dt_find_by_path(dt_root, "cpus/ibm,powerpc-cpu-features/mmu-radix") == 0);
	assert(dt_find_by_path(dt_root, "cpus/ibm,powerpc-cpu-features/tm-suspend-hypervisor-assist") == 0);
	assert(dt_find_by_path(dt_root, "cpus/ibm,powerpc-cpu-features/tm-suspend-xer-so-bug") == 0);
	dt_free(dt_root);

	fake_pvr = (PVR_TYPE_P8E << 16) | 0x200; // P8E DD2.0
	dt_root = dt_new_root("");
	dt_add_cpufeatures(dt_root);
	dump_dt(dt_root, 0, false);
	assert(dt_find_by_path(dt_root, "cpus/ibm,powerpc-cpu-features/mmu-radix") == 0);
	assert(dt_find_by_path(dt_root, "cpus/ibm,powerpc-cpu-features/tm-suspend-hypervisor-assist") == 0);
	assert(dt_find_by_path(dt_root, "cpus/ibm,powerpc-cpu-features/tm-suspend-xer-so-bug") == 0);
	dt_free(dt_root);

	fake_pvr = (PVR_TYPE_P8 << 16) | 0x100; // P8 DD1.0
	dt_root = dt_new_root("");
	dt_add_cpufeatures(dt_root);
	dump_dt(dt_root, 0, false);
	assert(dt_find_by_path(dt_root, "cpus/ibm,powerpc-cpu-features/mmu-radix") == 0);
	assert(dt_find_by_path(dt_root, "cpus/ibm,powerpc-cpu-features/tm-suspend-hypervisor-assist") == 0);
	assert(dt_find_by_path(dt_root, "cpus/ibm,powerpc-cpu-features/tm-suspend-xer-so-bug") == 0);
	dt_free(dt_root);

	fake_pvr = (PVR_TYPE_P8 << 16) | 0x200; // P8 DD2.0
	dt_root = dt_new_root("");
	dt_add_cpufeatures(dt_root);
	dump_dt(dt_root, 0, false);
	assert(dt_find_by_path(dt_root, "cpus/ibm,powerpc-cpu-features/mmu-radix") == 0);
	assert(dt_find_by_path(dt_root, "cpus/ibm,powerpc-cpu-features/tm-suspend-hypervisor-assist") == 0);
	assert(dt_find_by_path(dt_root, "cpus/ibm,powerpc-cpu-features/tm-suspend-xer-so-bug") == 0);
	dt_free(dt_root);

	fake_pvr = (PVR_TYPE_P8NVL << 16) | 0x100; // P8NVL DD1.0
	dt_root = dt_new_root("");
	dt_add_cpufeatures(dt_root);
	dump_dt(dt_root, 0, false);
	assert(dt_find_by_path(dt_root, "cpus/ibm,powerpc-cpu-features/mmu-radix") == 0);
	assert(dt_find_by_path(dt_root, "cpus/ibm,powerpc-cpu-features/tm-suspend-hypervisor-assist") == 0);
	assert(dt_find_by_path(dt_root, "cpus/ibm,powerpc-cpu-features/tm-suspend-xer-so-bug") == 0);
	dt_free(dt_root);

	fake_pvr = (PVR_TYPE_P9 << 16) | 0x200; // P9 DD2.0
	dt_root = dt_new_root("");
	dt_add_cpufeatures(dt_root);
	dump_dt(dt_root, 0, false);
	assert(dt_find_by_path(dt_root, "cpus/ibm,powerpc-cpu-features/mmu-radix"));
	assert(dt_find_by_path(dt_root, "cpus/ibm,powerpc-cpu-features/tm-suspend-hypervisor-assist") == 0);
	assert(dt_find_by_path(dt_root, "cpus/ibm,powerpc-cpu-features/tm-suspend-xer-so-bug") == 0);
	dt_free(dt_root);

	fake_pvr = (PVR_TYPE_P9 << 16) | 0x201; // P9 DD2.1
	dt_root = dt_new_root("");
	dt_add_cpufeatures(dt_root);
	dump_dt(dt_root, 0, false);
	assert(dt_find_by_path(dt_root, "cpus/ibm,powerpc-cpu-features/mmu-radix"));
	assert(dt_find_by_path(dt_root, "cpus/ibm,powerpc-cpu-features/tm-suspend-hypervisor-assist") == 0);
	assert(dt_find_by_path(dt_root, "cpus/ibm,powerpc-cpu-features/tm-suspend-xer-so-bug") == 0);
	dt_free(dt_root);

	fake_pvr = (PVR_TYPE_P9 << 16) | 0x202; // P9 DD2.2
	dt_root = dt_new_root("");
	dt_add_cpufeatures(dt_root);
	dump_dt(dt_root, 0, false);
	assert(dt_find_by_path(dt_root, "cpus/ibm,powerpc-cpu-features/mmu-radix"));
	assert(dt_find_by_path(dt_root, "cpus/ibm,powerpc-cpu-features/tm-suspend-hypervisor-assist") != 0);
	assert(dt_find_by_path(dt_root, "cpus/ibm,powerpc-cpu-features/tm-suspend-xer-so-bug") != 0);
	dt_free(dt_root);

	fake_pvr = (PVR_TYPE_P9 << 16) | 0x203; // P9 DD2.3
	dt_root = dt_new_root("");
	dt_add_cpufeatures(dt_root);
	dump_dt(dt_root, 0, false);
	assert(dt_find_by_path(dt_root, "cpus/ibm,powerpc-cpu-features/mmu-radix"));
	assert(dt_find_by_path(dt_root, "cpus/ibm,powerpc-cpu-features/tm-suspend-hypervisor-assist") != 0);
	assert(dt_find_by_path(dt_root, "cpus/ibm,powerpc-cpu-features/tm-suspend-xer-so-bug") == 0);
	dt_free(dt_root);

	fake_pvr = (PVR_TYPE_P9P << 16) | 0x100; // P9P DD1.0
	dt_root = dt_new_root("");
	dt_add_cpufeatures(dt_root);
	dump_dt(dt_root, 0, false);
	assert(dt_find_by_path(dt_root, "cpus/ibm,powerpc-cpu-features/mmu-radix"));
	assert(dt_find_by_path(dt_root, "cpus/ibm,powerpc-cpu-features/tm-suspend-hypervisor-assist") != 0);
	assert(dt_find_by_path(dt_root, "cpus/ibm,powerpc-cpu-features/tm-suspend-xer-so-bug") == 0);
	dt_free(dt_root);

	exit(EXIT_SUCCESS);
}
