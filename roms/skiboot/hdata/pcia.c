// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#include <skiboot.h>
#include "spira.h"
#include <cpu.h>
#include <fsp.h>
#include <opal.h>
#include <ccan/str/str.h>
#include <device.h>

#include "hdata.h"

#define PCIA_MAX_THREADS	8

static unsigned int pcia_index(const void *pcia)
{
	return (pcia - (void *)get_hdif(&spira.ntuples.pcia, "SPPCIA"))
		/ be32_to_cpu(spira.ntuples.pcia.alloc_len);
}

static const struct sppcia_cpu_thread *find_tada(const void *pcia,
						 unsigned int thread)
{
	int count = HDIF_get_iarray_size(pcia, SPPCIA_IDATA_THREAD_ARRAY);
	int i;

	if (count < 0)
		return NULL;

	for (i = 0; i < count; i++) {
		const struct sppcia_cpu_thread *t;
		unsigned int size;

		t = HDIF_get_iarray_item(pcia, SPPCIA_IDATA_THREAD_ARRAY,
					 i, &size);
		if (!t || size < sizeof(*t))
			continue;
		if (be32_to_cpu(t->phys_thread_id) == thread)
			return t;
	}
	return NULL;
}

static void add_xics_icp(const void *pcia, u32 tcount, const char *compat)
{
	const struct sppcia_cpu_thread *t;
	struct dt_node *icp;
	__be64 *reg;
	u32 i, irange[2], rsize;

	rsize = tcount * 2 * sizeof(__be64);
	reg = malloc(rsize);
	assert(reg);

	/* Suppresses uninitialized warning from gcc */
	irange[0] = 0;
	for (i = 0; i < tcount; i++) {
		t = find_tada(pcia, i);
		assert(t);
		if (i == 0)
			irange[0] = be32_to_cpu(t->pir);
		reg[i * 2] = cpu_to_be64(cleanup_addr(be64_to_cpu(t->ibase)));
		reg[i * 2 + 1] = cpu_to_be64(0x1000);
	}
	irange[1] = tcount;

	icp = dt_new_addr(dt_root, "interrupt-controller", be64_to_cpu(reg[0]));
	if (!icp) {
		free(reg);
		return;
	}

	if (compat)
		dt_add_property_strings(icp, "compatible", "ibm,ppc-xicp", compat);
	else
		dt_add_property_strings(icp, "compatible", "ibm,ppc-xicp");
	dt_add_property_cells(icp, "ibm,interrupt-server-ranges",
			      irange[0], irange[1]);
	dt_add_property(icp, "interrupt-controller", NULL, 0);
	dt_add_property(icp, "reg", reg, rsize);
	dt_add_property_cells(icp, "#address-cells", 0);
	dt_add_property_string(icp, "device_type",
			       "PowerPC-External-Interrupt-Presentation");
	free(reg);
}

static struct dt_node *add_core_node(struct dt_node *cpus,
				     const void *pcia,
				     const struct sppcia_core_unique *id,
				     bool okay)
{
	const struct sppcia_cpu_thread *t;
	const struct sppcia_cpu_timebase *timebase;
	const struct sppcia_cpu_cache *cache;
	const struct sppcia_cpu_attr *attr;
	struct dt_node *cpu;
	const char *icp_compat;
	u32 i, size, threads, ve_flags, l2_phandle, chip_id;
	__be32 iserv[PCIA_MAX_THREADS];

	/* Look for thread 0 */
	t = find_tada(pcia, 0);
	if (!t) {
		prerror("CORE[%i]: Failed to find thread 0 !\n",
			pcia_index(pcia));
		return NULL;
	}

	ve_flags = be32_to_cpu(id->verif_exist_flags);
	threads = ((ve_flags & CPU_ID_NUM_SECONDARY_THREAD_MASK)
		   >> CPU_ID_NUM_SECONDARY_THREAD_SHIFT) + 1;
	assert(threads <= PCIA_MAX_THREADS);

	prlog(PR_INFO, "CORE[%i]: PIR=%.8x %s %s(%u threads)\n",
	      pcia_index(pcia), be32_to_cpu(t->pir),
	      ve_flags & CPU_ID_PCIA_RESERVED
	      ? "**RESERVED**" : cpu_state(ve_flags),
	      be32_to_cpu(t->pir) == boot_cpu->pir ? "[boot] " : "", threads);

	timebase = HDIF_get_idata(pcia, SPPCIA_IDATA_TIMEBASE, &size);
	if (!timebase || size < sizeof(*timebase)) {
		prerror("CORE[%i]: bad timebase size %u @ %p\n",
			pcia_index(pcia), size, timebase);
		return NULL;
	}

	cache = HDIF_get_idata(pcia, SPPCIA_IDATA_CPU_CACHE, &size);
	if (!cache || size < sizeof(*cache)) {
		prerror("CORE[%i]: bad cache size %u @ %p\n",
			pcia_index(pcia), size, cache);
		return NULL;
	}

	cpu = add_core_common(cpus, cache, timebase,
			      be32_to_cpu(t->pir), okay);

	/* Core attributes */
	attr = HDIF_get_idata(pcia, SPPCIA_IDATA_CPU_ATTR, &size);
	if (attr)
		add_core_attr(cpu, be32_to_cpu(attr->attr));

	/* Add cache info */
	l2_phandle = add_core_cache_info(cpus, cache,
					 be32_to_cpu(t->pir), okay);
	dt_add_property_cells(cpu, "l2-cache", l2_phandle);

	if (proc_gen == proc_gen_p8)
		icp_compat = "IBM,power8-icp";

	/* Get HW Chip ID */
	chip_id = pcid_to_chip_id(be32_to_cpu(id->proc_chip_id));

	dt_add_property_cells(cpu, "ibm,pir", be32_to_cpu(t->pir));
	dt_add_property_cells(cpu, "ibm,chip-id", chip_id);

	/* Build ibm,ppc-interrupt-server#s with all threads */
	for (i = 0; i < threads; i++) {
		t = find_tada(pcia, i);
		if (!t) {
			threads = i;
			break;
		}

		iserv[i] = t->pir;
	}

	dt_add_property(cpu, "ibm,ppc-interrupt-server#s", iserv, 4 * threads);

	/* Add the ICP node for this CPU for P8 */
	if (proc_gen == proc_gen_p8)
		add_xics_icp(pcia, threads, icp_compat);

	return cpu;
}

bool pcia_parse(void)
{
	const void *pcia;
	struct dt_node *cpus;

	pcia = get_hdif(&spira.ntuples.pcia, "SPPCIA");
	if (!pcia)
		return false;

	prlog(PR_INFO, "Got PCIA !\n");

	cpus = dt_new(dt_root, "cpus");
	dt_add_property_cells(cpus, "#address-cells", 1);
	dt_add_property_cells(cpus, "#size-cells", 0);

	for_each_pcia(pcia) {
		const struct sppcia_core_unique *id;
		u32 size, ve_flags;
		bool okay;

		id = HDIF_get_idata(pcia, SPPCIA_IDATA_CORE_UNIQUE, &size);
		if (!id || size < sizeof(*id)) {
			prerror("CORE[%i]: bad id size %u @ %p\n",
				pcia_index(pcia), size, id);
			return false;
		}
		ve_flags = be32_to_cpu(id->verif_exist_flags);

		switch ((ve_flags & CPU_ID_VERIFY_MASK)
			>> CPU_ID_VERIFY_SHIFT) {
		case CPU_ID_VERIFY_USABLE_NO_FAILURES:
		case CPU_ID_VERIFY_USABLE_FAILURES:
			okay = true;
			break;
		default:
			okay = false;
		}

		prlog(okay ? PR_INFO : PR_WARNING,
		      "CORE[%i]: HW_PROC_ID=%i PROC_CHIP_ID=%i EC=0x%x %s\n",
		      pcia_index(pcia), be32_to_cpu(id->hw_proc_id),
		      be32_to_cpu(id->proc_chip_id),
		      be32_to_cpu(id->chip_ec_level),
		      okay ? "OK" : "UNAVAILABLE");

		if (!add_core_node(cpus, pcia, id, okay))
			break;
	}
	return true;
}
