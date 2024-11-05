// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Produce and consume flattened device trees
 *
 * Copyright 2013-2019 IBM Corp.
 */

#include <skiboot.h>
#include <stdarg.h>
#include <libfdt.h>
#include <device.h>
#include <chip.h>
#include <cpu.h>
#include <opal.h>
#include <interrupts.h>
#include <fsp.h>
#include <cec.h>
#include <vpd.h>
#include <ccan/str/str.h>

static int fdt_error;

#undef DEBUG_FDT
#ifdef DEBUG_FDT
#define FDT_DBG(fmt, a...)	prlog(PR_DEBUG, "FDT: " fmt, ##a)
#else
#define FDT_DBG(fmt, a...)
#endif

static void __save_err(int err, const char *str)
{
	FDT_DBG("rc: %d from \"%s\"\n", err, str);
	if (err && !fdt_error) {
		prerror("FDT: Error %d from \"%s\"\n", err, str);
		fdt_error = err;
	}
}

#define save_err(...) __save_err(__VA_ARGS__, #__VA_ARGS__)

static void dt_property_cell(void *fdt, const char *name, u32 cell)
{
	save_err(fdt_property_cell(fdt, name, cell));
}

static void dt_begin_node(void *fdt, const struct dt_node *dn)
{
	save_err(fdt_begin_node(fdt, dn->name));

	dt_property_cell(fdt, "phandle", dn->phandle);
}

static void dt_property(void *fdt, const struct dt_property *p)
{
	save_err(fdt_property(fdt, p->name, p->prop, p->len));
}

static void dt_end_node(void *fdt)
{
	save_err(fdt_end_node(fdt));
}

#ifdef DEBUG_FDT
static void dump_fdt(void *fdt)
{
	int i, off, depth, err;

	prlog(PR_INFO, "Device tree %u@%p\n", fdt_totalsize(fdt), fdt);
	err = fdt_check_header(fdt);
	if (err) {
		prerror("fdt_check_header: %s\n", fdt_strerror(err));
		return;
	}
	prlog(PR_INFO, "fdt_check_header passed\n");

	prlog(PR_INFO, "fdt_num_mem_rsv = %u\n", fdt_num_mem_rsv(fdt));
	for (i = 0; i < fdt_num_mem_rsv(fdt); i++) {
		u64 addr, size;

		err = fdt_get_mem_rsv(fdt, i, &addr, &size);
		if (err) {
			prlog(PR_INFO, " ERR %s\n", fdt_strerror(err));
			return;
		}
		prlog(PR_INFO, "  mem_rsv[%i] = %lu@%#lx\n",
		      i, (long)addr, (long)size);
	}

	for (off = fdt_next_node(fdt, 0, &depth);
	     off > 0;
	     off = fdt_next_node(fdt, off, &depth)) {
		int len;
		const char *name;

		name = fdt_get_name(fdt, off, &len);
		if (!name) {
			prerror("fdt: offset %i no name!\n", off);
			return;
		}
		prlog(PR_INFO, "name: %s [%u]\n", name, off);
	}
}
#endif

static void flatten_dt_properties(void *fdt, const struct dt_node *dn)
{
	const struct dt_property *p;

	list_for_each(&dn->properties, p, list) {
		if (strstarts(p->name, DT_PRIVATE))
			continue;

		FDT_DBG("  prop: %s size: %ld\n", p->name, p->len);
		dt_property(fdt, p);
	}
}

static void flatten_dt_node(void *fdt, const struct dt_node *root,
			    bool exclusive)
{
	const struct dt_node *i;

	if (!exclusive) {
		FDT_DBG("node: %s\n", root->name);
		dt_begin_node(fdt, root);
		flatten_dt_properties(fdt, root);
	}

	list_for_each(&root->children, i, list)
		flatten_dt_node(fdt, i, false);

	if (!exclusive)
		dt_end_node(fdt);
}

static void create_dtb_reservemap(void *fdt, const struct dt_node *root)
{
	uint64_t base, size;
	const __be64 *ranges;
	const struct dt_property *prop;
	int i;

	/* Duplicate the reserved-ranges property into the fdt reservemap */
	prop = dt_find_property(root, "reserved-ranges");
	if (prop) {
		ranges = (const void *)prop->prop;

		for (i = 0; i < prop->len / (sizeof(uint64_t) * 2); i++) {
			base = be64_to_cpu(*(ranges++));
			size = be64_to_cpu(*(ranges++));
			save_err(fdt_add_reservemap_entry(fdt, base, size));
		}
	}

	save_err(fdt_finish_reservemap(fdt));
}

static int __create_dtb(void *fdt, size_t len,
			const struct dt_node *root,
			bool exclusive)
{
	if (chip_quirk(QUIRK_SLOW_SIM))
		save_err(fdt_create_with_flags(fdt, len, FDT_CREATE_FLAG_NO_NAME_DEDUP));
	else
		save_err(fdt_create_with_flags(fdt, len, 0));
	if (fdt_error)
		goto err;

	if (root == dt_root && !exclusive)
		create_dtb_reservemap(fdt, root);
	else
		save_err(fdt_finish_reservemap(fdt));

	flatten_dt_node(fdt, root, exclusive);

	save_err(fdt_finish(fdt));
	if (fdt_error) {
err:
		prerror("dtb: error %s\n", fdt_strerror(fdt_error));
		return fdt_error;
	}

#ifdef DEBUG_FDT
	dump_fdt(fdt);
#endif
	return 0;
}

void *create_dtb(const struct dt_node *root, bool exclusive)
{
	void *fdt = NULL;
	size_t len = DEVICE_TREE_MAX_SIZE;
	uint32_t old_last_phandle = get_last_phandle();
	int ret;

	do {
		set_last_phandle(old_last_phandle);
		fdt_error = 0;
		fdt = malloc(len);
		if (!fdt) {
			prerror("dtb: could not malloc %lu\n", (long)len);
			return NULL;
		}

		ret = __create_dtb(fdt, len, root, exclusive);
		if (ret) {
			free(fdt);
			fdt = NULL;
		}

		len *= 2;
	} while (ret == -FDT_ERR_NOSPACE);

	return fdt;
}

static int64_t opal_get_device_tree(uint32_t phandle,
				    uint64_t buf, uint64_t len)
{
	struct dt_node *root;
	void *fdt = (void *)buf;
	uint32_t old_last_phandle;
	int64_t totalsize;
	int ret;

	if (!opal_addr_valid(fdt))
		return OPAL_PARAMETER;

	root = dt_find_by_phandle(dt_root, phandle);
	if (!root)
		return OPAL_PARAMETER;

	if (!fdt) {
		fdt = create_dtb(root, true);
		if (!fdt)
			return OPAL_INTERNAL_ERROR;
		totalsize = fdt_totalsize(fdt);
		free(fdt);
		return totalsize;
	}

	if (!len)
		return OPAL_PARAMETER;

	fdt_error = 0;
	old_last_phandle = get_last_phandle();
	ret = __create_dtb(fdt, len, root, true);
	if (ret) {
		set_last_phandle(old_last_phandle);
		if (ret == -FDT_ERR_NOSPACE)
			return OPAL_NO_MEM;

		return OPAL_EMPTY;
	}

	return OPAL_SUCCESS;
}
opal_call(OPAL_GET_DEVICE_TREE, opal_get_device_tree, 3);
