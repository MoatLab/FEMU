// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Open Capi Memory Buffer chip
 *
 * Copyright 2020 IBM Corp.
 */


#define pr_fmt(fmt)	"OCMB: " fmt

#include <skiboot.h>
#include <xscom.h>
#include <device.h>
#include <ocmb.h>
#include <io.h>
#include <inttypes.h>

struct ocmb_range {
	uint64_t start;
	uint64_t end;
	uint64_t flags;

	/* flags come from hdat */
#define ACCESS_8B PPC_BIT(0)
#define ACCESS_4B PPC_BIT(1)
#define ACCESS_SIZE_MASK (ACCESS_8B | ACCESS_4B)
};

struct ocmb {
	struct scom_controller scom;
	int range_count;
	struct ocmb_range ranges[];
};

static const struct ocmb_range *find_range(const struct ocmb *o, uint64_t offset)
{
	int i;
	uint64_t addr = offset & ~(HRMOR_BIT);

	for (i = 0; i < o->range_count; i++) {
		uint64_t start = o->ranges[i].start;
		uint64_t end = o->ranges[i].end;

		if (addr >= start && addr <= end)
			return &o->ranges[i];
	}

	return NULL;
}

static int64_t ocmb_fake_scom_write(struct scom_controller *f,
				    uint32_t __unused chip_id,
				    uint64_t offset, uint64_t val)
{
	const struct ocmb *o = f->private;
	const struct ocmb_range *r;

	r = find_range(o, offset);
	if (!r) {
		prerror("no matching address range!\n");
		return OPAL_XSCOM_ADDR_ERROR;
	}

	switch (r->flags & ACCESS_SIZE_MASK) {
	case ACCESS_8B:
		if (offset & 0x7)
			return OPAL_XSCOM_ADDR_ERROR;
		out_be64((void *) offset, val);
		break;

	case ACCESS_4B:
		if (offset & 0x3)
			return OPAL_XSCOM_ADDR_ERROR;
		out_be32((void *) offset, val);
		break;
	default:
		prerror("bad flags? %llx\n", r->flags);
		return OPAL_XSCOM_ADDR_ERROR;
	}

	return OPAL_SUCCESS;
}

static int64_t ocmb_fake_scom_read(struct scom_controller *f,
				   uint32_t chip_id __unused,
				   uint64_t offset, uint64_t *val)
{
	const struct ocmb *o = f->private;
	const struct ocmb_range *r = NULL;

	r = find_range(o, offset);
	if (!r) {
		prerror("no matching address range!\n");
		return OPAL_XSCOM_ADDR_ERROR;
	}


	switch (r->flags & ACCESS_SIZE_MASK) {
	case ACCESS_8B:
		if (offset & 0x7)
			return OPAL_XSCOM_ADDR_ERROR;
		*val = in_be64((void *) offset);
		break;

	case ACCESS_4B:
		if (offset & 0x3)
			return OPAL_XSCOM_ADDR_ERROR;
		*val = in_be32((void *) offset);
		break;
	default:
		prerror("bad flags? %llx\n", r->flags);
		return OPAL_XSCOM_ADDR_ERROR;
	}

	return OPAL_SUCCESS;
}

static bool ocmb_probe_one(struct dt_node *ocmb_node)
{
	uint64_t chip_id = dt_prop_get_u32(ocmb_node, "ibm,chip-id");
	const struct dt_property *flags;
	int i = 0, num = 0;
	struct ocmb *ocmb;

	num = dt_count_addresses(ocmb_node);

	ocmb = zalloc(sizeof(*ocmb) + sizeof(*ocmb->ranges) * num);
	if (!ocmb)
		return false;

	ocmb->scom.private = ocmb;
	ocmb->scom.part_id = chip_id;
	ocmb->scom.write = ocmb_fake_scom_write;
	ocmb->scom.read = ocmb_fake_scom_read;
	ocmb->range_count = num;

	flags = dt_require_property(ocmb_node, "flags", sizeof(u64) * num);

	for (i = 0; i < num; i++) {
		uint64_t start, size;

		start = dt_get_address(ocmb_node, i, &size);

		ocmb->ranges[i].start = start;
		ocmb->ranges[i].end = start + size - 1;
		ocmb->ranges[i].flags = dt_property_get_u64(flags, i);

		prlog(PR_DEBUG, "Added range:  %" PRIx64 " - [%llx - %llx]\n",
			chip_id, start, start + size - 1);
	}

	if (scom_register(&ocmb->scom))
		prerror("Error registering fake scom\n");

	dt_add_property(ocmb_node, "scom-controller", NULL, 0);
	prlog(PR_NOTICE, "Added scom controller for %s\n", ocmb_node->name);

	return true;
}

void ocmb_init(void)
{
	struct dt_node *dn;

	dt_for_each_compatible(dt_root, dn, "ibm,explorer")
		ocmb_probe_one(dn);
}
