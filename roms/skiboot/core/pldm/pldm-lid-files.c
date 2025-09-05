// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
// Copyright 2022 IBM Corp.

#define pr_fmt(fmt) "PLDM: " fmt

#include <endian.h>
#include <lock.h>
#include <opal-api.h>
#include <libflash/errors.h>
#include <libflash/ffs.h>
#include "pldm.h"

/*
 * This struct is used to map a PNOR sections.
 * The content is deriving from the hb_lid_ids PLDM BIOS Attribute.
 */
struct pldm_lid {
	struct list_node	list;
	uint32_t		start;
	uint32_t		handle;
	uint32_t		length;
	char			name[FFS_PART_NAME_MAX + 1];
	char			id[FFS_PART_NAME_MAX + 1];
};

static LIST_HEAD(lid_files);

struct pldm_ctx_data {
	/* Members protected by the blocklevel lock */
	struct blocklevel_device bl;
	uint32_t total_size;
	uint32_t erase_granule;
	struct lock lock;
};

#define MEGABYTE (1024*1024)

/*
 * When using PLDM for PNOR Resource Provider operations,
 * reserve 32 MB of VMM address space per section.
 * Note that all of this space may not actually be used by each section.
 */
#define VMM_SIZE_RESERVED_PER_SECTION (32 * MEGABYTE)

#define ERASE_GRANULE_DEF 0x1000

/* 'fake' header flash */
struct __ffs_hdr *raw_hdr;
size_t raw_hdr_size;

/*
 * Print the attributes of lid files.
 */
static void print_lid_files_attr(void)
{
	struct pldm_lid *lid = NULL;

	list_for_each(&lid_files, lid, list)
		prlog(PR_NOTICE, "name: %s, id: %s, handle: %d, length: 0x%x, start: 0x%x\n",
				 lid->name, lid->id, lid->handle, lid->length, lid->start);
}

/*
 * Return the number of lid files.
 */
static uint32_t get_lids_count(void)
{
	struct pldm_lid *lid = NULL;
	uint32_t count = 0;

	list_for_each(&lid_files, lid, list)
		count++;

	return count;
}

/*
 * parse the "hb_lid_ids" string
 * <ATTR_a>=<lid_id_1>,<ATTR_b>=<lid_id_2>
 */
static int parse_hb_lid_ids_string(char *str)
{
	struct pldm_lid *lid, *tmp;
	const char *pp = "=";
	char *attr, *attr_end;
	int rc, count = 1;
	char *lid_id;

	for (char *p = strtok(str, ","); p != NULL; p = strtok(NULL, ",")) {
		lid = zalloc(sizeof(struct pldm_lid));
		if (!lid) {
			prlog(PR_ERR, "Error allocating pldm_lid structure\n");
			rc = OPAL_NO_MEM;
			goto err;
		}

		/* parse the string <attr>=<lid_id> */
		attr = p;
		while ((*pp != *p) && (*p != '\0'))
			p++;

		attr_end = p;
		lid_id = ++p;
		*attr_end = '\0';

		strcpy(lid->name, attr);
		strcpy(lid->id, lid_id);

		/* reserve 32 MB of VMM address space per section.
		 * Address 0x0 -> 0x2000000:   'fake' header flash
		 * Address 0x2000000 -> 0x4000000: lid id 1
		 * Address 0x4000000 -> 0x6000000: lid id 2
		 * ....
		 */
		lid->start = VMM_SIZE_RESERVED_PER_SECTION * count;

		/* handle and length */
		rc = pldm_find_file_handle_by_lid_id(lid->id,
						     &lid->handle,
						     &lid->length);
		/* OPAL_PARAMETER means that lid_id is present in hb_lid_ids,
		 * but we don't have any file attribute information in the
		 * file table, so continue on the next item.
		 */
		if ((rc) && (rc != OPAL_PARAMETER))
			goto err;

		if (lid->length > VMM_SIZE_RESERVED_PER_SECTION) {
			prlog(PR_ERR, "file length (0x%x) > virtual size reserved per "
				      "section (0x%x)\n",
				      lid->length, VMM_SIZE_RESERVED_PER_SECTION);
			rc = OPAL_RESOURCE;
			goto err;
		}

		/* add new member in the global list */
		list_add_tail(&lid_files, &lid->list);

		count++;
	}

	return OPAL_SUCCESS;

err:
	/* free all lid entries */
	list_for_each_safe(&lid_files, lid, tmp, list)
		free(lid);

	return rc;
}

/*
 * Parse the "hb_lid_ids" string from bios tables and complete
 * the global list of lid files.
 */
static int lid_ids_to_vaddr_mapping(void)
{
	char *lid_ids_string = NULL;
	int rc;

	/* get lid ids string from bios tables */
	rc = pldm_bios_get_lids_id(&lid_ids_string);
	if (rc)
		goto out;

	/* parse the "hb_lid_ids" string */
	rc = parse_hb_lid_ids_string(lid_ids_string);

out:
	if (lid_ids_string)
		free(lid_ids_string);

	return rc;
}

static uint32_t checksum(void *data, size_t size)
{
	uint32_t i, csum = 0;

	for (i = csum = 0; i < (size/4); i++)
		csum ^= ((uint32_t *)data)[i];
	return csum;
}

/* Helper functions for typesafety and size safety */
static uint32_t hdr_checksum(struct __ffs_hdr *hdr)
{
	return checksum(hdr, sizeof(struct __ffs_hdr));
}

static uint32_t entry_checksum(struct __ffs_entry *ent)
{
	return checksum(ent, sizeof(struct __ffs_entry));
}

/*
 * Fill __ffs structures in order to return a 'fake' header flash
 */
static int lid_ids_to_header_flash(void *buf, uint64_t len)
{
	struct __ffs_entry *entry;
	struct pldm_lid *lid = NULL;
	uint32_t count, part_id, i;
	uint32_t block_size;

	/* reading the flash header has already been requested */
	if (raw_hdr) {
		(raw_hdr_size < len) ? memcpy(buf, raw_hdr, raw_hdr_size) :
				       memcpy(buf, raw_hdr, len);
		return OPAL_SUCCESS;
	}

	/* number of lid files */
	count = get_lids_count();

	/* last member of struct __ffs_hdr is a flexible array member */
	raw_hdr_size = sizeof(struct __ffs_hdr) + (count * sizeof(struct __ffs_entry));
	raw_hdr = zalloc(raw_hdr_size);
	if (!raw_hdr)
		return OPAL_NO_MEM;

	/* complete header flash
	 * Represents the on flash layout of FFS structures
	 * Note: Beware that the size of the partition table is in units of block_size
	 *
	 * @magic:		Eye catcher/corruption detector
	 * @version:		Version of the structure
	 * @size:		Size of partition table (in block_size)
	 * @entry_size:		Size of struct __ffs_entry element (in bytes)
	 * @entry_count:	Number of struct __ffs_entry elements in @entries array
	 * @block_size:		Size of block on device (in bytes)
	 * @block_count:	Number of blocks on device
	 * @checksum:		Header checksum
	 */
	/* size of the cached map: block_size * raw_hdr->size
	 * raw_hdr->size = 0x3: we take a little margin if the number
	 * of element would increase
	 */
	block_size = ERASE_GRANULE_DEF;

	raw_hdr->magic = cpu_to_be32(FFS_MAGIC);
	raw_hdr->version = cpu_to_be32(FFS_VERSION_1);
	raw_hdr->size = cpu_to_be32(0x3);
	raw_hdr->entry_size = cpu_to_be32(sizeof(struct __ffs_entry));
	raw_hdr->entry_count = cpu_to_be32(count);
	raw_hdr->block_size = cpu_to_be32(block_size);
	raw_hdr->block_count = cpu_to_be32(0x4000); /* value from IPMI/PNOR protocol */
	raw_hdr->checksum = hdr_checksum(raw_hdr);

	lid = list_top(&lid_files, struct pldm_lid, list);
	part_id = 1;

	for (i = 0; i < count; i++) {
		entry = &raw_hdr->entries[i];

		memcpy(entry->name, lid->name, sizeof(entry->name));
		entry->name[FFS_PART_NAME_MAX] = '\0';
		entry->base = cpu_to_be32(lid->start / block_size);
		entry->size = cpu_to_be32(lid->length / block_size);
		entry->pid = cpu_to_be32(FFS_PID_TOPLEVEL);
		entry->id = cpu_to_be32(part_id);
		entry->type = cpu_to_be32(0x1);
		entry->flags = cpu_to_be32(0x0);
		entry->actual = cpu_to_be32(lid->length);
		entry->checksum = entry_checksum(entry);

		lid = list_next(&lid_files, lid, list);
		part_id++;
	}

	/* fill in rquester buffer */
	(raw_hdr_size < len) ? memcpy(buf, raw_hdr, raw_hdr_size) :
			       memcpy(buf, raw_hdr, len);

	return OPAL_SUCCESS;
}

/*
 * Search lid member from the virtual address.
 */
static int vaddr_to_lid_id(uint64_t pos, uint32_t *start, uint32_t *handle,
			   uint32_t *length)
{
	struct pldm_lid *lid = NULL;

	list_for_each(&lid_files, lid, list) {
		if ((pos >= lid->start) && (pos < lid->start + VMM_SIZE_RESERVED_PER_SECTION)) {
			*start = lid->start;
			*handle = lid->handle;
			*length = lid->length;
			return OPAL_SUCCESS;
		}
	}

	return OPAL_PARAMETER;
}

static int lid_files_read(struct blocklevel_device *bl __unused,
			  uint64_t pos, void *buf, uint64_t len)
{
	uint32_t lid_start, lid_handle, lid_length;
	int rc = OPAL_SUCCESS;
	uint64_t offset;

	/* LPC is only 32bit */
	if (pos > UINT_MAX || (pos + len) > UINT_MAX)
		return FLASH_ERR_PARM_ERROR;

	prlog(PR_TRACE, "lid files read at 0x%llx for 0x%llx\n",
			pos, len);

	if ((pos == 0) || (pos <= (ERASE_GRANULE_DEF * 0x3))) {
		/* return a 'fake' header flash or cached map */
		rc = lid_ids_to_header_flash(buf, len);
	} else {
		/* convert offset to lid id */
		rc = vaddr_to_lid_id(pos, &lid_start,
				     &lid_handle, &lid_length);
		if (rc)
			return rc;

		/* read lid file */
		offset = pos - lid_start;
		rc = pldm_file_io_read_file(lid_handle, lid_length,
					    offset, buf, len);
	}

	return rc;
}

static int lid_files_write(struct blocklevel_device *bl __unused,
			   uint64_t pos, const void *buf __unused,
			   uint64_t len)
{
	prlog(PR_ERR, "lid files writes at 0x%llx for 0x%llx\n",
		       pos, len);
	return OPAL_UNSUPPORTED;
}

static int lid_files_erase(struct blocklevel_device *bl __unused,
			   uint64_t pos, uint64_t len)
{

	prlog(PR_ERR, "lid files erase at 0x%llx for 0x%llx\n",
		       pos, len);
	return OPAL_UNSUPPORTED;
}

static int get_lid_files_info(struct blocklevel_device *bl,
			      const char **name, uint64_t *total_size,
			      uint32_t *erase_granule)
{
	struct pldm_ctx_data *ctx;

	ctx = container_of(bl, struct pldm_ctx_data, bl);
	ctx->bl.erase_mask = ctx->erase_granule - 1;

	if (name)
		*name = NULL;
	if (total_size)
		*total_size = ctx->total_size;
	if (erase_granule)
		*erase_granule = ctx->erase_granule;

	return OPAL_SUCCESS;
}

bool pldm_lid_files_exit(struct blocklevel_device *bl)
{
	struct pldm_ctx_data *ctx;
	struct pldm_lid *lid, *tmp;

	if (bl) {
		ctx = container_of(bl, struct pldm_ctx_data, bl);
		free(ctx);
	}

	/* free all lid entries */
	list_for_each_safe(&lid_files, lid, tmp, list)
		free(lid);

	if (raw_hdr)
		free(raw_hdr);

	return true;
}

int pldm_lid_files_init(struct blocklevel_device **bl)
{
	struct pldm_ctx_data *ctx;
	uint32_t lid_files_count;
	int rc;

	if (!bl)
		return FLASH_ERR_PARM_ERROR;

	*bl = NULL;

	ctx = zalloc(sizeof(struct pldm_ctx_data));
	if (!ctx)
		return FLASH_ERR_MALLOC_FAILED;

	init_lock(&ctx->lock);

	ctx->bl.read = &lid_files_read;
	ctx->bl.write = &lid_files_write;
	ctx->bl.erase = &lid_files_erase;
	ctx->bl.get_info = &get_lid_files_info;
	ctx->bl.exit = &pldm_lid_files_exit;

	/* convert lid ids data to pnor structure */
	rc = lid_ids_to_vaddr_mapping();
	if (rc)
		goto err;

	lid_files_count = get_lids_count();

	prlog(PR_NOTICE, "Number of lid files: %d\n", lid_files_count);
	print_lid_files_attr();

	ctx->total_size = lid_files_count * VMM_SIZE_RESERVED_PER_SECTION;
	ctx->erase_granule = ERASE_GRANULE_DEF;

	ctx->bl.keep_alive = 0;

	*bl = &(ctx->bl);

	return OPAL_SUCCESS;

err:
	free(ctx);
	return rc;
}
