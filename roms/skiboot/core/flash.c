// SPDX-License-Identifier: Apache-2.0
/*
 * Init, manage, read, write, and load resources from flash
 *
 * Copyright 2013-2019 IBM Corp.
 * Copyright 2018-2019 Raptor Engineering, LLC
 */

#define pr_fmt(fmt)    "FLASH: " fmt

#include <skiboot.h>
#include <cpu.h>
#include <lock.h>
#include <opal.h>
#include <opal-msg.h>
#include <platform.h>
#include <device.h>
#include <libflash/libflash.h>
#include <libflash/libffs.h>
#include <libflash/ipmi-hiomap.h>
#include <libflash/blocklevel.h>
#include <libflash/ecc.h>
#include <libstb/secureboot.h>
#include <libstb/trustedboot.h>
#include <libxz/xz.h>
#include <elf.h>
#include <timebase.h>

struct flash {
	struct list_node	list;
	bool			busy;
	bool			no_erase;
	struct blocklevel_device *bl;
	uint64_t		size;
	uint32_t		block_size;
	int			id;
};

static struct {
	enum resource_id	id;
	uint32_t		subid;
	char			name[PART_NAME_MAX+1];
} part_name_map[] = {
	{ RESOURCE_ID_KERNEL,	RESOURCE_SUBID_NONE,		"BOOTKERNEL" },
	{ RESOURCE_ID_INITRAMFS,RESOURCE_SUBID_NONE,		"ROOTFS" },
	{ RESOURCE_ID_CAPP,	RESOURCE_SUBID_SUPPORTED,	"CAPP" },
	{ RESOURCE_ID_IMA_CATALOG,  RESOURCE_SUBID_SUPPORTED,	"IMA_CATALOG" },
	{ RESOURCE_ID_VERSION,	RESOURCE_SUBID_NONE,		"VERSION" },
	{ RESOURCE_ID_KERNEL_FW,	RESOURCE_SUBID_NONE,		"BOOTKERNFW" },
};

static LIST_HEAD(flashes);
static struct flash *system_flash;

/* Using a single lock as we only have one flash at present. */
static struct lock flash_lock;

/* nvram-on-flash support */
static struct flash *nvram_flash;
static u32 nvram_offset, nvram_size;

/* secboot-on-flash support */
static struct flash *secboot_flash;
static u32 secboot_offset, secboot_size;

bool flash_reserve(void)
{
	bool rc = false;

	if (!try_lock(&flash_lock))
		return false;

	if (!system_flash->busy) {
		system_flash->busy = true;
		rc = true;
	}
	unlock(&flash_lock);

	return rc;
}

void flash_release(void)
{
	lock(&flash_lock);
	system_flash->busy = false;
	unlock(&flash_lock);
}

bool flash_unregister(void)
{
	struct blocklevel_device *bl = system_flash->bl;

	if (bl->exit)
		return bl->exit(bl);

	prlog(PR_NOTICE, "Unregister flash device is not supported\n");
	return true;
}

int flash_secboot_info(uint32_t *total_size)
{
	int rc;

	lock(&flash_lock);
	if (!secboot_flash) {
		rc = OPAL_HARDWARE;
	} else if (secboot_flash->busy) {
		rc = OPAL_BUSY;
	} else {
		*total_size = secboot_size;
		rc = OPAL_SUCCESS;
	}
	unlock(&flash_lock);

	return rc;
}

int flash_secboot_read(void *dst, uint32_t src, uint32_t len)
{
	int rc;

	if (!try_lock(&flash_lock))
		return OPAL_BUSY;

	if (!secboot_flash) {
		rc = OPAL_HARDWARE;
		goto out;
	}

	if (secboot_flash->busy) {
		rc = OPAL_BUSY;
		goto out;
	}

	if ((src + len) > secboot_size) {
		prerror("FLASH_SECBOOT: read out of bound (0x%x,0x%x)\n",
			src, len);
		rc = OPAL_PARAMETER;
		goto out;
	}

	secboot_flash->busy = true;
	unlock(&flash_lock);

	rc = blocklevel_read(secboot_flash->bl, secboot_offset + src, dst, len);

	lock(&flash_lock);
	secboot_flash->busy = false;
out:
	unlock(&flash_lock);
	return rc;
}

int flash_secboot_write(uint32_t dst, void *src, uint32_t len)
{
	int rc;

	if (!try_lock(&flash_lock))
		return OPAL_BUSY;

	if (secboot_flash->busy) {
		rc = OPAL_BUSY;
		goto out;
	}

	if ((dst + len) > secboot_size) {
		prerror("FLASH_SECBOOT: write out of bound (0x%x,0x%x)\n",
			dst, len);
		rc = OPAL_PARAMETER;
		goto out;
	}

	secboot_flash->busy = true;
	unlock(&flash_lock);

	rc = blocklevel_write(secboot_flash->bl, secboot_offset + dst, src, len);

	lock(&flash_lock);
	secboot_flash->busy = false;
out:
	unlock(&flash_lock);
	return rc;
}

static int flash_nvram_info(uint32_t *total_size)
{
	int rc;

	lock(&flash_lock);
	if (!nvram_flash) {
		rc = OPAL_HARDWARE;
	} else if (nvram_flash->busy) {
		rc = OPAL_BUSY;
	} else {
		*total_size = nvram_size;
		rc = OPAL_SUCCESS;
	}
	unlock(&flash_lock);

	return rc;
}

static int flash_nvram_start_read(void *dst, uint32_t src, uint32_t len)
{
	int rc;

	if (!try_lock(&flash_lock))
		return OPAL_BUSY;

	if (!nvram_flash) {
		rc = OPAL_HARDWARE;
		goto out;
	}

	if (nvram_flash->busy) {
		rc = OPAL_BUSY;
		goto out;
	}

	if ((src + len) > nvram_size) {
		prerror("NVRAM: read out of bound (0x%x,0x%x)\n",
			src, len);
		rc = OPAL_PARAMETER;
		goto out;
	}

	nvram_flash->busy = true;
	unlock(&flash_lock);

	rc = blocklevel_read(nvram_flash->bl, nvram_offset + src, dst, len);

	lock(&flash_lock);
	nvram_flash->busy = false;
out:
	unlock(&flash_lock);
	if (!rc)
		nvram_read_complete(true);
	return rc;
}

static int flash_nvram_write(uint32_t dst, void *src, uint32_t len)
{
	int rc;

	if (!try_lock(&flash_lock))
		return OPAL_BUSY;

	if (nvram_flash->busy) {
		rc = OPAL_BUSY;
		goto out;
	}

	/* TODO: When we have async jobs for PRD, turn this into one */

	if ((dst + len) > nvram_size) {
		prerror("NVRAM: write out of bound (0x%x,0x%x)\n",
			dst, len);
		rc = OPAL_PARAMETER;
		goto out;
	}

	nvram_flash->busy = true;
	unlock(&flash_lock);

	rc = blocklevel_write(nvram_flash->bl, nvram_offset + dst, src, len);

	lock(&flash_lock);
	nvram_flash->busy = false;
out:
	unlock(&flash_lock);
	return rc;
}


static int flash_secboot_probe(struct flash *flash, struct ffs_handle *ffs)
{
	uint32_t start, size, part;
	bool ecc;
	int rc;

	prlog(PR_DEBUG, "FLASH: probing for SECBOOT\n");

	rc = ffs_lookup_part(ffs, "SECBOOT", &part);
	if (rc) {
		prlog(PR_WARNING, "FLASH: no SECBOOT partition found\n");
		return OPAL_HARDWARE;
	}

	rc = ffs_part_info(ffs, part, NULL,
			   &start, &size, NULL, &ecc);
	if (rc) {
		/**
		 * @fwts-label SECBOOTNoPartition
		 * @fwts-advice OPAL could not find an SECBOOT partition
		 *     on the system flash. Check that the system flash
		 *     has a valid partition table, and that the firmware
		 *     build process has added a SECBOOT partition.
		 */
		prlog(PR_ERR, "FLASH: Can't parse ffs info for SECBOOT\n");
		return OPAL_HARDWARE;
	}

	secboot_flash = flash;
	secboot_offset = start;
	secboot_size = ecc ? ecc_buffer_size_minus_ecc(size) : size;

	return 0;
}

static int flash_nvram_probe(struct flash *flash, struct ffs_handle *ffs)
{
	uint32_t start, size, part;
	bool ecc;
	int rc;

	prlog(PR_INFO, "probing for NVRAM\n");

	rc = ffs_lookup_part(ffs, "NVRAM", &part);
	if (rc) {
		prlog(PR_WARNING, "no NVRAM partition found\n");
		return OPAL_HARDWARE;
	}

	rc = ffs_part_info(ffs, part, NULL,
			   &start, &size, NULL, &ecc);
	if (rc) {
		/**
		 * @fwts-label NVRAMNoPartition
		 * @fwts-advice OPAL could not find an NVRAM partition
		 *     on the system flash. Check that the system flash
		 *     has a valid partition table, and that the firmware
		 *     build process has added a NVRAM partition.
		 */
		prlog(PR_ERR, "Can't parse ffs info for NVRAM\n");
		return OPAL_HARDWARE;
	}

	nvram_flash = flash;
	nvram_offset = start;
	nvram_size = ecc ? ecc_buffer_size_minus_ecc(size) : size;

	platform.nvram_info = flash_nvram_info;
	platform.nvram_start_read = flash_nvram_start_read;
	platform.nvram_write = flash_nvram_write;

	return 0;
}

/* core flash support */

static struct dt_node *flash_add_dt_node(struct flash *flash, int id)
{
	int i;
	int rc;
	const char *name;
	bool ecc;
	struct ffs_handle *ffs;
	int ffs_part_num, ffs_part_start, ffs_part_size;
	struct dt_node *flash_node;
	struct dt_node *partition_container_node;
	struct dt_node *partition_node;

	flash_node = dt_new_addr(opal_node, "flash", id);
	dt_add_property_strings(flash_node, "compatible", "ibm,opal-flash");
	dt_add_property_cells(flash_node, "ibm,opal-id", id);
	dt_add_property_u64(flash_node, "reg", flash->size);
	dt_add_property_cells(flash_node, "ibm,flash-block-size",
			flash->block_size);
	if (flash->no_erase)
		dt_add_property(flash_node, "no-erase", NULL, 0);

	/* we fix to 32-bits */
	dt_add_property_cells(flash_node, "#address-cells", 1);
	dt_add_property_cells(flash_node, "#size-cells", 1);

	/* Add partition container node */
	partition_container_node = dt_new(flash_node, "partitions");
	dt_add_property_strings(partition_container_node, "compatible", "fixed-partitions");

	/* we fix to 32-bits */
	dt_add_property_cells(partition_container_node, "#address-cells", 1);
	dt_add_property_cells(partition_container_node, "#size-cells", 1);

	/* Add partitions */
	for (i = 0, name = NULL; i < ARRAY_SIZE(part_name_map); i++) {
		name = part_name_map[i].name;

		rc = ffs_init(0, flash->size, flash->bl, &ffs, 1);
		if (rc) {
			prerror("Can't open ffs handle\n");
			continue;
		}

		rc = ffs_lookup_part(ffs, name, &ffs_part_num);
		if (rc) {
			/* This is not an error per-se, some partitions
			 * are purposefully absent, don't spam the logs
			 */
		        prlog(PR_DEBUG, "No %s partition\n", name);
			continue;
		}
		rc = ffs_part_info(ffs, ffs_part_num, NULL,
				   &ffs_part_start, NULL, &ffs_part_size, &ecc);
		if (rc) {
			prerror("Failed to get %s partition info\n", name);
			continue;
		}

		partition_node = dt_new_addr(partition_container_node, "partition", ffs_part_start);
		dt_add_property_strings(partition_node, "label", name);
		dt_add_property_cells(partition_node, "reg", ffs_part_start, ffs_part_size);
		if (part_name_map[i].id != RESOURCE_ID_KERNEL_FW) {
			/* Mark all partitions other than the full PNOR and the boot kernel
			 * firmware as read only.  These two partitions are the only partitions
			 * that are properly erase block aligned at this time.
			 */
			dt_add_property(partition_node, "read-only", NULL, 0);
		}
	}

	partition_node = dt_new_addr(partition_container_node, "partition", 0);
	dt_add_property_strings(partition_node, "label", "PNOR");
	dt_add_property_cells(partition_node, "reg", 0, flash->size);

	return flash_node;
}

static void setup_system_flash(struct flash *flash, struct dt_node *node,
		const char *name, struct ffs_handle *ffs)
{
	char *path;

	if (!ffs)
		return;

	if (system_flash) {
		/**
		 * @fwts-label SystemFlashMultiple
		 * @fwts-advice OPAL Found multiple system flash.
		 *    Since we've already found a system flash we are
		 *    going to use that one but this ordering is not
		 *    guaranteed so may change in future.
		 */
		prlog(PR_WARNING, "Attempted to register multiple system "
		      "flash: %s\n", name);
		return;
	}

	prlog(PR_NOTICE, "Found system flash: %s id:%i\n",
	      name, flash->id);

	system_flash = flash;
	path = dt_get_path(node);
	dt_add_property_string(dt_chosen, "ibm,system-flash", path);
	free(path);

	prlog(PR_INFO, "registered system flash device %s\n", name);

	flash_nvram_probe(flash, ffs);
	flash_secboot_probe(flash, ffs);
}

static int num_flashes(void)
{
	struct flash *flash;
	int i = 0;

	list_for_each(&flashes, flash, list)
		i++;

	return i;
}

int flash_register(struct blocklevel_device *bl)
{
	uint64_t size;
	uint32_t block_size;
	struct ffs_handle *ffs;
	struct dt_node *node;
	struct flash *flash;
	const char *name;
	int rc;

	rc = blocklevel_get_info(bl, &name, &size, &block_size);
	if (rc)
		return rc;

	if (!name)
		name = "(unnamed)";

	prlog(PR_INFO, "registering flash device %s "
			"(size 0x%llx, blocksize 0x%x)\n",
			name, size, block_size);

	flash = malloc(sizeof(struct flash));
	if (!flash) {
		prlog(PR_ERR, "Error allocating flash structure\n");
		return OPAL_RESOURCE;
	}

	flash->busy = false;
	flash->bl = bl;
	flash->no_erase = !(bl->flags & WRITE_NEED_ERASE);
	flash->size = size;
	flash->block_size = block_size;
	flash->id = num_flashes();

	rc = ffs_init(0, flash->size, bl, &ffs, 1);
	if (rc) {
		/**
		 * @fwts-label NoFFS
		 * @fwts-advice System flash isn't formatted as expected.
		 * This could mean several OPAL utilities do not function
		 * as expected. e.g. gard, pflash.
		 */
		prlog(PR_WARNING, "No ffs info; "
				"using raw device only\n");
		ffs = NULL;
	}

	node = flash_add_dt_node(flash, flash->id);

	setup_system_flash(flash, node, name, ffs);

	if (ffs)
		ffs_close(ffs);

	lock(&flash_lock);
	list_add(&flashes, &flash->list);
	unlock(&flash_lock);

	return OPAL_SUCCESS;
}

enum flash_op {
	FLASH_OP_READ,
	FLASH_OP_WRITE,
	FLASH_OP_ERASE,
};

static int64_t opal_flash_op(enum flash_op op, uint64_t id, uint64_t offset,
		uint64_t buf, uint64_t size, uint64_t token)
{
	struct flash *flash = NULL;
	int rc;

	if (!try_lock(&flash_lock))
		return OPAL_BUSY;

	list_for_each(&flashes, flash, list)
		if (flash->id == id)
			break;

	if (flash->id != id) {
		/* Couldn't find the flash */
		rc = OPAL_PARAMETER;
		goto err;
	}

	if (flash->busy) {
		rc = OPAL_BUSY;
		goto err;
	}

	if (size >= flash->size || offset >= flash->size
			|| offset + size > flash->size) {
		rc = OPAL_PARAMETER;
		goto err;
	}

	/*
	 * These ops intentionally have no smarts (ecc correction or erase
	 * before write) to them.
	 * Skiboot is simply exposing the PNOR flash to the host.
	 * The host is expected to understand that this is a raw flash
	 * device and treat it as such.
	 */
	switch (op) {
	case FLASH_OP_READ:
		rc = blocklevel_raw_read(flash->bl, offset, (void *)buf, size);
		break;
	case FLASH_OP_WRITE:
		rc = blocklevel_raw_write(flash->bl, offset, (void *)buf, size);
		break;
	case FLASH_OP_ERASE:
		rc = blocklevel_erase(flash->bl, offset, size);
		break;
	default:
		assert(0);
	}

	if (rc) {
		rc = OPAL_HARDWARE;
		goto err;
	}

	unlock(&flash_lock);

	opal_queue_msg(OPAL_MSG_ASYNC_COMP, NULL, NULL,
			cpu_to_be64(token),
			cpu_to_be64(rc));

	return OPAL_ASYNC_COMPLETION;

err:
	unlock(&flash_lock);
	return rc;
}

static int64_t opal_flash_read(uint64_t id, uint64_t offset, uint64_t buf,
		uint64_t size, uint64_t token)
{
	if (!opal_addr_valid((void *)buf))
		return OPAL_PARAMETER;

	return opal_flash_op(FLASH_OP_READ, id, offset, buf, size, token);
}

static int64_t opal_flash_write(uint64_t id, uint64_t offset, uint64_t buf,
		uint64_t size, uint64_t token)
{
	if (!opal_addr_valid((void *)buf))
		return OPAL_PARAMETER;

	return opal_flash_op(FLASH_OP_WRITE, id, offset, buf, size, token);
}

static int64_t opal_flash_erase(uint64_t id, uint64_t offset, uint64_t size,
		uint64_t token)
{
	return opal_flash_op(FLASH_OP_ERASE, id, offset, 0L, size, token);
}

opal_call(OPAL_FLASH_READ, opal_flash_read, 5);
opal_call(OPAL_FLASH_WRITE, opal_flash_write, 5);
opal_call(OPAL_FLASH_ERASE, opal_flash_erase, 4);

/* flash resource API */
const char *flash_map_resource_name(enum resource_id id)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(part_name_map); i++) {
		if (part_name_map[i].id == id)
			return part_name_map[i].name;
	}
	return NULL;
}

static size_t sizeof_elf_from_hdr(void *buf)
{
	struct elf_hdr *elf = (struct elf_hdr *)buf;
	size_t sz = 0;

	BUILD_ASSERT(SECURE_BOOT_HEADERS_SIZE > sizeof(struct elf_hdr));
	BUILD_ASSERT(SECURE_BOOT_HEADERS_SIZE > sizeof(struct elf64be_hdr));
	BUILD_ASSERT(SECURE_BOOT_HEADERS_SIZE > sizeof(struct elf32be_hdr));

	if (elf->ei_ident == ELF_IDENT) {
		if (elf->ei_class == ELF_CLASS_64) {
			if (elf->ei_data == ELF_DATA_LSB) {
				struct elf64le_hdr *kh = (struct elf64le_hdr *)buf;
				sz = le64_to_cpu(kh->e_shoff) +
					((uint32_t)le16_to_cpu(kh->e_shentsize) *
					 (uint32_t)le16_to_cpu(kh->e_shnum));
			} else {
				struct elf64be_hdr *kh = (struct elf64be_hdr *)buf;
				sz = be64_to_cpu(kh->e_shoff) +
					((uint32_t)be16_to_cpu(kh->e_shentsize) *
					 (uint32_t)be16_to_cpu(kh->e_shnum));
			}
		} else if (elf->ei_class == ELF_CLASS_32) {
			if (elf->ei_data == ELF_DATA_LSB) {
				struct elf32le_hdr *kh = (struct elf32le_hdr *)buf;
				sz = le32_to_cpu(kh->e_shoff) +
					(le16_to_cpu(kh->e_shentsize) *
					 le16_to_cpu(kh->e_shnum));
			} else {
				struct elf32be_hdr *kh = (struct elf32be_hdr *)buf;
				sz = be32_to_cpu(kh->e_shoff) +
					(be16_to_cpu(kh->e_shentsize) *
					 be16_to_cpu(kh->e_shnum));
			}
		}
	}

	return sz;
}

/*
 * load a resource from FLASH
 * buf and len shouldn't account for ECC even if partition is ECCed.
 *
 * The API here is a bit strange.
 * If resource has a STB container, buf will contain it
 * If loading subpartition with STB container, buff will *NOT* contain it
 * For trusted boot, the whole partition containing the subpart is measured.
 *
 * Additionally, the logic to work out how much to read from flash is insane.
 */
static int flash_load_resource(enum resource_id id, uint32_t subid,
			       void *buf, size_t *len)
{
	int i;
	int rc = OPAL_RESOURCE;
	struct ffs_handle *ffs;
	struct flash *flash;
	const char *name;
	bool status = false;
	bool ecc;
	bool part_signed = false;
	void *bufp = buf;
	size_t bufsz = *len;
	int ffs_part_num, ffs_part_start, ffs_part_size;
	int content_size = 0;
	int offset = 0;

	lock(&flash_lock);

	if (!system_flash) {
		/**
		 * @fwts-label SystemFlashNotFound
		 * @fwts-advice No system flash was found. Check for missing
		 * calls flash_register(...).
		 */
		prlog(PR_WARNING, "Can't load resource id:%i. "
		      "No system flash found\n", id);
		goto out_unlock;
	}

	flash = system_flash;

	if (flash->busy)
		goto out_unlock;

	for (i = 0, name = NULL; i < ARRAY_SIZE(part_name_map); i++) {
		if (part_name_map[i].id == id) {
			name = part_name_map[i].name;
			break;
		}
	}
	if (!name) {
		prerror("Couldn't find partition for id %d\n", id);
		goto out_unlock;
	}
	/*
	 * If partition doesn't have a subindex but the caller specifies one,
	 * we fail.  eg. kernel partition doesn't have a subindex
	 */
	if ((part_name_map[i].subid == RESOURCE_SUBID_NONE) &&
	    (subid != RESOURCE_SUBID_NONE)) {
		prerror("PLAT: Partition %s doesn't have subindex\n", name);
		goto out_unlock;
	}

	rc = ffs_init(0, flash->size, flash->bl, &ffs, 1);
	if (rc) {
		prerror("Can't open ffs handle: %d\n", rc);
		goto out_unlock;
	}

	rc = ffs_lookup_part(ffs, name, &ffs_part_num);
	if (rc) {
		/* This is not an error per-se, some partitions
		 * are purposefully absent, don't spam the logs
		 */
	        prlog(PR_DEBUG, "No %s partition\n", name);
		goto out_free_ffs;
	}
	rc = ffs_part_info(ffs, ffs_part_num, NULL,
			   &ffs_part_start, NULL, &ffs_part_size, &ecc);
	if (rc) {
		prerror("Failed to get %s partition info\n", name);
		goto out_free_ffs;
	}
	prlog(PR_DEBUG,"%s partition %s ECC\n",
	      name, ecc  ? "has" : "doesn't have");

	/*
	 * FIXME: Make the fact we don't support partitions smaller than 4K
	 *  	  more explicit.
	 */
	if (ffs_part_size < SECURE_BOOT_HEADERS_SIZE) {
		prerror("secboot headers bigger than "
			"partition size 0x%x\n", ffs_part_size);
		goto out_free_ffs;
	}

	rc = blocklevel_read(flash->bl, ffs_part_start, bufp,
			SECURE_BOOT_HEADERS_SIZE);
	if (rc) {
		prerror("failed to read the first 0x%x from "
			"%s partition, rc %d\n", SECURE_BOOT_HEADERS_SIZE,
			name, rc);
		goto out_free_ffs;
	}

	part_signed = stb_is_container(bufp, SECURE_BOOT_HEADERS_SIZE);

	prlog(PR_DEBUG, "%s partition %s signed\n", name,
	      part_signed ? "is" : "isn't");

	/*
	 * part_start/size are raw pointers into the partition.
	 *  ie. they will account for ECC if included.
	 */

	if (part_signed) {
		bufp += SECURE_BOOT_HEADERS_SIZE;
		bufsz -= SECURE_BOOT_HEADERS_SIZE;
		content_size = stb_sw_payload_size(buf, SECURE_BOOT_HEADERS_SIZE);
		*len = content_size + SECURE_BOOT_HEADERS_SIZE;

		if (content_size > bufsz) {
			prerror("content size > buffer size\n");
			rc = OPAL_PARAMETER;
			goto out_free_ffs;
		}

		if (*len > ffs_part_size) {
			prerror("FLASH: Cannot load %s. Content is larger than the partition\n",
					name);
			rc = OPAL_PARAMETER;
			goto out_free_ffs;
		}

		ffs_part_start += SECURE_BOOT_HEADERS_SIZE;

		rc = blocklevel_read(flash->bl, ffs_part_start, bufp,
					  content_size);
		if (rc) {
			prerror("failed to read content size %d"
				" %s partition, rc %d\n",
				content_size, name, rc);
			goto out_free_ffs;
		}

		if (subid == RESOURCE_SUBID_NONE)
			goto done_reading;

		rc = flash_subpart_info(bufp, content_size, ffs_part_size,
					NULL, subid, &offset, &content_size);
		if (rc) {
			prerror("Failed to parse subpart info for %s\n",
				name);
			goto out_free_ffs;
		}
		bufp += offset;
		goto done_reading;
	} else /* stb_signed */ {
		/*
		 * Back to the old way of doing things, no STB header.
		 */
		if (subid == RESOURCE_SUBID_NONE) {
			if (id == RESOURCE_ID_KERNEL ||
				id == RESOURCE_ID_INITRAMFS) {
				/*
				 * Because actualSize is a lie, we compute the
				 * size of the BOOTKERNEL based on what the ELF
				 * headers say. Otherwise we end up reading more
				 * than we should
				 */
				content_size = sizeof_elf_from_hdr(buf);
				if (!content_size) {
					prerror("Invalid ELF header part"
						" %s\n", name);
					rc = OPAL_RESOURCE;
					goto out_free_ffs;
				}
			} else {
				content_size = ffs_part_size;
			}
			if (content_size > bufsz) {
				prerror("%s content size %d > "
					" buffer size %lu\n", name,
					content_size, bufsz);
				rc = OPAL_PARAMETER;
				goto out_free_ffs;
			}
			prlog(PR_DEBUG, "computed %s size %u\n",
			      name, content_size);
			rc = blocklevel_read(flash->bl, ffs_part_start,
						  buf, content_size);
			if (rc) {
				prerror("failed to read content size %d"
					" %s partition, rc %d\n",
					content_size, name, rc);
				goto out_free_ffs;
			}
			*len = content_size;
			goto done_reading;
		}
		BUILD_ASSERT(FLASH_SUBPART_HEADER_SIZE <= SECURE_BOOT_HEADERS_SIZE);
		rc = flash_subpart_info(bufp, SECURE_BOOT_HEADERS_SIZE,
					ffs_part_size, &ffs_part_size, subid,
					&offset, &content_size);
		if (rc) {
			prerror("FAILED reading subpart info. rc=%d\n",
				rc);
			goto out_free_ffs;
		}

		*len = ffs_part_size;
		prlog(PR_DEBUG, "Computed %s partition size: %u "
		      "(subpart %u size %u offset %u)\n", name, ffs_part_size,
		      subid, content_size, offset);
		/*
		 * For a sub partition, we read the whole (computed)
		 * partition, and then measure that.
		 * Afterwards, we memmove() things back into place for
		 * the caller.
		 */
		rc = blocklevel_read(flash->bl, ffs_part_start,
					  buf, ffs_part_size);

		bufp += offset;
	}

done_reading:
	/*
	 * Verify and measure the retrieved PNOR partition as part of the
	 * secure boot and trusted boot requirements
	 */
	secureboot_verify(id, buf, *len);
	trustedboot_measure(id, buf, *len);

	/* Find subpartition */
	if (subid != RESOURCE_SUBID_NONE) {
		memmove(buf, bufp, content_size);
		*len = content_size;
	}

	status = true;

out_free_ffs:
	ffs_close(ffs);
out_unlock:
	unlock(&flash_lock);
	return status ? OPAL_SUCCESS : rc;
}


struct flash_load_resource_item {
	enum resource_id id;
	uint32_t subid;
	int result;
	void *buf;
	size_t *len;
	struct list_node link;
};

static LIST_HEAD(flash_load_resource_queue);
static LIST_HEAD(flash_loaded_resources);
static struct lock flash_load_resource_lock = LOCK_UNLOCKED;
static struct cpu_job *flash_load_job = NULL;

int flash_resource_loaded(enum resource_id id, uint32_t subid)
{
	struct flash_load_resource_item *resource = NULL;
	struct flash_load_resource_item *r;
	int rc = OPAL_BUSY;

	lock(&flash_load_resource_lock);
	list_for_each(&flash_loaded_resources, r, link) {
		if (r->id == id && r->subid == subid) {
			resource = r;
			break;
		}
	}

	if (resource) {
		rc = resource->result;
		list_del(&resource->link);
		free(resource);
	}

	if (list_empty(&flash_load_resource_queue) && flash_load_job) {
		cpu_wait_job(flash_load_job, true);
		flash_load_job = NULL;
	}

	unlock(&flash_load_resource_lock);

	return rc;
}

/*
 * Retry for 10 minutes in 5 second intervals: allow 5 minutes for a BMC reboot
 * (need the BMC if we're using HIOMAP flash access), then 2x for some margin.
 */
#define FLASH_LOAD_WAIT_MS	5000
#define FLASH_LOAD_RETRIES	(2 * 5 * (60 / (FLASH_LOAD_WAIT_MS / 1000)))

static void flash_load_resources(void *data __unused)
{
	struct flash_load_resource_item *r;
	int retries = FLASH_LOAD_RETRIES;
	int result = OPAL_RESOURCE;

	lock(&flash_load_resource_lock);
	do {
		if (list_empty(&flash_load_resource_queue)) {
			break;
		}
		r = list_top(&flash_load_resource_queue,
			     struct flash_load_resource_item, link);
		if (r->result != OPAL_EMPTY)
			prerror("flash_load_resources() list_top unexpected "
				" result %d\n", r->result);
		r->result = OPAL_BUSY;
		unlock(&flash_load_resource_lock);

		while (retries) {
			result = flash_load_resource(r->id, r->subid, r->buf,
						     r->len);
			if (result == OPAL_SUCCESS) {
				retries = FLASH_LOAD_RETRIES;
				break;
			}

			if (result != FLASH_ERR_AGAIN &&
					result != FLASH_ERR_DEVICE_GONE)
				break;

			time_wait_ms(FLASH_LOAD_WAIT_MS);

			retries--;

			prlog(PR_WARNING,
			      "Retrying load of %d:%d, %d attempts remain\n",
			      r->id, r->subid, retries);
		}

		lock(&flash_load_resource_lock);
		r = list_pop(&flash_load_resource_queue,
			     struct flash_load_resource_item, link);
		/* Will reuse the result from when we hit retries == 0 */
		r->result = result;
		list_add_tail(&flash_loaded_resources, &r->link);
	} while(true);
	unlock(&flash_load_resource_lock);
}

static void start_flash_load_resource_job(void)
{
	if (flash_load_job)
		cpu_wait_job(flash_load_job, true);

	flash_load_job = cpu_queue_job(NULL, "flash_load_resources",
				       flash_load_resources, NULL);

	cpu_process_local_jobs();
}

int flash_start_preload_resource(enum resource_id id, uint32_t subid,
				 void *buf, size_t *len)
{
	struct flash_load_resource_item *r;
	bool start_thread = false;

	r = malloc(sizeof(struct flash_load_resource_item));

	assert(r != NULL);
	r->id = id;
	r->subid = subid;
	r->buf = buf;
	r->len = len;
	r->result = OPAL_EMPTY;

	prlog(PR_DEBUG, "Queueing preload of %x/%x\n",
	      r->id, r->subid);

	lock(&flash_load_resource_lock);
	if (list_empty(&flash_load_resource_queue)) {
		start_thread = true;
	}
	list_add_tail(&flash_load_resource_queue, &r->link);
	unlock(&flash_load_resource_lock);

	if (start_thread)
		start_flash_load_resource_job();

	return OPAL_SUCCESS;
}

/*
 * The `libxz` decompression routines are blocking; the new decompression
 * routines, wrapper around `libxz` functions, provide support for asynchronous
 * decompression. There are two routines, which start the decompression, and one
 * which waits for the decompression to complete.
 *
 * The decompressed image will be present in the `dst` parameter of
 * `xz_decompress` structure.
 *
 * When the decompression is successful, the xz_decompress->status will be
 * `OPAL_SUCCESS` else OPAL_PARAMETER, see definition of xz_decompress structure
 * for details.
 */
static void xz_decompress(void *data)
{
	struct xz_decompress *xz = (struct xz_decompress *)data;
	struct xz_dec *s;
	struct xz_buf b;

	/* Initialize the xz library first */
	xz_crc32_init();
	s = xz_dec_init(XZ_SINGLE, 0);
	if (s == NULL) {
		prerror("initialization error for xz\n");
		xz->status = OPAL_NO_MEM;
		return;
	}

	xz->xz_error = XZ_DATA_ERROR;
	xz->status = OPAL_PARTIAL;

	b.in = xz->src;
	b.in_pos = 0;
	b.in_size = xz->src_size;
	b.out = xz->dst;
	b.out_pos = 0;
	b.out_size = xz->dst_size;

	/* Start decompressing */
	xz->xz_error = xz_dec_run(s, &b);
	if (xz->xz_error != XZ_STREAM_END) {
		prerror("failed to decompress subpartition\n");
		xz->status = OPAL_PARAMETER;
	} else
		xz->status = OPAL_SUCCESS;

	xz_dec_end(s);
}

/*
 * xz_start_decompress: start the decompression job and return.
 *
 * struct xz_decompress *xz, should be populated by the caller with
 *     - the starting address of the compressed binary
 *     - the address where the decompressed image should be placed
 *     - the sizes of the source and the destination
 *
 * xz->src: Source address (The compressed binary)
 * xz->src_size: Source size
 * xz->dst: Destination address (The memory area where the `src` will be
 *          decompressed)
 * xz->dst_size: Destination size
 *
 * The `status` value will be OPAL_PARTIAL till the job completes (successfully
 * or not)
 */
void xz_start_decompress(struct xz_decompress *xz)
{
	struct cpu_job *job;

	if (!xz)
		return;

	if (!xz->dst || !xz->dst_size || !xz->src || !xz->src_size) {
		xz->status = OPAL_PARAMETER;
		return;
	}

	job = cpu_queue_job(NULL, "xz_decompress", xz_decompress,
			    (void *) xz);
	if (!job) {
		xz->status = OPAL_NO_MEM;
		return;
	}

	xz->job = job;
}

/*
 * This function waits for the decompression job to complete. The `ret`
 * structure member in `xz_decompress` will have the status code.
 *
 * status == OPAL_SUCCESS on success, else the corresponding error code.
 */
void wait_xz_decompress(struct xz_decompress *xz)
{
	if (!xz)
		return;

	cpu_wait_job(xz->job, true);
}
