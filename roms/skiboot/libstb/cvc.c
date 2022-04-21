// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2018 IBM Corp. */

#ifndef pr_fmt
#define pr_fmt(fmt) "STB: " fmt
#endif

#include <skiboot.h>
#include <string.h>
#include <opal-api.h>
#include <chip.h>
#include <xscom.h>
#include <inttypes.h>
#include "secureboot.h"
#include "cvc.h"
#include "mbedtls/sha512.h"

/*
 * Assembly interfaces to call into the Container Verification Code.
 * func_ptr: CVC base address + offset
 */
ROM_response __cvc_verify_v1(void *func_ptr, ROM_container_raw *container,
			     ROM_hw_params *params);
void __cvc_sha512_v1(void *func_ptr, const uint8_t *data, size_t len,
		     uint8_t *digest);

struct container_verification_code {
	uint64_t start_addr;
	uint64_t end_addr;
	struct list_head service_list;
};

static struct container_verification_code *cvc = NULL;
static bool softrom = false;
static void *secure_rom_mem = NULL;

static struct dt_node *cvc_resv_mem = NULL;
static struct dt_node *cvc_node = NULL;

struct cvc_service {
	int id;
	uint64_t addr;    /* base_addr + offset */
	uint32_t version;
	struct list_node link;
};

static struct {
	enum cvc_service_id id;
	const char *name;
} cvc_service_map[] = {
	{ CVC_SHA512_SERVICE, "sha512" },
	{ CVC_VERIFY_SERVICE, "verify" },
};

static struct cvc_service *cvc_find_service(enum cvc_service_id id)
{
	struct cvc_service *service;
	if (!cvc)
		return NULL;

	list_for_each(&cvc->service_list, service, link) {
		if (service->id == id)
			return service;
	}
	return NULL;
}

static const char *cvc_service_map_name(enum cvc_service_id id)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(cvc_service_map); i++) {
		if (cvc_service_map[i].id == id)
			return cvc_service_map[i].name;
	}
	return NULL;
}

static void cvc_register(uint64_t start_addr, uint64_t end_addr)
{
	if (cvc)
		return;

	cvc = malloc(sizeof(struct container_verification_code));
	assert(cvc);
	cvc->start_addr = start_addr;
	cvc->end_addr = end_addr;
	list_head_init(&cvc->service_list);
	prlog(PR_INFO, "Found CVC @ %" PRIx64 "-%" PRIx64 "\n",
	      start_addr, end_addr);
}

static void cvc_service_register(uint32_t id, uint32_t offset, uint32_t version)
{
	struct cvc_service *service;
	const char *name;

	if (!cvc)
		return;

	/* Service already registered? */
	if (cvc_find_service(id))
		return;

	if (cvc->start_addr + offset > cvc->end_addr) {
		prlog(PR_WARNING, "CVC service @ %x out of range, "
		      "id=%d\n", offset, id);
		return;
	}

	name = cvc_service_map_name(id);
	if (!name) {
		prlog(PR_ERR, "CVC service %d not supported\n", id);
		return;
	}

	service = malloc(sizeof(struct cvc_service));
	assert(service);
	service->id = id;
	service->version = version;
	service->addr = cvc->start_addr + offset;
	list_add_tail(&cvc->service_list, &service->link);
	prlog(PR_INFO, "Found CVC-%s @ %" PRIx64 ", version=%d\n",
	      name, service->addr, service->version);
}

static int cvc_reserved_mem_init(struct dt_node *parent) {
	struct dt_node *node, *service;
	struct dt_node *reserved_mem;
	struct dt_node *exports;
	uint32_t phandle;
	uint64_t addr, size;

	reserved_mem = dt_find_by_path(dt_root, "/ibm,hostboot/reserved-memory");
	if (!reserved_mem) {
		prlog(PR_ERR, "/ibm,hostboot/reserved-memory not found\n");
		return -1;
	}

	/*
	 * The container verification code is stored in a hostboot reserved
	 * memory which is pointed by the property
	 * /ibm,secureboot/ibm,container-verification-code/memory-region
	 */
	dt_for_each_child(parent, node) {
		if (dt_node_is_compatible(node, "ibm,container-verification-code")) {
			phandle = dt_prop_get_u32(node, "memory-region");
			cvc_resv_mem = dt_find_by_phandle(reserved_mem, phandle);
			cvc_node = node;
			break;
		}
	}
	if (!cvc_resv_mem) {
		prlog(PR_ERR, "CVC not found in /ibm,hostboot/reserved-memory\n");
		return -1;
	}
	addr = dt_get_address(cvc_resv_mem, 0, &size);
	cvc_register(addr, addr + size-1);

	exports = dt_find_by_path(dt_root, "/ibm,opal/firmware/exports");
	if (!exports) {
		prerror("OCC: dt node /ibm,opal/firmware/exports not found\n");
		return false;
	}
	dt_add_property_u64s(exports, "cvc", addr, size - 1);

	/*
	 *  Each child of the CVC node describes a CVC service
	 */
	dt_for_each_child(node, service) {
		uint32_t version, offset;

		version = dt_prop_get_u32(service, "version");
		offset = dt_prop_get_u32(service, "reg");

		if (dt_node_is_compatible(service, "ibm,cvc-sha512"))
			cvc_service_register(CVC_SHA512_SERVICE, offset, version);
		else if (dt_node_is_compatible(service, "ibm,cvc-verify"))
			cvc_service_register(CVC_VERIFY_SERVICE, offset, version);
		else
			prlog(PR_DEBUG, "unknown %s\n", service->name);
	}

	return 0;
}

#define SECURE_ROM_MEMORY_SIZE		(16 * 1024)
#define SECURE_ROM_XSCOM_ADDRESS	0x02020017

#define SECURE_ROM_SHA512_OFFSET	0x20
#define SECURE_ROM_VERIFY_OFFSET	0x30

static int cvc_secure_rom_init(void) {
	const uint32_t reg_addr = SECURE_ROM_XSCOM_ADDRESS;
	struct dt_node *exports;
	struct proc_chip *chip;
	uint64_t reg_data;

	if (!secure_rom_mem) {
		secure_rom_mem = malloc(SECURE_ROM_MEMORY_SIZE);
		assert(secure_rom_mem);
	}
	/*
	 * The logic that contains the ROM within the processor is implemented
	 * in a way that it only responds to CI (cache inhibited) operations.
	 * Due to performance issues we copy the verification code from the
	 * secure ROM to RAM. We use memcpy_from_ci() to do that.
	 */
	chip = next_chip(NULL);
	xscom_read(chip->id, reg_addr, &reg_data);
	memcpy_from_ci(secure_rom_mem, (void*) reg_data,
		       SECURE_ROM_MEMORY_SIZE);
	cvc_register((uint64_t)secure_rom_mem,
		     (uint64_t)secure_rom_mem + SECURE_ROM_MEMORY_SIZE-1);

	exports = dt_find_by_path(dt_root, "/ibm,opal/firmware/exports");
	if (!exports) {
		prerror("OCC: dt node /ibm,opal/firmware/exports not found\n");
		return false;
	}

	dt_add_property_u64s(exports, "securerom", (uint64_t)secure_rom_mem,
			     SECURE_ROM_MEMORY_SIZE-1);

	cvc_service_register(CVC_SHA512_SERVICE, SECURE_ROM_SHA512_OFFSET, 1);
	cvc_service_register(CVC_VERIFY_SERVICE, SECURE_ROM_VERIFY_OFFSET, 1);
	return 0;
}

void cvc_update_reserved_memory_phandle(void) {
	struct dt_node *reserved_mem;

	if (!cvc_resv_mem || !cvc_node)
		return;

	/*
	 * The linux documentation, reserved-memory.txt, says that memory-region
	 * is a phandle that pairs to a children of /reserved-memory
	 */
	reserved_mem = dt_find_by_path(dt_root, "/reserved-memory");
	if (!reserved_mem) {
		prlog(PR_ERR, "/reserved-memory not found\n");
		return;
	}
	cvc_resv_mem = dt_find_by_name(reserved_mem, cvc_resv_mem->name);
	if (cvc_resv_mem) {
		dt_check_del_prop(cvc_node, "memory-region");
		dt_add_property_cells(cvc_node, "memory-region", cvc_resv_mem->phandle);
	} else {
		prlog(PR_WARNING, "CVC not found in /reserved-memory\n");
		return;
	}

	cvc_resv_mem = NULL;
	cvc_node = NULL;
}

int cvc_init(void)
{
	struct dt_node *node;
	int version;
	int rc = 0;

	if (cvc)
		return 0;

	node = dt_find_by_path(dt_root, "/ibm,secureboot");
	if (!node)
		return -1;

	if (!secureboot_is_compatible(node, &version, NULL)) {
		/**
		 * @fwts-label CVCNotCompatible
		 * @fwts-advice Compatible CVC driver not found. Probably,
		 * hostboot/mambo/skiboot has updated the
		 * /ibm,secureboot/compatible without adding a driver that
		 * supports it.
		 */
		prlog(PR_ERR, "%s FAILED, /ibm,secureboot not compatible.\n",
		     __func__);
		return -1;
	}

	/* Only in P8 the CVC is stored in a secure ROM */
	if (version == IBM_SECUREBOOT_V1 &&
	    proc_gen == proc_gen_p8) {
		rc = cvc_secure_rom_init();
	} else if (version == IBM_SECUREBOOT_SOFTROM) {
		softrom = true;
	} else if (version == IBM_SECUREBOOT_V2) {
		rc = cvc_reserved_mem_init(node);
	} else {
		prlog(PR_ERR, "%s FAILED. /ibm,secureboot not supported\n",
		      __func__);
		return -1;
	}
	return rc;
}

int call_cvc_sha512(const uint8_t *data, size_t data_len, uint8_t *digest,
		   size_t digest_size)
{
	struct cvc_service *service;

	if (!data || !digest || digest_size < SHA512_DIGEST_LENGTH)
		return OPAL_PARAMETER;

	if (data_len <= 0)
		return OPAL_SUCCESS;

	memset(digest, 0, SHA512_DIGEST_LENGTH);
	if (softrom) {
		mbedtls_sha512_context ctx;
		mbedtls_sha512_init(&ctx);
		mbedtls_sha512_starts(&ctx, 0); // SHA512 = 0
		mbedtls_sha512_update(&ctx, data, data_len);
		mbedtls_sha512_finish(&ctx, digest);
		mbedtls_sha512_free(&ctx);
		return OPAL_SUCCESS;
	}

	service = cvc_find_service(CVC_SHA512_SERVICE);

	if (!service)
		return OPAL_UNSUPPORTED;

	if (service->version == 1) {
		unsigned long msr = mfmsr();
		__cvc_sha512_v1((void*) service->addr, data, data_len, digest);
		assert(msr == mfmsr());
	} else {
		return OPAL_UNSUPPORTED;
	}

	return OPAL_SUCCESS;
}

int call_cvc_verify(void *container, size_t len, const void *hw_key_hash,
		    size_t hw_key_hash_size, __be64 *log)
{
	ROM_hw_params hw_params;
	ROM_response rc;
	struct cvc_service *service;

	if (!container || len < SECURE_BOOT_HEADERS_SIZE ||
	    !hw_key_hash || hw_key_hash_size <= 0)
		return OPAL_PARAMETER;

	if (softrom)
		return OPAL_UNSUPPORTED;

	service = cvc_find_service(CVC_VERIFY_SERVICE);

	if (!service)
		return OPAL_UNSUPPORTED;

	memset(&hw_params, 0, sizeof(ROM_hw_params));
	memcpy(&hw_params.hw_key_hash, hw_key_hash, hw_key_hash_size);

	if (service->version == 1) {
		unsigned long msr = mfmsr();
		rc = __cvc_verify_v1((void*) service->addr,
				   (ROM_container_raw*) container,
				   &hw_params);
		assert(msr == mfmsr());
	} else {
		return OPAL_UNSUPPORTED;
	}

	if (log)
		*log = hw_params.log;

	if (rc != ROM_DONE)
		return OPAL_PARTIAL;

	return OPAL_SUCCESS;
}
