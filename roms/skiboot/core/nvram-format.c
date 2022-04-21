// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * NVRAM Format as specified in PAPR
 *
 * Copyright 2013-2019 IBM Corp.
 */

#include <skiboot.h>
#include <nvram.h>

struct chrp_nvram_hdr {
	uint8_t		sig;
	uint8_t		cksum;
	be16		len;
	char		name[12];
};

static struct chrp_nvram_hdr *skiboot_part_hdr;

#define NVRAM_SIG_FW_PRIV	0x51
#define NVRAM_SIG_SYSTEM	0x70
#define NVRAM_SIG_FREE		0x7f

#define NVRAM_NAME_COMMON	"common"
#define NVRAM_NAME_FW_PRIV	"ibm,skiboot"
#define NVRAM_NAME_FREE		"wwwwwwwwwwww"

/* 64k should be enough, famous last words... */
#define NVRAM_SIZE_COMMON	0x10000

/* 4k should be enough, famous last words... */
#define NVRAM_SIZE_FW_PRIV	0x1000

static uint8_t chrp_nv_cksum(struct chrp_nvram_hdr *hdr)
{
	struct chrp_nvram_hdr h_copy = *hdr;
	uint8_t b_data, i_sum, c_sum;
	uint8_t *p = (uint8_t *)&h_copy;
	unsigned int nbytes = sizeof(h_copy);

	h_copy.cksum = 0;
	for (c_sum = 0; nbytes; nbytes--) {
		b_data = *(p++);
		i_sum = c_sum + b_data;
		if (i_sum < c_sum)
			i_sum++;
		c_sum = i_sum;
	}
	return c_sum;
}

int nvram_format(void *nvram_image, uint32_t nvram_size)
{
	struct chrp_nvram_hdr *h;
	unsigned int offset = 0;

	prerror("NVRAM: Re-initializing (size: 0x%08x)\n", nvram_size);
	memset(nvram_image, 0, nvram_size);

	/* Create private partition */
	if (nvram_size - offset < NVRAM_SIZE_FW_PRIV)
		return -1;
	h = nvram_image + offset;
	h->sig = NVRAM_SIG_FW_PRIV;
	h->len = cpu_to_be16(NVRAM_SIZE_FW_PRIV >> 4);
	strcpy(h->name, NVRAM_NAME_FW_PRIV);
	h->cksum = chrp_nv_cksum(h);
	prlog(PR_DEBUG, "NVRAM: Created '%s' partition at 0x%08x"
	      " for size 0x%08x with cksum 0x%02x\n",
	      NVRAM_NAME_FW_PRIV, offset,
	      be16_to_cpu(h->len), h->cksum);
	offset += NVRAM_SIZE_FW_PRIV;

	/* Create common partition */
	if (nvram_size - offset < NVRAM_SIZE_COMMON)
		return -1;
	h = nvram_image + offset;
	h->sig = NVRAM_SIG_SYSTEM;
	h->len = cpu_to_be16(NVRAM_SIZE_COMMON >> 4);
	strcpy(h->name, NVRAM_NAME_COMMON);
	h->cksum = chrp_nv_cksum(h);
	prlog(PR_DEBUG, "NVRAM: Created '%s' partition at 0x%08x"
	      " for size 0x%08x with cksum 0x%02x\n",
	      NVRAM_NAME_COMMON, offset,
	      be16_to_cpu(h->len), h->cksum);
	offset += NVRAM_SIZE_COMMON;

	/* Create free space partition */
	if (nvram_size - offset < sizeof(struct chrp_nvram_hdr))
		return -1;
	h = nvram_image + offset;
	h->sig = NVRAM_SIG_FREE;
	h->len = cpu_to_be16((nvram_size - offset) >> 4);
	/* We have the full 12 bytes here */
	memcpy(h->name, NVRAM_NAME_FREE, 12);
	h->cksum = chrp_nv_cksum(h);
	prlog(PR_DEBUG, "NVRAM: Created '%s' partition at 0x%08x"
	      " for size 0x%08x with cksum 0x%02x\n",
	      NVRAM_NAME_FREE, offset, be16_to_cpu(h->len), h->cksum);
	return 0;
}

/*
 * Check that the nvram partition layout is sane and that it
 * contains our required partitions. If not, we re-format the
 * lot of it
 */
int nvram_check(void *nvram_image, const uint32_t nvram_size)
{
	unsigned int offset = 0;
	bool found_common = false;

	skiboot_part_hdr = NULL;

	while (offset + sizeof(struct chrp_nvram_hdr) < nvram_size) {
		struct chrp_nvram_hdr *h = nvram_image + offset;

		if (chrp_nv_cksum(h) != h->cksum) {
			prerror("NVRAM: Partition at offset 0x%x"
				" has bad checksum: 0x%02x vs 0x%02x\n",
				offset, h->cksum, chrp_nv_cksum(h));
			goto failed;
		}
		if (be16_to_cpu(h->len) < 1) {
			prerror("NVRAM: Partition at offset 0x%x"
				" has incorrect 0 length\n", offset);
			goto failed;
		}

		if (h->sig == NVRAM_SIG_SYSTEM &&
		    strcmp(h->name, NVRAM_NAME_COMMON) == 0)
			found_common = true;

		if (h->sig == NVRAM_SIG_FW_PRIV &&
		    strcmp(h->name, NVRAM_NAME_FW_PRIV) == 0)
			skiboot_part_hdr = h;

		offset += be16_to_cpu(h->len) << 4;
		if (offset > nvram_size) {
			prerror("NVRAM: Partition at offset 0x%x"
				" extends beyond end of nvram !\n", offset);
			goto failed;
		}
	}
	if (!found_common) {
		prlog_once(PR_ERR, "NVRAM: Common partition not found !\n");
		goto failed;
	}

	if (!skiboot_part_hdr) {
		prlog_once(PR_ERR, "NVRAM: Skiboot private partition not found !\n");
		goto failed;
	} else {
		/*
		 * The OF NVRAM format requires config strings to be NUL
		 * terminated and unused memory to be set to zero. Well behaved
		 * software should ensure this is done for us, but we should
		 * always check.
		 */
		const char *last_byte = (const char *) skiboot_part_hdr +
			be16_to_cpu(skiboot_part_hdr->len) * 16 - 1;

		if (*last_byte != 0) {
			prerror("NVRAM: Skiboot private partition is not NUL terminated");
			goto failed;
		}
	}

	prlog(PR_INFO, "NVRAM: Layout appears sane\n");
	assert(skiboot_part_hdr);
	return 0;
 failed:
	return -1;
}

static const char *find_next_key(const char *start, const char *end)
{
	/*
	 * Unused parts of the partition are set to NUL. If we hit two
	 * NULs in a row then we assume that we have hit the end of the
	 * partition.
	 */
	if (*start == 0)
		return NULL;

	while (start < end) {
		if (*start == 0)
			return start + 1;

		start++;
	}

	return NULL;
}

static void nvram_dangerous(const char *key)
{
	prlog(PR_ERR, " ___________________________________________________________\n");
	prlog(PR_ERR, "<  Dangerous NVRAM option: %s\n", key);
	prlog(PR_ERR, " -----------------------------------------------------------\n");
	prlog(PR_ERR, "                  \\                         \n");
	prlog(PR_ERR, "                   \\   WW                   \n");
	prlog(PR_ERR, "                      <^ \\___/|             \n");
	prlog(PR_ERR, "                       \\      /             \n");
	prlog(PR_ERR, "                        \\_  _/              \n");
	prlog(PR_ERR, "                          }{                 \n");
}


/*
 * nvram_query_safe/dangerous() - Searches skiboot NVRAM partition
 * for a key=value pair.
 *
 * Dangerous means it should only be used for testing as it may
 * mask issues. Safe is ok for long term use.
 *
 * Returns a pointer to a NUL terminated string that contains the value
 * associated with the given key.
 */
static const char *__nvram_query(const char *key, bool dangerous)
{
	const char *part_end, *start;
	int key_len = strlen(key);

	assert(key);

	if (!nvram_has_loaded()) {
		prlog(PR_DEBUG,
			"NVRAM: Query for '%s' must wait for NVRAM to load\n",
			key);
		if (!nvram_wait_for_load()) {
			prlog(PR_CRIT, "NVRAM: Failed to load\n");
			return NULL;
		}
	}

	/*
	 * The running OS can modify the NVRAM as it pleases so we need to be
	 * a little paranoid and check that it's ok before we try parse it.
	 *
	 * NB: nvram_validate() can update skiboot_part_hdr
	 */
	if (!nvram_validate())
		return NULL;

	assert(skiboot_part_hdr);

	part_end = (const char *) skiboot_part_hdr
		+ be16_to_cpu(skiboot_part_hdr->len) * 16 - 1;

	start = (const char *) skiboot_part_hdr
		+ sizeof(*skiboot_part_hdr);

	if (!key_len) {
		prlog(PR_WARNING, "NVRAM: search key is empty!\n");
		return NULL;
	}

	if (key_len > 32)
		prlog(PR_WARNING, "NVRAM: search key '%s' is longer than 32 chars\n", key);

	while (start) {
		int remaining = part_end - start;

		prlog(PR_TRACE, "NVRAM: '%s' (%lu)\n",
			start, strlen(start));

		if (key_len + 1 > remaining)
			return NULL;

		if (!strncmp(key, start, key_len) && start[key_len] == '=') {
			const char *value = &start[key_len + 1];

			prlog(PR_DEBUG, "NVRAM: Searched for '%s' found '%s'\n",
				key, value);

			if (dangerous)
				nvram_dangerous(start);
			return value;
		}

		start = find_next_key(start, part_end);
	}

	prlog(PR_DEBUG, "NVRAM: '%s' not found\n", key);

	return NULL;
}

const char *nvram_query_safe(const char *key)
{
	return __nvram_query(key, false);
}

const char *nvram_query_dangerous(const char *key)
{
	return __nvram_query(key, true);
}

/*
 * nvram_query_eq_safe/dangerous() - Check if the given 'key' exists
 * and is set to 'value'.
 *
 * Dangerous means it should only be used for testing as it may
 * mask issues. Safe is ok for long term use.
 *
 * Note: Its an error to check for non-existence of a key
 * by passing 'value == NULL' as a key's value can never be
 * NULL in nvram.
 */
static bool __nvram_query_eq(const char *key, const char *value, bool dangerous)
{
	const char *s = __nvram_query(key, dangerous);

	if (!s)
		return false;

	assert(value != NULL);
	return !strcmp(s, value);
}

bool nvram_query_eq_safe(const char *key, const char *value)
{
	return __nvram_query_eq(key, value, false);
}

bool nvram_query_eq_dangerous(const char *key, const char *value)
{
	return __nvram_query_eq(key, value, true);
}

