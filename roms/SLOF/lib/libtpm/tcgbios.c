/*****************************************************************************
 * Copyright (c) 2015-2020 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *     Stefan Berger, stefanb@linux.ibm.com
 *     Kevin O'Connor, kevin@koconnor.net
 *****************************************************************************/

/*
 *  Implementation of the TPM BIOS extension according to the specification
 *  described in the IBM VTPM Firmware document and the TCG Specification
 *  that can be found here under the following link:
 *  https://trustedcomputinggroup.org/resource/pc-client-work-group-specific-implementation-specification-for-conventional-bios/
 */

#include <stddef.h>
#include <stdlib.h>

#include "types.h"
#include "byteorder.h"
#include "tpm_drivers.h"
#include "string.h"
#include "tcgbios.h"
#include "tcgbios_int.h"
#include "stdio.h"
#include "sha.h"
#include "helpers.h"
#include "version.h"
#include "OF.h"
#include "libelf.h"

#undef TCGBIOS_DEBUG
//#define TCGBIOS_DEBUG
#ifdef TCGBIOS_DEBUG
#define dprintf(_x ...) do { printf("TCGBIOS: " _x); } while(0)
#else
#define dprintf(_x ...)
#endif

static struct {
	unsigned tpm_probed:1;
	unsigned tpm_found:1;
	unsigned tpm_working:1;

	/* base address of the log area */
	uint8_t *log_base;

	/* size of the logging area */
	size_t log_area_size;

	/* where to write the next log entry to */
	uint8_t *log_area_next_entry;

	/* PCR selection as received from TPM */
	uint32_t tpm20_pcr_selection_size;
	struct tpml_pcr_selection *tpm20_pcr_selection;
} tpm_state;

#define TPM2_ALG_SHA1_FLAG          (1 << 0)
#define TPM2_ALG_SHA256_FLAG        (1 << 1)
#define TPM2_ALG_SHA384_FLAG        (1 << 2)
#define TPM2_ALG_SHA512_FLAG        (1 << 3)
#define TPM2_ALG_SM3_256_FLAG       (1 << 4)
#define TPM2_ALG_SHA3_256_FLAG      (1 << 5)
#define TPM2_ALG_SHA3_384_FLAG      (1 << 6)
#define TPM2_ALG_SHA3_512_FLAG      (1 << 7)

static const uint8_t ZeroGuid[16] = { 0 };

static UEFI_GPT_DATA *uefi_gpt_data;
static size_t uefi_gpt_data_size;

/*
 * TPM 2 logs are written in little endian format.
 */
static inline uint32_t log32_to_cpu(uint32_t val)
{
	return le32_to_cpu(val);
}

static inline uint32_t cpu_to_log32(uint32_t val)
{
	return cpu_to_le32(val);
}

static inline uint16_t cpu_to_log16(uint16_t val)
{
	return cpu_to_le16(val);
}

/********************************************************
  Extensions for TCG-enabled BIOS
 *******************************************************/

static void probe_tpm(void)
{
	tpm_state.tpm_probed = true;
	tpm_state.tpm_found = spapr_is_vtpm_present();
	tpm_state.tpm_working = tpm_state.tpm_found;
}

/****************************************************************
 * Digest formatting
 ****************************************************************/

/* A 'struct tpm_log_entry' is a local data structure containing a
 * 'TCG_PCR_EVENT2_Header' followed by space for the maximum supported
 * digest. The digest is a series of TPMT_HA structs on tpm2.0.
 */
struct tpm_log_entry {
	TCG_PCR_EVENT2_Header hdr;
	uint8_t pad[sizeof(struct TPML_DIGEST_VALUES)
	   + 8 * sizeof(struct TPMT_HA)
	   + SHA1_BUFSIZE + SHA256_BUFSIZE + SHA384_BUFSIZE
	   + SHA512_BUFSIZE + SM3_256_BUFSIZE + SHA3_256_BUFSIZE
	   + SHA3_384_BUFSIZE + SHA3_512_BUFSIZE];
} __attribute__((packed));

static const struct hash_parameters {
	uint16_t hashalg;
	uint8_t  hashalg_flag;
	uint8_t  hash_buffersize;
	const char *name;
	void (*hashfunc)(const uint8_t *data, uint32_t length, uint8_t *hash);
} hash_parameters[] = {
	{
		.hashalg = TPM2_ALG_SHA1,
		.hashalg_flag = TPM2_ALG_SHA1_FLAG,
		.hash_buffersize = SHA1_BUFSIZE,
		.name = "SHA1",
		.hashfunc = sha1,
	}, {
		.hashalg = TPM2_ALG_SHA256,
		.hashalg_flag = TPM2_ALG_SHA256_FLAG,
		.hash_buffersize = SHA256_BUFSIZE,
		.name = "SHA256",
		.hashfunc = sha256,
	}, {
		.hashalg = TPM2_ALG_SHA384,
		.hashalg_flag = TPM2_ALG_SHA384_FLAG,
		.hash_buffersize = SHA384_BUFSIZE,
		.name = "SHA384",
		.hashfunc = sha384,
	}, {
		.hashalg = TPM2_ALG_SHA512,
		.hashalg_flag = TPM2_ALG_SHA512_FLAG,
		.hash_buffersize = SHA512_BUFSIZE,
		.name = "SHA512",
		.hashfunc = sha512,
	}, {
		.hashalg = TPM2_ALG_SM3_256,
		.hashalg_flag = TPM2_ALG_SM3_256_FLAG,
		.hash_buffersize = SM3_256_BUFSIZE,
		.name = "SM3-256",
	}, {
		.hashalg = TPM2_ALG_SHA3_256,
		.hashalg_flag = TPM2_ALG_SHA3_256_FLAG,
		.hash_buffersize = SHA3_256_BUFSIZE,
		.name = "SHA3-256",
	}, {
		.hashalg = TPM2_ALG_SHA3_384,
		.hashalg_flag = TPM2_ALG_SHA3_384_FLAG,
		.hash_buffersize = SHA3_384_BUFSIZE,
		.name = "SHA3-384",
	}, {
		.hashalg = TPM2_ALG_SHA3_512,
		.hashalg_flag = TPM2_ALG_SHA3_512_FLAG,
		.hash_buffersize = SHA3_512_BUFSIZE,
		.name = "SHA3-512",
	}
};

static const struct hash_parameters *tpm20_find_by_hashalg(uint16_t hashAlg)
{
	unsigned i;

	for (i = 0; i < ARRAY_SIZE(hash_parameters); i++) {
		if (hash_parameters[i].hashalg == hashAlg)
			return &hash_parameters[i];
	}
	return NULL;
}

static const struct hash_parameters *
tpm20_find_by_hashalg_flag(uint16_t hashalg_flag)
{
	unsigned i;

	for (i = 0; i < ARRAY_SIZE(hash_parameters); i++) {
		if (hash_parameters[i].hashalg_flag == hashalg_flag)
			return &hash_parameters[i];
	}
	return NULL;
}

static inline int tpm20_get_hash_buffersize(uint16_t hashAlg)
{
	const struct hash_parameters *hp = tpm20_find_by_hashalg(hashAlg);

	if (hp)
		return hp->hash_buffersize;
	return -1;
}

static inline uint8_t tpm20_hashalg_to_flag(uint16_t hashAlg)
{
	const struct hash_parameters *hp = tpm20_find_by_hashalg(hashAlg);

	if (hp)
		return hp->hashalg_flag;
	return 0;
}

static uint16_t tpm20_hashalg_flag_to_hashalg(uint8_t hashalg_flag)
{
	const struct hash_parameters *hp;

	hp = tpm20_find_by_hashalg_flag(hashalg_flag);
	if (hp)
		return hp->hashalg;
	return 0;
}

static const char * tpm20_hashalg_flag_to_name(uint8_t hashalg_flag)
{
	const struct hash_parameters *hp;

	hp = tpm20_find_by_hashalg_flag(hashalg_flag);
	if (hp)
		return hp->name;
	return NULL;
}

static void tpm2_hash_data(uint16_t hashAlg,
                           const uint8_t *data, uint32_t data_len,
                           uint8_t *hash)
{
	unsigned i;

	for (i = 0; i < ARRAY_SIZE(hash_parameters); i++) {
		if (hash_parameters[i].hashalg == hashAlg) {
			if (hash_parameters[i].hashfunc) {
				hash_parameters[i].hashfunc(data, data_len,
							    hash);
			} else {
				memset(hash, 0xff,
				       hash_parameters[i].hash_buffersize);
			}
		}
	}
}

/*
 * Build the TPM2 TPML_DIGEST_VALUES data structure from the given hash.
 * Follow the PCR bank configuration of the TPM and write the same hash
 * in either truncated or zero-padded form in the areas of all the other
 * hashes. For example, write the sha256 hash in the area of the sha384
 * hash and fill the remaining bytes with zeros. Or truncate the sha256
 * hash when writing it in the area of the sha1 hash.
 *
 * le: the log entry to build the digest in
 * hashdata: the data to hash
 * hashdata_len: the length of the hashdata
 * bigEndian: whether to build in big endian format for the TPM or log
 *            little endian for the log (TPM 2.0)
 *
 * Returns the digest size; -1 on fatal error
 */
static int tpm20_build_digest(struct tpm_log_entry *le,
                              const uint8_t *hashdata, uint32_t hashdata_len,
			      bool bigEndian)
{
	struct tpms_pcr_selection *sel;
	void *nsel, *end;
	void *dest = le->hdr.digests + sizeof(struct TPML_DIGEST_VALUES);
	uint32_t count, numAlgs;
	struct TPMT_HA *v;
	struct TPML_DIGEST_VALUES *vs;

	sel = tpm_state.tpm20_pcr_selection->selections;
	end = (void *)tpm_state.tpm20_pcr_selection +
		tpm_state.tpm20_pcr_selection_size;

	for (count = 0, numAlgs = 0;
	     count < be32_to_cpu(tpm_state.tpm20_pcr_selection->count);
	     count++) {
		int hsize;
		uint8_t sizeOfSelect = sel->sizeOfSelect;

		nsel = (void*)sel + sizeof(*sel) + sizeOfSelect;
		if (nsel > end)
			break;

		/* PCR 0-7 unused ? -- skip */
		if (!sizeOfSelect || sel->pcrSelect[0] == 0) {
			sel = nsel;
			continue;
		}

		hsize = tpm20_get_hash_buffersize(be16_to_cpu(sel->hashAlg));
		if (hsize < 0) {
			dprintf("TPM is using an unsupported hash: %d\n",
				be16_to_cpu(sel->hashAlg));
			return -1;
		}

		/* buffer size sanity check before writing */
		v = dest;
		if (dest + sizeof(*v) + hsize > (void*)le + sizeof(*le)) {
			dprintf("tpm_log_entry is too small\n");
			return -1;
		}

		if (bigEndian)
			v->hashAlg = sel->hashAlg;
		else
			v->hashAlg = cpu_to_le16(be16_to_cpu(sel->hashAlg));

		tpm2_hash_data(be16_to_cpu(sel->hashAlg), hashdata, hashdata_len,
			       v->hash);

		dest += sizeof(*v) + hsize;
		sel = nsel;

		numAlgs++;
	}

	if (sel != end) {
		dprintf("Malformed pcr selection structure fron TPM\n");
		return -1;
	}

	vs = (void*)le->hdr.digests;
	if (bigEndian)
		vs->count = cpu_to_be32(numAlgs);
	else
		vs->count = cpu_to_le32(numAlgs);

	return dest - (void*)le->hdr.digests;
}

/****************************************************************
 * TPM hardware command wrappers
 ****************************************************************/

/* Helper function for sending TPM commands that take a single
 * optional parameter (0, 1, or 2 bytes) and have no special response.
 */
static int
tpm_simple_cmd(uint8_t locty, uint32_t ordinal, int param_size, uint16_t param,
	       enum tpm_duration_type to_t)
{
	struct {
		struct tpm_req_header trqh;
		uint16_t param;
	} __attribute__((packed)) req = {
		.trqh.totlen = cpu_to_be32(sizeof(req.trqh) + param_size),
		.trqh.tag = cpu_to_be16(TPM2_ST_NO_SESSIONS),
		.trqh.ordinal = cpu_to_be32(ordinal),
	};
	uint8_t obuffer[64];
	struct tpm_rsp_header *trsh = (void *)obuffer;
	uint32_t obuffer_len = sizeof(obuffer);
	int ret;

	switch (param_size) {
	case 2:
		req.param = cpu_to_be16(param);
		break;
	case 1:
		*(uint8_t *)&req.param = param;
		break;
	}

	memset(obuffer, 0, sizeof(obuffer));
	ret = spapr_transmit(locty, &req.trqh, obuffer, &obuffer_len, to_t);
	ret = ret ? -1 : (int) be32_to_cpu(trsh->errcode);
	dprintf("Return from tpm_simple_cmd(%x, %x) = %x\n",
		ordinal, param, ret);

	return ret;
}

static int
tpm20_getcapability(uint32_t capability, uint32_t property, uint32_t count,
	            struct tpm_rsp_header *rsp, uint32_t rsize)
{
	struct tpm2_req_getcapability trg = {
		.hdr.tag = cpu_to_be16(TPM2_ST_NO_SESSIONS),
		.hdr.totlen = cpu_to_be32(sizeof(trg)),
		.hdr.ordinal = cpu_to_be32(TPM2_CC_GetCapability),
		.capability = cpu_to_be32(capability),
		.property = cpu_to_be32(property),
		.propertycount = cpu_to_be32(count),
	};
	uint32_t resp_size = rsize;
	int ret;

	ret = spapr_transmit(0, &trg.hdr, rsp, &resp_size,
			     TPM_DURATION_TYPE_SHORT);
	ret = (ret ||
	       rsize < be32_to_cpu(rsp->totlen)) ? -1
						 : (int) be32_to_cpu(rsp->errcode);

	dprintf("TCGBIOS: Return value from sending TPM2_CC_GetCapability = 0x%08x\n",
		ret);

	return ret;
}

static int
tpm20_get_pcrbanks(void)
{
	uint8_t buffer[128];
	uint32_t size;
	struct tpm2_res_getcapability *trg =
		(struct tpm2_res_getcapability *)&buffer;
	uint32_t resplen;
	int ret;

	ret = tpm20_getcapability(TPM2_CAP_PCRS, 0, 8, &trg->hdr,
				  sizeof(buffer));
	if (ret)
		return ret;

	/* defend against (broken) TPM sending packets that are too short */
	resplen = be32_to_cpu(trg->hdr.totlen);
	if (resplen <= offset_of(struct tpm2_res_getcapability, data))
		return -1;

	size = resplen - offset_of(struct tpm2_res_getcapability, data);
	/* we need a valid tpml_pcr_selection up to and including sizeOfSelect*/
	if (size < offset_of(struct tpml_pcr_selection, selections) +
		   offset_of(struct tpms_pcr_selection, pcrSelect))
		return -1;

	tpm_state.tpm20_pcr_selection = SLOF_alloc_mem(size);
	if (tpm_state.tpm20_pcr_selection) {
		memcpy(tpm_state.tpm20_pcr_selection, &trg->data, size);
		tpm_state.tpm20_pcr_selection_size = size;
	} else {
		printf("TCGBIOS: Failed to allocated %u bytes.\n", size);
		return -1;
	}

	return 0;
}

static int tpm20_extend(struct tpm_log_entry *le, int digest_len)
{
	struct tpm2_req_extend tmp_tre = {
		.hdr.tag     = cpu_to_be16(TPM2_ST_SESSIONS),
		.hdr.totlen  = cpu_to_be32(0),
		.hdr.ordinal = cpu_to_be32(TPM2_CC_PCR_Extend),
		.pcrindex    = cpu_to_be32(log32_to_cpu(le->hdr.pcrindex)),
		.authblocksize = cpu_to_be32(sizeof(tmp_tre.authblock)),
		.authblock = {
			.handle = cpu_to_be32(TPM2_RS_PW),
			.noncesize = cpu_to_be16(0),
			.contsession = TPM2_YES,
			.pwdsize = cpu_to_be16(0),
		},
	};
	uint8_t buffer[sizeof(tmp_tre) + sizeof(le->pad)];
	struct tpm2_req_extend *tre = (struct tpm2_req_extend *)buffer;
	struct tpm_rsp_header rsp;
	uint32_t resp_length = sizeof(rsp);
	int ret;

	memcpy(tre, &tmp_tre, sizeof(tmp_tre));
	memcpy(&tre->digest[0], le->hdr.digests, digest_len);

	tre->hdr.totlen = cpu_to_be32(sizeof(tmp_tre) + digest_len);

	ret = spapr_transmit(0, &tre->hdr, &rsp, &resp_length,
			     TPM_DURATION_TYPE_SHORT);
	if (ret || resp_length != sizeof(rsp) || rsp.errcode)
		return -1;

	return 0;
}

static int tpm20_stirrandom(void)
{
	struct tpm2_req_stirrandom stir = {
		.hdr.tag = cpu_to_be16(TPM2_ST_NO_SESSIONS),
		.hdr.totlen = cpu_to_be32(sizeof(stir)),
		.hdr.ordinal = cpu_to_be32(TPM2_CC_StirRandom),
		.size = cpu_to_be16(sizeof(stir.stir)),
		.stir = rand(),
	};
	struct tpm_rsp_header rsp;
	uint32_t resp_length = sizeof(rsp);
	int ret = spapr_transmit(0, &stir.hdr, &rsp, &resp_length,
				 TPM_DURATION_TYPE_SHORT);

	if (ret || resp_length != sizeof(rsp) || rsp.errcode)
		ret = -1;

	dprintf("TCGBIOS: Return value from sending TPM2_CC_StirRandom = 0x%08x\n",
		ret);

	return ret;
}

static int tpm20_getrandom(uint8_t *buf, uint16_t buf_len)
{
	struct tpm2_res_getrandom rsp;
	struct tpm2_req_getrandom trgr = {
		.hdr.tag = cpu_to_be16(TPM2_ST_NO_SESSIONS),
		.hdr.totlen = cpu_to_be32(sizeof(trgr)),
		.hdr.ordinal = cpu_to_be32(TPM2_CC_GetRandom),
		.bytesRequested = cpu_to_be16(buf_len),
	};
	uint32_t resp_length = sizeof(rsp);
	int ret;

	if (buf_len > sizeof(rsp.rnd.buffer))
		return -1;

	ret = spapr_transmit(0, &trgr.hdr, &rsp, &resp_length,
			     TPM_DURATION_TYPE_MEDIUM);
	if (ret || resp_length != sizeof(rsp) || rsp.hdr.errcode)
		ret = -1;
	else
		memcpy(buf, rsp.rnd.buffer, buf_len);

	dprintf("TCGBIOS: Return value from sending TPM2_CC_GetRandom = 0x%08x\n",
		ret);

	return ret;
}

static int tpm20_hierarchychangeauth(uint8_t auth[20])
{
	struct tpm2_req_hierarchychangeauth trhca = {
		.hdr.tag = cpu_to_be16(TPM2_ST_SESSIONS),
		.hdr.totlen = cpu_to_be32(sizeof(trhca)),
		.hdr.ordinal = cpu_to_be32(TPM2_CC_HierarchyChangeAuth),
		.authhandle = cpu_to_be32(TPM2_RH_PLATFORM),
		.authblocksize = cpu_to_be32(sizeof(trhca.authblock)),
		.authblock = {
			.handle = cpu_to_be32(TPM2_RS_PW),
			.noncesize = cpu_to_be16(0),
			.contsession = TPM2_YES,
			.pwdsize = cpu_to_be16(0),
		},
		.newAuth = {
			.size = cpu_to_be16(sizeof(trhca.newAuth.buffer)),
		},
	};
	struct tpm_rsp_header rsp;
	uint32_t resp_length = sizeof(rsp);
	int ret;

	memcpy(trhca.newAuth.buffer, auth, sizeof(trhca.newAuth.buffer));

	ret = spapr_transmit(0, &trhca.hdr, &rsp, &resp_length,
			     TPM_DURATION_TYPE_MEDIUM);
	if (ret || resp_length != sizeof(rsp) || rsp.errcode)
		ret = -1;

	dprintf("TCGBIOS: Return value from sending TPM2_CC_HierarchyChangeAuth = 0x%08x\n",
		ret);

	return ret;
}

static int tpm20_hierarchycontrol(uint32_t hierarchy, uint8_t state)
{
	struct tpm2_req_hierarchycontrol trh = {
		.hdr.tag = cpu_to_be16(TPM2_ST_SESSIONS),
		.hdr.totlen = cpu_to_be32(sizeof(trh)),
		.hdr.ordinal = cpu_to_be32(TPM2_CC_HierarchyControl),
		.authhandle = cpu_to_be32(TPM2_RH_PLATFORM),
		.authblocksize = cpu_to_be32(sizeof(trh.authblock)),
		.authblock = {
			.handle = cpu_to_be32(TPM2_RS_PW),
			.noncesize = cpu_to_be16(0),
			.contsession = TPM2_YES,
			.pwdsize = cpu_to_be16(0),
		},
		.enable = cpu_to_be32(hierarchy),
		.state = state,
	};
	struct tpm_rsp_header rsp;
	uint32_t resp_length = sizeof(rsp);
	int ret;

	ret = spapr_transmit(0, &trh.hdr, &rsp, &resp_length,
			     TPM_DURATION_TYPE_MEDIUM);
	if (ret || resp_length != sizeof(rsp) || rsp.errcode)
		ret = -1;

	dprintf("TCGBIOS: Return value from sending TPM2_CC_HierarchyControl = 0x%08x\n",
		ret);

	return ret;
}

/****************************************************************
 * Setup and Measurements
 ****************************************************************/

bool tpm_is_working(void)
{
	if (!tpm_state.tpm_probed)
		probe_tpm();

	return tpm_state.tpm_working;
}

static void tpm_set_failure(void)
{
	tpm20_hierarchycontrol(TPM2_RH_ENDORSEMENT, TPM2_NO);
	tpm20_hierarchycontrol(TPM2_RH_OWNER, TPM2_NO);
	tpm20_hierarchycontrol(TPM2_RH_PLATFORM, TPM2_NO);

	tpm_state.tpm_working = false;
}

/*
 * Extend the OFDT log with the given entry by copying the
 * entry data into the log.
 *
 * @pcpes: Pointer to the structure to be copied into the log
 * @event: The event to be appended to 'pcpes'
 * @event_length: The length of the event
 *
 * Returns 0 on success, an error code otherwise.
 */
static uint32_t tpm_log_event_long(TCG_PCR_EVENT2_Header *entry,
				   int digest_len,
				   const void *event, uint32_t event_length)
{
	size_t size, logsize;
	void *dest;
	TCG_PCR_EVENT2_Trailer *t;

	dprintf("log base address = %p, next entry = %p\n",
		tpm_state.log_base, tpm_state.log_area_next_entry);

	if (tpm_state.log_area_next_entry == NULL)
		return TCGBIOS_LOGOVERFLOW;

	size = sizeof(*entry) + digest_len +
	       sizeof(TCG_PCR_EVENT2_Trailer) + event_length;
	logsize = (tpm_state.log_area_next_entry + size -
	           tpm_state.log_base);
	if (logsize > tpm_state.log_area_size) {
		dprintf("TCGBIOS: LOG OVERFLOW: size = %zu\n", size);
		return TCGBIOS_LOGOVERFLOW;
	}

	dest = tpm_state.log_area_next_entry;
	memcpy(dest, entry, sizeof(*entry) + digest_len);

	t = dest + sizeof(*entry) + digest_len;
	t->eventdatasize = cpu_to_log32(event_length);
	if (event_length)
		memcpy(t->event, event, event_length);

	tpm_state.log_area_next_entry += size;

	return 0;
}

/* Add an entry at the start of the log describing digest formats
 */
static int tpm20_write_EfiSpecIdEventStruct(void)
{
	struct {
		struct TCG_EfiSpecIdEventStruct hdr;
		uint32_t pad[sizeof(struct tpm_log_entry) +
		             sizeof(uint8_t)];
	} event = {
		.hdr.signature = "Spec ID Event03",
		.hdr.platformClass = TPM_TCPA_ACPI_CLASS_CLIENT,
		.hdr.specVersionMinor = 0,
		.hdr.specVersionMajor = 2,
		.hdr.specErrata = 2,
		.hdr.uintnSize = 2,
	};
	struct tpms_pcr_selection *sel;
	void *nsel, *end;
	unsigned event_size;
	uint8_t *vendorInfoSize;
	struct tpm_log_entry le = {
		.hdr.eventtype = cpu_to_log32(EV_NO_ACTION),
	};
	uint32_t count, numAlgs;

	sel = tpm_state.tpm20_pcr_selection->selections;
	end = (void*)tpm_state.tpm20_pcr_selection +
	      tpm_state.tpm20_pcr_selection_size;

	for (count = 0, numAlgs = 0;
	     count < be32_to_cpu(tpm_state.tpm20_pcr_selection->count);
	     count++) {
		int hsize;
		uint8_t sizeOfSelect = sel->sizeOfSelect;

		nsel = (void*)sel + sizeof(*sel) + sizeOfSelect;
		if (nsel > end)
			break;

		/* PCR 0-7 unused ? -- skip */
		if (!sizeOfSelect || sel->pcrSelect[0] == 0) {
			sel = nsel;
			continue;
		}

		hsize = tpm20_get_hash_buffersize(be16_to_cpu(sel->hashAlg));
		if (hsize < 0) {
			dprintf("TPM is using an unsupported hash: %d\n",
				be16_to_cpu(sel->hashAlg));
			return -1;
		}

		event_size = offset_of(struct TCG_EfiSpecIdEventStruct,
				       digestSizes[count+1]);
		if (event_size > sizeof(event) - sizeof(uint8_t)) {
			dprintf("EfiSpecIdEventStruct pad too small\n");
			return -1;
		}

		event.hdr.digestSizes[numAlgs].algorithmId =
			cpu_to_log16(be16_to_cpu(sel->hashAlg));
		event.hdr.digestSizes[numAlgs].digestSize = cpu_to_log16(hsize);
		numAlgs++;

		sel = nsel;
	}

	if (sel != end) {
		dprintf("Malformed pcr selection structure fron TPM\n");
		return -1;
	}

	event.hdr.numberOfAlgorithms = cpu_to_log32(numAlgs);
	event_size = offset_of(struct TCG_EfiSpecIdEventStruct,
			       digestSizes[numAlgs]);
	vendorInfoSize = (void*)&event + event_size;
	*vendorInfoSize = 0;
	event_size += sizeof(*vendorInfoSize);

	return tpm_log_event_long(&le.hdr, SHA1_BUFSIZE, &event, event_size);
}

static int tpm20_startup(void)
{
	int ret;

	ret = tpm_simple_cmd(0, TPM2_CC_Startup,
			     2, TPM2_SU_CLEAR, TPM_DURATION_TYPE_SHORT);
	dprintf("TCGBIOS: Return value from sending TPM2_CC_Startup(SU_CLEAR) = 0x%08x\n",
		ret);

	if (ret)
		goto err_exit;

	ret = tpm_simple_cmd(0, TPM2_CC_SelfTest,
			     1, TPM2_YES, TPM_DURATION_TYPE_LONG);

	dprintf("TCGBIOS: Return value from sending TPM2_CC_SELF_TEST = 0x%08x\n",
		ret);

	if (ret)
		goto err_exit;

	ret = tpm20_get_pcrbanks();
	if (ret)
		goto err_exit;

	/* the log parameters will be passed from Forth layer */

	return 0;

err_exit:
	dprintf("TCGBIOS: TPM malfunctioning (line %d).\n", __LINE__);

	tpm_set_failure();
	return -1;
}

uint32_t tpm_start(void)
{
	probe_tpm();

	if (!tpm_is_working()) {
		dprintf("%s: Machine does not have a working TPM\n",
			__func__);
		return TCGBIOS_FATAL_COM_ERROR;
	}

	return tpm20_startup();
}

void tpm_finalize(void)
{
	spapr_vtpm_finalize();
}

static void tpm20_prepboot(void)
{
	uint8_t auth[20];
	int ret;

	ret = tpm20_stirrandom();
	if (ret)
		 goto err_exit;

	ret = tpm20_getrandom(&auth[0], sizeof(auth));
	if (ret)
		goto err_exit;

	ret = tpm20_hierarchychangeauth(auth);
	if (ret)
		goto err_exit;

	return;

err_exit:
	dprintf("TCGBIOS: TPM malfunctioning (line %d).\n", __LINE__);

	tpm_set_failure();
}

/*
 * Prepare TPM for boot; this function has to be called before
 * the firmware transitions to the boot loader.
 */
uint32_t tpm_leave_firmware(void)
{
	tpm20_prepboot();

	return 0;
}

/****************************************************************
 * Forth interface
 ****************************************************************/

void tpm_set_log_parameters(void *addr, size_t size)
{
	int ret;

	dprintf("Log is at 0x%llx; size is %zu bytes\n",
		(uint64_t)addr, size);
	tpm_state.log_base = addr;
	tpm_state.log_area_next_entry = addr;
	tpm_state.log_area_size = size;

	ret = tpm20_write_EfiSpecIdEventStruct();
	if (ret)
		tpm_set_failure();
}

uint32_t tpm_get_logsize(void)
{
	uint32_t logsize = tpm_state.log_area_next_entry - tpm_state.log_base;

	dprintf("log size: %u\n", logsize);

	return logsize;
}

/*
 * Add a measurement to the log;
 *
 * Input parameters:
 *  @pcrindex : PCR to extend
 *  @event_type : type of event
 *  @info : pointer to info (i.e., string) to be added to the log as-is
 *  @info_length: length of the info
 *  @hashdata : pointer to data to be hashed
 *  @hashdata_length: length of the data
 *
 */
static uint32_t tpm_add_measurement_to_log(uint32_t pcrindex,
					   uint32_t eventtype,
					   const char *info,
					   uint32_t infolen,
					   const uint8_t *hashdata,
					   uint32_t hashdatalen)
{
	struct tpm_log_entry le = {
		.hdr.pcrindex = cpu_to_log32(pcrindex),
		.hdr.eventtype = cpu_to_log32(eventtype),
	};
	int digest_len;
	int ret;

	digest_len = tpm20_build_digest(&le, hashdata, hashdatalen, true);
	if (digest_len < 0)
		return TCGBIOS_GENERAL_ERROR;
	ret = tpm20_extend(&le, digest_len);
	if (ret) {
		tpm_set_failure();
		return TCGBIOS_COMMAND_ERROR;
	}
	tpm20_build_digest(&le, hashdata, hashdatalen, false);
	return tpm_log_event_long(&le.hdr, digest_len, info, infolen);
}

/*
 * Measure the contents of a buffer into the given PCR and log it with the
 * given eventtype. If is_elf is true, try to determine the size of the
 * ELF file in the buffer and use its size rather than the much larger data
 * buffer it is held in. In case of failure to detect the ELF file size,
 * log an error.
 *
 * Input parameters:
 *  @pcrindex : PCR to extend
 *  @eventtype : type of event
 *  @data: the buffer to measure
 *  @datalen: length of the buffer
 *  @desc: The description to log
 *  @desclen: The length of the description
 *  @is_elf: Whether data buffer holds an ELF file and we should determine
 *           the original file size.
 *
 *  Returns 0 on success, an error code otherwise.
 */
uint32_t tpm_hash_log_extend_event_buffer(uint32_t pcrindex, uint32_t eventtype,
					  const void *data, uint64_t datalen,
					  const char *desc, uint32_t desclen,
					  bool is_elf)
{
	long len;
	char buf[256];

	if (is_elf) {
		len = elf_get_file_size(data, datalen);
		if (len > 0) {
			datalen = len;
		} else {
			snprintf(buf, sizeof(buf), "BAD ELF FILE: %s", desc);
			return tpm_add_measurement_to_log(pcrindex, eventtype,
					  buf, strlen(buf),
					  (uint8_t *)buf, strlen(buf));
		}
	}
	return tpm_add_measurement_to_log(pcrindex, eventtype,
					  desc, desclen,
					  data, datalen);
}

uint32_t tpm_2hash_ext_log(uint32_t pcrindex,
			   uint32_t eventtype,
			   const char *info, uint32_t infolen,
			   const void *data, uint64_t datalen)
{
	uint32_t ret;

	ret = tpm_add_measurement_to_log(pcrindex, eventtype,
					 info, infolen,
					 data, datalen);
	if (!ret)
		return (uint32_t)-1; // TRUE
	return 0; // FALSE
}

/*
 * Add an EV_ACTION measurement to the list of measurements
 */
static uint32_t tpm_add_action(uint32_t pcrIndex, const char *string)
{
	uint32_t len = strlen(string);

	return tpm_add_measurement_to_log(pcrIndex, EV_ACTION,
					  string, len, (uint8_t *)string, len);
}

/*
 * Add event separators for a range of PCRs
 */
uint32_t tpm_add_event_separators(uint32_t start_pcr, uint32_t end_pcr)
{
	static const uint8_t evt_separator[] = {0xff,0xff,0xff,0xff};
	uint32_t pcrIndex;
	int rc;

	if (!tpm_is_working())
		return TCGBIOS_GENERAL_ERROR;

	if (start_pcr >= 24 || start_pcr > end_pcr)
		return TCGBIOS_INVALID_INPUT_PARA;

	/* event separators need to be extended and logged for PCRs 0-7 */
	for (pcrIndex = start_pcr; pcrIndex <= end_pcr; pcrIndex++) {
		rc = tpm_add_measurement_to_log(pcrIndex, EV_SEPARATOR,
						(const char *)evt_separator,
						sizeof(evt_separator),
						evt_separator,
						sizeof(evt_separator));
		if (rc)
			return rc;
	}

	return 0;
}

uint32_t tpm_measure_bcv_mbr(uint32_t bootdrv, const uint8_t *addr,
			     uint32_t length)
{
	uint32_t rc;
	const char *string;

	if (!tpm_is_working())
		return TCGBIOS_GENERAL_ERROR;

	if (length < 0x200)
		return TCGBIOS_INVALID_INPUT_PARA;

	string = "Booting BCV device 00h (Floppy)";
	if (bootdrv == BCV_DEVICE_HDD)
		string = "Booting BCV device 80h (HDD)";

	rc = tpm_add_action(4, string);
	if (rc)
		return rc;

	/*
	 * equivalent to: dd if=/dev/hda ibs=1 count=440 | sha256sum
	 */
	string = "MBR";
	rc = tpm_add_measurement_to_log(4, EV_IPL,
					string, strlen(string),
					addr, 0x1b8);
	if (rc)
		return rc;

	/*
	 * equivalent to: dd if=/dev/hda ibs=1 count=72 skip=440 | sha256sum
	 */
	string = "MBR PARTITION TABLE";
	return tpm_add_measurement_to_log(5, EV_IPL_PARTITION_DATA,
					  string, strlen(string),
					  addr + 0x1b8, 0x48);
}

/*
 * This is the first function to call when measuring a GPT table.
 * It allocates memory for the data to log which are 'measured' later on.
 */
void tpm_gpt_set_lba1(const uint8_t *addr, uint32_t length)
{
	if (!tpm_is_working())
		return;

	SLOF_free_mem(uefi_gpt_data, uefi_gpt_data_size);

	uefi_gpt_data_size = sizeof(UEFI_GPT_DATA);
	uefi_gpt_data = SLOF_alloc_mem(uefi_gpt_data_size);
	if (!uefi_gpt_data)
		return;

	memcpy(&uefi_gpt_data->EfiPartitionHeader,
	       addr, MIN(sizeof(uefi_gpt_data->EfiPartitionHeader), length));
	uefi_gpt_data->NumberOfPartitions = 0;
}

/*
 * This function adds a GPT entry to the data to measure. It must
 * be called after tpm_gpt_set_lba1.
 */
void tpm_gpt_add_entry(const uint8_t *addr, uint32_t length)
{
	size_t sz;
	UEFI_PARTITION_ENTRY *upe = (void *)addr;
	void *tmp;

	if (!tpm_is_working() ||
	    !uefi_gpt_data ||
	    length < sizeof(*upe) ||
	    !memcmp(upe->partTypeGuid, ZeroGuid, sizeof(ZeroGuid)))
		return;

	sz = offset_of(UEFI_GPT_DATA, Partitions) +
	       (uefi_gpt_data->NumberOfPartitions + 1)
	       * sizeof(UEFI_PARTITION_ENTRY);
	if (sz > uefi_gpt_data_size) {
		tmp = SLOF_alloc_mem(sz);
		if (!tmp)
			goto err_no_mem;

		memcpy(tmp, uefi_gpt_data, uefi_gpt_data_size);
		SLOF_free_mem(uefi_gpt_data, uefi_gpt_data_size);
		uefi_gpt_data = tmp;
		uefi_gpt_data_size = sz;
	}

	memcpy(&uefi_gpt_data->Partitions[uefi_gpt_data->NumberOfPartitions],
	       addr,
	       sizeof(UEFI_PARTITION_ENTRY));
	uefi_gpt_data->NumberOfPartitions++;

	return;

err_no_mem:
	SLOF_free_mem(uefi_gpt_data, uefi_gpt_data_size);
	uefi_gpt_data_size = 0;
	uefi_gpt_data = NULL;
}

/*
 * tpm_measure_gpt finally measures the GPT table and adds an entry
 * to the log.
 */
uint32_t tpm_measure_gpt(void)
{
	size_t sz;

	if (!tpm_is_working())
		return TCGBIOS_GENERAL_ERROR;

	sz = offset_of(UEFI_GPT_DATA, Partitions) +
	     uefi_gpt_data->NumberOfPartitions * sizeof(UEFI_PARTITION_ENTRY);

	return tpm_add_measurement_to_log(5, EV_EFI_GPT_EVENT,
					  (const char *)uefi_gpt_data, sz,
					  (const uint8_t *)uefi_gpt_data, sz);
}

uint32_t tpm_measure_scrtm(void)
{
	uint32_t rc, i;
	char *slof_text_start = (char *)&_slof_text;
	uint32_t slof_text_length = (long)&_slof_text_end - (long)&_slof_text;
	const char *scrtm = "S-CRTM Contents";
#define _TT(a, x) a##x
#define _T(a, x) _TT(a, x)
	unsigned short ucs2_version[] = _T(L, RELEASE);

	dprintf("Measure S-CRTM Version: addr = %p, length = %d\n",
		ucs2_version, ucs2_length);

	for (i = 0; i < ARRAY_SIZE(ucs2_version); ++i)
	    ucs2_version[i] = cpu_to_le16(ucs2_version[i]);

	rc = tpm_add_measurement_to_log(0, EV_S_CRTM_VERSION,
					(char *)ucs2_version,
					sizeof(ucs2_version),
					(uint8_t *)ucs2_version,
					sizeof(ucs2_version));
	if (rc)
		return rc;

	dprintf("Measure S-CRTM Content (text): start = %p, length = %d\n",
		slof_text_start, slof_text_length);

	rc = tpm_add_measurement_to_log(0, EV_S_CRTM_CONTENTS,
					scrtm, strlen(scrtm),
					(uint8_t *)slof_text_start,
					slof_text_length);

	return rc;
}

/*
 * tpm_driver_get_failure_reason: Function for interfacing with the firmware
 *                                API
 */
uint32_t tpm_driver_get_failure_reason(void)
{
	/* do not check for a working TPM here */
	if (!tpm_state.tpm_found)
		return VTPM_DRV_STATE_INVALID;

	return spapr_vtpm_get_error();
}

/*
 * tpm_driver_set_failure_reason: Function for interfacing with the firmware
 *                                API
 */
void tpm_driver_set_failure_reason(uint32_t errcode)
{
	if (!tpm_state.tpm_found)
		return;

	spapr_vtpm_set_error(errcode);
}

/****************************************************************
 * TPM Configuration Menu
 ****************************************************************/

static int
tpm20_get_suppt_pcrbanks(uint8_t *suppt_pcrbanks, uint8_t *active_pcrbanks)
{
	struct tpms_pcr_selection *sel;
	void *end;

	*suppt_pcrbanks = 0;
	*active_pcrbanks = 0;

	sel = tpm_state.tpm20_pcr_selection->selections;
	end = (void*)tpm_state.tpm20_pcr_selection +
		tpm_state.tpm20_pcr_selection_size;

	while (1) {
		uint16_t hashalg;
		uint8_t hashalg_flag;
		unsigned i;
		uint8_t sizeOfSelect = sel->sizeOfSelect;
		void *nsel = (void*)sel + sizeof(*sel) + sizeOfSelect;

		if (nsel > end)
			return 0;

		hashalg = be16_to_cpu(sel->hashAlg);
		hashalg_flag = tpm20_hashalg_to_flag(hashalg);

		*suppt_pcrbanks |= hashalg_flag;

		for (i = 0; i < sizeOfSelect; i++) {
			if (sel->pcrSelect[i]) {
				*active_pcrbanks |= hashalg_flag;
				break;
			}
		}

		sel = nsel;
	}
}

static int
tpm20_set_pcrbanks(uint32_t active_banks)
{
	struct tpm2_req_pcr_allocate trpa = {
		.hdr.tag = cpu_to_be16(TPM2_ST_SESSIONS),
		.hdr.ordinal = cpu_to_be32(TPM2_CC_PCR_Allocate),
		.authhandle = cpu_to_be32(TPM2_RH_PLATFORM),
		.authblocksize = cpu_to_be32(sizeof(trpa.authblock)),
		.authblock = {
			.handle = cpu_to_be32(TPM2_RS_PW),
			.noncesize = cpu_to_be16(0),
			.contsession = TPM2_YES,
			.pwdsize = cpu_to_be16(0),
		},
	};
	struct tpms_pcr_selection3 {
		uint16_t hashAlg;
		uint8_t sizeOfSelect;
		uint8_t pcrSelect[3];
	} tps[ARRAY_SIZE(trpa.tpms_pcr_selections)];
	int i = 0;
	uint8_t hashalg_flag = TPM2_ALG_SHA1_FLAG;
	uint8_t dontcare, suppt_banks;
	struct tpm_rsp_header rsp;
	uint32_t resp_length = sizeof(rsp);
	uint16_t hashalg;
	int ret;

	tpm20_get_suppt_pcrbanks(&suppt_banks, &dontcare);

	while (hashalg_flag) {
		if ((hashalg_flag & suppt_banks)) {
			hashalg = tpm20_hashalg_flag_to_hashalg(hashalg_flag);

			if (hashalg) {
				uint8_t mask = 0;

				tps[i].hashAlg = cpu_to_be16(hashalg);
				tps[i].sizeOfSelect = 3;

				if (active_banks & hashalg_flag)
					mask = 0xff;

				tps[i].pcrSelect[0] = mask;
				tps[i].pcrSelect[1] = mask;
				tps[i].pcrSelect[2] = mask;
				i++;
			}
		}
		hashalg_flag <<= 1;
	}

	trpa.count = cpu_to_be32(i);
	memcpy(trpa.tpms_pcr_selections, tps, i * sizeof(tps[0]));
	trpa.hdr.totlen = cpu_to_be32(offset_of(struct tpm2_req_pcr_allocate,
						tpms_pcr_selections) +
				      i * sizeof(tps[0]));

	ret = spapr_transmit(0, &trpa.hdr, &rsp, &resp_length,
			     TPM_DURATION_TYPE_SHORT);
	ret = ret ? -1 : (int) be32_to_cpu(rsp.errcode);

	return ret;
}

static int tpm20_activate_pcrbanks(uint32_t active_banks)
{
	int ret;

	ret = tpm20_set_pcrbanks(active_banks);
	if (!ret)
		ret = tpm_simple_cmd(0, TPM2_CC_Shutdown,
				     2, TPM2_SU_CLEAR, TPM_DURATION_TYPE_SHORT);
	if (!ret)
		SLOF_reset();
	return ret;
}

static int
tpm20_clearcontrol(uint8_t disable)
{
	struct tpm2_req_clearcontrol trc = {
		.hdr.tag     = cpu_to_be16(TPM2_ST_SESSIONS),
		.hdr.totlen  = cpu_to_be32(sizeof(trc)),
		.hdr.ordinal = cpu_to_be32(TPM2_CC_ClearControl),
		.authhandle = cpu_to_be32(TPM2_RH_PLATFORM),
		.authblocksize = cpu_to_be32(sizeof(trc.authblock)),
		.authblock = {
			.handle = cpu_to_be32(TPM2_RS_PW),
			.noncesize = cpu_to_be16(0),
			.contsession = TPM2_YES,
			.pwdsize = cpu_to_be16(0),
		},
		.disable = disable,
	};
	struct tpm_rsp_header rsp;
	uint32_t resp_length = sizeof(rsp);
	int ret;

	ret = spapr_transmit(0, &trc.hdr, &rsp, &resp_length,
			     TPM_DURATION_TYPE_SHORT);
	if (ret || resp_length != sizeof(rsp) || rsp.errcode)
		ret = -1;

	dprintf("TCGBIOS: Return value from sending TPM2_CC_ClearControl = 0x%08x\n",
		ret);

	return ret;
}

static int
tpm20_clear(void)
{
	struct tpm2_req_clear trq = {
		.hdr.tag	 = cpu_to_be16(TPM2_ST_SESSIONS),
		.hdr.totlen  = cpu_to_be32(sizeof(trq)),
		.hdr.ordinal = cpu_to_be32(TPM2_CC_Clear),
		.authhandle = cpu_to_be32(TPM2_RH_PLATFORM),
		.authblocksize = cpu_to_be32(sizeof(trq.authblock)),
		.authblock = {
			.handle = cpu_to_be32(TPM2_RS_PW),
			.noncesize = cpu_to_be16(0),
			.contsession = TPM2_YES,
			.pwdsize = cpu_to_be16(0),
		},
	};
	struct tpm_rsp_header rsp;
	uint32_t resp_length = sizeof(rsp);
	int ret;

	ret = spapr_transmit(0, &trq.hdr, &rsp, &resp_length,
			     TPM_DURATION_TYPE_MEDIUM);
	if (ret || resp_length != sizeof(rsp) || rsp.errcode)
		ret = -1;

	dprintf("TCGBIOS: Return value from sending TPM2_CC_Clear = 0x%08x\n",
		ret);

	return ret;
}

static int tpm20_menu_change_active_pcrbanks(void)
{
	uint8_t active_banks, suppt_banks, activate_banks;

	tpm20_get_suppt_pcrbanks(&suppt_banks, &active_banks);

	activate_banks = active_banks;

	while (1) {
		uint8_t hashalg_flag = TPM2_ALG_SHA1_FLAG;
		uint8_t i = 0;
		uint8_t flagnum;
		int show = 0;

		printf("\nToggle active PCR banks by pressing number key\n\n");

		while (hashalg_flag) {
			uint8_t flag = hashalg_flag & suppt_banks;
			const char *hashname = tpm20_hashalg_flag_to_name(flag);

			i++;
			if (hashname) {
				printf("  %d: %s", i, hashname);
				if (activate_banks & hashalg_flag)
					printf(" (enabled)");
				printf("\n");
			}

			hashalg_flag <<= 1;
		}
		printf("\n"
		       "ESC: return to previous menu without changes\n");
		if (activate_banks)
			printf("a  : activate selection\n");

		while (!show) {
			int key_code = SLOF_get_keystroke();

			switch (key_code) {
			case ~0:
				continue;
			case 27: /* ESC */
				printf("\n");
				return -1;
			case '1' ... '5': /* keys 1 .. 5 */
				flagnum = key_code - '0';
				if (flagnum > i)
					continue;
				if (suppt_banks & (1 << (flagnum - 1))) {
					activate_banks ^= 1 << (flagnum - 1);
					show = 1;
				}
				break;
			case 'a': /* a */
				if (activate_banks)
					tpm20_activate_pcrbanks(activate_banks);
			}
		}
	}
}

void tpm20_menu(void)
{
	int key_code;
	int waitkey;
	int ret;

	for (;;) {
		printf("1. Clear TPM\n");
		printf("2. Change active PCR banks\n");

		printf("\nIf not change is desired or if this menu was reached by "
		       "mistake, press ESC to\ncontinue the boot.\n");

		waitkey = 1;

		while (waitkey) {
			key_code = SLOF_get_keystroke();
			switch (key_code) {
			case 27:
				// ESC
				return;
			case '1':
				ret = tpm20_clearcontrol(false);
				if (!ret)
					ret = tpm20_clear();
				if (ret)
					printf("An error occurred clearing "
					       "the TPM: 0x%x\n",
					       ret);
				break;
			case '2':
				tpm20_menu_change_active_pcrbanks();
				waitkey = 0;
				continue;
			default:
				continue;
			}

			waitkey = 0;
		}
	}
}
