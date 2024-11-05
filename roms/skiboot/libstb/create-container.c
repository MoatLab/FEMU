// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2017-2018 IBM Corp. */

#include <config.h>

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <types.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sysexits.h>
#include <unistd.h>

#include "ccan/endian/endian.h"
#include "ccan/short_types/short_types.h"
#include "container-utils.h"
#include "container.h"

#define CONTAINER_HDR 0
#define PREFIX_HDR 1
#define SOFTWARE_HDR 2

char *progname;

bool verbose, debug;
int wrap = 100;

void usage(int status);

void getPublicKeyRaw(ecc_key_t *pubkeyraw, char *filename)
{
	EVP_PKEY* pkey;
	unsigned char pubkeyData[1 + 2 * EC_COORDBYTES];

	FILE *fp = fopen(filename, "r");
	if (!fp)
		die(EX_NOINPUT, "Cannot open key file: %s: %s", filename, strerror(errno));

	if ((pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL))) {
		debug_msg("File \"%s\" is a PEM private key", filename);
		fclose(fp);
	} else {
		fclose(fp);
		fp = fopen(filename, "r");
		if ((pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL))) {
			debug_msg("File \"%s\" is a PEM public key", filename);
		}
		fclose(fp);
	}

	if (pkey) {
		EC_KEY *key;
		const EC_GROUP *ecgrp;
		const EC_POINT *ecpoint;
		BIGNUM *pubkeyBN;

		key = EVP_PKEY_get1_EC_KEY(pkey);
		if (!key)
			die(EX_SOFTWARE, "%s", "Cannot EVP_PKEY_get1_EC_KEY");

		ecgrp = EC_KEY_get0_group(key);
		if (!ecgrp)
			die(EX_SOFTWARE, "%s", "Cannot EC_KEY_get0_group");

		ecpoint = EC_KEY_get0_public_key(key);
		if (!ecpoint)
			die(EX_SOFTWARE, "%s", "Cannot EC_KEY_get0_public_key");

		pubkeyBN = EC_POINT_point2bn(ecgrp, ecpoint, POINT_CONVERSION_UNCOMPRESSED,
				NULL, NULL);
		BN_bn2bin(pubkeyBN, pubkeyData);

		BN_free(pubkeyBN);
		EC_KEY_free(key);
		EVP_PKEY_free(pkey);
	}
	else {
		/* The file is not a public or private key in PEM format. So we check if
		 * it is a p521 pubkey in RAW format, in which case it will be 133 bytes
		 * with a leading byte of 0x04, indicating an uncompressed key. */
		int fdin, r;
		struct stat s;
		void *infile = MAP_FAILED;

		fdin = open(filename, O_RDONLY);
		if (fdin <= 0)
			die(EX_NOINPUT, "Cannot open key file: %s: %s", filename, strerror(errno));

		r = fstat(fdin, &s);
		if (r != 0)
			die(EX_NOINPUT, "Cannot stat key file: %s", filename);

		if (s.st_size == 1 + 2 * EC_COORDBYTES)
			infile = mmap(NULL, s.st_size, PROT_READ, MAP_PRIVATE, fdin, 0);

		close(fdin);

		if ((infile == MAP_FAILED) || (*(unsigned char*) infile != 0x04)) {
			die(EX_DATAERR,
					"File \"%s\" is not in expected format (private or public key in PEM, or public key RAW)",
					filename);
		}
		else
			debug_msg("File \"%s\" is a RAW public key", filename);

		memcpy(pubkeyData, infile, sizeof(ecc_key_t) + 1);
		munmap(infile, s.st_size);
	}

	// Remove the leading byte
	memcpy(*pubkeyraw, &pubkeyData[1], sizeof(ecc_key_t));

	return;
}

void getSigRaw(ecc_signature_t *sigraw, char *filename)
{
	int fdin;
	struct stat s;
	void *infile;
	int r;
	int rlen, roff, slen, soff;
	const BIGNUM *sr, *ss;
	unsigned char outbuf[2 * EC_COORDBYTES];
	ECDSA_SIG* signature;

	fdin = open(filename, O_RDONLY);
	if (fdin <= 0)
		die(EX_NOINPUT, "Cannot open sig file: %s: %s", filename, strerror(errno));

	r = fstat(fdin, &s);
	if (r != 0)
		die(EX_NOINPUT, "Cannot stat sig file: %s", filename);

	infile = mmap(NULL, s.st_size, PROT_READ, MAP_PRIVATE, fdin, 0);
	if (infile == MAP_FAILED)
		die(EX_OSERR, "%s", "Cannot mmap file");

	close(fdin);

	if (s.st_size == 2 * EC_COORDBYTES) {
		/* The file is a p521 signature in RAW format. */
		debug_msg("File \"%s\" is a RAW signature", filename);
		memcpy(sigraw, infile, sizeof(ecc_signature_t));
	}
	else {
		/* Assume the file is a p521 signature in DER format.
		 * Convert the DER to a signature object, then extract the RAW. */
		debug_msg("File \"%s\" is a DER signature", filename);

		signature = d2i_ECDSA_SIG(NULL,
					  (const unsigned char **) &infile, 7 + 2 * EC_COORDBYTES);

		memset(&outbuf, 0, sizeof(outbuf));

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		ECDSA_SIG_get0(signature, &sr, &ss);
#else
		sr = signature->r;
		ss = signature->s;
#endif
		rlen = BN_num_bytes(sr);
		roff = 66 - rlen;
		BN_bn2bin(sr, &outbuf[roff]);

		slen = BN_num_bytes(ss);
		soff = 66 + (66 - slen);
		BN_bn2bin(ss, &outbuf[soff]);

		memcpy(sigraw, outbuf, sizeof(ecc_signature_t));

		ECDSA_SIG_free(signature);
	}
	munmap(infile, s.st_size);
	return;
}

void writeHdr(void *hdr, const char *outFile, int hdr_type)
{
	int fdout;
	int r, hdr_sz;
	unsigned char md[SHA512_DIGEST_LENGTH];

	switch (hdr_type) {
	case CONTAINER_HDR:
		hdr_sz = SECURE_BOOT_HEADERS_SIZE;
		break;
	case PREFIX_HDR:
		hdr_sz = sizeof(ROM_prefix_header_raw);
		SHA512(hdr, hdr_sz, md);
		verbose_print((char *) "PR header hash  = ", md, sizeof(md));
		break;
	case SOFTWARE_HDR:
		hdr_sz = sizeof(ROM_sw_header_raw);
		SHA512(hdr, hdr_sz, md);
		verbose_print((char *) "SW header hash  = ", md, sizeof(md));
		break;
	default:
		die(EX_SOFTWARE, "Unknown header type (%d)", hdr_type);
	}

	fdout = open(outFile, O_WRONLY | O_CREAT | O_TRUNC,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fdout <= 0)
		die(EX_CANTCREAT, "Cannot create output file: %s", outFile);

	r = write(fdout, (const void *) hdr, hdr_sz);
	close(fdout);

	if (r < hdr_sz)
		die(EX_SOFTWARE, "Error writing header file (r = %d)", r);

	debug_msg("Wrote %d bytes to %s", r, outFile);

	return;
}

__attribute__((__noreturn__)) void usage (int status)
{
	if (status != 0) {
		fprintf(stderr, "Try '%s --help' for more information.\n", progname);
	}
	else {
		printf("Usage: %s [options]\n", progname);
		printf(
			"\n"
			"Options:\n"
			" -h, --help              display this message and exit\n"
			" -v, --verbose           show verbose output\n"
			" -d, --debug             show additional debug output\n"
			" -w, --wrap              column to wrap long output in verbose mode\n"
			" -a, --hw_key_a          file containing HW key A key in PEM or RAW format\n"
			" -b, --hw_key_b          file containing HW key B key in PEM or RAW format\n"
			" -c, --hw_key_c          file containing HW key C key in PEM or RAW format\n"
			" -p, --sw_key_p          file containing SW key P key in PEM or RAW format\n"
			" -q, --sw_key_q          file containing SW key Q key in PEM or RAW format\n"
			" -r, --sw_key_r          file containing SW key R key in PEM or RAW format\n"
			" -A, --hw_sig_a          file containing HW key A signature in DER format\n"
			" -B, --hw_sig_b          file containing HW key B signature in DER format\n"
			" -C, --hw_sig_c          file containing HW key C signature in DER format\n"
			" -P, --sw_sig_p          file containing SW key P signature in DER format\n"
			" -Q, --sw_sig_q          file containing SW key Q signature in DER format\n"
			" -R, --sw_sig_r          file containing SW key R signature in DER format\n"
			" -l, --payload           file containing the payload to be signed\n"
			" -I, --imagefile         file to write containerized image (output)\n"
			" -o, --hw-cs-offset      code start offset for prefix header in hex\n"
			" -O, --sw-cs-offset      code start offset for software header in hex\n"
			" -f, --hw-flags          prefix header flags in hex\n"
			" -F, --sw-flags          software header flags in hex\n"
			" -L, --label             character field up to 8 bytes, written to SW header\n"
			"     --dumpPrefixHdr     file to dump Prefix header blob (to be signed)\n"
			"     --dumpSwHdr         file to dump Software header blob (to be signed)\n"
			"     --dumpContrHdr      file to dump full Container header (w/o payload)\n"
			"Note:\n"
			"- Keys A,B,C,P,Q,R must be valid p521 ECC keys. Keys may be provided as public\n"
			"  or private key in PEM format, or public key in uncompressed raw format.\n"
			"\n");
	};
	exit(status);
}

static struct option const opts[] = {
	{ "help",             no_argument,       0,  'h' },
	{ "verbose",          no_argument,       0,  'v' },
	{ "debug",            no_argument,       0,  'd' },
	{ "wrap",             required_argument, 0,  'w' },
	{ "hw_key_a",         required_argument, 0,  'a' },
	{ "hw_key_b",         required_argument, 0,  'b' },
	{ "hw_key_c",         required_argument, 0,  'c' },
	{ "sw_key_p",         required_argument, 0,  'p' },
	{ "sw_key_q",         required_argument, 0,  'q' },
	{ "sw_key_r",         required_argument, 0,  'r' },
	{ "hw_sig_a",         required_argument, 0,  'A' },
	{ "hw_sig_b",         required_argument, 0,  'B' },
	{ "hw_sig_c",         required_argument, 0,  'C' },
	{ "sw_sig_p",         required_argument, 0,  'P' },
	{ "sw_sig_q",         required_argument, 0,  'Q' },
	{ "sw_sig_r",         required_argument, 0,  'R' },
	{ "payload",          required_argument, 0,  'l' },
	{ "imagefile",        required_argument, 0,  'I' },
	{ "hw-cs-offset",     required_argument, 0,  'o' },
	{ "sw-cs-offset",     required_argument, 0,  'O' },
	{ "hw-flags",         required_argument, 0,  'f' },
	{ "sw-flags",         required_argument, 0,  'F' },
	{ "label",            required_argument, 0,  'L' },
	{ "dumpPrefixHdr",    required_argument, 0,  128 },
	{ "dumpSwHdr",        required_argument, 0,  129 },
	{ "dumpContrHdr",     required_argument, 0,  130 },
	{ NULL, 0, NULL, 0 }
};

static struct {
	char *hw_keyfn_a;
	char *hw_keyfn_b;
	char *hw_keyfn_c;
	char *sw_keyfn_p;
	char *sw_keyfn_q;
	char *sw_keyfn_r;
	char *hw_sigfn_a;
	char *hw_sigfn_b;
	char *hw_sigfn_c;
	char *sw_sigfn_p;
	char *sw_sigfn_q;
	char *sw_sigfn_r;
	char *imagefn;
	char *payloadfn;
	char *hw_cs_offset;
	char *sw_cs_offset;
	char *hw_flags;
	char *sw_flags;
	char *label;
	char *prhdrfn;
	char *swhdrfn;
	char *cthdrfn;
} params;


int main(int argc, char* argv[])
{
	int fdin, fdout;
	int indexptr;
	unsigned int size, offset;
	void *container = malloc(SECURE_BOOT_HEADERS_SIZE);
	char *buf = malloc(SECURE_BOOT_HEADERS_SIZE);
	struct stat payload_st;
	off_t l;
	void *infile;
	int r;
	uint32_t data;
	uint64_t data64;
	ROM_container_raw *c = (ROM_container_raw*) container;
	ROM_prefix_header_raw *ph;
	ROM_prefix_data_raw *pd;
	ROM_sw_header_raw *swh;
	ROM_sw_sig_raw *ssig;

	unsigned char md[SHA512_DIGEST_LENGTH];
	void *p;
	ecc_key_t pubkeyraw;
	ecc_signature_t sigraw;

	progname = strrchr(argv[0], '/');
	if (progname != NULL)
		++progname;
	else
		progname = argv[0];

	memset(container, 0, SECURE_BOOT_HEADERS_SIZE);

	while (1) {
		int opt;
		opt = getopt_long(argc, argv, "hvdw:a:b:c:p:q:r:A:B:C:P:Q:R:L:I:o:O:f:F:l:",
				opts, &indexptr);
		if (opt == -1)
			break;

		switch (opt) {
		case 'h':
		case '?':
			usage(EX_OK);
			break;
		case 'v':
			verbose = true;
			break;
		case 'd':
			debug = true;
			break;
		case 'w':
			wrap = atoi(optarg);
			wrap = (wrap < 2) ? INT_MAX : wrap;
			break;
		case 'a':
			params.hw_keyfn_a = optarg;
			break;
		case 'b':
			params.hw_keyfn_b = optarg;
			break;
		case 'c':
			params.hw_keyfn_c = optarg;
			break;
		case 'p':
			params.sw_keyfn_p = optarg;
			break;
		case 'q':
			params.sw_keyfn_q = optarg;
			break;
		case 'r':
			params.sw_keyfn_r = optarg;
			break;
		case 'A':
			params.hw_sigfn_a = optarg;
			break;
		case 'B':
			params.hw_sigfn_b = optarg;
			break;
		case 'C':
			params.hw_sigfn_c = optarg;
			break;
		case 'P':
			params.sw_sigfn_p = optarg;
			break;
		case 'Q':
			params.sw_sigfn_q = optarg;
			break;
		case 'R':
			params.sw_sigfn_r = optarg;
			break;
		case 'l':
			params.payloadfn = optarg;
			break;
		case 'I':
			params.imagefn = optarg;
			break;
		case 'o':
			params.hw_cs_offset = optarg;
			break;
		case 'O':
			params.sw_cs_offset = optarg;
			break;
		case 'f':
			params.hw_flags = optarg;
			break;
		case 'F':
			params.sw_flags = optarg;
			break;
		case 'L':
			params.label = optarg;
			break;
		case 128:
			params.prhdrfn = optarg;
			break;
		case 129:
			params.swhdrfn = optarg;
			break;
		case 130:
			params.cthdrfn = optarg;
			break;
		default:
			usage(EX_USAGE);
		}
	}

	fdin = open(params.payloadfn, O_RDONLY);
	if (fdin <= 0)
		die(EX_NOINPUT, "Cannot open payload file: %s", params.payloadfn);

	r = fstat(fdin, &payload_st);
	if (r != 0)
		die(EX_NOINPUT, "Cannot stat payload file: %s", params.payloadfn);

	infile = mmap(NULL, payload_st.st_size, PROT_READ, MAP_PRIVATE, fdin, 0);
	if (infile == MAP_FAILED)
		die(EX_OSERR, "%s", "Cannot mmap file");

	fdout = open(params.imagefn, O_WRONLY | O_CREAT | O_TRUNC,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fdout <= 0)
		die(EX_CANTCREAT, "Cannot create output file: %s", params.imagefn);

	// Container creation starts here.
	c->magic_number = cpu_to_be32(ROM_MAGIC_NUMBER);
	c->version = cpu_to_be16(1);
	c->container_size = cpu_to_be64(SECURE_BOOT_HEADERS_SIZE + payload_st.st_size);
	c->target_hrmor = 0;
	c->stack_pointer = 0;
	memset(c->hw_pkey_a, 0, sizeof(ecc_key_t));
	memset(c->hw_pkey_b, 0, sizeof(ecc_key_t));
	memset(c->hw_pkey_c, 0, sizeof(ecc_key_t));
	if (params.hw_keyfn_a) {
		getPublicKeyRaw(&pubkeyraw, params.hw_keyfn_a);
		verbose_print((char *) "pubkey A = ", pubkeyraw, sizeof(pubkeyraw));
		memcpy(c->hw_pkey_a, pubkeyraw, sizeof(ecc_key_t));
	}
	if (params.hw_keyfn_b) {
		getPublicKeyRaw(&pubkeyraw, params.hw_keyfn_b);
		verbose_print((char *) "pubkey B = ", pubkeyraw, sizeof(pubkeyraw));
		memcpy(c->hw_pkey_b, pubkeyraw, sizeof(ecc_key_t));
	}
	if (params.hw_keyfn_c) {
		getPublicKeyRaw(&pubkeyraw, params.hw_keyfn_c);
		verbose_print((char *) "pubkey C = ", pubkeyraw, sizeof(pubkeyraw));
		memcpy(c->hw_pkey_c, pubkeyraw, sizeof(ecc_key_t));
	}
	p = SHA512(c->hw_pkey_a, sizeof(ecc_key_t) * 3, md);
	if (!p)
		die(EX_SOFTWARE, "%s", "Cannot get SHA512");
	verbose_print((char *) "HW keys hash = ", md, sizeof(md));

	ph = container + sizeof(ROM_container_raw);
	ph->ver_alg.version = cpu_to_be16(1);
	ph->ver_alg.hash_alg = 1;
	ph->ver_alg.sig_alg = 1;

	// Set code-start-offset.
	if (params.hw_cs_offset) {
		if (!isValidHex(params.hw_cs_offset, 4))
			die(EX_DATAERR, "%s",
					"Invalid input for hw-cs-offset, expecting a 4 byte hexadecimal value");
		sscanf(params.hw_cs_offset, "%lx", &data64);
		ph->code_start_offset = cpu_to_be64(data64);
		verbose_msg("hw-cs-offset = %#010lx", data64);
	} else {
		ph->code_start_offset = 0;
	}
	ph->reserved = 0;

	// Set flags.
	if (params.hw_flags) {
		if (!isValidHex(params.hw_flags, 4))
			die(EX_DATAERR, "%s",
					"Invalid input for hw-flags, expecting a 4 byte hexadecimal value");
		sscanf(params.hw_flags, "%x", &data);
		ph->flags = cpu_to_be32(data);
		verbose_msg("hw-flags = %#010x", data);
	} else {
		ph->flags = cpu_to_be32(0x80000000);
	}
	memset(ph->payload_hash, 0, sizeof(sha2_hash_t));
	ph->ecid_count = 0;

	pd = (ROM_prefix_data_raw*) ph->ecid;
	memset(pd->hw_sig_a, 0, sizeof(ecc_signature_t));
	memset(pd->hw_sig_b, 0, sizeof(ecc_signature_t));
	memset(pd->hw_sig_c, 0, sizeof(ecc_signature_t));

	// Write the HW signatures.
	if (params.hw_sigfn_a) {
		getSigRaw(&sigraw, params.hw_sigfn_a);
		verbose_print((char *) "signature A = ", sigraw, sizeof(sigraw));
		memcpy(pd->hw_sig_a, sigraw, sizeof(ecc_key_t));
	}
	if (params.hw_sigfn_b) {
		getSigRaw(&sigraw, params.hw_sigfn_b);
		verbose_print((char *) "signature B = ", sigraw, sizeof(sigraw));
		memcpy(pd->hw_sig_b, sigraw, sizeof(ecc_key_t));
	}
	if (params.hw_sigfn_c) {
		getSigRaw(&sigraw, params.hw_sigfn_c);
		verbose_print((char *) "signature C = ", sigraw, sizeof(sigraw));
		memcpy(pd->hw_sig_c, sigraw, sizeof(ecc_key_t));
	}
	memset(pd->sw_pkey_p, 0, sizeof(ecc_key_t));
	memset(pd->sw_pkey_q, 0, sizeof(ecc_key_t));
	memset(pd->sw_pkey_r, 0, sizeof(ecc_key_t));

	// Write the FW keys.
	if (params.sw_keyfn_p) {
		getPublicKeyRaw(&pubkeyraw, params.sw_keyfn_p);
		verbose_print((char *) "pubkey P = ", pubkeyraw, sizeof(pubkeyraw));
		memcpy(pd->sw_pkey_p, pubkeyraw, sizeof(ecc_key_t));
		ph->sw_key_count++;
	}
	if (params.sw_keyfn_q) {
		getPublicKeyRaw(&pubkeyraw, params.sw_keyfn_q);
		verbose_print((char *) "pubkey Q = ", pubkeyraw, sizeof(pubkeyraw));
		memcpy(pd->sw_pkey_q, pubkeyraw, sizeof(ecc_key_t));
		ph->sw_key_count++;
	}
	if (params.sw_keyfn_r) {
		getPublicKeyRaw(&pubkeyraw, params.sw_keyfn_r);
		verbose_print((char *) "pubkey R = ", pubkeyraw, sizeof(pubkeyraw));
		memcpy(pd->sw_pkey_r, pubkeyraw, sizeof(ecc_key_t));
		ph->sw_key_count++;
	}
	debug_msg("sw_key_count = %u", ph->sw_key_count);
	ph->payload_size = cpu_to_be64(ph->sw_key_count * sizeof(ecc_key_t));

	// Calculate the SW keys hash.
	p = SHA512(pd->sw_pkey_p, sizeof(ecc_key_t) * ph->sw_key_count, md);
	if (!p)
		die(EX_SOFTWARE, "%s", "Cannot get SHA512");
	memcpy(ph->payload_hash, md, sizeof(sha2_hash_t));
	verbose_print((char *) "SW keys hash = ", md, sizeof(md));

	// Dump the Prefix header.
	if (params.prhdrfn)
		writeHdr((void *) ph, params.prhdrfn, PREFIX_HDR);

	swh = (ROM_sw_header_raw*) (((uint8_t*) pd) + sizeof(ecc_signature_t) * 3
			+ be64_to_cpu(ph->payload_size));
	swh->ver_alg.version = cpu_to_be16(1);
	swh->ver_alg.hash_alg = 1;
	swh->ver_alg.sig_alg = 1;

	// Set code-start-offset.
	if (params.sw_cs_offset) {
		if (!isValidHex(params.sw_cs_offset, 4))
			die(EX_DATAERR, "%s",
					"Invalid input for sw-cs-offset, expecting a 4 byte hexadecimal value");
		sscanf(params.sw_cs_offset, "%lx", &data64);
		swh->code_start_offset = cpu_to_be64(data64);
		verbose_msg("sw-cs-offset = %#010lx", data64);
	} else {
		swh->code_start_offset = 0;
	}
	swh->reserved = 0;

	// Add component ID (label).
	if (params.label) {
		if (!isValidAscii(params.label, 0))
			die(EX_DATAERR, "%s",
					"Invalid input for label, expecting a 8 char ASCII value");
		strncpy((char *) &swh->reserved, params.label, 8);
		verbose_msg("component ID (was reserved) = %.8s",
				(char * ) &swh->reserved);
	}

	// Set flags.
	if (params.sw_flags) {
		if (!isValidHex(params.sw_flags, 4))
			die(EX_DATAERR, "%s",
					"Invalid input for sw-flags, expecting a 4 byte hexadecimal value");
		sscanf(params.sw_flags, "%x", &data);
		swh->flags = cpu_to_be32(data);
		verbose_msg("sw-flags = %#010x", data);
	} else {
		swh->flags = cpu_to_be32(0x00000000);
	}
	swh->reserved_0 = 0;
	swh->payload_size = cpu_to_be64(payload_st.st_size);

	// Calculate the payload hash.
	p = SHA512(infile, payload_st.st_size, md);
	if (!p)
		die(EX_SOFTWARE, "%s", "Cannot get SHA512");
	memcpy(swh->payload_hash, md, sizeof(sha2_hash_t));
	verbose_print((char *) "Payload hash = ", md, sizeof(md));

	// Dump the Software header.
	if (params.swhdrfn)
		writeHdr((void *) swh, params.swhdrfn, SOFTWARE_HDR);

	ssig = (ROM_sw_sig_raw*) (((uint8_t*) swh) + sizeof(ROM_sw_header_raw));
	memset(ssig->sw_sig_p, 0, sizeof(ecc_signature_t));
	memset(ssig->sw_sig_q, 0, sizeof(ecc_signature_t));
	memset(ssig->sw_sig_r, 0, sizeof(ecc_signature_t));

	// Write the HW signatures.
	if (params.sw_sigfn_p) {
		getSigRaw(&sigraw, params.sw_sigfn_p);
		verbose_print((char *) "signature P = ", sigraw, sizeof(sigraw));
		memcpy(ssig->sw_sig_p, sigraw, sizeof(ecc_key_t));
	}
	if (params.sw_sigfn_q) {
		getSigRaw(&sigraw, params.sw_sigfn_q);
		verbose_print((char *) "signature Q = ", sigraw, sizeof(sigraw));
		memcpy(ssig->sw_sig_q, sigraw, sizeof(ecc_key_t));
	}
	if (params.sw_sigfn_r) {
		getSigRaw(&sigraw, params.sw_sigfn_r);
		verbose_print((char *) "signature R = ", sigraw, sizeof(sigraw));
		memcpy(ssig->sw_sig_r, sigraw, sizeof(ecc_key_t));
	}

	// Dump the full container header.
	if (params.cthdrfn)
		writeHdr((void *) c, params.cthdrfn, CONTAINER_HDR);

	// Print container stats.
	size = (uint8_t*) ph - (uint8_t *) c;
	offset = (uint8_t*) c - (uint8_t *) c;
	verbose_msg("HW header size        = %4u (%#06x) at offset %4u (%#06x)",
			size, size, offset, offset);
	size = (uint8_t*) pd - (uint8_t *) ph;
	offset = (uint8_t*) ph - (uint8_t *) c;
	verbose_msg("Prefix header size    = %4u (%#06x) at offset %4u (%#06x)",
			size, size, offset, offset);
	size = (uint8_t*) swh - (uint8_t *) pd;
	offset = (uint8_t*) pd - (uint8_t *) c;
	verbose_msg("Prefix data size      = %4u (%#06x) at offset %4u (%#06x)",
			size, size, offset, offset);
	size = (uint8_t*) ssig - (uint8_t *) swh;
	offset = (uint8_t*) swh - (uint8_t *) c;
	verbose_msg("SW header size        = %4u (%#06x) at offset %4u (%#06x)",
			size, size, offset, offset);
	size = sizeof(ecc_key_t) * ph->sw_key_count;
	offset = (uint8_t*) ssig - (uint8_t *) c;
	verbose_msg("SW signature size     = %4u (%#06x) at offset %4u (%#06x)",
			size, size, offset, offset);

	verbose_msg("TOTAL HEADER SIZE     = %4d (%#0x)", SECURE_BOOT_HEADERS_SIZE,
			SECURE_BOOT_HEADERS_SIZE);
	verbose_msg("PAYLOAD SIZE          = %4lu (%#0lx)",
			be64_to_cpu(swh->payload_size), be64_to_cpu(swh->payload_size));
	verbose_msg("TOTAL CONTAINER SIZE  = %4lu (%#0lx)",
			be64_to_cpu(c->container_size), be64_to_cpu(c->container_size));

	// Write container.
	r = write(fdout, container, SECURE_BOOT_HEADERS_SIZE);
	if (r != 4096)
		die(EX_SOFTWARE, "Cannot write container (r = %d)", r);
	r = read(fdin, buf, payload_st.st_size % 4096);
	r = write(fdout, buf, payload_st.st_size % 4096);
	l = payload_st.st_size - payload_st.st_size % 4096;
	while (l) {
		r = read(fdin, buf, 4096);
		r = write(fdout, buf, 4096);
		l -= 4096;
	};
	close(fdin);
	close(fdout);

	free(container);
	free(buf);
	return 0;
}
