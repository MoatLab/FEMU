// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2017 IBM Corp. */

#include <config.h>

#include <alloca.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/opensslv.h>
#include <openssl/ossl_typ.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <stddef.h>
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

#define PASSED 1
#define FAILED 0
#define UNATTEMPTED -1

char *progname;

bool print_stats;
bool verbose, debug;
int wrap = 100;

ecc_key_t ECDSA_KEY_NULL;

typedef struct keyprops {
	char index;
	const char *name;
	const ecc_key_t *key;
	const ecc_signature_t *sig;
} Keyprops;

static void usage(int status);

static bool getPayloadHash(int fdin, unsigned char *md);
static bool getVerificationHash(char *input, unsigned char *md, int len);
static bool verify_signature(const char *moniker, const unsigned char *dgst,
		int dgst_len, const ecc_signature_t sig_raw, const ecc_key_t key_raw);

static void print_bytes(char *lead, uint8_t *buffer, size_t buflen)
{
	unsigned int i;
	unsigned int width;
	unsigned int leadbytes = strlen(lead);
	leadbytes = leadbytes > 30 ? 30 : leadbytes;
	width = (wrap - leadbytes) / 2;
	width = (width < 1) ? INT_MAX : width;

	fprintf(stdout, "%s", lead);
	for (i = 1; i < buflen + 1; i++) {
		fprintf(stdout, "%02x", buffer[i - 1]);
		if (((i % width) == 0) && (i < buflen))
			fprintf(stdout, "\n%*c", leadbytes, ' ');
	}
	fprintf(stdout, "\n");
}

bool stb_is_container(const void *buf, size_t size)
{
	ROM_container_raw *c;

	c = (ROM_container_raw*) buf;
	if (!buf || size < SECURE_BOOT_HEADERS_SIZE)
		return false;
	if (be32_to_cpu(c->magic_number) != ROM_MAGIC_NUMBER)
		return false;
	return true;
}

int parse_stb_container(const void* data, size_t len,
		struct parsed_stb_container *c)
{
	const size_t prefix_data_min_size = 3 * (EC_COORDBYTES * 2);
	c->buf = data;
	c->bufsz = len;
	c->c = data;
	c->ph = data += sizeof(ROM_container_raw);
	c->pd = data += sizeof(ROM_prefix_header_raw)
			+ (c->ph->ecid_count * ECID_SIZE);
	c->sh = data += prefix_data_min_size
			+ c->ph->sw_key_count * (EC_COORDBYTES * 2);
	c->ssig = data += sizeof(ROM_sw_header_raw) + c->sh->ecid_count * ECID_SIZE;

	return 0;
}

static void display_version_raw(const ROM_version_raw v)
{
	printf("ver_alg:\n");
	printf("  version:  %04x\n", be16_to_cpu(v.version));
	printf("  hash_alg: %02x (%s)\n", v.hash_alg,
			(v.hash_alg == 1) ? "SHA512" : "UNKNOWN");
	printf("  sig_alg:  %02x (%s)\n", v.sig_alg,
			(v.sig_alg == 1) ? "SHA512/ECDSA-521" : "UNKNOWN");
}

static void display_container_stats(const struct parsed_stb_container *c)
{
	unsigned int size, offset;

	printf("Container stats:\n");
	size = (uint8_t*) c->ph - (uint8_t *) c->c;
	offset = (uint8_t*) c->c - (uint8_t *) c->buf;
	printf("  HW header size        = %4u (%#06x) at offset %4u (%#06x)\n",
			size, size, offset, offset);
	size = (uint8_t*) c->pd - (uint8_t *) c->ph;
	offset = (uint8_t*) c->ph - (uint8_t *) c->buf;
	printf("  Prefix header size    = %4u (%#06x) at offset %4u (%#06x)\n",
			size, size, offset, offset);
	size = (uint8_t*) c->sh - (uint8_t *) c->pd;
	offset = (uint8_t*) c->pd - (uint8_t *) c->buf;
	printf("  Prefix data size      = %4u (%#06x) at offset %4u (%#06x)\n",
			size, size, offset, offset);
	size = (uint8_t*) c->ssig - (uint8_t *) c->sh;
	offset = (uint8_t*) c->sh - (uint8_t *) c->buf;
	printf("  SW header size        = %4u (%#06x) at offset %4u (%#06x)\n",
			size, size, offset, offset);
	size = sizeof(ecc_key_t) * c->ph->sw_key_count;
	offset = (uint8_t*) c->ssig - (uint8_t *) c->buf;
	printf("  SW signature size     = %4u (%#06x) at offset %4u (%#06x)\n",
			size, size, offset, offset);

	printf("  TOTAL HEADER SIZE     = %4lu (%#0lx)\n", c->bufsz, c->bufsz);
	printf("  PAYLOAD SIZE          = %4lu (%#0lx)\n",
			be64_to_cpu(c->sh->payload_size), be64_to_cpu(c->sh->payload_size));
	printf("  TOTAL CONTAINER SIZE  = %4lu (%#0lx)\n",
			be64_to_cpu(c->c->container_size),
			be64_to_cpu(c->c->container_size));
	printf("\n");
}

static void display_container(struct parsed_stb_container c)
{
	unsigned char md[SHA512_DIGEST_LENGTH];
	void *p;

	printf("Container:\n");
	printf("magic:          0x%04x\n", be32_to_cpu(c.c->magic_number));
	printf("version:        0x%02x\n", be16_to_cpu(c.c->version));
	printf("container_size: 0x%08lx (%lu)\n", be64_to_cpu(c.c->container_size),
			be64_to_cpu(c.c->container_size));
	printf("target_hrmor:   0x%08lx\n", be64_to_cpu(c.c->target_hrmor));
	printf("stack_pointer:  0x%08lx\n", be64_to_cpu(c.c->stack_pointer));
	print_bytes((char *) "hw_pkey_a: ", (uint8_t *) c.c->hw_pkey_a,
			sizeof(c.c->hw_pkey_a));
	print_bytes((char *) "hw_pkey_b: ", (uint8_t *) c.c->hw_pkey_b,
			sizeof(c.c->hw_pkey_b));
	print_bytes((char *) "hw_pkey_c: ", (uint8_t *) c.c->hw_pkey_c,
			sizeof(c.c->hw_pkey_c));

	p = SHA512(c.c->hw_pkey_a, sizeof(ecc_key_t) * 3, md);
	if (!p)
		die(EX_SOFTWARE, "%s", "Cannot get SHA512");
	printf("HW keys hash (calculated):\n");
	print_bytes((char *) "           ", (uint8_t *) md, sizeof(md));
	printf("\n");

	printf("Prefix Header:\n");
	display_version_raw(c.ph->ver_alg);
	printf("code_start_offset: %08lx\n", be64_to_cpu(c.ph->code_start_offset));
	printf("reserved:          %08lx\n", be64_to_cpu(c.ph->reserved));
	printf("flags:             %08x\n", be32_to_cpu(c.ph->flags));
	printf("sw_key_count:      %02x\n", c.ph->sw_key_count);
	printf("payload_size:      %08lx\n", be64_to_cpu(c.ph->payload_size));
	print_bytes((char *) "payload_hash:      ", (uint8_t *) c.ph->payload_hash,
			sizeof(c.ph->payload_hash));
	printf("ecid_count:        %02x\n", c.ph->ecid_count);

	for (int i = 0; i < c.ph->ecid_count; i++) {
		printf("ecid:              ");
		print_bytes((char *) "ecid:              ",
				(uint8_t *) c.ph->ecid[i].ecid, sizeof(c.ph->ecid[i].ecid));
		printf("\n");
	}
	printf("\n");

	printf("Prefix Data:\n");
	print_bytes((char *) "hw_sig_a:  ", (uint8_t *) c.pd->hw_sig_a, sizeof(c.pd->hw_sig_a));
	print_bytes((char *) "hw_sig_b:  ", (uint8_t *) c.pd->hw_sig_b, sizeof(c.pd->hw_sig_b));
	print_bytes((char *) "hw_sig_c:  ", (uint8_t *) c.pd->hw_sig_c, sizeof(c.pd->hw_sig_c));

	if (c.ph->sw_key_count >=1)
		print_bytes((char *) "sw_pkey_p: ", (uint8_t *) c.pd->sw_pkey_p, sizeof(c.pd->sw_pkey_p));
	if (c.ph->sw_key_count >=2)
		print_bytes((char *) "sw_pkey_q: ", (uint8_t *) c.pd->sw_pkey_q, sizeof(c.pd->sw_pkey_q));
	if (c.ph->sw_key_count >=3)
		print_bytes((char *) "sw_pkey_r: ", (uint8_t *) c.pd->sw_pkey_r, sizeof(c.pd->sw_pkey_r));

	printf("\n");

	printf("Software Header:\n");
	display_version_raw(c.sh->ver_alg);
	printf("code_start_offset: %08lx\n", be64_to_cpu(c.sh->code_start_offset));
	printf("reserved:          %08lx\n", be64_to_cpu(c.sh->reserved));
	printf("reserved (ASCII):  %.8s\n", (char *) &(c.sh->reserved));
	printf("flags:             %08x\n", be32_to_cpu(c.sh->flags));
	printf("reserved_0:        %02x\n", c.sh->reserved_0);
	printf("payload_size:      %08lx (%lu)\n", be64_to_cpu(c.sh->payload_size),
			be64_to_cpu(c.sh->payload_size));
	print_bytes((char *) "payload_hash:      ", (uint8_t *) c.sh->payload_hash,
			sizeof(c.sh->payload_hash));
	printf("ecid_count:        %02x\n", c.sh->ecid_count);

	for (int i = 0; i < c.sh->ecid_count; i++) {
		printf("ecid:              ");
		print_bytes((char *) "ecid:              ",
				(uint8_t *) c.sh->ecid[i].ecid, sizeof(c.sh->ecid[i].ecid));
		printf("\n");
	}
	printf("\n");

	printf("Software Signatures:\n");
	print_bytes((char *) "sw_sig_p:  ", (uint8_t *) c.ssig->sw_sig_p,
			sizeof(c.ssig->sw_sig_p));
	print_bytes((char *) "sw_sig_q:  ", (uint8_t *) c.ssig->sw_sig_q,
			sizeof(c.ssig->sw_sig_q));
	print_bytes((char *) "sw_sig_r:  ", (uint8_t *) c.ssig->sw_sig_r,
			sizeof(c.ssig->sw_sig_r));
	printf("\n");

	if (print_stats)
	display_container_stats(&c);
}

static bool validate_container(struct parsed_stb_container c, int fdin)
{
	static int n;
	static int status = true;

	Keyprops *k;

	Keyprops hwKeylist[] = {
		{ 'a', "HW_key_A", &(c.c->hw_pkey_a), &(c.pd->hw_sig_a) },
		{ 'b', "HW_key_B", &(c.c->hw_pkey_b), &(c.pd->hw_sig_b) },
		{ 'c', "HW_key_C", &(c.c->hw_pkey_c), &(c.pd->hw_sig_c) },
		{ 0, NULL, NULL, NULL },
	};
	Keyprops swKeylist[] = {
		{ 'p', "SW_key_P", &(c.pd->sw_pkey_p), &(c.ssig->sw_sig_p) },
		{ 'q', "SW_key_Q", &(c.pd->sw_pkey_q), &(c.ssig->sw_sig_q) },
		{ 'r', "SW_key_R", &(c.pd->sw_pkey_r), &(c.ssig->sw_sig_r) },
		{ 0, NULL, NULL, NULL },
	};

	void *md = alloca(SHA512_DIGEST_LENGTH);
	void *p;

	// Get Prefix header hash.
	p = SHA512((uint8_t *) c.ph, sizeof(ROM_prefix_header_raw), md);
	if (!p)
		die(EX_SOFTWARE, "%s", "Cannot get SHA512");
	if (verbose) print_bytes((char *) "PR header hash = ", (uint8_t *) md,
			SHA512_DIGEST_LENGTH);

	// Verify HW key sigs.
	for (k = hwKeylist; k->index; k++) {

		if (memcmp(k->key, &ECDSA_KEY_NULL, sizeof(ecc_key_t)))
			status = verify_signature(k->name, md, SHA512_DIGEST_LENGTH,
					*(k->sig), *(k->key)) && status;
		else
			if (verbose) printf("%s is NULL, skipping signature check.\n", k->name);
	}
	if (verbose) printf("\n");

	// Get SW header hash.
	p = SHA512((uint8_t *) c.sh, sizeof(ROM_sw_header_raw), md);
	if (!p)
		die(EX_SOFTWARE, "%s", "Cannot get SHA512");
	if (verbose) print_bytes((char *) "SW header hash = ", (uint8_t *) md,
			SHA512_DIGEST_LENGTH);

	// Verify SW key sigs.
	for (k = swKeylist, n = 1; k->index && n <= c.ph->sw_key_count; k++, n++) {

		if (memcmp(k->key, &ECDSA_KEY_NULL, sizeof(ecc_key_t)))
			status = verify_signature(k->name, md, SHA512_DIGEST_LENGTH,
					*(k->sig), *(k->key)) && status;
		else
			if (verbose) printf("%s is NULL, skipping\n", k->name);
	}
	if (verbose) printf("\n");

	// Verify Payload hash.
	status = getPayloadHash(fdin, md) && status;
	if (verbose) print_bytes((char *) "Payload hash = ", (uint8_t *) md,
			SHA512_DIGEST_LENGTH);

	if (memcmp((uint8_t *) c.sh->payload_hash, md, SHA512_DIGEST_LENGTH)) {
		if (verbose)
			printf("Payload hash does not agree with value in SW header: MISMATCH\n");
		status = false;
	} else {
		if (verbose)
			printf("Payload hash agrees with value in SW header: VERIFIED ./\n");
		status = status && true;
	}
	if (verbose) printf("\n");

	// Verify SW keys hash.
	p = SHA512(c.pd->sw_pkey_p, sizeof(ecc_key_t) * c.ph->sw_key_count, md);
	if (!p)
		die(EX_SOFTWARE, "%s", "Cannot get SHA512");
	if (verbose) print_bytes((char *) "SW keys hash = ", (uint8_t *) md,
			SHA512_DIGEST_LENGTH);

	if (memcmp((uint8_t *) c.ph->payload_hash, md, SHA512_DIGEST_LENGTH)) {
		if (verbose)
			printf("SW keys hash does not agree with value in Prefix header: MISMATCH\n");
		status = false;
	} else {
		if (verbose)
			printf("SW keys hash agrees with value in Prefix header: VERIFIED ./\n");
		status = status && true;
	}
	if (verbose) printf("\n");
	return status;
}

static bool verify_container(struct parsed_stb_container c, char * verify)
{
	static int status = false;

	void *md = alloca(SHA512_DIGEST_LENGTH);
	void *p;
	void *md_verify;

	p = SHA512(c.c->hw_pkey_a, sizeof(ecc_key_t) * 3, md);
	if (!p)
		die(EX_SOFTWARE, "%s", "Cannot get SHA512");
	if (verbose) print_bytes((char *) "HW keys hash = ", (uint8_t *) md,
			SHA512_DIGEST_LENGTH);

	md_verify = alloca(SHA512_DIGEST_LENGTH);
	getVerificationHash(verify, md_verify, SHA512_DIGEST_LENGTH);

	if (memcmp((uint8_t *) md_verify, md, SHA512_DIGEST_LENGTH )) {
		if (verbose)
			printf("HW keys hash does not agree with provided value: MISMATCH\n");
	} else {
		if (verbose)
			printf("HW keys hash agrees with provided value: VERIFIED ./\n");
		status = true;
	}
	if (verbose) printf("\n");
	return status;
}

static bool verify_signature(const char *moniker, const unsigned char *dgst,
		int dgst_len, const ecc_signature_t sig_raw, const ecc_key_t key_raw)
{
	int r;
	bool status = false;
	BIGNUM *r_bn, *s_bn;
	ECDSA_SIG* ecdsa_sig;
	EC_KEY *ec_key;
	const EC_GROUP *ec_group;
	unsigned char *buffer;
	BIGNUM *key_bn;
	EC_POINT *ec_point;

	// Convert the raw sig to a structure that can be handled by openssl.
	debug_print((char *) "Raw sig = ", (uint8_t *) sig_raw,
			sizeof(ecc_signature_t));

	r_bn = BN_new();
	s_bn = BN_new();

	BN_bin2bn((const unsigned char*) &sig_raw[0], 66, r_bn);
	BN_bin2bn((const unsigned char*) &sig_raw[66], 66, s_bn);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	ecdsa_sig = ECDSA_SIG_new();
	ECDSA_SIG_set0(ecdsa_sig, r_bn, s_bn);
#else
	ecdsa_sig = malloc(sizeof(ECDSA_SIG));
	ecdsa_sig->r = r_bn;
	ecdsa_sig->s = s_bn;
#endif

	// Convert the raw key to a structure that can be handled by openssl.
	debug_print((char *) "Raw key = ", (uint8_t *) key_raw,
			sizeof(ecc_key_t));

	ec_key = EC_KEY_new();
	if (!ec_key)
		die(EX_SOFTWARE, "%s", "Cannot EC_KEY_new");

	ec_group = EC_GROUP_new_by_curve_name(NID_secp521r1);
	if (!ec_group)
		die(EX_SOFTWARE, "%s", "Cannot EC_GROUP_new_by_curve_name");

	r = EC_KEY_set_group(ec_key, ec_group);
	if (r == 0)
		die(EX_SOFTWARE, "%s", "Cannot EC_KEY_set_group");

	// Add prefix 0x04, for uncompressed key.
	buffer = alloca(sizeof(ecc_key_t) + 1);
	*buffer = 0x04;
	memcpy(buffer + 1, key_raw, sizeof(ecc_key_t));

	key_bn = BN_new();
	BN_bin2bn((const unsigned char*) buffer, EC_COORDBYTES * 2 + 1, key_bn);

	ec_point = EC_POINT_bn2point(ec_group, key_bn, NULL, NULL);
	if (!ec_point)
		die(EX_SOFTWARE, "%s", "Cannot EC_POINT_bn2point");

	r = EC_KEY_set_public_key(ec_key, (const EC_POINT*) ec_point);
	if (r == 0)
		die(EX_SOFTWARE, "%s", "Cannot EC_KEY_set_public_key");

	// Verify the signature.
	r = ECDSA_do_verify(dgst, dgst_len, ecdsa_sig, ec_key);
	if (r == 1) {
		if (verbose) printf("%s signature is good: VERIFIED ./\n", moniker);
		status = true;
	} else if (r == 0) {
		if (verbose) printf("%s signature FAILED to verify.\n", moniker);
		status = false;
	} else {
		die(EX_SOFTWARE, "%s", "Cannot ECDSA_do_verify");
	}

	BN_free(r_bn);
	BN_free(s_bn);
	BN_free(key_bn);

	EC_KEY_free(ec_key);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	ECDSA_SIG_free(ecdsa_sig);
#else
	free(ecdsa_sig);
#endif
	return status;
}

static bool getPayloadHash(int fdin, unsigned char *md)
{
	struct stat payload_st;
	void *payload;
	int r;
	void *p;

	r = fstat(fdin, &payload_st);
	if (r != 0)
		die(EX_NOINPUT, "Cannot stat payload file at descriptor: %d (%s)", fdin,
				strerror(errno));

	payload = mmap(NULL, payload_st.st_size - SECURE_BOOT_HEADERS_SIZE,
			PROT_READ, MAP_PRIVATE, fdin, SECURE_BOOT_HEADERS_SIZE);
	if (payload == MAP_FAILED)
		die(EX_OSERR, "Cannot mmap file at descriptor: %d (%s)", fdin,
				strerror(errno));

	p = SHA512(payload, payload_st.st_size - SECURE_BOOT_HEADERS_SIZE, md);
	if (!p)
		die(EX_SOFTWARE, "%s", "Cannot get SHA512");

	return true;
}

static bool getVerificationHash(char *input, unsigned char *md, int len)
{
	char buf[len * 2 + 1 + 2]; // allow trailing \n and leading "0x"
	char *p;
	struct stat s;
	int r;

	if (isValidHex(input, len)) {
		p = input;
	} else {
		int fdin = open(input, O_RDONLY);
		if (fdin <= 0)
			die(EX_NOINPUT, "%s",
					"Verify requested but no valid hash or hash file provided");

		r = fstat(fdin, &s);
		if (r != 0)
			die(EX_NOINPUT, "Cannot stat hash file: %s (%s)", input,
					strerror(errno));
		if ((size_t) s.st_size > (sizeof(buf)))
			die(EX_DATAERR,
					"Verify hash file \"%s\" invalid size: expected a %d byte hexadecimal value",
					input, len);

		r = read(fdin, buf, s.st_size);
		if (r <= 0)
			die(EX_NOINPUT, "Cannot read hash file: %s (%s)", input,
					strerror(errno));
		p = (char *) buf;

		for (unsigned int i = 0; i < sizeof(buf); i++) // strip newline char
			if (buf[i] == '\n')
				buf[i] = '\0';

		close(fdin);
	}

	// Convert hexascii to binary.
	if (isValidHex(p, len)) {
		if (!strncmp(p, "0x", 2)) // skip leading "0x"
			p += 2;
		for (int count = 0; count < len; count++) {
			sscanf(p, "%2hhx", &md[count]);
			p += 2;
		}
	} else
		die(EX_DATAERR,
				"Verify hash file \"%s\" invalid data: expected a %d byte hexadecimal value",
				input, len);

	return true;
}

__attribute__((__noreturn__)) static void usage (int status)
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
			" -w, --wrap              column at which to wrap long output (wrap=0 => unlimited)\n"
			" -s, --stats             additionally print container stats\n"
			" -I, --imagefile         containerized image to display (input)\n"
			"     --validate          perform all checks to ensure is container valid for secure boot\n"
			"     --verify            value, or filename containing value, of the HW Keys hash to\n"
			"                         verify the container against. must be valid 64 byte hexascii.\n"
			"\n");
	};
	exit(status);
}

static struct option const opts[] = {
	{ "help",             no_argument,       0,  'h' },
	{ "verbose",          no_argument,       0,  'v' },
	{ "debug",            no_argument,       0,  'd' },
	{ "wrap",             required_argument, 0,  'w' },
	{ "stats",            no_argument,       0,  's' },
	{ "imagefile",        required_argument, 0,  'I' },
	{ "validate",         no_argument,       0,  128 },
	{ "verify",           required_argument, 0,  129 },
	{ "no-print",         no_argument,       0,  130 },
	{ "print",            no_argument,       0,  131 },
	{ NULL, 0, NULL, 0 }
};

static struct {
	char *imagefn;
	bool validate;
	char *verify;
	bool print_container;
} params;


int main(int argc, char* argv[])
{
	int indexptr;
	int r;
	struct stat st;
	void *container;
	struct parsed_stb_container c;
	int container_status = EX_OK;
	int validate_status = UNATTEMPTED;
	int verify_status = UNATTEMPTED;
	int fdin;

	params.print_container = true;

	progname = strrchr(argv[0], '/');
	if (progname != NULL)
		++progname;
	else
		progname = argv[0];

	while (1) {
		int opt;
		opt = getopt_long(argc, argv, "hvdw:sI:", opts, &indexptr);
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
		case 's':
			print_stats = true;
			break;
		case 'I':
			params.imagefn = optarg;
			break;
		case 128:
			params.validate = true;
			break;
		case 129:
			params.verify = optarg;
			break;
		case 130:
			params.print_container = false;
			break;
		case 131:
			params.print_container = true;
			break;
		default:
			usage(EX_USAGE);
		}
	}

	fdin = open(params.imagefn, O_RDONLY);
	if (fdin <= 0)
		die(EX_NOINPUT, "Cannot open container file: %s (%s)", params.imagefn,
				strerror(errno));

	r = fstat(fdin, &st);
	if (r != 0)
		die(EX_NOINPUT, "Cannot stat container file: %s (%s)", params.imagefn,
				strerror(errno));

	container = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fdin, 0);
	if (container == MAP_FAILED)
		die(EX_OSERR, "Cannot mmap file: %s (%s)", params.imagefn,
				strerror(errno));

	if (!stb_is_container(container, SECURE_BOOT_HEADERS_SIZE))
		die(EX_DATAERR, "%s", "Not a container, missing magic number");

	if (parse_stb_container(container, SECURE_BOOT_HEADERS_SIZE, &c) != 0)
		die(EX_DATAERR, "%s", "Failed to parse container");

	if (params.print_container)
		display_container(c);

	if (params.validate)
		validate_status = validate_container(c, fdin);

	if (params.verify)
		verify_status = verify_container(c, params.verify);

	if ((validate_status != UNATTEMPTED) || (verify_status != UNATTEMPTED)) {

		printf("Container validity check %s. Container verification check %s.\n\n",
				(validate_status == UNATTEMPTED) ?
						"not attempted" :
						((validate_status == PASSED) ? "PASSED" : "FAILED"),
				(verify_status == UNATTEMPTED) ?
						"not attempted" :
						((verify_status == PASSED) ? "PASSED" : "FAILED"));

		if ((validate_status == FAILED) || (verify_status == FAILED))
			container_status = 1;
	}

	close(fdin);
	return container_status;
}
