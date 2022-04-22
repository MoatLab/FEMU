// SPDX-License-Identifier: GPL-2.0
/*
 * (C) Copyright 2018 Xilinx, Inc.
 * Siva Durga Prasad Paladugu <siva.durga.paladugu@xilinx.com>
 */

#include <common.h>
#include <command.h>
#include <cpu_func.h>
#include <env.h>
#include <malloc.h>
#include <memalign.h>
#include <zynqmp_firmware.h>
#include <asm/arch/hardware.h>
#include <asm/arch/sys_proto.h>
#include <asm/io.h>

struct aes {
	u64 srcaddr;
	u64 ivaddr;
	u64 keyaddr;
	u64 dstaddr;
	u64 len;
	u64 op;
	u64 keysrc;
};

static int do_zynqmp_verify_secure(struct cmd_tbl *cmdtp, int flag, int argc,
				   char *const argv[])
{
	u64 src_addr, addr;
	u32 len, src_lo, src_hi;
	u8 *key_ptr = NULL;
	int ret;
	u32 key_lo = 0;
	u32 key_hi = 0;
	u32 ret_payload[PAYLOAD_ARG_CNT];

	if (argc < 4)
		return CMD_RET_USAGE;

	src_addr = simple_strtoull(argv[2], NULL, 16);
	len = simple_strtoul(argv[3], NULL, 16);

	if (argc == 5)
		key_ptr = (uint8_t *)(uintptr_t)simple_strtoull(argv[4],
								NULL, 16);

	if ((ulong)src_addr != ALIGN((ulong)src_addr,
				     CONFIG_SYS_CACHELINE_SIZE)) {
		printf("Failed: source address not aligned:%lx\n",
		       (ulong)src_addr);
		return -EINVAL;
	}

	src_lo = lower_32_bits((ulong)src_addr);
	src_hi = upper_32_bits((ulong)src_addr);
	flush_dcache_range((ulong)src_addr, (ulong)(src_addr + len));

	if (key_ptr) {
		key_lo = lower_32_bits((ulong)key_ptr);
		key_hi = upper_32_bits((ulong)key_ptr);
		flush_dcache_range((ulong)key_ptr,
				   (ulong)(key_ptr + KEY_PTR_LEN));
	}

	ret = xilinx_pm_request(PM_SECURE_IMAGE, src_lo, src_hi,
				key_lo, key_hi, ret_payload);
	if (ret) {
		printf("Failed: secure op status:0x%x\n", ret);
	} else {
		addr = (u64)ret_payload[1] << 32 | ret_payload[2];
		printf("Verified image at 0x%llx\n", addr);
		env_set_hex("zynqmp_verified_img_addr", addr);
	}

	return ret;
}

static int do_zynqmp_mmio_read(struct cmd_tbl *cmdtp, int flag, int argc,
			       char *const argv[])
{
	u32 read_val, addr;
	int ret;

	if (argc != cmdtp->maxargs)
		return CMD_RET_USAGE;

	addr = simple_strtoul(argv[2], NULL, 16);

	ret = zynqmp_mmio_read(addr, &read_val);
	if (!ret)
		printf("mmio read value at 0x%x = 0x%x\n",
		       addr, read_val);
	else
		printf("Failed: mmio read\n");

	return ret;
}

static int do_zynqmp_mmio_write(struct cmd_tbl *cmdtp, int flag, int argc,
				char *const argv[])
{
	u32 addr, mask, val;
	int ret;

	if (argc != cmdtp->maxargs)
		return CMD_RET_USAGE;

	addr = simple_strtoul(argv[2], NULL, 16);
	mask = simple_strtoul(argv[3], NULL, 16);
	val = simple_strtoul(argv[4], NULL, 16);

	ret = zynqmp_mmio_write(addr, mask, val);
	if (ret != 0)
		printf("Failed: mmio write\n");

	return ret;
}

static int do_zynqmp_aes(struct cmd_tbl *cmdtp, int flag, int argc,
			 char * const argv[])
{
	ALLOC_CACHE_ALIGN_BUFFER(struct aes, aes, 1);
	int ret;
	u32 ret_payload[PAYLOAD_ARG_CNT];

	if (zynqmp_firmware_version() <= PMUFW_V1_0) {
		puts("ERR: PMUFW v1.0 or less is detected\n");
		puts("ERR: Encrypt/Decrypt feature is not supported\n");
		puts("ERR: Please upgrade PMUFW\n");
		return CMD_RET_FAILURE;
	}

	if (argc < cmdtp->maxargs - 1)
		return CMD_RET_USAGE;

	aes->srcaddr = simple_strtoul(argv[2], NULL, 16);
	aes->ivaddr = simple_strtoul(argv[3], NULL, 16);
	aes->len = simple_strtoul(argv[4], NULL, 16);
	aes->op = simple_strtoul(argv[5], NULL, 16);
	aes->keysrc = simple_strtoul(argv[6], NULL, 16);
	aes->dstaddr = simple_strtoul(argv[7], NULL, 16);

	flush_dcache_range((ulong)aes, (ulong)(aes) +
			   roundup(sizeof(struct aes), ARCH_DMA_MINALIGN));

	if (aes->srcaddr && aes->ivaddr && aes->dstaddr) {
		flush_dcache_range(aes->srcaddr,
				   (aes->srcaddr +
				    roundup(aes->len, ARCH_DMA_MINALIGN)));
		flush_dcache_range(aes->ivaddr,
				   (aes->ivaddr +
				    roundup(IV_SIZE, ARCH_DMA_MINALIGN)));
		flush_dcache_range(aes->dstaddr,
				   (aes->dstaddr +
				    roundup(aes->len, ARCH_DMA_MINALIGN)));
	}

	if (aes->keysrc == 0) {
		if (argc < cmdtp->maxargs)
			return CMD_RET_USAGE;

		aes->keyaddr = simple_strtoul(argv[8], NULL, 16);
		if (aes->keyaddr)
			flush_dcache_range(aes->keyaddr,
					   (aes->keyaddr +
					    roundup(KEY_PTR_LEN,
						    ARCH_DMA_MINALIGN)));
	}

	ret = xilinx_pm_request(PM_SECURE_AES, upper_32_bits((ulong)aes),
				lower_32_bits((ulong)aes), 0, 0, ret_payload);
	if (ret || ret_payload[1])
		printf("Failed: AES op status:0x%x, errcode:0x%x\n",
		       ret, ret_payload[1]);

	return ret;
}

#ifdef CONFIG_DEFINE_TCM_OCM_MMAP
static int do_zynqmp_tcm_init(struct cmd_tbl *cmdtp, int flag, int argc,
			      char *const argv[])
{
	u8 mode;

	if (argc != cmdtp->maxargs)
		return CMD_RET_USAGE;

	mode = simple_strtoul(argv[2], NULL, 16);
	if (mode != TCM_LOCK && mode != TCM_SPLIT) {
		printf("Mode should be either 0(lock)/1(split)\n");
		return CMD_RET_FAILURE;
	}

	dcache_disable();
	tcm_init(mode);
	dcache_enable();

	return CMD_RET_SUCCESS;
}
#endif

static int do_zynqmp_pmufw(struct cmd_tbl *cmdtp, int flag, int argc,
			   char * const argv[])
{
	u32 addr, size;

	if (argc != cmdtp->maxargs)
		return CMD_RET_USAGE;

	addr = simple_strtoul(argv[2], NULL, 16);
	size = simple_strtoul(argv[3], NULL, 16);
	flush_dcache_range((ulong)addr, (ulong)(addr + size));

	zynqmp_pmufw_load_config_object((const void *)(uintptr_t)addr,
					(size_t)size);

	return 0;
}

static int do_zynqmp_rsa(struct cmd_tbl *cmdtp, int flag, int argc,
			 char * const argv[])
{
	u64 srcaddr, mod, exp;
	u32 srclen, rsaop, size, ret_payload[PAYLOAD_ARG_CNT];
	int ret;

	if (argc != cmdtp->maxargs)
		return CMD_RET_USAGE;

	if (zynqmp_firmware_version() <= PMUFW_V1_0) {
		puts("ERR: PMUFW v1.0 or less is detected\n");
		puts("ERR: Encrypt/Decrypt feature is not supported\n");
		puts("ERR: Please upgrade PMUFW\n");
		return CMD_RET_FAILURE;
	}

	srcaddr = simple_strtoul(argv[2], NULL, 16);
	srclen = simple_strtoul(argv[3], NULL, 16);
	if (srclen != RSA_KEY_SIZE) {
		puts("ERR: srclen should be equal to 0x200(512 bytes)\n");
		return CMD_RET_USAGE;
	}

	mod = simple_strtoul(argv[4], NULL, 16);
	exp = simple_strtoul(argv[5], NULL, 16);
	rsaop = simple_strtoul(argv[6], NULL, 16);
	if (!(rsaop == 0 || rsaop == 1)) {
		puts("ERR: rsaop should be either 0 or 1\n");
		return CMD_RET_USAGE;
	}

	memcpy((void *)srcaddr + srclen, (void *)mod, MODULUS_LEN);

	/*
	 * For encryption we load public exponent (key size 4096-bits),
	 * for decryption we load private exponent (32-bits)
	 */
	if (rsaop) {
		memcpy((void *)srcaddr + srclen + MODULUS_LEN,
		       (void *)exp, PUB_EXPO_LEN);
		size = srclen + MODULUS_LEN + PUB_EXPO_LEN;
	} else {
		memcpy((void *)srcaddr + srclen + MODULUS_LEN,
		       (void *)exp, PRIV_EXPO_LEN);
		size = srclen + MODULUS_LEN + PRIV_EXPO_LEN;
	}

	flush_dcache_range((ulong)srcaddr,
			   (ulong)(srcaddr) + roundup(size, ARCH_DMA_MINALIGN));

	ret = xilinx_pm_request(PM_SECURE_RSA, upper_32_bits((ulong)srcaddr),
				lower_32_bits((ulong)srcaddr), srclen, rsaop,
				ret_payload);
	if (ret || ret_payload[1]) {
		printf("Failed: RSA status:0x%x, errcode:0x%x\n",
		       ret, ret_payload[1]);
		return CMD_RET_FAILURE;
	}

	return CMD_RET_SUCCESS;
}

static int do_zynqmp_sha3(struct cmd_tbl *cmdtp, int flag,
			  int argc, char * const argv[])
{
	u64 srcaddr, hashaddr;
	u32 srclen, ret_payload[PAYLOAD_ARG_CNT];
	int ret;

	if (argc > cmdtp->maxargs || argc < (cmdtp->maxargs - 1))
		return CMD_RET_USAGE;

	if (zynqmp_firmware_version() <= PMUFW_V1_0) {
		puts("ERR: PMUFW v1.0 or less is detected\n");
		puts("ERR: Encrypt/Decrypt feature is not supported\n");
		puts("ERR: Please upgrade PMUFW\n");
		return CMD_RET_FAILURE;
	}

	srcaddr = simple_strtoul(argv[2], NULL, 16);
	srclen = simple_strtoul(argv[3], NULL, 16);

	if (argc == 5) {
		hashaddr = simple_strtoul(argv[4], NULL, 16);
		flush_dcache_range(hashaddr,
				   hashaddr + roundup(ZYNQMP_SHA3_SIZE,
						      ARCH_DMA_MINALIGN));
	} else {
		hashaddr = srcaddr;
	}

	/* Check srcaddr or srclen != 0 */
	if (!srcaddr || !srclen) {
		puts("ERR: srcaddr & srclen should not be 0\n");
		return CMD_RET_USAGE;
	}

	flush_dcache_range(srcaddr,
			   srcaddr + roundup(srclen, ARCH_DMA_MINALIGN));

	ret = xilinx_pm_request(PM_SECURE_SHA, 0, 0, 0,
				ZYNQMP_SHA3_INIT, ret_payload);
	if (ret || ret_payload[1]) {
		printf("Failed: SHA INIT status:0x%x, errcode:0x%x\n",
		       ret, ret_payload[1]);
		return CMD_RET_FAILURE;
	}

	ret = xilinx_pm_request(PM_SECURE_SHA, upper_32_bits((ulong)srcaddr),
				lower_32_bits((ulong)srcaddr),
				srclen, ZYNQMP_SHA3_UPDATE, ret_payload);
	if (ret || ret_payload[1]) {
		printf("Failed: SHA UPDATE status:0x%x, errcode:0x%x\n",
		       ret, ret_payload[1]);
		return CMD_RET_FAILURE;
	}

	ret = xilinx_pm_request(PM_SECURE_SHA, upper_32_bits((ulong)hashaddr),
				lower_32_bits((ulong)hashaddr),
				ZYNQMP_SHA3_SIZE, ZYNQMP_SHA3_FINAL,
				ret_payload);
	if (ret || ret_payload[1]) {
		printf("Failed: SHA FINAL status:0x%x, errcode:0x%x\n",
		       ret, ret_payload[1]);
		return CMD_RET_FAILURE;
	}

	return CMD_RET_SUCCESS;
}

static struct cmd_tbl cmd_zynqmp_sub[] = {
	U_BOOT_CMD_MKENT(secure, 5, 0, do_zynqmp_verify_secure, "", ""),
	U_BOOT_CMD_MKENT(pmufw, 4, 0, do_zynqmp_pmufw, "", ""),
	U_BOOT_CMD_MKENT(mmio_read, 3, 0, do_zynqmp_mmio_read, "", ""),
	U_BOOT_CMD_MKENT(mmio_write, 5, 0, do_zynqmp_mmio_write, "", ""),
	U_BOOT_CMD_MKENT(aes, 9, 0, do_zynqmp_aes, "", ""),
	U_BOOT_CMD_MKENT(rsa, 7, 0, do_zynqmp_rsa, "", ""),
	U_BOOT_CMD_MKENT(sha3, 5, 0, do_zynqmp_sha3, "", ""),
#ifdef CONFIG_DEFINE_TCM_OCM_MMAP
	U_BOOT_CMD_MKENT(tcminit, 3, 0, do_zynqmp_tcm_init, "", ""),
#endif
};

/**
 * do_zynqmp - Handle the "zynqmp" command-line command
 * @cmdtp:	Command data struct pointer
 * @flag:	Command flag
 * @argc:	Command-line argument count
 * @argv:	Array of command-line arguments
 *
 * Processes the zynqmp specific commands
 *
 * Return: return 0 on success and CMD_RET_USAGE incase of misuse and error
 */
static int do_zynqmp(struct cmd_tbl *cmdtp, int flag, int argc,
		     char *const argv[])
{
	struct cmd_tbl *c;

	if (argc < 2)
		return CMD_RET_USAGE;

	c = find_cmd_tbl(argv[1], &cmd_zynqmp_sub[0],
			 ARRAY_SIZE(cmd_zynqmp_sub));

	if (c)
		return c->cmd(c, flag, argc, argv);
	else
		return CMD_RET_USAGE;
}

/***************************************************/
#ifdef CONFIG_SYS_LONGHELP
static char zynqmp_help_text[] =
	"secure src len [key_addr] - verifies secure images of $len bytes\n"
	"                            long at address $src. Optional key_addr\n"
	"                            can be specified if user key needs to\n"
	"                            be used for decryption\n"
	"zynqmp mmio_read address - read from address\n"
	"zynqmp mmio_write address mask value - write value after masking to\n"
	"					address\n"
	"zynqmp aes srcaddr ivaddr len aesop keysrc dstaddr [keyaddr] -\n"
	"	Encrypts or decrypts blob of data at src address and puts it\n"
	"	back to dstaddr using key and iv at keyaddr and ivaddr\n"
	"	respectively. keysrc value specifies from which source key\n"
	"	has to be used, it can be User/Device/PUF key. A value of 0\n"
	"	for KUP(user key),1 for DeviceKey and 2 for PUF key. The\n"
	"	aesop value specifies the operation which can be 0 for\n"
	"	decrypt and 1 for encrypt operation\n"
#ifdef CONFIG_DEFINE_TCM_OCM_MMAP
	"zynqmp tcminit mode - Initialize the TCM with zeros. TCM needs to be\n"
	"		       initialized before accessing to avoid ECC\n"
	"		       errors. mode specifies in which mode TCM has\n"
	"		       to be initialized. Supported modes will be\n"
	"		       lock(0)/split(1)\n"
#endif
	"zynqmp pmufw address size - load PMU FW configuration object\n"
	"zynqmp rsa srcaddr srclen mod exp rsaop -\n"
	"	Performs RSA encryption and RSA decryption on blob of data\n"
	"	at srcaddr and puts it back in srcaddr using modulus and\n"
	"	public or private exponent\n"
	"	srclen : must be key size(4096 bits)\n"
	"	exp :	private key exponent for RSA decryption(4096 bits)\n"
	"		public key exponent for RSA encryption(32 bits)\n"
	"	rsaop :	0 for RSA Decryption, 1 for RSA Encryption\n"
	"zynqmp sha3 srcaddr srclen [key_addr] -\n"
	"	Generates sha3 hash value for data blob at srcaddr and puts\n"
	"	48 bytes hash value into srcaddr\n"
	"	Optional key_addr can be specified for saving sha3 hash value\n"
	"	Note: srcaddr/srclen should not be 0\n"
	;
#endif

U_BOOT_CMD(
	zynqmp, 9, 1, do_zynqmp,
	"ZynqMP sub-system",
	zynqmp_help_text
)
