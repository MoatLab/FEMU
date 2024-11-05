// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2017 IBM Corp. */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <libflash/libflash.h>
#include <libflash/libflash-priv.h>

#include "../libflash.c"
#include "../ecc.c"

#define __unused		__attribute__((unused))

#define ERR(fmt...) fprintf(stderr, fmt)

/* Flash commands */
#define CMD_PP		0x02
#define CMD_READ	0x03
#define CMD_WRDI	0x04
#define CMD_RDSR	0x05
#define CMD_WREN	0x06
#define CMD_SE		0x20
#define CMD_RDSCUR	0x2b
#define CMD_BE32K	0x52
#define CMD_CE		0x60
#define CMD_RDID	0x9f
#define CMD_EN4B	0xb7
#define CMD_BE		0xd8
#define CMD_RDDPB	0xe0
#define CMD_RDSPB	0xe2
#define CMD_EX4B	0xe9

/* Flash status bits */
#define STAT_WIP	0x01
#define STAT_WEN	0x02

static uint8_t *sim_image;
static uint32_t sim_image_sz = 0x100000;
static uint32_t sim_index;
static uint32_t sim_addr;
static uint32_t sim_er_size;
static uint8_t sim_sr;
static bool sim_fl_4b;
static bool sim_ct_4b;

static enum sim_state {
	sim_state_idle,
	sim_state_rdid,
	sim_state_rdsr,
	sim_state_read_addr,
	sim_state_read_data,
	sim_state_write_addr,
	sim_state_write_data,
	sim_state_erase_addr,
	sim_state_erase_done,
} sim_state;

/*
 * Simulated flash & controller
 */
static int sim_start_cmd(uint8_t cmd)
{
	if (sim_state != sim_state_idle) {
		ERR("SIM: Command %02x in wrong state %d\n", cmd, sim_state);
		return -1;
	}

	sim_index = 0;
	sim_addr = 0;

	switch(cmd) {
	case CMD_RDID:
		sim_state = sim_state_rdid;
		break;
	case CMD_RDSR:
		sim_state = sim_state_rdsr;
		break;
	case CMD_EX4B:
		sim_fl_4b = false;
		break;
	case CMD_EN4B:
		sim_fl_4b = true;
		break;
	case CMD_WREN:
		sim_sr |= STAT_WEN;
		break;
	case CMD_READ:
		sim_state = sim_state_read_addr;
		if (sim_ct_4b != sim_fl_4b)
			ERR("SIM: 4b mode mismatch in READ !\n");
		break;
	case CMD_PP:
		sim_state = sim_state_write_addr;
		if (sim_ct_4b != sim_fl_4b)
			ERR("SIM: 4b mode mismatch in PP !\n");
		if (!(sim_sr & STAT_WEN))
			ERR("SIM: PP without WEN, ignoring... \n");
		break;
	case CMD_SE:
	case CMD_BE32K:
	case CMD_BE:
		if (sim_ct_4b != sim_fl_4b)
			ERR("SIM: 4b mode mismatch in SE/BE !\n");
		if (!(sim_sr & STAT_WEN))
			ERR("SIM: SE/BE without WEN, ignoring... \n");
		sim_state = sim_state_erase_addr;
		switch(cmd) {
		case CMD_SE:	sim_er_size = 0x1000; break;
		case CMD_BE32K:	sim_er_size = 0x8000; break;
		case CMD_BE:	sim_er_size = 0x10000; break;
		}
		break;
	case CMD_CE:
		if (!(sim_sr & STAT_WEN)) {
			ERR("SIM: CE without WEN, ignoring... \n");
			break;
		}
		memset(sim_image, 0xff, sim_image_sz);
		sim_sr |= STAT_WIP;
		sim_sr &= ~STAT_WEN;
		break;
	default:
		ERR("SIM: Unsupported command %02x\n", cmd);
		return -1;
	}
	return 0;
}

static void sim_end_cmd(void)
{
	/* For write and sector/block erase, set WIP & clear WEN here */
	if (sim_state == sim_state_write_data) {
		sim_sr |= STAT_WIP;
		sim_sr &= ~STAT_WEN;
	}
	sim_state = sim_state_idle;
}

static bool sim_do_address(const uint8_t **buf, uint32_t *len)
{
	uint8_t asize = sim_fl_4b ? 4 : 3;
	const uint8_t *p = *buf;

	while(*len) {
		sim_addr = (sim_addr << 8) | *(p++);
		*buf = p;
		*len = *len - 1;
		sim_index++;
		if (sim_index >= asize)
			return true;
	}
	return false;
}
			
static int sim_wbytes(const void *buf, uint32_t len)
{
	const uint8_t *b = buf;
	bool addr_complete;

 again:
	switch(sim_state) {
	case sim_state_read_addr:
		addr_complete = sim_do_address(&b, &len);
		if (addr_complete) {
			sim_state = sim_state_read_data;
			sim_index = 0;
			if (len)
				goto again;
		}
		break;
	case sim_state_write_addr:
		addr_complete = sim_do_address(&b, &len);
		if (addr_complete) {
			sim_state = sim_state_write_data;
			sim_index = 0;
			if (len)
				goto again;
		}
		break;
	case sim_state_write_data:
		if (!(sim_sr & STAT_WEN))
			break;
		while(len--) {
			uint8_t c = *(b++);
			if (sim_addr >= sim_image_sz) {
				ERR("SIM: Write past end of flash\n");
				return -1;
			}
			/* Flash write only clears bits */
			sim_image[sim_addr] &= c;
			sim_addr = (sim_addr & 0xffffff00) |
				((sim_addr + 1) & 0xff);
		}
		break;
	case sim_state_erase_addr:
		if (!(sim_sr & STAT_WEN))
			break;
		addr_complete = sim_do_address(&b, &len);
		if (addr_complete) {
			memset(sim_image + sim_addr, 0xff, sim_er_size);
			sim_sr |= STAT_WIP;
			sim_sr &= ~STAT_WEN;
			sim_state = sim_state_erase_done;
		}
		break;
	default:
		ERR("SIM: Write in wrong state %d\n", sim_state);
		return -1;
	}
	return 0;
}

static int sim_rbytes(void *buf, uint32_t len)
{
	uint8_t *b = buf;

	switch(sim_state) {
	case sim_state_rdid:
		while(len--) {
			switch(sim_index) {
			case 0:
				*(b++) = 0x55;
				break;
			case 1:
				*(b++) = 0xaa;
				break;
			case 2:
				*(b++) = 0x55;
				break;
			default:
				ERR("SIM: RDID index %d\n", sim_index);
				*(b++) = 0;
				break;
			}
			sim_index++;
		}
		break;
	case sim_state_rdsr:
		while(len--) {
			*(b++) = sim_sr;
			if (sim_index > 0)
				ERR("SIM: RDSR index %d\n", sim_index);
			sim_index++;

			/* If WIP was 1, clear it, ie, simulate write/erase
			 * completion
			 */
			sim_sr &= ~STAT_WIP;
		}
		break;
	case sim_state_read_data:
		while(len--) {
			if (sim_addr >= sim_image_sz) {
				ERR("SIM: Read past end of flash\n");
				return -1;
			}
			*(b++) = sim_image[sim_addr++];
		}
		break;
	default:
		ERR("SIM: Read in wrong state %d\n", sim_state);
		return -1;
	}
	return 0;
}

static int sim_send_addr(uint32_t addr)
{
	const void *ap;

	/* Layout address MSB first in memory */
	addr = cpu_to_be32(addr);

	/* Send the right amount of bytes */
	ap = (char *)&addr;

	if (sim_ct_4b)
		return sim_wbytes(ap, 4);
	else
		return sim_wbytes(ap + 1, 3);
}

static int sim_cmd_rd(struct spi_flash_ctrl *ctrl __unused, uint8_t cmd,
		      bool has_addr, uint32_t addr, void *buffer,
		      uint32_t size)
{
	int rc;

	rc = sim_start_cmd(cmd);
	if (rc)
		goto bail;
	if (has_addr) {
		rc = sim_send_addr(addr);
		if (rc)
			goto bail;
	}
	if (buffer && size)
		rc = sim_rbytes(buffer, size);
 bail:
	sim_end_cmd();
	return rc;
}

static int sim_cmd_wr(struct spi_flash_ctrl *ctrl __unused, uint8_t cmd,
		      bool has_addr, uint32_t addr, const void *buffer,
		      uint32_t size)
{
	int rc;

	rc = sim_start_cmd(cmd);
	if (rc)
		goto bail;
	if (has_addr) {
		rc = sim_send_addr(addr);
		if (rc)
			goto bail;
	}
	if (buffer && size)
		rc = sim_wbytes(buffer, size);
 bail:
	sim_end_cmd();
	return rc;
}

static int sim_set_4b(struct spi_flash_ctrl *ctrl __unused, bool enable)
{
	sim_ct_4b = enable;

	return 0;
}

static int sim_read(struct spi_flash_ctrl *ctrl __unused, uint32_t pos,
		    void *buf, uint32_t len)
{
	if (sim_ct_4b != sim_fl_4b)
		ERR("SIM: 4b mode mismatch in autoread !\n");
	if ((pos + len) < pos)
		return -1;
	if ((pos + len) > sim_image_sz)
		return -1;
	memcpy(buf, sim_image + pos, len);
	return 0;
};

struct spi_flash_ctrl sim_ctrl = {
	.cmd_wr = sim_cmd_wr,
	.cmd_rd = sim_cmd_rd,
	.set_4b = sim_set_4b,
	.read = sim_read,
};

int main(void)
{
	struct blocklevel_device *bl;
	uint64_t total_size;
	uint32_t erase_granule;
	const char *name;
	uint16_t *test;
	struct ecc64 *ecc_test;
	uint64_t *test64;
	int i, rc;

	sim_image = malloc(sim_image_sz);
	memset(sim_image, 0xff, sim_image_sz);
	test = malloc(0x10000 * 2);

	rc = flash_init(&sim_ctrl, &bl, NULL);
	if (rc) {
		ERR("flash_init failed with err %d\n", rc);
		exit(1);
	}
	rc = flash_get_info(bl, &name, &total_size, &erase_granule);
	if (rc) {
		ERR("flash_get_info failed with err %d\n", rc);
		exit(1);
	}

	/* Make up a test pattern */
	for (i=0; i<0x10000;i++)
		test[i] = cpu_to_be16(i);

	/* Write 64k of stuff at 0 and at 128k */
	printf("Writing test patterns...\n");
	flash_smart_write(bl, 0, test, 0x10000);
	flash_smart_write(bl, 0x20000, test, 0x10000);

	/* Write "Hello world" straddling the 64k boundary */
#define HW "Hello World"
	printf("Writing test string...\n");
	flash_smart_write(bl, 0xfffc, HW, sizeof(HW));

	/* Check result */
	if (memcmp(sim_image + 0xfffc, HW, sizeof(HW))) {
		ERR("Test string mismatch !\n");
		exit(1);
	}
	printf("Test string pass\n");
	if (memcmp(sim_image, test, 0xfffc)) {
		ERR("Test pattern mismatch !\n");
		exit(1);
	}
	printf("Test pattern pass\n");

	printf("Test ECC interfaces\n");
	flash_smart_write_corrected(bl, 0, test, 0x10000, 1);
	ecc_test = (struct ecc64 *)sim_image;
	test64 = (uint64_t *)test;
	for (i = 0; i < 0x10000 / sizeof(*ecc_test); i++) {
		if (test64[i] != ecc_test[i].data) {
			ERR("flash_smart_write_corrected() pattern missmatch at %d: 0x%016lx vs 0x%016lx\n",
					i, test64[i], ecc_test[i].data);
			exit(1);
		}
		if (ecc_test[i].ecc != eccgenerate(be64toh(test64[i]))) {
			ERR("ECCs don't match 0x%02x vs 0x%02x\n", ecc_test[i].ecc, eccgenerate(test64[i]));
			exit(1);
		}
	}
	printf("Test ECC interface pass\n");

	printf("Test ECC erase\n");
	if (flash_erase(bl, 0, 0x10000) != 0) {
		ERR("flash_erase didn't return 0\n");
		exit(1);
	}

	for (i = 0; i < 0x10000 / sizeof(*ecc_test); i++) {
		uint8_t zero = 0;
		if (ecc_test[i].data != 0xFFFFFFFFFFFFFFFF) {
			ERR("Data not properly cleared at %d\n", i);
			exit(1);
		}
		rc = flash_write(bl, i * sizeof(*ecc_test) + 8, &zero, 1, 0);
		if (rc || ecc_test[i].ecc != 0) {
			ERR("Cleared data not correctly ECCed: 0x%02x (0x%016lx) expecting 0 at %d\n", ecc_test[i].ecc, ecc_test[i].data, i);
			exit(1);
		}
	}
	printf("Test ECC erase pass\n");

	flash_exit(bl);
	free(test);

	return 0;
}
