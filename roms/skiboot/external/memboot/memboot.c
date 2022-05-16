// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * The old way of booting a temporary f/w image.
 * These days, use mboxd on a BMC.
 *
 * Copyright 2013-2015 IBM Corp.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

/* Where to put the firmware image if booting from memory */
#define MEM_IMG_BASE (0x5c000000)

/* Start of flash memory if booting from flash */
#define FLASH_IMG_BASE (0x30000000)

/* LPC registers */
#define LPC_BASE		0x1e789000
#define LPC_HICR6		0x80
#define LPC_HICR7		0x88
#define LPC_HICR8		0x8c
#define LPC_SCR0SIO		0x170

#define MEMBOOT_SIO_VERSION_FLAG 0x42
#define MEMBOOT_SIO_FLAG	(0x10 << 8)

uint32_t readl(void *addr)
{
	asm volatile("" : : : "memory");
	return *(volatile uint32_t *)addr;
}

void writel(uint32_t val, void *addr)
{
	asm volatile("" : : : "memory");
	*(volatile uint32_t *)addr = val;
}

void copy_flash_img(int mem_fd, int flash_fd, unsigned int size)
{
	static void *memimg, *fwimg;
	size_t pagesize = getpagesize();

	memimg = mmap(NULL, ((size/pagesize)+1)*pagesize,
		      PROT_READ | PROT_WRITE, MAP_SHARED, mem_fd, MEM_IMG_BASE);
	if (memimg == MAP_FAILED) {
		perror("Unable to map image destination memory");
		exit(1);
	}

	fwimg = mmap(NULL,size, PROT_READ, MAP_SHARED, flash_fd, 0);
	if (fwimg == MAP_FAILED) {
		perror("Unable to open image source memory");
		exit(1);
	}

	/* Copy boot image */
	memcpy(memimg, fwimg, size);
}

void boot_firmware_image(int mem_fd, char *filename)
{
	int fw_fd;
	struct stat st;

	fw_fd = open(filename, O_RDONLY);
	if (fw_fd < 0) {
		perror("Unable to open flash image\n");
		exit(1);
	}

	if (stat(filename, &st)) {
		perror("Unable to determine size of firmware image");
		exit(1);
	}

	if (st.st_size > 32*1024*1024) {
		fprintf(stderr, "Flash too large (> 32MB)");
		exit(1);
	}

	copy_flash_img(mem_fd, fw_fd, st.st_size);
	close(fw_fd);
}

int main(int argc, char *argv[])
{
	int mem_fd;
	void *lpcreg;
	uint32_t lpc_scr0sio_val;
	uint32_t lpc_hicr7_val = (FLASH_IMG_BASE | 0xe00);

	if (argc > 2) {
		printf("Usage: %s <flash image>\n", argv[0]);
		exit(1);
	}

	mem_fd = open("/dev/mem", O_RDWR | O_SYNC);
	if (mem_fd < 0) {
		perror("Unable to open /dev/mem");
		exit(1);
	}

	lpcreg = mmap(NULL, getpagesize(),
		      PROT_READ | PROT_WRITE, MAP_SHARED, mem_fd, LPC_BASE);
	if (lpcreg == MAP_FAILED) {
		perror("Unable to map LPC register memory");
		exit(1);
	}

	lpc_scr0sio_val = readl(lpcreg+LPC_SCR0SIO);
	lpc_scr0sio_val &= ~0xff;
	lpc_scr0sio_val |= MEMBOOT_SIO_VERSION_FLAG;
	lpc_scr0sio_val &= ~MEMBOOT_SIO_FLAG;

	if (argc == 2) {
		boot_firmware_image(mem_fd, argv[1]);
		lpc_hicr7_val = (MEM_IMG_BASE | 0xe00);

		/* Set the boot mode scratch register to indicate a memboot */
		lpc_scr0sio_val |= MEMBOOT_SIO_FLAG;
		printf("Booting from memory after power cycle\n");
	}

	if (readl(lpcreg + LPC_HICR7) != lpc_hicr7_val) {
		printf("Resetting LPC_HICR7 to 0x%x\n", lpc_hicr7_val);
		writel(lpc_hicr7_val, lpcreg+LPC_HICR7);
	}

	/* Set the magic value */
	writel(0x42, lpcreg+LPC_SCR0SIO);

	writel(lpc_scr0sio_val, lpcreg+LPC_SCR0SIO);
	printf("LPC_HICR7 = 0x%x\n", lpc_hicr7_val);
	return 0;
}
