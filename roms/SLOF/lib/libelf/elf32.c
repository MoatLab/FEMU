/******************************************************************************
 * Copyright (c) 2004, 2011 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

/*
 * 32-bit ELF loader
 */
#include <stdio.h> 
#include <string.h>
#include <libelf.h>
#include <byteorder.h>
#include <helpers.h>

struct ehdr32 {
	uint32_t ei_ident;
	uint8_t ei_class;
	uint8_t ei_data;
	uint8_t ei_version;
	uint8_t ei_pad[9];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint32_t e_entry;
	uint32_t e_phoff;
	uint32_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct phdr32 {
	uint32_t p_type;
	uint32_t p_offset;
	uint32_t p_vaddr;
	uint32_t p_paddr;
	uint32_t p_filesz;
	uint32_t p_memsz;
	uint32_t p_flags;
	uint32_t p_align;
};

struct shdr32 {
	uint32_t sh_name;
	uint32_t sh_type;
	uint32_t sh_flags;
	uint32_t sh_addr;
	uint32_t sh_offset;
	uint32_t sh_size;
	uint32_t sh_link;
	uint32_t sh_info;
	uint32_t sh_addralign;
	uint32_t sh_entsize;
};

static struct phdr32*
get_phdr32(void *file_addr)
{
	return (struct phdr32 *) (((unsigned char *)file_addr)
		+ ((struct ehdr32 *)file_addr)->e_phoff);
}

static void
load_segment(void *file_addr, struct phdr32 *phdr, signed long offset,
             int (*pre_load)(void*, long),
             void (*post_load)(void*, long))
{
	unsigned long src = phdr->p_offset + (unsigned long) file_addr;
	unsigned long destaddr;

	destaddr = (unsigned long)phdr->p_paddr;
	destaddr = destaddr + offset;

	/* check if we're allowed to copy */
	if (pre_load != NULL) {
		if (pre_load((void*)destaddr, phdr->p_memsz) != 0)
			return;
	}

	/* copy into storage */
	memmove((void *)destaddr, (void *)src, phdr->p_filesz);

	/* clear bss */
	memset((void *)(destaddr + phdr->p_filesz), 0,
	       phdr->p_memsz - phdr->p_filesz);

	if (phdr->p_memsz && post_load) {
		post_load((void*)destaddr, phdr->p_memsz);
	}
}

unsigned int
elf_load_segments32(void *file_addr, signed long offset,
                    int (*pre_load)(void*, long),
                    void (*post_load)(void*, long))
{
	struct ehdr32 *ehdr = (struct ehdr32 *) file_addr;
	/* Calculate program header address */
	struct phdr32 *phdr = get_phdr32(file_addr);
	int i;

	/* loop e_phnum times */
	for (i = 0; i <= ehdr->e_phnum; i++) {
		/* PT_LOAD ? */
		if (phdr->p_type == 1) {
			if (phdr->p_paddr != phdr->p_vaddr) {
				printf("ELF32: VirtAddr(%lx) != PhysAddr(%lx) not supported, aborting\n",
					(long)phdr->p_vaddr, (long)phdr->p_paddr);
				return 0;
			}

			/* copy segment */
			load_segment(file_addr, phdr, offset, pre_load,
			             post_load);
		}
		/* step to next header */
		phdr = (struct phdr32 *)(((uint8_t *)phdr) + ehdr->e_phentsize);
	}

	/* Entry point is always a virtual address, so translate it
	 * to physical before returning it */
	return ehdr->e_entry;
}

/**
 * Return the base address for loading (i.e. the address of the first PT_LOAD
 * segment)
 * @param  file_addr	pointer to the ELF file in memory
 * @return		the base address
 */
long
elf_get_base_addr32(void *file_addr)
{
	struct ehdr32 *ehdr = (struct ehdr32 *) file_addr;
	struct phdr32 *phdr = get_phdr32(file_addr);
	int i;

	/* loop e_phnum times */
	for (i = 0; i <= ehdr->e_phnum; i++) {
		/* PT_LOAD ? */
		if (phdr->p_type == 1) {
			return phdr->p_paddr;
		}
		/* step to next header */
		phdr = (struct phdr32 *)(((uint8_t *)phdr) + ehdr->e_phentsize);
	}

	return 0;
}

uint32_t elf_get_eflags_32(void *file_addr)
{
	struct ehdr32 *ehdr = (struct ehdr32 *) file_addr;

	return ehdr->e_flags;
}

void
elf_byteswap_header32(void *file_addr)
{
	struct ehdr32 *ehdr = (struct ehdr32 *) file_addr;
	struct phdr32 *phdr;
	int i;

	bswap_16p(&ehdr->e_type);
	bswap_16p(&ehdr->e_machine);
	bswap_32p(&ehdr->e_version);
	bswap_32p(&ehdr->e_entry);
	bswap_32p(&ehdr->e_phoff);
	bswap_32p(&ehdr->e_shoff);
	bswap_32p(&ehdr->e_flags);
	bswap_16p(&ehdr->e_ehsize);
	bswap_16p(&ehdr->e_phentsize);
	bswap_16p(&ehdr->e_phnum);
	bswap_16p(&ehdr->e_shentsize);
	bswap_16p(&ehdr->e_shnum);
	bswap_16p(&ehdr->e_shstrndx);

	phdr = get_phdr32(file_addr);

	/* loop e_phnum times */
	for (i = 0; i <= ehdr->e_phnum; i++) {
		bswap_32p(&phdr->p_type);
		bswap_32p(&phdr->p_offset);
		bswap_32p(&phdr->p_vaddr);
		bswap_32p(&phdr->p_paddr);
		bswap_32p(&phdr->p_filesz);
		bswap_32p(&phdr->p_memsz);
		bswap_32p(&phdr->p_flags);
		bswap_32p(&phdr->p_align);

		/* step to next header */
		phdr = (struct phdr32 *)(((uint8_t *)phdr) + ehdr->e_phentsize);
	}
}

/*
 * Determine the size of an ELF image that has been loaded into
 * a buffer larger than its size. We search all program headers
 * and sections for the one that shows the farthest extent of the
 * file.
 * @return Return -1 on error, size of file otherwise.
 */
long elf_get_file_size32(const void *buffer, const unsigned long buffer_size)
{
	const struct ehdr32 *ehdr = (const struct ehdr32 *) buffer;
	const uint8_t *buffer_end = buffer + buffer_size;
	const struct phdr32 *phdr;
	const struct shdr32 *shdr;
	unsigned long elf_size = 0;
	uint16_t entsize;
	unsigned i;

	if (buffer_size < sizeof(struct ehdr) ||
	    ehdr->e_ehsize != sizeof(struct ehdr32))
		return -1;

	phdr = buffer + elf32_to_cpu(ehdr->e_phoff, ehdr);
	entsize = elf16_to_cpu(ehdr->e_phentsize, ehdr);
	for (i = 0; i < elf16_to_cpu(ehdr->e_phnum, ehdr); i++) {
		if (((uint8_t *)phdr) + entsize > buffer_end)
			return -1;

		elf_size = MAX(elf32_to_cpu(phdr->p_offset, ehdr) +
			         elf32_to_cpu(phdr->p_filesz, ehdr),
			       elf_size);

		/* step to next header */
		phdr = (struct phdr32 *)(((uint8_t *)phdr) + entsize);
	}

	shdr = buffer + elf32_to_cpu(ehdr->e_shoff, ehdr);
	entsize = elf16_to_cpu(ehdr->e_shentsize, ehdr);
	for (i = 0; i < elf16_to_cpu(ehdr->e_shnum, ehdr); i++) {
		if (((uint8_t *)shdr) + entsize > buffer_end)
			return -1;

		elf_size = MAX(elf32_to_cpu(shdr->sh_offset, ehdr) +
		                 elf32_to_cpu(shdr->sh_size, ehdr),
		               elf_size);

		/* step to next header */
		shdr = (struct shdr32 *)(((uint8_t *)shdr) + entsize);
	}

	elf_size = ROUNDUP(elf_size, 4);
	if (elf_size > buffer_size)
		return -1;

	return (long) elf_size;
}
