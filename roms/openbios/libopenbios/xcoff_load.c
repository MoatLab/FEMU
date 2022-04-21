/*
 *
 *       <xcoff_load.c>
 *
 *       XCOFF file loader
 *
 *   Copyright (C) 2009 Laurent Vivier (Laurent@vivier.eu)
 *
 *   from original XCOFF loader by Steven Noonan <steven@uplinklabs.net>
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   version 2
 *
 */

#include "config.h"
#include "libopenbios/bindings.h"
#include "libopenbios/initprogram.h"
#include "libopenbios/xcoff_load.h"
#include "libc/diskio.h"

#include "arch/common/xcoff.h"

#ifdef CONFIG_PPC
extern void             flush_icache_range( char *start, char *stop );
#endif

//#define DEBUG_XCOFF

#ifdef DEBUG_XCOFF
#define DPRINTF(fmt, args...) \
    do { printk("%s: " fmt, __func__ , ##args); } while (0)
#else
#define DPRINTF(fmt, args...) \
    do { } while (0)
#endif

int 
is_xcoff(COFF_filehdr_t *fhdr)
{
	return (fhdr->f_magic == U802WRMAGIC
            || fhdr->f_magic == U802ROMAGIC
	    || fhdr->f_magic == U802TOCMAGIC
	    || fhdr->f_magic == U802TOMAGIC);
}

int 
xcoff_load(ihandle_t dev)
{
	COFF_filehdr_t fhdr;
	COFF_aouthdr_t ahdr;
	COFF_scnhdr_t shdr;
	uint32_t offset;
	size_t total_size = 0;
	int fd, i;
	int retval = -1;
	
	/* Mark the saved-program-state as invalid */
	feval("0 state-valid !");

	fd = open_ih(dev);
	if (fd == -1) {
		retval = LOADER_NOT_SUPPORT;
		goto out;
	}
	
	for (offset = 0; offset < 16 * 512; offset += 512) {
		seek_io(fd, offset);
		if (read_io(fd, &fhdr, sizeof fhdr) != sizeof fhdr) {
			DPRINTF("Can't read XCOFF header\n");
			retval = LOADER_NOT_SUPPORT;
			goto out;
		}
		
		if (is_xcoff(&fhdr))
			break;
	}
	
	/* Is it executable ? */
	if (fhdr.f_magic != 0x01DF &&
	    (fhdr.f_flags & COFF_F_EXEC) == 0) {
		DPRINTF("Not an executable XCOFF file %02x\n", fhdr.f_flags);
		return LOADER_NOT_SUPPORT;
	}

	/* Optional header is a.out ? */
	if (fhdr.f_opthdr != sizeof(COFF_aouthdr_t)) {
		DPRINTF("AOUT optional error size mismatch in XCOFF file\n");
		return LOADER_NOT_SUPPORT;
	}
	
	seek_io(fd, sizeof(COFF_filehdr_t));
	read_io(fd, &ahdr, sizeof(COFF_aouthdr_t));
	
	/* check a.out magic number */
	if (ahdr.magic != AOUT_MAGIC) {
		DPRINTF("Invalid AOUT optional header\n");
		return LOADER_NOT_SUPPORT;
	}

	offset = sizeof(COFF_filehdr_t) + sizeof(COFF_aouthdr_t);

	DPRINTF("XCOFF file with %d sections\n", fhdr.f_nscns);

	for (i = 0; i < fhdr.f_nscns; i++) {
		DPRINTF("Read header at offset %0x\n", offset);
		seek_io(fd, offset);
		read_io(fd, &shdr, sizeof(COFF_scnhdr_t));

		DPRINTF("Initializing '%s' section from %0x %0x to %0x (%0x)\n",
			shdr.s_name, offset, shdr.s_scnptr,
			shdr.s_vaddr, shdr.s_size);

		if (strcmp(shdr.s_name, ".text") == 0) {
			read_io(fd, (void *)shdr.s_vaddr, shdr.s_size);
			total_size += shdr.s_size;
#ifdef CONFIG_PPC
			flush_icache_range((char*)(uintptr_t)shdr.s_vaddr,
					 (char*)(uintptr_t)(shdr.s_vaddr + shdr.s_size));
#endif
		} else if (strcmp(shdr.s_name, ".data") == 0) {
			read_io(fd, (void *)shdr.s_vaddr, shdr.s_size);
			total_size += shdr.s_size;

		} else if (strcmp(shdr.s_name, ".bss") == 0) {
			memset((void *)(uintptr_t)shdr.s_vaddr, 0, shdr.s_size);
			total_size += shdr.s_size;
		} else {
			DPRINTF("    Skip '%s' section\n", shdr.s_name);
		}
		offset += sizeof(COFF_scnhdr_t);
	}

	DPRINTF("XCOFF entry point: %x\n", *(uint32_t*)ahdr.entry);

	// Initialise load-state
	PUSH(total_size);
	feval("load-state >ls.file-size !");
	feval("xcoff load-state >ls.file-type !");

out:
	close_io(fd);
	return retval;
}

void
xcoff_init_program(void)
{
	char *base;
	COFF_filehdr_t *fhdr;
	COFF_aouthdr_t *ahdr;
	COFF_scnhdr_t *shdr;
	uint32_t offset;
	size_t total_size = 0;
	int i;

	feval("load-base");
	base = (char*)cell2pointer(POP());

	fhdr = (COFF_filehdr_t*)base;

	/* Is it an XCOFF file ? */
	if (!is_xcoff(fhdr)) {
		DPRINTF("Not a XCOFF file %02x\n", fhdr->f_magic);
		return;
	}

	/* Is it executable ? */
	if (fhdr->f_magic != 0x01DF &&
	    (fhdr->f_flags & COFF_F_EXEC) == 0) {
		DPRINTF("Not an executable XCOFF file %02x\n", fhdr->f_flags);
		return;
	}

	/* Optional header is a.out ? */
	if (fhdr->f_opthdr != sizeof(COFF_aouthdr_t)) {
		DPRINTF("AOUT optional error size mismatch in XCOFF file\n");
		return;
	}

        ahdr = (COFF_aouthdr_t*)(base + sizeof(COFF_filehdr_t));

	/* check a.out magic number */
	if (ahdr->magic != AOUT_MAGIC) {
		DPRINTF("Invalid AOUT optional header\n");
		return;
	}

	offset = sizeof(COFF_filehdr_t) + sizeof(COFF_aouthdr_t);

	DPRINTF("XCOFF file with %d sections\n", fhdr->f_nscns);

	for (i = 0; i < fhdr->f_nscns; i++) {

		DPRINTF("Read header at offset %0x\n", offset);

		shdr = (COFF_scnhdr_t*)(base + offset);

		DPRINTF("Initializing '%s' section from %0x %0x to %0x (%0x)\n",
			shdr->s_name, offset, shdr->s_scnptr,
			shdr->s_vaddr, shdr->s_size);

		if (strcmp(shdr->s_name, ".text") == 0) {

			memcpy((char*)(uintptr_t)shdr->s_vaddr, base + shdr->s_scnptr,
			       shdr->s_size);
			total_size += shdr->s_size;
#ifdef CONFIG_PPC
			flush_icache_range((char*)(uintptr_t)shdr->s_vaddr,
					 (char*)(uintptr_t)(shdr->s_vaddr + shdr->s_size));
#endif
		} else if (strcmp(shdr->s_name, ".data") == 0) {

			memcpy((char*)(uintptr_t)shdr->s_vaddr, base + shdr->s_scnptr,
			       shdr->s_size);
			total_size += shdr->s_size;

		} else if (strcmp(shdr->s_name, ".bss") == 0) {

			memset((void *)(uintptr_t)shdr->s_vaddr, 0, shdr->s_size);
			total_size += shdr->s_size;
		} else {
			DPRINTF("    Skip '%s' section\n", shdr->s_name);
		}
		offset += sizeof(COFF_scnhdr_t);
	}

	DPRINTF("XCOFF entry point: %x\n", *(uint32_t*)ahdr->entry);

	// Initialise load-state
	PUSH(*(uint32_t*)(uintptr_t)ahdr->entry);
	feval("load-state >ls.entry !");
	feval("xcoff load-state >ls.file-type !");

	arch_init_program();
	
	feval("-1 state-valid !");
}
