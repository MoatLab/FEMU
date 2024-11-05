// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2015 IBM Corp. */

#ifndef __ELF_H
#define __ELF_H

#include <stdint.h>
#include <types.h>

/* Generic ELF header */
struct elf_hdr {
	uint32_t ei_ident;
#if HAVE_BIG_ENDIAN
#define ELF_IDENT	0x7F454C46
#else
#define ELF_IDENT	0x464C457F
#endif
	uint8_t ei_class;
#define ELF_CLASS_32	1
#define ELF_CLASS_64	2
	uint8_t ei_data;
#define ELF_DATA_LSB	1
#define ELF_DATA_MSB	2
	uint8_t ei_version;
	uint8_t ei_pad[9];
};

#define ELF_MACH_PPC32	0x14
#define ELF_MACH_PPC64	0x15

/* 64-bit ELF header */
struct elf64be_hdr {
	uint32_t ei_ident;
	uint8_t ei_class;
	uint8_t ei_data;
	uint8_t ei_version;
	uint8_t ei_pad[9];
	__be16 e_type;
	__be16 e_machine;
	__be32 e_version;
	__be64 e_entry;
	__be64 e_phoff;
	__be64 e_shoff;
	__be32 e_flags;
	__be16 e_ehsize;
	__be16 e_phentsize;
	__be16 e_phnum;
	__be16 e_shentsize;
	__be16 e_shnum;
	__be16 e_shstrndx;
};

/* 64-bit ELF program header */
struct elf64be_phdr {
	__be32 p_type;
#define ELF_PTYPE_LOAD	1
	__be32 p_flags;
#define ELF_PFLAGS_R	0x4
#define ELF_PFLAGS_W	0x2
#define ELF_PFLAGS_X	0x1
	__be64 p_offset;
	__be64 p_vaddr;
	__be64 p_paddr;
	__be64 p_filesz;
	__be64 p_memsz;
	__be64 p_align;
};

/* 64-bit ELF section header */
struct elf64be_shdr {
	__be32 sh_name;
	__be32 sh_type;
	__be64 sh_flags;
#define ELF_SFLAGS_X	0x4
#define ELF_SFLAGS_A	0x2
#define ELF_SFLAGS_W	0x1
	__be64 sh_addr;
	__be64 sh_offset;
	__be64 sh_size;
	__be32 sh_link;
	__be32 sh_info;
	__be64 sh_addralign;
	__be64 sh_entsize;
};

/* 32-bit ELF header */
struct elf32be_hdr {
	uint32_t ei_ident;
	uint8_t ei_class;
	uint8_t ei_data;
	uint8_t ei_version;
	uint8_t ei_pad[9];
	__be16 e_type;
	__be16 e_machine;
	__be32 e_version;
	__be32 e_entry;
	__be32 e_phoff;
	__be32 e_shoff;
	__be32 e_flags;
	__be16 e_ehsize;
	__be16 e_phentsize;
	__be16 e_phnum;
	__be16 e_shentsize;
	__be16 e_shnum;
	__be16 e_shstrndx;
};

/* 32-bit ELF program header*/
struct elf32be_phdr {
	__be32 p_type;
	__be32 p_offset;
	__be32 p_vaddr;
	__be32 p_paddr;
	__be32 p_filesz;
	__be32 p_memsz;
	__be32 p_flags;
	__be32 p_align;
};

/* 64-bit ELF header */
struct elf64le_hdr {
	uint32_t ei_ident;
	uint8_t ei_class;
	uint8_t ei_data;
	uint8_t ei_version;
	uint8_t ei_pad[9];
	__le16 e_type;
	__le16 e_machine;
	__le32 e_version;
	__le64 e_entry;
	__le64 e_phoff;
	__le64 e_shoff;
	__le32 e_flags;
	__le16 e_ehsize;
	__le16 e_phentsize;
	__le16 e_phnum;
	__le16 e_shentsize;
	__le16 e_shnum;
	__le16 e_shstrndx;
};

/* 64-bit ELF program header */
struct elf64le_phdr {
	__le32 p_type;
#define ELF_PTYPE_LOAD	1
	__le32 p_flags;
#define ELF_PFLAGS_R	0x4
#define ELF_PFLAGS_W	0x2
#define ELF_PFLAGS_X	0x1
	__le64 p_offset;
	__le64 p_vaddr;
	__le64 p_paddr;
	__le64 p_filesz;
	__le64 p_memsz;
	__le64 p_align;
};

/* 64-bit ELF section header */
struct elf64le_shdr {
	__le32 sh_name;
	__le32 sh_type;
	__le64 sh_flags;
#define ELF_SFLAGS_X	0x4
#define ELF_SFLAGS_A	0x2
#define ELF_SFLAGS_W	0x1
	__le64 sh_addr;
	__le64 sh_offset;
	__le64 sh_size;
	__le32 sh_link;
	__le32 sh_info;
	__le64 sh_addralign;
	__le64 sh_entsize;
};

/* 32-bit ELF header */
struct elf32le_hdr {
	uint32_t ei_ident;
	uint8_t ei_class;
	uint8_t ei_data;
	uint8_t ei_version;
	uint8_t ei_pad[9];
	__le16 e_type;
	__le16 e_machine;
	__le32 e_version;
	__le32 e_entry;
	__le32 e_phoff;
	__le32 e_shoff;
	__le32 e_flags;
	__le16 e_ehsize;
	__le16 e_phentsize;
	__le16 e_phnum;
	__le16 e_shentsize;
	__le16 e_shnum;
	__le16 e_shstrndx;
};

/* 32-bit ELF program header*/
struct elf32le_phdr {
	__le32 p_type;
	__le32 p_offset;
	__le32 p_vaddr;
	__le32 p_paddr;
	__le32 p_filesz;
	__le32 p_memsz;
	__le32 p_flags;
	__le32 p_align;
};


/* Some relocation related stuff used in relocate.c */
struct elf64_dyn {
	int64_t	 d_tag;
#define DT_NULL	 	0
#define DT_RELA	 	7
#define DT_RELASZ	8
#define DT_RELAENT	9
#define DT_RELACOUNT	0x6ffffff9
	uint64_t d_val;
};

struct elf64_rela {
	uint64_t	r_offset;
	uint64_t	r_info;
#define ELF64_R_TYPE(info)		((info) & 0xffffffffu)
	int64_t		r_addend;
};

/* relocs we support */
#define R_PPC64_RELATIVE	22


#endif /* __ELF_H */
