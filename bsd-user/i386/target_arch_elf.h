/*
 * i386 ELF definitions
 *
 * Copyright (c) 2013 Stacey D. Son
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef TARGET_ARCH_ELF_H
#define TARGET_ARCH_ELF_H

#define ELF_ET_DYN_LOAD_ADDR    0x01001000
#define elf_check_arch(x) (((x) == EM_386) || ((x) == EM_486))

#define ELF_HWCAP       0 /* FreeBSD doesn't do AT_HWCAP{,2} on x86 */

#define ELF_CLASS       ELFCLASS32
#define ELF_DATA        ELFDATA2LSB
#define ELF_ARCH        EM_386

#define USE_ELF_CORE_DUMP
#define ELF_EXEC_PAGESIZE       4096

#endif /* TARGET_ARCH_ELF_H */
