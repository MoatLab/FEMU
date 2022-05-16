// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2013-2019 IBM Corp.
 */

#include <config.h>
#include <mem-map.h>

/* Debug sections from binutils `ld --verbose` */

#define DEBUG_SECTIONS							\
  /* Stabs debugging sections.  */					\
  .stab          0 : { *(.stab) }					\
  .stabstr       0 : { *(.stabstr) }					\
  .stab.excl     0 : { *(.stab.excl) }					\
  .stab.exclstr  0 : { *(.stab.exclstr) }				\
  .stab.index    0 : { *(.stab.index) }					\
  .stab.indexstr 0 : { *(.stab.indexstr) }				\
  .comment       0 : { *(.comment) }					\
  /* DWARF debug sections.						\
     Symbols in the DWARF debugging sections are relative to the beginning \
     of the section so we begin them at 0.  */				\
  /* DWARF 1 */								\
  .debug          0 : { *(.debug) }					\
  .line           0 : { *(.line) }					\
  /* GNU DWARF 1 extensions */						\
  .debug_srcinfo  0 : { *(.debug_srcinfo) }				\
  .debug_sfnames  0 : { *(.debug_sfnames) }				\
  /* DWARF 1.1 and DWARF 2 */						\
  .debug_aranges  0 : { *(.debug_aranges) }				\
  .debug_pubnames 0 : { *(.debug_pubnames) }				\
  /* DWARF 2 */								\
  .debug_info     0 : { *(.debug_info .gnu.linkonce.wi.*) }		\
  .debug_abbrev   0 : { *(.debug_abbrev) }				\
  .debug_line     0 : { *(.debug_line .debug_line.* .debug_line_end ) }	\
  .debug_frame    0 : { *(.debug_frame) }				\
  .debug_str      0 : { *(.debug_str) }					\
  .debug_loc      0 : { *(.debug_loc) }					\
  .debug_macinfo  0 : { *(.debug_macinfo) }				\
  /* SGI/MIPS DWARF 2 extensions */					\
  .debug_weaknames 0 : { *(.debug_weaknames) }				\
  .debug_funcnames 0 : { *(.debug_funcnames) }				\
  .debug_typenames 0 : { *(.debug_typenames) }				\
  .debug_varnames  0 : { *(.debug_varnames) }				\
  /* DWARF 3 */								\
  .debug_pubtypes 0 : { *(.debug_pubtypes) }				\
  .debug_ranges   0 : { *(.debug_ranges) }				\
  /* DWARF Extension.  */						\
  .debug_macro    0 : { *(.debug_macro) }				\
  .debug_addr     0 : { *(.debug_addr) }

ENTRY(boot_entry);
SECTIONS
{
	_start = .;
	. = 0;

	.head : {
		KEEP(*(.head))
	}

	. = NACA_OFF;
	.naca : {
		KEEP(*(.naca.data))
	}

	. = SPIRA_OFF;
	.spira : {
		KEEP(*(.spira.data))
	}

	. = SPIRAH_OFF;
	.spirah : {
		KEEP(*(.spirah.data))
	}

	_head_end = .;
	. = ALIGN(PAGE_SIZE);

	/*
	 * The following sections are read-write at runtime. We need
	 * to skip over them when checksumming the skiboot images
	 * before a fast-reboot.
	 */
	. = PROC_DUMP_AREA_OFF;
	.procdump : {
		KEEP(*(.procdump.data))
	}

	. = PROCIN_OFF;
	.procin.data : {
		KEEP(*(.procin.data))
	}

	. = MDST_TABLE_OFF;
	.mdst : {
		KEEP(*(.mdst.data))
	}

	. = MDDT_TABLE_OFF;
	.mddt : {
		KEEP(*(.mddt.data))
	}

	. = CPU_CTL_OFF;
	.cpuctrl : {
		KEEP(*(.cpuctrl.data))
	}

	/* ...and back to RO */
	. = ALIGN(PAGE_SIZE);
	_stext = .;
 	.text : {
		*(.text*)
		*(.sfpr .glink)
	}
	_etext = .;
	. = ALIGN(PAGE_SIZE);

	.rodata : {
		__rodata_start = .;
		*(.rodata .rodata.*)
		__rodata_end = .;
	}

	. = ALIGN(0x10);
	.trap_table : {
		__trap_table_start = .;
		KEEP(*(.trap_table))
		__trap_table_end = .;
	}

	. = ALIGN(0x10);
	.init : {
		__ctors_start = .;
		KEEP(*(.ctors*))
		KEEP(*(SORT(.init_array.*)))
		KEEP(*(.init_array))
		__ctors_end = .;
	}

	. = ALIGN(0x10);
	.opd : {
		*(.opd)
	}
  
	. = ALIGN(0x100);
	.got : {
		__toc_start = . + 0x8000;
		*(.got)
		*(.toc)
	}

	. = ALIGN(0x10);
	.opal_table : {
		__opal_table_start = .;
		KEEP(*(.opal_table))
		__opal_table_end = .;
	}

	.platforms : {
		__platforms_start = .;
		KEEP(*(.platforms))
		__platforms_end = .;
	}

	/* Relocations */
	. = ALIGN(0x10);
	.dynamic : {
		__dynamic_start = .;
		*(.dynamic)
		__dynamic_end = .;
	}

	. = ALIGN(0x10);
	.rela.dyn : {
		__rela_dyn_start = .;
		*(.rela*)
		__rela_dyn_end = .;
	}

	.hash          : { *(.hash)   }
	.gnu.hash      : { *(.gnu.hash) }
	.gnu.version   : { *(.gnu.version) }
	.gnu.version_d : { *(.gnu.version_d) }
	.gnu.version_r : { *(.gnu.version_r) }

	. = ALIGN(0x10);
	.sym_map : {
		__sym_map_start = . ;
		KEEP(*(.sym_map))
		__sym_map_end = . ;
	}

	/*
	 * Memory above this point should be un-changing after the OS
	 * boots, and is verified with a checksum upon fast reboot.
	 */
	_romem_end = .;

	. = ALIGN(PAGE_SIZE);

	_sdata = .;
	.data : {
		/*
		 * A couple of things that need to be 4K aligned and
		 * to reside in their own pages for the sake of TCE
		 * mappings, so use PAGE_SIZE alignment.
		 */
		. = ALIGN(PAGE_SIZE);
		*(.data.memcons);
		. = ALIGN(PAGE_SIZE);
		*(.data.boot_trace);
		. = ALIGN(PAGE_SIZE);
		*(.data*)
		*(.force.data)
		*(.toc1)
		*(.branch_lt)
	}
	_edata = .;

	/* We locate the BSS at 5M to leave room for the symbol map */
	. = 0x500000;

	_sbss = .;
	.bss : {
		*(.dynbss)
		*(.bss*)
	}
	. = ALIGN(PAGE_SIZE);
	_ebss = .;
	_end = .;

	ASSERT((HEAP_BASE - SKIBOOT_BASE) >= _end, "Heap collision with image")

	/* Optional kernel image */
       . = ALIGN(PAGE_SIZE);
       .builtin_kernel : {
		__builtin_kernel_start = .;
		KEEP(*(.builtin_kernel))
		__builtin_kernel_end = .;
	}

	DEBUG_SECTIONS

	/* Discards */
	/DISCARD/ : {
		*(.note.GNU-stack)
		*(.comment)
		*(.eh_frame)
		*(.interp)
		*(.fini_array.*)
		*(.dynsym)
		*(.dynstr)
		*(.plt)
		*(.iplt)
	}
}
