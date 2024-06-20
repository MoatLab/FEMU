#include "parisc/hppa_hardware.h"

#if BITS == 64
OUTPUT_FORMAT("elf64-hppa-linux")
OUTPUT_ARCH(hppa:hppa2.0w)
#else
OUTPUT_FORMAT("elf32-hppa-linux")
OUTPUT_ARCH(hppa)
#endif
ENTRY(startup)
SECTIONS
{
#if BITS == 64
	/* limit firmware high bits to physical addresses to allow debug info */
	. = ((FIRMWARE_HIGH & 0x3ffffff0) << 32) + FIRMWARE_START;
#else
	. = FIRMWARE_START;
#endif

	/* align on next page boundary */
	. = ALIGN(4096);
	.text :	{
		_text = .;	/* Text */
		*(.head.text)
		*(.text)
		*(.text.*)
		_etext = . ;
	}

        . = ALIGN(4096);
        .sti : {
                _sti_rom_start = .;
                *(.sti.hdr)
                *(.sti.text.init_graph)
                *(.sti.text.state_mgmt)
                *(.sti.text.font_unpmv)
                *(.sti.text.block_move)
                *(.sti.text.self_test)
                *(.sti.text.excep_hdlr)
                *(.sti.text.inq_conf)
                *(.sti.text.set_cm_entry)
                *(.sti.text.dma_ctrl)
                *(.sti.text)
                *(.sti.data)
                *(.sti.font)
                *(.sti.text.end)
                . = ALIGN(4096);
                _sti_rom_end = .;
        }

#if BITS == 64
	. = ALIGN(16);
	.opd : {
		__start_opd = .;
		*(.opd)
		__end_opd = .;
	} PROVIDE (__gp = .);
	.plt : {
		*(.plt)
	}
	.dlt : {
		*(.dlt)
	}
#endif

	. = ALIGN(8);
	.rodata : {
		_rodata = . ;
		*(.rodata)	 /* read-only data */
		*(.rodata.*)
		_erodata = . ;
	}
	. = ALIGN(8);
	.data :	{
		_data = . ;
		*(.data)
		*(.data.*)
		_edata = . ;
	}
	. = ALIGN(8);
	.bss : {
		_bss = . ;
		*(.bss)
		*(.bss.*)
		*(COMMON)
		_ebss = .;
	}

	/* STABS_DEBUG */
	.note 0 : { *(.note) }

	/* Sections to be discarded */
	/DISCARD/ : {
	}
}
