#include "parisc/hppa_hardware.h"

OUTPUT_FORMAT("elf32-hppa-linux")
OUTPUT_ARCH(hppa)
ENTRY(startup)
SECTIONS
{
	. = FIRMWARE_START;

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
