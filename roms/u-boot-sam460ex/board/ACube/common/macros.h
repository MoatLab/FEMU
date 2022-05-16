
#ifndef _MACROS_H
#define _MACROS_H

	/*
	** Load a long integer into a register
	*/
      	.macro liw reg, value
                lis \reg, \value@h
                ori \reg, \reg, \value@l
        .endm


	/* 
	** Generate config_addr request
	** This macro expects the values in registers:
	** r3 - bus
	** r4 - devfn
	** r5 - offset
	*/
	.macro config_addr 	
		rlwinm	r9, r5, 2, 0, 31 
		rlwinm	r8, r4, 8, 0, 31
		rlwinm	r7, r3, 16, 0, 31
		or	r9, r8, r9
		or	r9, r7, r9
		oris	r9, r9, 0x8000
		liw	r10, 0xeec00000
		stw	r9, 0(r10)
		eieio
		sync
	.endm

	
	/*
	** Generate config_data address
	*/
	.macro config_data mask
		andi.	r9, r5, \mask
		addi	r9, r9, 0x004
		oris	r9, r9, 0xeec0
	.endm


	/*
	** Write a byte value to an output port
	*/
        .macro outb port, value
                lis     r2, 0xe800
                li      r0, \value
                stb     r0, \port(r2)
        .endm


	/*
	** Write a register byte value to an output port
	*/
        .macro outbr port, value
                lis     r2, 0xe800
                stb     \value, \port(r2)
        .endm


	/* 
	** Read a byte value from a port into a specified register
	*/
        .macro inb reg, port
                lis     r2, 0xe800
                lbz     \reg, \port(r2)
        .endm


	/*
	** Write a byte to the SuperIO config area
	*/
        .macro siowb offset, value
                li      r3, 0
                li      r4, (7<<3)
                li      r5, \offset
                li      r6, \value
                bl      pci_write_cfg_byte
        .endm

#endif
