/*
 * Top-level entry points to the Boot ROM. This includes:
 * - Reset, exception and interrupt vectors.
 * - C run-time initialization.
 * - Secondary CPU boot code.
 *
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define	KiB (1024)

#define SRAM_SIZE (128 * KiB)

	.section .text.vectors, "ax"

	.global _start
	.type _start, %function
_start:
	ldr pc, reset_addr
	. = 0x04
	b	undefined_instruction
	. = 0x08
	b	software_interrupt
	. = 0x0c
	b	prefetch_abort
	. = 0x10
	b	data_abort
	. = 0x18
	b	interrupt
	. = 0x1c
	b	fast_interrupt

	.align 2
reset_addr:
	.word reset

undefined_instruction:
	mov	r0, #1
	ldr	pc, handle_exception_addr

software_interrupt:
	mov	r0, #2
	ldr	pc, handle_exception_addr

prefetch_abort:
	mov	r0, #3
	ldr	pc, handle_exception_addr

data_abort:
	mov	r0, #4
	ldr	pc, handle_exception_addr

interrupt:
	mov	r0, #6
	ldr	pc, handle_exception_addr

fast_interrupt:
	mov	r0, #7
	ldr	pc, handle_exception_addr

handle_exception_addr:
	.word	handle_exception

vectors_end:

	. = 0xf8
chip_id:
	.word	0x00a92750

	. = 0xfc
rom_version:
	.word	0x00010055

	.text
	.align 2
handle_exception:

	.global panic
	.type panic, %function
panic:
1:	wfi
	b	1b
	.size panic, . - panic

	.type reset, %function
reset:
	mov	r0, #0
	// Read the CPU ID from MPIDR.
	mrc	p15, 0, r1, c0, c0, 5
	tst	r1, #0x03
	beq	cpu0_init

	// Not CPU0 -- clear the SCRPAD register and wait for it to change.
	ldr	r2, scrpad_addr
	str	r0, [r2]
	dsb	st
	sev
1:	wfe
	ldr	r3, [r2]
	cmp	r3, #0
	beq	1b

	// SCRPAD is no longer NULL, so jump there.
	bx	r3
	.size reset, . - reset

	.type scrpad_addr, %object
scrpad_addr:
	.word	0xF080013C
	.size scrpad_addr, . - scrpad_addr

	.type cpu0_init, %function
cpu0_init:
	ldr	r1, sram_base_addr
	add	sp, r1, #SRAM_SIZE
	
	// Copy vectors from ROM to SRAM.
	ldr	r3, rom_base_addr
	mov	r2, #0x100
1:	ldmia	r3!, {r4 - r11}
	stmia	r1!, {r4 - r11}
	subs	r2, #32
	bgt	1b

	// Copy data from ROM to SRAM.
	ldr	r3, etext_addr
	ldr	r2, edata_addr
1:	ldmia	r3!, {r4 - r11}
	stmia	r1!, {r4 - r11}
	cmp	r1, r2
	blt	1b

	// Zero the BSS section.
	ldr	r2, end_addr
1:	stmia	r1!, {r0}
	cmp	r1, r2
	blt	1b

	// Load the boot image into SRAM. Returns the entry address.
	bl	load_boot_image

	// Jump to the boot image. Panic if it returns back to us.
	blx	r0
	b	panic
	
	.size cpu0_init, . - cpu0_init
	
	.type sram_base_addr, %object
sram_base_addr:
	.word	0xFFFD0000
	.size sram_base_addr, . - sram_base_addr

	.type rom_base_addr, %object
rom_base_addr:
	.word	0xFFFF0000
	.size rom_base_addr, . - rom_base_addr

	.type etext_addr, %object
etext_addr:
	.word	_etext
	.size etext_addr, . - etext_addr

	.type edata_addr, %object
edata_addr:
	.word	_edata
	.size edata_addr, . - edata_addr

	.type end_addr, %object
end_addr:
	.word	_end
	.size end_addr, . - end_addr
