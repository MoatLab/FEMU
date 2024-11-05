// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Test the SRESET OPAL call in Mambo by
 * having a bit of fun printing 'Hello World' from the SRESET vector.
 *
 * Copyright 2013-2017 IBM Corp.
 */

	. = 0x0
	.globl _start
_start:
/*
 * Save some values passed in from skiboot into registers that are
 * non-volatile over OPAL calls.
 *   r8 is the OPAL base
 *   r9 is the OPAL entry point point
 */
	mr	%r13, %r8
	mr	%r14, %r9

	bl	here
here:	mflr	%r8 /* work out where we are running */
	subi	%r8, %r8, here - _start
	/* Stash OPAL base and entry point somewhere SRESET can find it */
	li	%r6, 0xe0
	std	%r13, 0(%r6)
	std	%r14, 8(%r6)
	std	%r8, 16(%r6)
	addi	%r6, %r8, sreset_code_end - _start
	addi	%r7, %r8, sreset_code - _start
	li	%r10, 0x100
c:
	lwa	%r9, 0(%r7)
	stw	%r9, 0(%r10)
	addi	%r7,%r7,4
	addi	%r10,%r10,4
	cmpd	%r7,%r6
	bne	c
	sync
	icbi	0,%r0
	sync
	isync
	
	li	%r0, 1 /* OPAL_CONSOLE_WRITE */
	li	%r3, 0 /* terminal 0 */
	addi	%r4, %r8, len - _start /* ptr to length of string */
	addi	%r5, %r8, str - _start /* ptr to string start */
	mr	%r2, %r13
	mtctr	%r14
	bctrl

	li	%r0, 145 /* OPAL_SIGNAL_SYSTEM_RESET */
	li	%r3, -2 /* All *OTHER* CPUs */
	mr	%r2, %r13
	mtctr	%r14
	bctrl

	/* We shouldn't get here but if we do, just wait here */
	b	.

sreset_code:
	li	%r6, 0xe0
	ld	%r13, 0(%r6)
	ld	%r14, 8(%r6)
	ld	%r8, 16(%r6) /* "here" */
        li      %r0, 1 /* OPAL_CONSOLE_WRITE */
        li      %r3, 0 /* terminal 0 */
	li	%r4, len2 - _start
	li	%r5, str2 - _start
        add     %r4, %r8, %r4
        add     %r5, %r8, %r5
        mr      %r2, %r13
        mtctr   %r14
        bctrl
	li	%r0, 5 /* OPAL_CEC_POWER_DOWN */
	li	%r3, 0 /* normal shutdown */
	mr	%r2, %r13
	mtctr	%r14
	bctrl

	/* We shouldn't get here but if we do, just wait here */
	b	.

sreset_code_end:

len:
	.long 0x00
	.long (strend - str)
str:
	.string "Hello World!\n"
strend:

len2:
	.long 0x00
	.long (str2end - str2)
str2:
	.string "Hello SRESET!\n"
str2end:

