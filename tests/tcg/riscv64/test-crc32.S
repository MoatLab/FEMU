/*
 * Copyright (c) 2026 lowRISC CIC
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define crc32(op, rd, rs1) .insn r 19, 1, 48, rd, rs1, x##op

#define crc32_b(rd, rs1) crc32(16, rd, rs1)
#define crc32_h(rd, rs1) crc32(17, rd, rs1)
#define crc32_w(rd, rs1) crc32(18, rd, rs1)
#define crc32_d(rd, rs1) crc32(19, rd, rs1)
#define crc32c_b(rd, rs1) crc32(24, rd, rs1)
#define crc32c_h(rd, rs1) crc32(25, rd, rs1)
#define crc32c_w(rd, rs1) crc32(26, rd, rs1)
#define crc32c_d(rd, rs1) crc32(27, rd, rs1)

	.option norvc

	.text
	.globl _start
_start:
	lla t0, trap
	csrw mtvec, t0

	li	t0, 0x34e24a2cd65650d4

	crc32_b 	(t0, t0)
	crc32_h 	(t0, t0)
	crc32_w 	(t0, t0)
	crc32_d 	(t0, t0)
	crc32c_b	(t0, t0)
	crc32c_h	(t0, t0)
	crc32c_w	(t0, t0)
	crc32c_d	(t0, t0)

	li	t1, 0x68167e78

	li	a0, 0
	beq	t0, t1, _exit
fail:
	li	a0, 1
_exit:
	lla	a1, semiargs
	li	t0, 0x20026	# ADP_Stopped_ApplicationExit
	sd	t0, 0(a1)
	sd	a0, 8(a1)
	li	a0, 0x20	# TARGET_SYS_EXIT_EXTENDED

	# Semihosting call sequence
	.balign	16
	slli	zero, zero, 0x1f
	ebreak
	srai	zero, zero, 0x7
	j	.

	.data
	.balign	16
semiargs:
	.space	16

trap:
	csrr t0, mepc
	addi t0, t0, 4
	mret
