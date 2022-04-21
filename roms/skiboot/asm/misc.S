// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Misc asm functions
 *
 * Copyright 2013-2014 IBM Corp.
 */

#include <asm-utils.h>
#include <asm-offsets.h>
#include <processor.h>
#include <stack.h>
#include <opal-api.h>

#define OLD_BINUTILS 1

	.section ".rodata"
	/* This is the OPAL branch table. It's populated at boot time
	 * with function pointers to the various OPAL functions from
	 * the content of the .opal_table section, indexed by Token.
	 */
.global opal_branch_table
opal_branch_table:
	.space	8 * (OPAL_LAST + 1)

	.section ".text","ax"
	.balign	0x10

.global enable_machine_check
enable_machine_check:
	mflr	%r0
	bcl	20,31,$+4
0:	mflr	%r3
	addi	%r3,%r3,(1f - 0b)
	mtspr	SPR_HSRR0,%r3
	mfmsr	%r3
	ori	%r3,%r3,MSR_ME
	mtspr	SPR_HSRR1,%r3
	hrfid
1:	mtlr	%r0
	blr

.global disable_machine_check
disable_machine_check:
	mflr	%r0
	bcl	20,31,$+4
0:	mflr	%r3
	addi	%r3,%r3,(1f - 0b)
	mtspr	SPR_HSRR0,%r3
	mfmsr	%r3
	li	%r4,MSR_ME
	andc	%r3,%r3,%r4
	mtspr	SPR_HSRR1,%r3
	hrfid
1:	mtlr	%r0
	blr

	/* void set_hid0(unsigned long hid0) */
.global set_hid0
set_hid0:
	sync
	mtspr	SPR_HID0,%r3
	mfspr	%r3,SPR_HID0
	mfspr	%r3,SPR_HID0
	mfspr	%r3,SPR_HID0
	mfspr	%r3,SPR_HID0
	mfspr	%r3,SPR_HID0
	mfspr	%r3,SPR_HID0
	isync
	blr

.global __trigger_attn
__trigger_attn:
	sync
	isync
	attn
	blr

#ifdef STACK_CHECK_ENABLED
.global _mcount
_mcount:
	mr	%r3,%r1
	mflr	%r4
	b	__mcount_stack_check
#endif

	.global cleanup_local_tlb
cleanup_local_tlb:
	/* Clean the TLB */
	li	%r3,512
	mtctr	%r3
	li	%r4,0xc00		/* IS field = 0b11 */
	ptesync
1:	tlbiel	%r4
	addi	%r4,%r4,0x1000
	bdnz	1b
	ptesync
	blr

	.global cleanup_global_tlb
cleanup_global_tlb:

	/* Only supported on P9, P10 for now */
	mfspr	%r3,SPR_PVR
	srdi	%r3,%r3,16
	cmpwi	cr0,%r3,PVR_TYPE_P9
	beq	cr0,1f
	cmpwi	cr0,%r3,PVR_TYPE_P9P
	beq	cr0,1f
	cmpwi	cr0,%r3,PVR_TYPE_P10
	beq	cr0,1f
	blr

	/* Sync out previous updates */
1:	ptesync

#ifndef OLD_BINUTILS
	.machine "power9"
#endif
	/* Lead RB with IS=11 */
	li	%r3,3
	sldi	%r3,%r3,10
	li	%r0,0

	/* Blow up radix partition scoped translations */
#ifdef OLD_BINUTILS
	.long   0x7c0b1a64
#else
	tlbie	%r3, %r0 /* rs */, 2 /* ric */, 1 /* prs */, 1 /* r */
#endif
	eieio
	tlbsync
	ptesync
#ifdef OLD_BINUTILS
	.long   0x7c091a64
#else
	tlbie	%r3, %r0 /* rs */, 2 /* ric */, 0 /* prs */, 1 /* r */
#endif
	eieio
	tlbsync
	ptesync

	/* Blow up hash partition scoped translations */
#ifdef OLD_BINUTILS
	.long   0x7c0a1a64
#else
	tlbie	%r3, %r0 /* rs */, 2 /* ric */, 1 /* prs */, 0 /* r */
#endif
	eieio
	tlbsync
	ptesync
#ifdef OLD_BINUTILS
	.long   0x7c081a64
#else
	tlbie	%r3, %r0 /* rs */, 2 /* ric */, 0 /* prs */, 0 /* r */
#endif
	eieio
	tlbsync
	ptesync

	blr


/* Power management instructions */
#define PPC_INST_NAP		.long 0x4c000364
#define PPC_INST_SLEEP		.long 0x4c0003a4
#define PPC_INST_RVWINKLE	.long 0x4c0003e4

#define PPC_INST_STOP		.long 0x4c0002e4
#define PPC_INST_URFID		.long 0x4c000264

#define SAVE_GPR(reg,sp)	std %r##reg,STACK_GPR##reg(sp)
#define REST_GPR(reg,sp)	ld %r##reg,STACK_GPR##reg(sp)

pm_save_regs:
	SAVE_GPR(2,%r1)
	SAVE_GPR(14,%r1)
	SAVE_GPR(15,%r1)
	SAVE_GPR(16,%r1)
	SAVE_GPR(17,%r1)
	SAVE_GPR(18,%r1)
	SAVE_GPR(19,%r1)
	SAVE_GPR(20,%r1)
	SAVE_GPR(21,%r1)
	SAVE_GPR(22,%r1)
	SAVE_GPR(23,%r1)
	SAVE_GPR(24,%r1)
	SAVE_GPR(25,%r1)
	SAVE_GPR(26,%r1)
	SAVE_GPR(27,%r1)
	SAVE_GPR(28,%r1)
	SAVE_GPR(29,%r1)
	SAVE_GPR(30,%r1)
	SAVE_GPR(31,%r1)
	mfcr	%r4
	mfxer	%r5
	mfspr	%r6,SPR_HSPRG0
	mfspr	%r7,SPR_HSPRG1
	stw	%r4,STACK_CR(%r1)
	stw	%r5,STACK_XER(%r1)
	std	%r6,STACK_GPR0(%r1)
	std	%r7,STACK_GPR1(%r1)
	blr

.global enter_p8_pm_state
enter_p8_pm_state:
	/* Before entering map or rvwinkle, we create a stack frame
	 * and save our non-volatile registers.
	 *
	 * We also save these SPRs:
	 *
	 *  - HSPRG0	in GPR0 slot
	 *  - HSPRG1	in GPR1 slot
	 *
	 *  - xxx TODO: HIDs
	 *  - TODO: Mask MSR:ME during the process
	 *
	 * On entry, r3 indicates:
	 *
	 *    0 = nap
	 *    1 = rvwinkle
	 */
	mflr	%r0
	std	%r0,16(%r1)
	stdu	%r1,-STACK_FRAMESIZE(%r1)

	bl	pm_save_regs

	/* Save stack pointer in struct cpu_thread */
	std	%r1,CPUTHREAD_SAVE_R1(%r16)

	/* Winkle or nap ? */
	cmpli	%cr0,0,%r3,0
	bne	1f

	/* nap sequence */
	ptesync
0:	ld	%r0,CPUTHREAD_SAVE_R1(%r16)
	cmpd	cr0,%r0,%r0
	bne	0b
	PPC_INST_NAP
	b	.

	/* rvwinkle sequence */
1:	ptesync
0:	ld	%r0,CPUTHREAD_SAVE_R1(%r16)
	cmpd	cr0,%r0,%r0
	bne	0b
	PPC_INST_RVWINKLE
	b	.

.global enter_p9_pm_lite_state
enter_p9_pm_lite_state:
	mtspr	SPR_PSSCR,%r3
	PPC_INST_STOP
	blr

.global enter_p9_pm_state
enter_p9_pm_state:
	mflr	%r0
	std	%r0,16(%r1)
	stdu	%r1,-STACK_FRAMESIZE(%r1)

	bl	pm_save_regs

	/* Save stack pointer in struct cpu_thread */
	std	%r1,CPUTHREAD_SAVE_R1(%r16)

	mtspr	SPR_PSSCR,%r3
	PPC_INST_STOP
	b	.

/*
 * Exit UV mode and disable Protected Execution Facility.
 *
 * For each core, this should be run on all secondary threads first to bring
 * them out of UV mode.  Then, it is called by the primary thread to disable
 * PEF and bring it out of UV mode. All threads will then be running in HV
 * mode and the only way to re-enable UV mode is with a reboot.
 *
 * r3 = 1 if primary thread
 *      0 if secondary thread
 */
.global exit_uv_mode
exit_uv_mode:
	mfmsr	%r4
	LOAD_IMM64(%r5, ~MSR_S)
	and	%r4,%r4,%r5
	mtspr	SPR_USRR1,%r4

	mfspr   %r4,SPR_HSRR1
	and     %r4,%r4,%r5
	mtspr   SPR_HSRR1,%r3

	mfspr   %r4,SPR_SRR1
	and     %r4,%r4,%r5
	mtspr   SPR_SRR1,%r4

	cmpdi	%r3,1
	bne	1f
	mfspr   %r4, SPR_SMFCTRL
	LOAD_IMM64(%r5, ~PPC_BIT(0))
	and     %r4,%r4,%r5
	mtspr   SPR_SMFCTRL,%r4
1:
	isync

	mflr	%r4
	mtspr	SPR_USRR0,%r4

	PPC_INST_URFID
