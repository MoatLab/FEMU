// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * OPAL Entry points (and related code)
 *
 * Copyright 2013-2019 IBM Corp.
 */

#include <asm-utils.h>
#include <asm-offsets.h>
#include <mem-map.h>
#include <processor.h>
#include <opal-api.h>
#include <stack.h>

#define EPAPR_MAGIC	0x65504150

#define GET_STACK(stack_reg,pir_reg)					\
	sldi	stack_reg,pir_reg,STACK_SHIFT;				\
	addis	stack_reg,stack_reg,CPU_STACKS_OFFSET@ha;		\
	addi	stack_reg,stack_reg,CPU_STACKS_OFFSET@l;

#define GET_EMERGENCY_STACK(stack_reg,pir_reg)				\
	sldi	stack_reg,pir_reg,STACK_SHIFT;				\
	addis	stack_reg,stack_reg,EMERGENCY_CPU_STACKS_OFFSET@ha;	\
	addi	stack_reg,stack_reg,EMERGENCY_CPU_STACKS_OFFSET@l;

#define GET_CPU()							\
	clrrdi	%r16,%r1,STACK_SHIFT

#define SAVE_GPR(reg,sp)	std %r##reg,STACK_GPR##reg(sp)
#define REST_GPR(reg,sp)	ld %r##reg,STACK_GPR##reg(sp)

	.section ".head","ax"

	. = 0
.global __head
__head:
	trap

	/* This entry point is used when booting with a flat device-tree
	 * pointer in r3
	 */
	. = 0x10
.global fdt_entry
fdt_entry:
	FIXUP_ENDIAN
	mr	%r27,%r3
	b	boot_entry

	/* This is a pointer to a descriptor used by debugging tools
	 * on the service processor to get to various trace buffers
	 */
	. = 0x80
	.llong	debug_descriptor

	/* This is our boot semaphore used for CPUs to sync, it has to be
	 * at an easy to locate address (without relocation) since we
	 * need to get at it very early, before we apply our relocs
	 */
	. = 0xf0
boot_sem:
	.long	0

	/* And this is a boot flag used to kick secondaries into the
	 * main code.
	 */
boot_flag:
	.long	0

	/* This is used to trigger an assert() and in turn an ATTN
	 * in skiboot when a special sequence is written at this
	 * address. For testing purposes only.
	 */
	. = 0xf8
.global attn_trigger
attn_trigger:
	.long	0

	/* This is the host initiated reset trigger for test */
	. = 0xfc
.global hir_trigger
hir_trigger:
	.long	0

	/*
	 * At 0x100 and 0x180 reside our entry points. Once started,
	 * we will ovewrite them with our actual 0x100 exception handler
	 * used for recovering from rvw or nap mode
	 */
	. = 0x100
sreset_vector:
	/* BML entry, load up r3 with device tree location */
	FIXUP_ENDIAN
	li	%r3, 0
	oris	%r3, %r3, 0xa
	b	fdt_entry /* hack for lab boot */

	/* Entry point set by the FSP */
	.= 0x180
hdat_entry:
	FIXUP_ENDIAN
	li	%r27,0
	b	boot_entry

	.= 0x200
	mtsprg0	%r3
	mtsprg1 %r4
	mfspr	%r3,SPR_SRR1
	mfcr	%r4
	rldicl.	%r3,%r3,48,62
	bne	1f		/* powersave wakeup (CFAR not required) */
	mtcr	%r4
	mfspr	%r3,SPR_CFAR
	li	%r4,0x200
	b	_exception
1:
	cmpdi	%r3,0x1
	bne	2f		/* state loss */
	LOAD_IMM32(%r3, reset_resume - __head)
	b	3f
2:
	LOAD_IMM32(%r3, reset_wakeup - __head)
3:
	LOAD_IMM64(%r5, SKIBOOT_BASE)
	add	%r3,%r5,%r3
	mtctr	%r3
	li	%r3,0x200
	bctr

#define EXCEPTION(nr)		\
	.= nr			;\
	mtsprg0	%r3		;\
	mfspr	%r3,SPR_CFAR	;\
	mtsprg1 %r4		;\
	li	%r4,nr		;\
	b	_exception

	/* More exception stubs */
	EXCEPTION(0x300)
	EXCEPTION(0x380)
	EXCEPTION(0x400)
	EXCEPTION(0x480)
	EXCEPTION(0x500)
	EXCEPTION(0x600)
	EXCEPTION(0x700)
	EXCEPTION(0x800)
	EXCEPTION(0x900)
	EXCEPTION(0x980)
	EXCEPTION(0xa00)
	EXCEPTION(0xb00)
	EXCEPTION(0xc00)
	EXCEPTION(0xd00)
	EXCEPTION(0xe00)
	EXCEPTION(0xe20)
	EXCEPTION(0xe40)
	EXCEPTION(0xe60)
	EXCEPTION(0xe80)
	EXCEPTION(0xf00)
	EXCEPTION(0xf20)
	EXCEPTION(0xf40)
	EXCEPTION(0xf60)
	EXCEPTION(0xf80)
	EXCEPTION(0x1000)
	EXCEPTION(0x1100)
	EXCEPTION(0x1200)
	EXCEPTION(0x1300)
	EXCEPTION(0x1400)
	EXCEPTION(0x1500)
	EXCEPTION(0x1600)

	.= 0x1e00
_exception:
	stdu	%r1,-INT_FRAMESIZE(%r1)
	std	%r3,STACK_CFAR(%r1)
	std	%r4,STACK_TYPE(%r1)
	mfspr	%r3,SPR_SRR0
	mfspr	%r4,SPR_SRR1
	std	%r3,STACK_SRR0(%r1)
	std	%r3,16(%r1)
	std	%r4,STACK_SRR1(%r1)
	mfspr	%r3,SPR_DSISR
	mfspr	%r4,SPR_DAR
	stw	%r3,STACK_DSISR(%r1)
	std	%r4,STACK_DAR(%r1)
	mfmsr	%r3
	li	%r4,MSR_RI
	std	%r3,STACK_MSR(%r1)
	mtmsrd	%r4,1
	mfspr	%r3,SPR_HSRR0
	mfspr	%r4,SPR_HSRR1
	std	%r3,STACK_HSRR0(%r1)
	std	%r4,STACK_HSRR1(%r1)
	mfsprg0	%r3
	mfsprg1 %r4
	SAVE_GPR(0,%r1)
	SAVE_GPR(1,%r1)
	SAVE_GPR(2,%r1)
	SAVE_GPR(3,%r1)
	SAVE_GPR(4,%r1)
	SAVE_GPR(5,%r1)
	SAVE_GPR(6,%r1)
	SAVE_GPR(7,%r1)
	SAVE_GPR(8,%r1)
	SAVE_GPR(9,%r1)
	SAVE_GPR(10,%r1)
	SAVE_GPR(11,%r1)
	SAVE_GPR(12,%r1)
	SAVE_GPR(13,%r1)
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
	mfcr	%r3
	mfxer	%r4
	mfctr	%r5
	mflr	%r6
	stw	%r3,STACK_CR(%r1)
	stw	%r4,STACK_XER(%r1)
	std	%r5,STACK_CTR(%r1)
	std	%r6,STACK_LR(%r1)
	LOAD_IMM64(%r3,STACK_INT_MAGIC)
	std	%r3,STACK_MAGIC(%r1)
	LOAD_IMM64(%r4, SKIBOOT_BASE)
	LOAD_IMM32(%r5,__toc_start - __head)
	LOAD_IMM32(%r6, exception_entry_foo - __head)
	add	%r2,%r4,%r5
	mr	%r3,%r1
	add	%r4,%r4,%r6
	mtctr	%r4
	bctr
exception_entry_foo:
	bl	exception_entry
	/* Restore HSRRs in case a NMI interrupted an HSRR-live section
	 * and the NMI uses HSRRs for something. Possibly does not happen
	 * in current skiboot code, but good to be careful.
	 */
	ld	%r3,STACK_HSRR0(%r1)
	ld	%r4,STACK_HSRR1(%r1)
	mtspr	SPR_HSRR0,%r3
	mtspr	SPR_HSRR1,%r4
	lwz	%r3,STACK_CR(%r1)
	lwz	%r4,STACK_XER(%r1)
	ld	%r5,STACK_CTR(%r1)
	ld	%r6,STACK_LR(%r1)
	mtcr	%r3
	mtxer	%r4
	mtctr	%r5
	mtlr	%r6
	REST_GPR(0,%r1)
	REST_GPR(2,%r1)
	REST_GPR(4,%r1)
	REST_GPR(5,%r1)
	REST_GPR(6,%r1)
	REST_GPR(7,%r1)
	REST_GPR(8,%r1)
	REST_GPR(9,%r1)
	REST_GPR(10,%r1)
	REST_GPR(11,%r1)
	REST_GPR(12,%r1)
	REST_GPR(13,%r1)
	REST_GPR(14,%r1)
	REST_GPR(15,%r1)
	REST_GPR(16,%r1)
	REST_GPR(17,%r1)
	REST_GPR(18,%r1)
	REST_GPR(19,%r1)
	REST_GPR(20,%r1)
	REST_GPR(21,%r1)
	REST_GPR(22,%r1)
	REST_GPR(23,%r1)
	REST_GPR(24,%r1)
	REST_GPR(25,%r1)
	REST_GPR(26,%r1)
	REST_GPR(27,%r1)
	REST_GPR(28,%r1)
	REST_GPR(29,%r1)
	REST_GPR(30,%r1)
	REST_GPR(31,%r1)
	li	%r3,0
	mtmsrd	%r3,1	/* Clear MSR[RI] */
	ld	%r3,STACK_SRR0(%r1)
	mtspr	SPR_SRR0,%r3
	ld	%r3,STACK_SRR1(%r1)
	mtspr	SPR_SRR1,%r3
	REST_GPR(3,%r1)
	addi	%r1,%r1,INT_FRAMESIZE
	rfid
	b	.

	.= EXCEPTION_VECTORS_END

/* Stores the offset we were started from.  Used later on if we want to
 * read any unrelocated code/data such as the built-in kernel image
 */
.global boot_offset
boot_offset:
        .llong   0

/*
 *
 * Boot time entry point from FSP
 *
 * All CPUs come here
 *
 * Boot code NV register usage:
 *
 *   r31 :  Boot PIR
 *   r30 :  Current running offset
 *   r29 :  Target address
 *   r28 :  PVR
 *   r27 :  DTB pointer (or NULL)
 *   r26 :  PIR thread mask
 *   r25 :  P9/10 fused core flag
 */
.global boot_entry
boot_entry:
	/* Check PVR and set some CR bits */
	mfspr	%r28,SPR_PVR
	li	%r26,3	/* Default to SMT4 */
	srdi	%r3,%r28,16
	cmpwi	cr0,%r3,PVR_TYPE_P8
	beq	2f
	cmpwi	cr0,%r3,PVR_TYPE_P8E
	beq	2f
	cmpwi	cr0,%r3,PVR_TYPE_P8NVL
	beq	2f
	cmpwi	cr0,%r3,PVR_TYPE_P9
	beq 	3f
	cmpwi	cr0,%r3,PVR_TYPE_P9P
	beq 	3f
	cmpwi	cr0,%r3,PVR_TYPE_P10
	beq 	4f
	attn		/* Unsupported CPU type... what do we do ? */
	b 	.	/* loop here, just in case attn is disabled */

	/* Check for fused core and set flag */
3:
	li	%r3, 0x1e0
	mtspr   SPR_SPRC, %r3
	mfspr	%r3, SPR_SPRD
	andi.	%r25, %r3, 1
	beq 1f
	b   2f

4:      /*
	 * P10 fused core check (SPRC/SPRD method does not work).
	 * PVR bit 12 set = normal code
	 */
	andi.	%r3, %r28, 0x1000
	bne	1f
	li	%r25, 1

	/* P8 or P9 fused or P10 fused -> 8 threads */

2:	li	%r26,7

	/* Get our reloc offset into r30 */
1:	bcl	20,31,$+4
1:	mflr	%r30
	subi	%r30,%r30,(1b - __head)

	/* Store reloc offset in boot_offset */
	LOAD_IMM32(%r3, boot_offset - __head)
	add     %r3,%r3,%r30
	std     %r30,0(%r3)

	/* Get ourselves a TOC & relocate it to our target address */
	LOAD_IMM32(%r2,__toc_start - __head)
	LOAD_IMM64(%r29, SKIBOOT_BASE)
	add	%r2,%r2,%r29

	/* Fixup our MSR (remove TA) */
#if HAVE_BIG_ENDIAN
	LOAD_IMM64(%r3, (MSR_HV | MSR_SF))
#else
	LOAD_IMM64(%r3, (MSR_HV | MSR_SF | MSR_LE))
#endif
	mtmsrd	%r3,0

	mfspr	%r31,SPR_PIR

	andi.	%r3,%r25,1
	bne	fused

	/* Apply core-mask PIR */
	and	%r0,%r31,%r26

	/* t0 is primary for small-core */
	cmpdi	%r0,0
	bne	secondary_wait

	/* Initialize per-core SPRs */
	bl	init_shared_sprs
	b	go_primary

fused:
	/* Apply core-mask PIR */
	ori	%r0,%r26,1	/* include both sub-cores in the core mask */
	and	%r0,%r31,%r0

	/* If fused, t0, t1 are primaries for sub-cores */
	cmpdi	%r0,0
	bne	1f
	bl	init_shared_sprs
	b	go_primary /* but only t0 can be a boot CPU */
1:
	cmpdi	%r0,1
	bne	secondary_wait
	bl	init_shared_sprs
	b	secondary_wait

go_primary:
	/* Pick a boot CPU, cpu index in r31 */
	LOAD_IMM32(%r3, boot_sem - __head)
	add	%r3,%r3,%r30
1:	lwarx	%r4,0,%r3
	addi	%r0,%r4,1
	stwcx.	%r0,0,%r3
	bne	1b
	isync
	cmpwi	cr0,%r4,0
	bne	secondary_wait

	/* Make sure we are in SMT medium */
	smt_medium

	/* Initialize thread SPRs */
	bl	init_replicated_sprs

	/* Save the initial offset. The secondary threads will spin on boot_flag
	 * before relocation so we need to keep track of its location to wake
	 * them up.
	 */
	mr	%r18,%r30

	/* Check if we need to copy ourselves up and update %r30 to
	 * be our new offset
	 */
	cmpd	%r29,%r30
	beq	2f
	LOAD_IMM32(%r3, _sbss - __head)
	srdi	%r3,%r3,3
	mtctr	%r3
	mr	%r4,%r30
	mr	%r30,%r29
	/* copy the skiboot image to the new offset */
1:	ld	%r0,0(%r4)
	std	%r0,0(%r29)
	addi	%r29,%r29,8
	addi	%r4,%r4,8
	bdnz	1b
	/* flush caches, etc */
	sync
	icbi	0,%r29
	sync
	isync
	/* branch to the new image location and continue */
	LOAD_IMM32(%r3, 2f - __head)
	add	%r3,%r3,%r30
	mtctr	%r3
	bctr

	/* Get ready for C code: get a stack */
2:	GET_STACK(%r1,%r31)

	/* Clear up initial frame.
	 * Zero back chain indicates stack entry from boot,
	 * non-zero indicates entry from OS (see backtrace code).
	 */
	li	%r3,0
	std	%r3,0(%r1)
	std	%r3,8(%r1)
	std	%r3,16(%r1)

	/* Relocate ourselves */
	bl	call_relocate

	/* Tell secondaries to move to second stage (relocated) spin loop */
	LOAD_IMM32(%r3, boot_flag - __head)
	add	%r3,%r3,%r18
	li	%r0,1
	stw	%r0,0(%r3)

	/* Clear BSS */
	li	%r0,0
	LOAD_ADDR_FROM_TOC(%r3, _sbss)
	LOAD_ADDR_FROM_TOC(%r4, _ebss)
	subf	%r4,%r3,%r4
	srdi	%r4,%r4,3
	mtctr	%r4
1:	std	%r0,0(%r3)
	addi	%r3,%r3,8
	bdnz	1b

	/* Get our per-cpu pointer into r16 */
	GET_CPU()

#ifdef STACK_CHECK_ENABLED
	/* Initialize stack bottom mark to 0, it will be updated in C code */
	li	%r0,0
	std	%r0,CPUTHREAD_STACK_BOT_MARK(%r16)
#endif
	/* Initialize the stack guard */
	LOAD_IMM64(%r3,STACK_CHECK_GUARD_BASE);
	xor	%r3,%r3,%r31
	std	%r3,0(%r16)

	/* Jump to C */
	mr	%r3,%r27
	bl	main_cpu_entry
	b	.

	/* Secondary CPUs wait here r31 is PIR */
secondary_wait:	
	/* The primary might be in the middle of relocating us,
	 * so first we spin on the boot_flag
	 */
	LOAD_IMM32(%r3, boot_flag - __head)
	add	%r3,%r3,%r30
1:	smt_lowest
	lwz	%r0,0(%r3)
	cmpdi	%r0,0
	beq	1b

	/* Init some registers */
	bl init_replicated_sprs

	/* Switch to new runtime address */
	mr	%r30,%r29
	LOAD_IMM32(%r3, 1f - __head)
	add	%r3,%r3,%r30
	mtctr	%r3
	isync
	bctr
1:
	/* Now wait for cpu_secondary_start to be set */
	LOAD_ADDR_FROM_TOC(%r3, cpu_secondary_start)
1:	smt_lowest
	ld	%r0,0(%r3)
	cmpdi	%r0,0
	beq	1b

	smt_medium

	/* Check our PIR is in bound */
	LOAD_ADDR_FROM_TOC(%r5, cpu_max_pir)
	lwz	%r5,0(%r5)
	cmpw	%r31,%r5
	bgt-	secondary_not_found

	/* Get our stack, cpu thread, and jump to C */
	GET_STACK(%r1,%r31)
	li	%r0,0
	std	%r0,0(%r1)
	std	%r0,16(%r1)
	GET_CPU()

	bl	secondary_cpu_entry
	b	.

	/* Not found... what to do ? set some global error ? */
secondary_not_found:
	smt_lowest
	b	.

call_relocate:
	mflr	%r17
	LOAD_IMM32(%r4,__dynamic_start - __head)
	LOAD_IMM32(%r5,__rela_dyn_start - __head)
	add	%r4,%r4,%r30
	add	%r5,%r5,%r30
	mr	%r3,%r30
	bl	relocate
	cmpwi	%r3,0
	bne	1f
	mtlr	%r17
	blr
1:	/* Fatal relocate failure */
	attn

/* This is a little piece of code that is copied down to
 * 0x100 for handling sresets and power management wakeups.
 * This matches the 0x200 handler closely.
 */
.global reset_patch_start
reset_patch_start:
	mtsprg0	%r3
	mtsprg1 %r4
	mfspr	%r3,SPR_SRR1
	mfcr	%r4
	rldicl.	%r3,%r3,48,62
	bne	1f		/* powersave wakeup (CFAR not required) */
	mtcr	%r4
	mfspr	%r3,SPR_CFAR
	li	%r4,0x100
	b	_exception + (reset_patch_start - sreset_vector)
1:
	cmpdi	%r3,0x1
	bne	2f		/* state loss */
	LOAD_IMM32(%r3, reset_resume - __head)
	b	3f
2:
	LOAD_IMM32(%r3, reset_wakeup - __head)
3:
	LOAD_IMM64(%r5, SKIBOOT_BASE)
	add	%r3,%r5,%r3
	mtctr	%r3
	li	%r3,0x100
	bctr
.global reset_patch_end
reset_patch_end:

.if reset_patch_end - reset_patch_start > 0x100
	.error "Reset patch overflow"
.endif

/* Wakeup vector in r3 */
.global reset_wakeup
reset_wakeup:
	/* Get PIR */
	mfspr	%r31,SPR_PIR

	/* Get that CPU stack base and use it to restore r16 */
	GET_STACK(%r1,%r31)
	GET_CPU()

	/* Restore original stack pointer */
	ld	%r1,CPUTHREAD_SAVE_R1(%r16)

	/* Restore more stuff */
	lwz	%r4,STACK_CR(%r1)
	lwz	%r5,STACK_XER(%r1)
	ld	%r6,STACK_GPR0(%r1)
	ld	%r7,STACK_GPR1(%r1)
	mtcr	%r4
	mtxer	%r5
	mtspr	SPR_HSPRG0,%r6
	mtspr	SPR_HSPRG1,%r7
	REST_GPR(2,%r1)
	REST_GPR(14,%r1)
	REST_GPR(15,%r1)
	REST_GPR(16,%r1)
	REST_GPR(17,%r1)
	REST_GPR(18,%r1)
	REST_GPR(19,%r1)
	REST_GPR(20,%r1)
	REST_GPR(21,%r1)
	REST_GPR(22,%r1)
	REST_GPR(23,%r1)
	REST_GPR(24,%r1)
	REST_GPR(25,%r1)
	REST_GPR(26,%r1)
	REST_GPR(27,%r1)
	REST_GPR(28,%r1)
	REST_GPR(29,%r1)
	REST_GPR(30,%r1)
	REST_GPR(31,%r1)
reset_resume:
	/* Get LR back, pop stack and return */
	addi	%r1,%r1,STACK_FRAMESIZE
	ld	%r0,16(%r1)
	mtlr	%r0
	blr

.global reset_fast_reboot_patch_start
reset_fast_reboot_patch_start:
	FIXUP_ENDIAN	/* HILE bit may or may not be set */
	smt_medium
	LOAD_IMM64(%r30, SKIBOOT_BASE)
	LOAD_IMM32(%r3, reset_fast_reboot_wakeup - __head)
	add	%r3,%r30,%r3
	mtctr	%r3
	bctr
.global reset_fast_reboot_patch_end
reset_fast_reboot_patch_end:

/* Fast reset code. We reset the stack, clean up the TLB and a few SPRs and
 * jump to C code. All CPUs do that, the CPU triggering the reset does it to
 * itself last. The C code will sort out who the master is. We come from the
 * trampoline above with r30 containing SKIBOOT_BASE
 */
reset_fast_reboot_wakeup:
	/* Get PIR */
	mfspr	%r31,SPR_PIR

	/* Get that CPU stack base and use it to restore r16 */
	GET_STACK(%r1,%r31)
	GET_CPU()

	/* Clear out SLB */
	li	%r6,0
	slbmte	%r6,%r6
	slbia
	ptesync

	/* Dummy stack frame */
	li	%r3,0
	std	%r3,0(%r1)
	std	%r3,8(%r1)
	std	%r3,16(%r1)

	/* Get our TOC */
	addis	%r2,%r30,(__toc_start - __head)@ha
	addi	%r2,%r2,(__toc_start - __head)@l

	/* Go to C ! */
	bl	fast_reboot_entry
	b	.

/* Functions to initialize replicated and shared SPRs to sane
 * values. This is called at boot and on soft-reset
 */
.global init_shared_sprs
init_shared_sprs:
	li	%r0,0
	mtspr	SPR_AMOR, %r0

	mfspr	%r3,SPR_PVR
	srdi	%r3,%r3,16
	cmpwi	cr0,%r3,PVR_TYPE_P8E
	beq	3f
	cmpwi	cr0,%r3,PVR_TYPE_P8
	beq	3f
	cmpwi	cr0,%r3,PVR_TYPE_P8NVL
	beq	3f
	cmpwi	cr0,%r3,PVR_TYPE_P9
	beq	4f
	cmpwi	cr0,%r3,PVR_TYPE_P9P
	beq	4f
	cmpwi	cr0,%r3,PVR_TYPE_P10
	beq	5f
	/* Unsupported CPU type... what do we do ? */
	b	9f

3:	/* P8E/P8 */
	mtspr	SPR_SDR1, %r0
	/* TSCR: Recommended value by HW folks */
	LOAD_IMM32(%r3,0x8ACC6880)
	mtspr	SPR_TSCR, %r3

	/* HID0: Clear bit 13 (enable core recovery)
	 *       Set/clear bit 19 (HILE) depending on skiboot endian
	 */
	mfspr	%r3,SPR_HID0
	li	%r0,1
	sldi	%r4,%r0,(63-13)
	andc	%r3,%r3,%r4
	sldi	%r4,%r0,(63-19)
#if HAVE_BIG_ENDIAN
	andc	%r3,%r3,%r4
#else
	or	%r3,%r3,%r4
#endif
	sync
	mtspr	SPR_HID0,%r3
	mfspr	%r3,SPR_HID0
	mfspr	%r3,SPR_HID0
	mfspr	%r3,SPR_HID0
	mfspr	%r3,SPR_HID0
	mfspr	%r3,SPR_HID0
	mfspr	%r3,SPR_HID0
	isync
	/* HMEER: Enable HMIs for core recovery and TOD errors. */
	LOAD_IMM64(%r0,SPR_HMEER_HMI_ENABLE_MASK)
	mfspr	%r3,SPR_HMEER
	or	%r3,%r3,%r0
	sync
	mtspr	SPR_HMEER,%r3
	isync
	/* RPR (per-LPAR but let's treat it as replicated for now) */
	LOAD_IMM64(%r3,0x00000103070F1F3F)
	mtspr	SPR_RPR,%r3
	b	9f

4:	/* P9 */
	/* TSCR: Recommended value by HW folks */
	LOAD_IMM32(%r3,0x80287880)
	mtspr	SPR_TSCR, %r3
	/* HID0: Clear bit 5 (enable core recovery)
	 *       Set/clear bit 4 (HILE) depending on skiboot endian
	 *       Set bit 8 (radix)
	 */
	mfspr	%r3,SPR_HID0
	li	%r0,1
	sldi	%r4,%r0,(63-4)
#if HAVE_BIG_ENDIAN
	andc	%r3,%r3,%r4
#else
	or	%r3,%r3,%r4
#endif
	sldi	%r4,%r0,(63-5)
	andc	%r3,%r3,%r4
	sldi	%r4,%r0,(63-8)
	or	%r3,%r3,%r4
	sync
	mtspr	SPR_HID0,%r3
	isync
	/* HMEER: Enable HMIs for core recovery and TOD errors. */
	LOAD_IMM64(%r0,SPR_HMEER_HMI_ENABLE_MASK)
	mfspr	%r3,SPR_HMEER
	or	%r3,%r3,%r0
	sync
	mtspr	SPR_HMEER,%r3
	isync

	LOAD_IMM64(%r3,0x00000103070F1F3F)
	mtspr	SPR_RPR,%r3
	b	9f

5:	/* P10 */
	/* TSCR: UM recommended value */
	LOAD_IMM32(%r3,0x80287880)
	mtspr	SPR_TSCR, %r3

	/* HID0:
	 * Boot with PPC_BIT(5) set (dis_recovery).
	 * Leave bit 5 set to disable recovery (due to HW570622)
	 * Set/clear bit 4 (HILE) depending on skiboot endian
	 */
#if HAVE_BIG_ENDIAN
	LOAD_IMM64(%r3, PPC_BIT(5))
#else
	LOAD_IMM64(%r3, PPC_BIT(5) | PPC_BIT(4))
#endif
	sync
	mtspr	SPR_HID0,%r3
	isync

	LOAD_IMM64(%r4,SPR_HMEER_P10_HMI_ENABLE_MASK)
	mfspr	%r3,SPR_HMEER
	or	%r3,%r3,%r4
	sync
	mtspr	SPR_HMEER,%r3
	isync

	LOAD_IMM64(%r3,0x00000103070F1F3F)
	mtspr	SPR_RPR,%r3

9:	blr

.global init_replicated_sprs
init_replicated_sprs:
	mfspr	%r3,SPR_PVR
	srdi	%r3,%r3,16
	cmpwi	cr0,%r3,PVR_TYPE_P8E
	beq	3f
	cmpwi	cr0,%r3,PVR_TYPE_P8
	beq	3f
	cmpwi	cr0,%r3,PVR_TYPE_P8NVL
	beq	3f
	cmpwi	cr0,%r3,PVR_TYPE_P9
	beq	4f
	cmpwi	cr0,%r3,PVR_TYPE_P9P
	beq	4f
	cmpwi	cr0,%r3,PVR_TYPE_P10
	beq	5f
	/* Unsupported CPU type... what do we do ? */
	b	9f

3:	/* P8, P8E */
	/* LPCR: sane value */
	LOAD_IMM64(%r3,0x0040000000000000)
	mtspr	SPR_LPCR, %r3
	sync
	isync
	LOAD_IMM64(%r3,0x0)
	mtspr	SPR_DSCR,%r3
	b	9f

4:	/* P9 */
	/* LPCR: sane value */
	LOAD_IMM64(%r3,0x0040000000000000)
	mtspr	SPR_LPCR, %r3
	sync
	isync
	/* DSCR: Stride-N Stream Enable */
	LOAD_IMM64(%r3,0x0000000000000010)
	mtspr	SPR_DSCR,%r3

5:	/* P10 */
	/* LPCR: sane value */
	LOAD_IMM64(%r3,0x0040000000000000)
	mtspr	SPR_LPCR, %r3
	sync
	isync
	/* DSCR: Stride-N Stream Enable */
	LOAD_IMM64(%r3,0x0000000000000010)
	mtspr	SPR_DSCR,%r3

9:	blr

	.global enter_nap
enter_nap:
	std	%r0,0(%r1)
	ptesync
	ld	%r0,0(%r1)
1:	cmp	%cr0,0,%r0,%r0
	bne	1b
	nap
	b	.

/*
 *
 * OPAL entry point from operating system
 *
 * Register usage:
 *
 *       r0: Token
 *       r2: OPAL Base
 *  r3..r10: Args
 * r11..r12: Scratch
 * r13..r31: Preserved
 */
	.balign	0x10
.global opal_entry
opal_entry:
	OPAL_ENTRY_TO_SKIBOOT_ENDIAN /* This clobbers r11, r12 */

	/* Get our per CPU pointer in r12 to check for quiesce */
	mfspr	%r12,SPR_PIR
	GET_STACK(%r12,%r12)

	/* Get CPU thread */
	clrrdi	%r12,%r12,STACK_SHIFT

	/*
	 * OPAL entry must first increment in_opal_call, then check
	 * for quiesce, without touching the stack or clobbering
	 * registers other than r11 and r12 and cr0. In this way, OPAL
	 * is tolerant of re-entry on this same CPU while it is spinning
	 * for quiesce.
	 *
	 * Sequence goes:
	 * in_opal_call++;
	 * sync;
	 * if (quiesce_opal_call) {
	 *     in_opal_call--;
	 *     reject-or-spin-then-retry;
	 */
1:	lwz	%r11,CPUTHREAD_IN_OPAL_CALL(%r12)
	addi	%r11,%r11,1
	stw	%r11,CPUTHREAD_IN_OPAL_CALL(%r12)
	/*
	 * Order the store in_opal_call vs load quiesce_opal_call.
	 * This also provides an acquire barrier for opal entry vs
	 * another thread quiescing opal. In this way, quiescing
	 * can behave as mutual exclusion.
	 */
	sync
	lwz	%r11,CPUTHREAD_QUIESCE_OPAL_CALL(%r12)
	cmpwi	%cr0,%r11,0
	beq+	4f
	/* We are quiescing, hold or reject */
	cmpwi	%cr0,%r11,QUIESCE_REJECT
	bne	2f
	li	%r3,OPAL_BUSY
	b	.Lreject
2:	/* hold */
	lwz	%r11,CPUTHREAD_IN_OPAL_CALL(%r12)
	subi	%r11,%r11,1
	stw	%r11,CPUTHREAD_IN_OPAL_CALL(%r12)
	smt_lowest
3:	lwz	%r11,CPUTHREAD_QUIESCE_OPAL_CALL(%r12)
	cmpwi	%cr0,%r11,QUIESCE_HOLD
	beq	3b
	/* spin finished, try again */
	smt_medium
	b	1b

4:	/* Quiesce protocol done, get our per CPU stack */
	/* Emergency stack if we have re-entered OPAL */
	lwz	%r11,CPUTHREAD_IN_OPAL_CALL(%r12)
	cmpwi	%r11,1

	mfspr	%r12,SPR_PIR
	bgt	5f
	GET_STACK(%r12,%r12)
	b	6f
5:
	GET_EMERGENCY_STACK(%r12,%r12)
6:
	stdu	%r12,-STACK_FRAMESIZE(%r12)

	/* Save caller r1, establish new r1 */
	std	%r1,0(%r12)
	std	%r1,STACK_GPR1(%r12)
	mr	%r1,%r12

	/* Save arguments because we call C */
	std	%r3,STACK_GPR3(%r1)
	std	%r4,STACK_GPR4(%r1)
	std	%r5,STACK_GPR5(%r1)
	std	%r6,STACK_GPR6(%r1)
	std	%r7,STACK_GPR7(%r1)
	std	%r8,STACK_GPR8(%r1)
	std	%r9,STACK_GPR9(%r1)
	std	%r10,STACK_GPR10(%r1)

	/* Save Token (r0), LR and r16 */
	mflr	%r12
	std	%r0,STACK_GPR0(%r1)
	std	%r16,STACK_GPR16(%r1)
	std	%r12,STACK_LR(%r1)

	/* Get the CPU thread */
	GET_CPU()

	/* Store token in CPU thread */
	std	%r0,CPUTHREAD_CUR_TOKEN(%r16)

	LOAD_IMM64(%r12,STACK_INT_MAGIC)
	std	%r12,STACK_MAGIC(%r1)
	/* Mark the stack frame */
	li	%r12,STACK_ENTRY_OPAL_API
	std	%r12,STACK_TYPE(%r1)

	/* Get our TOC */
	addis	%r2,%r2,(__toc_start - __head)@ha
	addi	%r2,%r2,(__toc_start - __head)@l

	/* Check entry */
	mr	%r3,%r1
	bl	opal_entry_check
	cmpdi	%r3,0
	bne	.Lreturn

	ld	%r0,STACK_GPR0(%r1)
	ld	%r3,STACK_GPR3(%r1)
	ld	%r4,STACK_GPR4(%r1)
	ld	%r5,STACK_GPR5(%r1)
	ld	%r6,STACK_GPR6(%r1)
	ld	%r7,STACK_GPR7(%r1)
	ld	%r8,STACK_GPR8(%r1)
	ld	%r9,STACK_GPR9(%r1)
	ld	%r10,STACK_GPR10(%r1)

	/* Convert our token into a table entry and get the
	 * function pointer. Also check the token.
	 * For ELFv2 ABI, the local entry point is used so no need for r12.
	 */
	sldi	%r0,%r0,3
	LOAD_ADDR_FROM_TOC(%r12, opal_branch_table)
	ldx	%r0,%r12,%r0
	mtctr	%r0

	/* Jump ! */
	bctrl

	mr	%r4,%r1
	bl	opal_exit_check /* r3 is preserved */

	/*
	 * Restore r1 and r16 before decrementing in_opal_call.
	 * Move per-cpu pointer to volatile r12, restore lr, r1, r16.
	 */
.Lreturn:
	ld	%r12,STACK_LR(%r1)
	mtlr	%r12
	mr	%r12,%r16
	ld	%r16,STACK_GPR16(%r1)
	ld	%r1,STACK_GPR1(%r1)
.Lreject:
	sync 	/* release barrier vs quiescing */
	lwz	%r11,CPUTHREAD_IN_OPAL_CALL(%r12)
	subi	%r11,%r11,1
	stw	%r11,CPUTHREAD_IN_OPAL_CALL(%r12)
#if HAVE_BIG_ENDIAN
	/*
	 * blr with BH=01b means it's not a function return, OPAL was entered
	 * via (h)rfid not bl, so we don't have a corresponding link stack
	 * prediction to return to here.
	 */
	bclr	20,0,1
#else
	mflr	%r12
	mtspr	SPR_HSRR0,%r12
	mfmsr	%r11
	li	%r12,MSR_LE
	andc	%r11,%r11,%r12
	mtspr	SPR_HSRR1,%r11
	hrfid
#endif

.global start_kernel
start_kernel:
	LOAD_IMM64(%r10,MSR_HV|MSR_SF)
__start_kernel:
	sync
	icbi	0,%r3
	sync
	isync
	mtspr	SPR_HSRR0,%r3
	mtspr	SPR_HSRR1,%r10
	mr	%r3,%r4
	LOAD_IMM64(%r8,SKIBOOT_BASE);
	LOAD_IMM32(%r10, opal_entry - __head)
	add	%r9,%r8,%r10
	LOAD_IMM32(%r6, EPAPR_MAGIC)
	addi	%r7,%r5,1
	li	%r4,0
	li	%r5,0
	hrfid

	.global start_kernel32
start_kernel32:
	LOAD_IMM64(%r10,MSR_HV)
	b	__start_kernel

.global start_kernel_secondary
start_kernel_secondary:
	sync
	isync
	LOAD_IMM64(%r10,MSR_HV|MSR_SF)
	mtspr	SPR_HSRR0,%r3
	mtspr	SPR_HSRR1,%r10
	mfspr	%r3,SPR_PIR
	hrfid

.global restore_cpu_ptr_r16
restore_cpu_ptr_r16:
	GET_CPU()
	blr

.global set_cpu_ptr_r16
set_cpu_ptr_r16:
	mr	%r16,%r3
	blr
