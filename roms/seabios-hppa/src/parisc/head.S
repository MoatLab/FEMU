/*
 * Startup glue code for parisc firmware
 *
 *   (C) 2017-2024 Helge Deller <deller@gmx.de>
 */

#include "parisc/hppa.h"
#include "parisc/hppa_hardware.h"
#include "parisc/pdc.h"
#include "autoconf.h"
#include "autoversion.h"

	/* load 32-bit 'value' into 'reg' with
	   sign-extension when running in wide mode. */
	.macro	load32_sign_extend value, reg
	ldil	L%\value, \reg
	ldo	R%\value(\reg), \reg
	.endm

	/* load 32-bit 'value' into 'reg' compensating for the ldil
	 * sign-extension when running in wide mode. */
	.macro	load32 value, reg
	ldil	L%\value, \reg
	ldo	R%\value(\reg), \reg
#ifdef CONFIG_64BIT
	depdi   0, 31, 32, \reg
#endif
	.endm

	/* set upper 32-bits of firmware address */
	.macro	load_fw_upper32 reg
#ifdef CONFIG_64BIT
	depdi   FIRMWARE_HIGH, 31, 32, \reg
#endif
	.endm

	.macro	load32_firmware value, reg
	ldil	L%\value, \reg
	ldo	R%\value(\reg), \reg
#ifdef CONFIG_64BIT
	depdi   FIRMWARE_HIGH, 31, 32, \reg
#endif
	.endm

;! set the W bit
#define set_PSW_W	.level 2.0 !	ssm PSW_W_SM, %r0 !	.level LEVEL

;! nuke the W bit
#define clear_PSW_W	.level 2.0 !	rsm PSW_W_SM, %r0 !	.level LEVEL

#define ENTRY(name) \
	.export name !\
	.align 4 !\
name:

#define END(name) \
	.size name, .-name

#define ENDPROC(name) \
	.type name, @function !\
	END(name)

#define BOOTADDR(x)	(x)

	.macro loadgp
#ifdef CONFIG_64BIT
	ldil		L%__gp, %r27
	ldo		R%__gp(%r27), %r27
	load_fw_upper32	%r27
#else
	ldil		L%$global$, %r27
	ldo		R%$global$(%r27), %r27
#endif
	.endm

#ifdef CONFIG_64BIT
#define LEVEL	2.0w
#define LDREG	ldd
#define STREG	std
#define LDREGX  ldd,s
#define LDREGM	ldd,mb
#define STREGM	std,ma
#define SHRREG	shrd
#define SHLREG	shld
#define ANDCM   andcm,*
#define	COND(x)	* ## x
#define FRAME_SIZE	128
#define FRAME_SIZE32	64
#define CALLEE_REG_FRAME_SIZE	144
#define ASM_ULONG_INSN	.dword
#define WORD_LEN 8
#define INT_LEN 4
#else	/* CONFIG_64BIT */
#define LEVEL	1.1
#define LDREG	ldw
#define STREG	stw
#define LDREGX  ldwx,s
#define LDREGM	ldwm
#define STREGM	stwm
#define SHRREG	shr
#define SHLREG	shlw
#define ANDCM   andcm
#define COND(x)	x
#define FRAME_SIZE	64
#define CALLEE_REG_FRAME_SIZE	128
#define ASM_ULONG_INSN	.word
#define WORD_LEN 4
#define INT_LEN 4
#endif

/* various control register and irq bits */
#define PSW_I		1
#define PSW_Q		8
#define CR_EIRR		23
#define CR_IVA		14
#define CR_EIEM		15
#define PSW_W_SM	0x200
#define PSW_W_BIT       36

	.import	$global$
	.section ".head.text","ax"
	 .level LEVEL

	/* On HPMC, the CPUs will start here at 0xf0000000 */
hpmc_entry:
        b,n toc_asm_entry       /* TOC and HPMC */

reset_entry:
	/* at reset, the CPU begins fetching instructions from address 0xf0000004. */
	b,n startup

marker:
	/* file identification, useful for strings command on binary file to see version. */
	.stringz "PA-RISC/HPPA PDC Firmware " SEABIOS_HPPA_VERSION_STR " (SeaBIOS fork)"
	.stringz "https://github.com/hdeller/seabios-hppa"
	.stringz BUILD_VERSION

/*******************************************************
	Firmware startup code
 *******************************************************/

        .align 0x80
ENTRY(startup)
	rsm	PSW_I, %r0	/* disable local irqs */
	ssm	PSW_Q, %r0	/* enable PSW_Q flag */

#ifdef CONFIG_64BIT
	/* check if we really run on 64-bit CPU */
	ldo	-1(%r0), %r1
	mtctl	%r1,%cr11
	mfctl,w %cr11, %r1
	ldo	-31(%r1),%r1
	cmpib,<>,n 0,%r1,1f
	.word 0xfffdead0	/* immediately halt the emulator */
1:
	/* we now know we run on a 64-bit CPU. */
	/* next step: turn on the PSW.W flag (enable 64-bit mode) */
	load32		2f,%r11
	load_fw_upper32 %r11

	mtctl           %r0,%cr17       /* Clear IIASQ tail */
	mtctl           %r0,%cr17       /* Clear IIASQ head */

	/* Load RFI target into PC queue */
	mtctl           %r11,%cr18      /* IIAOQ head */
	ldo             4(%r11),%r11
	mtctl           %r11,%cr18      /* IIAOQ tail */

	load32          (0x08000000 | PSW_Q),%r10 /* PSW.W=1 */
	mtctl           %r10,%ipsw

	/* Jump through hyperspace to enable PSW.W */
	rfi
	nop
2:
#else
	/* clear any PSW.W on 32-bit firmware */
	clear_PSW_W
#endif

	/* Make sure space registers are set to zero */
	mtsp    %r0,%sr0
	mtsp    %r0,%sr1
	mtsp    %r0,%sr2
	mtsp    %r0,%sr3
	mtsp    %r0,%sr4
	mtsp    %r0,%sr5
	mtsp    %r0,%sr6
	mtsp    %r0,%sr7

	/* If CPU HPA is already set in CPU_HPA_CR_REG then the
	 * CPU is already initialized and the machine was only reset */
	mfctl   CPU_HPA_CR_REG, %r1
	comib,= 0,%r1,$startup_fresh_booted
	nop

$startup_just_rebooted:
	/* Get current CPU HPA. It was stored there at initial bootup. */
	mfctl   CPU_HPA_CR_REG, %r5

	/* branch if this is the monarch cpu */
	load32_sign_extend CPU_HPA, %r1
	comb,=,n %r5,%r1,$is_monarch_cpu_reboot

	b,n	enter_smp_idle_loop

$startup_fresh_booted:
	/* Here the machine was booted from scratch: */

	/* Save CPU HPA in cr7, hopefully HP-UX will not use that register. */
#ifdef CONFIG_64BIT
	extrw,s,>= %r5,31,32,%r5	/* sign extend CPU HPA */
#endif
	mtctl   %r5, CPU_HPA_CR_REG /* store CPU HPA */

	/* branch if this is the monarch cpu */
	load32_sign_extend CPU_HPA,%r1
	comb,= %r5,%r1,$is_monarch_cpu
	nop

ENTRY(enter_smp_idle_loop)
	/* IDLE LOOP for SMP CPUs - wait for rendenzvous. */
	mfctl   CPU_HPA_CR_REG, %r25 /* get CPU HPA from cr7 */

	rsm	PSW_I, %r0	/* disable local irqs */
	mtctl	%r0, CR_EIEM	/* disable all external irqs */

	/* EIRR : clear all pending external intr */
	load32	-1,%r1
	mtctl	%r1, CR_EIRR
	mfctl	CR_EIRR, %r0
	mtctl	%r0, CR_EIRR

	/* Load IVT for SMT tiny loop exit */
	load32_firmware	BOOTADDR(smp_ivt),%r1
	mtctl	%r1, CR_IVA

	/* enable CPU local interrupts */
	load32	1<<31, %r1	/* allow IRQ0 (Timer) */
	mtctl	%r1, CR_EIEM
	ssm	PSW_I, %r0	/* enable local irqs */

	/* endless idle loop for secondary CPUs. Exits to $smp_exit_loop by IRQ only */
$smp_idle_loop:
	b $smp_idle_loop
	or %r10,%r10,%r10	/* qemu sleep instruction */

$smp_exit_loop:
	rsm	PSW_I, %r0	/* disable local irqs */
	mtctl	%r0, CR_EIEM

	/* Load IVT to detect and report crashes */
	load32_firmware	BOOTADDR(firmware_default_ivt),%r1
	mtctl	%r1, CR_IVA

	/* provide PDCE_PROC entry in arg0 (required on 64-bit) */
	load32	MEM_PDC_ENTRY, %arg0

	/* jump to rendevouz */
	ldw	0x10(%r0),%r3	/* MEM_RENDEZ */
#ifdef CONFIG_64BIT
	addb,*>,n %r0,%r0,1f	/* branch if narrow addressing */
	ldw	0x28(%r0),%r1	/* MEM_RENDEZ_HI */
	depd    %r1, 31, 32, %r3
1:
#endif
	cmpb,=,n  %r0,%r3,enter_smp_idle_loop
	nop			/* failed backward branch is nullified */
	load32_firmware	startup, %rp
	bv,n	0(%r3)

$is_monarch_cpu:
	/* Save boot_args in PAGE0->pad608[]. Only monarch CPU does this once. */
        load32          BOOTADDR(0x608),%r1
        STREGM          %r26,WORD_LEN(%r1)
        STREGM          %r25,WORD_LEN(%r1)
        STREGM          %r24,WORD_LEN(%r1)
        STREGM          %r23,WORD_LEN(%r1)
        STREGM          %r22,WORD_LEN(%r1)
        STREGM          %r21,WORD_LEN(%r1)
        STREGM          %r20,WORD_LEN(%r1)
        STREGM          %r19,WORD_LEN(%r1)

$is_monarch_cpu_reboot:
	/* Initialize stack pointer */
	load32_firmware BOOTADDR(parisc_stack),%r1
	ldo	FRAME_SIZE(%r1),%sp

	/* Initialize the global data pointer */
	loadgp

	/* Clear BSS on monarch CPU */
	.import _bss,data
	.import _ebss,data

	load32_firmware	BOOTADDR(_bss),%r3
	load32_firmware	BOOTADDR(_ebss),%r4
$bss_loop:
	cmpb,<<,n %r3,%r4,$bss_loop
	STREGM	%r0,WORD_LEN(%r3)

	/* Load IVT to detect and report crashes */
	load32_firmware	BOOTADDR(firmware_default_ivt),%r1
	mtctl	%r1, CR_IVA

	load32_firmware	BOOTADDR(start_parisc_firmware),%r3
	bv	0(%r3)
	copy	%r0,%r2
END(startup)

/*******************************************************/

ENTRY(start_kernel)
#ifdef CONFIG_64BIT
	bv	0(%r22)
	clear_PSW_W	/* clear PSW before we start the kernel! */
#else
	ldw	-0x34(%sp),%r1
	bv,n	0(%r1)
#endif
END(start_kernel)

/*******************************************************
  TOC handler
  Write all GRs, CRs, SRs and the iaoq_back and iasq_back registers (in
  r24/r25) into PIM area (when it's not filled yet). This is done by trashing the
  shadow registers.
  In a second step call the arificial getshadowregs asm instruction to restore
  the shadow registers to their real values and store them in PIM as well.  Then
  call the C-code.
 *******************************************************/

/* uses the shadow registers: 1,8,9,16,17,24,25 */
#define PIM_PTR         %r1
#define TEMP            %r8
#define TEMP2           %r9
#define PIM_SAVE        %r16
#define IASQ_BACK       %r24    /* provided by qemu */
#define IAOQ_BACK       %r25    /* provided by qemu */

        .import pim_toc_data, data
ENTRY(toc_asm_entry)
        /* serialize CPUs on entry */
        load32_firmware BOOTADDR(toc_lock),TEMP
0:      ldcw,co 0(TEMP),TEMP2
        cmpib,= 0,TEMP2,0b
        nop

        mfctl   CPU_HPA_CR_REG, TEMP2   /* get CPU HPA from cr7 */
        extru   TEMP2,31-12,4, TEMP     /* extract cpu id */

        load32_firmware BOOTADDR(pim_toc_data), PIM_PTR

1:      comib,= 0,TEMP,2f
        ldo     -1(TEMP),TEMP
        ldo     (PIM_STORAGE_SIZE)(PIM_PTR), PIM_PTR /* find PIM entry */
        b 1b

2:      copy    PIM_PTR, PIM_SAVE
        mtsp    %r0,%sr0

        /* save registers into PIM only if cpu_state field is empty */
        ldw     ((32+32+8+2)*WORD_LEN + 1*INT_LEN)(PIM_SAVE), TEMP
        comib,<>,n 0, TEMP, 5f

        /* save all general registers */
        .set loop,0
        .rept 32
        copy    loop,TEMP
        STREGM  TEMP, WORD_LEN(PIM_PTR)
        .set loop,loop+1
        .endr

        /* save all control registers */
        .set loop,0
        .rept 32
        mfctl   loop,TEMP
        STREGM  TEMP, WORD_LEN(PIM_PTR)
        .set loop,loop+1
        .endr

        /* save all space registers */
        .set loop,0
        .rept 8
        mfsp    loop,TEMP
        STREGM  TEMP, WORD_LEN(PIM_PTR)
        .set loop,loop+1
        .endr

        /* save IASQ_back and IAOQ_back as provided by qemu */
        STREG   IASQ_BACK, ((32+32+8+0)*WORD_LEN)(PIM_SAVE)
        STREG   IAOQ_BACK, ((32+32+8+1)*WORD_LEN)(PIM_SAVE)

        /* restore shadow registers, can not use PIM_SAVE reg for this */
        copy    PIM_SAVE, %r26
        .word 0xfffdead2 /* qemu artificial getshadowregs asm instruction */
        STREG   %r1, (1*WORD_LEN)(%r26)
        STREG   %r8, (8*WORD_LEN)(%r26)
        STREG   %r9, (9*WORD_LEN)(%r26)
        STREG   %r16, (16*WORD_LEN)(%r26)
        STREG   %r17, (17*WORD_LEN)(%r26)
        STREG   %r24, (24*WORD_LEN)(%r26)
        STREG   %r25, (25*WORD_LEN)(%r26)

#ifdef CONFIG_64BIT
        /* cr11 (sar) is a funny one.  5 bits on PA1.1 and 6 bit on PA2.0
         * For PA2.0 mtsar or mtctl always write 6 bits, but mfctl only
         * reads 5 bits.  Use mfctl,w to read all six bits.  Otherwise
         * we lose the 6th bit on a save/restore. */
        mfctl,w %cr11, TEMP
        STREG   TEMP, ((32+11)*WORD_LEN)(%r26)
#endif

5:      /* call the "C" toc_handler in SeaBIOS */
        loadgp
        load32_firmware BOOTADDR(parisc_stack), %sp
        b,l     toc_handler, %r2
        ldo     FRAME_SIZE(%sp),%sp

        /* call OS handler, in case it returns reset the system */
        load32_firmware BOOTADDR(reset), %rp
        bv,n    0(%ret0)
END(toc_asm_entry)


/*******************************************************
	SMP Interrupt vector table (IVT)
 *******************************************************/

	.macro  DEF_IVA_ENTRY
	.align 32
	load32_firmware BOOTADDR($smp_exit_loop),%r1
	bv	0(%r1)
	nop
	.endm

	.align 32	/* should be 4k aligned but qemu does not check */
ENTRY(smp_ivt)
	.rept 32
	DEF_IVA_ENTRY
	.endr
END(smp_ivt)

/*******************************************************
	Fault detection & reporting Interrupt vector table (IVT)
 *******************************************************/

/* fault happened at bootup. Return to instruction after fault. */
ENTRY(fault_return_to_caller)
	mfctl	%cr18,TEMP
	ldo	4(TEMP),TEMP
	mtctl	TEMP,%cr18	/* IIAOQ head */
	ldo	4(TEMP),TEMP
	mtctl	TEMP,%cr18	/* IIAOQ tail */
	rfi
	nop
END(fault_return_to_caller)

/* call firmware_fault_handler in parisc.c and halt. */
ENTRY(fault_call_firmware)
	load32_firmware firmware_fault_handler,TEMP
	loadgp
	bv,n	0(TEMP)
END(fault_call_firmware)

	.align 32
ENTRY(firmware_default_ivt)	/* to detect crashes */
	.set loop,0
	.import firmware_fault_handler,code
	.rept 32
	/* Make sure to use shadow registers only! */
	/* While booting up we check if various devices are available.
	   Allow such checks and do not raise an HPMC. */
	ldi	loop,TEMP	/* trap# into TEMP */
	cmpib,= 1,TEMP,fault_return_to_caller
	nop
	b	fault_call_firmware
	ldi	loop,%arg0	/* trap# into arg0 */
	.set loop,loop+1
	.align 32
	.endr
END(smp_ivt)

/*******************************************************
 Check if space register hashing is enabled.
 Returns non-zero if sr-hashing in CPU is enabled.
 Needs adjustment when we emulate PCX-T later.
 Requires at least qemu v9.x
 *******************************************************/
ENTRY(sr_hashing_enabled)
	copy %r0,%r26
	copy %r0,%r28		/* zero-initialize %r28 in case qemu can't emulate mfdiag call */
#ifdef CONFIG_64BIT
	.word 0x144008bc	/* PCXU,PCXU+,PCXW,PCXW+,PCXW2: mfdiag %dr2, %r28 */
	depdi 1,54,1, %r26	/* set DIAG_SPHASH_ENABLE (bit 54) of %dr2 */
#else
	.word 0x141c0600	/* PCXL: mfdiag %dr0, %r28 */
	depwi 3,28,2, %r26	/* Set DHASH_EN & IHASH_EN of %dr0 */
#endif
	bv    %r0(%rp)
	and   %r28, %r26, %r28	/* mask hash enable bits */
END(sr_hashing_enabled)


/*******************************************************
	PDC and IODC entry
 *******************************************************/

/* pdc_entry_table will be copied into low memory. */
ENTRY(pdc_entry_table)
#ifdef CONFIG_64BIT
	/* see section "Testing the Current State of the PSW W-Bit",
	   page I-2 in parisc2 spec */
	addb,*>,n %r0,%r0,pdc_called_narrow /* branch if narrow addressing */

pdc_called_wide:
	/* we know that PDC was called with PSW.W=1 */
	load32_firmware pdc_entry_64_64,%r1
	bv,n %r0(%r1)

pdc_called_narrow:
	/* we know that PDC was called with PSW.W=0 */
	load32		MEM_PDC_ENTRY + pdc_entry_64_32 - pdc_entry_table,%r1
	bv              0(%r1)
	set_PSW_W	/* enable PSW.W */
#else
ENTRY(pdc_entry_32)	/* 32-bit PDC */
	stw %rp,-20(%sp)
	stw %dp,-32(%sp)
	stw %arg0,-36(%sp)
	stw %arg1,-40(%sp)
	stw %arg2,-44(%sp)
	stw %arg3,-48(%sp)
	ldo -FRAME_SIZE(%sp),%arg0
	ldi 1,%arg1		/* called with wide-bit cleared (narrow mode) */

	loadgp
	load32		MEM_PDC_ENTRY + 1f - pdc_entry_table,%rp
	load32 parisc_pdc_entry, %r1
	clear_PSW_W
	bv              0(%r1)
	ldo FRAME_SIZE(%sp),%sp
1:
	ldo -FRAME_SIZE(%sp),%sp
	ldw -20(%sp),%rp
	ldw -32(%sp),%dp
	bv,n %r0(%rp)
END(pdc_entry_32)
#endif
END(pdc_entry_table)

#ifdef CONFIG_64BIT
ENTRY(pdc_entry_64_32)	/* 32-bit call on 64-bit PDC */
	/* clear upper bits */
	depdi   0, 31, 32, %sp
	depdi   0, 31, 32, %rp
	depdi   0, 31, 32, %dp
	depdi   0, 31, 32, %arg0
	depdi   0, 31, 32, %arg1
	depdi   0, 31, 32, %arg2
	depdi   0, 31, 32, %arg3

	copy %sp,%r1	/* copy original stack pointer */
	ldo 2*FRAME_SIZE(%sp),%sp /* build new 64-bit stack */

	std %rp,-0x10(%sp)
	std %dp,-0x18(%sp)
	std %arg0,-0x20(%sp)
	std %arg1,-0x28(%sp)
	std %arg2,-0x30(%sp)
	std %arg3,-0x38(%sp)

	ldw -FRAME_SIZE32 + 12(%r1),%arg0	/* ARG4 */
	depdi   0, 31, 32, %arg0
	std %arg0, -0x40(%sp)

	ldw -FRAME_SIZE32 + 8(%r1),%arg0	/* ARG5 */
	depdi   0, 31, 32, %arg0
	std %arg0, -0x48(%sp)

	ldw -FRAME_SIZE32 + 4(%r1),%arg0	/* ARG6 */
	depdi   0, 31, 32, %arg0
	std %arg0, -0x50(%sp)

	ldw -FRAME_SIZE32 + 0(%r1),%arg0	/* ARG7 */
	depdi   0, 31, 32, %arg0
	std %arg0, -0x58(%sp)

	ldo -0x58(%sp),%arg0	/* points to arg7 */
	ldi 1,%arg1		/* called with wide-bit cleared (narrow mode) */

	loadgp
	load32_firmware parisc_pdc_entry,%r1
	load32	MEM_PDC_ENTRY + c64_32_return - pdc_entry_table,%rp
	bv 0(%r1)
	ldo FRAME_SIZE(%sp),%sp

c64_32_return:
	/* return from PDC call */
	ldo -FRAME_SIZE(%sp),%sp
	ldd -0x10(%sp),%rp
	ldd -0x18(%sp),%dp
	ldd -0x30(%sp),%arg2	/* addr of result buffer */
	ldo -2*FRAME_SIZE(%sp),%sp /* restore original 32-bit stack */

	cmpb,=,n %r0,%arg2,5f   /* skip copy results if target buffer is NULL */
	cmpb,<   %ret0,%r0,5f	/* skip copy results if return value was negative (=error) */
	ldi MEM_PDC_ENTRY,%r1
	cmpb,>=,n %arg2,%r1,convert_ret64_buffer  /* copy results if target buffer >= MEM_PDC_ENTRY */
	b,n .
	.word 0xfffdead0	/* immediately halt the emulator */

convert_ret64_buffer:
	/* copy 64-bit-wide PDC result to 32-bit wide results */
	ldi 32,%r1
	copy %arg2,%arg3
.L1:	ldd,ma 8(%arg2),%arg1
	stwm %arg1, 4(%arg3)
	ldo -1(%r1),%r1
	cmpb,>>,n %r1,%r0,.L1

5:	/* return to caller */
	clear_PSW_W
	bv,n %r0(%rp)

ENTRY(pdc_entry_64_64)	/* 64-bit call on 64-bit PDC */
	ldo FRAME_SIZE(%sp),%sp
	std %rp,-0x10(%sp)
	std %dp,-0x18(%sp)
	std %arg0,-0x20(%sp)
	std %arg1,-0x28(%sp)
	std %arg2,-0x30(%sp)
	std %arg3,-0x38(%sp)
	std %r22, -0x40(%sp)
	std %r21, -0x48(%sp)
	std %r20, -0x50(%sp)
	std %r19, -0x58(%sp)
	ldo -0x58(%sp),%arg0	/* points to arg7 */
	ldi 0,%arg1		/* called with wide-bit set (not narrow) */

	loadgp
	b,l parisc_pdc_entry, %rp
	ldo FRAME_SIZE(%sp),%sp

	ldo -FRAME_SIZE(%sp),%sp
	ldd -0x10(%sp),%rp
	ldd -0x18(%sp),%dp
	bv  %r0(%rp)
	ldo -FRAME_SIZE(%sp),%sp
END(pdc_entry_64_32)
#endif


ENTRY(iodc_entry_table)
	load32 parisc_iodc_ENTRY_INIT,   %r1
iodc_entry_table_one_entry:
	.export iodc_entry_table_one_entry
	load32 parisc_iodc_ENTRY_IO,     %r1
	load32 parisc_iodc_ENTRY_SPA,    %r1
	load32 parisc_iodc_ENTRY_CONFIG, %r1
	load32 hlt,			 %r1 /* obsolete */
	load32 parisc_iodc_ENTRY_TEST,   %r1
	load32 parisc_iodc_ENTRY_TLB,    %r1
END(iodc_entry_table)

/* the code for iodc_entry[] will be copied to user.
   the first load32* wil be replaced by an entry from
   the iodc_entry_table[] table above. */
ENTRY(iodc_entry)
	/* this first call we be replaced at runtime: */
	load32 parisc_iodc_ENTRY_IO, %r1

#ifdef CONFIG_64BIT
	addb,*>,n %r0,%r0,iodc_narrow /* branch if narrow addressing */
	nop
#if 1
	// HALT
	load32_firmware hlt,%r1
	bv,n %r0(%r1)
#endif
	b,n iodc_wide

iodc_narrow:
	/* we run narrow, but want wide! Jump to firmware to set PSW.W=1 */
	/* Switch to wide mode. */
	load32		MEM_PDC_ENTRY + 2f - pdc_entry_table,%r31
	bv              0(%r31)
	set_PSW_W
2:	/* now in wide mode, running in low memory */
	depdi   0, 31, 32, %sp
	load_fw_upper32 %r1

	stw %rp,-20(%sp)
	stw %dp,-32(%sp)
	stw %arg0,-36(%sp)
	stw %arg1,-40(%sp)
	stw %arg2,-44(%sp)
	stw %arg3,-48(%sp)
	ldo -FRAME_SIZE32(%sp),%arg0
	loadgp
	load32	MEM_PDC_ENTRY +  .iodc_ret32 - pdc_entry_table,%rp
	bv %r0(%r1)
	ldo 2*FRAME_SIZE(%sp),%sp
.iodc_ret32:
	ldo -2*FRAME_SIZE(%sp),%sp
	ldw -20(%sp),%rp
	ldw -32(%sp),%dp
	bv   %r0(%rp)
	clear_PSW_W
	/* END for 32-bit IODC call */

iodc_narrow_jump_to_firmware:
	/* clear upper bits */
	depdi   0, 31, 32, %rp
	depdi   0, 31, 32, %dp
	depdi   0, 31, 32, %arg0
	depdi   0, 31, 32, %arg1
	depdi   0, 31, 32, %arg2
	depdi   0, 31, 32, %arg3
	depdi   0, 31, 32, %r22
	depdi   0, 31, 32, %r21
	depdi   0, 31, 32, %r20
	depdi   0, 31, 32, %r19
iodc_wide:
	std %rp,-0x10(%sp)
	std %dp,-0x18(%sp)
	std %arg0,-0x20(%sp)
	std %arg1,-0x28(%sp)
	std %arg2,-0x30(%sp)
	std %arg3,-0x38(%sp)
	std %r22, -0x40(%sp)
	std %r21, -0x48(%sp)
	std %r20, -0x50(%sp)
	std %r19, -0x58(%sp)
	ldo -0x58(%sp),%arg0	/* points to arg7 */
#else
	stw %rp,-20(%sp)
	stw %dp,-32(%sp)
	stw %arg0,-36(%sp)
	stw %arg1,-40(%sp)
	stw %arg2,-44(%sp)
	stw %arg3,-48(%sp)
	ldo -FRAME_SIZE(%sp),%arg0
#endif

	loadgp
	load32 .iodc_ret, %rp
	bv %r0(%r1)
	ldo FRAME_SIZE(%sp),%sp
.iodc_ret:
	ldo -FRAME_SIZE(%sp),%sp
#ifdef CONFIG_64BIT
	ldd -0x10(%sp),%rp
	ldd -0x18(%sp),%dp
#else
	ldw -20(%sp),%rp
	ldw -32(%sp),%dp
#endif
	bv   %r0(%rp)
	clear_PSW_W
END(iodc_entry)

/* PDC is copied up until here: */
pdc_entry_table_end:
	.export pdc_entry_table_end

/****************************************************************
 * Rom Header for VGA / STI
 ****************************************************************/

#if 0 // def CONFIG_BUILD_VGABIOS

        .section .rom.header
        .global _rom_header, _rom_header_size, _rom_header_checksum
_rom_header:
        .word 0xaa55
_rom_header_size:
        .byte 0
_rom_header_entry:
        .word _optionrom_entry  // b,n ?
_rom_header_checksum:
        .byte 0
_rom_header_other:
        .space 17
_rom_header_pcidata:
#if CONFIG_VGA_PCI == 1
        .word rom_pci_data
#else
        .word 0
#endif
_rom_header_pnpdata:
        .word 0
_rom_header_other2:
        .word 0
_rom_header_signature:
        .asciz "IBM"


ENTRY(_optionrom_entry)
	.import vga_post
	load32 BOOTADDR(vga_post), %r1
	bv,n %r0(%r1)
END(_optionrom_entry)

#endif /* CONFIG_BUILD_VGABIOS */
