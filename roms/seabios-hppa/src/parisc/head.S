/*
 * Startup glue code for parisc firmware
 *
 *   (C) 2017-2021 Helge Deller <deller@gmx.de>
 */

#include "parisc/hppa_hardware.h"
#include "autoconf.h"
#include "autoversion.h"

	/* load 32-bit 'value' into 'reg' compensating for the ldil
	 * sign-extension when running in wide mode.
	 * WARNING!! neither 'value' nor 'reg' can be expressions
	 * containing '.'!!!! */
	.macro	load32 value, reg
	ldil	L%\value, \reg
	ldo	R%\value(\reg), \reg
	.endm

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
	ldil		L%$global$, %r27
	ldo		R%$global$(%r27), %r27
	.endm

#ifdef CONFIG_64BIT
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
#define CALLEE_REG_FRAME_SIZE	144
#define ASM_ULONG_INSN	.dword
#define WORD_LEN 8
#define INT_LEN 4
#else	/* CONFIG_64BIT */
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

	.import	$global$
	.section ".head.text","ax"
	 .level 1.1

	/* On HPMC, the CPUs will start here at 0xf0000000 */
hpmc_entry:
        b,n toc_asm_entry       /* TOC and HPMC */

reset_entry:
	/* at reset, the CPU begins fetching instructions from address 0xf0000004. */
	b,n startup

marker:
	/* file identification */
	.stringz "PA-RISC/HPPA PDC Firmware (SeaBIOS fork)"
	.stringz "https://github.com/hdeller/seabios-hppa"
	.stringz BUILD_VERSION

/*******************************************************
	Firmware startup code
 *******************************************************/

        .align 0x80
ENTRY(startup)
	/* Make sure space registers are set to zero */
	mtsp    %r0,%sr0
	mtsp    %r0,%sr1
	mtsp    %r0,%sr2
	mtsp    %r0,%sr3
	mtsp    %r0,%sr4
	mtsp    %r0,%sr5
	mtsp    %r0,%sr6
	mtsp    %r0,%sr7

#define PSW_W_SM	0x200
#define PSW_W_BIT       36

	;! nuke the W bit
	.level 2.0
	rsm	PSW_W_SM, %r0
	.level 1.1

	/* Save CPU HPA in cr7, hopefully HP-UX will not use that register. */
	mtctl   %r5, CPU_HPA_CR_REG /* store CPU HPA */

	/* branch if this is the monarch cpu */
	load32 CPU_HPA,%r1
	comb,= %r5,%r1,$is_monarch_cpu
	nop

ENTRY(enter_smp_idle_loop)
	/* IDLE LOOP for SMP CPUs - wait for rendenzvous. */
	mfctl   CPU_HPA_CR_REG, %r25 /* get CPU HPA from cr7 */

#define PSW_I 1
	rsm	PSW_I, %r0	/* disable local irqs */

	/* EIRR : clear all pending external intr */
#define CR_EIRR 23
	load32	-1,%r1
	mtctl	%r1, CR_EIRR
	mfctl	CR_EIRR, %r0
	mtctl	%r0, CR_EIRR

	/* Load IVT for SMT tiny loop exit */
#define CR_IVA 14
	load32	BOOTADDR(smp_ivt),%r1
	mtctl	%r1, CR_IVA

	/* enable CPU local interrupts */
#define CR_EIEM 15
	load32	1<<31, %r1	/* allow IRQ0 (Timer) */
	mtctl	%r1, CR_EIEM
	ssm	PSW_I, %r0	/* enable local irqs */

	/* endless idle loop, exits to $smp_exit_loop by IRQ only */
$smp_idle_loop:
	b $smp_idle_loop
	or %r10,%r10,%r10

$smp_exit_loop:
	mtctl	%r0, CR_EIEM
	rsm	PSW_I, %r0	/* disable local irqs */

	/* tell QEMU to drop all local TLB entries. */
	pdtlbe	%r0(%sr1,%r0)

	/* on 64bit: Address of PDCE_PROC for each non-monarch processor in GR26. */
	load32	BOOTADDR(pdc_entry), %r26

	/* jump to rendevouz */
	ldw	0x10(%r0),%r3	/* MEM_RENDEZ */
	/* ldw	0x28(%r0),%r0	MEM_RENDEZ_HI - assume addr < 4GB */
	load32	enter_smp_idle_loop, %rp
	bv,n	0(%r3)


$is_monarch_cpu:
	/* Initialize stack pointer */
	load32	BOOTADDR(parisc_stack),%r1
	ldo	FRAME_SIZE(%r1),%sp

	/* Initialize the global data pointer */
	loadgp

	/* Clear BSS on monarch CPU */
	.import _bss,data
	.import _ebss,data

	load32	BOOTADDR(_bss),%r3
	load32	BOOTADDR(_ebss),%r4
$bss_loop:
	cmpb,<<,n %r3,%r4,$bss_loop
	stw,ma	%r0,4(%r3)

	/* Save boot args */
        load32          BOOTADDR(boot_args),%r1
        stw,ma          %r26,4(%r1)
        stw,ma          %r25,4(%r1)
        stw,ma          %r24,4(%r1)
        stw,ma          %r23,4(%r1)
        stw,ma          %r22,4(%r1)
        stw,ma          %r21,4(%r1)
        stw,ma          %r20,4(%r1)
        stw,ma          %r19,4(%r1)

	load32	BOOTADDR(start_parisc_firmware),%r3
	bv	0(%r3)
	copy	%r0,%r2
END(startup)


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
        load32  BOOTADDR(toc_lock),TEMP
0:      ldcw,co 0(TEMP),TEMP2
        cmpib,= 0,TEMP2,0b
        nop

        mfctl   CPU_HPA_CR_REG, TEMP2   /* get CPU HPA from cr7 */
        extru   TEMP2,31-12,4, TEMP     /* extract cpu id */

        load32  BOOTADDR(pim_toc_data), PIM_PTR

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
        STREGM  loop, WORD_LEN(PIM_PTR)
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
        load32  BOOTADDR(parisc_stack), %sp
        b,l     toc_handler, %r2
        ldo     FRAME_SIZE(%sp),%sp

        /* call OS handler, in case it returns reset the system */
        load32  BOOTADDR(reset), %rp
        bv,n    0(%ret0)
END(toc_asm_entry)


/*******************************************************
	SMP Interrupt vector table (IVT)
 *******************************************************/

	.macro  DEF_IVA_ENTRY
	.align 32
	load32 BOOTADDR($smp_exit_loop),%r1
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
	PDC and IODC entry
 *******************************************************/

ENTRY(pdc_entry)
	stw %rp,-20(%sp)
	stw %dp,-32(%sp)
	stw %arg0,-36(%sp)
	stw %arg1,-40(%sp)
	stw %arg2,-44(%sp)
	stw %arg3,-48(%sp)
	ldo -FRAME_SIZE(%sp),%arg0

	loadgp
	b,l parisc_pdc_entry, %rp
	ldo FRAME_SIZE(%sp),%sp

	ldo -FRAME_SIZE(%sp),%sp
	ldw -20(%sp),%rp
	bv %r0(%rp)
	ldw -32(%sp),%dp
END(pdc_entry)

/* pdc_entry_table will be copied into low memory. */
ENTRY(pdc_entry_table)
	load32 pdc_entry,%r1
	bv,n %r0(%r1)
END(pdc_entry_table)

ENTRY(iodc_entry_table)
	load32 parisc_iodc_ENTRY_INIT,   %r1
	load32 parisc_iodc_ENTRY_IO,     %r1
	load32 parisc_iodc_ENTRY_SPA,    %r1
	load32 parisc_iodc_ENTRY_CONFIG, %r1
	load32 hlt,			 %r1 /* obsolete */
	load32 parisc_iodc_ENTRY_TEST,   %r1
	load32 parisc_iodc_ENTRY_TLB,    %r1
END(iodc_entry_table)

ENTRY(iodc_entry)
	load32 parisc_iodc_ENTRY_IO, %r1

	stw %rp,-20(%sp)
	stw %dp,-32(%sp)
	stw %arg0,-36(%sp)
	stw %arg1,-40(%sp)
	stw %arg2,-44(%sp)
	stw %arg3,-48(%sp)
	ldo -FRAME_SIZE(%sp),%arg0

	loadgp
	load32 .iodc_ret, %rp
	bv %r0(%r1)
	ldo FRAME_SIZE(%sp),%sp
.iodc_ret:
	ldo -FRAME_SIZE(%sp),%sp
	ldw -20(%sp),%rp
	bv %r0(%rp)
	ldw -32(%sp),%dp
END(iodc_entry)

	.data
ENTRY(boot_args)
        .word 0 /* r26: ramsize */
        .word 0 /* r25: kernel entry point */
        .word 0 /* r24: cmdline */
        .word 0 /* r23: initrd_start */
        .word 0 /* r22: initrd_end */
        .word 0 /* r21: num CPUs */
        .word 0 /* r20: pdc_debug */
        .word 0 /* r19: fw_cfg port */
END(boot_args)

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
