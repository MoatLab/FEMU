#include "pstate.h"
#include <asm/asi.h>
#include "cpustate.h"
#define ASI_BP ASI_M_BYPASS
#define REGWIN_SZ   0x40

	.globl	__switch_context, __switch_context_nosave, __exit_context, halt

	.text
	.align	4
        .register %g2, #scratch
        .register %g3, #scratch
        .register %g6, #scratch
        .register %g7, #scratch

/*
 * Switch execution context
 * This saves registers in the stack, then
 * switches the stack, and restores everything from the new stack.
 * This function takes no argument. New stack pointer is
 * taken from global variable __context, and old stack pointer
 * is also saved to __context. This way we can just jump to
 * this routine to get back to the original context.
 */

__switch_context:
	/* make sure caller's windows are on caller's stack */
	flushw;

	/* Save everything in current stack */
	stx	%g1, [%sp + 2047 - 0x500 + 0x30]
	stx	%g2, [%sp + 2047 - 0x500 + 0x38]
	stx	%g3, [%sp + 2047 - 0x500 + 0x40]
	stx	%g4, [%sp + 2047 - 0x500 + 0x48]
	stx	%g5, [%sp + 2047 - 0x500 + 0x50]
	stx	%g6, [%sp + 2047 - 0x500 + 0x58]
	stx	%g7, [%sp + 2047 - 0x500 + 0x60]
	
	mov	%sp, %g1
	add     %g1, 2047 - 0x500, %g1
	
	/* Return PC value */
	mov	%o7, %g2
	add	%g2, 0x8, %g2
	stx	%g2, [%g1 + 0x4d0]
	
	SAVE_CPU_STATE(switch)
	
	/* swap context */
	setx	__context, %g2, %g3
	ldx     [%g3], %g2
	stx	%g1, [%g3]
	mov	%g2, %g1
	
	ba	__set_context

__switch_context_nosave:
	/* Interrupts are not allowed... */
	/* make sure caller's windows are on caller's stack */
	flushw
	/* Load all registers
	 */
	setx	__context, %g2, %g1
        ldx     [%g1], %g1
        
__set_context:
	RESTORE_CPU_STATE(switch)
	
	/* Restore globals */
	mov	%g1, %g2
	add	%g2, 0x30, %g2
	stx	%g2, [%sp + 2047 - 8]
	
	ldx	[%g1 + 0x38], %g2
	ldx	[%g1 + 0x40], %g3
	ldx	[%g1 + 0x48], %g4 
	ldx	[%g1 + 0x50], %g5 
	ldx	[%g1 + 0x58], %g6
	ldx	[%g1 + 0x60], %g7

	/* Finally, load new %pc */
	ldx     [%g1 + 0x4d0], %g1
	jmpl    %g1, %o7
         ldx    [%sp + 2047 - 8], %g1

__exit_context:
	/* Get back to the original context */
	ba	__switch_context
	 nop
