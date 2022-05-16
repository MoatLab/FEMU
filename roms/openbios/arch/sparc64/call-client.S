#include "cpustate.h"

	.globl	sparc64_of_client_interface, client_tba


/*
 * SAVE_WINDOW_STATE and RESTORE_WINDOW_STATE are used to ensure
 * that the CPU window state is preserved across CIF calls. This is
 * to workaround a *BSD restriction that window fill/spill traps must
 * be minimised during trap table takeover, and likely emulates the
 * behaviour of OBP.
 */

	.data
	.align	8

client_context:
	.xword	0
client_stack:
	.xword	0
client_window:
	.skip	2048


	.text
	.align	4
        .register %g2, #scratch
        .register %g3, #scratch
        .register %g6, #scratch
        .register %g7, #scratch
/*
	make some more space on stack since linux kernel only provides 128 bytes
	without memory to spill registers (used by gcc in -O0 mode)
*/

sparc64_of_client_interface:

	/* Save globals on callers stack */
	stx	%g1, [%sp + 2047 - 248 + 192]
	stx	%g2, [%sp + 2047 - 248 + 200]
	stx	%g3, [%sp + 2047 - 248 + 208]
	stx	%g4, [%sp + 2047 - 248 + 216]
	stx	%g5, [%sp + 2047 - 248 + 224]
	stx	%g6, [%sp + 2047 - 248 + 232]
	stx	%g7, [%sp + 2047 - 248 + 240]

	/* Save existing stack */
	setx	client_stack, %g6, %g7
	stx	%sp, [%g7]

	/* Save windows */
	setx	_fcstack_ptr, %g6, %g7
	ldx	[%g7], %g1
	add	%g1, -CONTEXT_STATE_SIZE, %g1
	stx	%g1, [%g7]
	
	/* Save globals */
	ldx	[%sp + 2047 - 248 + 192], %g7
	stx	%g7, [%g1 + 0x30]
	ldx	[%sp + 2047 - 248 + 200], %g7
	stx	%g7, [%g1 + 0x38]
	ldx	[%sp + 2047 - 248 + 208], %g7
	stx	%g7, [%g1 + 0x40]
	ldx	[%sp + 2047 - 248 + 216], %g7
	stx	%g7, [%g1 + 0x48]
	ldx	[%sp + 2047 - 248 + 224], %g7
	stx	%g7, [%g1 + 0x50]
	ldx	[%sp + 2047 - 248 + 232], %g7
	stx	%g7, [%g1 + 0x58]
	ldx	[%sp + 2047 - 248 + 240], %g7
	stx	%g7, [%g1 + 0x60]
	
	/* Save %pc */
	mov	%o7, %g7
	add	%g7, 8, %g7
	stx	%g7, [%g1 + 0x4d0]
	
	SAVE_CPU_STATE(cif)
	
	RESET_CPU_WINDOW_STATE(cif)
	
	/* Update __context to point to saved area */
	setx	__context, %g6, %g7
	ldx	[%g7], %g3
	setx	client_context, %g4, %g5
	stx	%g3, [%g5]
	stx	%g1, [%g7]
	
	/* Move to OpenBIOS context stack */
	setx	_fcstack_ptr, %g6, %g7
	ldx	[%g7], %g6
	setx	CONTEXT_STACK_SIZE, %g4, %g5
	sub	%g6, %g5, %g6
	stx	%g6, [%g7]
	
	setx	- 2047 - 192, %g6, %g7
	add	%g1, %g7, %g7
	mov	%g7, %sp

	/* Call client inteface */
	call of_client_interface
	 ldx	[%g1 + 0x70], %o0

	/* Restore windows */
	setx	_fcstack_ptr, %g6, %g7
	ldx	[%g7], %g1
	setx	CONTEXT_STACK_SIZE, %g4, %g5
	add	%g1, %g5, %g1
	stx	%g1, [%g7]
	
	/* Return value */
	stx	%o0, [%g1 + 0x70]
	
	/* Restore __context */
	setx	client_context, %g4, %g5
	ldx	[%g5], %g3
	setx	__context, %g6, %g7
	stx	%g3, [%g7]
	
	RESTORE_CPU_STATE(cif)
	
	add	%g1, CONTEXT_STATE_SIZE, %g5
	setx	_fcstack_ptr, %g6, %g7
	stx	%g5, [%g7]
	
	/* Restore stack */
	setx	client_stack, %g6, %g7
	ldx	[%g7], %sp
	
	/* Restore %pc */
	ldx	[%g1 + 0x4d0], %o7
	
	/* Restore globals */
	ldx	[%g1 + 0x38], %g2
	ldx	[%g1 + 0x40], %g3
	ldx	[%g1 + 0x48], %g4 
	ldx	[%g1 + 0x50], %g5 
	ldx	[%g1 + 0x58], %g6
	ldx	[%g1 + 0x60], %g7
	
	jmp	%o7
	 ldx	[%g1 + 0x30], %g1
