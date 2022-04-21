#define __ASSEMBLY
#include "psr.h"
#include "asm/asi.h"
#include "cpustate.h"
#define ASI_BP ASI_M_BYPASS
#define REGWIN_SZ   0x40

        .globl    __switch_context, __switch_context_nosave, __exit_context, halt

        .text
        .align 4

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
        FLUSH_ALL_KERNEL_WINDOWS
        
        /* Save everything in stack */        
        st      %g1, [%sp - 0x260 + 0x14]
        st      %g2, [%sp - 0x260 + 0x18]
        st      %g3, [%sp - 0x260 + 0x1c]
        st      %g4, [%sp - 0x260 + 0x20]
        st      %g5, [%sp - 0x260 + 0x24]
        st      %g6, [%sp - 0x260 + 0x28]
        st      %g7, [%sp - 0x260 + 0x2c]

        mov     %sp, %g1
        add     %g1, -0x260, %g1
        
        SAVE_CPU_STATE(switch)

        /* Return PC value */
        mov     %o7, %g2
        add     %g2, 4, %g2
        st      %g2, [%sp - 0x260 + 0x250]

        /* swap context */
        set     __context, %g3
        ld      [%g3], %g2
        st      %g1, [%g3]
        mov     %g2, %g1
        
        ba      __set_context
         nop

__switch_context_nosave:
        FLUSH_ALL_KERNEL_WINDOWS
        
        set     __context, %g1
        ld      [%g1], %g1
        
__set_context:
        RESTORE_CPU_STATE(switch)
        
        /* Restore globals */
        mov     %g1, %g2
        add     %g2, 0x14, %g2
        st      %g2, [%sp - 96]
        
        ld      [%g1 + 0x18], %g2
        ld      [%g1 + 0x1c], %g3
        ld      [%g1 + 0x20], %g4
        ld      [%g1 + 0x24], %g5
        ld      [%g1 + 0x28], %g6
        ld      [%g1 + 0x2c], %g7

        /* Finally, load new %pc */
        ld      [%g1 + 0x250], %g1
        jmpl    %g1, %o7
         ld     [%sp - 96], %g1
        
__exit_context:
        /* Get back to the original context */
        ba    __switch_context
         nop
