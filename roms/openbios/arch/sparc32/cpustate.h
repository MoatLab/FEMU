/*
 *   Save/restore CPU state macros
 *
 *   Copyright (C) 2016 Mark Cave-Ayland (mark.cave-ayland@ilande.co.uk>)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   version 2
 *
 */

#include "autoconf.h"

#define STACKFRAME_SZ     0x60

/* These are just handy. */
#define _SV	save	%sp, -STACKFRAME_SZ, %sp
#define _RS     restore

#define FLUSH_ALL_KERNEL_WINDOWS \
	_SV; _SV; _SV; _SV; _SV; _SV; _SV; \
	_RS; _RS; _RS; _RS; _RS; _RS; _RS;


#define SAVE_CPU_GENERAL_STATE(type) \
        /* Save general state into context at %g1 */ \
        rd      %psr, %g4; \
        st      %g4, [%g1]; \
        rd      %wim, %g4; \
        st      %g4, [%g1 + 0x4];

#define SAVE_CPU_WINDOW_STATE(type) \
        /* Save window state into context at %g1 */ \
        st      %o0, [%g1 + 0x30]; \
        st      %o1, [%g1 + 0x34]; \
        st      %o2, [%g1 + 0x38]; \
        st      %o3, [%g1 + 0x3c]; \
        st      %o4, [%g1 + 0x40]; \
        st      %o5, [%g1 + 0x44]; \
        st      %o6, [%g1 + 0x48]; \
        st      %o7, [%g1 + 0x4c]; \
        \
        set     nwindows, %g6; \
        ld      [%g6], %g6;         /* nwindows */ \
        mov     %g6, %g5; \
        sub     %g5, 1, %g5;        /* mask */ \
        \
        rd      %psr, %g4; \
        and     %g4, %g5, %g4;      /* window */ \
        \
        rd      %psr, %g3; \
        srl     %g3, 5, %g3; \
        sll     %g3, 5, %g3;        /* psr hi */ \
        \
        mov     %g1, %g2; \
        add     %g2, 0x50, %g2; \
        \
save_cpu_window_##type: \
        mov     %g3, %g7; \
        or      %g7, %g4, %g7; \
        wr      %g7, %psr; \
        \
        st      %l0, [%g2]; \
        st      %l1, [%g2 + 0x4]; \
        st      %l2, [%g2 + 0x8]; \
        st      %l3, [%g2 + 0xc]; \
        st      %l4, [%g2 + 0x10]; \
        st      %l5, [%g2 + 0x14]; \
        st      %l6, [%g2 + 0x18]; \
        st      %l7, [%g2 + 0x1c]; \
        st      %i0, [%g2 + 0x20]; \
        st      %i1, [%g2 + 0x24]; \
        st      %i2, [%g2 + 0x28]; \
        st      %i3, [%g2 + 0x2c]; \
        st      %i4, [%g2 + 0x30]; \
        st      %i5, [%g2 + 0x34]; \
        st      %i6, [%g2 + 0x38]; \
        st      %i7, [%g2 + 0x3c]; \
        dec     %g4; \
        and     %g4, %g5, %g4; \
        subcc   %g6, 1, %g6; \
        bne     save_cpu_window_##type; \
         add    %g2, 0x40, %g2; \
        \
        /* Get back to the correct window */ \
        ld      [%g1], %g2; \
        wr      %g2, %psr;

#define SAVE_CPU_STATE(type) \
        SAVE_CPU_GENERAL_STATE(type); \
        SAVE_CPU_WINDOW_STATE(type);
        

#define RESTORE_CPU_GENERAL_STATE(type) \
        /* Restore window state from context at %g1 */ \
        ld      [%g1], %g2; \
        wr      %g2, %psr; \
        ld      [%g1 + 0x4], %g2; \
        wr      %g2, %wim;
        
#define RESTORE_CPU_WINDOW_STATE(type) \
        /* Restore window state from context at %g1 */ \
        set     nwindows, %g6; \
        ld      [%g6], %g6;         /* nwindows */ \
        mov     %g6, %g5; \
        sub     %g5, 1, %g5;        /* mask */ \
        \
        rd      %psr, %g4; \
        and     %g4, %g5, %g4;      /* window */ \
        \
        rd      %psr, %g3; \
        srl     %g3, 5, %g3; \
        sll     %g3, 5, %g3;        /* psr hi */ \
        \
        mov     %g1, %g2; \
        add     %g2, 0x50, %g2; \
        \
restore_cpu_window_##type: \
        mov     %g3, %g7; \
        or      %g7, %g4, %g7; \
        wr      %g7, %psr; \
        \
        ld      [%g2], %l0; \
        ld      [%g2 + 0x4], %l1; \
        ld      [%g2 + 0x8], %l2; \
        ld      [%g2 + 0xc], %l3; \
        ld      [%g2 + 0x10], %l4; \
        ld      [%g2 + 0x14], %l5; \
        ld      [%g2 + 0x18], %l6; \
        ld      [%g2 + 0x1c], %l7; \
        ld      [%g2 + 0x20], %i0; \
        ld      [%g2 + 0x24], %i1; \
        ld      [%g2 + 0x28], %i2; \
        ld      [%g2 + 0x2c], %i3; \
        ld      [%g2 + 0x30], %i4; \
        ld      [%g2 + 0x34], %i5; \
        ld      [%g2 + 0x38], %i6; \
        ld      [%g2 + 0x3c], %i7; \
        dec     %g4; \
        and     %g4, %g5, %g4; \
        subcc   %g6, 1, %g6; \
        bne     restore_cpu_window_##type; \
         add    %g2, 0x40, %g2; \
        \
        /* Get back to the correct window */ \
        ld      [%g1], %g2; \
        wr      %g2, %psr; \
        \
        ld      [%g1 + 0x30], %o0; \
        ld      [%g1 + 0x34], %o1; \
        ld      [%g1 + 0x38], %o2; \
        ld      [%g1 + 0x3c], %o3; \
        ld      [%g1 + 0x40], %o4; \
        ld      [%g1 + 0x44], %o5; \
        ld      [%g1 + 0x48], %o6; \
        ld      [%g1 + 0x4c], %o7;

#define RESTORE_CPU_STATE(type) \
        RESTORE_CPU_GENERAL_STATE(type); \
        RESTORE_CPU_WINDOW_STATE(type);
