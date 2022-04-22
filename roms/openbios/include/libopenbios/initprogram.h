/*
 *   Creation Date: <2010/04/02 13:00:00 mcayland>
 *   Time-stamp: <2010/04/02 13:00:00 mcayland>
 *
 *	<initprogram.h>
 *
 *	C implementation of (init-program) word
 *
 *   Copyright (C) 2010 Mark Cave-Ayland (mark.cave-ayland@siriusit.co.uk)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   version 2
 *
 */

#ifndef _H_INITPROGRAM
#define _H_INITPROGRAM

extern struct context * volatile __context;
extern unsigned int start_elf(void);

extern int	arch_init_program(void);
extern void	init_program(void);

void init_fcode_context(void);
void init_forth_context(void);

void go(void);

#endif   /* _H_INITPROGRAM */
