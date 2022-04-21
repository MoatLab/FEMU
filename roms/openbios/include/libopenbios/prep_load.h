/*
 *   Creation Date: <2010/03/22 18:00:00 mcayland>
 *   Time-stamp: <2010/03/22 18:00:00 mcayland>
 *
 *   <prep_load.h>
 *
 *   PReP boot partition loader
 *
 *   Copyright (C) 2018 Mark Cave-Ayland (mark.cave-ayland@ilande.co.uk)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation
 *
 */

#ifndef _H_PREPLOAD
#define _H_PREPLOAD

extern int prep_load(ihandle_t dev);
int is_prep(char *addr);
void prep_init_program(void);

#endif   /* _H_PREPLOAD */
