/******************************************************************************
 * Copyright (c) 2004, 2008 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#ifndef CRCLIB_H
#define CRCLIB_H
#include <stdint.h>

extern uint64_t ui64Generator1;

int createCRCParameter(uint64_t *, unsigned int *);
uint64_t calCRCword(unsigned char *, uint32_t, uint64_t);
uint64_t checkCRC(unsigned char *, uint32_t, uint64_t);

#endif /* CRCLIB_H */
