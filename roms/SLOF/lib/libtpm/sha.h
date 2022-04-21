/*****************************************************************************
 * Copyright (c) 2015-2020 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#ifndef __SHA_H
#define __SHA_H

#include "types.h"

void sha1(const uint8_t *data, uint32_t length, uint8_t *hash);
void sha256(const uint8_t *data, uint32_t length, uint8_t *hash);
void sha384(const uint8_t *data, uint32_t length, uint8_t *hash);
void sha512(const uint8_t *data, uint32_t length, uint8_t *hash);

#endif /* __SHA_H */
