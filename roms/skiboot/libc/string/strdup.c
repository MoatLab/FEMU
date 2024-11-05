/******************************************************************************
 * Copyright (c) 2012 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#include <stdlib.h>

size_t strlen(const char *s);
void *memcpy(void *dest, const void *src, size_t n);
char *strdup(const char *src);
char *strdup(const char *src)
{
	size_t len = strlen(src) + 1;
	char *ret;

	ret = malloc(len);
	if (ret)
		memcpy(ret, src, len);
	return ret;
}
