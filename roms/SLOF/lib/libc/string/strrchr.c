/******************************************************************************
 * libc strrchr() implementation
 *
 * This program and the accompanying materials are made available under
 * the terms of the BSD License which accompanies this distribution, and
 * is available at http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     Thomas Huth - initial implementation
 *****************************************************************************/

#include <string.h>

char *
strrchr(const char *s, int c)
{
	char cb = c;
	char *ptr = (char *)s + strlen(s) - 1;

	while (ptr >= s) {
		if (*ptr == cb) {
			return ptr;
		}
		--ptr;
	}

	return NULL;
}
