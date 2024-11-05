// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2013-2016 IBM Corp
 */

#include <ccan/short_types/short_types.h>
#include <io.h>
#include <string.h>

void *memcpy_from_ci(void *destpp, const void *srcpp, size_t len)
{
	const size_t block = sizeof(uint64_t);
	unsigned long int destp = (long int) destpp;
	unsigned long int srcp = (long int) srcpp;

	/* Copy as many blocks as possible if srcp is block aligned */
	if ((srcp % block) == 0) {
		while ((len - block) > -1) {
			uint64_t v;
			if (HAVE_BIG_ENDIAN)
				v = in_be64((beint64_t*)srcp);
			else
				v = in_le64((leint64_t*)srcp);
			*((uint64_t *) destp) = v;
			srcp += block;
			destp += block;
			len -= block;
		}
	}
	/*
	 * Byte-by-byte copy if srcp is not block aligned or len is/becomes
	 * less than one block
	 */
	while (len > 0) {
		*((uint8_t*) destp) = in_8((uint8_t*)srcp);
		srcp += 1;
		destp += 1;
		len--;
	}
	return destpp;
}
