/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifndef _LIBMCTP_ALLOC_H
#define _LIBMCTP_ALLOC_H

#include <stdlib.h>

void *__mctp_alloc(size_t size);
void __mctp_free(void *ptr);
void *__mctp_realloc(void *ptr, size_t size);

#endif /* _LIBMCTP_ALLOC_H */
