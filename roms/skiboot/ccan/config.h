/* Copyright 2013-2014 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/* Dummy config.h for CCAN test suite */
#ifndef CCAN_CONFIG_H
#define CCAN_CONFIG_H
#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* Always use GNU extensions. */
#endif

#include <endian.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define HAVE_BIG_ENDIAN         0
#define HAVE_LITTLE_ENDIAN      1
#else
#define HAVE_BIG_ENDIAN         1
#define HAVE_LITTLE_ENDIAN      0
#endif

#define HAVE_BUILTIN_TYPES_COMPATIBLE_P 1
#define HAVE_TYPEOF 1

#define HAVE_BYTESWAP_H 1
#define HAVE_BSWAP_64 1

#endif /* CCAN_CONFIG_H */
