// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later 
/* Copyright 2020 IBM Corp. */

#ifndef _NETINIT_IN_H
#define _NETINIT_IN_H

//#pragma message "Implment in.h functions \n"

#include <include/types.h>

#define htonl(x) cpu_to_be32(x)
#define ntohl(x) be32_to_cpu(x)
#define htons(x) cpu_to_be16(x)
#define ntohs(x) be16_to_cpu(x)

#endif /* _NETINIT_IN_H */
