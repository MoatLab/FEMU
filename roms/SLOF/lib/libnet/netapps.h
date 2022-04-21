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

#ifndef _NETAPPS_H_
#define _NETAPPS_H_

#define F_IPV4	4
#define F_IPV6	6

struct filename_ip;

extern int netload(char *buffer, int len, char *args_fs, unsigned alen);
extern int ping(char *args_fs, unsigned alen);
extern int dhcp(char *ret_buffer, struct filename_ip *fn_ip,
		unsigned int retries, int flags);

#endif
