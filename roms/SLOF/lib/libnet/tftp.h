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


#ifndef _TFTP_H_
#define _TFTP_H_

#include <stdint.h>
#include "ipv6.h"

struct tftphdr {
	int16_t th_opcode;
	uint16_t th_data;
};

struct filename_ip {
	uint32_t own_ip;
	ip6_addr_t own_ip6;
	uint32_t server_ip;
	ip6_addr_t server_ip6;
	ip6_addr_t dns_ip6;
	char filename[256];
	char *pl_cfgfile; /* For PXELINUX DHCPv4 option 209. Must be free()ed */
	char *pl_prefix;  /* For PXELINUX DHCPv4 option 210. Must be free()ed */
	int fd;
	int ip_version;
};
typedef struct filename_ip filename_ip_t;

typedef struct {
	uint32_t bad_tftp_packets;
	uint32_t no_packets;
	uint32_t blocks_missed;
	uint32_t blocks_received;
} tftp_err_t;

int tftp(filename_ip_t *fnip, unsigned char *buf, int len,
         unsigned int retries, tftp_err_t *err);
int32_t handle_tftp(int fd, uint8_t *, int32_t);
void handle_tftp_dun(uint8_t err_code);
int parse_tftp_args(char buffer[], char *server_ip, char filename[], int fd, int len);
int tftp_get_error_info(filename_ip_t *fnip, tftp_err_t *tftperr, int rc,
                        const char **errstr, int *ecode);

#endif
