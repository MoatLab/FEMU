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

#include <tftp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>

#include <ethernet.h>
#include <ipv4.h>
#include <ipv6.h>
#include <udp.h>
#include <dns.h>

//#define __DEBUG__

#define MAX_BLOCKSIZE 1428
#define BUFFER_LEN 256
#define INVALID_BUFFER ((void *)-1L)

#define ENOTFOUND 1
#define EACCESS   2
#define EBADOP    4
#define EBADID    5
#define ENOUSER   7
//#define EUNDEF 0
//#define ENOSPACE 3
//#define EEXISTS 6

#define RRQ   1
#define WRQ   2
#define DATA  3
#define ACK   4
#define ERROR 5
#define OACK  6

/* Local variables */
static unsigned char packet[BUFFER_LEN];
static unsigned char  *buffer = INVALID_BUFFER;
static unsigned short block;
static unsigned short blocksize;
static char blocksize_str[6];    /* Blocksize string for read request */
static int received_len;
static unsigned int retries;
static int huge_load;
static int len;
static int tftp_finished;
static int lost_packets;
static int tftp_errno;
static int ip_version;
static short port_number;
static tftp_err_t *tftp_err;
static filename_ip_t  *fn_ip;
static int progress_first;
static int progress_last_bytes;

/**
 * dump_package - Prints a package.
 *
 * @package: package which is to print
 * @len:     length of the package
 */
#ifdef __DEBUG__

static void dump_package(unsigned char *buffer, unsigned int len)
{
	int i;

	for (i = 1; i <= len; i++) {
		printf("%02x%02x ", buffer[i - 1], buffer[i]);
		i++;
		if ((i % 16) == 0)
			printf("\n");
	}
	printf("\n");
}
#endif

/**
 * send_rrq - Sends a read request package.
 *
 * @fd:          Socket Descriptor
 */
static void send_rrq(int fd)
{
	int ip_len = 0;
	int ip6_payload_len    = 0;
	unsigned short udp_len = 0;
	const char mode[] = "octet";
	char *ptr	     = NULL;
	struct iphdr *ip     = NULL;
	struct ip6hdr *ip6   = NULL;
	struct udphdr *udph  = NULL;
	struct tftphdr *tftp = NULL;

	memset(packet, 0, BUFFER_LEN);

	if (4 == ip_version) {
		ip = (struct iphdr *) packet;
		udph = (struct udphdr *) (ip + 1);
		ip_len = sizeof(struct iphdr) + sizeof(struct udphdr)
			+ strlen(fn_ip->filename) + strlen(mode) + 4
			+ strlen("blksize") + strlen(blocksize_str) + 2;
		fill_iphdr ((uint8_t *) ip, ip_len, IPTYPE_UDP, 0,
			    fn_ip->server_ip);
	}
	else if (6 == ip_version) {
		ip6 = (struct ip6hdr *) packet;
		udph = (struct udphdr *) (ip6 + 1);
		ip6_payload_len = sizeof(struct udphdr)
			+ strlen(fn_ip->filename) + strlen(mode) + 4
			+ strlen("blksize") + strlen(blocksize_str) + 2;
		ip_len = sizeof(struct ip6hdr) + ip6_payload_len;
		fill_ip6hdr ((uint8_t *) ip6, ip6_payload_len, IPTYPE_UDP, get_ipv6_address(),
			     &(fn_ip->server_ip6));

	}
	udp_len = htons(sizeof(struct udphdr)
			      + strlen(fn_ip->filename) + strlen(mode) + 4
			      + strlen("blksize") + strlen(blocksize_str) + 2);
	fill_udphdr ((uint8_t *) udph, udp_len, htons(2001), htons(69));

	tftp = (struct tftphdr *) (udph + 1);
	tftp->th_opcode = htons(RRQ);

	ptr = (char *) &tftp->th_data;
	memcpy(ptr, fn_ip->filename, strlen(fn_ip->filename) + 1);

	ptr += strlen(fn_ip->filename) + 1;
	memcpy(ptr, mode, strlen(mode) + 1);

	ptr += strlen(mode) + 1;
	memcpy(ptr, "blksize", strlen("blksize") + 1);

	ptr += strlen("blksize") + 1;
	memcpy(ptr, blocksize_str, strlen(blocksize_str) + 1);

	send_ip (fd, packet, ip_len);

#ifdef __DEBUG__
	printf("tftp RRQ with %d bytes transmitted.\n", ip_len);
#endif
	return;
}

/**
 * send_ack - Sends a acknowlege package.
 *
 * @blckno: block number
 * @dport:  UDP destination port
 */
static void send_ack(int fd, int blckno, unsigned short dport)
{
	int ip_len 	       = 0;
	int ip6_payload_len    = 0;
	unsigned short udp_len = 0;
	struct iphdr *ip     = NULL;
	struct ip6hdr *ip6   = NULL;
	struct udphdr *udph  = NULL;
	struct tftphdr *tftp = NULL;

	memset(packet, 0, BUFFER_LEN);

	if (4 == ip_version) {
		ip = (struct iphdr *) packet;
		udph = (struct udphdr *) (ip + 1);
		ip_len = sizeof(struct iphdr) + sizeof(struct udphdr) + 4;
		fill_iphdr ((uint8_t *) ip, ip_len, IPTYPE_UDP, 0,
			    fn_ip->server_ip);
	}
	else if (6 == ip_version) {
		ip6 = (struct ip6hdr *) packet;
		udph = (struct udphdr *) (ip6 + 1);
		ip6_payload_len = sizeof(struct udphdr) + 4;
		ip_len = sizeof(struct ip6hdr) + ip6_payload_len;
		fill_ip6hdr ((uint8_t *) ip6, ip6_payload_len, IPTYPE_UDP, get_ipv6_address(),
			     &(fn_ip->server_ip6));
	}
	udp_len = htons(sizeof(struct udphdr) + 4);
	fill_udphdr ((uint8_t *) udph, udp_len, htons(2001), htons(dport));

	tftp = (struct tftphdr *) (udph + 1);
	tftp->th_opcode = htons(ACK);
	tftp->th_data = htons(blckno);

	send_ip(fd, packet, ip_len);

#ifdef __DEBUG__
	printf("tftp ACK %d bytes transmitted.\n", ip_len);
#endif

	return;
}

/**
 * send_error - Sends an error package.
 *
 * @fd:          Socket Descriptor
 * @error_code:  Used sub code for error packet
 * @dport:       UDP destination port
 */
static void send_error(int fd, int error_code, unsigned short dport)
{
	int ip_len 	       = 0;
	int ip6_payload_len    = 0;
	unsigned short udp_len = 0;
	struct ip6hdr *ip6   = NULL;
	struct iphdr *ip     = NULL;
	struct udphdr *udph  = NULL;
	struct tftphdr *tftp = NULL;

	memset(packet, 0, BUFFER_LEN);

	if (4 == ip_version) {
		ip = (struct iphdr *) packet;
		udph = (struct udphdr *) (ip + 1);
		ip_len = sizeof(struct iphdr) + sizeof(struct udphdr) + 5;
		fill_iphdr ((uint8_t *) ip, ip_len, IPTYPE_UDP, 0,
			    fn_ip->server_ip);
	}
	else if (6 == ip_version) {
		ip6 = (struct ip6hdr *) packet;
		udph = (struct udphdr *) (ip6 + 1);
		ip6_payload_len = sizeof(struct udphdr) + 5;
		ip_len = sizeof(struct ip6hdr) + ip6_payload_len;
		fill_ip6hdr ((uint8_t *) ip6, ip6_payload_len, IPTYPE_UDP, get_ipv6_address(),
			    &(fn_ip->server_ip6));
	}
	udp_len = htons(sizeof(struct udphdr) + 5);
	fill_udphdr ((uint8_t *) udph, udp_len, htons(2001), htons(dport));

	tftp = (struct tftphdr *) (udph + 1);
	tftp->th_opcode = htons(ERROR);
	tftp->th_data = htons(error_code);
	((char *) &tftp->th_data)[2] = 0;

	send_ip(fd, packet, ip_len);

#ifdef __DEBUG__
	printf("tftp ERROR %d bytes transmitted.\n", ip_len);
#endif

	return;
}

static void print_progress(int urgent, int received_bytes)
{
	static unsigned int i = 1;
	char buffer[100];
	char *ptr;

	// 1MB steps or 0x400 times or urgent
	if(((received_bytes - progress_last_bytes) >> 20) > 0
	|| (i & 0x3FF) == 0 || urgent) {
		if (!progress_first) {
			sprintf(buffer, "%d KBytes", (progress_last_bytes >> 10));
			for(ptr = buffer; *ptr != 0; ++ptr)
				*ptr = '\b';
			printf("%s", buffer);
		}
		printf("%d KBytes", (received_bytes >> 10));
		i = 1;
		progress_first = 0;
		progress_last_bytes = received_bytes;
	}
	++i;
}

/**
 * get_blksize tries to extract the blksize from the OACK package
 * the TFTP returned. From RFC 1782
 * The OACK packet has the following format:
 *
 *   +-------+---~~---+---+---~~---+---+---~~---+---+---~~---+---+
 *   |  opc  |  opt1  | 0 | value1 | 0 |  optN  | 0 | valueN | 0 |
 *   +-------+---~~---+---+---~~---+---+---~~---+---+---~~---+---+
 *
 * @param buffer  the network packet
 * @param len  the length of the network packet
 * @return  the blocksize the server supports or 0 for error
 */
static int get_blksize(unsigned char *buffer, unsigned int len)
{
	unsigned char *orig = buffer;
	/* skip all headers until tftp has been reached */
	buffer += sizeof(struct udphdr);
	/* skip opc */
	buffer += 2;
	while (buffer < orig + len) {
		if (!memcmp(buffer, "blksize", strlen("blksize") + 1))
			return (unsigned short) strtoul((char *) (buffer +
							strlen("blksize") + 1),
							(char **) NULL, 10);
		else {
			/* skip the option name */
			buffer = (unsigned char *) strchr((char *) buffer, 0);
			if (!buffer)
				return 0;
			buffer++;
			/* skip the option value */
			buffer = (unsigned char *) strchr((char *) buffer, 0);
			if (!buffer)
				return 0;
			buffer++;
		}
	}
	return 0;
}

/**
 * Handle incoming tftp packets after read request was sent
 *
 * this function also prints out some status characters
 * \|-/ for each packet received
 * A for an arp packet
 * I for an ICMP packet
 * #+* for different unexpected TFTP packets (not very good)
 *
 * @param fd     socket descriptor
 * @param packet points to the UDP header of the packet
 * @param len    the length of the network packet
 * @return       ZERO if packet was handled successfully
 *               ERRORCODE if error occurred
 */
int32_t handle_tftp(int fd, uint8_t *pkt, int32_t packetsize)
{
	struct udphdr *udph;
	struct tftphdr *tftp;

	/* buffer is only set if we are handling TFTP */
	if (buffer == INVALID_BUFFER)
		return 0;

#ifndef __DEBUG__
	print_progress(0, received_len);
#endif
	udph = (struct udphdr *) pkt;
	tftp = (struct tftphdr *) ((void *) udph + sizeof(struct udphdr));
	set_timer(TICKS_SEC);

#ifdef __DEBUG__
	dump_package(pkt, packetsize);
#endif

	port_number = udph->uh_sport;
	if (tftp->th_opcode == htons(OACK)) {
		/* an OACK means that the server answers our blocksize request */
		blocksize = get_blksize(pkt, packetsize);
		if (!blocksize || blocksize > MAX_BLOCKSIZE) {
			send_error(fd, 8, port_number);
			tftp_errno = -8;
			goto error;
		}
		send_ack(fd, 0, port_number);
	} else if (tftp->th_opcode == htons(ACK)) {
		/* an ACK means that the server did not answers
		 * our blocksize request, therefore we will set the blocksize
		 * to the default value of 512 */
		blocksize = 512;
		send_ack(fd, 0, port_number);
	} else if ((unsigned char) tftp->th_opcode == ERROR) {
#ifdef __DEBUG__
		printf("tftp->th_opcode : %x\n", tftp->th_opcode);
		printf("tftp->th_data   : %x\n", tftp->th_data);
#endif
		switch ( (uint8_t) tftp->th_data) {
		case ENOTFOUND:
			tftp_errno = -3;	// ERROR: file not found
			break;
		case EACCESS:
			tftp_errno = -4;	// ERROR: access violation
			break;
		case EBADOP:
			tftp_errno = -5;	// ERROR: illegal TFTP operation
			break;
		case EBADID:
			tftp_errno = -6;	// ERROR: unknown transfer ID
			break;
		case ENOUSER:
			tftp_errno = -7;	// ERROR: no such user
			break;
		default:
			tftp_errno = -1;	// ERROR: unknown error
		}
		goto error;
	} else if (tftp->th_opcode == DATA) {
		/* DATA PACKAGE */
		if (block + 1 == tftp->th_data) {
			++block;
		}
		else if( block == 0xffff && huge_load != 0
		     &&  (tftp->th_data == 0 || tftp->th_data == 1) ) {
			block = tftp->th_data;
		}
		else if (tftp->th_data == block) {
#ifdef __DEBUG__
			printf
			    ("\nTFTP: Received block %x, expected block was %x\n",
			     tftp->th_data, block + 1);
			printf("\b+ ");
#endif
			send_ack(fd, tftp->th_data, port_number);
			lost_packets++;
			tftp_err->bad_tftp_packets++;
			return 0;
		} else if (tftp->th_data < block) {
#ifdef __DEBUG__
			printf
			    ("\nTFTP: Received block %x, expected block was %x\n",
			     tftp->th_data, block + 1);
			printf("\b* ");
#endif
			/* This means that an old data packet appears (again);
			 * this happens sometimes if we don't answer fast enough
			 * and a timeout is generated on the server side;
			 * as we already have this packet we just ignore it */
			tftp_err->bad_tftp_packets++;
			return 0;
		} else {
			tftp_err->blocks_missed = block + 1;
			tftp_err->blocks_received = tftp->th_data;
			tftp_errno = -42;
			goto error;
		}
		tftp_err->bad_tftp_packets = 0;
		/* check if our buffer is large enough */
		if (received_len + udph->uh_ulen - 12 > len) {
			tftp_errno = -2;
			goto error;
		}
		memcpy(buffer + received_len, &tftp->th_data + 1,
		       udph->uh_ulen - 12);
		send_ack(fd, tftp->th_data, port_number);
		received_len += udph->uh_ulen - 12;
		/* Last packet reached if the payload of the UDP packet
		 * is smaller than blocksize + 12
		 * 12 = UDP header (8) + 4 bytes TFTP payload */
		if (udph->uh_ulen < blocksize + 12) {
			tftp_finished = 1;
			return 0;
		}
		/* 0xffff is the highest block number possible
		 * see the TFTP RFCs */

		if (block >= 0xffff && huge_load == 0) {
			tftp_errno = -9;
			goto error;
		}
	} else {
#ifdef __DEBUG__
		printf("Unknown packet %x\n", tftp->th_opcode);
		printf("\b# ");
#endif
		tftp_err->bad_tftp_packets++;
		return 0;
	}

	return 0;

error:
#ifdef __DEBUG__
	printf("\nTFTP errno: %d\n", tftp_errno);
#endif
	tftp_finished = 1;
	return tftp_errno;
}

/**
 * TFTP: This function handles situation when "Destination unreachable"
 *       ICMP-error occurs during sending TFTP-packet.
 *
 * @param  err_code   Error Code (e.g. "Host unreachable")
 */
void handle_tftp_dun(uint8_t err_code)
{
	tftp_errno = - err_code - 10;
	tftp_finished = 1;
}

/**
 * TFTP: Interface function to load files via TFTP.
 *
 * @param  _fn_ip        contains the following configuration information:
 *                       client IP, TFTP-server IP, filename to be loaded
 * @param  _buffer       destination buffer for the file
 * @param  _len          size of destination buffer
 * @param  _retries      max number of retries
 * @param  _tftp_err     contains info about TFTP-errors (e.g. lost packets)
 * @return               ZERO - error condition occurs
 *                       NON ZERO - size of received file
 */
int tftp(filename_ip_t * _fn_ip, unsigned char *_buffer, int _len,
	 unsigned int _retries, tftp_err_t * _tftp_err)
{
	retries     = _retries;
	fn_ip       = _fn_ip;
	len         = _len;
	ip_version  = _fn_ip->ip_version;
	tftp_errno  = 0;
	tftp_err    = _tftp_err;
	tftp_err->bad_tftp_packets = 0;
	tftp_err->no_packets = 0;

	block = 0;
	received_len = 0;
	tftp_finished = 0;
	lost_packets = 0;
	port_number = -1;
	progress_first = -1;
	progress_last_bytes = 0;
	huge_load   = 1;

	/* Default blocksize must be 512 for TFTP servers
	 * which do not support the RRQ blocksize option */
	blocksize = 512;

	/* Preferred blocksize - used as option for the read request */
	sprintf(blocksize_str, "%d", MAX_BLOCKSIZE);

	printf("  Receiving data:  ");
	print_progress(-1, 0);

	/* Set buffer to a valid address, enables handling of received packets */
	buffer = _buffer;

	set_timer(TICKS_SEC);
	send_rrq(fn_ip->fd);

	while (! tftp_finished) {
		/* if timeout (no packet received) */
		if(get_timer() <= 0) {
			/* the server doesn't seem to retry let's help out a bit */
			if (tftp_err->no_packets > 4 && port_number != -1
			    && block > 1) {
				send_ack(fn_ip->fd, block, port_number);
			}
			else if (port_number == -1 && block == 0
				 && (tftp_err->no_packets&3) == 3) {
				printf("\nRepeating TFTP read request...\n");
				send_rrq(fn_ip->fd);
			}
			tftp_err->no_packets++;
			set_timer(TICKS_SEC);
		}

		/* handle received packets */
		receive_ether(fn_ip->fd);

		/* bad_tftp_packets are counted whenever we receive a TFTP packet
			* which was not expected; if this gets larger than 'retries'
			* we just exit */
		if (tftp_err->bad_tftp_packets > retries) {
			tftp_errno = -40;
			break;
		}

		/* no_packets counts the times we have returned from receive_ether()
			* without any packet received; if this gets larger than 'retries'
			* we also just exit */
		if (tftp_err->no_packets > retries) {
			tftp_errno = -41;
			break;
		}
	}

	/* Setting buffer invalid to disable handling of received packets */
	buffer = INVALID_BUFFER;

	if (tftp_errno)
		return tftp_errno;

	print_progress(-1, received_len);
	printf("\n");
	if (lost_packets)
		printf("Lost ACK packets: %d\n", lost_packets);

	return received_len;
}

/**
 * Parses a tftp arguments, extracts all
 * parameters and fills server ip according to this
 *
 * Parameters:
 * @param  buffer        string with arguments,
 * @param  server_ip	 server ip as result
 * @param  filename	 default filename
 * @param  fd            Socket descriptor
 * @param  len           len of the buffer,
 * @return               0 on SUCCESS and -1 on failure
 */
int parse_tftp_args(char buffer[], char *server_ip, char filename[], int fd,
		    int len)
{
	char *raw;
	char *tmp, *tmp1;
	int i, j = 0;
	char domainname[256];
	uint8_t server_ip6[16];

	raw = malloc(len);
	if (raw == NULL) {
		printf("\n unable to allocate memory, parsing failed\n");
		return -1;
	}
	strncpy(raw, (const char *)buffer, len);
	/* tftp url contains tftp://[fd00:4f53:4444:90:214:5eff:fed9:b200]/testfile */
	if (strncmp(raw, "tftp://", 7)){
		printf("\n tftp missing in %s\n", raw);
		free(raw);
		return -1;
	}
	tmp = strchr(raw, '[');
	if (tmp != NULL && *tmp == '[') {
		/* check for valid ipv6 address */
		tmp1 = strchr(tmp, ']');
		if (tmp1 == NULL) {
			printf("\n missing ] in %s\n", raw);
			free(raw);
			return -1;
		}
		i = tmp1 - tmp;
		/* look for file name */
		tmp1 = strchr(tmp, '/');
		if (tmp1 == NULL) {
			printf("\n missing filename in %s\n", raw);
			free(raw);
			return -1;
		}
		tmp[i] = '\0';
		/* check for 16 byte ipv6 address */
		if (!str_to_ipv6(tmp + 1, (uint8_t *)server_ip)) {
			printf("\n wrong format IPV6 address in %s\n", raw);
			free(raw);
			return -1;;
		}
		else {
			/* found filename */
			strcpy(filename, tmp1 + 1);
			free(raw);
			return 0;
		}
	}
	else {
		/* here tftp://hostname/testfile from option request of dhcp */
		/* look for dns server name */
		tmp1 = strchr(raw, '.');
		if (tmp1 == NULL) {
			printf("\n missing . seperator in %s\n", raw);
			free(raw);
			return -1;
		}
		/* look for domain name beyond dns server name
		 * so ignore the current . and look for one more */
		tmp = strchr(tmp1 + 1, '.');
		if (tmp == NULL) {
			printf("\n missing domain in %s\n", raw);
			free(raw);
			return -1;
		}
		tmp1 = strchr(tmp1, '/');
		if (tmp1 == NULL) {
			printf("\n missing filename in %s\n", raw);
			free(raw);
			return -1;
		}
		j = tmp1 - (raw + 7);
		tmp = raw + 7;
		tmp[j] = '\0';
		strcpy(domainname, tmp);
		if (dns_get_ip(fd, domainname, server_ip6, 6) == 0) {
			printf("\n DNS failed for IPV6\n");
			return -1;
		}
		ipv6_to_str(server_ip6, server_ip);

		strcpy(filename, tmp1 + 1);
		free(raw);
		return 0;
	}
}

int tftp_get_error_info(filename_ip_t *fnip, tftp_err_t *tftperr, int rc,
                        const char **errstr, int *ecode)
{
	static char estrbuf[80];

	if (rc == -1) {
		*ecode = 0x3003;
		*errstr = "unknown TFTP error";
		return -103;
	} else if (rc == -2) {
		*ecode = 0x3004;
		snprintf(estrbuf, sizeof(estrbuf),
			 "TFTP buffer of %d bytes is too small for %s", len,
			fnip->filename);
		*errstr = estrbuf;
		return -104;
	} else if (rc == -3) {
		*ecode = 0x3009;
		snprintf(estrbuf, sizeof(estrbuf), "file not found: %s",
			 fnip->filename);
		*errstr = estrbuf;
		return -108;
	} else if (rc == -4) {
		*ecode = 0x3010;
		*errstr = "TFTP access violation";
		return -109;
	} else if (rc == -5) {
		*ecode = 0x3011;
		*errstr = "illegal TFTP operation";
		return -110;
	} else if (rc == -6) {
		*ecode = 0x3012;
		*errstr = "unknown TFTP transfer ID";
		return -111;
	} else if (rc == -7) {
		*ecode = 0x3013;
		*errstr = "no such TFTP user";
		return -112;
	} else if (rc == -8) {
		*ecode = 0x3017;
		*errstr = "TFTP blocksize negotiation failed";
		return -116;
	} else if (rc == -9) {
		*ecode = 0x3018;
		*errstr = "file exceeds maximum TFTP transfer size";
		return -117;
	} else if (rc <= -10 && rc >= -15) {
		const char *icmp_err_str;
		switch (rc) {
		case -ICMP_NET_UNREACHABLE - 10:
			icmp_err_str = "net unreachable";
			break;
		case -ICMP_HOST_UNREACHABLE - 10:
			icmp_err_str = "host unreachable";
			break;
		case -ICMP_PROTOCOL_UNREACHABLE - 10:
			icmp_err_str = "protocol unreachable";
			break;
		case -ICMP_PORT_UNREACHABLE - 10:
			icmp_err_str = "port unreachable";
			break;
		case -ICMP_FRAGMENTATION_NEEDED - 10:
			icmp_err_str = "fragmentation needed and DF set";
			break;
		case -ICMP_SOURCE_ROUTE_FAILED - 10:
			icmp_err_str = "source route failed";
			break;
		default:
			icmp_err_str = "UNKNOWN";
			break;
		}
		*ecode = 0x3005;
		sprintf(estrbuf, "ICMP ERROR \"%s\"", icmp_err_str);
		*errstr = estrbuf;
		return -105;
	} else if (rc == -40) {
		*ecode = 0x3014;
		sprintf(estrbuf,
			"TFTP error occurred after %d bad packets received",
			tftperr->bad_tftp_packets);
		*errstr = estrbuf;
		return -113;
	} else if (rc == -41) {
		*ecode = 0x3015;
		sprintf(estrbuf,
			"TFTP error occurred after missing %d responses",
			tftperr->no_packets);
		*errstr = estrbuf;
		return -114;
	} else if (rc == -42) {
		*ecode = 0x3016;
		sprintf(estrbuf,
			"TFTP error missing block %d, expected block was %d",
			tftperr->blocks_missed, tftperr->blocks_received);
		*errstr = estrbuf;
		return -115;
	}

	return rc;
}
