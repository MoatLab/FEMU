// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Compile with:
 *   gcc -static -O2 mambo-socket-proxy.c -o mambo-socket-proxy -pthread
 * Run inside the simulator:
 *   - to forward host ssh connections to sim ssh server
 *     ./mambo-socket-proxy -h 10022 -s 22
 *        Then connect to port 10022 on your host
 *        ssh -p 10022 localhost
 *   - to allow http proxy access from inside the sim to local http proxy
 *     ./mambo-socket-proxy -b proxy.mynetwork -h 3128 -s 3128
 *
 * Copyright (C) 2017 Michael Neuling <mikey@neuling.org>, IBM
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <getopt.h>

#define CALL_TCL		       86
#define BOGUS_SOCKET_CONN_PROBE_CODE  224
#define BOGUS_SOCKET_CONN_SEND_CODE   225
#define BOGUS_SOCKET_CONN_RECV_CODE   226

static inline int callthru2(int command, unsigned long arg1, unsigned long arg2)
{
	register int c asm("r3") = command;
	register unsigned long a1 asm("r4") = arg1;
	register unsigned long a2 asm("r5") = arg2;
	asm volatile (".long 0x000eaeb0":"=r" (c):"r"(c), "r"(a1), "r"(a2));
	return (c);
}

static inline int callthru3(int command, unsigned long arg1, unsigned long arg2,
			    unsigned long arg3)
{
	register int c asm("r3") = command;
	register unsigned long a1 asm("r4") = arg1;
	register unsigned long a2 asm("r5") = arg2;
	register unsigned long a3 asm("r6") = arg3;
	asm volatile (".long 0x000eaeb0":"=r" (c):"r"(c), "r"(a1), "r"(a2),
		      "r"(a3));
	return (c);
}

static inline int callthru4(int command, unsigned long arg1, unsigned long arg2,
                            unsigned long arg3, unsigned long arg4)
{
    register int c asm("r3") = command;
    register unsigned long a1 asm("r4") = arg1;
    register unsigned long a2 asm("r5") = arg2;
    register unsigned long a3 asm("r6") = arg3;
    register unsigned long a4 asm("r7") = arg4;
    asm volatile (".long 0x000eaeb0":"=r" (c):"r"(c),  "r"(a1), "r"(a2),
                                              "r"(a3), "r"(a4));
    return (c);
}

static inline int callthru5(int command, unsigned long arg1, unsigned long arg2,
                            unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
    register int c asm("r3") = command;
    register unsigned long a1 asm("r4") = arg1;
    register unsigned long a2 asm("r5") = arg2;
    register unsigned long a3 asm("r6") = arg3;
    register unsigned long a4 asm("r7") = arg4;
    register unsigned long a5 asm("r8") = arg5;
    asm volatile (".long 0x000eaeb0":"=r" (c):"r"(c),  "r"(a1), "r"(a2),
                                              "r"(a3), "r"(a4), "r"(a5));
    return (c);
}

unsigned long callthru_tcl(const char *str, int strlen)
{
	return callthru2(CALL_TCL, (unsigned long)str,
			 (unsigned long)strlen);
}

unsigned long bogus_socket_conn_probe(int dev, void *addr, int conn)
{
    return callthru3(BOGUS_SOCKET_CONN_PROBE_CODE,
                     (unsigned long)dev,
                     (unsigned long)addr,
                     (unsigned long)conn);
}

unsigned long bogus_socket_conn_recv(int dev, void *addr, int maxlen, int conn)
{
    return callthru4(BOGUS_SOCKET_CONN_RECV_CODE,
                     (unsigned long)dev,
                     (unsigned long)addr,
                     (unsigned long)maxlen,
                     (unsigned long)conn);
}

unsigned long bogus_socket_conn_send(int dev, void *addr, int maxlen, int conn)
{
    return callthru5(BOGUS_SOCKET_CONN_SEND_CODE,
                     (unsigned long)dev,
                     (unsigned long)addr,
                     (unsigned long)maxlen,
                     0,
                     (unsigned long)conn);
}

#define BUF_MAX 1024

struct sock_info {
	char *host;
	int sock;
	int dev;
	int open;
	int conn;
};

void *recv_thread(void *ptr)
{
	struct timeval timeout;
	struct sock_info *si = ptr;
	char buf[BUF_MAX];
	int len;
	fd_set set;

	/* 1 sec */


	while(1) {
		FD_ZERO(&set);
		FD_SET(si->sock, &set);
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
		/* Set timeout to 1 second */
		len =  select(si->sock+1, &set, NULL, NULL, &timeout);
		if (len <= 0) /* timeout */
			len = -1;
		else 	/* Receive from mambo tcp server */
			len = recv(si->sock, &buf, BUF_MAX, 0);
		if (len == 0) {
			si->open = 0;
			return NULL; /* closed */
		}
		if (len != -1) {
			bogus_socket_conn_send(si->dev, &buf, len, si->conn);
		}
		if (!si->open)
			return NULL;
	}
}

#define POLL_MAX_NS 10000000

void *send_thread(void *ptr)
{
	struct sock_info *si = ptr;
	char buf[BUF_MAX];
	int len;
	struct timespec t;
	int fault_retry = 16;

	t.tv_sec = 0;
	t.tv_nsec = POLL_MAX_NS;

	while(1) {
		/* Send to mambo tcp server */
		len = bogus_socket_conn_recv(si->dev, &buf, BUF_MAX, si->conn);
		if (len == -3 && fault_retry--) {
			 /* Page fault.  Touch the buf and try again */
			memset(buf, 0, BUF_MAX);
			continue;
		}
		fault_retry = 16;

		if (len == -1) /* EAGAIN */
			nanosleep(&t , NULL);
		else if (len > 0)
			send(si->sock, &buf, len, 0);
		else {
			si->open = 0;
			return NULL; /* closed */
		}
		if (!si->open)
			return NULL;
	}

}

void *connect_sockets(void *ptr)
{
	struct sock_info *si = ptr;
	pthread_t recv, send;
	unsigned long rc = 0;

	if (pthread_create(&recv, NULL, recv_thread, si) ||
	    pthread_create(&send, NULL, send_thread, si)) {
		rc = -1;
		goto out;
	}

	if (pthread_join(recv, NULL) || pthread_join(send, NULL)) {
		rc = -1;
		goto out;
	}

out:
	/* FIXME: Do shutdown better */
	shutdown(si->sock, SHUT_WR);
	si->open = 0;
	free(si);
	return (void *)rc;
}

void print_usage() {
	printf("Usage:\n");
	printf("     mambo-socket-proxy [-b <host>] -h <host port> -s <sim port>\n");
	printf("\n");
	printf("             -h <host port>     : Port on the host to forward\n");
	printf("             -s <host port>     : Port in the sim to forward\n");
	printf("             -b <host machine>  : Connect sim port to host network\n");
	printf("\n");
}

int main (int argc, char *argv[])
{
	char cmd[128];
	struct sockaddr_in ser, client;
	pthread_t sockets_thread;
	struct sock_info *si;
	int sock, conn, rc = 0, option = 0, one_shot = 0, c, sock_desc = 0;
	char *host = NULL;
	int host_port = -1, sim_port = -1;
	int dev = 1; /* backwards starts at 1 so forwards can use 0 */

	while ((option = getopt(argc, argv,"rb:h:s:")) != -1) {
		switch (option) {
		case 'b' :
			host = optarg;
			break;
		case 'h' :
			host_port = atoi(optarg);
			break;
		case 's' :
			sim_port = atoi(optarg);
			break;
		default:
			print_usage();
			exit(1);
		}
	}

	if (host_port == -1 || sim_port ==-1) {
		print_usage();
		exit(EXIT_FAILURE);
	}

	/*
	 * A host/backwards connection will use dev=0 and conn >= 0.
	 * The forwards connection will use dev >= 1 and conn=0
	 */
	if (host) {
		sock_desc = socket(PF_INET, SOCK_STREAM, 0);
		ser.sin_family = AF_INET;
		ser.sin_addr.s_addr = INADDR_ANY;
		ser.sin_port = htons(sim_port);

		if (bind(sock_desc, (struct sockaddr *) &ser, sizeof(ser)) < 0) {
			perror("Can't connect to sim port");
			rc = -1;
			goto out;
		}

		listen(sock_desc, 3);
	} else {
		/*
		 * Cleaning up old bogus socket.
		 */
		sprintf(cmd, "mysim bogus socket cleanup");
		callthru_tcl(cmd, strlen(cmd));
		sleep(1); /* Cleanup takes a while */
		sprintf(cmd, "mysim bogus socket init 0 server "
			"127.0.0.1 %i poll 0 nonblock",	host_port);
		callthru_tcl(cmd, strlen(cmd));
	}

	while (1) {

		if (host) {
			sock = accept(sock_desc, (struct sockaddr *)&client, (socklen_t*)&c);
			if (sock < 0) {
				perror("accept failed");
				rc = -1;
				goto out;
			}

			sprintf(cmd, "mysim bogus socket init %i client %s %i poll 0",
				dev, host, host_port);
			callthru_tcl(cmd, strlen(cmd));
			while (bogus_socket_conn_probe(dev, NULL, 0) == -1)
				sleep(1);
		} else {
			struct timespec t;
			t.tv_sec = 0;
			t.tv_nsec = 10000000;
			do {
				conn = bogus_socket_conn_probe(0, NULL, -1);
				nanosleep(&t , NULL);
			} while (conn == -1);

			sock = socket(PF_INET, SOCK_STREAM, 0);
			ser.sin_family = AF_INET;
			ser.sin_port = htons(sim_port);
			ser.sin_addr.s_addr = inet_addr("127.0.0.1");
			memset(ser.sin_zero, '\0', sizeof ser.sin_zero);

			if (connect(sock, (struct sockaddr *) &ser, sizeof(ser))) {
				perror("Can't connect to sim port");
				rc = -1;
				goto out;
			}
		}

		si = malloc(sizeof(struct sock_info));
		si->host = host;
		si->sock = sock;
		si->dev = host?dev:0;
		si->open = 1;
		si->conn = host?0:conn;

		if (pthread_create(&sockets_thread, NULL, connect_sockets, si)) {
				rc = -1;
				goto out;
		}

		if (one_shot)
			break;
		++dev; // FIXME: do a real allocator
	}
out:
	exit(rc);
}
