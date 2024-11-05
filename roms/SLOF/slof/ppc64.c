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

#include <unistd.h>
#include <sys/socket.h>
#include <cpu.h>

void asm_cout(long Character,long UART,long NVRAM);

/* the exception frame should be page aligned
 * the_exception_frame is used by the handler to store a copy of all
 * registers after an exception; this copy can then be used by paflof's
 * exception handler to printout a register dump */
cell the_exception_frame[0x400 / CELLSIZE] __attribute__ ((aligned(PAGE_SIZE)));;

/* the_client_frame is the register save area when starting a client */
cell the_client_frame[0x1000 / CELLSIZE] __attribute__ ((aligned(0x100)));
cell the_client_stack[0x8000 / CELLSIZE] __attribute__ ((aligned(0x100)));
/* THE forth stack */
cell the_data_stack[0x2000 / CELLSIZE] __attribute__ ((aligned(0x100)));
/* the forth return stack */
cell the_return_stack[0x2000 / CELLSIZE] __attribute__ ((aligned(0x100)));

/* forth stack and return-stack pointers */
cell *restrict dp;
cell *restrict rp;

/* terminal input buffer */
cell the_tib[0x1000 / CELLSIZE] __attribute__ ((aligned(0x100)));
/* temporary string buffers */
char the_pockets[NUMPOCKETS * POCKETSIZE] __attribute__ ((aligned(0x100)));

cell the_comp_buffer[0x1000 / CELLSIZE] __attribute__ ((aligned(0x100)));

cell the_heap[HEAP_SIZE / CELLSIZE] __attribute__ ((aligned(0x1000)));
cell *the_heap_start = &the_heap[0];
cell *the_heap_end = &the_heap[HEAP_SIZE / CELLSIZE];

extern void io_putchar(unsigned char);
extern unsigned long call_c(cell arg0, cell arg1, cell arg2, cell entry);


static long writeLogByte_wrapper(long x, long y)
{
	unsigned long result;

	SET_CI;
	result = writeLogByte(x, y);
	CLR_CI;

	return result;
}


/**
 * Standard write function for the libc.
 *
 * @param fd    file descriptor (should always be 1 or 2)
 * @param buf   pointer to the array with the output characters
 * @param count number of bytes to be written
 * @return      the number of bytes that have been written successfully
 */
ssize_t write(int fd, const void *buf, size_t count)
{
	char *ptr = (char *)buf;
	int len;

	if (fd != 1 && fd != 2)
		return 0;

	if (!init_engine || fd == 2) {
		len = count;
		while (len-- > 0) {
			if (*ptr == '\n')
				io_putchar('\r');
			io_putchar(*ptr++);
		}
		return count;
	}

	while ((ptr = strchr(buf, '\n')) != NULL) {
		forth_push((long)buf);
		forth_push((long)ptr - (long)buf);
		forth_eval("type cr");
		buf = ptr + 1;
	}
	len = strlen(buf);
	if (len) {
		forth_push((long)buf);
		forth_push(len);
		forth_eval("type");
	}

	return count;
}

/* This should probably be temporary until a better solution is found */
void
asm_cout(long Character, long UART, long NVRAM __attribute__((unused)))
{
	if (UART)
		io_putchar(Character);
}

static type_u find_method(type_u phandle, const char *name)
{
	forth_push((type_u)name);
	forth_push(strlen(name));
	forth_push(phandle);
	forth_eval("find-method");
	if (forth_pop())
		return forth_pop();

	return 0;
}

#define FILEIO_TYPE_EMPTY   0
#define FILEIO_TYPE_FILE    1
#define FILEIO_TYPE_SOCKET  2

struct fileio_type {
	int type;
	type_u read_xt;
	type_u write_xt;
};

#define FILEIO_MAX 32
static struct fileio_type fd_array[FILEIO_MAX];

int socket(int domain, int type, int proto, char *mac_addr)
{
	const char mac_prop_name[] = "local-mac-address";
	type_u phandle;
	uint8_t *prop_addr;
	int prop_len;
	int fd;

	if (!(domain == AF_INET || domain == AF_INET6))
		return -1;

	if (type != SOCK_DGRAM || proto != 0)
		return -1;

	/* search free file descriptor (and skip stdio handlers) */
	for (fd = 3; fd < FILEIO_MAX; ++fd) {
		if (fd_array[fd].type == FILEIO_TYPE_EMPTY) {
			break;
		}
	}
	if (fd == FILEIO_MAX) {
		puts("Can not open socket, file descriptor list is full");
		return -2;
	}

	/* Assume that obp-tftp package is the current one, so
	 * my-parent is the NIC node that we are interested in */
	forth_eval("my-parent ?dup IF ihandle>phandle THEN");
	phandle = forth_pop();
	if (phandle == 0) {
		puts("Can not open socket, no parent instance");
		return -1;
	}
	fd_array[fd].read_xt = find_method(phandle, "read");
	if (!fd_array[fd].read_xt) {
		puts("Can not open socket, no 'read' method");
		return -1;
	}
	fd_array[fd].write_xt = find_method(phandle, "write");
	if (!fd_array[fd].write_xt) {
		puts("Can not open socket, no 'write' method");
		return -1;
	}

	/* Read MAC address from device */
	forth_push((unsigned long)mac_prop_name);
	forth_push(strlen(mac_prop_name));
	forth_push(phandle);
	forth_eval("get-property");
	if (forth_pop())
		return -1;
	prop_len = forth_pop();
	prop_addr = (uint8_t *)forth_pop();
	memcpy(mac_addr, &prop_addr[prop_len - 6], 6);

	fd_array[fd].type = FILEIO_TYPE_SOCKET;

	return fd;
}

static inline int is_valid_fd(int fd)
{
	return fd >= 0 && fd < FILEIO_MAX &&
	       fd_array[fd].type != FILEIO_TYPE_EMPTY;
}

int close(int fd)
{
	if (!is_valid_fd(fd))
		return -1;

	fd_array[fd].type = FILEIO_TYPE_EMPTY;

	return 0;
}

/**
 * Standard recv function for the libc.
 *
 * @param fd     socket file descriptor
 * @param buf    pointer to the array where the packet should be stored
 * @param len    maximum length in bytes of the packet
 * @param flags  currently unused, should be 0
 * @return       the number of bytes that have been received successfully
 */
int recv(int fd, void *buf, int len, int flags)
{
	if (!is_valid_fd(fd) || flags)
		return -1;

	forth_push((unsigned long)buf);
	forth_push(len);
	forth_push(fd_array[fd].read_xt);
	return forth_eval_pop("EXECUTE");
}

/**
 * Standard send function for the libc.
 *
 * @param fd     socket file descriptor
 * @param buf    pointer to the array with the output packet
 * @param len    length in bytes of the packet
 * @param flags  currently unused, should be 0
 * @return       the number of bytes that have been sent successfully
 */
int send(int fd, const void *buf, int len, int flags)
{
	if (!is_valid_fd(fd) || flags)
		return -1;

	forth_push((unsigned long)buf);
	forth_push(len);
	forth_push(fd_array[fd].write_xt);
	return forth_eval_pop("EXECUTE");

}

/**
 * Standard read function for the libc.
 *
 * @param fd    file descriptor (should always be 0 or 2)
 * @param buf   pointer to the array with the output characters
 * @param len    number of bytes to be read
 * @return      the number of bytes that have been read successfully
 */
ssize_t read(int fd, void *buf, size_t len)
{
	char *ptr = (char *)buf;
	unsigned cnt = 0;
	char code;

	if (fd == 0 || fd == 2) {
		while (cnt < len) {
			code = forth_eval_pop("key? IF key ELSE 0 THEN");
			if (!code)
				break;
			ptr[cnt++] = code;
		}
	}

	return cnt;
}
