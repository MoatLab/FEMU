#include <errno.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <linux/nvme_ioctl.h>

#define POSIX_FADV_STREAMID 8 
#define IO_TRANSFER_SIZE (4*1024) 
#define IO_ST_TRANSFER_SIZE (16*1024) 
#define IO_SEGMENT_SIZE (IO_TRANSFER_SIZE * 8) 
#define MAX_FILE_OFFSET (1024 * 10)

#define IO_OFFSET_ST 0x2000
#define IO_OFFSET_NW 0xa000 

#define nvme_admin_directive_send 0x19
#define nvme_admin_directive_recv 0x1a

//#define IO_OPEN_OPTIONS (O_RDWR | O_DIRECT | O_LARGEFILE)
#define IO_OPEN_OPTIONS (O_RDWR | O_DIRECT | O_NONBLOCK | O_ASYNC)

static unsigned long next;

struct sdm {
	char *fn;
	unsigned int sid;
	unsigned char *data_in;
	unsigned char *data_out;
};


