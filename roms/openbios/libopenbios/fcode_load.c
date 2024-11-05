/*
 * FCode boot loader
 */

#include "config.h"
#include "kernel/kernel.h"
#include "libopenbios/bindings.h"
#include "libopenbios/fcode_load.h"
#include "libopenbios/initprogram.h"
#include "libopenbios/sys_info.h"
#include "libc/diskio.h"
#define printf printk
#define debug printk

static int fd;

int 
is_fcode(unsigned char *fcode)
{
	return (fcode[0] == 0xf0	// start0
		|| fcode[0] == 0xf1	// start1 
		|| fcode[0] == 0xf2	// start2
		|| fcode[0] == 0xf3	// start4
		|| fcode[0] == 0xfd);	// version1
}

int 
fcode_load(ihandle_t dev)
{
    int retval = -1;
    uint8_t fcode_header[8];
    unsigned long start, size;
    unsigned int offset;

    /* Mark the saved-program-state as invalid */
    feval("0 state-valid !");

    fd = open_ih(dev);
    if (fd == -1) {
        goto out;
    }

    for (offset = 0; offset < 16 * 512; offset += 512) {
        seek_io(fd, offset);
        if (read_io(fd, &fcode_header, sizeof(fcode_header))
            != sizeof(fcode_header)) {
            debug("Can't read FCode header from ihandle " FMT_ucellx "\n", dev);
            retval = LOADER_NOT_SUPPORT;
            goto out;
        }

	if (is_fcode(fcode_header))
            goto found;
    }

    debug("Not a bootable FCode image\n");
    retval = LOADER_NOT_SUPPORT;
    goto out;

 found:
    size = (fcode_header[4] << 24) | (fcode_header[5] << 16) |
        (fcode_header[6] << 8) | fcode_header[7];

    fword("load-base");
    start = POP();

    printf("\nLoading FCode image...\n");

    seek_io(fd, offset);

    if ((size_t)read_io(fd, (void *)start, size) != size) {
        printf("Can't read file (size 0x%lx)\n", size);
        goto out;
    }

    debug("Loaded %lu bytes\n", size);
    debug("entry point is %#lx\n", start);
    
    // Initialise load-state
    PUSH(size);
    feval("load-state >ls.file-size !");
    feval("fcode load-state >ls.file-type !");

out:
    close_io(fd);
    return retval;
}

void 
fcode_init_program(void)
{
    /* Use trampoline context to execute FCode */
    PUSH((ucell)&init_fcode_context);
    feval("load-state >ls.entry !");
    
    arch_init_program();
    
    feval("-1 state-valid !");
}
