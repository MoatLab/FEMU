/* tag: forth source loader
 *
 * Copyright (C) 2004 Stefan Reinauer
 *
 * See the file "COPYING" for further information about
 * the copyright and warranty status of this work.
 */

#include "config.h"
#include "kernel/kernel.h"
#include "libopenbios/bindings.h"
#include "libopenbios/initprogram.h"
#include "libopenbios/sys_info.h"
#include "libc/diskio.h"
#include "libopenbios/forth_load.h"
#define printk printk
#define debug printk

static int fd;

int is_forth(char *forth)
{
	return (forth[0] == '\\' && forth[1] == ' ');
}

int forth_load(ihandle_t dev)
{
    char magic[2];
    unsigned long forthsize;
    ucell *forthtext;
    int retval = -1;

    /* Mark the saved-program-state as invalid */
    feval("0 state-valid !");

    fd = open_ih(dev);
    if (fd == -1) {
	goto out;
    }

    if (read_io(fd, magic, 2) != 2) {
	debug("Can't read magic header\n");
	retval = LOADER_NOT_SUPPORT;
	goto out;
    }

    if (!is_forth(magic)) {
	debug("No forth source image\n");
	retval = LOADER_NOT_SUPPORT;
	goto out;
    }

    /* Calculate the file size by seeking to the end of the file */
    seek_io(fd, -1);
    forthsize = tell(fd);
    seek_io(fd, 0);

    fword("load-base");
    forthtext = (void *)POP();
    
    printk("Loading forth source ...");
    if ((size_t)read_io(fd, forthtext, forthsize) != forthsize) {
	printk("Can't read forth text\n");
	goto out;
    }
    forthtext[(forthsize / sizeof(ucell)) + 1]=0;
    printk("ok\n");

    // Initialise saved-program-state
    PUSH((ucell)forthsize);
    feval("load-state >ls.file-size !");
    feval("forth load-state >ls.file-type !");

out:
    return retval;
}

void 
forth_init_program(void)
{
    /* Use trampoline context to execute Forth */
    PUSH((ucell)&init_forth_context);
    feval("load-state >ls.entry !");
    
    arch_init_program();
    
    feval("-1 state-valid !");
}
