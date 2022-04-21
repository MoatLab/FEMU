/*
 * PReP boot partition loader
 * Written by Mark Cave-Ayland 2018
 */

#include "config.h"
#include "kernel/kernel.h"
#include "libopenbios/bindings.h"
#include "libopenbios/prep_load.h"
#include "libopenbios/initprogram.h"
#include "libopenbios/sys_info.h"
#include "libc/byteorder.h"
#include "libc/diskio.h"
#include "drivers/drivers.h"
#define printf printk
#define debug printk


int
prep_load(ihandle_t dev)
{
    int retval = LOADER_NOT_SUPPORT, fd, count, size;
    ucell *loadbase;
    unsigned char *image;
    uint32_t entry_point_offset, load_image_length;
    unsigned long entry;

    /* Mark the saved-program-state as invalid */
    feval("0 state-valid !");

    fd = open_ih(dev);
    if (fd == -1) {
        goto out;
    }

    /* Default to loading at load-base */
    fword("load-base");
    loadbase = cell2pointer(POP());

    /* Read block 2 containing the boot info */
    seek_io(fd, 512);
    count = read_io(fd, (void *)loadbase, 512);
    if (count != 512) {
        goto out;
    }

    entry_point_offset = __le32_to_cpu(loadbase[0]);
    load_image_length = __le32_to_cpu(loadbase[1]);

    /* Load the entire image */
    size = 0;
    image = (unsigned char *)loadbase;
    entry = (uintptr_t)loadbase + entry_point_offset;

    seek_io(fd, 0);
    while (size < load_image_length) {
        count = read_io(fd, (void *)image, 512);
        if (count == -1) {
            break;
        }

        size += count;
        image += count;
    }

    /* If we didn't read anything, something went wrong */
    if (!size) {
        goto out;
    }

    /* Set correct size */
    size = load_image_length;

    /* Initialise load-state */
    PUSH(entry);
    feval("load-state >ls.entry !");
    PUSH(size);
    feval("load-state >ls.file-size !");
    feval("prep load-state >ls.file-type !");

out:
    close_io(fd);
    return retval;
}

int
is_prep(char *addr)
{
    /* PReP bootloaders are executed directly. So we'll say that something is
     * PReP if the loader detected the PReP type sucessfully */
    ucell filetype;

    feval("load-state >ls.file-type @");
    filetype = POP();

    return (filetype == 0x13);
}

void
prep_init_program(void)
{
    /* Entry point is already set, just need to setup the context */
    arch_init_program();

    feval("-1 state-valid !");
}
