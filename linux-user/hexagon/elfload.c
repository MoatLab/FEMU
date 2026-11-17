/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "qemu.h"
#include "loader.h"


const char *get_elf_cpu_model(uint32_t eflags)
{
    static char buf[32];
    int err;

    switch (eflags) {
    case 0x04:
        return "v5";
    case 0x05:
        return "v55";
    case 0x60:
        return "v60";
    case 0x61:
        return "v61";
    case 0x62:
        return "v62";
    case 0x65:
        return "v65";
    case 0x66:
        return "v66";
    case 0x67:
    case 0x8067:        /* v67t */
        return "v67";
    case 0x68:
        return "v68";
    case 0x69:
        return "v69";
    case 0x71:
    case 0x8071:        /* v71t */
        return "v71";
    case 0x73:
        return "v73";
    }

    err = snprintf(buf, sizeof(buf), "unknown (0x%x)", eflags);
    return err >= 0 && err < sizeof(buf) ? buf : "unknown";
}
