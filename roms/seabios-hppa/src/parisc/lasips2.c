/* LASI PS2 keyboard support code
 *
 * Copyright (C) 2019 Sven Schnelle <svens@stackframe.org>
 *
 * This file may be distributed under the terms of the GNU LGPLv2 license.
 */

#include "bregs.h"
#include "autoconf.h"
#include "types.h"
#include "output.h"
#include "hw/ps2port.h"
#include "util.h"
#include "string.h"
#include "lasips2.h"

int lasips2_kbd_in(char *c, int max)
{
    struct bregs regs;
    volatile int count = 0;

    while((readl(LASIPS2_KBD_STATUS) & LASIPS2_KBD_STATUS_RBNE)) {
        process_key(readb(LASIPS2_KBD_DATA));
    }

    while(count < max) {
        memset(&regs, 0, sizeof(regs));
        regs.ah = 0x10;
        handle_16(&regs);
        if (!regs.ah)
            break;
        *c++ = regs.ah;
        count++;
    }
    return count;
}


int ps2_kbd_command(int command, u8 *param)
{
    return 0;
}

int lasips2_command(u16 cmd)
{
    while(readl(LASIPS2_KBD_STATUS) & LASIPS2_KBD_STATUS_TBNE)
        udelay(10);
    writeb(LASIPS2_KBD_DATA, cmd & 0xff);

    while(!(readl(LASIPS2_KBD_STATUS) & LASIPS2_KBD_STATUS_RBNE))
        udelay(10);
    return readb(LASIPS2_KBD_DATA);
}

void ps2port_setup(void)
{
    writeb(LASIPS2_KBD_RESET, 0);
    udelay(1000);
    writeb(LASIPS2_KBD_CONTROL, LASIPS2_KBD_CONTROL_EN);
    lasips2_command(ATKBD_CMD_RESET_BAT);
    lasips2_command(ATKBD_CMD_RESET_DIS);
    lasips2_command(ATKBD_CMD_SSCANSET);
    lasips2_command(0x01);
    lasips2_command(ATKBD_CMD_ENABLE);
    kbd_init();
}
