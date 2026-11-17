/*
 * QEMU VNC display driver
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"

#include "ui/vnc.h"
#include "system/runstate.h"

void vnc_action_shutdown(VncState *vs)
{
    qemu_system_powerdown_request();
}

void vnc_action_reset(VncState *vs)
{
    qemu_system_reset_request(SHUTDOWN_CAUSE_HOST_QMP_SYSTEM_RESET);
}
