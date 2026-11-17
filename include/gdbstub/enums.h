/*
 * gdbstub enums
 *
 * Copyright (c) 2024 Linaro Ltd
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef GDBSTUB_ENUMS_H
#define GDBSTUB_ENUMS_H

#define DEFAULT_GDBSTUB_PORT "1234"

/* GDB breakpoint/watchpoint types */
typedef enum GdbBreakpointType {
    GDB_BREAKPOINT_SW       = 0,
    GDB_BREAKPOINT_HW       = 1,
    GDB_WATCHPOINT_WRITE    = 2,
    GDB_WATCHPOINT_READ     = 3,
    GDB_WATCHPOINT_ACCESS   = 4,
} GdbBreakpointType;

#endif /* GDBSTUB_ENUMS_H */
