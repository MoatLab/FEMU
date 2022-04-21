// Low-level serial (and serial-like) device access.
//
// Copyright (C) 2008-1013  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "config.h" // CONFIG_DEBUG_SERIAL
#include "fw/paravirt.h" // RunningOnQEMU
#include "output.h" // dprintf
#include "serialio.h" // serial_debug_preinit
#include "x86.h" // outb


/****************************************************************
 * Serial port debug output
 ****************************************************************/

#define DEBUG_TIMEOUT 100000

// Write to a serial port register
static void
serial_debug_write(u8 offset, u8 val)
{
    if (CONFIG_DEBUG_SERIAL) {
        outb(val, CONFIG_DEBUG_SERIAL_PORT + offset);
    } else if (CONFIG_DEBUG_SERIAL_MMIO) {
        ASSERT32FLAT();
        writeb((void*)CONFIG_DEBUG_SERIAL_MEM_ADDRESS + 4*offset, val);
    }
}

// Read from a serial port register
static u8
serial_debug_read(u8 offset)
{
    if (CONFIG_DEBUG_SERIAL)
        return inb(CONFIG_DEBUG_SERIAL_PORT + offset);
    if (CONFIG_DEBUG_SERIAL_MMIO) {
        ASSERT32FLAT();
        return readb((void*)CONFIG_DEBUG_SERIAL_MEM_ADDRESS + 4*offset);
    }
}

// Setup the debug serial port for output.
void
serial_debug_preinit(void)
{
    if (!CONFIG_DEBUG_SERIAL && (!CONFIG_DEBUG_SERIAL_MMIO || MODESEGMENT))
        return;
    // setup for serial logging: 8N1
    u8 oldparam, newparam = 0x03;
    oldparam = serial_debug_read(SEROFF_LCR);
    serial_debug_write(SEROFF_LCR, newparam);
    // Disable irqs
    u8 oldier, newier = 0;
    oldier = serial_debug_read(SEROFF_IER);
    serial_debug_write(SEROFF_IER, newier);

    if (oldparam != newparam || oldier != newier)
        dprintf(1, "Changing serial settings was %x/%x now %x/%x\n"
                , oldparam, oldier, newparam, newier);
}

// Write a character to the serial port.
static void
serial_debug(char c)
{
    if (!CONFIG_DEBUG_SERIAL && (!CONFIG_DEBUG_SERIAL_MMIO || MODESEGMENT))
        return;
    int timeout = DEBUG_TIMEOUT;
    while ((serial_debug_read(SEROFF_LSR) & 0x20) != 0x20)
        if (!timeout--)
            // Ran out of time.
            return;
    serial_debug_write(SEROFF_DATA, c);
}

void
serial_debug_putc(char c)
{
    if (c == '\n')
        serial_debug('\r');
    serial_debug(c);
}

// Make sure all serial port writes have been completely sent.
void
serial_debug_flush(void)
{
    if (!CONFIG_DEBUG_SERIAL && (!CONFIG_DEBUG_SERIAL_MMIO || MODESEGMENT))
        return;
    int timeout = DEBUG_TIMEOUT;
    while ((serial_debug_read(SEROFF_LSR) & 0x60) != 0x60)
        if (!timeout--)
            // Ran out of time.
            return;
}


/****************************************************************
 * QEMU debug port
 ****************************************************************/

portaddr_t DebugOutputPort VARFSEG = 0x402;

void
qemu_debug_preinit(void)
{
    /* Xen doesn't support checking if debug output is active. */
    if (runningOnXen())
        return;

    /* Check if the QEMU debug output port is active */
    if (CONFIG_DEBUG_IO &&
        inb(GET_GLOBAL(DebugOutputPort)) != QEMU_DEBUGCON_READBACK)
        DebugOutputPort = 0;
}

// Write a character to the special debugging port.
void
qemu_debug_putc(char c)
{
    if (!CONFIG_DEBUG_IO || !runningOnQEMU())
        return;
    u16 port = GET_GLOBAL(DebugOutputPort);
    if (port)
        // Send character to debug port.
        outb(c, port);
}
