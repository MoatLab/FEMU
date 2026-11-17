/*
 * S390 guest code used in migration tests
 *
 * Copyright 2018 Thomas Huth, Red Hat Inc.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

/* for sclp.h */
#define LOADPARM_LEN 8
typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;

#include <sclp.h>

#define START_ADDRESS  (1024 * 1024)
#define END_ADDRESS    (100 * 1024 * 1024)

/* at pc-bios/s390-ccw/start.S */

void  __attribute__((weak)) consume_sclp_int(void)
{
}

static char _sccb[4096] __attribute__((__aligned__(4096)));
char stack[0x8000] __attribute__((aligned(4096)));

static void sclp_service_call(unsigned int command)
{
        int cc;

        asm volatile(
                "       .insn   rre,0xb2200000,%1,%2\n"  /* servc %1,%2 */
                "       ipm     %0\n"
                "       srl     %0,28"
                : "=&d" (cc) : "d" (command), "a" (__pa(_sccb))
                : "cc", "memory");
        consume_sclp_int();
}

static void sclp_setup(void)
{
    WriteEventMask *sccb = (void *)_sccb;

    sccb->h.length = sizeof(WriteEventMask);

    sccb->mask_length = sizeof(unsigned int);
    sccb->cp_receive_mask = 0;
    sccb->cp_send_mask = SCLP_EVENT_MASK_MSG_ASCII;

    sclp_service_call(SCLP_CMD_WRITE_EVENT_MASK);
}

static void putc(const char c)
{
    WriteEventData *sccb = (void *)_sccb;
    int len = 1;

    sccb->data[0] = c;

    sccb->h.length = sizeof(WriteEventData) + len;
    sccb->h.function_code = SCLP_FC_NORMAL_WRITE;

    sccb->ebh.length = sizeof(EventBufferHeader) + len;
    sccb->ebh.type = SCLP_EVENT_ASCII_CONSOLE_DATA;
    sccb->ebh.flags = 0;

    sclp_service_call(SCLP_CMD_WRITE_EVENT_DATA);
}

void main(void)
{
    unsigned long addr;

    sclp_setup();
    putc('A');

    /*
     * Make sure all of the pages have consistent contents before incrementing
     * the first byte below.
     */
    for (addr = START_ADDRESS; addr < END_ADDRESS; addr += 4096) {
        *(volatile char *)addr = 0;
    }

    while (1) {
        for (addr = START_ADDRESS; addr < END_ADDRESS; addr += 4096) {
            *(volatile char *)addr += 1;  /* Change pages */
        }
        putc('B');
    }
}
