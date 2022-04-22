/*
 * Copyright (C) 2003, 2004 Stefan Reinauer
 *
 * See the file "COPYING" for further information about
 * the copyright and warranty status of this work.
 */

#include "config.h"
#include "libopenbios/bindings.h"
#include "kernel/kernel.h"
#include "drivers/drivers.h"
#include "libc/vsprintf.h"

/* ******************************************************************
 *          simple polling video/keyboard console functions
 * ****************************************************************** */

#define SER_SIZE 8

/*
 *  keyboard driver
 */

static const char normal[] = {
	0x0, 0x1b, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-',
	'=', '\b', '\t', 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o',
	'p', '[', ']', 0xa, 0x0, 'a', 's', 'd', 'f', 'g', 'h', 'j',
	'k', 'l', ';', 0x27, 0x60, 0x0, 0x5c, 'z', 'x', 'c', 'v', 'b',
	'n', 'm', ',', '.', '/', 0x0, '*', 0x0, ' ', 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, '0', 0x7f
};

static const char shifted[] = {
	0x0, 0x1b, '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_',
	'+', '\b', '\t', 'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O',
	'P', '{', '}', 0xa, 0x0, 'A', 'S', 'D', 'F', 'G', 'H', 'J',
	'K', 'L', ':', 0x22, '~', 0x0, '|', 'Z', 'X', 'C', 'V', 'B',
	'N', 'M', '<', '>', '?', 0x0, '*', 0x0, ' ', 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, '7', '8',
	'9', 0x0, '4', '5', '6', 0x0, '1', '2', '3', '0', 0x7f
};

static int key_ext;
static int key_lshift = 0, key_rshift = 0, key_caps = 0;

static char last_key;

static void pc_kbd_cmd(unsigned char cmd, unsigned char val)
{
	outb(cmd, 0x60);
	/* wait until keyboard controller accepts cmds: */
	while (inb(0x64) & 2);
	outb(val, 0x60);
	while (inb(0x64) & 2);
}

static void pc_kbd_controller_cmd(unsigned char cmd, unsigned char val)
{
	outb(cmd, 0x64);
	/* wait until keyboard controller accepts cmds: */
	while (inb(0x64) & 2);
	outb(val, 0x60);
	while (inb(0x64) & 2);
}

static char pc_kbd_poll(void)
{
	unsigned int c;
	if (inb(0x64) & 1) {
		c = inb(0x60);
		switch (c) {
		case 0xe0:
			key_ext = 1;
			return 0;
		case 0x2a:
			key_lshift = 1;
			return 0;
		case 0x36:
			key_rshift = 1;
			return 0;
		case 0xaa:
			key_lshift = 0;
			return 0;
		case 0xb6:
			key_rshift = 0;
			return 0;
		case 0x3a:
			if (key_caps) {
				key_caps = 0;
				pc_kbd_cmd(0xed, 0);
			} else {
				key_caps = 1;
				pc_kbd_cmd(0xed, 4);	/* set caps led */
			}
			return 0;
		}

		if (key_ext) {
			// void printk(const char *format, ...);
			printk("extended keycode: %x\n", c);

			key_ext = 0;
			return 0;
		}

		if (c & 0x80)	/* unhandled key release */
			return 0;

		if (key_lshift || key_rshift)
			return key_caps ? normal[c] : shifted[c];
		else
			return key_caps ? shifted[c] : normal[c];
	}
	return 0;
}

int pc_kbd_dataready(void)
{
	if (last_key)
		return 1;

	last_key = pc_kbd_poll();

	return (last_key != 0);
}

unsigned char pc_kbd_readdata(void)
{
	char tmp;
	while (!pc_kbd_dataready());
	tmp = last_key;
	last_key = 0;
	return tmp;
}

static void
pc_kbd_reset(void)
{
	/* Reset first port */
	outb(0xae, 0x64);
	while (inb(0x64) & 2);

	/* Write mode command, translated mode */
	pc_kbd_controller_cmd(0x60, 0x40);

	/* Reset keyboard device */
	outb(0xff, 0x60);
	while (inb(0x64) & 2);
	inb(0x60);    /* Should be 0xfa */
	while (inb(0x64) & 2);
	inb(0x60);    /* Should be 0xaa */
}

/* ( addr len -- actual ) */
static void
pc_kbd_read(void)
{
    unsigned char *addr;
    int len;

    len = POP();
    addr = (unsigned char *)POP();

    if (len != 1)
        printk("pc_kbd_read: bad len, addr %lx len %x\n", (unsigned long)addr, len);

    if (pc_kbd_dataready()) {
        *addr = pc_kbd_readdata();
        PUSH(1);
    } else {
        PUSH(0);
    }
}

static void
pc_kbd_close(void)
{
}

static void
pc_kbd_open(unsigned long *address)
{
    PUSH(find_ih_method("address", my_self()));
    fword("execute");
    *address = POP();

    RET ( -1 );
}

DECLARE_UNNAMED_NODE(pc_kbd, 0, sizeof(unsigned long));

NODE_METHODS(pc_kbd) = {
    { "open",               pc_kbd_open              },
    { "close",              pc_kbd_close             },
    { "read",               pc_kbd_read              },
};

void
ob_pc_kbd_init(const char *path, const char *kdev_name, const char *mdev_name,
               uint64_t base, uint64_t offset, int kintr, int mintr)
{
    phandle_t chosen, aliases;
    char nodebuff[128];

    fword("new-device");
    
    push_str("8042");
    fword("device-type");

    push_str("8042");
    fword("device-name");

    /* Make openable */
    fword("is-open");

    PUSH((base + offset) >> 32);
    fword("encode-int");
    PUSH((base + offset) & 0xffffffff);
    fword("encode-int");
    fword("encode+");
    PUSH(SER_SIZE);
    fword("encode-int");
    fword("encode+");
    
    if (mdev_name != NULL) {
        PUSH((base + offset) >> 32);
        fword("encode-int");
        fword("encode+");
        PUSH((base + offset) & 0xffffffff);
        fword("encode-int");
        fword("encode+");
        PUSH(SER_SIZE);
        fword("encode-int");
        fword("encode+");
    }
    
    push_str("reg");
    fword("property");    

    chosen = get_cur_dev();
    set_int_property(chosen, "#address-cells", 1);
    set_int_property(chosen, "#size-cells", 0);
    
    PUSH(kintr);
    fword("encode-int");

    if (mdev_name != NULL) {
        PUSH(mintr);
        fword("encode-int");
        fword("encode+");
    }

    push_str("interrupts");
    fword("property");

    /* Keyboard */
    fword("new-device");

    push_str(kdev_name);
    fword("device-name");

    push_str("serial");
    fword("device-type");

    PUSH(0);
    fword("encode-int");
    push_str("reg");
    fword("property");
    
    PUSH(-1);
    fword("encode-int");
    push_str("keyboard");
    fword("property");

    PUSH(offset);
    fword("encode-int");
    push_str("address");
    fword("property");

    BIND_NODE_METHODS(get_cur_dev(), pc_kbd);

    PUSH(offset);
    feval("value address");

    fword("finish-device");

    snprintf(nodebuff, sizeof(nodebuff), "%s/8042/%s", path, kdev_name);
    chosen = find_dev("/chosen");
    push_str(nodebuff);
    fword("open-dev");
    set_int_property(chosen, "keyboard", POP());

    aliases = find_dev("/aliases");
    set_property(aliases, "keyboard", nodebuff, strlen(nodebuff) + 1);

    pc_kbd_reset();

    /* Mouse (optional) */
    if (mdev_name != NULL) {
        fword("new-device");

        push_str(mdev_name);
        fword("device-name");

        push_str("mouse");
        fword("device-type");

        PUSH(1);
        fword("encode-int");
        push_str("reg");
        fword("property");

        PUSH(-1);
        fword("encode-int");
        push_str("mouse");
        fword("property");
    
        PUSH(offset);
        fword("encode-int");
        push_str("address");
        fword("property");

        fword("finish-device");
    }

    fword("finish-device");
}
