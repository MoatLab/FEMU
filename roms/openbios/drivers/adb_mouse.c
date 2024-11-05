/*
 *
 * Open Hack'Ware BIOS ADB mouse support, ported to OpenBIOS
 *
 *  Copyright (c) 2005 Jocelyn Mayer
 *  Copyright (c) 2005 Stefan Reinauer
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License V2
 *   as published by the Free Software Foundation
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA, 02110-1301 USA
 */

#include "config.h"
#include "libopenbios/bindings.h"
#include "libc/byteorder.h"
#include "libc/vsprintf.h"

#include "adb_bus.h"
#include "adb_mouse.h"

DECLARE_UNNAMED_NODE( mouse, 0, sizeof(int));

static void
mouse_open(int *idx)
{
	RET(-1);
}

static void
mouse_close(int *idx)
{
}

NODE_METHODS( mouse ) = {
	{ "open",		mouse_open		},
	{ "close",		mouse_close		},
};

void adb_mouse_new (char *path, void *private)
{
	char buf[64];
	phandle_t aliases;
	adb_dev_t *dev = private;

	fword("new-device");

	push_str("mouse");
	fword("device-name");

	push_str("mouse");
	fword("device-type");

	PUSH(dev->addr);
	fword("encode-int");
	push_str("reg");
	fword("property");

	PUSH(3);
	fword("encode-int");
	push_str("#buttons");
	fword("property");

	BIND_NODE_METHODS(get_cur_dev(), mouse);
	fword("finish-device");

	aliases = find_dev("/aliases");
	snprintf(buf, sizeof(buf), "%s/mouse", path);
	set_property(aliases, "adb-mouse", buf, strlen(buf) + 1);
}
