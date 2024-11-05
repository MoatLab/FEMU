/*
 *   Creation Date: <2010/04/02 12:00:00 mcayland>
 *   Time-stamp: <2010/04/02 12:00:00 mcayland>
 *
 *	<init.c>
 *
 *	OpenBIOS intialization
 *
 *   Copyright (C) 2010 Mark Cave-Ayland (mark.cave-ayland@siriusit.co.uk)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   version 2
 *
 */

#include "config.h"
#include "libc/byteorder.h"
#include "libopenbios/openbios.h"
#include "libopenbios/bindings.h"
#include "libopenbios/initprogram.h"
#define NO_QEMU_PROTOS
#include "arch/common/fw_cfg.h"


/*
 *  le-w!          ( w waddr -- )
 */

static void lewstore(void)
{
	u16 *aaddr = (u16 *)cell2pointer(POP());
	const u16 word = POP();
	*aaddr = __cpu_to_le16(word);
}

/*
 *  le-l!          ( quad qaddr -- )
 */

static void lelstore(void)
{
	u32 *aaddr = (u32 *)cell2pointer(POP());
	const u32 longval = POP();
	*aaddr = __cpu_to_le32(longval);
}

/*
 *  le-w@          ( waddr -- w )
 */

static void lewfetch(void)
{
	const u16 *aaddr = (u16 *)cell2pointer(POP());
	PUSH(__le16_to_cpu(*aaddr));
}

/*
 *  le-l@          ( qaddr -- quad )
 */

static void lelfetch(void)
{
	const u32 *aaddr = (u32 *)cell2pointer(POP());
	PUSH(__le32_to_cpu(*aaddr));
}

void
openbios_init( void )
{
	// Bind the saved program state context into Forth
	PUSH(pointer2cell((void *)&__context));
	feval("['] __context cell+ !");
	
#if defined(CONFIG_DRIVER_FW_CFG)
	// Bind the Forth fw_cfg file interface
	bind_func("fw-cfg-read-file", forth_fw_cfg_read_file);
#endif
	
	// Bind the C implementation of (init-program) into Forth
	bind_func("(init-program)", init_program);
	
	// Bind the C implementation of (go) into Forth
	bind_func("(go)", go);
	
	// Bind the LE access words
	bind_func("le-w!", lewstore);
	bind_func("le-l!", lelstore);
	bind_func("le-w@", lewfetch);
	bind_func("le-l@", lelfetch);
}
