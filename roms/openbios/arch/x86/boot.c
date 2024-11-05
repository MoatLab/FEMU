/* tag: openbios boot command for x86
 *
 * Copyright (C) 2003-2004 Stefan Reinauer
 *
 * See the file "COPYING" for further information about
 * the copyright and warranty status of this work.
 */

#undef BOOTSTRAP
#include "config.h"
#include "libopenbios/bindings.h"
#include "arch/common/nvram.h"
#include "libc/diskio.h"
#include "libopenbios/initprogram.h"
#include "libopenbios/sys_info.h"
#include "boot.h"


void boot(void)
{
	/* No platform-specific boot code */
	return;
}
