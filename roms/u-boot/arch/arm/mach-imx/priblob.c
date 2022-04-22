// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2018 NXP
 */

/*
 * Boot command to get and set the PRIBLOB bitfield form the SCFGR register
 * of the CAAM IP. It is recommended to set this bitfield to 3 once your
 * encrypted boot image is ready, to prevent the generation of blobs usable
 * to decrypt an encrypted boot image.
 */

#include <asm/io.h>
#include <common.h>
#include <command.h>
#include "../drivers/crypto/fsl_caam_internal.h"

int do_priblob_write(cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[])
{
	writel((readl(CAAM_SCFGR) & 0xFFFFFFFC) | 3, CAAM_SCFGR);
	printf("New priblob setting = 0x%x\n", readl(CAAM_SCFGR) & 0x3);

	return 0;
}

U_BOOT_CMD(
	set_priblob_bitfield, 1, 0, do_priblob_write,
	"Set the PRIBLOB bitfield to 3",
	"<value>\n"
	"    - Write 3 in PRIBLOB bitfield of SCFGR regiter of CAAM IP.\n"
	"    Prevent the generation of blobs usable to decrypt an\n"
	"    encrypted boot image."
);
