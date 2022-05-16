// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Code for handling FSP_MCLASS_DIAG messages (cmd 0xee)
 * Receiving a high level ack timeout is likely indicative of a firmware bug
 *
 * Copyright 2013-2014 IBM Corp.
 */

#include <skiboot.h>
#include <fsp.h>
#include <lock.h>
#include <processor.h>
#include <timebase.h>
#include <opal.h>
#include <fsp-sysparam.h>

static bool fsp_diag_msg(u32 cmd_sub_mod, struct fsp_msg *msg)
{

	if (cmd_sub_mod == FSP_RSP_DIAG_LINK_ERROR) {
		printf("FIXME: Unhandled FSP_MCLASS_DIAG Link Error Report\n");
		return false;
	}

	if (cmd_sub_mod != FSP_RSP_DIAG_ACK_TIMEOUT) {
		printf("BUG: Unhandled subcommand: 0x%x (New FSP spec?)\n",
		       cmd_sub_mod);
		return false;
	}

	printf("BUG: High Level ACK timeout (FSP_MCLASS_DIAG) for 0x%x\n",
	       fsp_msg_get_data_word(msg, 0) & 0xffff0000);

	return true;
}

static struct fsp_client fsp_diag = {
	.message = fsp_diag_msg,
};

/* This is called at boot time */
void fsp_init_diag(void)
{
	/* Register for the diag event */
	fsp_register_client(&fsp_diag, FSP_MCLASS_DIAG);
}
