// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2020 IBM Corp. */
#include <tssskiboot.h>
#include "secboot_tpm.h"

struct tpmnv_ops_s tpmnv_ops = {
	.read = tss_nv_read,
	.write = tss_nv_write,
	.writelock = tss_nv_write_lock,
	.definespace = tss_nv_define_space,
	.getindices = tss_get_defined_nv_indices,
	.undefinespace = tss_nv_undefine_space,
	.readpublic = tss_nv_read_public,
};

