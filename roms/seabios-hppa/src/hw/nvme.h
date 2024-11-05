// External interfaces for low level NVMe support
//
// Copyright 2017 Amazon.com, Inc. or its affiliates.
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#ifndef __NVME_H
#define __NVME_H

#include "block.h" // struct disk_op_s

void nvme_setup(void);
int nvme_process_op(struct disk_op_s *op);

#endif

/* EOF */
