// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2017 NXP Semiconductors
 * Copyright (C) 2017 Bin Meng <bmeng.cn@gmail.com>
 */

#include <common.h>
#include <dm.h>

UCLASS_DRIVER(nvme) = {
	.name	= "nvme",
	.id	= UCLASS_NVME,
};
