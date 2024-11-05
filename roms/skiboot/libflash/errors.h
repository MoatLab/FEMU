// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2018 IBM Corp. */

#ifndef __LIBFLASH_ERRORS_H
#define __LIBFLASH_ERRORS_H

#define FLASH_ERR_MALLOC_FAILED		1
#define FLASH_ERR_CHIP_UNKNOWN		2
#define FLASH_ERR_PARM_ERROR		3
#define FLASH_ERR_ERASE_BOUNDARY	4
#define FLASH_ERR_WREN_TIMEOUT		5
#define FLASH_ERR_WIP_TIMEOUT		6
#define FLASH_ERR_BAD_PAGE_SIZE		7
#define FLASH_ERR_VERIFY_FAILURE	8
#define FLASH_ERR_4B_NOT_SUPPORTED	9
#define FLASH_ERR_CTRL_CONFIG_MISMATCH	10
#define FLASH_ERR_CHIP_ER_NOT_SUPPORTED	11
#define FLASH_ERR_CTRL_CMD_UNSUPPORTED	12
#define FLASH_ERR_CTRL_TIMEOUT		13
#define FLASH_ERR_ECC_INVALID		14
#define FLASH_ERR_BAD_READ		15
#define FLASH_ERR_DEVICE_GONE	16
#define FLASH_ERR_AGAIN	17

#ifdef __SKIBOOT__
#include <skiboot.h>
#define FL_INF(fmt...) do { prlog(PR_INFO, fmt);  } while(0)
#define FL_DBG(fmt...) do { prlog(PR_TRACE, fmt); } while(0)
#define FL_ERR(fmt...) do { prlog(PR_ERR, fmt);   } while(0)
#else
#include <stdio.h>
extern bool libflash_debug;
#define FL_DBG(fmt...) do { if (libflash_debug) printf(fmt); } while(0)
#define FL_INF(fmt...) do { printf(fmt); } while(0)
#define FL_ERR(fmt...) do { printf(fmt); } while(0)
#endif


#endif /* __LIBFLASH_ERRORS_H */
