// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2018 IBM Corp. */

#ifndef __FSP_SYSPARAM_H
#define __FSP_SYSPARAM_H

/* System parameter numbers used in the protocol
 *
 * these are the only ones we care about right now
 */
#define SYS_PARAM_SURV			0xf0000001
#define SYS_PARAM_HMC_MANAGED		0xf0000003
#define SYS_PARAM_FW_IPL_SIDE		0xf0000007
#define SYS_PARAM_FLASH_POLICY		0xf0000012
#define SYS_PARAM_NEED_HMC		0xf0000016
#define SYS_PARAM_REAL_SAI		0xf0000019
#define SYS_PARAM_PARTITION_SAI		0xf000001A
#define SYS_PARAM_PLAT_SAI		0xf000001B
#define SYS_PARAM_FW_LICENSE		0xf000001d
#define SYS_PARAM_WWPN			0xf0000023
#define SYS_PARAM_DEF_BOOT_DEV		0xf0000024
#define SYS_PARAM_NEXT_BOOT_DEV		0xf0000025
#define SYS_PARAM_CONSOLE_SELECT	0xf0000026
#define SYS_PARAM_BOOT_DEV_PATH		0xf0000027


/* Completion for a sysparam call. err_len is either a negative error
 * code or the positive length of the returned data
 */
typedef void (*sysparam_compl_t)(uint32_t param_id, int err_len, void *data);


/* Send a sysparam query request. Operation can be synchronous or
 * asynchronous:
 *
 * - synchronous (async_complete is NULL), the result code is either
 *   a negative error code or a positive returned length.
 *
 * - asynchronous (async_complete non NULL). The result code is 0 for
 *   successfully queued request or an error for an immediate error.
 *   A successfully queued request will complete via the completion
 *   callback defined above
 */
int fsp_get_sys_param(uint32_t param_id, void *buffer, uint32_t length,
		      sysparam_compl_t async_complete, void *comp_data);


void fsp_sysparam_init(void);

/*
 * System parameter update notification.
 * param_id : parameter id
 * len      : length of data
 * data     : pointer to data
 */
typedef bool (*sysparam_update_notify)(struct fsp_msg *msg);

/* Register/unregister for system parameter update notifier chain */
void sysparam_add_update_notifier(sysparam_update_notify notify);
void sysparam_del_update_notifier(sysparam_update_notify notify);

#endif /*  __FSP_SYSPARAM_H */
