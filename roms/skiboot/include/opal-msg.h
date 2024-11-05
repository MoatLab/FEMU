// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#ifndef __OPALMSG_H
#define __OPALMSG_H

#include <opal.h>

/*
 * It dictates the number of asynchronous tokens available at the kernel,
 * ideally the value matches to the number of modules using async
 * infrastructure, but not necessarily the same..
 */
#define OPAL_MAX_ASYNC_COMP	16

/* Max size of struct opal_msg */
#define OPAL_MSG_SIZE		(64 * 1024)

/* opal_msg fixed parameters size */
#define OPAL_MSG_HDR_SIZE		(offsetof(struct opal_msg, params))
#define OPAL_MSG_FIXED_PARAMS_SIZE	\
				(sizeof(struct opal_msg) - OPAL_MSG_HDR_SIZE)

int _opal_queue_msg(enum opal_msg_type msg_type, void *data,
		    void (*consumed)(void *data, int status),
		    size_t params_size, const void *params);

#define opal_queue_msg(msg_type, data, cb, ...) \
	_opal_queue_msg(msg_type, data, cb, \
			sizeof((__be64[]) {__VA_ARGS__}), \
			(__be64[]) {__VA_ARGS__});

void opal_init_msg(void);

#endif /* __OPALMSG_H */
