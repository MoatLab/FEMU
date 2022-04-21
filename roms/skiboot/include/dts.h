// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2017 IBM Corp. */

#ifndef __DTS_H
#define __DTS_H

#include <stdint.h>

extern int64_t dts_sensor_read(u32 sensor_hndl, int token, __be64 *sensor_data);
extern bool dts_sensor_create_nodes(struct dt_node *sensors);

#endif /* __DTS_H */
