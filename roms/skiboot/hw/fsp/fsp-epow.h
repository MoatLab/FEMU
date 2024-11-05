// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Handle FSP EPOW event notifications
 *
 * Copyright 2013-2015 IBM Corp.
 */

#ifndef __FSP_EPOW_H
#define __FSP_EPOW_H

/* FSP based EPOW event notifications */
#define EPOW_NORMAL	0x00	/* panel status normal */
#define EPOW_EX1	0x01	/* panel status extended 1 */
#define EPOW_EX2	0x02	/* Panel status extended 2 */

/* EPOW reason code notifications */
#define EPOW_ON_UPS	1	/* System on UPS */
#define EPOW_TMP_AMB	2	/* Over ambient temperature */
#define EPOW_TMP_INT	3	/* Over internal temperature */

#endif
