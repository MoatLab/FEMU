/******************************************************************************
 * Copyright (c) 2004, 2008 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#ifndef __BMC_H
#define __BMC_H

extern short (*bmc_set_flashside) (short mode);
extern short (*bmc_get_flashside) (void);

#endif				/* __BMC_H */
