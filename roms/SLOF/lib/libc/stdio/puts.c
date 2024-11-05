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


#include "stdio.h"
#include "string.h"
#include "unistd.h"


int
puts(const char *str)
{
	int ret;

	ret = write(stdout->fd, str, strlen(str));
	write(stdout->fd, "\r\n", 2);

	return ret;
}
