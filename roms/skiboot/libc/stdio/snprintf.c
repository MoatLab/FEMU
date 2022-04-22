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

#include <stdio.h>


int snprintf(char *buff, size_t size, const char *format, ...)
{
	va_list ar;
	int count;

	if (buff==NULL)
		return(-1);

	va_start(ar, format);
	count = vsnprintf(buff, size, format, ar);
	va_end(ar);
	
	return(count);
}

