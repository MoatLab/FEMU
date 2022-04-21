/******************************************************************************
 * Copyright (c) 2017 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#include <stdlib.h>

/**
 * labs() -	Computes the absolute value of long integer
 * @n:		long integer number
 *
 * Returns the absolute value of the long integer argument
 */

long int __attribute__((const)) labs(long int n)
{
	return  (n > 0) ? n : -n;
}
