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
#ifndef _TIME_H
#define _TIME_H

struct tm {
	int tm_sec;
	int tm_min;
	int tm_hour;
	int tm_mday;
	int tm_mon;
	int tm_year;
};

typedef long time_t;

struct timespec {
	time_t tv_sec;        /* seconds */
	long   tv_nsec;       /* nanoseconds */
};

struct tm *gmtime_r(const time_t *timep, struct tm *result);
time_t mktime(struct tm *tm);

/* Not implemented by libc but by hosting environment, however
 * this is where the prototype is expected
 */
int nanosleep(const struct timespec *req, struct timespec *rem);

#endif /* _TIME_H */
