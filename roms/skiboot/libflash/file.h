// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2016 IBM Corp. */

#ifndef __LIBFLASH_FILE_H
#define __LIBFLASH_FILE_H

#include <stdbool.h>

#include "blocklevel.h"

/*
 * Blockevel functions created leave errno set on errors, as these calls
 * often boil down to standard read() and write() calls, inspecting errno
 * may prove useful
 */

int file_init(int fd, struct blocklevel_device **bl);
void file_exit(struct blocklevel_device *bl);

/*
 * file_init_path() is a convenience wrapper which will open the path and call
 * file_init(). The call to open happens with O_RDWR and no additional flags
 * Because file_exit() doesn't close the file descriptor, file_init_path()
 * makes it available.
 */
int file_init_path(const char *path, int *fd, bool keep_alive, struct blocklevel_device **bl);

/*
 * file_exit_close is a convenience wrapper which will close the open
 * file descriptor and call file_exit().
 */
void file_exit_close(struct blocklevel_device *bl);

#endif /* __LIBFLASH_FILE_H */
