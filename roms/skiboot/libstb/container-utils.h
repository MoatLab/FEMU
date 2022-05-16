// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2017 IBM Corp. */

#ifndef _CREATE_CONTAINER_UTILS_H
#define _CREATE_CONTAINER_UTILS_H

#include <stdio.h>
#include <unistd.h>

#define die(status, msg, ...)						\
        { fprintf(stderr, "error: %s.%s() line %d: " msg "\n", progname, \
        		__func__, __LINE__, __VA_ARGS__); exit(status); }

#define debug_msg(msg, ...) \
        if (debug) fprintf(stderr, "--> %s.%s(): " msg "\n", progname, \
        		__func__, __VA_ARGS__);

#define verbose_msg(msg, ...) \
        if (verbose) fprintf(stdout, "--> %s: " msg "\n", progname, \
        		__VA_ARGS__);

void hex_print(char *lead, unsigned char *buffer, size_t buflen);
void verbose_print(char *lead, unsigned char *buffer, size_t buflen);
void debug_print(char *lead, unsigned char *buffer, size_t buflen);
int isValidHex(char *input, int len);
int isValidAscii(char *input, int len);

#endif /* _CREATE_CONTAINER_UTILS_H */
