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

#ifndef _STDIO_H
#define _STDIO_H

#include <stdarg.h>
#include "stddef.h"

#define EOF (-1)

#define _IONBF 0
#define _IOLBF 1
#define _IOFBF 2
#define BUFSIZ 80

typedef struct {
	int fd;
	int mode;
	int pos;
	char *buf;
	int bufsiz;
} FILE;

extern FILE stdin_data;
extern FILE stdout_data;
extern FILE stderr_data;

#define stdin (&stdin_data)
#define stdout (&stdout_data)
#define stderr (&stderr_data)

int fileno(FILE *stream);

int _printf(const char *format, ...) __attribute__((format (printf, 1, 2)));

#ifndef pr_fmt
#define pr_fmt(fmt) fmt
#endif

#define printf(f, ...) do { _printf(pr_fmt(f), ##__VA_ARGS__); } while(0)

int fprintf(FILE *stream, const char *format, ...) __attribute__((format (printf, 2, 3)));
int snprintf(char *str, size_t size, const char *format, ...)  __attribute__((format (printf, 3, 4)));
int vfprintf(FILE *stream, const char *format, va_list);
int vsnprintf(char *str, size_t size, const char *format, va_list);
void setbuf(FILE *stream, char *buf);
int setvbuf(FILE *stream, char *buf, int mode , size_t size);

int fputc(int ch, FILE *stream);
#define putc(ch, stream)	fputc(ch, stream)
int putchar(int ch);
int puts(const char *str);
int fputs(const char *str, FILE *stream);

int scanf(const char *format, ...)  __attribute__((format (scanf, 1, 2)));
int fscanf(FILE *stream, const char *format, ...) __attribute__((format (scanf, 2, 3)));
int vfscanf(FILE *stream, const char *format, va_list);
int vsscanf(const char *str, const char *format, va_list);
int getc(FILE *stream);
int getchar(void);

#endif
