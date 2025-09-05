/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Root include file of C runtime library to support building the third-party
 * cryptographic library.
 **/

#ifndef __CRT_LIB_SUPPORT_H__
#define __CRT_LIB_SUPPORT_H__

#include <base.h>
#include "library/memlib.h"
#include "library/debuglib.h"

#if defined(_MSC_VER) && defined(__clang__)
#include <corecrt.h>
#endif
#define OPENSSLDIR ""
#define ENGINESDIR ""
#define MODULESDIR ""

#define MAX_STRING_SIZE 0x1000


/* We already have "no-ui" in out Configure invocation.
 * but the code still fails to compile.
 * Ref:  https://github.com/openssl/openssl/issues/8904*/

/* This is defined in CRT library(stdio.h).*/

#ifndef BUFSIZ
#define BUFSIZ 8192
#endif


/* OpenSSL relies on explicit configuration for word size in crypto/bn,
 * but we want it to be automatically inferred from the target. So we
 * bypass what's in <openssl/opensslconf.h> for OPENSSL_SYS_UEFI, and
 * define our own here.*/

#ifdef CONFIG_HEADER_BN_H
#error CONFIG_HEADER_BN_H already defined
#endif

#define CONFIG_HEADER_BN_H

#if defined(LIBSPDM_CPU_X64) || defined(LIBSPDM_CPU_AARCH64) || defined(LIBSPDM_CPU_RISCV64)

/* With GCC we would normally use SIXTY_FOUR_BIT_LONG, but MSVC needs
 * SIXTY_FOUR_BIT, because 'long' is 32-bit and only 'long long' is
 * 64-bit. Since using 'long long' works fine on GCC too, just do that.*/

#define SIXTY_FOUR_BIT
#elif defined(LIBSPDM_CPU_IA32) || defined(LIBSPDM_CPU_ARM) || defined(LIBSPDM_CPU_EBC) || \
    defined(LIBSPDM_CPU_RISCV32) || defined(LIBSPDM_CPU_ARC)
#define THIRTY_TWO_BIT
#else
#error Unknown target architecture
#endif


/* Map all va_xxxx elements to VA_xxx defined in MdePkg/include/base.h*/

/**
 * Return the size of argument that has been aligned to sizeof (size_t).
 *
 * @param  n    The parameter size to be aligned.
 *
 * @return The aligned size.
 **/
#define _LIBSPDM_INT_SIZE_OF(n) ((sizeof(n) + sizeof(size_t) - 1) & ~(sizeof(size_t) - 1))

#if defined(__CC_arm)

/* RVCT arm variable argument list support.*/

/* Variable used to traverse the list of arguments. This type can vary by
 * implementation and could be an array or structure.*/

#ifdef __APCS_ADSABI
typedef int *va_list[1];
#define LIBSPDM_VA_LIST va_list
#else
typedef struct __va_list {
    void *__ap;
} va_list;
#define LIBSPDM_VA_LIST va_list
#endif

#define LIBSPDM_VA_START(marker, parameter) __va_start(marker, parameter)

#define LIBSPDM_VA_ARG(marker, TYPE) __va_arg(marker, TYPE)

#define LIBSPDM_VA_END(marker) ((void)0)

/* For some arm RVCT compilers, __va_copy is not defined*/
#ifndef __va_copy
#define __va_copy(dest, src) ((void)((dest) = (src)))
#endif

#elif defined(_M_arm) || defined(_M_arm64)

/* MSFT arm variable argument list support.*/


typedef char *LIBSPDM_VA_LIST;

#define LIBSPDM_VA_START(marker, parameter)                                            \
    __va_start(&marker, &parameter, _LIBSPDM_INT_SIZE_OF(parameter),               \
               __alignof(parameter), &parameter)
#define LIBSPDM_VA_ARG(marker, TYPE)                                                   \
    (*(TYPE *)((marker += _LIBSPDM_INT_SIZE_OF(TYPE) +                             \
                          ((-(size_t)marker) & (sizeof(TYPE) - 1))) -        \
               _LIBSPDM_INT_SIZE_OF(TYPE)))
#define LIBSPDM_VA_END(marker) (marker = (LIBSPDM_VA_LIST)0)

#elif defined(__GNUC__) || defined(__clang__)

/* Use GCC built-in macros for variable argument lists.*/

/* Variable used to traverse the list of arguments. This type can vary by
 * implementation and could be an array or structure.*/

typedef __builtin_va_list LIBSPDM_VA_LIST;

#define LIBSPDM_VA_START(marker, parameter) __builtin_va_start(marker, parameter)

#define LIBSPDM_VA_ARG(marker, TYPE)                                                   \
    ((sizeof(TYPE) < sizeof(size_t)) ?                                      \
     (TYPE)(__builtin_va_arg(marker, size_t)) :                     \
     (TYPE)(__builtin_va_arg(marker, TYPE)))

#define LIBSPDM_VA_END(marker) __builtin_va_end(marker)

#else

/* Variable used to traverse the list of arguments. This type can vary by
 * implementation and could be an array or structure.*/

typedef char *LIBSPDM_VA_LIST;

/**
 * Retrieves a pointer to the beginning of a variable argument list, based on
 * the name of the parameter that immediately precedes the variable argument list.
 *
 * This function initializes marker to point to the beginning of the variable
 * argument list that immediately follows parameter.  The method for computing the
 * pointer to the next argument in the argument list is CPU-specific following the
 * EFIAPI ABI.
 *
 * @param   marker       The LIBSPDM_VA_LIST used to traverse the list of arguments.
 * @param   parameter    The name of the parameter that immediately precedes
 *                      the variable argument list.
 *
 * @return  A pointer to the beginning of a variable argument list.
 *
 **/
#define LIBSPDM_VA_START(marker, parameter)                                            \
    (marker = (LIBSPDM_VA_LIST)((size_t) &(parameter) + _LIBSPDM_INT_SIZE_OF(parameter)))

/**
 * Returns an argument of a specified type from a variable argument list and updates
 * the pointer to the variable argument list to point to the next argument.
 *
 * This function returns an argument of the type specified by TYPE from the beginning
 * of the variable argument list specified by marker.  marker is then updated to point
 * to the next argument in the variable argument list.  The method for computing the
 * pointer to the next argument in the argument list is CPU-specific following the EFIAPI ABI.
 *
 * @param   marker   LIBSPDM_VA_LIST used to traverse the list of arguments.
 * @param   TYPE     The type of argument to retrieve from the beginning
 *                  of the variable argument list.
 *
 * @return  An argument of the type specified by TYPE.
 *
 **/
#define LIBSPDM_VA_ARG(marker, TYPE)                                                   \
    (*(TYPE *)((marker += _LIBSPDM_INT_SIZE_OF(TYPE)) - _LIBSPDM_INT_SIZE_OF(TYPE)))

/**
 * Terminates the use of a variable argument list.
 *
 * This function initializes marker so it can no longer be used with LIBSPDM_VA_ARG().
 * After this macro is used, the only way to access the variable argument list is
 * by using LIBSPDM_VA_START() again.
 *
 * @param   marker   LIBSPDM_VA_LIST used to traverse the list of arguments.
 *
 **/
#define LIBSPDM_VA_END(marker) (marker = (LIBSPDM_VA_LIST)0)

#endif


#if !defined(__CC_arm) /* if va_list is not already defined*/
#define va_list LIBSPDM_VA_LIST
#define va_arg LIBSPDM_VA_ARG
#define va_start LIBSPDM_VA_START
#define va_end LIBSPDM_VA_END
#else /* __CC_arm*/
#define va_start(marker, parameter) __va_start(marker, parameter)
#define va_arg(marker, TYPE) __va_arg(marker, TYPE)
#define va_end(marker) ((void)0)
#endif


/* Definitions for global constants used by CRT library routines*/

#define EINVAL 22 /* Invalid argument */
#define INT_MAX 0x7FFFFFFF /* Maximum (signed) int value */
#define INT_MIN       (-INT_MAX-1)    /* Minimum (signed) int value */
#define LONG_MAX 0X7FFFFFFFL /* max value for a long */
#define LONG_MIN (-LONG_MAX - 1) /* min value for a long */
#define UINT_MAX      0xFFFFFFFF      /* Maximum unsigned int value */
#define ULONG_MAX 0xFFFFFFFF /* Maximum unsigned long value */
#define CHAR_BIT 8 /* Number of bits in a char */


/* Address families.*/

#define AF_INET 2 /* internetwork: UDP, TCP, etc. */
#define AF_INET6 24 /* IP version 6 */


/* Define constants based on RFC0883, RFC1034, RFC 1035*/

#define NS_INT16SZ 2 /*%< #/bytes of data in a u_int16_t */
#define NS_INADDRSZ 4 /*%< IPv4 T_A */
#define NS_IN6ADDRSZ 16 /*%< IPv6 T_AAAA */


/* Basic types mapping*/

typedef size_t u_int;
#if defined(__GNUC__) && !defined(__MINGW64__)
typedef size_t time_t; /* time_t is 4 bytes for 32bit machine and 8 bytes for 64bit machine */
#endif
typedef uint8_t __uint8_t;
typedef uint8_t sa_family_t;
typedef uint8_t u_char;
typedef uint32_t uid_t;
typedef uint32_t gid_t;


/* file operations are not required for EFI building,
 * so FILE is mapped to void * to pass build*/

typedef void *FILE;


/* Structures Definitions*/

struct tm {
    int tm_sec; /* seconds after the minute [0-60] */
    int tm_min; /* minutes after the hour [0-59] */
    int tm_hour; /* hours since midnight [0-23] */
    int tm_mday; /* day of the month [1-31] */
    int tm_mon; /* months since January [0-11] */
    int tm_year; /* years since 1900 */
    int tm_wday; /* days since Sunday [0-6] */
    int tm_yday; /* days since January 1 [0-365] */
    int tm_isdst; /* Daylight Savings Time flag */
    long tm_gmtoff; /* offset from CUT in seconds */
    char *tm_zone; /* timezone abbreviation */
};

struct timeval {
    long tv_sec; /* time value, in seconds */
    long tv_usec; /* time value, in microseconds */
};

struct sockaddr {
    __uint8_t sa_len; /* total length */
    sa_family_t sa_family; /* address family */
    char sa_data[14]; /* actually longer; address value */
};


/* Global variables*/

extern int errno;
extern FILE *stderr;


/* Function prototypes of CRT Library routines*/

void *malloc(size_t);
void *realloc(void *, size_t);
void free(void *);
void *memset(void *, int, size_t);
int memcmp(const void *, const void *, size_t);
int isdigit(int);
int isspace(int);
int isxdigit(int);
int isalnum(int);
int isupper(int);
int tolower(int);
int strcmp(const char *, const char *);
int strncasecmp(const char *, const char *, size_t);
char *strchr(const char *, int);
char *strrchr(const char *, int);
unsigned long strtoul(const char *, char **, int);
long strtol(const char *, char **, int);
char *strerror(int);
size_t strspn(const char *, const char *);
size_t strcspn(const char *, const char *);
int printf(const char *, ...);
int sscanf(const char *, const char *, ...);
FILE *fopen(const char *, const char *);
size_t fread(void *, size_t, size_t, FILE *);
size_t fwrite(const void *, size_t, size_t, FILE *);
int fclose(FILE *);
int fprintf(FILE *, const char *, ...);
time_t time(time_t *);
struct tm *gmtime(const time_t *);
uid_t getuid(void);
uid_t geteuid(void);
gid_t getgid(void);
gid_t getegid(void);
int issetugid(void);
void qsort(void *, size_t, size_t, int (*)(const void *, const void *));
char *getenv(const char *);
char *secure_getenv(const char *);
#if defined(__GNUC__) && (__GNUC__ >= 2)
void abort(void) __attribute__((__noreturn__));
#else
void abort(void);
#endif
int inet_pton(int, const char *, void *);

void *memcpy(void *destin, const void *source, size_t n);
void *memset(void *s, int ch, size_t n);
void *memchr(const void *buf, int ch, size_t count);
int memcmp(const void *str1, const void *str2, size_t n);
void *memmove(void *dest, const void *src, size_t count);
size_t strlen(const char *string);
char *strcpy(char *dest, const char *src);
char *strncpy(char *destinin, const char *source, size_t maxlen);
char *strcat(char *dest, const char *src);
char *strstr(const char *str1, const char *str2);
int strncmp(const char *str1, const char *str2, size_t n);
int strcasecmp(const char *s1, const char *s2);
int sprintf(char *string, const char *format, ...);
#define localtime(timer) NULL
#define assert(expression)
int atoi(const char *nptr);
#define gettimeofday(tvp, tz)                                                  \
    do {                                                                   \
        (tvp)->tv_sec = time(NULL);                                    \
        (tvp)->tv_usec = 0;                                            \
    } while (0)

#endif
