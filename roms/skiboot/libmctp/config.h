/* Define to 1 if you have the <dlfcn.h> header file. */
#undef HAVE_DLFCN_H

/* use the ccan endian conversion functions rather than the BSD ones */
#define HAVE_ENDIAN_H 1

/* Define to 1 if you have the <fcntl.h> header file. */
#undef HAVE_FCNTL_H

/* Define to 1 if you have the <inttypes.h> header file. */
#undef HAVE_INTTYPES_H

/* Define to 1 if you have the <memory.h> header file. */
#undef HAVE_MEMORY_H

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#undef HAVE_STDLIB_H

/* Define to 1 if you have the <strings.h> header file. */
#undef HAVE_STRINGS_H

/* Define to 1 if you have the <string.h> header file. */
#undef HAVE_STRING_H

/* Define to 1 if you have the <sys/stat.h> header file. */
#undef HAVE_SYS_STAT_H

/* Define to 1 if you have the <sys/types.h> header file. */
#undef HAVE_SYS_TYPES_H

/* Define to 1 if you have the <unistd.h> header file. */
#undef HAVE_UNISTD_H

/* Define to use libc malloc and free for heap memory.
 *
 * NB: Skiboot's malloc() is defined as a macro and can't
 *     be used directly.
 */
#undef MCTP_DEFAULT_ALLOC

/* Support interfaces based on file-descriptors */
#undef MCTP_HAVE_FILEIO

/* Define to enable stdio functions */
#undef MCTP_HAVE_STDIO

/* Define to enable syslog */
#undef MCTP_HAVE_SYSLOG

/* Define to 1 if you have the ANSI C header files. */
#undef STDC_HEADERS


#include <opal-api.h>
/* Convert POSIX / Linux errno codes used by libmctp to OPAL return codes */
#define EHOSTDOWN (-OPAL_CLOSED)
