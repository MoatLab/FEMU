LIBFLASH_SRCS = libflash.c libffs.c ecc.c blocklevel.c mbox-flash.c ipmi-hiomap.c
LIBFLASH_OBJS = $(LIBFLASH_SRCS:%.c=%.o)

SUBDIRS += libflash
LIBFLASH = libflash/built-in.a

$(LIBFLASH): $(LIBFLASH_OBJS:%=libflash/%)
