# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
.DEFAULT_GOAL := all

override CFLAGS  += -O2 -Wall -g -I.
EXE     = ffspart
OBJS    = $(EXE).o version.o
LIBFLASH_FILES := libflash.c libffs.c ecc.c blocklevel.c file.c
LIBFLASH_OBJS := $(addprefix libflash-, $(LIBFLASH_FILES:.c=.o))
LIBFLASH_SRC := $(addprefix libflash/,$(LIBFLASH_FILES))
OBJS	+= $(LIBFLASH_OBJS)
OBJS	+= common-arch_flash.o

prefix = /usr/local/
sbindir = $(prefix)/sbin

CC	= $(CROSS_COMPILE)gcc

FFSPART_VERSION ?= $(shell ./make_version.sh $(EXE))

version.c: make_version.sh .version
	@(if [ "a$(FFSPART_VERSION)" = "a" ]; then \
	echo "#error You need to set FFSPART_VERSION environment variable" > $@ ;\
	else \
	echo "const char version[] = \"$(FFSPART_VERSION)\";" ;\
	fi) > $@

%.o : %.c
	$(Q_CC)$(CC) $(CFLAGS) -c $< -o $@

$(LIBFLASH_SRC): | links

$(LIBFLASH_OBJS): libflash-%.o : libflash/%.c
	$(Q_CC)$(CC) $(CFLAGS) -c $< -o $@

$(EXE): $(OBJS)
	$(Q_CC)$(CC) $(CFLAGS) $^ -lrt -o $@

