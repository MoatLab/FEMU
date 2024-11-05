# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

.DEFAULT_GOAL := all

override CFLAGS  += -O2 -Wall -I.
LIBFLASH_FILES	:= libflash.c libffs.c ecc.c blocklevel.c file.c
LIBFLASH_OBJS	:= $(addprefix libflash-, $(LIBFLASH_FILES:.c=.o))
LIBFLASH_SRC	:= $(addprefix libflash/,$(LIBFLASH_FILES))
CCAN_FILES	:= list.c
CCAN_OBJS	:= $(addprefix ccan-list-, $(CCAN_FILES:.c=.o))
CCAN_SRC	:= $(addprefix ccan/list/,$(CCAN_FILES))
PFLASH_OBJS	:= pflash.o progress.o version.o common-arch_flash.o
OBJS		:= $(PFLASH_OBJS) $(LIBFLASH_OBJS) $(CCAN_OBJS)
EXE     	:= pflash
sbindir		= $(prefix)/sbin
datadir		= $(prefix)/share
mandir		= $(datadir)/man

PFLASH_VERSION	?= $(shell ../../make_version.sh $(EXE))
LINKAGE		?= static

ifeq ($(LINKAGE),dynamic)
include ../shared/rules.mk
SHARED		:= ../shared/$(SHARED_NAME)
OBJS		:= $(PFLASH_OBJS) $(SHARED)
INSTALLDEPS	+= install-shared

install-shared:
	$(MAKE) -C ../shared install prefix=$(prefix)

$(SHARED):
	$(MAKE) -C ../shared
endif

version.c: .version
	@(if [ "a$(PFLASH_VERSION)" = "a" ]; then \
	echo "#error You need to set PFLASH_VERSION environment variable" > $@ ;\
	else \
	echo "const char version[] = \"$(PFLASH_VERSION)\";" ;\
	fi) > $@

%.o : %.c | links
	$(Q_CC)$(CC) $(CFLAGS) -c $< -o $@

$(LIBFLASH_SRC): | links

$(CCAN_SRC): | links

$(LIBFLASH_OBJS): libflash-%.o : libflash/%.c | links
	$(Q_CC)$(CC) $(CFLAGS) -c $< -o $@

$(CCAN_OBJS): ccan-list-%.o: ccan/list/%.c | links
	$(Q_CC)$(CC) $(CFLAGS) -c $< -o $@

$(EXE): $(OBJS)
	$(Q_CC)$(CC) $(LDFLAGS) $(CFLAGS) $^ -lrt -o $@

