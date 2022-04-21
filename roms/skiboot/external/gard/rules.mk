# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
.DEFAULT_GOAL := all

override CFLAGS += -O2 -Wall -Werror -Wno-stringop-truncation -I.
OBJS      = version.o gard.o units.o
LIBFLASH_FILES    := libflash.c libffs.c ecc.c blocklevel.c file.c
LIBFLASH_OBJS     := $(addprefix libflash-, $(LIBFLASH_FILES:.c=.o))
LIBFLASH_SRC      := $(addprefix libflash/,$(LIBFLASH_FILES))
CCAN_FILES	:= list.c
CCAN_OBJS	:= $(addprefix ccan-list-, $(CCAN_FILES:.c=.o))
CCAN_SRC	:= $(addprefix ccan/list/,$(CCAN_FILES))
OBJS     += $(LIBFLASH_OBJS) $(CCAN_OBJS)
OBJS     += common-arch_flash.o
EXE       = opal-gard

prefix = /usr/local/
sbindir = $(prefix)/sbin
datadir = $(prefix)/share
mandir = $(datadir)/man

#This will only be unset if we're running out of git tree,
#../../make_version.sh is garanteed to exist that way
GARD_VERSION ?= $(shell ../../make_version.sh $(EXE))

version.c: .version
	@(if [ "a$(GARD_VERSION)" = "a" ]; then \
	echo "#error You need to set GARD_VERSION environment variable" > $@ ;\
	else \
	echo "const char version[] = \"$(GARD_VERSION)\";" ;\
	fi) > $@

%.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(LIBFLASH_SRC): | links
$(CCAN_SRC): | links

$(LIBFLASH_OBJS): libflash-%.o : libflash/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(CCAN_OBJS): ccan-list-%.o: ccan/list/%.c
	$(Q_CC)$(CC) $(CFLAGS) -c $< -o $@

$(EXE): $(OBJS)
	$(CC) $(LDFLAGS) $(CFLAGS) $^ -o $@

install: all
	install -D $(EXE) $(DESTDIR)$(sbindir)/$(EXE)
	install -D -m 0644 $(EXE).1 $(DESTDIR)$(mandir)/man1/$(EXE).1


