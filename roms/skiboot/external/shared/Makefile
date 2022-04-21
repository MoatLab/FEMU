# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
.DEFAULT_GOAL := all
GET_ARCH := ../../external/common/get_arch.sh
include ../../external/common/rules.mk
include rules.mk

PREFIX ?= /usr/local/
LIBDIR := $(PREFIX)/lib
INCDIR := $(PREFIX)/include/libflash

ifneq ($(ARCH), ARCH_ARM)
CFLAGS += -m64
endif
CFLAGS += -Werror -Wall -g2 -ggdb -I. -fPIC

LIBFLASH_OBJS := libflash-file.o libflash-libflash.o libflash-libffs.o \
	libflash-ecc.o libflash-blocklevel.o
ARCHFLASH_OBJS := common-arch_flash.o
OBJS := $(LIBFLASH_OBJS) $(ARCHFLASH_OBJS)

LIBFLASH_H := libflash/file.h libflash/libflash.h libflash/libffs.h \
	libflash/ffs.h libflash/ecc.h libflash/blocklevel.h libflash/errors.h
ARCHFLASH_H := common/arch_flash.h

LIBFLASH_FILES := libflash.c libffs.c ecc.c blocklevel.c file.c
LIBFLASH_SRC := $(addprefix libflash/,$(LIBFLASH_FILES))

$(LIBFLASH_SRC): | links

$(LIBFLASH_OBJS) : libflash-%.o : libflash/%.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) common-*.o *.so*

distclean: clean
	rm -f ccan libflash common

all: links arch_links $(OBJS)
	$(CC) -shared -Wl,-soname,libflash.so -o $(SHARED_NAME) $(OBJS)

install-lib: all
	install -D -m 0755 $(SHARED_NAME) $(DESTDIR)$(LIBDIR)/$(SHARED_NAME)
	ln -sf $(SHARED_NAME) $(DESTDIR)$(LIBDIR)/libflash.so

install-dev: links arch_links
	mkdir -p $(DESTDIR)$(INCDIR)
	install -m 0644 $(LIBFLASH_H) $(ARCHFLASH_H) $(DESTDIR)$(INCDIR)

install: install-lib install-dev

uninstall:
	rm -f $(DESTDIR)$(LIBDIR)/libflash*
	rm -rf $(DESTDIR)$(INCDIR)
