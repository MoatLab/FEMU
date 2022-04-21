# SPDX-License-Identifier: Apache-2.0
CFLAGS += -m64 -Werror -Wall -g2 -ggdb
LDFLAGS += -m64
ASFLAGS = -m64
CPPFLAGS += -I. -I../../include -I../../

prefix = /usr/local/
sbindir = $(prefix)/sbin
datadir = $(prefix)/share
mandir = $(datadir)/man

all: links arch_links | opal-prd

GET_ARCH = ../../external/common/get_arch.sh
include ../../external/common/rules.mk

LIBFLASH_OBJS = libflash-blocklevel.o libflash-libffs.o \
                libflash-libflash.o libflash-ecc.o \
                libflash-file.o

OBJS = opal-prd.o thunk.o pnor.o i2c.o module.o version.o \
       $(LIBFLASH_OBJS) common-arch_flash.o

OPAL_PRD_VERSION ?= $(shell ../../make_version.sh opal-prd)

ifdef KERNEL_DIR
links += asm/opal-prd.h
endif

asm/opal-prd.h:
	$(Q_MKDIR)mkdir -p asm
	$(Q_LN)ln -sfr $(KERNEL_DIR)/arch/powerpc/include/uapi/asm/opal-prd.h \
			asm/opal-prd.h

%.o: %.c
	$(Q_CC)$(COMPILE.c) $< -o $@

$(LIBFLASH_OBJS): libflash-%.o : libflash/%.c
	$(Q_CC)$(COMPILE.c) $< -o $@

%.o: %.S
	$(Q_CC)$(COMPILE.S) $< -o $@

opal-prd: $(OBJS)
	$(Q_LINK)$(LINK.o) -o $@ $^

version.c: ../../make_version.sh .version
	@(if [ "a$(OPAL_PRD_VERSION)" = "a" ]; then \
	echo "#error You need to set OPAL_PRD_VERSION environment variable" > $@ ;\
	else \
	echo "const char version[] = \"$(OPAL_PRD_VERSION)\";" ;\
	fi) > $@

.PHONY: VERSION-always
.version: VERSION-always
	@echo $(OPAL_PRD_VERSION) > $@.tmp
	@cmp -s $@ $@.tmp || cp $@.tmp $@
	@rm -f $@.tmp

test: links test/test_pnor

test/test_pnor: test/test_pnor.o pnor.o $(LIBFLASH_OBJS) common-arch_flash.o
	$(Q_LINK)$(LINK.o) -o $@ $^

install: all
	install -D opal-prd $(DESTDIR)$(sbindir)/opal-prd
	install -D -m 0644 opal-prd.8 $(DESTDIR)$(mandir)/man8/opal-prd.8

clean:
	$(RM) *.[odsa] opal-prd
	$(RM) test/*.[odsa] test/test_pnor

distclean: clean
	$(RM) -f $(LINKS) asm
	$(RM) -f libflash ccan version.c .version common
