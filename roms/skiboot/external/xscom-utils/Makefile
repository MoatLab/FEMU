# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
CC = $(CROSS_COMPILE)gcc

XSCOM_VERSION ?= $(shell ../../make_version.sh xscom-utils)
CFLAGS += -O2 -g -Wall -m64

prefix = /usr/local/
sbindir = $(prefix)/sbin
datadir = $(prefix)/share
mandir = $(datadir)/man

%.o: %.c
	$(Q_CC)$(COMPILE.c) $< -o $@

# Use make V=1 for a verbose build.
ifndef V
        Q_CC=	@echo '    CC ' $@;
        Q_LINK=	@echo '  LINK ' $@;
        Q_LN=   @echo '    LN ' $@;
        Q_MKDIR=@echo ' MKDIR ' $@;
endif

all: getscom putscom getsram

getscom: getscom.o xscom.o version.o
	$(Q_LINK)$(LINK.o) -o $@ $^

getsram: getsram.o xscom.o sram.o version.o
	$(Q_LINK)$(LINK.o) -o $@ $^

putscom: putscom.o xscom.o version.o
	$(Q_LINK)$(LINK.o) -o $@ $^

install: all
	install -D getscom $(DESTDIR)$(sbindir)/getscom
	install -D putscom $(DESTDIR)$(sbindir)/putscom
	install -D getsram $(DESTDIR)$(sbindir)/getsram
	install -D -m 0644 getscom.1 $(DESTDIR)$(mandir)/man1/getscom.1
	install -D -m 0644 putscom.1 $(DESTDIR)$(mandir)/man1/putscom.1
	install -D -m 0644 getsram.1 $(DESTDIR)$(mandir)/man1/getsram.1

.PHONY: clean
clean:
	rm -rf *.[od] getscom putscom getsram

.PHONY: distclean
distclean: clean
	rm -rf *.c~ *.h~ *.i *.s Makefile~ .version version.c

version.c: ../../make_version.sh  .version
	@(if [ "a$(XSCOM_VERSION)" = "a" ]; then \
	echo "#error You need to set XSCOM_VERSION environment variable" > $@ ;\
	else \
	echo "const char version[] = \"$(XSCOM_VERSION)\";" ;\
	fi) > $@

.PHONY: VERSION-always
.version: VERSION-always
	@echo $(XSCOM_VERSION) > $@.tmp
	@cmp -s $@ $@.tmp || cp $@.tmp $@
	@rm -f $@.tmp
