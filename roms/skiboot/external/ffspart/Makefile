# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# Use make V=1 for a verbose build.
include rules.mk
GET_ARCH = ../../external/common/get_arch.sh
include ../../external/common/rules.mk

all: links arch_links $(EXE)

#Rebuild version.o so that the the version always matches
#what the test suite will get from ./make_version.sh
check: version.o all
	@ln -sf ../../test/test.sh test/test.sh
	@test/test-ffspart

$(OBJS): | links arch_links

.PHONY: VERSION-always
.version: VERSION-always
	@echo $(FFSPART_VERSION) > $@.tmp
	@cmp -s $@ $@.tmp || cp $@.tmp $@
	@rm -f $@.tmp

install: all
	install -D ffspart $(DESTDIR)$(sbindir)/ffspart

.PHONY: dist
#File is named $(FFSPART_VERSION).tar because the expectation is that ffspart-
#is always at the start of the verion. This remains consistent with skiboot
#version strings
dist: links .version
	find -L ../ffspart/ -iname '*.[ch]' -print0 | xargs -0 tar -rhf $(FFSPART_VERSION).tar
	tar --transform 's/Makefile.dist/Makefile/' -rhf $(FFSPART_VERSION).tar \
		../ffspart/Makefile.dist ../ffspart/rules.mk \
		../ffspart/.version ../ffspart/make_version.sh \
		../ffspart/common/*

.PHONY: clean
clean: arch_clean
	rm -f $(OBJS) $(EXE) *.o *.d
.PHONY: distclean
distclean: clean
	rm -f *.c~ *.h~ *.sh~ Makefile~ config.mk~ libflash/*.c~ libflash/*.h~
	rm -f libflash ccan .version .version.tmp
	rm -f common io.h
