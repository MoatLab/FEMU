# SPDX-License-Identifier: Apache-2.0
# This tool is a linux userland tool and should be completely stand alone
include rules.mk
GET_ARCH = ../../external/common/get_arch.sh
include ../../external/common/rules.mk

all: links arch_links $(EXE)

.PHONY: coverage
coverage: CFLAGS += -fprofile-arcs -ftest-coverage
coverage: check

#Rebuild version.o so that the the version always matches
#what the test suite will get from ./make_version.sh
check: version.o all
	@ln -sf ../../make_version.sh make_version.sh
	@ln -sf ../../test/test.sh test/test.sh
	@test/test-gard

.PHONY: VERSION-always
.version: VERSION-always
	@echo $(GARD_VERSION) > $@.tmp
	@cmp -s $@ $@.tmp || cp $@.tmp $@
	@rm -f $@.tmp

.PHONY: dist
#File is named $(GARD_VERSION).tar because the expectation is that gard-
#is always at the start of the verion. This remains consistent with skiboot
#version strings
dist: arch_links links .version
	@find -L ../gard/ -iname '*.[ch]' -print0 | xargs -0 tar -rhf $(GARD_VERSION).tar
	@tar --transform 's/Makefile.dist/Makefile/' -rhf $(GARD_VERSION).tar \
		../gard/Makefile.dist ../gard/rules.mk \
		../gard/.version ../gard/common/*

clean: arch_clean
	rm -f $(OBJS) $(EXE) *.o *.d .version .version.tmp

distclean: clean
	rm -f *.c~ *.h~ *.sh~ Makefile~ config.mk~ libflash/*.c~ libflash/*.h~
	rm -f libflash ccan common io.h version.c make_version.sh
	rm -f gard-*.tar

