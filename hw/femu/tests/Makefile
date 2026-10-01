# Builds the NAND media unit test (tests/unit/test-femu-nand-media.c) without
# QEMU. The media layer (hw/femu/nand/nand-media.c) includes only qemu/osdep.h
# and its own header, so it compiles against the stub in qemu/ here. That keeps
# this path in the millisecond range: no QEMU build, no guest, no hardware. CI
# runs it before installing the build dependencies; `make check-unit` in a
# configured build directory runs the same test through meson.
# Run with `make -C hw/femu/tests check`.
#
# The media source is built at the project's own warning level; only the test
# is held to -Wextra -Werror, so this cannot start failing on unrelated code.
CFLAGS_TEST ?= -O2 -Wall -Wextra -Werror -std=gnu11
CFLAGS_LIB  ?= -O2 -Wall -std=gnu11
ROOT = ../../..
TEST_SRC = unit/test-nand-media.c
# the stub directory first, so qemu/osdep.h resolves here and not in QEMU
INCLUDES = -I. -I$(ROOT) -I../nand
PKG_CONFIG ?= pkg-config
# The CXL cache test needs GLib; CI runs this before installing it, then again
# after, so the test is skipped only in the first pass.
HAVE_GLIB := $(shell $(PKG_CONFIG) --exists glib-2.0 && echo 1)
UNIT_TESTS = test-femu-nand-media test-femu-hybrid-oracle test-femu-cxl-spte \
             test-femu-cxl-cca-ring
ifeq ($(HAVE_GLIB),1)
UNIT_TESTS += test-femu-cxl-cache
endif

test-femu-nand-media: $(TEST_SRC) nand-media.o ../nand/nand-media.h
	$(CC) $(CFLAGS_TEST) $(INCLUDES) -o $@ $(TEST_SRC) nand-media.o

nand-media.o: ../nand/nand-media.c ../nand/nand-media.h
	$(CC) $(CFLAGS_LIB) $(INCLUDES) -c -o $@ ../nand/nand-media.c

test-femu-hybrid-oracle: unit/test-hybrid-oracle.c unit/hybrid-oracle.h
	$(CC) $(CFLAGS_TEST) $(INCLUDES) -o $@ $<

test-femu-cxl-cache: unit/test-cxl-cache.c ../cxlssd/cache.c ../cxlssd/cache.h \
                     ../cxlssd/der.h
	$(CC) $(CFLAGS_TEST) $(INCLUDES) $(shell $(PKG_CONFIG) --cflags glib-2.0) \
	    -o $@ unit/test-cxl-cache.c ../cxlssd/cache.c \
	    $(shell $(PKG_CONFIG) --libs glib-2.0)

test-femu-cxl-spte: unit/test-cxl-spte.c ../cxlssd/spte.h ../cxlssd/spt.h
	$(CC) $(CFLAGS_TEST) $(INCLUDES) -o $@ $<

# The guest library and the device's ring consumer, in one process. The
# library directory comes first: the device has its own cca.h.
test-femu-cxl-cca-ring: unit/test-cxl-cca-ring.c ../cxlssd/cca-ring.c \
                        ../cxlssd/cca-ring.h ../cxlssd/cca-abi.h \
                        ../tools/cca/cca.c ../tools/cca/cca.h
	$(CC) $(CFLAGS_TEST) $(INCLUDES) -I../tools/cca -I../cxlssd -pthread \
	    -o $@ unit/test-cxl-cca-ring.c ../cxlssd/cca-ring.c \
	    ../tools/cca/cca.c

check: $(UNIT_TESTS)
	@for t in $(UNIT_TESTS); do ./$$t || exit 1; done
ifneq ($(HAVE_GLIB),1)
	@echo "SKIP test-femu-cxl-cache: glib-2.0 not found"
endif

# Needs a built binary; QEMU names the one to check, build/ by default.
QEMU ?= $(ROOT)/build/qemu-system-x86_64
check-docs:
	python3 ../scripts/gen-property-docs.py --check --qemu $(QEMU)

clean:
	rm -f test-femu-nand-media test-femu-hybrid-oracle test-femu-cxl-cache test-femu-cxl-spte \
	      test-femu-cxl-cca-ring nand-media.o

.PHONY: check check-docs clean
