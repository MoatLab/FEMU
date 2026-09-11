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

test-femu-nand-media: $(TEST_SRC) nand-media.o ../nand/nand-media.h
	$(CC) $(CFLAGS_TEST) $(INCLUDES) -o $@ $(TEST_SRC) nand-media.o

nand-media.o: ../nand/nand-media.c ../nand/nand-media.h
	$(CC) $(CFLAGS_LIB) $(INCLUDES) -c -o $@ ../nand/nand-media.c

check: test-femu-nand-media
	./test-femu-nand-media

clean:
	rm -f test-femu-nand-media nand-media.o

.PHONY: check clean
