# The NAND media layer (hw/femu/nand/nand-media.c) includes only qemu/osdep.h
# and its own header, so it compiles standalone against the stub in qemu/.
# That keeps this test in the millisecond range: no QEMU build, no guest, no
# hardware. Run it with `make -C hw/femu/tests check`.
#
# The media source is built at the project's own warning level; only the test
# is held to -Wextra -Werror, so this cannot start failing on unrelated code.
CFLAGS_TEST ?= -O2 -Wall -Wextra -Werror -std=gnu11
CFLAGS_LIB  ?= -O2 -Wall -std=gnu11
INCLUDES = -I. -I../nand

test-nand-media: test-nand-media.c nand-media.o ../nand/nand-media.h
	$(CC) $(CFLAGS_TEST) $(INCLUDES) -o $@ test-nand-media.c nand-media.o

nand-media.o: ../nand/nand-media.c ../nand/nand-media.h
	$(CC) $(CFLAGS_LIB) $(INCLUDES) -c -o $@ ../nand/nand-media.c

check: test-nand-media
	./test-nand-media

clean:
	rm -f test-nand-media nand-media.o

.PHONY: check clean
