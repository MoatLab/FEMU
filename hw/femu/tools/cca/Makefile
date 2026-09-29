# SPDX-License-Identifier: GPL-2.0-or-later
# Guest tools for the femu-cxl-ssd caching API. Build inside the guest:
#   make -C hw/femu/tools/cca
# The library and the device share ../../cxlssd/cca-abi.h.
CC ?= cc
CFLAGS ?= -O2 -g
CFLAGS += -Wall -Wextra -Werror -std=gnu11 -I. -I../../cxlssd
LDLIBS += -pthread

TARGETS := ccactl cca-test libcca.a

all: $(TARGETS)

cca.o: cca.c cca.h ../../cxlssd/cca-abi.h
	$(CC) $(CFLAGS) -pthread -c -o $@ cca.c

libcca.a: cca.o
	$(AR) rcs $@ $^

ccactl: ccactl.c libcca.a cca.h
	$(CC) $(CFLAGS) -o $@ ccactl.c libcca.a $(LDLIBS)

cca-test: cca-test.c libcca.a cca.h
	$(CC) $(CFLAGS) -o $@ cca-test.c libcca.a $(LDLIBS)

clean:
	rm -f $(TARGETS) cca.o

.PHONY: all clean
