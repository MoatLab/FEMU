CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -g
SO_CFLAGS ?= -Wall -Wextra -O2 -g -fPIC

TARGETS := csd-passthru csd-vadd.so

.PHONY: all clean

all: $(TARGETS)

csd-passthru: csd-passthru.c
	$(CC) $(CFLAGS) -o $@ $<

csd-vadd.so: csd-vadd.c femu-csd-kernel.h
	$(CC) $(SO_CFLAGS) -shared -o $@ $<

clean:
	rm -f $(TARGETS)
