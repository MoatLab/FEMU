CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -g

TARGETS := csd-passthru

.PHONY: all clean

all: $(TARGETS)

csd-passthru: csd-passthru.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS)
