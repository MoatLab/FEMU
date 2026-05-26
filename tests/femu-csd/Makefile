CC ?= gcc
CXX ?= c++
CFLAGS ?= -Wall -Wextra -O2 -g
SO_CFLAGS ?= -Wall -Wextra -O2 -g -fPIC
CXX_SO_CFLAGS ?= -Wall -Wextra -O2 -g -fPIC

TARGETS := csd-passthru csd-vadd.so csd-original-kernels.so

.PHONY: all clean

all: $(TARGETS)

csd-passthru: csd-passthru.c
	$(CC) $(CFLAGS) -o $@ $<

csd-vadd.so: csd-vadd.c femu-csd-kernel.h
	$(CC) $(SO_CFLAGS) -shared -o $@ $<

csd-original-kernels.so: csd-original-kernels.cc femu-csd-kernel.h
	$(CXX) $(CXX_SO_CFLAGS) -shared -o $@ $< -pthread

clean:
	rm -f $(TARGETS)
