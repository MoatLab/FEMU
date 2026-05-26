CC ?= gcc
CXX ?= c++
CFLAGS ?= -Wall -Wextra -O2 -g
SO_CFLAGS ?= -Wall -Wextra -O2 -g -fPIC
CXX_SO_CFLAGS ?= -Wall -Wextra -O2 -g -fPIC

BPF_TARGETS := csd-vadd.bpf.o
TARGETS := csd-passthru csd-vadd.so csd-original-kernels.so

.PHONY: all bpf clean

all: $(TARGETS)

bpf: $(BPF_TARGETS)

csd-passthru: csd-passthru.c
	$(CC) $(CFLAGS) -o $@ $<

csd-vadd.so: csd-vadd.c femu-csd-kernel.h
	$(CC) $(SO_CFLAGS) -shared -o $@ $<

csd-original-kernels.so: csd-original-kernels.cc femu-csd-kernel.h
	$(CXX) $(CXX_SO_CFLAGS) -shared -o $@ $< -pthread -llz4

csd-vadd.bpf.o: csd-vadd.bpf.c femu-csd-kernel.h
	clang -target bpf -O2 -g -c -o $@ $<

clean:
	rm -f $(TARGETS) $(BPF_TARGETS)
