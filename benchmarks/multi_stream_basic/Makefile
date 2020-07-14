CFLAGS := -std=gnu99 -O0 -g -pthread -D_GNU_SOURCE -D__CHECK_ENDIAN__ -Wall -Werror
LDFLAGS := -lm
NVME_PROGS = nvme_rw_stream
ALL_PROGS := $(NVME_PROGS)
default: $(ALL_PROGS)
clean:
	rm -f $(ALL_PROGS) *.o

clobber: clean

.PHONY: default clean clobber

