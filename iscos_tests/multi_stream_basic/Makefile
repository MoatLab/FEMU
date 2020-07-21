CFLAGS := -std=gnu99 -O0 -g -pthread -D__CHECK_ENDIAN__ -Wall -Werror
LDFLAGS := -lm -lpthread
NVME_PROGS = nvme_rw_stream normal stream
SRC_FILES = nvme_rw_stream.c normal.c stream.c
ALL_PROGS := $(NVME_PROGS)

default: nvme_rw_stream normal stream

nvme_rw_stream: common.c nvme_rw_stream.c
	gcc -c common.c
	gcc $(CLFAGS) common.o nvme_rw_stream.c $(LDFLAGS) -o nvme_rw_stream

normal: common.c normal.c
	gcc -c common.c
	gcc $(CLFAGS) common.o normal.c $(LDFLAGS) -o normal

stream: common.c stream.c
	gcc -c common.c
	gcc $(CLFAGS) common.o stream.c $(LDFLAGS) -o stream


clean:
	rm -f $(ALL_PROGS) *.o common

clobber: clean

.PHONY: default clean clobber

