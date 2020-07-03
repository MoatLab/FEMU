#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <error.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <assert.h>

#define BLOCK_SIZE 4096
#define END_BLOCK_MAGIC 99999
