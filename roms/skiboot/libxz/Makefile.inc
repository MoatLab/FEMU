LIBXZ_SRCS = xz_dec_stream.c xz_dec_lzma2.c xz_crc32.c
LIBXZ_OBJS = $(LIBXZ_SRCS:%.c=%.o)

SUBDIRS += libxz
LIBXZ = libxz/built-in.a

$(LIBXZ): $(LIBXZ_OBJS:%=libxz/%)
