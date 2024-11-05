# Makefile.inc
#
# LIBFDT_ variables are taken from Makefile.libfdt

LIBFDT_INCLUDES = fdt.h libfdt.h libfdt_env.h
LIBFDT_SRCS = fdt.c fdt_ro.c fdt_wip.c fdt_sw.c fdt_rw.c fdt_strerror.c fdt_empty_tree.c \
	fdt_addresses.c fdt_overlay.c
LIBFDT_OBJS = $(LIBFDT_SRCS:%.c=%.o)

CFLAGS_SKIP_libfdt/ = -Wsuggest-attribute=const -Wsuggest-attribute=noreturn

SUBDIRS += libfdt
LIBFDT = libfdt/built-in.a

$(LIBFDT): $(LIBFDT_OBJS:%=libfdt/%)

