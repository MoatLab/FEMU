LIBPORE_SRCS = p9_stop_api.C p9_stop_util.C p10_stop_api.C p10_stop_util.C
ifeq ($(CONFIG_P8),1)
LIBPORE_SRCS += sbe_xip_image.c pore_inline_assembler.c
LIBPORE_SRCS += p8_pore_table_gen_api_fixed.C p8_pore_table_static_data.c
endif

LIBPORE_OBJS_1 = $(LIBPORE_SRCS:%.c=%.o)
LIBPORE_OBJS = $(LIBPORE_OBJS_1:%.C=%.o)
SUBDIRS += libpore
LIBPORE = libpore/built-in.a

CFLAGS_SKIP_libpore/pore_inline_assembler.o=-Wsuggest-attribute=const

$(LIBPORE): $(LIBPORE_OBJS:%=libpore/%)

