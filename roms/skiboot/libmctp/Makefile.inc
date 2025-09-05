# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# Copyright 2022 IBM Corp.

LIBMCTP_DIR ?= libmctp
SUBDIRS += $(LIBMCTP_DIR)

LIBMCTP_OBJS = crc32.o core.o alloc.o log.o
LIBMCTP_BINDINGS ?= astlpc

LIBMCTP_OBJS += $(LIBMCTP_BINDINGS:%=%.o)

CFLAGS_$(LIBMCTP_DIR)/ = -I$(SRC)/ccan/endian/ \
			-DHAVE_CONFIG_H \
			-Wno-error \
			-Wno-type-limits \
			-Wno-missing-prototypes \
			-Wno-missing-declarations \
			-Wno-suggest-attribute=const

LIBMCTP = $(LIBMCTP_DIR)/built-in.a

$(LIBMCTP): $(LIBMCTP_OBJS:%=$(LIBMCTP_DIR)/%)
