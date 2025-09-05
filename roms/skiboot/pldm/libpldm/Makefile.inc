# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# Copyright 2022 IBM Corp.

LIBPLDM_DIR ?= pldm/libpldm
SUBDIRS += $(LIBPLDM_DIR)

LIBPLDM_OBJS = base.o platform.o bios.o bios_table.o fru.o utils.o
LIBPLDM_OBJS += pdr.o firmware_update.o

CFLAGS_$(LIBPLDM_DIR)/ = -I$(SRC)/pldm/include/libpldm/ \
		-I$(SRC)/pldm/include/ \
		-Wno-error \
		-Wno-declaration-after-statement \
		-Wno-suggest-attribute=const \
		-Wno-jump-misses-init \
		-Wno-strict-prototypes \
		-Wno-missing-prototypes \
		-Wno-stack-usage \
		-Wno-missing-declarations \
		-Wno-type-limits

LIBPLDM = $(LIBPLDM_DIR)/built-in.a

$(LIBPLDM): $(LIBPLDM_OBJS:%=$(LIBPLDM_DIR)/%)
