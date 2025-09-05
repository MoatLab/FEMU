# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# Copyright 2022 IBM Corp.

LIBPLDM_IBM_DIR ?= pldm/libpldm/oem/ibm
SUBDIRS += $(LIBPLDM_IBM_DIR)

LIBPLDM_IBM_OBJS = file_io.o host.o platform.o

CPPFLAGS += -I$(SRC)/pldm/include/ \
	-I$(SRC)/pldm/include/libpldm/ \
	-I$(SRC)/pldm/include/libpldm/oem/ibm/

CFLAGS_$(LIBPLDM_IBM_DIR)/ = -Wno-error \
			-Wno-declaration-after-statement \
			-Wno-strict-prototypes

LIBPLDM_IBM = $(LIBPLDM_IBM_DIR)/built-in.a

$(LIBPLDM_IBM): $(LIBPLDM_IBM_OBJS:%=$(LIBPLDM_IBM_DIR)/%)
