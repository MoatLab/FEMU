# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# -*-Makefile-*-

SECVAR_BACKEND_DIR = libstb/secvar/backend

SUBDIRS += $(SECVAR_BACKEND_DIR)

SECVAR_BACKEND_OBJS = edk2-compat.o edk2-compat-process.o edk2-compat-reset.o
SECVAR_BACKEND = $(SECVAR_BACKEND_DIR)/built-in.a

$(SECVAR_BACKEND): $(SECVAR_BACKEND_OBJS:%=$(SECVAR_BACKEND_DIR)/%)
