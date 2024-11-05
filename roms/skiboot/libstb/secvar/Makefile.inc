# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# -*-Makefile-*-

SUBDIRS += libstb/secvar

SECVAR_OBJS = secvar_main.o secvar_util.o secvar_devtree.o secvar_api.o
SECVAR = libstb/secvar/built-in.a

include $(SRC)/libstb/secvar/storage/Makefile.inc
include $(SRC)/libstb/secvar/backend/Makefile.inc

$(SECVAR): $(SECVAR_OBJS:%=libstb/secvar/%) $(SECVAR_STORAGE) $(SECVAR_BACKEND)
