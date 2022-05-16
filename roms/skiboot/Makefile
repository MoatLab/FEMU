# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# Copyright 2012-2019 IBM Corp

#
# If you want to build in another directory copy this file there and
# fill in the following values
#

#
# Prefix of cross toolchain, if anything
# Example: CROSS= powerpc64-unknown-linux-gnu-
#
ARCH = $(shell uname -m)
ifdef CROSS_COMPILE
	CROSS ?= $(CROSS_COMPILE)
endif
ifneq ("$(ARCH)", "ppc64")
ifneq ("$(ARCH)", "ppc64le")
ifneq ($(shell which powerpc64-linux-gcc 2> /dev/null),)
	CROSS ?= powerpc64-linux-
else ifneq ($(shell which powerpc64le-linux-gcc 2> /dev/null),)
	CROSS ?= powerpc64le-linux-
else ifneq ($(shell which powerpc64-linux-gnu-gcc 2> /dev/null),)
	CROSS ?= powerpc64-linux-gnu-
else ifneq ($(shell which powerpc64le-linux-gnu-gcc 2> /dev/null),)
	CROSS ?= powerpc64le-linux-gnu-
endif
endif
endif

#
# Main debug switch
#
DEBUG ?= 0

# Run tests under valgrind?
USE_VALGRIND ?= 1

#
# Optional location of embedded linux kernel file
# This can be a raw vmlinux, stripped vmlinux or
# zImage.epapr
#
KERNEL ?=

#
# Optional build with advanced stack checking
#
STACK_CHECK ?= $(DEBUG)

#
# Experimental (unsupported) build options
#
# Little-endian does not yet build. Include it here to set ELF ABI.
LITTLE_ENDIAN ?= 0
# ELF v2 ABI is more efficient and compact
ELF_ABI_v2 ?= $(LITTLE_ENDIAN)
# Discard unreferenced code and data at link-time
DEAD_CODE_ELIMINATION ?= 0
# Try to build without FSP code
CONFIG_FSP?=1

#
# Where is the source directory, must be a full path (no ~)
# Example: SRC= /home/me/skiboot
#
SRC=$(CURDIR)

#
# Where to get information about this machine (subdir name)
#
DEVSRC=hdata

#
# default config file, see include config_*.h for more specifics
#
CONFIG := config.h

include $(SRC)/Makefile.main
