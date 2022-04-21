# *****************************************************************************
# * Copyright (c) 2004, 2016 IBM Corporation
# * All rights reserved.
# * This program and the accompanying materials
# * are made available under the terms of the BSD License
# * which accompanies this distribution, and is available at
# * http://www.opensource.org/licenses/bsd-license.php
# *
# * Contributors:
# *     IBM Corporation - initial implementation
# ****************************************************************************/

SUBDIRS += $(LIBCDIR)/string

STRING_OBJS = strcat.o strchr.o strrchr.o strcmp.o strcpy.o strlen.o \
	      strncmp.o strncpy.o strstr.o memset.o memcpy.o memcpy_from_ci.o \
	      memmove.o memchr.o memcmp.o strcasecmp.o strncasecmp.o \
	      strtok.o strdup.o
STRING = $(LIBCDIR)/string/built-in.a
$(STRING): $(STRING_OBJS:%=$(LIBCDIR)/string/%)

CFLAGS_SKIP_libc/string/ += -Os
CFLAGS_libc/string/ += -O2
