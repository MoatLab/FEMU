# *****************************************************************************
# * Copyright (c) 2004, 2008 IBM Corporation
# * All rights reserved.
# * This program and the accompanying materials
# * are made available under the terms of the BSD License
# * which accompanies this distribution, and is available at
# * http://www.opensource.org/licenses/bsd-license.php
# *
# * Contributors:
# *     IBM Corporation - initial implementation
# ****************************************************************************/


SUBDIRS += $(LIBCDIR)/stdio

STDIO_OBJS = vfprintf.o vsnprintf.o fprintf.o \
	     setvbuf.o fputc.o puts.o fputs.o putchar.o \
	     stdchnls.o fileno.o snprintf.o

STDIO = $(LIBCDIR)/stdio/built-in.a
$(STDIO): $(STDIO_OBJS:%=$(LIBCDIR)/stdio/%)
