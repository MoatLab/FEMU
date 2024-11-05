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

SUBDIRS += $(LIBCDIR)/stdlib

STDLIB_OBJS = error.o atoi.o atol.o strtol.o strtoul.o \
	      rand.o labs.o

STDLIB = $(LIBCDIR)/stdlib/built-in.a
$(STDLIB): $(STDLIB_OBJS:%=$(LIBCDIR)/stdlib/%)

