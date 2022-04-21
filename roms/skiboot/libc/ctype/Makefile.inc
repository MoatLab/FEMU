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

SUBDIRS += $(LIBCDIR)/ctype

CTYPE_OBJS = isdigit.o isprint.o isspace.o isxdigit.o tolower.o toupper.o

CTYPE = $(LIBCDIR)/ctype/built-in.a
$(CTYPE): $(CTYPE_OBJS:%=$(LIBCDIR)/ctype/%)

