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

ifndef TOP
  TOP = $(shell while ! test -e make.rules; do cd ..  ; done; pwd)
  export TOP
endif
include $(TOP)/make.rules

CFLAGS += -I. -I.. -I../libc/include -I$(SLOFCMNDIR) -I$(INCLCMNDIR)

SRCS =	bootmenu.c

OBJS = $(SRCS:%.c=%.o)

TARGET = ../libbootmenu.a

all: $(TARGET)

$(TARGET): $(OBJS)
	$(AR) -rc $@ $(OBJS)
	$(RANLIB) $@

clean:
	$(RM) $(TARGET) $(OBJS)

distclean: clean
	$(RM) Makefile.dep


# Rules for creating the dependency file:
depend:
	$(RM) Makefile.dep
	$(MAKE) Makefile.dep

Makefile.dep: Makefile
	$(CC) -M $(CPPFLAGS) $(CFLAGS) $(SRCS) > Makefile.dep

# Include dependency file if available:
-include Makefile.dep
