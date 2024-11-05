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

include ../make.rules

TARGETS = gen_reloc_table sloffs
HOSTCFLAGS += -I../romfs/tools

all: $(TARGETS)

crclib.o: ../romfs/tools/crclib.c
		$(HOSTCC) -W $(HOSTCFLAGS) -c $^ -o $@

%.o: %.c
		$(HOSTCC) -W $(HOSTCFLAGS) -c $^

gen_reloc_table: gen_reloc_table.o
		$(HOSTCC) $(HOSTCFLAGS) -o $@ $^

sloffs: sloffs.o crclib.o
		$(HOSTCC) $(HOSTCFLAGS) -o $@ $^

clean_here:
	rm -f *.o $(TARGETS)

clean: clean_here


distclean: clean_here
