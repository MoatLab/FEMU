#
# (C) Copyright 2008
# Wolfgang Denk, DENX Software Engineering, wd@denx.de.
#
# See file CREDITS for list of people who contributed to this
# project.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of
# the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston,
# MA 02111-1307 USA
#
#
# ACube Systems Sam460EX Board
#

sinclude $(OBJTREE)/board/$(BOARDDIR)/config.tmp

ifndef TEXT_BASE
TEXT_BASE = 0xFFF80000
endif

X86EMU =  -I../bios_emulator/scitech/include -I../bios_emulator/scitech/src/x86emu

# -fgnu89-inline requires gcc 4.2 (it can be omitted in previous versions)
PLATFORM_CPPFLAGS += -DCONFIG_440=1 $(X86EMU) -Dprintk=printf -fgnu89-inline


ifeq ($(debug),1)
PLATFORM_CPPFLAGS += -DDEBUG
endif

ifeq ($(dbcr),1)
PLATFORM_CPPFLAGS += -DCONFIG_SYS_INIT_DBCR=0x8cff0000
endif
