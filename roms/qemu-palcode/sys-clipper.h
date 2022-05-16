/* Declarations for the CLIPPER system emulation.

   Copyright (C) 2011 Richard Henderson

   This file is part of QEMU PALcode.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the text
   of the GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; see the file COPYING.  If not see
   <http://www.gnu.org/licenses/>.  */

#ifndef SYS_CLIPPER_H
#define SYS_CLIPPER_H 1

#include "core-typhoon.h"

#define SYS_TYPE	ST_DEC_TSUNAMI
#define SYS_VARIATION	(5 << 10)
#define SYS_REVISION	0

#ifndef __ASSEMBLER__

static inline uint8_t MAP_PCI_INTERRUPT(int slot, int pin, int class_id)
{
  uint8_t irq = 0xff; /* no interrupt mapping */

  /* PCI-ISA bridge is hard-wired to IRQ 55 on real hardware, and comes in
     at a different SCB vector; force the line register to 0xff.
     Otherwise, see qemu hw/alpha/dp264.c:clipper_pci_map_irq()  */
  if (class_id != 0x0601 && pin >= 1 && pin <= 4)
    irq = (slot + 1) * 4 + (pin - 1);

  return irq;
}

#endif /* ! __ASSEMBLER__ */

#endif
