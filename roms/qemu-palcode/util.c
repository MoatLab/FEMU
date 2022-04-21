/* Utility functions for the QEMU PALcode.

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

#include "protos.h"

static inline long
ndelay_with_int(unsigned long nsec)
{
  register long a0 __asm__("16") = nsec;
  register long v0 __asm__("0");
  asm volatile ("call_pal 3" : "=r"(v0) : "r"(a0));
  return v0;
}

void
ndelay(unsigned long nsec)
{
  long left = nsec;
  do {
    left = ndelay_with_int(left);
  } while (left > 0);
}
