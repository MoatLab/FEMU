/*
 * Copyright (C) 2025 ASPEED Technology Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __AST27X0_INCLUDE_IO_H__
#define __AST27X0_INCLUDE_IO_H__

#define readb(addr) (*(volatile unsigned char *)(addr))
#define readw(addr) (*(volatile unsigned short *)(addr))
#define readl(addr) (*((volatile unsigned int *)(addr)))
#define readq(addr) (*((volatile unsigned long long *)(addr)))

#define writeb(value, addr) (*(volatile unsigned char *)(addr) = (unsigned char)value)
#define writew(value, addr) (*(volatile unsigned short *)(addr) = (unsigned short)value)
#define writel(value, addr) (*(volatile unsigned int *)(addr) = (unsigned int)(value))
#define writeq(value, addr) (*(volatile unsigned long long *)(addr) = (unsigned long long)(value))

#define BITS_PER_LONG (sizeof(unsigned long) * 8)
#define GENMASK(h, l) \
    (((~0UL) >> (BITS_PER_LONG - ((h) - (l) + 1))) << (l))

#define BIT(x) (1UL << (x))

#define ALIGN_UP(x, align)  (((x) + ((align) - 1)) & ~((align) - 1))

#endif /* __AST27X0_INCLUDE_IO_H__ */
