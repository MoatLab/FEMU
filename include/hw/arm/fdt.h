/*
 *
 * Copyright (c) 2015 Linaro Limited
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Define macros useful when building ARM device tree nodes
 */

#ifndef QEMU_ARM_FDT_H
#define QEMU_ARM_FDT_H

/*
 * These are for GICv2/v3/v4 only; GICv5 encodes the interrupt type in
 * the DTB "interrupts" properties differently, using constants that
 * match the architectural INTID.Type. In QEMU those are available as
 * the GICV5_PPI and GICV5_SPI enum values in arm_gicv5_types.h.
 */
#define GIC_FDT_IRQ_TYPE_SPI 0
#define GIC_FDT_IRQ_TYPE_PPI 1

/*
 * The trigger type/level field in the DTB "interrupts" property has
 * the same encoding for GICv2/v3/v4 and v5.
 */
#define GIC_FDT_IRQ_FLAGS_EDGE_LO_HI 1
#define GIC_FDT_IRQ_FLAGS_EDGE_HI_LO 2
#define GIC_FDT_IRQ_FLAGS_LEVEL_HI 4
#define GIC_FDT_IRQ_FLAGS_LEVEL_LO 8

#define GIC_FDT_IRQ_PPI_CPU_START 8
#define GIC_FDT_IRQ_PPI_CPU_WIDTH 8

#endif
