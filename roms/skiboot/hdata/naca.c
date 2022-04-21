// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#include <compiler.h>
#include <mem-map.h>
#include <types.h>

#include "naca.h"
#include "spira.h"

__section(".naca.data") struct naca naca = {
	.spirah_addr = CPU_TO_BE64(SPIRAH_OFF),
	.hv_release_data_addr = CPU_TO_BE64(NACA_OFF + offsetof(struct naca, hv_release_data)),
	.spira_addr = CPU_TO_BE64(SPIRA_OFF),
	.lid_table_addr = CPU_TO_BE64(NACA_OFF + offsetof(struct naca, hv_lid_load_table)),
	.spira_size = CPU_TO_BE32(SPIRA_ACTUAL_SIZE),
	.hv_load_map_addr = 0,
	.attn_enabled = 0,
	.pcia_supported = 1,
	.__primary_thread_entry = CPU_TO_BE64(0x180),
	.__secondary_thread_entry = CPU_TO_BE64(0x180),
	.hv_release_data = {
		.vrm = CPU_TO_BE64(0x666), /* ? */
	},
	.hv_lid_load_table = {
		.w0 = CPU_TO_BE32(0x10),
		.w1 = CPU_TO_BE32(0x10),
	},
};
