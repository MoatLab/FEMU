// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2015, Bin Meng <bmeng.cn@gmail.com>
 */

#include <common.h>
#include <bloblist.h>
#include <log.h>
#include <malloc.h>
#include <smbios.h>
#include <acpi/acpi_table.h>
#include <asm/global_data.h>
#include <asm/sfi.h>
#include <asm/mpspec.h>
#include <asm/tables.h>
#include <asm/coreboot_tables.h>

DECLARE_GLOBAL_DATA_PTR;

/**
 * Function prototype to write a specific configuration table
 *
 * @addr:	start address to write the table
 * @return:	end address of the table
 */
typedef ulong (*table_write)(ulong addr);

/**
 * struct table_info - Information about each table to write
 *
 * @name: Name of table (for debugging)
 * @write: Function to call to write this table
 * @tag: Bloblist tag if using CONFIG_BLOBLIST_TABLES
 * @size: Maximum table size
 * @align: Table alignment in bytes
 */
struct table_info {
	const char *name;
	table_write write;
	enum bloblist_tag_t tag;
	int size;
	int align;
};

static struct table_info table_list[] = {
#ifdef CONFIG_GENERATE_PIRQ_TABLE
	{ "pirq", write_pirq_routing_table },
#endif
#ifdef CONFIG_GENERATE_SFI_TABLE
	{ "sfi", write_sfi_table, },
#endif
#ifdef CONFIG_GENERATE_MP_TABLE
	{ "mp", write_mp_table, },
#endif
#ifdef CONFIG_GENERATE_ACPI_TABLE
	{ "acpi", write_acpi_tables, BLOBLISTT_ACPI_TABLES, 0x10000, 0x1000},
#endif
#ifdef CONFIG_GENERATE_SMBIOS_TABLE
	{ "smbios", write_smbios_table, BLOBLISTT_SMBIOS_TABLES, 0x1000, 0x100},
#endif
};

void table_fill_string(char *dest, const char *src, size_t n, char pad)
{
	int start, len;
	int i;

	strncpy(dest, src, n);

	/* Fill the remaining bytes with pad */
	len = strlen(src);
	start = len < n ? len : n;
	for (i = start; i < n; i++)
		dest[i] = pad;
}

int write_tables(void)
{
	u32 rom_table_start;
	u32 rom_table_end;
	u32 high_table, table_size;
	struct memory_area cfg_tables[ARRAY_SIZE(table_list) + 1];
	int i;

	rom_table_start = ROM_TABLE_ADDR;

	debug("Writing tables to %x:\n", rom_table_start);
	for (i = 0; i < ARRAY_SIZE(table_list); i++) {
		const struct table_info *table = &table_list[i];
		int size = table->size ? : CONFIG_ROM_TABLE_SIZE;

		if (IS_ENABLED(CONFIG_BLOBLIST_TABLES) && table->tag) {
			rom_table_start = (ulong)bloblist_add(table->tag, size,
							      table->align);
			if (!rom_table_start)
				return log_msg_ret("bloblist", -ENOBUFS);
		}
		rom_table_end = table->write(rom_table_start);
		rom_table_end = ALIGN(rom_table_end, ROM_TABLE_ALIGN);

		if (IS_ENABLED(CONFIG_SEABIOS)) {
			table_size = rom_table_end - rom_table_start;
			high_table = (u32)(ulong)high_table_malloc(table_size);
			if (high_table) {
				table->write(high_table);

				cfg_tables[i].start = high_table;
				cfg_tables[i].size = table_size;
			} else {
				printf("%d: no memory for configuration tables\n",
				       i);
				return -ENOSPC;
			}
		}

		debug("- wrote '%s' to %x, end %x\n", table->name,
		      rom_table_start, rom_table_end);
		if (rom_table_end - rom_table_start > size) {
			log_err("Out of space for configuration tables: need %x, have %x\n",
				rom_table_end - rom_table_start, size);
			return log_msg_ret("bloblist", -ENOSPC);
		}
		rom_table_start = rom_table_end;
	}

	if (IS_ENABLED(CONFIG_SEABIOS)) {
		/* make sure the last item is zero */
		cfg_tables[i].size = 0;
		write_coreboot_table(CB_TABLE_ADDR, cfg_tables);
	}

	if (IS_ENABLED(CONFIG_BLOBLIST_TABLES)) {
		void *ptr = (void *)CONFIG_ROM_TABLE_ADDR;

		/* Write an RSDP pointing to the tables */
		if (IS_ENABLED(CONFIG_GENERATE_ACPI_TABLE)) {
			struct acpi_ctx *ctx = gd_acpi_ctx();

			acpi_write_rsdp(ptr, ctx->rsdt, ctx->xsdt);
			ptr += ALIGN(sizeof(struct acpi_rsdp), 16);
		}
		if (IS_ENABLED(CONFIG_GENERATE_SMBIOS_TABLE)) {
			void *smbios;

			smbios = bloblist_find(BLOBLISTT_SMBIOS_TABLES, 0);
			if (!smbios)
				return log_msg_ret("smbios", -ENOENT);
			memcpy(ptr, smbios, sizeof(struct smbios_entry));
		}
	}

	debug("- done writing tables\n");

	return 0;
}
