/* cmd_bootu.c */

/*
 * Copyright (C) 2008
 *     Giuseppe Coviello <cjg@cruxppc.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <common.h>
#include <command.h>
#include <part.h>
#include <../../../disk/part_amiga.h>
#include <malloc.h>
#include <ext2fs.h>
#include "sys_dep.h"

#define BOOTLOADER_MAX_BUFFER 128*1024
#define HEADER_INFO_SIZE 20 
#define UNUSED_BLOCK_ADDRESS 0xffffffff

struct BootDevice {
        char *interface;
        int device;
        int partition;
	char *filename;
        block_dev_desc_t *desc;
};

struct BootDeviceTable {
	char *name;
	struct BootDevice device;
};

static struct BootDeviceTable table[] = {{"s4siicdrom", {"s4sii", 1}}};

extern unsigned long valid_elf_image(void *);
extern unsigned long load_elf_image(void *);
static char *argarray[5];


static int start(void *buffer)
{
	short (* bls)(struct sbl_callback_context *);
	unsigned long entrypoint;
	short result = -1;
	struct sbl_callback_context *context;

	if(!valid_elf_image(buffer)) {
		printf("Error: no real ELF image installed as bootloader!\n");
		return;
	}

	context = build_callback_context(argarray);

	entrypoint = load_elf_image(buffer);
	bls = (short (*)(struct sbl_callback_context *)) entrypoint;

	result = bls(context);
	
	return result;
}

static int do_bootu_tftp(void)
{
	char *filename;
	int transfer_size;
	void *buffer;

	buffer = malloc(BOOTLOADER_MAX_BUFFER);

	if((filename = getenv("netboot_file")) == NULL)
		filename = "OS4Bootloader";

	puts("Starting Net booting procedure\n");

	if ((transfer_size = my_NetLoop(filename, buffer)) != -1)
		puts("Successfully loaded SLB from network\n");
	else {
		printf("Couldn't download %s from network.\n", filename);
		free(buffer);
		return -1;
	}	
	
	start(buffer);
	return 0;
}

static int do_bootu_hd(struct BootDevice *dev)
{
	void *buffer;
	char *filename;
	int partition;
	disk_partition_t info;
	ulong part_length;
	ulong filelen;
	
	if((partition = dev->partition) < 0) {
		printf("Warning: partition is not set. Using the first "
			"partition!\n");
		partition = 1;
	}
	
	if((filename = dev->filename) == NULL) {
		printf("Warning: filename is not set. Using the default: "
			"Parthenope!\n");
		filename = "Parthenope";
	}
	
	if(get_partition_info(dev->desc, partition, &info)) {
		printf("Error: Bad partition %d!\n", partition);
		return -1;
	}
	
	if((part_length = ext2fs_set_blk_dev(dev->desc, partition)) == 0) {
		printf("Error: Bad partition %s %d:%d!\n", dev->interface,
			dev->device, partition);
		ext2fs_close();
		return -1;
	}

	if(!ext2fs_mount(part_length)) {
		printf("Error: Bad ext2 partition %s %d:%d!\n", dev->interface,
			dev->device, partition);
		ext2fs_close();
		return -1;
	}
	
	if((filelen = ext2fs_open(filename)) < 0) {
		printf("Error: File not found %s!\n", filename);
		ext2fs_close();
		return -1;
	}
	
 	buffer = malloc(filelen);
	
	if(ext2fs_read((char *) buffer, filelen) != filelen) {
		printf("Error: Unable to read %s!\n", filename);
		ext2fs_close();
		free(buffer);
	}
	
	ext2fs_close();	

	start(buffer);
	return 0;
}

static int do_bootu_amiga_hd(block_dev_desc_t *dev_desc)
{
	struct rigid_disk_block *rdb;
	char *blockbuffer;
	void *buffer;
	u32 next, chunklen;
	u32 *current;
	struct BootstrapCodeBlock *bcb;
	
	rdb = get_rdisk(dev_desc);

	if(rdb == NULL) {
		printf("No RDB found!\n");
		return 1;
	}

	buffer = malloc(BOOTLOADER_MAX_BUFFER);
	blockbuffer = malloc(dev_desc->blksz);
	
	next = rdb->bootcode_block;

	current = (u32 *) buffer;
	bcb = (struct BootstrapCodeBlock *) blockbuffer;
	do {
		dev_desc->block_read(dev_desc->dev, next, 1, blockbuffer);
		memcpy((char *)current, blockbuffer + HEADER_INFO_SIZE, 
		  (chunklen = bcb->bcb_SummedLongs-(HEADER_INFO_SIZE>>2))<<2);
		current+=chunklen;
	} while((next = bcb->bcb_Next) != UNUSED_BLOCK_ADDRESS);
        	
	start(buffer);
	return 0;
}

static int do_bootu_eltorito(struct BootDevice *device)
{
	void *buffer;
	disk_partition_t info;
	get_partition_info(device->desc, 0, &info);
	buffer = malloc(info.size * info.blksz);
	if(device->desc->block_read(device->desc->dev, info.start, info.size, 
		buffer) != info.size) {
		printf("Error: read error from %s:%d\n", device->interface,
			device->device);
		free(buffer);
		return -1;
	}
		
	start(buffer);
	return 0;
}

static char *pop(char *s, char sep)
{
	char *p, *x;
	if((p = strchr(s, sep)) == NULL)
		return strdup(s);
	x = malloc(p - s + 1);
	memmove(x, s, p - s);
	x[p - s] = 0;
	return x;
}

static struct BootDevice *BootDevice_new_from_string(char *s)
{
	struct BootDevice *self;
	char *value;
	
	self = malloc(sizeof(struct BootDevice));
	self->interface = pop(s, ':');
	self->device = 0;
	self->partition = -1;
	self->filename = NULL;
	s += strlen(self->interface);
	if(*s == 0 || *++s == 0)
		goto validate;
	value = pop(s, ':');
	self->device = (int) simple_strtoul(value, NULL, 16);
	s += strlen(value);
	free(value);
	if(*s == 0 || *++s == 0)
		goto validate;
	value = pop(s, ':');
	self->partition = (int) simple_strtoul(value, NULL, 16);
	s += strlen(value);
	free(value);
	if(*s == 0 || *++s == 0)
		goto validate;
	self->filename = strdup(s);

validate:
	if((self->desc = get_dev(self->interface, self->device)) == NULL) {
		free(self->interface);
		free(self->filename);
		free(self);
		return NULL;
	}
	return self;
}

static struct BootDevice *BootDevice_find(char *s)
{
	struct BootDevice *self;
	int i;
	
	self = malloc(sizeof(struct BootDevice));
	for(i = 0; i < sizeof(table) / sizeof(struct BootDeviceTable);i++) {
		if(strcmp(s, table[i].name))
			continue;
		memmove(self, &table[i].device, sizeof(struct BootDevice));
		goto found;
	}
	return NULL;
found:
	if((self->desc = get_dev(self->interface, self->device)) == NULL) {
		free(self->interface);
		free(self->filename);
		free(self);
		return NULL;
	}
	return self;
}

static void BootDevice_print(struct BootDevice *self)
{
	printf("%s:%d", self->interface, self->device);
	if(self->partition >= 0) 
		printf(":%d:%s", self->partition, (self->filename == NULL ? "Parthenope" : self->filename));
	printf("\n");
}

static void BootDevice_boot(struct BootDevice *self)
{
	if(self->desc->type == DEV_TYPE_HARDDISK 
		&& self->desc->part_type == PART_TYPE_AMIGA
		&& self->partition == -1)
		do_bootu_amiga_hd(self->desc);
	if(self->desc->type == DEV_TYPE_HARDDISK)
		do_bootu_hd(self);
	if(self->desc->type == DEV_TYPE_CDROM)
		do_bootu_eltorito(self);
}

static void copyright(void)
{
	puts("bootu (u-boot first level bootloader) 1.0\n");
	puts("Copyright (C) 2008 Giuseppe Coviello.\n");
	puts("This is free software.  You may redistribute ");
	puts("copies of it under the terms of\n");
	puts("the GNU General Public License ");
	puts("<http://www.gnu.org/licenses/gpl.html>.\n");
	puts("There is NO WARRANTY, to the extent permitted by law.\n");
}

int bootu(char *device_str)
{
	struct BootDevice *device;
	if(strcmp(device_str, "net") == 0) 
		return do_bootu_tftp();
	device = BootDevice_find(device_str);
	if(device == NULL)
		device = BootDevice_new_from_string(device_str);
	if(device != NULL) {
		BootDevice_print(device);
		BootDevice_boot(device);
		return -1;
	}
	return 0;
}

int do_bootu(cmd_tbl_t * cmdtp, int flag, int argc, char *argv[])
{
	int i;
	SCAN_HANDLE scanner;
	ULONG sector_size;

	copyright();
	argarray[0] = getenv("boot1");
	argarray[1] = getenv("boot2");
	argarray[2] = getenv("boot3");
	argarray[3] = NULL;

	for(i = 1; i < 5; i++) {
		if(argarray[i - 1] == NULL)
			continue;
		scanner = next_unit_scan(scanner, &sector_size);
		printf("%s\n", argarray[i - 1]);
		if(bootu(argarray[i - 1]) == 0)
			break;
	}

	return 0;
}

U_BOOT_CMD(
	bootu,      1,      0,      do_bootu,
	"bootu   - load and start secondory level bootloader.\n",
	". 'Bootu' allows to load secondary level bootloader "
	"like Parthenope or AOS SLB.\n");

U_BOOT_CMD(
	boota,      1,      0,      do_bootu,
	"boota   - load and start secondory level bootloader.\n",
	". 'Boota' allows to load secondary level bootloader "
	"like Parthenope or AOS SLB.\n");
