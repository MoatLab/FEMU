/*
 *   OpenBIOS LSI driver
 *
 *   Copyright (C) 2018 Mark Cave-Ayland <mark.cave-ayland@ilande.co.uk>
 *
 *   Based upon drivers/esp.c
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   version 2
 *
 */

#include "config.h"
#include "libc/byteorder.h"
#include "libc/vsprintf.h"
#include "libopenbios/bindings.h"
#include "drivers/drivers.h"
#include "scsi.h"

typedef struct sd_private sd_private_t;
typedef struct lsi_table lsi_table_t;
typedef struct lsi_private lsi_private_t;

struct sd_private {
    unsigned int bs;
    const char *media_str[2];
    uint32_t sectors;
    uint8_t media;
    uint8_t id;
    uint8_t present;
    char model[40];
    lsi_private_t *lsi;
};

struct lsi_table {
    uint32_t id;
    uint32_t id_addr;
    uint32_t msg_out_len;
    uint32_t msg_out_ptr;
    uint32_t cmd_len;
    uint32_t cmd_ptr;
    uint32_t data_in_len;
    uint32_t data_in_ptr;
    uint32_t status_len;
    uint32_t status_ptr;
    uint32_t msg_in_len;
    uint32_t msg_in_ptr;
};

struct lsi_private {
    volatile uint8_t *mmio;
    uint32_t *scripts;
    uint32_t *scripts_iova;
    lsi_table_t *table;
    lsi_table_t *table_iova;
    volatile uint8_t *buffer;
    volatile uint8_t *buffer_iova;
    sd_private_t sd[8];
};

#ifdef CONFIG_DEBUG_LSI
#define DPRINTF(fmt, args...)                   \
    do { printk(fmt , ##args); } while (0)
#else
#define DPRINTF(fmt, args...)
#endif

/* DECLARE data structures for the nodes.  */
DECLARE_UNNAMED_NODE(ob_sd, INSTALL_OPEN, sizeof(sd_private_t *));
DECLARE_UNNAMED_NODE(ob_lsi, INSTALL_OPEN, sizeof(lsi_private_t **));

#ifdef CONFIG_DEBUG_LSI
static void dump_drive(sd_private_t *drive)
{
    printk("SCSI DRIVE @%lx:\n", (unsigned long)drive);
    printk("id: %d\n", drive->id);
    printk("media: %s\n", drive->media_str[0]);
    printk("media: %s\n", drive->media_str[1]);
    printk("model: %s\n", drive->model);
    printk("sectors: %d\n", drive->sectors);
    printk("present: %d\n", drive->present);
    printk("bs: %d\n", drive->bs);
}
#endif

#define PHASE_DO          0
#define PHASE_DI          1
#define PHASE_CMD         2
#define PHASE_ST          3
#define PHASE_MO          6
#define PHASE_MI          7

#define LSI_DSTAT         0x0c
#define LSI_DSA           0x10
#define LSI_ISTAT0        0x14
#define LSI_DSP           0x2c
#define LSI_SIST0         0x42
#define LSI_SIST1         0x43

#define LSI_ISTAT0_DIP    0x01
#define LSI_ISTAT0_SIP    0x02

/* Indirection table */
#define LSI_TABLE_OFFSET(x)  (((uintptr_t)&(x)) - ((uintptr_t)lsi->table))

#define LSI_TABLE_MSG_OUT_OFFSET   0x0
#define LSI_TABLE_CMD_OFFSET       0x2
#define LSI_TABLE_DATA_OFFSET      0x20
#define LSI_TABLE_STATUS_OFFSET    0x10
#define LSI_TABLE_MSG_IN_OFFSET    0x12

static void
init_scripts(lsi_private_t *lsi)
{
    /* Initialise SCRIPTS for the commands we are interested in */

    /* 1 - INQUIRY / READ CAPACITY */
    
    /* 1.0 Select with ATN */
    lsi->scripts[0x0] = __cpu_to_le32(0x47000000);
    lsi->scripts[0x1] = __cpu_to_le32(LSI_TABLE_OFFSET(lsi->table->id));

    /* 1.1 Select LUN */    
    lsi->scripts[0x2] = __cpu_to_le32(0x10000000 | (PHASE_MO << 24));
    lsi->scripts[0x3] = __cpu_to_le32(LSI_TABLE_OFFSET(lsi->table->msg_out_len));

    /* 1.2 Send command */
    lsi->scripts[0x4] = __cpu_to_le32(0x10000000 | (PHASE_CMD << 24));
    lsi->scripts[0x5] = __cpu_to_le32(LSI_TABLE_OFFSET(lsi->table->cmd_len));

    /* 1.3 Data in */
    lsi->scripts[0x6] = __cpu_to_le32(0x10000000 | (PHASE_DI << 24));
    lsi->scripts[0x7] = __cpu_to_le32(LSI_TABLE_OFFSET(lsi->table->data_in_len));

    /* 1.4 Status */
    lsi->scripts[0x8] = __cpu_to_le32(0x10000000 | (PHASE_ST << 24));
    lsi->scripts[0x9] = __cpu_to_le32(LSI_TABLE_OFFSET(lsi->table->status_len));

    /* 1.5 Message in */
    lsi->scripts[0xa] = __cpu_to_le32(0x10000000 | (PHASE_MI << 24));
    lsi->scripts[0xb] = __cpu_to_le32(LSI_TABLE_OFFSET(lsi->table->msg_in_len));
    
    /* 1.6 Wait disconnect */
    lsi->scripts[0xc] = __cpu_to_le32(0x48000000);
    lsi->scripts[0xd] = __cpu_to_le32(LSI_TABLE_OFFSET(lsi->table->id));

    /* 1.7 Interrupt */
    lsi->scripts[0xe] = __cpu_to_le32(0x98080000);
    lsi->scripts[0xf] = 0x0;
    
    
    /* 2 - TEST UNIT READY */
    
    /* 2.0 Select with ATN */
    lsi->scripts[0x10] = __cpu_to_le32(0x47000000);
    lsi->scripts[0x11] = __cpu_to_le32(LSI_TABLE_OFFSET(lsi->table->id));

    /* 2.1 Select LUN */    
    lsi->scripts[0x12] = __cpu_to_le32(0x10000000 | (PHASE_MO << 24));
    lsi->scripts[0x13] = __cpu_to_le32(LSI_TABLE_OFFSET(lsi->table->msg_out_len));

    /* 2.2 Send command */
    lsi->scripts[0x14] = __cpu_to_le32(0x10000000 | (PHASE_CMD << 24));
    lsi->scripts[0x15] = __cpu_to_le32(LSI_TABLE_OFFSET(lsi->table->cmd_len));

    /* 2.3 Status */
    lsi->scripts[0x16] = __cpu_to_le32(0x10000000 | (PHASE_ST << 24));
    lsi->scripts[0x17] = __cpu_to_le32(LSI_TABLE_OFFSET(lsi->table->status_len));

    /* 2.4 Message in */
    lsi->scripts[0x18] = __cpu_to_le32(0x10000000 | (PHASE_MI << 24));
    lsi->scripts[0x19] = __cpu_to_le32(LSI_TABLE_OFFSET(lsi->table->msg_in_len));
    
    /* 2.5 Wait disconnect */
    lsi->scripts[0x1a] = __cpu_to_le32(0x48000000);
    lsi->scripts[0x1b] = __cpu_to_le32(LSI_TABLE_OFFSET(lsi->table->id));
    
    /* 2.6 Interrupt */
    lsi->scripts[0x1c] = __cpu_to_le32(0x98080000);
    lsi->scripts[0x1d] = 0x0;
    
    
    /* 3 - READ 10 */
    
    /* 3.0 Select with ATN */
    lsi->scripts[0x20] = __cpu_to_le32(0x47000000);
    lsi->scripts[0x21] = __cpu_to_le32(LSI_TABLE_OFFSET(lsi->table->id));

    /* 3.1 Select LUN */    
    lsi->scripts[0x22] = __cpu_to_le32(0x10000000 | (PHASE_MO << 24));
    lsi->scripts[0x23] = __cpu_to_le32(LSI_TABLE_OFFSET(lsi->table->msg_out_len));

    /* 3.2 Send command */
    lsi->scripts[0x24] = __cpu_to_le32(0x10000000 | (PHASE_CMD << 24));
    lsi->scripts[0x25] = __cpu_to_le32(LSI_TABLE_OFFSET(lsi->table->cmd_len));

    /* 3.3 Message in */
    lsi->scripts[0x26] = __cpu_to_le32(0x10000000 | (PHASE_MI << 24));
    lsi->scripts[0x27] = __cpu_to_le32(LSI_TABLE_OFFSET(lsi->table->msg_in_len));
        
    /* 3.6 Interrupt */
    lsi->scripts[0x28] = __cpu_to_le32(0x98080000);
    lsi->scripts[0x29] = 0x0;

    /* 3.7 Wait reselect */    
    lsi->scripts[0x2a] = __cpu_to_le32(0x50000000);
    lsi->scripts[0x2b] = __cpu_to_le32(LSI_TABLE_OFFSET(lsi->table->id));

    /* 3.8 Message in */
    lsi->scripts[0x2c] = __cpu_to_le32(0x10000000 | (PHASE_MI << 24));
    lsi->scripts[0x2d] = __cpu_to_le32(LSI_TABLE_OFFSET(lsi->table->msg_in_len));
        
    /* 3.9 Data in */
    lsi->scripts[0x2e] = __cpu_to_le32(0x10000000 | (PHASE_DI << 24));
    lsi->scripts[0x2f] = __cpu_to_le32(LSI_TABLE_OFFSET(lsi->table->data_in_len));
    
    /* 3.10 Wait disconnect */
    lsi->scripts[0x30] = __cpu_to_le32(0x48000000);
    lsi->scripts[0x31] = __cpu_to_le32(LSI_TABLE_OFFSET(lsi->table->id));

    /* 3.11 Interrupt */
    lsi->scripts[0x32] = __cpu_to_le32(0x98080000);
    lsi->scripts[0x33] = 0x0;
}

static void
init_table(lsi_private_t *lsi)
{
    uint32_t dsa;

    /* Initialise indirect table */
    lsi->table->msg_out_ptr = __cpu_to_le32((uintptr_t)&lsi->buffer_iova[LSI_TABLE_MSG_OUT_OFFSET]);
    lsi->table->cmd_ptr = __cpu_to_le32((uintptr_t)&lsi->buffer_iova[LSI_TABLE_CMD_OFFSET]);
    lsi->table->data_in_ptr = __cpu_to_le32((uintptr_t)&lsi->buffer_iova[LSI_TABLE_DATA_OFFSET]);
    lsi->table->status_ptr = __cpu_to_le32((uintptr_t)&lsi->buffer_iova[LSI_TABLE_STATUS_OFFSET]);
    lsi->table->msg_in_ptr = __cpu_to_le32((uintptr_t)&lsi->buffer_iova[LSI_TABLE_MSG_IN_OFFSET]);
    
    /* Set the DSA to point to the base of our data table */
    dsa = (uintptr_t)lsi->table_iova;
    lsi->mmio[LSI_DSA] = dsa & 0xff;
    lsi->mmio[LSI_DSA + 1] = (dsa >> 8) & 0xff;
    lsi->mmio[LSI_DSA + 2] = (dsa >> 16) & 0xff;
    lsi->mmio[LSI_DSA + 3] = (dsa >> 24) & 0xff;
}

static unsigned int
lsi_interrupt_status(lsi_private_t *lsi)
{
    uint32_t istat, sist0, sist1, dstat;
    
    /* Wait for interrupt status */
    while ((istat = lsi->mmio[LSI_ISTAT0]) == 0);

    if (istat & LSI_ISTAT0_SIP) {
        /* If SCSI interrupt, clear SCSI interrupt registers */
        sist0 = lsi->mmio[LSI_SIST0];
        sist1 = lsi->mmio[LSI_SIST1];
        
        if (sist0 != 0 || sist1 != 0) {
            return 1;
        }
    }
    
    if (istat & LSI_ISTAT0_DIP) {
        /* If DMA interrupt, clear DMA interrupt register */
        dstat = lsi->mmio[LSI_DSTAT];
        
        if ((dstat & 0x7f) != 0x4) {
            return 1;
        }
    }
    
    return 0;
}

static unsigned int
inquiry(lsi_private_t *lsi, sd_private_t *sd)
{
    const char *media[2] = { "UNKNOWN", "UNKNOWN"};
    uint8_t *buffer;

    // Setup command = Inquiry
    memset((uint8_t *)&lsi->buffer[LSI_TABLE_CMD_OFFSET], 0, 7);
    lsi->buffer[LSI_TABLE_MSG_OUT_OFFSET] = 0x80;
    lsi->table->msg_out_len = __cpu_to_le32(0x1);
    
    lsi->buffer[LSI_TABLE_CMD_OFFSET] = INQUIRY;
    lsi->table->cmd_len = __cpu_to_le32(0x6);
    
    lsi->buffer[LSI_TABLE_CMD_OFFSET + 4] = 36;
    lsi->table->data_in_len = __cpu_to_le32(36);

    lsi->table->status_len = __cpu_to_le32(0x1);
    lsi->table->msg_in_len = __cpu_to_le32(0x1);
    
    lsi->table->id = __cpu_to_le32((sd->id << 16));
    lsi->table->id_addr = __cpu_to_le32(&lsi->scripts_iova[0x2]);
    
    /* Write DSP to start DMA engine */    
    uint32_t dsp = (uintptr_t)lsi->scripts_iova;
    lsi->mmio[LSI_DSP] = dsp & 0xff;
    lsi->mmio[LSI_DSP + 1] = (dsp >> 8) & 0xff;
    lsi->mmio[LSI_DSP + 2] = (dsp >> 16) & 0xff;
    lsi->mmio[LSI_DSP + 3] = (dsp >> 24) & 0xff;
    
    if (lsi_interrupt_status(lsi)) {
        sd->present = 0;
        sd->media = -1;
        return 0;
    }

    buffer = (uint8_t *)&lsi->buffer[LSI_TABLE_DATA_OFFSET];
    sd->present = 1;
    sd->media = buffer[0];

    switch (sd->media) {
    case TYPE_DISK:
        media[0] = "disk";
        media[1] = "hd";
        break;
    case TYPE_ROM:
        media[0] = "cdrom";
        media[1] = "cd";
        break;
    }
    sd->media_str[0] = media[0];
    sd->media_str[1] = media[1];
    memcpy(sd->model, &buffer[16], 16);
    sd->model[17] = '\0';

    return 1;
}

static unsigned int
read_capacity(lsi_private_t *lsi, sd_private_t *sd)
{
    uint8_t *buffer;
    
    // Setup command = Read Capacity    
    memset((uint8_t *)&lsi->buffer[LSI_TABLE_CMD_OFFSET], 0, 11);
    lsi->buffer[LSI_TABLE_MSG_OUT_OFFSET] = 0x80;
    lsi->table->msg_out_len = __cpu_to_le32(0x1);
    
    lsi->buffer[LSI_TABLE_CMD_OFFSET] = READ_CAPACITY;
    lsi->table->cmd_len = __cpu_to_le32(0x11);
    
    lsi->table->data_in_len = __cpu_to_le32(0x8);

    lsi->table->status_len = __cpu_to_le32(0x1);
    lsi->table->msg_in_len = __cpu_to_le32(0x1);
    
    lsi->table->id = __cpu_to_le32((sd->id << 16));
    lsi->table->id_addr = __cpu_to_le32(&lsi->scripts_iova[0x2]);
    
    /* Write DSP to start DMA engine */    
    uint32_t dsp = (uintptr_t)lsi->scripts_iova;
    lsi->mmio[LSI_DSP] = dsp & 0xff;
    lsi->mmio[LSI_DSP + 1] = (dsp >> 8) & 0xff;
    lsi->mmio[LSI_DSP + 2] = (dsp >> 16) & 0xff;
    lsi->mmio[LSI_DSP + 3] = (dsp >> 24) & 0xff;

    if (lsi_interrupt_status(lsi)) {
        sd->sectors = 0;
        sd->bs = 0;
        DPRINTF("read_capacity id %d failed\n", sd->id);
        return 0;
    }
    
    buffer = (uint8_t *)&lsi->buffer[LSI_TABLE_DATA_OFFSET];
    sd->bs = (buffer[4] << 24) | (buffer[5] << 16) | (buffer[6] << 8) | buffer[7];
    sd->sectors = ((buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | buffer[3]) * (sd->bs / 512);

    DPRINTF("read_capacity id %d bs %d sectors %d\n", sd->id, sd->bs,
            sd->sectors);
    return 1;
}

static unsigned int
test_unit_ready(lsi_private_t *lsi, sd_private_t *sd)
{
    /* Setup command = Test Unit Ready */
    memset((uint8_t *)&lsi->buffer[LSI_TABLE_CMD_OFFSET], 0, 7);
    lsi->buffer[LSI_TABLE_MSG_OUT_OFFSET] = 0x80;
    lsi->table->msg_out_len = __cpu_to_le32(0x1);
    
    lsi->buffer[LSI_TABLE_CMD_OFFSET] = TEST_UNIT_READY;
    lsi->table->cmd_len = __cpu_to_le32(0x6);

    lsi->table->status_len = __cpu_to_le32(0x1);
    lsi->table->msg_in_len = __cpu_to_le32(0x1);

    lsi->table->id = __cpu_to_le32((sd->id << 16));
    lsi->table->id_addr = __cpu_to_le32(&lsi->scripts_iova[0x12]);

    /* Write DSP to start DMA engine */    
    uint32_t dsp = (uintptr_t)&lsi->scripts_iova[0x10];
    lsi->mmio[LSI_DSP] = dsp & 0xff;
    lsi->mmio[LSI_DSP + 1] = (dsp >> 8) & 0xff;
    lsi->mmio[LSI_DSP + 2] = (dsp >> 16) & 0xff;
    lsi->mmio[LSI_DSP + 3] = (dsp >> 24) & 0xff;

    if (lsi_interrupt_status(lsi)) {
        DPRINTF("test_unit_ready id %d failed\n", sd->id);
        return 0;
    }

    DPRINTF("test_unit_ready id %d success\n", sd->id);
    return 1;
}

static void
ob_lsi_dma_alloc(__attribute__((unused)) lsi_private_t **lsi)
{
    call_parent_method("dma-alloc");
}

static void
ob_lsi_dma_free(__attribute__((unused)) lsi_private_t **lsi)
{
    call_parent_method("dma-free");
}

static void
ob_lsi_dma_map_in(__attribute__((unused)) lsi_private_t **lsi)
{
    call_parent_method("dma-map-in");
}

static void
ob_lsi_dma_map_out(__attribute__((unused)) lsi_private_t **lsi)
{
    call_parent_method("dma-map-out");
}

static void
ob_lsi_dma_sync(__attribute__((unused)) lsi_private_t **lsi)
{
    call_parent_method("dma-sync");
}

// offset is in sectors
static int
ob_sd_read_sector(lsi_private_t *lsi, sd_private_t *sd, int offset)
{
    uint32_t dsp;

    DPRINTF("ob_sd_read_sector id %d sector=%d\n",
            sd->id, offset);

    // Setup command = Read(10)
    memset((uint8_t *)&lsi->buffer[LSI_TABLE_CMD_OFFSET], 0, 10);
    lsi->buffer[LSI_TABLE_MSG_OUT_OFFSET] = 0x80;
    lsi->table->msg_out_len = __cpu_to_le32(0x1);
    
    lsi->buffer[LSI_TABLE_CMD_OFFSET] = READ_10;    
    lsi->buffer[LSI_TABLE_CMD_OFFSET + 2] = (offset >> 24) & 0xff;
    lsi->buffer[LSI_TABLE_CMD_OFFSET + 3] = (offset >> 16) & 0xff;;    
    lsi->buffer[LSI_TABLE_CMD_OFFSET + 4] = (offset >> 8) & 0xff;
    lsi->buffer[LSI_TABLE_CMD_OFFSET + 5] = offset & 0xff;
    lsi->buffer[LSI_TABLE_CMD_OFFSET + 7] = 0;
    lsi->buffer[LSI_TABLE_CMD_OFFSET + 8] = 1;
    lsi->table->cmd_len = __cpu_to_le32(0xa);

    lsi->table->data_in_len = __cpu_to_le32(sd->bs);

    lsi->table->status_len = __cpu_to_le32(0x1);
    lsi->table->msg_in_len = __cpu_to_le32(0x2);
    
    lsi->table->id = __cpu_to_le32((sd->id << 16));
    lsi->table->id_addr = __cpu_to_le32(&lsi->scripts_iova[0x22]);
    
    /* Write DSP to start DMA engine */    
    dsp = (uintptr_t)&lsi->scripts_iova[0x20];
    lsi->mmio[LSI_DSP] = dsp & 0xff;
    lsi->mmio[LSI_DSP + 1] = (dsp >> 8) & 0xff;
    lsi->mmio[LSI_DSP + 2] = (dsp >> 16) & 0xff;
    lsi->mmio[LSI_DSP + 3] = (dsp >> 24) & 0xff;
    
    if (lsi_interrupt_status(lsi)) {
        return 1;
    }

    // Reslect and data transfer
    lsi->table->msg_in_len = __cpu_to_le32(0x1);

    lsi->table->data_in_len = __cpu_to_le32(sd->bs);
    
    /* Write DSP to start DMA engine */    
    dsp = (uintptr_t)&lsi->scripts_iova[0x2a];
    lsi->mmio[LSI_DSP] = dsp & 0xff;
    lsi->mmio[LSI_DSP + 1] = (dsp >> 8) & 0xff;
    lsi->mmio[LSI_DSP + 2] = (dsp >> 16) & 0xff;
    lsi->mmio[LSI_DSP + 3] = (dsp >> 24) & 0xff;

    if (lsi_interrupt_status(lsi)) {
        return 1;
    }

    return 0;
}

static void
ob_sd_read_blocks(sd_private_t **sd)
{
    cell n = POP(), cnt = n;
    ucell blk = POP();
    char *dest = (char*)POP();
    int pos, spb, sect_offset;
    lsi_private_t *lsi = (*sd)->lsi;

    DPRINTF("ob_sd_read_blocks id %d %lx block=%d n=%d\n", (*sd)->id, (unsigned long)dest, blk, n );

    if ((*sd)->bs == 0) {
        PUSH(0);
        return;
    }
    spb = (*sd)->bs / 512;
    while (n) {
        sect_offset = blk / spb;
        pos = (blk - sect_offset * spb) * 512;

        if (ob_sd_read_sector(lsi, *sd, sect_offset)) {
            DPRINTF("ob_sd_read_blocks: error\n");
            RET(0);
        }
        while (n && pos < spb * 512) {
            memcpy(dest, (uint8_t *)&lsi->buffer[LSI_TABLE_DATA_OFFSET] + pos, 512);
            pos += 512;
            dest += 512;
            n--;
            blk++;
        }
    }
    PUSH(cnt);
}

static void
ob_sd_block_size(__attribute__((unused))sd_private_t **sd)
{
    PUSH(512);
}

static void
ob_sd_open(__attribute__((unused))sd_private_t **sd)
{
    int ret = 1;
    phandle_t ph;

    PUSH(find_ih_method("sd-private", my_self()));
    fword("execute");
    *sd = cell2pointer(POP());

#ifdef CONFIG_DEBUG_LSI
    {
        char *args;

        fword("my-args");
        args = pop_fstr_copy();
        DPRINTF("opening drive args %s\n", args);
        free(args);
    }
#endif

    selfword("open-deblocker");

    /* interpose disk-label */
    ph = find_dev("/packages/disk-label");
    fword("my-args");
    PUSH_ph( ph );
    fword("interpose");

    RET ( -ret );
}

static void
ob_sd_close(__attribute__((unused)) sd_private_t **sd)
{
    selfword("close-deblocker");
}

NODE_METHODS(ob_sd) = {
    { "open",           ob_sd_open },
    { "close",          ob_sd_close },
    { "read-blocks",    ob_sd_read_blocks },
    { "block-size",     ob_sd_block_size },
};

static void
ob_lsi_decodeunit(__attribute__((unused)) lsi_private_t **lsi_p)
{
    /* ( str len -- id ) */
    fword("parse-hex");
}

static void
ob_lsi_encodeunit(__attribute__((unused)) lsi_private_t **lsi_p)
{
    /* ( id -- str len ) */
    fword("pocket");
    fword("tohexstr");
}

static void
ob_lsi_open(__attribute__((unused)) lsi_private_t **lsi_p)
{
    PUSH(-1);
}

static void
ob_lsi_close(__attribute__((unused)) lsi_private_t **lsi_p)
{
    return;
}

NODE_METHODS(ob_lsi) = {
    { "open"       ,    ob_lsi_open },
    { "close"      ,    ob_lsi_close },
    { "decode-unit",    ob_lsi_decodeunit },
    { "encode-unit",    ob_lsi_encodeunit },
    { "dma-alloc",      ob_lsi_dma_alloc   },
    { "dma-free",       ob_lsi_dma_free    },
    { "dma-map-in",     ob_lsi_dma_map_in  },
    { "dma-map-out",    ob_lsi_dma_map_out },
    { "dma-sync",       ob_lsi_dma_sync    },
};

static void
add_alias(const char *device, const char *alias)
{
    phandle_t aliases;

    DPRINTF("add_alias dev \"%s\" = alias \"%s\"\n", device, alias);

    aliases = find_dev("/aliases");
    set_property(aliases, alias, device, strlen(device) + 1);
}

int
ob_lsi_init(const char *path, uint64_t mmio, uint64_t ram)
{
    int id, diskcount = 0, cdcount = 0, *counter_ptr;
    char nodebuff[256], aliasbuff[256];
    phandle_t ph = get_cur_dev();
    lsi_private_t *lsi;
    int i;
    ucell addr;

    BIND_NODE_METHODS(ph, ob_lsi);

    lsi = malloc(sizeof(lsi_private_t));
    if (!lsi) {
        DPRINTF("Can't allocate LSI private structure\n");
        return -1;
    }

    /* Buffer for commands */
    PUSH(0x1000);
    feval("dma-alloc");
    addr = POP();
    lsi->buffer = cell2pointer(addr);

    PUSH(addr);
    PUSH(0x1000);
    PUSH(0);
    feval("dma-map-in");
    addr = POP();
    lsi->buffer_iova = cell2pointer(addr);

    PUSH(0x40 * sizeof(uint32_t));
    feval("dma-alloc");
    addr = POP();
    lsi->scripts = cell2pointer(addr);

    PUSH(addr);
    PUSH(0x40 * sizeof(uint32_t));
    PUSH(0);
    feval("dma-map-in");
    addr = POP();
    lsi->scripts_iova = cell2pointer(addr);

    PUSH(sizeof(lsi_table_t));
    feval("dma-alloc");
    addr = POP();
    lsi->table = cell2pointer(addr);

    PUSH(addr);
    PUSH(sizeof(lsi_table_t));
    PUSH(0);
    feval("dma-map-in");
    addr = POP();
    lsi->table_iova = cell2pointer(addr);

    set_int_property(ph, "#address-cells", 1);
    set_int_property(ph, "#size-cells", 0);

    /* Initialise SCRIPTS */
    lsi->mmio = (uint8_t *)(uint32_t)mmio;
    init_scripts(lsi);
    init_table(lsi);

    /* Scan the SCSI bus */
    for (id = 0; id < 8; id++) {
        lsi->sd[id].id = id;
        if (!inquiry(lsi, &lsi->sd[id])) {
            DPRINTF("Unit %d not present\n", id);
            continue;
        }
        
        /* Clear Unit Attention condition from reset */
        for (i = 0; i < 5; i++) {
            if (test_unit_ready(lsi, &lsi->sd[id])) {
                break;
            }
        }
        if (i == 5) {
            DPRINTF("Unit %d present but won't become ready\n", id);
            continue;
        }
        DPRINTF("Unit %d present\n", id);
        read_capacity(lsi, &lsi->sd[id]);

#ifdef CONFIG_DEBUG_LSI
        dump_drive(&lsi->sd[id]);
#endif
    }

    for (id = 0; id < 8; id++) {
        if (!lsi->sd[id].present)
            continue;

        lsi->sd[id].lsi = lsi;

        fword("new-device");
        push_str("sd");
        fword("device-name");
        push_str("block");
        fword("device-type");
        fword("is-deblocker");
        PUSH(id);
        fword("encode-int");
        PUSH(0);
        fword("encode-int");
        fword("encode+");
        push_str("reg");
        fword("property");

        PUSH(pointer2cell(&lsi->sd[id]));
        feval("value sd-private");

        BIND_NODE_METHODS(get_cur_dev(), ob_sd);
        fword("finish-device");

        snprintf(nodebuff, sizeof(nodebuff), "%s/sd@%d",
                 get_path_from_ph(ph), id);

        if (lsi->sd[id].media == TYPE_ROM) {
            counter_ptr = &cdcount;
        } else {
            counter_ptr = &diskcount;
        }
        if (*counter_ptr == 0) {
            add_alias(nodebuff, lsi->sd[id].media_str[0]);
            add_alias(nodebuff, lsi->sd[id].media_str[1]);
        }
        snprintf(aliasbuff, sizeof(aliasbuff), "%s%d",
                 lsi->sd[id].media_str[0], *counter_ptr);
        add_alias(nodebuff, aliasbuff);
        snprintf(aliasbuff, sizeof(aliasbuff), "%s%d",
                 lsi->sd[id].media_str[1], *counter_ptr);
        add_alias(nodebuff, aliasbuff);
    }

    return 0;
}
