// Simple framebuffer vgabios for use with qemu ramfb device
//
// Copyright (C) 2019 Gerd Hoffmann <kraxel@redhat.com>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "biosvar.h" // GET_BDA
#include "output.h" // dprintf
#include "string.h" // memset16_far
#include "vgautil.h" // VBE_total_memory
#include "std/pmm.h" // struct pmmheader
#include "byteorder.h"
#include "fw/paravirt.h"

/* ---------------------------------------------------------------------- */
/* minimal qemu fc_cfg support bits, requires dma support                 */

#define QEMU_CFG_FILE_DIR               0x19

struct QemuCfgFile {
    u32  size;        /* file size */
    u16  select;      /* write this to 0x510 to read it */
    u16  reserved;
    char name[56];
};

static void
qemu_cfg_dma_transfer(void *address, u32 length, u32 control)
{
    QemuCfgDmaAccess access;

    if (length == 0) {
        return;
    }

    access.address = cpu_to_be64((u64)(u32)address);
    access.length = cpu_to_be32(length);
    access.control = cpu_to_be32(control);

    barrier();

    outl(cpu_to_be32((u32)&access), PORT_QEMU_CFG_DMA_ADDR_LOW);

    while(be32_to_cpu(access.control) & ~QEMU_CFG_DMA_CTL_ERROR)
        /* wait */;
}

static void
qemu_cfg_read(void *buf, int len)
{
    qemu_cfg_dma_transfer(buf, len, QEMU_CFG_DMA_CTL_READ);
}

static void
qemu_cfg_read_entry(void *buf, int e, int len)
{
    u32 control = (e << 16) | QEMU_CFG_DMA_CTL_SELECT
        | QEMU_CFG_DMA_CTL_READ;
    qemu_cfg_dma_transfer(buf, len, control);
}

static void
qemu_cfg_write_entry(void *buf, int e, int len)
{
    u32 control = (e << 16) | QEMU_CFG_DMA_CTL_SELECT
        | QEMU_CFG_DMA_CTL_WRITE;
    qemu_cfg_dma_transfer(buf, len, control);
}

static int
qemu_cfg_find_file(const char *filename)
{
    u32 count, e, select;

    qemu_cfg_read_entry(&count, QEMU_CFG_FILE_DIR, sizeof(count));
    count = be32_to_cpu(count);
    for (select = 0, e = 0; e < count; e++) {
        struct QemuCfgFile qfile;
        qemu_cfg_read(&qfile, sizeof(qfile));
        if (memcmp_far(GET_SEG(SS), qfile.name,
                       GET_SEG(CS), filename, 10) == 0)
            select = be16_to_cpu(qfile.select);
    }
    return select;
}

/* ---------------------------------------------------------------------- */

#define FRAMEBUFFER_WIDTH      1024
#define FRAMEBUFFER_HEIGHT     768
#define FRAMEBUFFER_BPP        4
#define FRAMEBUFFER_STRIDE     (FRAMEBUFFER_BPP * FRAMEBUFFER_WIDTH)
#define FRAMEBUFFER_SIZE       (FRAMEBUFFER_STRIDE * FRAMEBUFFER_HEIGHT)

struct QemuRAMFBCfg {
    u64 addr;
    u32 fourcc;
    u32 flags;
    u32 width;
    u32 height;
    u32 stride;
};

#define fourcc_code(a, b, c, d) ((u32)(a) | ((u32)(b) << 8) | \
                                 ((u32)(c) << 16) | ((u32)(d) << 24))

#define DRM_FORMAT_RGB565       fourcc_code('R', 'G', '1', '6') /* [15:0] R:G:B 5:6:5 little endian */
#define DRM_FORMAT_RGB888       fourcc_code('R', 'G', '2', '4') /* [23:0] R:G:B little endian */
#define DRM_FORMAT_XRGB8888     fourcc_code('X', 'R', '2', '4') /* [31:0] x:R:G:B 8:8:8:8 little endian */

static u32
allocate_framebuffer(void)
{
    u32 res = allocate_pmm(FRAMEBUFFER_SIZE, 1, 1);
    if (!res)
        return 0;
    dprintf(1, "ramfb: framebuffer allocated at %x\n", res);
    return res;
}

int
ramfb_setup(void)
{
    dprintf(1, "ramfb: init\n");

    if (GET_GLOBAL(HaveRunInit))
        return 0;

    u32 select = qemu_cfg_find_file("etc/ramfb");
    if (select == 0) {
        dprintf(1, "ramfb: fw_cfg (etc/ramfb) file not found\n");
        return -1;
    }

    dprintf(1, "ramfb: fw_cfg (etc/ramfb) file at slot 0x%x\n", select);
    u32 fb = allocate_framebuffer();
    if (!fb) {
        dprintf(1, "ramfb: allocating framebuffer failed\n");
        return -1;
    }

    u64 addr = fb;
    u8 bpp = FRAMEBUFFER_BPP * 8;
    u32 xlines = FRAMEBUFFER_WIDTH;
    u32 ylines = FRAMEBUFFER_HEIGHT;
    u32 linelength = FRAMEBUFFER_STRIDE;
    dprintf(1, "Found FB @ %llx %dx%d with %d bpp (%d stride)\n"
            , addr, xlines, ylines, bpp, linelength);

    if (!addr || addr > 0xffffffff
        || (bpp != 15 && bpp != 16 && bpp != 24 && bpp != 32)) {
        dprintf(1, "Unable to use FB\n");
        return -1;
    }

    cbvga_setup_modes(addr, bpp, xlines, ylines, linelength);

    struct QemuRAMFBCfg cfg = {
        .addr   = cpu_to_be64(fb),
        .fourcc = cpu_to_be32(DRM_FORMAT_XRGB8888),
        .flags  = cpu_to_be32(0),
        .width  = cpu_to_be32(FRAMEBUFFER_WIDTH),
        .height = cpu_to_be32(FRAMEBUFFER_HEIGHT),
        .stride = cpu_to_be32(FRAMEBUFFER_STRIDE),
    };
    qemu_cfg_write_entry(&cfg, select, sizeof(cfg));

    return 0;
}
