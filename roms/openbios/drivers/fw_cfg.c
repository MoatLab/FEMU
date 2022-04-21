#include "config.h"
#include "libopenbios/bindings.h"
#include "libc/byteorder.h"
#include "libopenbios/ofmem.h"
#define NO_QEMU_PROTOS
#include "arch/common/fw_cfg.h"

#if !defined(CONFIG_SPARC64)
static volatile uint16_t *fw_cfg_cmd;
static volatile uint8_t *fw_cfg_data;

static void
fw_cfg_read_bytes(char *buf, unsigned int nbytes)
{
    unsigned int i;

    for (i = 0; i < nbytes; i++)
        buf[i] = *fw_cfg_data;
}

void
fw_cfg_read(uint16_t cmd, char *buf, unsigned int nbytes)
{
    *fw_cfg_cmd = cmd;
    fw_cfg_read_bytes(buf, nbytes);
}
#else
// XXX depends on PCI bus location, should be removed
static void
fw_cfg_read_bytes(char *buf, unsigned int nbytes)
{
    unsigned int i;

    for (i = 0; i < nbytes; i++)
        buf[i] = inb(CONFIG_FW_CFG_ADDR + 1);
}

void
fw_cfg_read(uint16_t cmd, char *buf, unsigned int nbytes)
{
    outw(cmd, CONFIG_FW_CFG_ADDR);
    fw_cfg_read_bytes(buf, nbytes);
}
#endif

uint64_t
fw_cfg_read_i64(uint16_t cmd)
{
    uint64_t buf;

    fw_cfg_read(cmd, (char *)&buf, sizeof(uint64_t));

    return __le64_to_cpu(buf);
}

uint32_t
fw_cfg_read_i32(uint16_t cmd)
{
    uint32_t buf;

    fw_cfg_read(cmd, (char *)&buf, sizeof(uint32_t));

    return __le32_to_cpu(buf);
}

uint16_t
fw_cfg_read_i16(uint16_t cmd)
{
    uint16_t buf;

    fw_cfg_read(cmd, (char *)&buf, sizeof(uint16_t));

    return __le16_to_cpu(buf);
}

uint32_t
fw_cfg_find_file(const char *filename, uint16_t *select, uint32_t *size)
{
    FWCfgFile f;
    unsigned int i;
    uint32_t buf, count;

    /* Unusually all FW_CFG_FILE_DIR fields are BE */
    fw_cfg_read(FW_CFG_FILE_DIR, (char *)&buf, sizeof(uint32_t));
    count = __be32_to_cpu(buf);

    for (i = 0; i < count; i++) {
        fw_cfg_read_bytes((char *)&f, sizeof(f));

        if (!strcmp(f.name, filename)) {
            *select = __be16_to_cpu(f.select);
            *size = __be32_to_cpu(f.size);

            return -1;
        }
    }

    return 0;
}

char *
fw_cfg_read_file(const char *filename, uint32_t *size)
{
    uint16_t cmd;
    uint32_t nbytes;
    char *buf;

    if (fw_cfg_find_file(filename, &cmd, &nbytes)) {
        buf = malloc(nbytes);
        fw_cfg_read(cmd, buf, nbytes);
        *size = nbytes;
        return buf;
    }

    return NULL;
}

//
// ( fname fnamelen -- buf buflen -1 | 0 )
//

void
forth_fw_cfg_read_file(void)
{
    char *filename = pop_fstr_copy();
    char *buffer;
    uint32_t size;

    buffer = fw_cfg_read_file(filename, &size);
    if (buffer) {
        PUSH(pointer2cell(buffer));
        PUSH(size);
        PUSH(-1);

        return;
    }

    PUSH(0);
}

void
fw_cfg_init(void)
{
#if defined(CONFIG_SPARC32)
    fw_cfg_cmd = (void *)ofmem_map_io(CONFIG_FW_CFG_ADDR, 2);
    fw_cfg_data = (uint8_t *)fw_cfg_cmd + 2;
#elif defined(CONFIG_SPARC64)
    // Nothing for the port version
#elif defined(CONFIG_PPC)
    fw_cfg_cmd = (void *)CONFIG_FW_CFG_ADDR;
    fw_cfg_data = (void *)(CONFIG_FW_CFG_ADDR + 2);
#endif
}
