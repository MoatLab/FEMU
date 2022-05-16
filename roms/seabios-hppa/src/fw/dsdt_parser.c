// Support for parsing dsdt acpi tables
//
// Copyright (C) 2008,2009  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "config.h" // CONFIG_*
#include "list.h"   // hlist_*
#include "malloc.h" // malloc_*
#include "output.h" // dprintf
#include "string.h" // memcpy
#include "util.h"
#include "std/acpi.h" // struct rsdp_descriptor

/****************************************************************
 * DSDT parser
 ****************************************************************/

struct acpi_device {
    struct hlist_node node;
    char name[16];
    u8 *hid_aml;
    u8 *sta_aml;
    u8 *crs_data;
    int crs_size;
};
static struct hlist_head acpi_devices VARVERIFY32INIT;
static const int parse_dumpdevs = 0;

struct parse_state {
    char name[32];
    struct acpi_device *dev;
    int error;
    int depth;
};

static void parse_termlist(struct parse_state *s,
                           u8 *ptr, int offset, int pkglength);

static void hex(const u8 *ptr, int count, int lvl, const char *item)
{
    int l = 0, i;

    do {
        dprintf(lvl, "%s: %04x:  ", item, l);
        for (i = l; i < l+16; i += 4)
            dprintf(lvl, "%02x %02x %02x %02x  ",
                    ptr[i+0], ptr[i+1], ptr[i+2], ptr[i+3]);
        for (i = l; i < l+16; i++)
            dprintf(lvl, "%c", (ptr[i] > 0x20 && ptr[i] < 0x80)
                    ? ptr[i] : '.');
        dprintf(lvl, "\n");
        l += 16;
    } while (l < count);
}

static u64 parse_resource_int(u8 *ptr, int count)
{
    u64 value = 0;
    int index = 0;

    for (index = 0; index < count; index++)
        value |= (u64)ptr[index] << (index * 8);
    return value;
}

static int parse_resource_bit(u8 *ptr, int count)
{
    int bit;

    for (bit = 0; bit < count*8; bit++)
        if (ptr[bit/8] & (1 << (bit%8)))
            return bit;
    return 0;
}

static int parse_resource(u8 *ptr, int length, int *type, u64 *min, u64 *max)
{
    int rname, rsize;
    u64 len;

    *type = -1;
    *min = 0;
    *max = 0;
    len = 0;
    if (!(ptr[0] & 0x80)) {
        /* small resource */
        rname = (ptr[0] >> 3) & 0x0f;
        rsize = ptr[0] & 0x07;
        rsize++;
        switch (rname) {
        case 0x04: /* irq */
            *min = parse_resource_bit(ptr + 1, rsize);
            *max = *min;
            *type = 3;
            break;
        case 0x0f: /* end marker */
            return 0;
        case 0x08: /* io */
            *min = parse_resource_int(ptr + 2, 2);
            *max = parse_resource_int(ptr + 4, 2);
            if (*min == *max) {
                *max = *min + ptr[7] - 1;
                *type = 1;
            }
            break;
        case 0x09: /* fixed io */
            *min = parse_resource_int(ptr + 2, 2);
            *max = *min + ptr[4] - 1;
            *type = 1;
            break;
        default:
            dprintf(3, "%s: small: 0x%x (len %d)\n",
                    __func__, rname, rsize);
            break;
        }
    } else {
        /* large resource */
        rname = ptr[0] & 0x7f;
        rsize = ptr[2] << 8 | ptr[1];
        rsize += 3;
        switch (rname) {
        case 0x06: /* 32-bit Fixed Location Memory Range Descriptor */
            *min = parse_resource_int(ptr + 4, 4);
            len = parse_resource_int(ptr + 8, 4);
            *max = *min + len - 1;
            *type = 0;
            break;
        case 0x07: /* DWORD Address Space Descriptor */
            *min = parse_resource_int(ptr + 10, 4);
            *max = parse_resource_int(ptr + 14, 4);
            *type = ptr[3];
            break;
        case 0x08: /* WORD Address Space Descriptor */
            *min = parse_resource_int(ptr +  8, 2);
            *max = parse_resource_int(ptr + 10, 2);
            *type = ptr[3];
            break;
        case 0x09: /* irq */
            *min = parse_resource_int(ptr +  5, 4);
            *max = *min;
            *type = 3;
            break;
        case 0x0a: /* QWORD Address Space Descriptor */
            *min = parse_resource_int(ptr + 14, 8);
            *max = parse_resource_int(ptr + 22, 8);
            *type = ptr[3];
            break;
        default:
            dprintf(3, "%s: large: 0x%x (len %d)\n", __func__, rname, rsize);
            break;
        }
    }
    return rsize;
}

static int find_resource(u8 *ptr, int len, int kind, u64 *min, u64 *max)
{
    int type, size, offset = 0;

    do {
        size = parse_resource(ptr + offset, len - offset,
                              &type, min, max);
        if (kind == type)
            return 0;
        offset += size;
    } while (size > 0 && offset < len);
    return -1;
}

static int print_resources(const char *prefix, u8 *ptr, int len)
{
    static const char *typename[] = { "mem", "i/o", "bus" };
    int type, size, offset = 0;
    u64 min, max;

    do {
        size = parse_resource(ptr + offset, len - offset,
                              &type, &min, &max);
        switch (type) {
        case 0:
        case 1:
        case 2:
            dprintf(1, "%s%s 0x%llx -> 0x%llx\n",
                    prefix, typename[type], min, max);
            break;
        case 3:
            dprintf(1, "%sirq %lld\n", prefix, min);
            break;
        }
        offset += size;
    } while (size > 0 && offset < len);
    return -1;
}

static int parse_nameseg(u8 *ptr, char **dst)
{
    if (dst && *dst) {
        *(dst[0]++) = ptr[0];
        if (ptr[1] != '_')
            *(dst[0]++) = ptr[1];
        if (ptr[2] != '_')
            *(dst[0]++) = ptr[2];
        if (ptr[3] != '_')
            *(dst[0]++) = ptr[3];
        *(dst[0]) = 0;
    }
    return 4;
}

static int parse_namestring(struct parse_state *s,
                            u8 *ptr, const char *item)
{
    char *dst = s->name;
    int offset = 0;
    int i, count;

    for (;;) {
        switch (ptr[offset]) {
        case 0: /* null name */
            offset++;
            *(dst++) = 0;
            break;
        case 0x2e:
            offset++;
            offset += parse_nameseg(ptr + offset, &dst);
            *(dst++) = '.';
            offset += parse_nameseg(ptr + offset, &dst);
            break;
        case 0x2f:
            offset++;
            count = ptr[offset];
            offset++;
            for (i = 0; i < count; i++) {
                if (i)
                    *(dst++) = '.';
                offset += parse_nameseg(ptr + offset, &dst);
            }
            break;
        case '\\':
            *(dst++) = '\\';
            offset++;
            continue;
        case '^':
            *(dst++) = '^';
            offset++;
            continue;
        case 'A' ... 'Z':
        case '_':
            offset += parse_nameseg(ptr, &dst);
            break;
        default:
            hex(ptr, 16, 3, __func__);
            s->error = 1;
            break;
        }
        break;
    }
    dprintf(5, "%s: %d %s '%s'\n", __func__, s->depth,
            item, s->name);
    return offset;
}

static int parse_termarg_int(u8 *ptr, int *error, u64 *dst)
{
    u64 value;
    int offset = 1;

    switch (ptr[0]) {
    case 0x00: /* zero */
        value = 0;
        break;
    case 0x01: /* one */
        value = 1;
        break;
    case 0x0a: /* byte prefix */
        value = ptr[1];
        offset++;
        break;
    case 0x0b: /* word prefix */
        value = ptr[1] |
            ((unsigned long)ptr[2] << 8);
        offset += 2;
        break;
    case 0x0c: /* dword prefix */
        value = ptr[1] |
            ((unsigned long)ptr[2] << 8) |
            ((unsigned long)ptr[3] << 16) |
            ((unsigned long)ptr[4] << 24);
        offset += 4;
        break;
    default:
        value = 0;
        hex(ptr, 16, 3, __func__);
        if (error)
            *error = 1;
        break;
    }

    if (dst)
        *dst = value;
    dprintf(5, "%s: 0x%llx\n", __func__, value);
    return offset;
}

static int parse_pkglength(u8 *ptr, int *pkglength)
{
    int offset = 2;

    *pkglength = 0;
    switch (ptr[0] >> 6) {
    case 3:
        *pkglength |= ptr[3] << 20;
        offset++;
    case 2:
        *pkglength |= ptr[2] << 12;
        offset++;
    case 1:
        *pkglength |= ptr[1] << 4;
        *pkglength |= ptr[0] & 0x0f;
        return offset;
    case 0:
    default:
        *pkglength |= ptr[0] & 0x3f;
        return 1;
    }
}

static int parse_pkg_common(struct parse_state *s,
                            u8 *ptr, const char *item, int *pkglength)
{
    int offset;

    offset = parse_pkglength(ptr, pkglength);
    offset += parse_namestring(s, ptr + offset, item);
    return offset;
}

static int parse_pkg_scope(struct parse_state *s,
                           u8 *ptr)
{
    int offset, pkglength;

    offset = parse_pkg_common(s, ptr, "scope", &pkglength);
    parse_termlist(s, ptr, offset, pkglength);
    return pkglength;
}

static int parse_pkg_device(struct parse_state *s,
                            u8 *ptr)
{
    int offset, pkglength;

    offset = parse_pkg_common(s, ptr, "device", &pkglength);

    s->dev = malloc_tmp(sizeof(struct acpi_device));
    if (!s->dev) {
        warn_noalloc();
        s->error = 1;
        return pkglength;
    }

    memset(s->dev, 0, sizeof(struct acpi_device));
    hlist_add_head(&s->dev->node, &acpi_devices);
    strtcpy(s->dev->name, s->name, sizeof(s->name));
    parse_termlist(s, ptr, offset, pkglength);
    s->dev = NULL;

    return pkglength;
}

static int parse_pkg_buffer(struct parse_state *s,
                            u8 *ptr)
{
    u64 blen;
    int pkglength, offset;

    offset = parse_pkglength(ptr, &pkglength);
    offset += parse_termarg_int(ptr + offset, &s->error, &blen);
    if (s->dev && strcmp(s->name, "_CRS") == 0) {
        s->dev->crs_data = ptr + offset;
        s->dev->crs_size = blen;
    }
    return pkglength;
}

static int parse_pkg_skip(struct parse_state *s,
                          u8 *ptr, int op, int name)
{
    int pkglength, offset;
    char item[8];

    snprintf(item, sizeof(item), "op %x", op);
    offset = parse_pkglength(ptr, &pkglength);
    if (name) {
        parse_namestring(s, ptr + offset, item);
    } else {
        dprintf(5, "%s: %s (%d)\n", __func__, item, pkglength);
    }
    return pkglength;
}

static int parse_termobj(struct parse_state *s,
                         u8 *ptr)
{
    int offset = 1;

    if (s->depth == 16) {
        dprintf(1, "%s: deep recursion\n", __func__);
        s->error = 1;
        return offset;
    }

    s->depth++;
    switch (ptr[0]) {
    case 0x00: /* zero */
        break;
    case 0x01: /* one */
        break;
    case 0x08: /* name op */
        offset += parse_namestring(s, ptr + offset, "name");
        offset += parse_termobj(s, ptr + offset);
        if (s->dev && strcmp(s->name, "_HID") == 0)
            s->dev->hid_aml = ptr;
        if (s->dev && strcmp(s->name, "_STA") == 0)
            s->dev->sta_aml = ptr;
        break;
    case 0x0a: /* byte prefix */
        offset++;
        break;
    case 0x0b: /* word prefix */
        offset += 2;
        break;
    case 0x0c: /* dword prefix */
        offset += 4;
        break;
    case 0x0d: /* string prefix */
        while (ptr[offset])
            offset++;
        offset++;
        break;
    case 0x10: /* scope op */
        offset += parse_pkg_scope(s, ptr + offset);
        break;
    case 0x11: /* buffer op */
        offset += parse_pkg_buffer(s, ptr + offset);
        break;
    case 0x12: /* package op */
    case 0x13: /* var package op */
        offset += parse_pkg_skip(s, ptr + offset, ptr[0], 0);
        break;
    case 0x14: /* method op */
        offset += parse_pkg_skip(s, ptr + offset, ptr[0], 1);
        if (s->dev && strcmp(s->name, "_STA") == 0)
            s->dev->sta_aml = ptr;
        break;
    case 0x5b: /* ext op prefix */
        offset++;
        switch (ptr[1]) {
        case 0x01: /* mutex op */
            offset += parse_namestring(s, ptr + offset, "mutex");
            offset++; /* sync flags */
            break;
        case 0x80: /* op region op */
            offset += parse_namestring(s, ptr + offset, "op region");
            offset++; /* region space */
            offset += parse_termarg_int(ptr + offset, &s->error, NULL);
            offset += parse_termarg_int(ptr + offset, &s->error, NULL);
            break;
        case 0x81: /* field op */
        case 0x83: /* processor op */
        case 0x84: /* power resource op */
        case 0x85: /* thermal zone op */
            offset += parse_pkg_skip(s, ptr + offset, 0x5b00 | ptr[1], 1);
            break;
        case 0x82: /* device op */
            offset += parse_pkg_device(s, ptr + offset);
            break;
        default:
            hex(ptr, 16, 3, __func__);
            s->error = 1;
            break;
        }
        break;
    default:
        hex(ptr, 16, 3, __func__);
        s->error = 1;
        break;
    }
    s->depth--;

    return offset;
}

static void parse_termlist(struct parse_state *s,
                           u8 *ptr, int offset, int pkglength)
{
    for (;;) {
        offset += parse_termobj(s, ptr + offset);
        if (offset == pkglength)
            return;
        if (offset > pkglength) {
            dprintf(1, "%s: overrun: %d/%d\n", __func__,
                    offset, pkglength);
            s->error = 1;
            return;
        }
        if (s->error) {
            dprintf(1, "%s: parse error, skip from %d/%d\n", __func__,
                    offset, pkglength);
            s->error = 0;
            return;
        }
    }
}

static struct acpi_device *acpi_dsdt_find(struct acpi_device *prev,
                                          const u8 *aml1, int size1,
                                          const u8 *aml2, int size2)
{
    struct acpi_device *dev;
    struct hlist_node *node;

    if (!prev)
        node = acpi_devices.first;
    else
        node = prev->node.next;

    for (; node != NULL; node = dev->node.next) {
        dev = container_of(node, struct acpi_device, node);
        if (!aml1 && !aml2)
            return dev;
        if (!dev->hid_aml)
            continue;
        if (aml1 && memcmp(dev->hid_aml + 5, aml1, size1) == 0)
            return dev;
        if (aml2 && memcmp(dev->hid_aml + 5, aml2, size2) == 0)
            return dev;
    }
    return NULL;
}

static int acpi_dsdt_present(struct acpi_device *dev)
{
    if (!dev)
        return 0; /* no */
    if (!dev->sta_aml)
        return 1; /* yes */
    if (dev->sta_aml[0] == 0x14)
        return -1; /* unknown (can't evaluate method) */
    if (dev->sta_aml[0] == 0x08) {
        u64 value = 0;
        parse_termarg_int(dev->sta_aml + 5, NULL, &value);
        if (value == 0)
            return 0; /* no */
        else
            return 1; /* yes */
    }
    return -1; /* unknown (should not happen) */
}

/****************************************************************
 * DSDT parser, public interface
 ****************************************************************/

struct acpi_device *acpi_dsdt_find_string(struct acpi_device *prev,
                                          const char *hid)
{
    if (!CONFIG_ACPI_PARSE)
        return NULL;

    u8 aml[10];
    int len = snprintf((char*)aml, sizeof(aml), "\x0d%s", hid);
    return acpi_dsdt_find(prev, aml, len, NULL, 0);
}

struct acpi_device *acpi_dsdt_find_eisaid(struct acpi_device *prev, u16 eisaid)
{
    if (!CONFIG_ACPI_PARSE)
        return NULL;
    u8 aml1[] = {
        0x0c, 0x41, 0xd0,
        eisaid >> 8,
        eisaid & 0xff
    };
    u8 aml2[10];
    int len2 = snprintf((char*)aml2, sizeof(aml2), "\x0dPNP%04X", eisaid);
    return acpi_dsdt_find(prev, aml1, 5, aml2, len2);
}

char *acpi_dsdt_name(struct acpi_device *dev)
{
    if (!CONFIG_ACPI_PARSE || !dev)
        return NULL;
    return dev->name;
}

int acpi_dsdt_find_io(struct acpi_device *dev, u64 *min, u64 *max)
{
    if (!CONFIG_ACPI_PARSE || !dev || !dev->crs_data)
        return -1;
    return find_resource(dev->crs_data, dev->crs_size,
                         1 /* I/O */, min, max);
}

int acpi_dsdt_find_mem(struct acpi_device *dev, u64 *min, u64 *max)
{
    if (!CONFIG_ACPI_PARSE || !dev || !dev->crs_data)
        return -1;
    return find_resource(dev->crs_data, dev->crs_size,
                         0 /* mem */, min, max);
}

int acpi_dsdt_find_irq(struct acpi_device *dev, u64 *irq)
{
    u64 max;
    if (!CONFIG_ACPI_PARSE || !dev || !dev->crs_data)
        return -1;
    return find_resource(dev->crs_data, dev->crs_size,
                         3 /* irq */, irq, &max);
}

int acpi_dsdt_present_eisaid(u16 eisaid)
{
    if (!CONFIG_ACPI_PARSE)
        return -1; /* unknown */
    if (hlist_empty(&acpi_devices))
        return -1; /* unknown (no dsdt table) */

    struct acpi_device *dev = acpi_dsdt_find_eisaid(NULL, eisaid);
    return acpi_dsdt_present(dev);
}

void acpi_dsdt_parse(void)
{
    if (!CONFIG_ACPI_PARSE)
        return;

    struct fadt_descriptor_rev1 *fadt = find_acpi_table(FACP_SIGNATURE);
    if (!fadt)
        return;
    u8 *dsdt = (void*)(fadt->dsdt);
    if (!dsdt)
        return;

    u32 length = *(u32*)(dsdt + 4);
    u32 offset = 0x24;
    dprintf(1, "ACPI: parse DSDT at %p (len %d)\n", dsdt, length);

    struct parse_state s;
    memset(&s, 0, sizeof(s));
    parse_termlist(&s, dsdt, offset, length);

    if (!parse_dumpdevs)
        return;

    struct acpi_device *dev;
    dprintf(1, "ACPI: dumping dsdt devices\n");
    for (dev = acpi_dsdt_find(NULL, NULL, 0, NULL, 0);
         dev != NULL;
         dev = acpi_dsdt_find(dev, NULL, 0, NULL, 0)) {
        dprintf(1, "    %s", acpi_dsdt_name(dev));
        if (dev->hid_aml)
            dprintf(1, ", hid");
        if (dev->sta_aml)
            dprintf(1, ", sta (0x%x)", dev->sta_aml[0]);
        if (dev->crs_data)
            dprintf(1, ", crs");
        dprintf(1, "\n");
        if (dev->crs_data)
            print_resources("        ", dev->crs_data, dev->crs_size);
    }
}
