#include "romfile_loader.h"
#include "byteorder.h" // leXX_to_cpu/cpu_to_leXX
#include "util.h" // checksum
#include "string.h" // strcmp
#include "romfile.h" // struct romfile_s
#include "malloc.h" // Zone*, _malloc
#include "list.h" // struct hlist_node
#include "output.h" // warn_*
#include "paravirt.h" // qemu_cfg_write_file

struct romfile_loader_file {
    struct romfile_s *file;
    void *data;
};
struct romfile_loader_files {
    int nfiles;
    struct romfile_loader_file files[];
};

// Data structures for storing "write pointer" entries for possible replay
struct romfile_wr_pointer_entry {
    u64 pointer;
    u32 offset;
    u16 key;
    u8 ptr_size;
    struct hlist_node node;
};
static struct hlist_head romfile_pointer_list;

static struct romfile_loader_file *
romfile_loader_find(const char *name,
                    struct romfile_loader_files *files)
{
    int i;
    if (name[ROMFILE_LOADER_FILESZ - 1])
        return NULL;
    for (i = 0; i < files->nfiles; ++i)
        if (!strcmp(files->files[i].file->name, name))
            return &files->files[i];
    return NULL;
}

// Replay "write pointer" entries back to QEMU
void romfile_fw_cfg_resume(void)
{
    if (!CONFIG_QEMU)
        return;

    struct romfile_wr_pointer_entry *entry;
    hlist_for_each_entry(entry, &romfile_pointer_list, node) {
        qemu_cfg_write_file_simple(&entry->pointer, entry->key,
                                   entry->offset, entry->ptr_size);
    }
}

static void romfile_loader_allocate(struct romfile_loader_entry_s *entry,
                                    struct romfile_loader_files *files)
{
    struct zone_s *zone;
    struct romfile_loader_file *file = &files->files[files->nfiles];
    void *data;
    int ret;
    unsigned alloc_align = le32_to_cpu(entry->alloc.align);

    if (alloc_align & (alloc_align - 1))
        goto err;

    switch (entry->alloc.zone) {
        case ROMFILE_LOADER_ALLOC_ZONE_HIGH:
            zone = &ZoneHigh;
            break;
        case ROMFILE_LOADER_ALLOC_ZONE_FSEG:
            zone = &ZoneFSeg;
            break;
        default:
            goto err;
    }
    if (alloc_align < MALLOC_MIN_ALIGN)
        alloc_align = MALLOC_MIN_ALIGN;
    if (entry->alloc.file[ROMFILE_LOADER_FILESZ - 1])
        goto err;
    file->file = romfile_find(entry->alloc.file);
    if (!file->file || !file->file->size)
        return;
    data = _malloc(zone, file->file->size, alloc_align);
    if (!data) {
        warn_noalloc();
        return;
    }
    ret = file->file->copy(file->file, data, file->file->size);
    if (ret != file->file->size)
        goto file_err;
    file->data = data;
    files->nfiles++;
    return;

file_err:
    free(data);
err:
    warn_internalerror();
}

static void romfile_loader_add_pointer(struct romfile_loader_entry_s *entry,
                                       struct romfile_loader_files *files)
{
    struct romfile_loader_file *dest_file;
    struct romfile_loader_file *src_file;
    unsigned offset = le32_to_cpu(entry->pointer.offset);
    u64 pointer = 0;

    dest_file = romfile_loader_find(entry->pointer.dest_file, files);
    src_file = romfile_loader_find(entry->pointer.src_file, files);

    if (!dest_file || !src_file || !dest_file->data || !src_file->data ||
        offset + entry->pointer.size < offset ||
        offset + entry->pointer.size > dest_file->file->size ||
        entry->pointer.size < 1 || entry->pointer.size > 8 ||
        entry->pointer.size & (entry->pointer.size - 1))
        goto err;

    memcpy(&pointer, dest_file->data + offset, entry->pointer.size);
    pointer = le64_to_cpu(pointer);
    pointer += (unsigned long)src_file->data;
    pointer = cpu_to_le64(pointer);
    memcpy(dest_file->data + offset, &pointer, entry->pointer.size);

    return;
err:
    warn_internalerror();
}

static void romfile_loader_add_checksum(struct romfile_loader_entry_s *entry,
                                        struct romfile_loader_files *files)
{
    struct romfile_loader_file *file;
    unsigned offset = le32_to_cpu(entry->cksum.offset);
    unsigned start = le32_to_cpu(entry->cksum.start);
    unsigned len = le32_to_cpu(entry->cksum.length);
    u8 *data;

    file = romfile_loader_find(entry->cksum.file, files);

    if (!file || !file->data || offset >= file->file->size ||
        start + len < start || start + len > file->file->size)
        goto err;

    data = file->data + offset;
    *data -= checksum(file->data + start, len);

    return;
err:
    warn_internalerror();
}

static void romfile_loader_write_pointer(struct romfile_loader_entry_s *entry,
                                         struct romfile_loader_files *files)
{
    struct romfile_s *dest_file;
    struct romfile_loader_file *src_file;
    unsigned dst_offset = le32_to_cpu(entry->wr_pointer.dst_offset);
    unsigned src_offset = le32_to_cpu(entry->wr_pointer.src_offset);
    u64 pointer = 0;

    /* Writing back to a file that may not be loaded in RAM */
    dest_file = romfile_find(entry->wr_pointer.dest_file);
    src_file = romfile_loader_find(entry->wr_pointer.src_file, files);

    if (!dest_file || !src_file || !src_file->data ||
        dst_offset + entry->wr_pointer.size < dst_offset ||
        dst_offset + entry->wr_pointer.size > dest_file->size ||
        src_offset >= src_file->file->size ||
        entry->wr_pointer.size < 1 || entry->wr_pointer.size > 8 ||
        entry->wr_pointer.size & (entry->wr_pointer.size - 1)) {
        goto err;
    }

    pointer = (unsigned long)src_file->data + src_offset;
    /* Make sure the pointer fits within wr_pointer.size */
    if ((entry->wr_pointer.size != sizeof(u64)) &&
        ((pointer >> (entry->wr_pointer.size * 8)) > 0)) {
        goto err;
    }
    pointer = cpu_to_le64(pointer);

    /* Only supported on QEMU */
    if (qemu_cfg_write_file(&pointer, dest_file, dst_offset,
                            entry->wr_pointer.size) != entry->wr_pointer.size) {
        goto err;
    }

    /* Store the info so it can replayed later if necessary */
    struct romfile_wr_pointer_entry *store = malloc_high(sizeof(*store));
    if (!store) {
        warn_noalloc();
        return;
    }
    store->pointer = pointer;
    store->key = qemu_get_romfile_key(dest_file);
    store->offset = dst_offset;
    store->ptr_size = entry->wr_pointer.size;
    hlist_add_head(&store->node, &romfile_pointer_list);

    return;
 err:
    warn_internalerror();
}

int romfile_loader_execute(const char *name)
{
    struct romfile_loader_entry_s *entry;
    int size, offset = 0, nfiles;
    struct romfile_loader_files *files;
    void *data = romfile_loadfile(name, &size);
    if (!data)
        return -1;

    if (size % sizeof(*entry)) {
        warn_internalerror();
        goto err;
    }

    /* (over)estimate the number of files to load. */
    nfiles = size / sizeof(*entry);
    files = malloc_tmp(sizeof(*files) + nfiles * sizeof(files->files[0]));
    if (!files) {
        warn_noalloc();
        goto err;
    }
    files->nfiles = 0;

    for (offset = 0; offset < size; offset += sizeof(*entry)) {
        entry = data + offset;
        switch (le32_to_cpu(entry->command)) {
                case ROMFILE_LOADER_COMMAND_ALLOCATE:
                        romfile_loader_allocate(entry, files);
                        break;
                case ROMFILE_LOADER_COMMAND_ADD_POINTER:
                        romfile_loader_add_pointer(entry, files);
                        break;
                case ROMFILE_LOADER_COMMAND_ADD_CHECKSUM:
                        romfile_loader_add_checksum(entry, files);
                        break;
                case ROMFILE_LOADER_COMMAND_WRITE_POINTER:
                        romfile_loader_write_pointer(entry, files);
                        break;
                default:
                        /* Skip commands that we don't recognize. */
                        break;
        }
    }

    free(files);
    free(data);
    return 0;

err:
    free(data);
    return -1;
}
