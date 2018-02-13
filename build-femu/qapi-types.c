/* AUTOMATICALLY GENERATED, DO NOT MODIFY */

/*
 * deallocation functions for schema-defined QAPI types
 *
 * Copyright IBM, Corp. 2011
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *  Michael Roth      <mdroth@linux.vnet.ibm.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "qapi/dealloc-visitor.h"
#include "qapi-types.h"
#include "qapi-visit.h"

void qapi_free_ACPIOSTInfo(ACPIOSTInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_ACPIOSTInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_ACPIOSTInfoList(ACPIOSTInfoList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_ACPIOSTInfoList(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const ACPISlotType_lookup[] = {
    [ACPI_SLOT_TYPE_DIMM] = "DIMM",
    [ACPI_SLOT_TYPE_CPU] = "CPU",
    [ACPI_SLOT_TYPE__MAX] = NULL,
};

void qapi_free_Abort(Abort *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_Abort(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_AcpiTableOptions(AcpiTableOptions *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_AcpiTableOptions(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const ActionCompletionMode_lookup[] = {
    [ACTION_COMPLETION_MODE_INDIVIDUAL] = "individual",
    [ACTION_COMPLETION_MODE_GROUPED] = "grouped",
    [ACTION_COMPLETION_MODE__MAX] = NULL,
};

void qapi_free_AddfdInfo(AddfdInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_AddfdInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BalloonInfo(BalloonInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BalloonInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const BiosAtaTranslation_lookup[] = {
    [BIOS_ATA_TRANSLATION_AUTO] = "auto",
    [BIOS_ATA_TRANSLATION_NONE] = "none",
    [BIOS_ATA_TRANSLATION_LBA] = "lba",
    [BIOS_ATA_TRANSLATION_LARGE] = "large",
    [BIOS_ATA_TRANSLATION_RECHS] = "rechs",
    [BIOS_ATA_TRANSLATION__MAX] = NULL,
};

const char *const BlkdebugEvent_lookup[] = {
    [BLKDBG_L1_UPDATE] = "l1_update",
    [BLKDBG_L1_GROW_ALLOC_TABLE] = "l1_grow_alloc_table",
    [BLKDBG_L1_GROW_WRITE_TABLE] = "l1_grow_write_table",
    [BLKDBG_L1_GROW_ACTIVATE_TABLE] = "l1_grow_activate_table",
    [BLKDBG_L2_LOAD] = "l2_load",
    [BLKDBG_L2_UPDATE] = "l2_update",
    [BLKDBG_L2_UPDATE_COMPRESSED] = "l2_update_compressed",
    [BLKDBG_L2_ALLOC_COW_READ] = "l2_alloc_cow_read",
    [BLKDBG_L2_ALLOC_WRITE] = "l2_alloc_write",
    [BLKDBG_READ_AIO] = "read_aio",
    [BLKDBG_READ_BACKING_AIO] = "read_backing_aio",
    [BLKDBG_READ_COMPRESSED] = "read_compressed",
    [BLKDBG_WRITE_AIO] = "write_aio",
    [BLKDBG_WRITE_COMPRESSED] = "write_compressed",
    [BLKDBG_VMSTATE_LOAD] = "vmstate_load",
    [BLKDBG_VMSTATE_SAVE] = "vmstate_save",
    [BLKDBG_COW_READ] = "cow_read",
    [BLKDBG_COW_WRITE] = "cow_write",
    [BLKDBG_REFTABLE_LOAD] = "reftable_load",
    [BLKDBG_REFTABLE_GROW] = "reftable_grow",
    [BLKDBG_REFTABLE_UPDATE] = "reftable_update",
    [BLKDBG_REFBLOCK_LOAD] = "refblock_load",
    [BLKDBG_REFBLOCK_UPDATE] = "refblock_update",
    [BLKDBG_REFBLOCK_UPDATE_PART] = "refblock_update_part",
    [BLKDBG_REFBLOCK_ALLOC] = "refblock_alloc",
    [BLKDBG_REFBLOCK_ALLOC_HOOKUP] = "refblock_alloc_hookup",
    [BLKDBG_REFBLOCK_ALLOC_WRITE] = "refblock_alloc_write",
    [BLKDBG_REFBLOCK_ALLOC_WRITE_BLOCKS] = "refblock_alloc_write_blocks",
    [BLKDBG_REFBLOCK_ALLOC_WRITE_TABLE] = "refblock_alloc_write_table",
    [BLKDBG_REFBLOCK_ALLOC_SWITCH_TABLE] = "refblock_alloc_switch_table",
    [BLKDBG_CLUSTER_ALLOC] = "cluster_alloc",
    [BLKDBG_CLUSTER_ALLOC_BYTES] = "cluster_alloc_bytes",
    [BLKDBG_CLUSTER_FREE] = "cluster_free",
    [BLKDBG_FLUSH_TO_OS] = "flush_to_os",
    [BLKDBG_FLUSH_TO_DISK] = "flush_to_disk",
    [BLKDBG_PWRITEV_RMW_HEAD] = "pwritev_rmw_head",
    [BLKDBG_PWRITEV_RMW_AFTER_HEAD] = "pwritev_rmw_after_head",
    [BLKDBG_PWRITEV_RMW_TAIL] = "pwritev_rmw_tail",
    [BLKDBG_PWRITEV_RMW_AFTER_TAIL] = "pwritev_rmw_after_tail",
    [BLKDBG_PWRITEV] = "pwritev",
    [BLKDBG_PWRITEV_ZERO] = "pwritev_zero",
    [BLKDBG_PWRITEV_DONE] = "pwritev_done",
    [BLKDBG_EMPTY_IMAGE_PREPARE] = "empty_image_prepare",
    [BLKDBG__MAX] = NULL,
};

void qapi_free_BlkdebugInjectErrorOptions(BlkdebugInjectErrorOptions *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlkdebugInjectErrorOptions(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlkdebugInjectErrorOptionsList(BlkdebugInjectErrorOptionsList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlkdebugInjectErrorOptionsList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlkdebugSetStateOptions(BlkdebugSetStateOptions *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlkdebugSetStateOptions(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlkdebugSetStateOptionsList(BlkdebugSetStateOptionsList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlkdebugSetStateOptionsList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockDeviceInfo(BlockDeviceInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockDeviceInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockDeviceInfoList(BlockDeviceInfoList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockDeviceInfoList(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const BlockDeviceIoStatus_lookup[] = {
    [BLOCK_DEVICE_IO_STATUS_OK] = "ok",
    [BLOCK_DEVICE_IO_STATUS_FAILED] = "failed",
    [BLOCK_DEVICE_IO_STATUS_NOSPACE] = "nospace",
    [BLOCK_DEVICE_IO_STATUS__MAX] = NULL,
};

void qapi_free_BlockDeviceMapEntry(BlockDeviceMapEntry *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockDeviceMapEntry(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockDeviceStats(BlockDeviceStats *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockDeviceStats(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockDeviceTimedStats(BlockDeviceTimedStats *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockDeviceTimedStats(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockDeviceTimedStatsList(BlockDeviceTimedStatsList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockDeviceTimedStatsList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockDirtyBitmap(BlockDirtyBitmap *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockDirtyBitmap(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockDirtyBitmapAdd(BlockDirtyBitmapAdd *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockDirtyBitmapAdd(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockDirtyInfo(BlockDirtyInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockDirtyInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockDirtyInfoList(BlockDirtyInfoList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockDirtyInfoList(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const BlockErrorAction_lookup[] = {
    [BLOCK_ERROR_ACTION_IGNORE] = "ignore",
    [BLOCK_ERROR_ACTION_REPORT] = "report",
    [BLOCK_ERROR_ACTION_STOP] = "stop",
    [BLOCK_ERROR_ACTION__MAX] = NULL,
};

void qapi_free_BlockIOThrottle(BlockIOThrottle *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockIOThrottle(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockInfo(BlockInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockInfoList(BlockInfoList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockInfoList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockJobInfo(BlockJobInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockJobInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockJobInfoList(BlockJobInfoList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockJobInfoList(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const BlockJobType_lookup[] = {
    [BLOCK_JOB_TYPE_COMMIT] = "commit",
    [BLOCK_JOB_TYPE_STREAM] = "stream",
    [BLOCK_JOB_TYPE_MIRROR] = "mirror",
    [BLOCK_JOB_TYPE_BACKUP] = "backup",
    [BLOCK_JOB_TYPE__MAX] = NULL,
};

void qapi_free_BlockStats(BlockStats *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockStats(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockStatsList(BlockStatsList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockStatsList(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const BlockdevAioOptions_lookup[] = {
    [BLOCKDEV_AIO_OPTIONS_THREADS] = "threads",
    [BLOCKDEV_AIO_OPTIONS_NATIVE] = "native",
    [BLOCKDEV_AIO_OPTIONS__MAX] = NULL,
};

void qapi_free_BlockdevBackup(BlockdevBackup *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockdevBackup(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockdevCacheInfo(BlockdevCacheInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockdevCacheInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockdevCacheOptions(BlockdevCacheOptions *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockdevCacheOptions(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const BlockdevChangeReadOnlyMode_lookup[] = {
    [BLOCKDEV_CHANGE_READ_ONLY_MODE_RETAIN] = "retain",
    [BLOCKDEV_CHANGE_READ_ONLY_MODE_READ_ONLY] = "read-only",
    [BLOCKDEV_CHANGE_READ_ONLY_MODE_READ_WRITE] = "read-write",
    [BLOCKDEV_CHANGE_READ_ONLY_MODE__MAX] = NULL,
};

const char *const BlockdevDetectZeroesOptions_lookup[] = {
    [BLOCKDEV_DETECT_ZEROES_OPTIONS_OFF] = "off",
    [BLOCKDEV_DETECT_ZEROES_OPTIONS_ON] = "on",
    [BLOCKDEV_DETECT_ZEROES_OPTIONS_UNMAP] = "unmap",
    [BLOCKDEV_DETECT_ZEROES_OPTIONS__MAX] = NULL,
};

const char *const BlockdevDiscardOptions_lookup[] = {
    [BLOCKDEV_DISCARD_OPTIONS_IGNORE] = "ignore",
    [BLOCKDEV_DISCARD_OPTIONS_UNMAP] = "unmap",
    [BLOCKDEV_DISCARD_OPTIONS__MAX] = NULL,
};

const char *const BlockdevDriver_lookup[] = {
    [BLOCKDEV_DRIVER_BLKDEBUG] = "blkdebug",
    [BLOCKDEV_DRIVER_BLKVERIFY] = "blkverify",
    [BLOCKDEV_DRIVER_BOCHS] = "bochs",
    [BLOCKDEV_DRIVER_CLOOP] = "cloop",
    [BLOCKDEV_DRIVER_DMG] = "dmg",
    [BLOCKDEV_DRIVER_FILE] = "file",
    [BLOCKDEV_DRIVER_FTP] = "ftp",
    [BLOCKDEV_DRIVER_FTPS] = "ftps",
    [BLOCKDEV_DRIVER_GLUSTER] = "gluster",
    [BLOCKDEV_DRIVER_HOST_CDROM] = "host_cdrom",
    [BLOCKDEV_DRIVER_HOST_DEVICE] = "host_device",
    [BLOCKDEV_DRIVER_HTTP] = "http",
    [BLOCKDEV_DRIVER_HTTPS] = "https",
    [BLOCKDEV_DRIVER_ISCSI] = "iscsi",
    [BLOCKDEV_DRIVER_LUKS] = "luks",
    [BLOCKDEV_DRIVER_NBD] = "nbd",
    [BLOCKDEV_DRIVER_NFS] = "nfs",
    [BLOCKDEV_DRIVER_NULL_AIO] = "null-aio",
    [BLOCKDEV_DRIVER_NULL_CO] = "null-co",
    [BLOCKDEV_DRIVER_PARALLELS] = "parallels",
    [BLOCKDEV_DRIVER_QCOW] = "qcow",
    [BLOCKDEV_DRIVER_QCOW2] = "qcow2",
    [BLOCKDEV_DRIVER_QED] = "qed",
    [BLOCKDEV_DRIVER_QUORUM] = "quorum",
    [BLOCKDEV_DRIVER_RAW] = "raw",
    [BLOCKDEV_DRIVER_RBD] = "rbd",
    [BLOCKDEV_DRIVER_REPLICATION] = "replication",
    [BLOCKDEV_DRIVER_SHEEPDOG] = "sheepdog",
    [BLOCKDEV_DRIVER_SSH] = "ssh",
    [BLOCKDEV_DRIVER_VDI] = "vdi",
    [BLOCKDEV_DRIVER_VHDX] = "vhdx",
    [BLOCKDEV_DRIVER_VMDK] = "vmdk",
    [BLOCKDEV_DRIVER_VPC] = "vpc",
    [BLOCKDEV_DRIVER_VVFAT] = "vvfat",
    [BLOCKDEV_DRIVER__MAX] = NULL,
};

const char *const BlockdevOnError_lookup[] = {
    [BLOCKDEV_ON_ERROR_REPORT] = "report",
    [BLOCKDEV_ON_ERROR_IGNORE] = "ignore",
    [BLOCKDEV_ON_ERROR_ENOSPC] = "enospc",
    [BLOCKDEV_ON_ERROR_STOP] = "stop",
    [BLOCKDEV_ON_ERROR_AUTO] = "auto",
    [BLOCKDEV_ON_ERROR__MAX] = NULL,
};

void qapi_free_BlockdevOptions(BlockdevOptions *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockdevOptions(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockdevOptionsBlkdebug(BlockdevOptionsBlkdebug *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockdevOptionsBlkdebug(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockdevOptionsBlkverify(BlockdevOptionsBlkverify *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockdevOptionsBlkverify(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockdevOptionsCurlBase(BlockdevOptionsCurlBase *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockdevOptionsCurlBase(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockdevOptionsCurlFtp(BlockdevOptionsCurlFtp *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockdevOptionsCurlFtp(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockdevOptionsCurlFtps(BlockdevOptionsCurlFtps *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockdevOptionsCurlFtps(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockdevOptionsCurlHttp(BlockdevOptionsCurlHttp *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockdevOptionsCurlHttp(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockdevOptionsCurlHttps(BlockdevOptionsCurlHttps *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockdevOptionsCurlHttps(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockdevOptionsFile(BlockdevOptionsFile *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockdevOptionsFile(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockdevOptionsGenericCOWFormat(BlockdevOptionsGenericCOWFormat *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockdevOptionsGenericCOWFormat(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockdevOptionsGenericFormat(BlockdevOptionsGenericFormat *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockdevOptionsGenericFormat(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockdevOptionsGluster(BlockdevOptionsGluster *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockdevOptionsGluster(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockdevOptionsIscsi(BlockdevOptionsIscsi *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockdevOptionsIscsi(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockdevOptionsLUKS(BlockdevOptionsLUKS *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockdevOptionsLUKS(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockdevOptionsNbd(BlockdevOptionsNbd *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockdevOptionsNbd(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockdevOptionsNfs(BlockdevOptionsNfs *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockdevOptionsNfs(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockdevOptionsNull(BlockdevOptionsNull *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockdevOptionsNull(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockdevOptionsQcow2(BlockdevOptionsQcow2 *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockdevOptionsQcow2(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockdevOptionsQuorum(BlockdevOptionsQuorum *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockdevOptionsQuorum(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockdevOptionsRaw(BlockdevOptionsRaw *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockdevOptionsRaw(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockdevOptionsRbd(BlockdevOptionsRbd *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockdevOptionsRbd(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockdevOptionsReplication(BlockdevOptionsReplication *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockdevOptionsReplication(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockdevOptionsSheepdog(BlockdevOptionsSheepdog *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockdevOptionsSheepdog(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockdevOptionsSsh(BlockdevOptionsSsh *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockdevOptionsSsh(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockdevOptionsVVFAT(BlockdevOptionsVVFAT *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockdevOptionsVVFAT(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockdevRef(BlockdevRef *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockdevRef(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockdevRefList(BlockdevRefList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockdevRefList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockdevSnapshot(BlockdevSnapshot *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockdevSnapshot(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockdevSnapshotInternal(BlockdevSnapshotInternal *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockdevSnapshotInternal(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_BlockdevSnapshotSync(BlockdevSnapshotSync *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_BlockdevSnapshotSync(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const COLOMessage_lookup[] = {
    [COLO_MESSAGE_CHECKPOINT_READY] = "checkpoint-ready",
    [COLO_MESSAGE_CHECKPOINT_REQUEST] = "checkpoint-request",
    [COLO_MESSAGE_CHECKPOINT_REPLY] = "checkpoint-reply",
    [COLO_MESSAGE_VMSTATE_SEND] = "vmstate-send",
    [COLO_MESSAGE_VMSTATE_SIZE] = "vmstate-size",
    [COLO_MESSAGE_VMSTATE_RECEIVED] = "vmstate-received",
    [COLO_MESSAGE_VMSTATE_LOADED] = "vmstate-loaded",
    [COLO_MESSAGE__MAX] = NULL,
};

const char *const COLOMode_lookup[] = {
    [COLO_MODE_UNKNOWN] = "unknown",
    [COLO_MODE_PRIMARY] = "primary",
    [COLO_MODE_SECONDARY] = "secondary",
    [COLO_MODE__MAX] = NULL,
};

void qapi_free_ChardevBackend(ChardevBackend *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_ChardevBackend(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_ChardevBackendInfo(ChardevBackendInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_ChardevBackendInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_ChardevBackendInfoList(ChardevBackendInfoList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_ChardevBackendInfoList(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const ChardevBackendKind_lookup[] = {
    [CHARDEV_BACKEND_KIND_FILE] = "file",
    [CHARDEV_BACKEND_KIND_SERIAL] = "serial",
    [CHARDEV_BACKEND_KIND_PARALLEL] = "parallel",
    [CHARDEV_BACKEND_KIND_PIPE] = "pipe",
    [CHARDEV_BACKEND_KIND_SOCKET] = "socket",
    [CHARDEV_BACKEND_KIND_UDP] = "udp",
    [CHARDEV_BACKEND_KIND_PTY] = "pty",
    [CHARDEV_BACKEND_KIND_NULL] = "null",
    [CHARDEV_BACKEND_KIND_MUX] = "mux",
    [CHARDEV_BACKEND_KIND_MSMOUSE] = "msmouse",
    [CHARDEV_BACKEND_KIND_WCTABLET] = "wctablet",
    [CHARDEV_BACKEND_KIND_BRAILLE] = "braille",
    [CHARDEV_BACKEND_KIND_TESTDEV] = "testdev",
    [CHARDEV_BACKEND_KIND_STDIO] = "stdio",
    [CHARDEV_BACKEND_KIND_CONSOLE] = "console",
    [CHARDEV_BACKEND_KIND_SPICEVMC] = "spicevmc",
    [CHARDEV_BACKEND_KIND_SPICEPORT] = "spiceport",
    [CHARDEV_BACKEND_KIND_VC] = "vc",
    [CHARDEV_BACKEND_KIND_RINGBUF] = "ringbuf",
    [CHARDEV_BACKEND_KIND_MEMORY] = "memory",
    [CHARDEV_BACKEND_KIND__MAX] = NULL,
};

void qapi_free_ChardevCommon(ChardevCommon *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_ChardevCommon(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_ChardevFile(ChardevFile *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_ChardevFile(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_ChardevHostdev(ChardevHostdev *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_ChardevHostdev(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_ChardevInfo(ChardevInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_ChardevInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_ChardevInfoList(ChardevInfoList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_ChardevInfoList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_ChardevMux(ChardevMux *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_ChardevMux(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_ChardevReturn(ChardevReturn *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_ChardevReturn(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_ChardevRingbuf(ChardevRingbuf *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_ChardevRingbuf(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_ChardevSocket(ChardevSocket *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_ChardevSocket(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_ChardevSpiceChannel(ChardevSpiceChannel *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_ChardevSpiceChannel(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_ChardevSpicePort(ChardevSpicePort *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_ChardevSpicePort(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_ChardevStdio(ChardevStdio *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_ChardevStdio(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_ChardevUdp(ChardevUdp *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_ChardevUdp(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_ChardevVC(ChardevVC *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_ChardevVC(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_CommandInfo(CommandInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_CommandInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_CommandInfoList(CommandInfoList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_CommandInfoList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_CommandLineOptionInfo(CommandLineOptionInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_CommandLineOptionInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_CommandLineOptionInfoList(CommandLineOptionInfoList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_CommandLineOptionInfoList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_CommandLineParameterInfo(CommandLineParameterInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_CommandLineParameterInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_CommandLineParameterInfoList(CommandLineParameterInfoList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_CommandLineParameterInfoList(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const CommandLineParameterType_lookup[] = {
    [COMMAND_LINE_PARAMETER_TYPE_STRING] = "string",
    [COMMAND_LINE_PARAMETER_TYPE_BOOLEAN] = "boolean",
    [COMMAND_LINE_PARAMETER_TYPE_NUMBER] = "number",
    [COMMAND_LINE_PARAMETER_TYPE_SIZE] = "size",
    [COMMAND_LINE_PARAMETER_TYPE__MAX] = NULL,
};

void qapi_free_CpuDefinitionInfo(CpuDefinitionInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_CpuDefinitionInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_CpuDefinitionInfoList(CpuDefinitionInfoList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_CpuDefinitionInfoList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_CpuInfo(CpuInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_CpuInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const CpuInfoArch_lookup[] = {
    [CPU_INFO_ARCH_X86] = "x86",
    [CPU_INFO_ARCH_SPARC] = "sparc",
    [CPU_INFO_ARCH_PPC] = "ppc",
    [CPU_INFO_ARCH_MIPS] = "mips",
    [CPU_INFO_ARCH_TRICORE] = "tricore",
    [CPU_INFO_ARCH_OTHER] = "other",
    [CPU_INFO_ARCH__MAX] = NULL,
};

void qapi_free_CpuInfoList(CpuInfoList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_CpuInfoList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_CpuInfoMIPS(CpuInfoMIPS *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_CpuInfoMIPS(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_CpuInfoOther(CpuInfoOther *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_CpuInfoOther(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_CpuInfoPPC(CpuInfoPPC *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_CpuInfoPPC(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_CpuInfoSPARC(CpuInfoSPARC *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_CpuInfoSPARC(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_CpuInfoTricore(CpuInfoTricore *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_CpuInfoTricore(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_CpuInfoX86(CpuInfoX86 *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_CpuInfoX86(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_CpuInstanceProperties(CpuInstanceProperties *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_CpuInstanceProperties(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_CpuModelBaselineInfo(CpuModelBaselineInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_CpuModelBaselineInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_CpuModelCompareInfo(CpuModelCompareInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_CpuModelCompareInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const CpuModelCompareResult_lookup[] = {
    [CPU_MODEL_COMPARE_RESULT_INCOMPATIBLE] = "incompatible",
    [CPU_MODEL_COMPARE_RESULT_IDENTICAL] = "identical",
    [CPU_MODEL_COMPARE_RESULT_SUPERSET] = "superset",
    [CPU_MODEL_COMPARE_RESULT_SUBSET] = "subset",
    [CPU_MODEL_COMPARE_RESULT__MAX] = NULL,
};

void qapi_free_CpuModelExpansionInfo(CpuModelExpansionInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_CpuModelExpansionInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const CpuModelExpansionType_lookup[] = {
    [CPU_MODEL_EXPANSION_TYPE_STATIC] = "static",
    [CPU_MODEL_EXPANSION_TYPE_FULL] = "full",
    [CPU_MODEL_EXPANSION_TYPE__MAX] = NULL,
};

void qapi_free_CpuModelInfo(CpuModelInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_CpuModelInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const DataFormat_lookup[] = {
    [DATA_FORMAT_UTF8] = "utf8",
    [DATA_FORMAT_BASE64] = "base64",
    [DATA_FORMAT__MAX] = NULL,
};

void qapi_free_DevicePropertyInfo(DevicePropertyInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_DevicePropertyInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_DevicePropertyInfoList(DevicePropertyInfoList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_DevicePropertyInfoList(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const DirtyBitmapStatus_lookup[] = {
    [DIRTY_BITMAP_STATUS_ACTIVE] = "active",
    [DIRTY_BITMAP_STATUS_DISABLED] = "disabled",
    [DIRTY_BITMAP_STATUS_FROZEN] = "frozen",
    [DIRTY_BITMAP_STATUS__MAX] = NULL,
};

void qapi_free_DriveBackup(DriveBackup *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_DriveBackup(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_DriveMirror(DriveMirror *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_DriveMirror(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_DummyForceArrays(DummyForceArrays *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_DummyForceArrays(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_DumpGuestMemoryCapability(DumpGuestMemoryCapability *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_DumpGuestMemoryCapability(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const DumpGuestMemoryFormat_lookup[] = {
    [DUMP_GUEST_MEMORY_FORMAT_ELF] = "elf",
    [DUMP_GUEST_MEMORY_FORMAT_KDUMP_ZLIB] = "kdump-zlib",
    [DUMP_GUEST_MEMORY_FORMAT_KDUMP_LZO] = "kdump-lzo",
    [DUMP_GUEST_MEMORY_FORMAT_KDUMP_SNAPPY] = "kdump-snappy",
    [DUMP_GUEST_MEMORY_FORMAT__MAX] = NULL,
};

void qapi_free_DumpGuestMemoryFormatList(DumpGuestMemoryFormatList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_DumpGuestMemoryFormatList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_DumpQueryResult(DumpQueryResult *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_DumpQueryResult(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const DumpStatus_lookup[] = {
    [DUMP_STATUS_NONE] = "none",
    [DUMP_STATUS_ACTIVE] = "active",
    [DUMP_STATUS_COMPLETED] = "completed",
    [DUMP_STATUS_FAILED] = "failed",
    [DUMP_STATUS__MAX] = NULL,
};

void qapi_free_EventInfo(EventInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_EventInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_EventInfoList(EventInfoList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_EventInfoList(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const FailoverStatus_lookup[] = {
    [FAILOVER_STATUS_NONE] = "none",
    [FAILOVER_STATUS_REQUIRE] = "require",
    [FAILOVER_STATUS_ACTIVE] = "active",
    [FAILOVER_STATUS_COMPLETED] = "completed",
    [FAILOVER_STATUS_RELAUNCH] = "relaunch",
    [FAILOVER_STATUS__MAX] = NULL,
};

void qapi_free_FdsetFdInfo(FdsetFdInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_FdsetFdInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_FdsetFdInfoList(FdsetFdInfoList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_FdsetFdInfoList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_FdsetInfo(FdsetInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_FdsetInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_FdsetInfoList(FdsetInfoList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_FdsetInfoList(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const FloppyDriveType_lookup[] = {
    [FLOPPY_DRIVE_TYPE_144] = "144",
    [FLOPPY_DRIVE_TYPE_288] = "288",
    [FLOPPY_DRIVE_TYPE_120] = "120",
    [FLOPPY_DRIVE_TYPE_NONE] = "none",
    [FLOPPY_DRIVE_TYPE_AUTO] = "auto",
    [FLOPPY_DRIVE_TYPE__MAX] = NULL,
};

void qapi_free_GICCapability(GICCapability *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_GICCapability(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_GICCapabilityList(GICCapabilityList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_GICCapabilityList(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const GuestPanicAction_lookup[] = {
    [GUEST_PANIC_ACTION_PAUSE] = "pause",
    [GUEST_PANIC_ACTION_POWEROFF] = "poweroff",
    [GUEST_PANIC_ACTION__MAX] = NULL,
};

void qapi_free_GuestPanicInformation(GuestPanicInformation *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_GuestPanicInformation(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_GuestPanicInformationHyperV(GuestPanicInformationHyperV *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_GuestPanicInformationHyperV(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const GuestPanicInformationType_lookup[] = {
    [GUEST_PANIC_INFORMATION_TYPE_HYPER_V] = "hyper-v",
    [GUEST_PANIC_INFORMATION_TYPE__MAX] = NULL,
};

void qapi_free_GuidInfo(GuidInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_GuidInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const HostMemPolicy_lookup[] = {
    [HOST_MEM_POLICY_DEFAULT] = "default",
    [HOST_MEM_POLICY_PREFERRED] = "preferred",
    [HOST_MEM_POLICY_BIND] = "bind",
    [HOST_MEM_POLICY_INTERLEAVE] = "interleave",
    [HOST_MEM_POLICY__MAX] = NULL,
};

void qapi_free_HotpluggableCPU(HotpluggableCPU *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_HotpluggableCPU(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_HotpluggableCPUList(HotpluggableCPUList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_HotpluggableCPUList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_IOThreadInfo(IOThreadInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_IOThreadInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_IOThreadInfoList(IOThreadInfoList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_IOThreadInfoList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_ImageCheck(ImageCheck *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_ImageCheck(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_ImageInfo(ImageInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_ImageInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_ImageInfoList(ImageInfoList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_ImageInfoList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_ImageInfoSpecific(ImageInfoSpecific *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_ImageInfoSpecific(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const ImageInfoSpecificKind_lookup[] = {
    [IMAGE_INFO_SPECIFIC_KIND_QCOW2] = "qcow2",
    [IMAGE_INFO_SPECIFIC_KIND_VMDK] = "vmdk",
    [IMAGE_INFO_SPECIFIC_KIND_LUKS] = "luks",
    [IMAGE_INFO_SPECIFIC_KIND__MAX] = NULL,
};

void qapi_free_ImageInfoSpecificQCow2(ImageInfoSpecificQCow2 *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_ImageInfoSpecificQCow2(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_ImageInfoSpecificVmdk(ImageInfoSpecificVmdk *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_ImageInfoSpecificVmdk(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_InetSocketAddress(InetSocketAddress *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_InetSocketAddress(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_InetSocketAddressBase(InetSocketAddressBase *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_InetSocketAddressBase(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_InetSocketAddressBaseList(InetSocketAddressBaseList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_InetSocketAddressBaseList(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const InputAxis_lookup[] = {
    [INPUT_AXIS_X] = "x",
    [INPUT_AXIS_Y] = "y",
    [INPUT_AXIS__MAX] = NULL,
};

void qapi_free_InputBtnEvent(InputBtnEvent *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_InputBtnEvent(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const InputButton_lookup[] = {
    [INPUT_BUTTON_LEFT] = "left",
    [INPUT_BUTTON_MIDDLE] = "middle",
    [INPUT_BUTTON_RIGHT] = "right",
    [INPUT_BUTTON_WHEEL_UP] = "wheel-up",
    [INPUT_BUTTON_WHEEL_DOWN] = "wheel-down",
    [INPUT_BUTTON_SIDE] = "side",
    [INPUT_BUTTON_EXTRA] = "extra",
    [INPUT_BUTTON__MAX] = NULL,
};

void qapi_free_InputEvent(InputEvent *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_InputEvent(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const InputEventKind_lookup[] = {
    [INPUT_EVENT_KIND_KEY] = "key",
    [INPUT_EVENT_KIND_BTN] = "btn",
    [INPUT_EVENT_KIND_REL] = "rel",
    [INPUT_EVENT_KIND_ABS] = "abs",
    [INPUT_EVENT_KIND__MAX] = NULL,
};

void qapi_free_InputEventList(InputEventList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_InputEventList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_InputKeyEvent(InputKeyEvent *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_InputKeyEvent(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_InputMoveEvent(InputMoveEvent *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_InputMoveEvent(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const IoOperationType_lookup[] = {
    [IO_OPERATION_TYPE_READ] = "read",
    [IO_OPERATION_TYPE_WRITE] = "write",
    [IO_OPERATION_TYPE__MAX] = NULL,
};

const char *const IscsiHeaderDigest_lookup[] = {
    [QAPI_ISCSI_HEADER_DIGEST_CRC32C] = "crc32c",
    [QAPI_ISCSI_HEADER_DIGEST_NONE] = "none",
    [QAPI_ISCSI_HEADER_DIGEST_CRC32C_NONE] = "crc32c-none",
    [QAPI_ISCSI_HEADER_DIGEST_NONE_CRC32C] = "none-crc32c",
    [QAPI_ISCSI_HEADER_DIGEST__MAX] = NULL,
};

const char *const IscsiTransport_lookup[] = {
    [ISCSI_TRANSPORT_TCP] = "tcp",
    [ISCSI_TRANSPORT_ISER] = "iser",
    [ISCSI_TRANSPORT__MAX] = NULL,
};

const char *const JSONType_lookup[] = {
    [JSON_TYPE_STRING] = "string",
    [JSON_TYPE_NUMBER] = "number",
    [JSON_TYPE_INT] = "int",
    [JSON_TYPE_BOOLEAN] = "boolean",
    [JSON_TYPE_NULL] = "null",
    [JSON_TYPE_OBJECT] = "object",
    [JSON_TYPE_ARRAY] = "array",
    [JSON_TYPE_VALUE] = "value",
    [JSON_TYPE__MAX] = NULL,
};

void qapi_free_KeyValue(KeyValue *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_KeyValue(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const KeyValueKind_lookup[] = {
    [KEY_VALUE_KIND_NUMBER] = "number",
    [KEY_VALUE_KIND_QCODE] = "qcode",
    [KEY_VALUE_KIND__MAX] = NULL,
};

void qapi_free_KeyValueList(KeyValueList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_KeyValueList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_KvmInfo(KvmInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_KvmInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const LostTickPolicy_lookup[] = {
    [LOST_TICK_POLICY_DISCARD] = "discard",
    [LOST_TICK_POLICY_DELAY] = "delay",
    [LOST_TICK_POLICY_MERGE] = "merge",
    [LOST_TICK_POLICY_SLEW] = "slew",
    [LOST_TICK_POLICY__MAX] = NULL,
};

void qapi_free_MachineInfo(MachineInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_MachineInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_MachineInfoList(MachineInfoList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_MachineInfoList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_MapEntry(MapEntry *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_MapEntry(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_Memdev(Memdev *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_Memdev(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_MemdevList(MemdevList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_MemdevList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_MemoryDeviceInfo(MemoryDeviceInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_MemoryDeviceInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const MemoryDeviceInfoKind_lookup[] = {
    [MEMORY_DEVICE_INFO_KIND_DIMM] = "dimm",
    [MEMORY_DEVICE_INFO_KIND__MAX] = NULL,
};

void qapi_free_MemoryDeviceInfoList(MemoryDeviceInfoList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_MemoryDeviceInfoList(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const MigrationCapability_lookup[] = {
    [MIGRATION_CAPABILITY_XBZRLE] = "xbzrle",
    [MIGRATION_CAPABILITY_RDMA_PIN_ALL] = "rdma-pin-all",
    [MIGRATION_CAPABILITY_AUTO_CONVERGE] = "auto-converge",
    [MIGRATION_CAPABILITY_ZERO_BLOCKS] = "zero-blocks",
    [MIGRATION_CAPABILITY_COMPRESS] = "compress",
    [MIGRATION_CAPABILITY_EVENTS] = "events",
    [MIGRATION_CAPABILITY_POSTCOPY_RAM] = "postcopy-ram",
    [MIGRATION_CAPABILITY_X_COLO] = "x-colo",
    [MIGRATION_CAPABILITY_RELEASE_RAM] = "release-ram",
    [MIGRATION_CAPABILITY__MAX] = NULL,
};

void qapi_free_MigrationCapabilityStatus(MigrationCapabilityStatus *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_MigrationCapabilityStatus(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_MigrationCapabilityStatusList(MigrationCapabilityStatusList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_MigrationCapabilityStatusList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_MigrationInfo(MigrationInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_MigrationInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const MigrationParameter_lookup[] = {
    [MIGRATION_PARAMETER_COMPRESS_LEVEL] = "compress-level",
    [MIGRATION_PARAMETER_COMPRESS_THREADS] = "compress-threads",
    [MIGRATION_PARAMETER_DECOMPRESS_THREADS] = "decompress-threads",
    [MIGRATION_PARAMETER_CPU_THROTTLE_INITIAL] = "cpu-throttle-initial",
    [MIGRATION_PARAMETER_CPU_THROTTLE_INCREMENT] = "cpu-throttle-increment",
    [MIGRATION_PARAMETER_TLS_CREDS] = "tls-creds",
    [MIGRATION_PARAMETER_TLS_HOSTNAME] = "tls-hostname",
    [MIGRATION_PARAMETER_MAX_BANDWIDTH] = "max-bandwidth",
    [MIGRATION_PARAMETER_DOWNTIME_LIMIT] = "downtime-limit",
    [MIGRATION_PARAMETER_X_CHECKPOINT_DELAY] = "x-checkpoint-delay",
    [MIGRATION_PARAMETER__MAX] = NULL,
};

void qapi_free_MigrationParameters(MigrationParameters *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_MigrationParameters(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_MigrationStats(MigrationStats *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_MigrationStats(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const MigrationStatus_lookup[] = {
    [MIGRATION_STATUS_NONE] = "none",
    [MIGRATION_STATUS_SETUP] = "setup",
    [MIGRATION_STATUS_CANCELLING] = "cancelling",
    [MIGRATION_STATUS_CANCELLED] = "cancelled",
    [MIGRATION_STATUS_ACTIVE] = "active",
    [MIGRATION_STATUS_POSTCOPY_ACTIVE] = "postcopy-active",
    [MIGRATION_STATUS_COMPLETED] = "completed",
    [MIGRATION_STATUS_FAILED] = "failed",
    [MIGRATION_STATUS_COLO] = "colo",
    [MIGRATION_STATUS__MAX] = NULL,
};

const char *const MirrorSyncMode_lookup[] = {
    [MIRROR_SYNC_MODE_TOP] = "top",
    [MIRROR_SYNC_MODE_FULL] = "full",
    [MIRROR_SYNC_MODE_NONE] = "none",
    [MIRROR_SYNC_MODE_INCREMENTAL] = "incremental",
    [MIRROR_SYNC_MODE__MAX] = NULL,
};

void qapi_free_MouseInfo(MouseInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_MouseInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_MouseInfoList(MouseInfoList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_MouseInfoList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_NFSServer(NFSServer *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_NFSServer(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const NFSTransport_lookup[] = {
    [NFS_TRANSPORT_INET] = "inet",
    [NFS_TRANSPORT__MAX] = NULL,
};

void qapi_free_NameInfo(NameInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_NameInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const NetClientDriver_lookup[] = {
    [NET_CLIENT_DRIVER_NONE] = "none",
    [NET_CLIENT_DRIVER_NIC] = "nic",
    [NET_CLIENT_DRIVER_USER] = "user",
    [NET_CLIENT_DRIVER_TAP] = "tap",
    [NET_CLIENT_DRIVER_L2TPV3] = "l2tpv3",
    [NET_CLIENT_DRIVER_SOCKET] = "socket",
    [NET_CLIENT_DRIVER_VDE] = "vde",
    [NET_CLIENT_DRIVER_DUMP] = "dump",
    [NET_CLIENT_DRIVER_BRIDGE] = "bridge",
    [NET_CLIENT_DRIVER_HUBPORT] = "hubport",
    [NET_CLIENT_DRIVER_NETMAP] = "netmap",
    [NET_CLIENT_DRIVER_VHOST_USER] = "vhost-user",
    [NET_CLIENT_DRIVER__MAX] = NULL,
};

const char *const NetFilterDirection_lookup[] = {
    [NET_FILTER_DIRECTION_ALL] = "all",
    [NET_FILTER_DIRECTION_RX] = "rx",
    [NET_FILTER_DIRECTION_TX] = "tx",
    [NET_FILTER_DIRECTION__MAX] = NULL,
};

void qapi_free_NetLegacy(NetLegacy *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_NetLegacy(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_NetLegacyNicOptions(NetLegacyNicOptions *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_NetLegacyNicOptions(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_NetLegacyOptions(NetLegacyOptions *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_NetLegacyOptions(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const NetLegacyOptionsType_lookup[] = {
    [NET_LEGACY_OPTIONS_TYPE_NONE] = "none",
    [NET_LEGACY_OPTIONS_TYPE_NIC] = "nic",
    [NET_LEGACY_OPTIONS_TYPE_USER] = "user",
    [NET_LEGACY_OPTIONS_TYPE_TAP] = "tap",
    [NET_LEGACY_OPTIONS_TYPE_L2TPV3] = "l2tpv3",
    [NET_LEGACY_OPTIONS_TYPE_SOCKET] = "socket",
    [NET_LEGACY_OPTIONS_TYPE_VDE] = "vde",
    [NET_LEGACY_OPTIONS_TYPE_DUMP] = "dump",
    [NET_LEGACY_OPTIONS_TYPE_BRIDGE] = "bridge",
    [NET_LEGACY_OPTIONS_TYPE_NETMAP] = "netmap",
    [NET_LEGACY_OPTIONS_TYPE_VHOST_USER] = "vhost-user",
    [NET_LEGACY_OPTIONS_TYPE__MAX] = NULL,
};

void qapi_free_Netdev(Netdev *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_Netdev(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_NetdevBridgeOptions(NetdevBridgeOptions *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_NetdevBridgeOptions(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_NetdevDumpOptions(NetdevDumpOptions *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_NetdevDumpOptions(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_NetdevHubPortOptions(NetdevHubPortOptions *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_NetdevHubPortOptions(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_NetdevL2TPv3Options(NetdevL2TPv3Options *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_NetdevL2TPv3Options(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_NetdevNetmapOptions(NetdevNetmapOptions *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_NetdevNetmapOptions(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_NetdevNoneOptions(NetdevNoneOptions *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_NetdevNoneOptions(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_NetdevSocketOptions(NetdevSocketOptions *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_NetdevSocketOptions(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_NetdevTapOptions(NetdevTapOptions *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_NetdevTapOptions(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_NetdevUserOptions(NetdevUserOptions *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_NetdevUserOptions(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_NetdevVdeOptions(NetdevVdeOptions *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_NetdevVdeOptions(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_NetdevVhostUserOptions(NetdevVhostUserOptions *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_NetdevVhostUserOptions(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const NetworkAddressFamily_lookup[] = {
    [NETWORK_ADDRESS_FAMILY_IPV4] = "ipv4",
    [NETWORK_ADDRESS_FAMILY_IPV6] = "ipv6",
    [NETWORK_ADDRESS_FAMILY_UNIX] = "unix",
    [NETWORK_ADDRESS_FAMILY_VSOCK] = "vsock",
    [NETWORK_ADDRESS_FAMILY_UNKNOWN] = "unknown",
    [NETWORK_ADDRESS_FAMILY__MAX] = NULL,
};

const char *const NewImageMode_lookup[] = {
    [NEW_IMAGE_MODE_EXISTING] = "existing",
    [NEW_IMAGE_MODE_ABSOLUTE_PATHS] = "absolute-paths",
    [NEW_IMAGE_MODE__MAX] = NULL,
};

void qapi_free_NumaNodeOptions(NumaNodeOptions *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_NumaNodeOptions(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_NumaOptions(NumaOptions *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_NumaOptions(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const NumaOptionsType_lookup[] = {
    [NUMA_OPTIONS_TYPE_NODE] = "node",
    [NUMA_OPTIONS_TYPE__MAX] = NULL,
};

void qapi_free_ObjectPropertyInfo(ObjectPropertyInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_ObjectPropertyInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_ObjectPropertyInfoList(ObjectPropertyInfoList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_ObjectPropertyInfoList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_ObjectTypeInfo(ObjectTypeInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_ObjectTypeInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_ObjectTypeInfoList(ObjectTypeInfoList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_ObjectTypeInfoList(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const OnOffAuto_lookup[] = {
    [ON_OFF_AUTO_AUTO] = "auto",
    [ON_OFF_AUTO_ON] = "on",
    [ON_OFF_AUTO_OFF] = "off",
    [ON_OFF_AUTO__MAX] = NULL,
};

const char *const OnOffSplit_lookup[] = {
    [ON_OFF_SPLIT_ON] = "on",
    [ON_OFF_SPLIT_OFF] = "off",
    [ON_OFF_SPLIT_SPLIT] = "split",
    [ON_OFF_SPLIT__MAX] = NULL,
};

void qapi_free_PCDIMMDeviceInfo(PCDIMMDeviceInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_PCDIMMDeviceInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_PciBridgeInfo(PciBridgeInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_PciBridgeInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_PciBusInfo(PciBusInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_PciBusInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_PciDeviceClass(PciDeviceClass *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_PciDeviceClass(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_PciDeviceId(PciDeviceId *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_PciDeviceId(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_PciDeviceInfo(PciDeviceInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_PciDeviceInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_PciDeviceInfoList(PciDeviceInfoList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_PciDeviceInfoList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_PciInfo(PciInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_PciInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_PciInfoList(PciInfoList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_PciInfoList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_PciMemoryRange(PciMemoryRange *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_PciMemoryRange(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_PciMemoryRegion(PciMemoryRegion *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_PciMemoryRegion(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_PciMemoryRegionList(PciMemoryRegionList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_PciMemoryRegionList(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const PreallocMode_lookup[] = {
    [PREALLOC_MODE_OFF] = "off",
    [PREALLOC_MODE_METADATA] = "metadata",
    [PREALLOC_MODE_FALLOC] = "falloc",
    [PREALLOC_MODE_FULL] = "full",
    [PREALLOC_MODE__MAX] = NULL,
};

void qapi_free_QCryptoBlockCreateOptions(QCryptoBlockCreateOptions *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_QCryptoBlockCreateOptions(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_QCryptoBlockCreateOptionsLUKS(QCryptoBlockCreateOptionsLUKS *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_QCryptoBlockCreateOptionsLUKS(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const QCryptoBlockFormat_lookup[] = {
    [Q_CRYPTO_BLOCK_FORMAT_QCOW] = "qcow",
    [Q_CRYPTO_BLOCK_FORMAT_LUKS] = "luks",
    [Q_CRYPTO_BLOCK_FORMAT__MAX] = NULL,
};

void qapi_free_QCryptoBlockInfo(QCryptoBlockInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_QCryptoBlockInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_QCryptoBlockInfoBase(QCryptoBlockInfoBase *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_QCryptoBlockInfoBase(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_QCryptoBlockInfoLUKS(QCryptoBlockInfoLUKS *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_QCryptoBlockInfoLUKS(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_QCryptoBlockInfoLUKSSlot(QCryptoBlockInfoLUKSSlot *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_QCryptoBlockInfoLUKSSlot(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_QCryptoBlockInfoLUKSSlotList(QCryptoBlockInfoLUKSSlotList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_QCryptoBlockInfoLUKSSlotList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_QCryptoBlockInfoQCow(QCryptoBlockInfoQCow *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_QCryptoBlockInfoQCow(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_QCryptoBlockOpenOptions(QCryptoBlockOpenOptions *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_QCryptoBlockOpenOptions(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_QCryptoBlockOptionsBase(QCryptoBlockOptionsBase *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_QCryptoBlockOptionsBase(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_QCryptoBlockOptionsLUKS(QCryptoBlockOptionsLUKS *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_QCryptoBlockOptionsLUKS(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_QCryptoBlockOptionsQCow(QCryptoBlockOptionsQCow *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_QCryptoBlockOptionsQCow(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const QCryptoCipherAlgorithm_lookup[] = {
    [QCRYPTO_CIPHER_ALG_AES_128] = "aes-128",
    [QCRYPTO_CIPHER_ALG_AES_192] = "aes-192",
    [QCRYPTO_CIPHER_ALG_AES_256] = "aes-256",
    [QCRYPTO_CIPHER_ALG_DES_RFB] = "des-rfb",
    [QCRYPTO_CIPHER_ALG_3DES] = "3des",
    [QCRYPTO_CIPHER_ALG_CAST5_128] = "cast5-128",
    [QCRYPTO_CIPHER_ALG_SERPENT_128] = "serpent-128",
    [QCRYPTO_CIPHER_ALG_SERPENT_192] = "serpent-192",
    [QCRYPTO_CIPHER_ALG_SERPENT_256] = "serpent-256",
    [QCRYPTO_CIPHER_ALG_TWOFISH_128] = "twofish-128",
    [QCRYPTO_CIPHER_ALG_TWOFISH_192] = "twofish-192",
    [QCRYPTO_CIPHER_ALG_TWOFISH_256] = "twofish-256",
    [QCRYPTO_CIPHER_ALG__MAX] = NULL,
};

const char *const QCryptoCipherMode_lookup[] = {
    [QCRYPTO_CIPHER_MODE_ECB] = "ecb",
    [QCRYPTO_CIPHER_MODE_CBC] = "cbc",
    [QCRYPTO_CIPHER_MODE_XTS] = "xts",
    [QCRYPTO_CIPHER_MODE_CTR] = "ctr",
    [QCRYPTO_CIPHER_MODE__MAX] = NULL,
};

const char *const QCryptoHashAlgorithm_lookup[] = {
    [QCRYPTO_HASH_ALG_MD5] = "md5",
    [QCRYPTO_HASH_ALG_SHA1] = "sha1",
    [QCRYPTO_HASH_ALG_SHA224] = "sha224",
    [QCRYPTO_HASH_ALG_SHA256] = "sha256",
    [QCRYPTO_HASH_ALG_SHA384] = "sha384",
    [QCRYPTO_HASH_ALG_SHA512] = "sha512",
    [QCRYPTO_HASH_ALG_RIPEMD160] = "ripemd160",
    [QCRYPTO_HASH_ALG__MAX] = NULL,
};

const char *const QCryptoIVGenAlgorithm_lookup[] = {
    [QCRYPTO_IVGEN_ALG_PLAIN] = "plain",
    [QCRYPTO_IVGEN_ALG_PLAIN64] = "plain64",
    [QCRYPTO_IVGEN_ALG_ESSIV] = "essiv",
    [QCRYPTO_IVGEN_ALG__MAX] = NULL,
};

const char *const QCryptoSecretFormat_lookup[] = {
    [QCRYPTO_SECRET_FORMAT_RAW] = "raw",
    [QCRYPTO_SECRET_FORMAT_BASE64] = "base64",
    [QCRYPTO_SECRET_FORMAT__MAX] = NULL,
};

const char *const QCryptoTLSCredsEndpoint_lookup[] = {
    [QCRYPTO_TLS_CREDS_ENDPOINT_CLIENT] = "client",
    [QCRYPTO_TLS_CREDS_ENDPOINT_SERVER] = "server",
    [QCRYPTO_TLS_CREDS_ENDPOINT__MAX] = NULL,
};

const char *const QKeyCode_lookup[] = {
    [Q_KEY_CODE_UNMAPPED] = "unmapped",
    [Q_KEY_CODE_SHIFT] = "shift",
    [Q_KEY_CODE_SHIFT_R] = "shift_r",
    [Q_KEY_CODE_ALT] = "alt",
    [Q_KEY_CODE_ALT_R] = "alt_r",
    [Q_KEY_CODE_ALTGR] = "altgr",
    [Q_KEY_CODE_ALTGR_R] = "altgr_r",
    [Q_KEY_CODE_CTRL] = "ctrl",
    [Q_KEY_CODE_CTRL_R] = "ctrl_r",
    [Q_KEY_CODE_MENU] = "menu",
    [Q_KEY_CODE_ESC] = "esc",
    [Q_KEY_CODE_1] = "1",
    [Q_KEY_CODE_2] = "2",
    [Q_KEY_CODE_3] = "3",
    [Q_KEY_CODE_4] = "4",
    [Q_KEY_CODE_5] = "5",
    [Q_KEY_CODE_6] = "6",
    [Q_KEY_CODE_7] = "7",
    [Q_KEY_CODE_8] = "8",
    [Q_KEY_CODE_9] = "9",
    [Q_KEY_CODE_0] = "0",
    [Q_KEY_CODE_MINUS] = "minus",
    [Q_KEY_CODE_EQUAL] = "equal",
    [Q_KEY_CODE_BACKSPACE] = "backspace",
    [Q_KEY_CODE_TAB] = "tab",
    [Q_KEY_CODE_Q] = "q",
    [Q_KEY_CODE_W] = "w",
    [Q_KEY_CODE_E] = "e",
    [Q_KEY_CODE_R] = "r",
    [Q_KEY_CODE_T] = "t",
    [Q_KEY_CODE_Y] = "y",
    [Q_KEY_CODE_U] = "u",
    [Q_KEY_CODE_I] = "i",
    [Q_KEY_CODE_O] = "o",
    [Q_KEY_CODE_P] = "p",
    [Q_KEY_CODE_BRACKET_LEFT] = "bracket_left",
    [Q_KEY_CODE_BRACKET_RIGHT] = "bracket_right",
    [Q_KEY_CODE_RET] = "ret",
    [Q_KEY_CODE_A] = "a",
    [Q_KEY_CODE_S] = "s",
    [Q_KEY_CODE_D] = "d",
    [Q_KEY_CODE_F] = "f",
    [Q_KEY_CODE_G] = "g",
    [Q_KEY_CODE_H] = "h",
    [Q_KEY_CODE_J] = "j",
    [Q_KEY_CODE_K] = "k",
    [Q_KEY_CODE_L] = "l",
    [Q_KEY_CODE_SEMICOLON] = "semicolon",
    [Q_KEY_CODE_APOSTROPHE] = "apostrophe",
    [Q_KEY_CODE_GRAVE_ACCENT] = "grave_accent",
    [Q_KEY_CODE_BACKSLASH] = "backslash",
    [Q_KEY_CODE_Z] = "z",
    [Q_KEY_CODE_X] = "x",
    [Q_KEY_CODE_C] = "c",
    [Q_KEY_CODE_V] = "v",
    [Q_KEY_CODE_B] = "b",
    [Q_KEY_CODE_N] = "n",
    [Q_KEY_CODE_M] = "m",
    [Q_KEY_CODE_COMMA] = "comma",
    [Q_KEY_CODE_DOT] = "dot",
    [Q_KEY_CODE_SLASH] = "slash",
    [Q_KEY_CODE_ASTERISK] = "asterisk",
    [Q_KEY_CODE_SPC] = "spc",
    [Q_KEY_CODE_CAPS_LOCK] = "caps_lock",
    [Q_KEY_CODE_F1] = "f1",
    [Q_KEY_CODE_F2] = "f2",
    [Q_KEY_CODE_F3] = "f3",
    [Q_KEY_CODE_F4] = "f4",
    [Q_KEY_CODE_F5] = "f5",
    [Q_KEY_CODE_F6] = "f6",
    [Q_KEY_CODE_F7] = "f7",
    [Q_KEY_CODE_F8] = "f8",
    [Q_KEY_CODE_F9] = "f9",
    [Q_KEY_CODE_F10] = "f10",
    [Q_KEY_CODE_NUM_LOCK] = "num_lock",
    [Q_KEY_CODE_SCROLL_LOCK] = "scroll_lock",
    [Q_KEY_CODE_KP_DIVIDE] = "kp_divide",
    [Q_KEY_CODE_KP_MULTIPLY] = "kp_multiply",
    [Q_KEY_CODE_KP_SUBTRACT] = "kp_subtract",
    [Q_KEY_CODE_KP_ADD] = "kp_add",
    [Q_KEY_CODE_KP_ENTER] = "kp_enter",
    [Q_KEY_CODE_KP_DECIMAL] = "kp_decimal",
    [Q_KEY_CODE_SYSRQ] = "sysrq",
    [Q_KEY_CODE_KP_0] = "kp_0",
    [Q_KEY_CODE_KP_1] = "kp_1",
    [Q_KEY_CODE_KP_2] = "kp_2",
    [Q_KEY_CODE_KP_3] = "kp_3",
    [Q_KEY_CODE_KP_4] = "kp_4",
    [Q_KEY_CODE_KP_5] = "kp_5",
    [Q_KEY_CODE_KP_6] = "kp_6",
    [Q_KEY_CODE_KP_7] = "kp_7",
    [Q_KEY_CODE_KP_8] = "kp_8",
    [Q_KEY_CODE_KP_9] = "kp_9",
    [Q_KEY_CODE_LESS] = "less",
    [Q_KEY_CODE_F11] = "f11",
    [Q_KEY_CODE_F12] = "f12",
    [Q_KEY_CODE_PRINT] = "print",
    [Q_KEY_CODE_HOME] = "home",
    [Q_KEY_CODE_PGUP] = "pgup",
    [Q_KEY_CODE_PGDN] = "pgdn",
    [Q_KEY_CODE_END] = "end",
    [Q_KEY_CODE_LEFT] = "left",
    [Q_KEY_CODE_UP] = "up",
    [Q_KEY_CODE_DOWN] = "down",
    [Q_KEY_CODE_RIGHT] = "right",
    [Q_KEY_CODE_INSERT] = "insert",
    [Q_KEY_CODE_DELETE] = "delete",
    [Q_KEY_CODE_STOP] = "stop",
    [Q_KEY_CODE_AGAIN] = "again",
    [Q_KEY_CODE_PROPS] = "props",
    [Q_KEY_CODE_UNDO] = "undo",
    [Q_KEY_CODE_FRONT] = "front",
    [Q_KEY_CODE_COPY] = "copy",
    [Q_KEY_CODE_OPEN] = "open",
    [Q_KEY_CODE_PASTE] = "paste",
    [Q_KEY_CODE_FIND] = "find",
    [Q_KEY_CODE_CUT] = "cut",
    [Q_KEY_CODE_LF] = "lf",
    [Q_KEY_CODE_HELP] = "help",
    [Q_KEY_CODE_META_L] = "meta_l",
    [Q_KEY_CODE_META_R] = "meta_r",
    [Q_KEY_CODE_COMPOSE] = "compose",
    [Q_KEY_CODE_PAUSE] = "pause",
    [Q_KEY_CODE_RO] = "ro",
    [Q_KEY_CODE_HIRAGANA] = "hiragana",
    [Q_KEY_CODE_HENKAN] = "henkan",
    [Q_KEY_CODE_YEN] = "yen",
    [Q_KEY_CODE_KP_COMMA] = "kp_comma",
    [Q_KEY_CODE_KP_EQUALS] = "kp_equals",
    [Q_KEY_CODE_POWER] = "power",
    [Q_KEY_CODE__MAX] = NULL,
};

const char *const QType_lookup[] = {
    [QTYPE_NONE] = "none",
    [QTYPE_QNULL] = "qnull",
    [QTYPE_QINT] = "qint",
    [QTYPE_QSTRING] = "qstring",
    [QTYPE_QDICT] = "qdict",
    [QTYPE_QLIST] = "qlist",
    [QTYPE_QFLOAT] = "qfloat",
    [QTYPE_QBOOL] = "qbool",
    [QTYPE__MAX] = NULL,
};

const char *const QapiErrorClass_lookup[] = {
    [QAPI_ERROR_CLASS_GENERICERROR] = "GenericError",
    [QAPI_ERROR_CLASS_COMMANDNOTFOUND] = "CommandNotFound",
    [QAPI_ERROR_CLASS_DEVICEENCRYPTED] = "DeviceEncrypted",
    [QAPI_ERROR_CLASS_DEVICENOTACTIVE] = "DeviceNotActive",
    [QAPI_ERROR_CLASS_DEVICENOTFOUND] = "DeviceNotFound",
    [QAPI_ERROR_CLASS_KVMMISSINGCAP] = "KVMMissingCap",
    [QAPI_ERROR_CLASS__MAX] = NULL,
};

void qapi_free_Qcow2OverlapCheckFlags(Qcow2OverlapCheckFlags *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_Qcow2OverlapCheckFlags(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const Qcow2OverlapCheckMode_lookup[] = {
    [QCOW2_OVERLAP_CHECK_MODE_NONE] = "none",
    [QCOW2_OVERLAP_CHECK_MODE_CONSTANT] = "constant",
    [QCOW2_OVERLAP_CHECK_MODE_CACHED] = "cached",
    [QCOW2_OVERLAP_CHECK_MODE_ALL] = "all",
    [QCOW2_OVERLAP_CHECK_MODE__MAX] = NULL,
};

void qapi_free_Qcow2OverlapChecks(Qcow2OverlapChecks *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_Qcow2OverlapChecks(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const QuorumOpType_lookup[] = {
    [QUORUM_OP_TYPE_READ] = "read",
    [QUORUM_OP_TYPE_WRITE] = "write",
    [QUORUM_OP_TYPE_FLUSH] = "flush",
    [QUORUM_OP_TYPE__MAX] = NULL,
};

const char *const QuorumReadPattern_lookup[] = {
    [QUORUM_READ_PATTERN_QUORUM] = "quorum",
    [QUORUM_READ_PATTERN_FIFO] = "fifo",
    [QUORUM_READ_PATTERN__MAX] = NULL,
};

const char *const ReplayMode_lookup[] = {
    [REPLAY_MODE_NONE] = "none",
    [REPLAY_MODE_RECORD] = "record",
    [REPLAY_MODE_PLAY] = "play",
    [REPLAY_MODE__MAX] = NULL,
};

const char *const ReplicationMode_lookup[] = {
    [REPLICATION_MODE_PRIMARY] = "primary",
    [REPLICATION_MODE_SECONDARY] = "secondary",
    [REPLICATION_MODE__MAX] = NULL,
};

void qapi_free_ReplicationStatus(ReplicationStatus *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_ReplicationStatus(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_RockerOfDpaFlow(RockerOfDpaFlow *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_RockerOfDpaFlow(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_RockerOfDpaFlowAction(RockerOfDpaFlowAction *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_RockerOfDpaFlowAction(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_RockerOfDpaFlowKey(RockerOfDpaFlowKey *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_RockerOfDpaFlowKey(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_RockerOfDpaFlowList(RockerOfDpaFlowList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_RockerOfDpaFlowList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_RockerOfDpaFlowMask(RockerOfDpaFlowMask *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_RockerOfDpaFlowMask(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_RockerOfDpaGroup(RockerOfDpaGroup *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_RockerOfDpaGroup(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_RockerOfDpaGroupList(RockerOfDpaGroupList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_RockerOfDpaGroupList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_RockerPort(RockerPort *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_RockerPort(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const RockerPortAutoneg_lookup[] = {
    [ROCKER_PORT_AUTONEG_OFF] = "off",
    [ROCKER_PORT_AUTONEG_ON] = "on",
    [ROCKER_PORT_AUTONEG__MAX] = NULL,
};

const char *const RockerPortDuplex_lookup[] = {
    [ROCKER_PORT_DUPLEX_HALF] = "half",
    [ROCKER_PORT_DUPLEX_FULL] = "full",
    [ROCKER_PORT_DUPLEX__MAX] = NULL,
};

void qapi_free_RockerPortList(RockerPortList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_RockerPortList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_RockerSwitch(RockerSwitch *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_RockerSwitch(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const RunState_lookup[] = {
    [RUN_STATE_DEBUG] = "debug",
    [RUN_STATE_INMIGRATE] = "inmigrate",
    [RUN_STATE_INTERNAL_ERROR] = "internal-error",
    [RUN_STATE_IO_ERROR] = "io-error",
    [RUN_STATE_PAUSED] = "paused",
    [RUN_STATE_POSTMIGRATE] = "postmigrate",
    [RUN_STATE_PRELAUNCH] = "prelaunch",
    [RUN_STATE_FINISH_MIGRATE] = "finish-migrate",
    [RUN_STATE_RESTORE_VM] = "restore-vm",
    [RUN_STATE_RUNNING] = "running",
    [RUN_STATE_SAVE_VM] = "save-vm",
    [RUN_STATE_SHUTDOWN] = "shutdown",
    [RUN_STATE_SUSPENDED] = "suspended",
    [RUN_STATE_WATCHDOG] = "watchdog",
    [RUN_STATE_GUEST_PANICKED] = "guest-panicked",
    [RUN_STATE_COLO] = "colo",
    [RUN_STATE__MAX] = NULL,
};

void qapi_free_RxFilterInfo(RxFilterInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_RxFilterInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_RxFilterInfoList(RxFilterInfoList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_RxFilterInfoList(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const RxState_lookup[] = {
    [RX_STATE_NORMAL] = "normal",
    [RX_STATE_NONE] = "none",
    [RX_STATE_ALL] = "all",
    [RX_STATE__MAX] = NULL,
};

void qapi_free_SchemaInfo(SchemaInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_SchemaInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_SchemaInfoAlternate(SchemaInfoAlternate *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_SchemaInfoAlternate(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_SchemaInfoAlternateMember(SchemaInfoAlternateMember *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_SchemaInfoAlternateMember(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_SchemaInfoAlternateMemberList(SchemaInfoAlternateMemberList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_SchemaInfoAlternateMemberList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_SchemaInfoArray(SchemaInfoArray *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_SchemaInfoArray(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_SchemaInfoBuiltin(SchemaInfoBuiltin *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_SchemaInfoBuiltin(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_SchemaInfoCommand(SchemaInfoCommand *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_SchemaInfoCommand(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_SchemaInfoEnum(SchemaInfoEnum *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_SchemaInfoEnum(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_SchemaInfoEvent(SchemaInfoEvent *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_SchemaInfoEvent(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_SchemaInfoList(SchemaInfoList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_SchemaInfoList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_SchemaInfoObject(SchemaInfoObject *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_SchemaInfoObject(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_SchemaInfoObjectMember(SchemaInfoObjectMember *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_SchemaInfoObjectMember(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_SchemaInfoObjectMemberList(SchemaInfoObjectMemberList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_SchemaInfoObjectMemberList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_SchemaInfoObjectVariant(SchemaInfoObjectVariant *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_SchemaInfoObjectVariant(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_SchemaInfoObjectVariantList(SchemaInfoObjectVariantList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_SchemaInfoObjectVariantList(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const SchemaMetaType_lookup[] = {
    [SCHEMA_META_TYPE_BUILTIN] = "builtin",
    [SCHEMA_META_TYPE_ENUM] = "enum",
    [SCHEMA_META_TYPE_ARRAY] = "array",
    [SCHEMA_META_TYPE_OBJECT] = "object",
    [SCHEMA_META_TYPE_ALTERNATE] = "alternate",
    [SCHEMA_META_TYPE_COMMAND] = "command",
    [SCHEMA_META_TYPE_EVENT] = "event",
    [SCHEMA_META_TYPE__MAX] = NULL,
};

void qapi_free_SnapshotInfo(SnapshotInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_SnapshotInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_SnapshotInfoList(SnapshotInfoList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_SnapshotInfoList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_SocketAddress(SocketAddress *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_SocketAddress(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_SocketAddressFlat(SocketAddressFlat *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_SocketAddressFlat(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_SocketAddressFlatList(SocketAddressFlatList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_SocketAddressFlatList(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const SocketAddressFlatType_lookup[] = {
    [SOCKET_ADDRESS_FLAT_TYPE_INET] = "inet",
    [SOCKET_ADDRESS_FLAT_TYPE_UNIX] = "unix",
    [SOCKET_ADDRESS_FLAT_TYPE_VSOCK] = "vsock",
    [SOCKET_ADDRESS_FLAT_TYPE_FD] = "fd",
    [SOCKET_ADDRESS_FLAT_TYPE__MAX] = NULL,
};

const char *const SocketAddressKind_lookup[] = {
    [SOCKET_ADDRESS_KIND_INET] = "inet",
    [SOCKET_ADDRESS_KIND_UNIX] = "unix",
    [SOCKET_ADDRESS_KIND_VSOCK] = "vsock",
    [SOCKET_ADDRESS_KIND_FD] = "fd",
    [SOCKET_ADDRESS_KIND__MAX] = NULL,
};

void qapi_free_SpiceBasicInfo(SpiceBasicInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_SpiceBasicInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_SpiceChannel(SpiceChannel *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_SpiceChannel(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_SpiceChannelList(SpiceChannelList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_SpiceChannelList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_SpiceInfo(SpiceInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_SpiceInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const SpiceQueryMouseMode_lookup[] = {
    [SPICE_QUERY_MOUSE_MODE_CLIENT] = "client",
    [SPICE_QUERY_MOUSE_MODE_SERVER] = "server",
    [SPICE_QUERY_MOUSE_MODE_UNKNOWN] = "unknown",
    [SPICE_QUERY_MOUSE_MODE__MAX] = NULL,
};

void qapi_free_SpiceServerInfo(SpiceServerInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_SpiceServerInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_StatusInfo(StatusInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_StatusInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_String(String *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_String(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_StringList(StringList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_StringList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_TPMInfo(TPMInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_TPMInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_TPMInfoList(TPMInfoList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_TPMInfoList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_TPMPassthroughOptions(TPMPassthroughOptions *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_TPMPassthroughOptions(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_TargetInfo(TargetInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_TargetInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const TpmModel_lookup[] = {
    [TPM_MODEL_TPM_TIS] = "tpm-tis",
    [TPM_MODEL__MAX] = NULL,
};

void qapi_free_TpmModelList(TpmModelList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_TpmModelList(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const TpmType_lookup[] = {
    [TPM_TYPE_PASSTHROUGH] = "passthrough",
    [TPM_TYPE__MAX] = NULL,
};

void qapi_free_TpmTypeList(TpmTypeList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_TpmTypeList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_TpmTypeOptions(TpmTypeOptions *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_TpmTypeOptions(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const TpmTypeOptionsKind_lookup[] = {
    [TPM_TYPE_OPTIONS_KIND_PASSTHROUGH] = "passthrough",
    [TPM_TYPE_OPTIONS_KIND__MAX] = NULL,
};

void qapi_free_TraceEventInfo(TraceEventInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_TraceEventInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_TraceEventInfoList(TraceEventInfoList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_TraceEventInfoList(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const TraceEventState_lookup[] = {
    [TRACE_EVENT_STATE_UNAVAILABLE] = "unavailable",
    [TRACE_EVENT_STATE_DISABLED] = "disabled",
    [TRACE_EVENT_STATE_ENABLED] = "enabled",
    [TRACE_EVENT_STATE__MAX] = NULL,
};

void qapi_free_TransactionAction(TransactionAction *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_TransactionAction(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const TransactionActionKind_lookup[] = {
    [TRANSACTION_ACTION_KIND_ABORT] = "abort",
    [TRANSACTION_ACTION_KIND_BLOCK_DIRTY_BITMAP_ADD] = "block-dirty-bitmap-add",
    [TRANSACTION_ACTION_KIND_BLOCK_DIRTY_BITMAP_CLEAR] = "block-dirty-bitmap-clear",
    [TRANSACTION_ACTION_KIND_BLOCKDEV_BACKUP] = "blockdev-backup",
    [TRANSACTION_ACTION_KIND_BLOCKDEV_SNAPSHOT] = "blockdev-snapshot",
    [TRANSACTION_ACTION_KIND_BLOCKDEV_SNAPSHOT_INTERNAL_SYNC] = "blockdev-snapshot-internal-sync",
    [TRANSACTION_ACTION_KIND_BLOCKDEV_SNAPSHOT_SYNC] = "blockdev-snapshot-sync",
    [TRANSACTION_ACTION_KIND_DRIVE_BACKUP] = "drive-backup",
    [TRANSACTION_ACTION_KIND__MAX] = NULL,
};

void qapi_free_TransactionActionList(TransactionActionList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_TransactionActionList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_TransactionProperties(TransactionProperties *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_TransactionProperties(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_UnixSocketAddress(UnixSocketAddress *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_UnixSocketAddress(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_UuidInfo(UuidInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_UuidInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_VersionInfo(VersionInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_VersionInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_VersionTriple(VersionTriple *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_VersionTriple(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_VncBasicInfo(VncBasicInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_VncBasicInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_VncClientInfo(VncClientInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_VncClientInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_VncClientInfoList(VncClientInfoList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_VncClientInfoList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_VncInfo(VncInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_VncInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_VncInfo2(VncInfo2 *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_VncInfo2(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_VncInfo2List(VncInfo2List *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_VncInfo2List(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const VncPrimaryAuth_lookup[] = {
    [VNC_PRIMARY_AUTH_NONE] = "none",
    [VNC_PRIMARY_AUTH_VNC] = "vnc",
    [VNC_PRIMARY_AUTH_RA2] = "ra2",
    [VNC_PRIMARY_AUTH_RA2NE] = "ra2ne",
    [VNC_PRIMARY_AUTH_TIGHT] = "tight",
    [VNC_PRIMARY_AUTH_ULTRA] = "ultra",
    [VNC_PRIMARY_AUTH_TLS] = "tls",
    [VNC_PRIMARY_AUTH_VENCRYPT] = "vencrypt",
    [VNC_PRIMARY_AUTH_SASL] = "sasl",
    [VNC_PRIMARY_AUTH__MAX] = NULL,
};

void qapi_free_VncServerInfo(VncServerInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_VncServerInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_VncServerInfo2(VncServerInfo2 *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_VncServerInfo2(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_VncServerInfo2List(VncServerInfo2List *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_VncServerInfo2List(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const VncVencryptSubAuth_lookup[] = {
    [VNC_VENCRYPT_SUB_AUTH_PLAIN] = "plain",
    [VNC_VENCRYPT_SUB_AUTH_TLS_NONE] = "tls-none",
    [VNC_VENCRYPT_SUB_AUTH_X509_NONE] = "x509-none",
    [VNC_VENCRYPT_SUB_AUTH_TLS_VNC] = "tls-vnc",
    [VNC_VENCRYPT_SUB_AUTH_X509_VNC] = "x509-vnc",
    [VNC_VENCRYPT_SUB_AUTH_TLS_PLAIN] = "tls-plain",
    [VNC_VENCRYPT_SUB_AUTH_X509_PLAIN] = "x509-plain",
    [VNC_VENCRYPT_SUB_AUTH_TLS_SASL] = "tls-sasl",
    [VNC_VENCRYPT_SUB_AUTH_X509_SASL] = "x509-sasl",
    [VNC_VENCRYPT_SUB_AUTH__MAX] = NULL,
};

void qapi_free_VsockSocketAddress(VsockSocketAddress *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_VsockSocketAddress(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const WatchdogExpirationAction_lookup[] = {
    [WATCHDOG_EXPIRATION_ACTION_RESET] = "reset",
    [WATCHDOG_EXPIRATION_ACTION_SHUTDOWN] = "shutdown",
    [WATCHDOG_EXPIRATION_ACTION_POWEROFF] = "poweroff",
    [WATCHDOG_EXPIRATION_ACTION_PAUSE] = "pause",
    [WATCHDOG_EXPIRATION_ACTION_DEBUG] = "debug",
    [WATCHDOG_EXPIRATION_ACTION_NONE] = "none",
    [WATCHDOG_EXPIRATION_ACTION_INJECT_NMI] = "inject-nmi",
    [WATCHDOG_EXPIRATION_ACTION__MAX] = NULL,
};

void qapi_free_X86CPUFeatureWordInfo(X86CPUFeatureWordInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_X86CPUFeatureWordInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_X86CPUFeatureWordInfoList(X86CPUFeatureWordInfoList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_X86CPUFeatureWordInfoList(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const X86CPURegister32_lookup[] = {
    [X86_CPU_REGISTER32_EAX] = "EAX",
    [X86_CPU_REGISTER32_EBX] = "EBX",
    [X86_CPU_REGISTER32_ECX] = "ECX",
    [X86_CPU_REGISTER32_EDX] = "EDX",
    [X86_CPU_REGISTER32_ESP] = "ESP",
    [X86_CPU_REGISTER32_EBP] = "EBP",
    [X86_CPU_REGISTER32_ESI] = "ESI",
    [X86_CPU_REGISTER32_EDI] = "EDI",
    [X86_CPU_REGISTER32__MAX] = NULL,
};

void qapi_free_XBZRLECacheStats(XBZRLECacheStats *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_XBZRLECacheStats(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_anyList(anyList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_anyList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_boolList(boolList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_boolList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_int16List(int16List *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_int16List(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_int32List(int32List *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_int32List(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_int64List(int64List *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_int64List(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_int8List(int8List *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_int8List(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_intList(intList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_intList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_numberList(numberList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_numberList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_sizeList(sizeList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_sizeList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_strList(strList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_strList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_uint16List(uint16List *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_uint16List(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_uint32List(uint32List *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_uint32List(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_uint64List(uint64List *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_uint64List(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_uint8List(uint8List *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_uint8List(v, NULL, &obj, NULL);
    visit_free(v);
}
