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
#include "qga-qapi-types.h"
#include "qga-qapi-visit.h"

void qapi_free_GuestAgentCommandInfo(GuestAgentCommandInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_GuestAgentCommandInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_GuestAgentCommandInfoList(GuestAgentCommandInfoList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_GuestAgentCommandInfoList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_GuestAgentInfo(GuestAgentInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_GuestAgentInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_GuestDiskAddress(GuestDiskAddress *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_GuestDiskAddress(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_GuestDiskAddressList(GuestDiskAddressList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_GuestDiskAddressList(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const GuestDiskBusType_lookup[] = {
    [GUEST_DISK_BUS_TYPE_IDE] = "ide",
    [GUEST_DISK_BUS_TYPE_FDC] = "fdc",
    [GUEST_DISK_BUS_TYPE_SCSI] = "scsi",
    [GUEST_DISK_BUS_TYPE_VIRTIO] = "virtio",
    [GUEST_DISK_BUS_TYPE_XEN] = "xen",
    [GUEST_DISK_BUS_TYPE_USB] = "usb",
    [GUEST_DISK_BUS_TYPE_UML] = "uml",
    [GUEST_DISK_BUS_TYPE_SATA] = "sata",
    [GUEST_DISK_BUS_TYPE_SD] = "sd",
    [GUEST_DISK_BUS_TYPE_UNKNOWN] = "unknown",
    [GUEST_DISK_BUS_TYPE_IEEE1394] = "ieee1394",
    [GUEST_DISK_BUS_TYPE_SSA] = "ssa",
    [GUEST_DISK_BUS_TYPE_FIBRE] = "fibre",
    [GUEST_DISK_BUS_TYPE_RAID] = "raid",
    [GUEST_DISK_BUS_TYPE_ISCSI] = "iscsi",
    [GUEST_DISK_BUS_TYPE_SAS] = "sas",
    [GUEST_DISK_BUS_TYPE_MMC] = "mmc",
    [GUEST_DISK_BUS_TYPE_VIRTUAL] = "virtual",
    [GUEST_DISK_BUS_TYPE_FILE_BACKED_VIRTUAL] = "file-backed-virtual",
    [GUEST_DISK_BUS_TYPE__MAX] = NULL,
};

void qapi_free_GuestExec(GuestExec *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_GuestExec(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_GuestExecStatus(GuestExecStatus *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_GuestExecStatus(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_GuestFileRead(GuestFileRead *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_GuestFileRead(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_GuestFileSeek(GuestFileSeek *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_GuestFileSeek(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_GuestFileWhence(GuestFileWhence *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_GuestFileWhence(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_GuestFileWrite(GuestFileWrite *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_GuestFileWrite(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_GuestFilesystemInfo(GuestFilesystemInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_GuestFilesystemInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_GuestFilesystemInfoList(GuestFilesystemInfoList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_GuestFilesystemInfoList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_GuestFilesystemTrimResponse(GuestFilesystemTrimResponse *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_GuestFilesystemTrimResponse(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_GuestFilesystemTrimResult(GuestFilesystemTrimResult *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_GuestFilesystemTrimResult(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_GuestFilesystemTrimResultList(GuestFilesystemTrimResultList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_GuestFilesystemTrimResultList(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const GuestFsfreezeStatus_lookup[] = {
    [GUEST_FSFREEZE_STATUS_THAWED] = "thawed",
    [GUEST_FSFREEZE_STATUS_FROZEN] = "frozen",
    [GUEST_FSFREEZE_STATUS__MAX] = NULL,
};

void qapi_free_GuestIpAddress(GuestIpAddress *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_GuestIpAddress(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_GuestIpAddressList(GuestIpAddressList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_GuestIpAddressList(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const GuestIpAddressType_lookup[] = {
    [GUEST_IP_ADDRESS_TYPE_IPV4] = "ipv4",
    [GUEST_IP_ADDRESS_TYPE_IPV6] = "ipv6",
    [GUEST_IP_ADDRESS_TYPE__MAX] = NULL,
};

void qapi_free_GuestLogicalProcessor(GuestLogicalProcessor *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_GuestLogicalProcessor(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_GuestLogicalProcessorList(GuestLogicalProcessorList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_GuestLogicalProcessorList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_GuestMemoryBlock(GuestMemoryBlock *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_GuestMemoryBlock(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_GuestMemoryBlockInfo(GuestMemoryBlockInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_GuestMemoryBlockInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_GuestMemoryBlockList(GuestMemoryBlockList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_GuestMemoryBlockList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_GuestMemoryBlockResponse(GuestMemoryBlockResponse *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_GuestMemoryBlockResponse(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_GuestMemoryBlockResponseList(GuestMemoryBlockResponseList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_GuestMemoryBlockResponseList(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const GuestMemoryBlockResponseType_lookup[] = {
    [GUEST_MEMORY_BLOCK_RESPONSE_TYPE_SUCCESS] = "success",
    [GUEST_MEMORY_BLOCK_RESPONSE_TYPE_NOT_FOUND] = "not-found",
    [GUEST_MEMORY_BLOCK_RESPONSE_TYPE_OPERATION_NOT_SUPPORTED] = "operation-not-supported",
    [GUEST_MEMORY_BLOCK_RESPONSE_TYPE_OPERATION_FAILED] = "operation-failed",
    [GUEST_MEMORY_BLOCK_RESPONSE_TYPE__MAX] = NULL,
};

void qapi_free_GuestNetworkInterface(GuestNetworkInterface *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_GuestNetworkInterface(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_GuestNetworkInterfaceList(GuestNetworkInterfaceList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_GuestNetworkInterfaceList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_GuestPCIAddress(GuestPCIAddress *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_GuestPCIAddress(v, NULL, &obj, NULL);
    visit_free(v);
}

const char *const QGASeek_lookup[] = {
    [QGA_SEEK_SET] = "set",
    [QGA_SEEK_CUR] = "cur",
    [QGA_SEEK_END] = "end",
    [QGA_SEEK__MAX] = NULL,
};
