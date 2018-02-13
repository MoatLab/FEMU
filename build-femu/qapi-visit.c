/* AUTOMATICALLY GENERATED, DO NOT MODIFY */

/*
 * schema-defined QAPI visitor functions
 *
 * Copyright IBM, Corp. 2011
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qapi/error.h"
#include "qapi-visit.h"

void visit_type_ACPIOSTInfo_members(Visitor *v, ACPIOSTInfo *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "device", &obj->has_device)) {
        visit_type_str(v, "device", &obj->device, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_str(v, "slot", &obj->slot, &err);
    if (err) {
        goto out;
    }
    visit_type_ACPISlotType(v, "slot-type", &obj->slot_type, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "source", &obj->source, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "status", &obj->status, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_ACPIOSTInfo(Visitor *v, const char *name, ACPIOSTInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(ACPIOSTInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_ACPIOSTInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_ACPIOSTInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_ACPIOSTInfoList(Visitor *v, const char *name, ACPIOSTInfoList **obj, Error **errp)
{
    Error *err = NULL;
    ACPIOSTInfoList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (ACPIOSTInfoList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_ACPIOSTInfo(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_ACPIOSTInfoList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_ACPISlotType(Visitor *v, const char *name, ACPISlotType *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, ACPISlotType_lookup, errp);
    *obj = value;
}

void visit_type_Abort_members(Visitor *v, Abort *obj, Error **errp)
{
    Error *err = NULL;

    error_propagate(errp, err);
}

void visit_type_Abort(Visitor *v, const char *name, Abort **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(Abort), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_Abort_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_Abort(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_AcpiTableOptions_members(Visitor *v, AcpiTableOptions *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "sig", &obj->has_sig)) {
        visit_type_str(v, "sig", &obj->sig, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "rev", &obj->has_rev)) {
        visit_type_uint8(v, "rev", &obj->rev, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "oem_id", &obj->has_oem_id)) {
        visit_type_str(v, "oem_id", &obj->oem_id, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "oem_table_id", &obj->has_oem_table_id)) {
        visit_type_str(v, "oem_table_id", &obj->oem_table_id, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "oem_rev", &obj->has_oem_rev)) {
        visit_type_uint32(v, "oem_rev", &obj->oem_rev, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "asl_compiler_id", &obj->has_asl_compiler_id)) {
        visit_type_str(v, "asl_compiler_id", &obj->asl_compiler_id, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "asl_compiler_rev", &obj->has_asl_compiler_rev)) {
        visit_type_uint32(v, "asl_compiler_rev", &obj->asl_compiler_rev, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "file", &obj->has_file)) {
        visit_type_str(v, "file", &obj->file, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "data", &obj->has_data)) {
        visit_type_str(v, "data", &obj->data, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_AcpiTableOptions(Visitor *v, const char *name, AcpiTableOptions **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(AcpiTableOptions), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_AcpiTableOptions_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_AcpiTableOptions(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_ActionCompletionMode(Visitor *v, const char *name, ActionCompletionMode *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, ActionCompletionMode_lookup, errp);
    *obj = value;
}

void visit_type_AddfdInfo_members(Visitor *v, AddfdInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, "fdset-id", &obj->fdset_id, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "fd", &obj->fd, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_AddfdInfo(Visitor *v, const char *name, AddfdInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(AddfdInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_AddfdInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_AddfdInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BalloonInfo_members(Visitor *v, BalloonInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, "actual", &obj->actual, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_BalloonInfo(Visitor *v, const char *name, BalloonInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BalloonInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BalloonInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BalloonInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BiosAtaTranslation(Visitor *v, const char *name, BiosAtaTranslation *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, BiosAtaTranslation_lookup, errp);
    *obj = value;
}

void visit_type_BlkdebugEvent(Visitor *v, const char *name, BlkdebugEvent *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, BlkdebugEvent_lookup, errp);
    *obj = value;
}

void visit_type_BlkdebugInjectErrorOptions_members(Visitor *v, BlkdebugInjectErrorOptions *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_BlkdebugEvent(v, "event", &obj->event, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "state", &obj->has_state)) {
        visit_type_int(v, "state", &obj->state, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "errno", &obj->has_q_errno)) {
        visit_type_int(v, "errno", &obj->q_errno, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "sector", &obj->has_sector)) {
        visit_type_int(v, "sector", &obj->sector, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "once", &obj->has_once)) {
        visit_type_bool(v, "once", &obj->once, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "immediately", &obj->has_immediately)) {
        visit_type_bool(v, "immediately", &obj->immediately, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlkdebugInjectErrorOptions(Visitor *v, const char *name, BlkdebugInjectErrorOptions **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlkdebugInjectErrorOptions), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlkdebugInjectErrorOptions_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlkdebugInjectErrorOptions(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlkdebugInjectErrorOptionsList(Visitor *v, const char *name, BlkdebugInjectErrorOptionsList **obj, Error **errp)
{
    Error *err = NULL;
    BlkdebugInjectErrorOptionsList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (BlkdebugInjectErrorOptionsList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_BlkdebugInjectErrorOptions(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlkdebugInjectErrorOptionsList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlkdebugSetStateOptions_members(Visitor *v, BlkdebugSetStateOptions *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_BlkdebugEvent(v, "event", &obj->event, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "state", &obj->has_state)) {
        visit_type_int(v, "state", &obj->state, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_int(v, "new_state", &obj->new_state, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlkdebugSetStateOptions(Visitor *v, const char *name, BlkdebugSetStateOptions **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlkdebugSetStateOptions), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlkdebugSetStateOptions_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlkdebugSetStateOptions(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlkdebugSetStateOptionsList(Visitor *v, const char *name, BlkdebugSetStateOptionsList **obj, Error **errp)
{
    Error *err = NULL;
    BlkdebugSetStateOptionsList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (BlkdebugSetStateOptionsList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_BlkdebugSetStateOptions(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlkdebugSetStateOptionsList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockDeviceInfo_members(Visitor *v, BlockDeviceInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "file", &obj->file, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "node-name", &obj->has_node_name)) {
        visit_type_str(v, "node-name", &obj->node_name, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_bool(v, "ro", &obj->ro, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "drv", &obj->drv, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "backing_file", &obj->has_backing_file)) {
        visit_type_str(v, "backing_file", &obj->backing_file, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_int(v, "backing_file_depth", &obj->backing_file_depth, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "encrypted", &obj->encrypted, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "encryption_key_missing", &obj->encryption_key_missing, &err);
    if (err) {
        goto out;
    }
    visit_type_BlockdevDetectZeroesOptions(v, "detect_zeroes", &obj->detect_zeroes, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "bps", &obj->bps, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "bps_rd", &obj->bps_rd, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "bps_wr", &obj->bps_wr, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "iops", &obj->iops, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "iops_rd", &obj->iops_rd, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "iops_wr", &obj->iops_wr, &err);
    if (err) {
        goto out;
    }
    visit_type_ImageInfo(v, "image", &obj->image, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "bps_max", &obj->has_bps_max)) {
        visit_type_int(v, "bps_max", &obj->bps_max, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "bps_rd_max", &obj->has_bps_rd_max)) {
        visit_type_int(v, "bps_rd_max", &obj->bps_rd_max, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "bps_wr_max", &obj->has_bps_wr_max)) {
        visit_type_int(v, "bps_wr_max", &obj->bps_wr_max, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "iops_max", &obj->has_iops_max)) {
        visit_type_int(v, "iops_max", &obj->iops_max, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "iops_rd_max", &obj->has_iops_rd_max)) {
        visit_type_int(v, "iops_rd_max", &obj->iops_rd_max, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "iops_wr_max", &obj->has_iops_wr_max)) {
        visit_type_int(v, "iops_wr_max", &obj->iops_wr_max, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "bps_max_length", &obj->has_bps_max_length)) {
        visit_type_int(v, "bps_max_length", &obj->bps_max_length, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "bps_rd_max_length", &obj->has_bps_rd_max_length)) {
        visit_type_int(v, "bps_rd_max_length", &obj->bps_rd_max_length, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "bps_wr_max_length", &obj->has_bps_wr_max_length)) {
        visit_type_int(v, "bps_wr_max_length", &obj->bps_wr_max_length, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "iops_max_length", &obj->has_iops_max_length)) {
        visit_type_int(v, "iops_max_length", &obj->iops_max_length, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "iops_rd_max_length", &obj->has_iops_rd_max_length)) {
        visit_type_int(v, "iops_rd_max_length", &obj->iops_rd_max_length, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "iops_wr_max_length", &obj->has_iops_wr_max_length)) {
        visit_type_int(v, "iops_wr_max_length", &obj->iops_wr_max_length, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "iops_size", &obj->has_iops_size)) {
        visit_type_int(v, "iops_size", &obj->iops_size, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "group", &obj->has_group)) {
        visit_type_str(v, "group", &obj->group, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_BlockdevCacheInfo(v, "cache", &obj->cache, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "write_threshold", &obj->write_threshold, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockDeviceInfo(Visitor *v, const char *name, BlockDeviceInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockDeviceInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockDeviceInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockDeviceInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockDeviceInfoList(Visitor *v, const char *name, BlockDeviceInfoList **obj, Error **errp)
{
    Error *err = NULL;
    BlockDeviceInfoList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (BlockDeviceInfoList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_BlockDeviceInfo(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockDeviceInfoList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockDeviceIoStatus(Visitor *v, const char *name, BlockDeviceIoStatus *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, BlockDeviceIoStatus_lookup, errp);
    *obj = value;
}

void visit_type_BlockDeviceMapEntry_members(Visitor *v, BlockDeviceMapEntry *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, "start", &obj->start, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "length", &obj->length, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "depth", &obj->depth, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "zero", &obj->zero, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "data", &obj->data, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "offset", &obj->has_offset)) {
        visit_type_int(v, "offset", &obj->offset, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockDeviceMapEntry(Visitor *v, const char *name, BlockDeviceMapEntry **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockDeviceMapEntry), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockDeviceMapEntry_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockDeviceMapEntry(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockDeviceStats_members(Visitor *v, BlockDeviceStats *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, "rd_bytes", &obj->rd_bytes, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "wr_bytes", &obj->wr_bytes, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "rd_operations", &obj->rd_operations, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "wr_operations", &obj->wr_operations, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "flush_operations", &obj->flush_operations, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "flush_total_time_ns", &obj->flush_total_time_ns, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "wr_total_time_ns", &obj->wr_total_time_ns, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "rd_total_time_ns", &obj->rd_total_time_ns, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "wr_highest_offset", &obj->wr_highest_offset, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "rd_merged", &obj->rd_merged, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "wr_merged", &obj->wr_merged, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "idle_time_ns", &obj->has_idle_time_ns)) {
        visit_type_int(v, "idle_time_ns", &obj->idle_time_ns, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_int(v, "failed_rd_operations", &obj->failed_rd_operations, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "failed_wr_operations", &obj->failed_wr_operations, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "failed_flush_operations", &obj->failed_flush_operations, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "invalid_rd_operations", &obj->invalid_rd_operations, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "invalid_wr_operations", &obj->invalid_wr_operations, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "invalid_flush_operations", &obj->invalid_flush_operations, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "account_invalid", &obj->account_invalid, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "account_failed", &obj->account_failed, &err);
    if (err) {
        goto out;
    }
    visit_type_BlockDeviceTimedStatsList(v, "timed_stats", &obj->timed_stats, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockDeviceStats(Visitor *v, const char *name, BlockDeviceStats **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockDeviceStats), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockDeviceStats_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockDeviceStats(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockDeviceTimedStats_members(Visitor *v, BlockDeviceTimedStats *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, "interval_length", &obj->interval_length, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "min_rd_latency_ns", &obj->min_rd_latency_ns, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "max_rd_latency_ns", &obj->max_rd_latency_ns, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "avg_rd_latency_ns", &obj->avg_rd_latency_ns, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "min_wr_latency_ns", &obj->min_wr_latency_ns, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "max_wr_latency_ns", &obj->max_wr_latency_ns, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "avg_wr_latency_ns", &obj->avg_wr_latency_ns, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "min_flush_latency_ns", &obj->min_flush_latency_ns, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "max_flush_latency_ns", &obj->max_flush_latency_ns, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "avg_flush_latency_ns", &obj->avg_flush_latency_ns, &err);
    if (err) {
        goto out;
    }
    visit_type_number(v, "avg_rd_queue_depth", &obj->avg_rd_queue_depth, &err);
    if (err) {
        goto out;
    }
    visit_type_number(v, "avg_wr_queue_depth", &obj->avg_wr_queue_depth, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockDeviceTimedStats(Visitor *v, const char *name, BlockDeviceTimedStats **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockDeviceTimedStats), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockDeviceTimedStats_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockDeviceTimedStats(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockDeviceTimedStatsList(Visitor *v, const char *name, BlockDeviceTimedStatsList **obj, Error **errp)
{
    Error *err = NULL;
    BlockDeviceTimedStatsList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (BlockDeviceTimedStatsList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_BlockDeviceTimedStats(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockDeviceTimedStatsList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockDirtyBitmap_members(Visitor *v, BlockDirtyBitmap *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "node", &obj->node, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "name", &obj->name, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockDirtyBitmap(Visitor *v, const char *name, BlockDirtyBitmap **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockDirtyBitmap), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockDirtyBitmap_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockDirtyBitmap(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockDirtyBitmapAdd_members(Visitor *v, BlockDirtyBitmapAdd *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "node", &obj->node, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "name", &obj->name, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "granularity", &obj->has_granularity)) {
        visit_type_uint32(v, "granularity", &obj->granularity, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockDirtyBitmapAdd(Visitor *v, const char *name, BlockDirtyBitmapAdd **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockDirtyBitmapAdd), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockDirtyBitmapAdd_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockDirtyBitmapAdd(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockDirtyInfo_members(Visitor *v, BlockDirtyInfo *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "name", &obj->has_name)) {
        visit_type_str(v, "name", &obj->name, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_int(v, "count", &obj->count, &err);
    if (err) {
        goto out;
    }
    visit_type_uint32(v, "granularity", &obj->granularity, &err);
    if (err) {
        goto out;
    }
    visit_type_DirtyBitmapStatus(v, "status", &obj->status, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockDirtyInfo(Visitor *v, const char *name, BlockDirtyInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockDirtyInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockDirtyInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockDirtyInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockDirtyInfoList(Visitor *v, const char *name, BlockDirtyInfoList **obj, Error **errp)
{
    Error *err = NULL;
    BlockDirtyInfoList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (BlockDirtyInfoList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_BlockDirtyInfo(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockDirtyInfoList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockErrorAction(Visitor *v, const char *name, BlockErrorAction *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, BlockErrorAction_lookup, errp);
    *obj = value;
}

void visit_type_BlockIOThrottle_members(Visitor *v, BlockIOThrottle *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "device", &obj->has_device)) {
        visit_type_str(v, "device", &obj->device, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "id", &obj->has_id)) {
        visit_type_str(v, "id", &obj->id, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_int(v, "bps", &obj->bps, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "bps_rd", &obj->bps_rd, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "bps_wr", &obj->bps_wr, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "iops", &obj->iops, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "iops_rd", &obj->iops_rd, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "iops_wr", &obj->iops_wr, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "bps_max", &obj->has_bps_max)) {
        visit_type_int(v, "bps_max", &obj->bps_max, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "bps_rd_max", &obj->has_bps_rd_max)) {
        visit_type_int(v, "bps_rd_max", &obj->bps_rd_max, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "bps_wr_max", &obj->has_bps_wr_max)) {
        visit_type_int(v, "bps_wr_max", &obj->bps_wr_max, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "iops_max", &obj->has_iops_max)) {
        visit_type_int(v, "iops_max", &obj->iops_max, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "iops_rd_max", &obj->has_iops_rd_max)) {
        visit_type_int(v, "iops_rd_max", &obj->iops_rd_max, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "iops_wr_max", &obj->has_iops_wr_max)) {
        visit_type_int(v, "iops_wr_max", &obj->iops_wr_max, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "bps_max_length", &obj->has_bps_max_length)) {
        visit_type_int(v, "bps_max_length", &obj->bps_max_length, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "bps_rd_max_length", &obj->has_bps_rd_max_length)) {
        visit_type_int(v, "bps_rd_max_length", &obj->bps_rd_max_length, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "bps_wr_max_length", &obj->has_bps_wr_max_length)) {
        visit_type_int(v, "bps_wr_max_length", &obj->bps_wr_max_length, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "iops_max_length", &obj->has_iops_max_length)) {
        visit_type_int(v, "iops_max_length", &obj->iops_max_length, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "iops_rd_max_length", &obj->has_iops_rd_max_length)) {
        visit_type_int(v, "iops_rd_max_length", &obj->iops_rd_max_length, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "iops_wr_max_length", &obj->has_iops_wr_max_length)) {
        visit_type_int(v, "iops_wr_max_length", &obj->iops_wr_max_length, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "iops_size", &obj->has_iops_size)) {
        visit_type_int(v, "iops_size", &obj->iops_size, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "group", &obj->has_group)) {
        visit_type_str(v, "group", &obj->group, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockIOThrottle(Visitor *v, const char *name, BlockIOThrottle **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockIOThrottle), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockIOThrottle_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockIOThrottle(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockInfo_members(Visitor *v, BlockInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "device", &obj->device, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "type", &obj->type, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "removable", &obj->removable, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "locked", &obj->locked, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "inserted", &obj->has_inserted)) {
        visit_type_BlockDeviceInfo(v, "inserted", &obj->inserted, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "tray_open", &obj->has_tray_open)) {
        visit_type_bool(v, "tray_open", &obj->tray_open, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "io-status", &obj->has_io_status)) {
        visit_type_BlockDeviceIoStatus(v, "io-status", &obj->io_status, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "dirty-bitmaps", &obj->has_dirty_bitmaps)) {
        visit_type_BlockDirtyInfoList(v, "dirty-bitmaps", &obj->dirty_bitmaps, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockInfo(Visitor *v, const char *name, BlockInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockInfoList(Visitor *v, const char *name, BlockInfoList **obj, Error **errp)
{
    Error *err = NULL;
    BlockInfoList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (BlockInfoList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_BlockInfo(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockInfoList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockJobInfo_members(Visitor *v, BlockJobInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "type", &obj->type, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "device", &obj->device, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "len", &obj->len, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "offset", &obj->offset, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "busy", &obj->busy, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "paused", &obj->paused, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "speed", &obj->speed, &err);
    if (err) {
        goto out;
    }
    visit_type_BlockDeviceIoStatus(v, "io-status", &obj->io_status, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "ready", &obj->ready, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockJobInfo(Visitor *v, const char *name, BlockJobInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockJobInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockJobInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockJobInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockJobInfoList(Visitor *v, const char *name, BlockJobInfoList **obj, Error **errp)
{
    Error *err = NULL;
    BlockJobInfoList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (BlockJobInfoList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_BlockJobInfo(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockJobInfoList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockJobType(Visitor *v, const char *name, BlockJobType *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, BlockJobType_lookup, errp);
    *obj = value;
}

void visit_type_BlockStats_members(Visitor *v, BlockStats *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "device", &obj->has_device)) {
        visit_type_str(v, "device", &obj->device, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "node-name", &obj->has_node_name)) {
        visit_type_str(v, "node-name", &obj->node_name, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_BlockDeviceStats(v, "stats", &obj->stats, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "parent", &obj->has_parent)) {
        visit_type_BlockStats(v, "parent", &obj->parent, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "backing", &obj->has_backing)) {
        visit_type_BlockStats(v, "backing", &obj->backing, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockStats(Visitor *v, const char *name, BlockStats **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockStats), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockStats_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockStats(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockStatsList(Visitor *v, const char *name, BlockStatsList **obj, Error **errp)
{
    Error *err = NULL;
    BlockStatsList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (BlockStatsList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_BlockStats(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockStatsList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockdevAioOptions(Visitor *v, const char *name, BlockdevAioOptions *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, BlockdevAioOptions_lookup, errp);
    *obj = value;
}

void visit_type_BlockdevBackup_members(Visitor *v, BlockdevBackup *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "job-id", &obj->has_job_id)) {
        visit_type_str(v, "job-id", &obj->job_id, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_str(v, "device", &obj->device, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "target", &obj->target, &err);
    if (err) {
        goto out;
    }
    visit_type_MirrorSyncMode(v, "sync", &obj->sync, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "speed", &obj->has_speed)) {
        visit_type_int(v, "speed", &obj->speed, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "compress", &obj->has_compress)) {
        visit_type_bool(v, "compress", &obj->compress, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "on-source-error", &obj->has_on_source_error)) {
        visit_type_BlockdevOnError(v, "on-source-error", &obj->on_source_error, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "on-target-error", &obj->has_on_target_error)) {
        visit_type_BlockdevOnError(v, "on-target-error", &obj->on_target_error, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockdevBackup(Visitor *v, const char *name, BlockdevBackup **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockdevBackup), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockdevBackup_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockdevBackup(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockdevCacheInfo_members(Visitor *v, BlockdevCacheInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_bool(v, "writeback", &obj->writeback, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "direct", &obj->direct, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "no-flush", &obj->no_flush, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockdevCacheInfo(Visitor *v, const char *name, BlockdevCacheInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockdevCacheInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockdevCacheInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockdevCacheInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockdevCacheOptions_members(Visitor *v, BlockdevCacheOptions *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "direct", &obj->has_direct)) {
        visit_type_bool(v, "direct", &obj->direct, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "no-flush", &obj->has_no_flush)) {
        visit_type_bool(v, "no-flush", &obj->no_flush, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockdevCacheOptions(Visitor *v, const char *name, BlockdevCacheOptions **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockdevCacheOptions), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockdevCacheOptions_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockdevCacheOptions(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockdevChangeReadOnlyMode(Visitor *v, const char *name, BlockdevChangeReadOnlyMode *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, BlockdevChangeReadOnlyMode_lookup, errp);
    *obj = value;
}

void visit_type_BlockdevDetectZeroesOptions(Visitor *v, const char *name, BlockdevDetectZeroesOptions *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, BlockdevDetectZeroesOptions_lookup, errp);
    *obj = value;
}

void visit_type_BlockdevDiscardOptions(Visitor *v, const char *name, BlockdevDiscardOptions *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, BlockdevDiscardOptions_lookup, errp);
    *obj = value;
}

void visit_type_BlockdevDriver(Visitor *v, const char *name, BlockdevDriver *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, BlockdevDriver_lookup, errp);
    *obj = value;
}

void visit_type_BlockdevOnError(Visitor *v, const char *name, BlockdevOnError *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, BlockdevOnError_lookup, errp);
    *obj = value;
}

void visit_type_BlockdevOptions_members(Visitor *v, BlockdevOptions *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_q_obj_BlockdevOptions_base_members(v, (q_obj_BlockdevOptions_base *)obj, &err);
    if (err) {
        goto out;
    }
    switch (obj->driver) {
    case BLOCKDEV_DRIVER_BLKDEBUG:
        visit_type_BlockdevOptionsBlkdebug_members(v, &obj->u.blkdebug, &err);
        break;
    case BLOCKDEV_DRIVER_BLKVERIFY:
        visit_type_BlockdevOptionsBlkverify_members(v, &obj->u.blkverify, &err);
        break;
    case BLOCKDEV_DRIVER_BOCHS:
        visit_type_BlockdevOptionsGenericFormat_members(v, &obj->u.bochs, &err);
        break;
    case BLOCKDEV_DRIVER_CLOOP:
        visit_type_BlockdevOptionsGenericFormat_members(v, &obj->u.cloop, &err);
        break;
    case BLOCKDEV_DRIVER_DMG:
        visit_type_BlockdevOptionsGenericFormat_members(v, &obj->u.dmg, &err);
        break;
    case BLOCKDEV_DRIVER_FILE:
        visit_type_BlockdevOptionsFile_members(v, &obj->u.file, &err);
        break;
    case BLOCKDEV_DRIVER_FTP:
        visit_type_BlockdevOptionsCurlFtp_members(v, &obj->u.ftp, &err);
        break;
    case BLOCKDEV_DRIVER_FTPS:
        visit_type_BlockdevOptionsCurlFtps_members(v, &obj->u.ftps, &err);
        break;
    case BLOCKDEV_DRIVER_GLUSTER:
        visit_type_BlockdevOptionsGluster_members(v, &obj->u.gluster, &err);
        break;
    case BLOCKDEV_DRIVER_HOST_CDROM:
        visit_type_BlockdevOptionsFile_members(v, &obj->u.host_cdrom, &err);
        break;
    case BLOCKDEV_DRIVER_HOST_DEVICE:
        visit_type_BlockdevOptionsFile_members(v, &obj->u.host_device, &err);
        break;
    case BLOCKDEV_DRIVER_HTTP:
        visit_type_BlockdevOptionsCurlHttp_members(v, &obj->u.http, &err);
        break;
    case BLOCKDEV_DRIVER_HTTPS:
        visit_type_BlockdevOptionsCurlHttps_members(v, &obj->u.https, &err);
        break;
    case BLOCKDEV_DRIVER_ISCSI:
        visit_type_BlockdevOptionsIscsi_members(v, &obj->u.iscsi, &err);
        break;
    case BLOCKDEV_DRIVER_LUKS:
        visit_type_BlockdevOptionsLUKS_members(v, &obj->u.luks, &err);
        break;
    case BLOCKDEV_DRIVER_NBD:
        visit_type_BlockdevOptionsNbd_members(v, &obj->u.nbd, &err);
        break;
    case BLOCKDEV_DRIVER_NFS:
        visit_type_BlockdevOptionsNfs_members(v, &obj->u.nfs, &err);
        break;
    case BLOCKDEV_DRIVER_NULL_AIO:
        visit_type_BlockdevOptionsNull_members(v, &obj->u.null_aio, &err);
        break;
    case BLOCKDEV_DRIVER_NULL_CO:
        visit_type_BlockdevOptionsNull_members(v, &obj->u.null_co, &err);
        break;
    case BLOCKDEV_DRIVER_PARALLELS:
        visit_type_BlockdevOptionsGenericFormat_members(v, &obj->u.parallels, &err);
        break;
    case BLOCKDEV_DRIVER_QCOW2:
        visit_type_BlockdevOptionsQcow2_members(v, &obj->u.qcow2, &err);
        break;
    case BLOCKDEV_DRIVER_QCOW:
        visit_type_BlockdevOptionsGenericCOWFormat_members(v, &obj->u.qcow, &err);
        break;
    case BLOCKDEV_DRIVER_QED:
        visit_type_BlockdevOptionsGenericCOWFormat_members(v, &obj->u.qed, &err);
        break;
    case BLOCKDEV_DRIVER_QUORUM:
        visit_type_BlockdevOptionsQuorum_members(v, &obj->u.quorum, &err);
        break;
    case BLOCKDEV_DRIVER_RAW:
        visit_type_BlockdevOptionsRaw_members(v, &obj->u.raw, &err);
        break;
    case BLOCKDEV_DRIVER_RBD:
        visit_type_BlockdevOptionsRbd_members(v, &obj->u.rbd, &err);
        break;
    case BLOCKDEV_DRIVER_REPLICATION:
        visit_type_BlockdevOptionsReplication_members(v, &obj->u.replication, &err);
        break;
    case BLOCKDEV_DRIVER_SHEEPDOG:
        visit_type_BlockdevOptionsSheepdog_members(v, &obj->u.sheepdog, &err);
        break;
    case BLOCKDEV_DRIVER_SSH:
        visit_type_BlockdevOptionsSsh_members(v, &obj->u.ssh, &err);
        break;
    case BLOCKDEV_DRIVER_VDI:
        visit_type_BlockdevOptionsGenericFormat_members(v, &obj->u.vdi, &err);
        break;
    case BLOCKDEV_DRIVER_VHDX:
        visit_type_BlockdevOptionsGenericFormat_members(v, &obj->u.vhdx, &err);
        break;
    case BLOCKDEV_DRIVER_VMDK:
        visit_type_BlockdevOptionsGenericCOWFormat_members(v, &obj->u.vmdk, &err);
        break;
    case BLOCKDEV_DRIVER_VPC:
        visit_type_BlockdevOptionsGenericFormat_members(v, &obj->u.vpc, &err);
        break;
    case BLOCKDEV_DRIVER_VVFAT:
        visit_type_BlockdevOptionsVVFAT_members(v, &obj->u.vvfat, &err);
        break;
    default:
        abort();
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptions(Visitor *v, const char *name, BlockdevOptions **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockdevOptions), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockdevOptions_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockdevOptions(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsBlkdebug_members(Visitor *v, BlockdevOptionsBlkdebug *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_BlockdevRef(v, "image", &obj->image, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "config", &obj->has_config)) {
        visit_type_str(v, "config", &obj->config, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "align", &obj->has_align)) {
        visit_type_int(v, "align", &obj->align, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "inject-error", &obj->has_inject_error)) {
        visit_type_BlkdebugInjectErrorOptionsList(v, "inject-error", &obj->inject_error, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "set-state", &obj->has_set_state)) {
        visit_type_BlkdebugSetStateOptionsList(v, "set-state", &obj->set_state, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsBlkdebug(Visitor *v, const char *name, BlockdevOptionsBlkdebug **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockdevOptionsBlkdebug), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockdevOptionsBlkdebug_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockdevOptionsBlkdebug(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsBlkverify_members(Visitor *v, BlockdevOptionsBlkverify *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_BlockdevRef(v, "test", &obj->test, &err);
    if (err) {
        goto out;
    }
    visit_type_BlockdevRef(v, "raw", &obj->raw, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsBlkverify(Visitor *v, const char *name, BlockdevOptionsBlkverify **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockdevOptionsBlkverify), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockdevOptionsBlkverify_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockdevOptionsBlkverify(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsCurlBase_members(Visitor *v, BlockdevOptionsCurlBase *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "url", &obj->url, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "readahead", &obj->has_readahead)) {
        visit_type_int(v, "readahead", &obj->readahead, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "timeout", &obj->has_timeout)) {
        visit_type_int(v, "timeout", &obj->timeout, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "username", &obj->has_username)) {
        visit_type_str(v, "username", &obj->username, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "password-secret", &obj->has_password_secret)) {
        visit_type_str(v, "password-secret", &obj->password_secret, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "proxy-username", &obj->has_proxy_username)) {
        visit_type_str(v, "proxy-username", &obj->proxy_username, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "proxy-password-secret", &obj->has_proxy_password_secret)) {
        visit_type_str(v, "proxy-password-secret", &obj->proxy_password_secret, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsCurlBase(Visitor *v, const char *name, BlockdevOptionsCurlBase **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockdevOptionsCurlBase), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockdevOptionsCurlBase_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockdevOptionsCurlBase(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsCurlFtp_members(Visitor *v, BlockdevOptionsCurlFtp *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_BlockdevOptionsCurlBase_members(v, (BlockdevOptionsCurlBase *)obj, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsCurlFtp(Visitor *v, const char *name, BlockdevOptionsCurlFtp **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockdevOptionsCurlFtp), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockdevOptionsCurlFtp_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockdevOptionsCurlFtp(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsCurlFtps_members(Visitor *v, BlockdevOptionsCurlFtps *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_BlockdevOptionsCurlBase_members(v, (BlockdevOptionsCurlBase *)obj, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "sslverify", &obj->has_sslverify)) {
        visit_type_bool(v, "sslverify", &obj->sslverify, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsCurlFtps(Visitor *v, const char *name, BlockdevOptionsCurlFtps **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockdevOptionsCurlFtps), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockdevOptionsCurlFtps_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockdevOptionsCurlFtps(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsCurlHttp_members(Visitor *v, BlockdevOptionsCurlHttp *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_BlockdevOptionsCurlBase_members(v, (BlockdevOptionsCurlBase *)obj, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "cookie", &obj->has_cookie)) {
        visit_type_str(v, "cookie", &obj->cookie, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsCurlHttp(Visitor *v, const char *name, BlockdevOptionsCurlHttp **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockdevOptionsCurlHttp), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockdevOptionsCurlHttp_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockdevOptionsCurlHttp(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsCurlHttps_members(Visitor *v, BlockdevOptionsCurlHttps *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_BlockdevOptionsCurlBase_members(v, (BlockdevOptionsCurlBase *)obj, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "cookie", &obj->has_cookie)) {
        visit_type_str(v, "cookie", &obj->cookie, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "sslverify", &obj->has_sslverify)) {
        visit_type_bool(v, "sslverify", &obj->sslverify, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsCurlHttps(Visitor *v, const char *name, BlockdevOptionsCurlHttps **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockdevOptionsCurlHttps), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockdevOptionsCurlHttps_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockdevOptionsCurlHttps(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsFile_members(Visitor *v, BlockdevOptionsFile *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "filename", &obj->filename, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "aio", &obj->has_aio)) {
        visit_type_BlockdevAioOptions(v, "aio", &obj->aio, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsFile(Visitor *v, const char *name, BlockdevOptionsFile **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockdevOptionsFile), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockdevOptionsFile_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockdevOptionsFile(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsGenericCOWFormat_members(Visitor *v, BlockdevOptionsGenericCOWFormat *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_BlockdevOptionsGenericFormat_members(v, (BlockdevOptionsGenericFormat *)obj, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "backing", &obj->has_backing)) {
        visit_type_BlockdevRef(v, "backing", &obj->backing, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsGenericCOWFormat(Visitor *v, const char *name, BlockdevOptionsGenericCOWFormat **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockdevOptionsGenericCOWFormat), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockdevOptionsGenericCOWFormat_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockdevOptionsGenericCOWFormat(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsGenericFormat_members(Visitor *v, BlockdevOptionsGenericFormat *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_BlockdevRef(v, "file", &obj->file, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsGenericFormat(Visitor *v, const char *name, BlockdevOptionsGenericFormat **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockdevOptionsGenericFormat), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockdevOptionsGenericFormat_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockdevOptionsGenericFormat(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsGluster_members(Visitor *v, BlockdevOptionsGluster *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "volume", &obj->volume, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "path", &obj->path, &err);
    if (err) {
        goto out;
    }
    visit_type_SocketAddressFlatList(v, "server", &obj->server, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "debug", &obj->has_debug)) {
        visit_type_int(v, "debug", &obj->debug, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "logfile", &obj->has_logfile)) {
        visit_type_str(v, "logfile", &obj->logfile, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsGluster(Visitor *v, const char *name, BlockdevOptionsGluster **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockdevOptionsGluster), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockdevOptionsGluster_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockdevOptionsGluster(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsIscsi_members(Visitor *v, BlockdevOptionsIscsi *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_IscsiTransport(v, "transport", &obj->transport, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "portal", &obj->portal, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "target", &obj->target, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "lun", &obj->has_lun)) {
        visit_type_int(v, "lun", &obj->lun, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "user", &obj->has_user)) {
        visit_type_str(v, "user", &obj->user, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "password-secret", &obj->has_password_secret)) {
        visit_type_str(v, "password-secret", &obj->password_secret, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "initiator-name", &obj->has_initiator_name)) {
        visit_type_str(v, "initiator-name", &obj->initiator_name, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "header-digest", &obj->has_header_digest)) {
        visit_type_IscsiHeaderDigest(v, "header-digest", &obj->header_digest, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "timeout", &obj->has_timeout)) {
        visit_type_int(v, "timeout", &obj->timeout, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsIscsi(Visitor *v, const char *name, BlockdevOptionsIscsi **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockdevOptionsIscsi), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockdevOptionsIscsi_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockdevOptionsIscsi(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsLUKS_members(Visitor *v, BlockdevOptionsLUKS *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_BlockdevOptionsGenericFormat_members(v, (BlockdevOptionsGenericFormat *)obj, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "key-secret", &obj->has_key_secret)) {
        visit_type_str(v, "key-secret", &obj->key_secret, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsLUKS(Visitor *v, const char *name, BlockdevOptionsLUKS **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockdevOptionsLUKS), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockdevOptionsLUKS_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockdevOptionsLUKS(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsNbd_members(Visitor *v, BlockdevOptionsNbd *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_SocketAddressFlat(v, "server", &obj->server, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "export", &obj->has_export)) {
        visit_type_str(v, "export", &obj->export, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "tls-creds", &obj->has_tls_creds)) {
        visit_type_str(v, "tls-creds", &obj->tls_creds, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsNbd(Visitor *v, const char *name, BlockdevOptionsNbd **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockdevOptionsNbd), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockdevOptionsNbd_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockdevOptionsNbd(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsNfs_members(Visitor *v, BlockdevOptionsNfs *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_NFSServer(v, "server", &obj->server, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "path", &obj->path, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "user", &obj->has_user)) {
        visit_type_int(v, "user", &obj->user, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "group", &obj->has_group)) {
        visit_type_int(v, "group", &obj->group, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "tcp-syn-count", &obj->has_tcp_syn_count)) {
        visit_type_int(v, "tcp-syn-count", &obj->tcp_syn_count, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "readahead-size", &obj->has_readahead_size)) {
        visit_type_int(v, "readahead-size", &obj->readahead_size, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "page-cache-size", &obj->has_page_cache_size)) {
        visit_type_int(v, "page-cache-size", &obj->page_cache_size, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "debug", &obj->has_debug)) {
        visit_type_int(v, "debug", &obj->debug, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsNfs(Visitor *v, const char *name, BlockdevOptionsNfs **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockdevOptionsNfs), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockdevOptionsNfs_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockdevOptionsNfs(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsNull_members(Visitor *v, BlockdevOptionsNull *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "size", &obj->has_size)) {
        visit_type_int(v, "size", &obj->size, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "latency-ns", &obj->has_latency_ns)) {
        visit_type_uint64(v, "latency-ns", &obj->latency_ns, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsNull(Visitor *v, const char *name, BlockdevOptionsNull **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockdevOptionsNull), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockdevOptionsNull_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockdevOptionsNull(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsQcow2_members(Visitor *v, BlockdevOptionsQcow2 *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_BlockdevOptionsGenericCOWFormat_members(v, (BlockdevOptionsGenericCOWFormat *)obj, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "lazy-refcounts", &obj->has_lazy_refcounts)) {
        visit_type_bool(v, "lazy-refcounts", &obj->lazy_refcounts, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "pass-discard-request", &obj->has_pass_discard_request)) {
        visit_type_bool(v, "pass-discard-request", &obj->pass_discard_request, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "pass-discard-snapshot", &obj->has_pass_discard_snapshot)) {
        visit_type_bool(v, "pass-discard-snapshot", &obj->pass_discard_snapshot, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "pass-discard-other", &obj->has_pass_discard_other)) {
        visit_type_bool(v, "pass-discard-other", &obj->pass_discard_other, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "overlap-check", &obj->has_overlap_check)) {
        visit_type_Qcow2OverlapChecks(v, "overlap-check", &obj->overlap_check, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "cache-size", &obj->has_cache_size)) {
        visit_type_int(v, "cache-size", &obj->cache_size, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "l2-cache-size", &obj->has_l2_cache_size)) {
        visit_type_int(v, "l2-cache-size", &obj->l2_cache_size, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "refcount-cache-size", &obj->has_refcount_cache_size)) {
        visit_type_int(v, "refcount-cache-size", &obj->refcount_cache_size, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "cache-clean-interval", &obj->has_cache_clean_interval)) {
        visit_type_int(v, "cache-clean-interval", &obj->cache_clean_interval, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsQcow2(Visitor *v, const char *name, BlockdevOptionsQcow2 **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockdevOptionsQcow2), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockdevOptionsQcow2_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockdevOptionsQcow2(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsQuorum_members(Visitor *v, BlockdevOptionsQuorum *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "blkverify", &obj->has_blkverify)) {
        visit_type_bool(v, "blkverify", &obj->blkverify, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_BlockdevRefList(v, "children", &obj->children, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "vote-threshold", &obj->vote_threshold, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "rewrite-corrupted", &obj->has_rewrite_corrupted)) {
        visit_type_bool(v, "rewrite-corrupted", &obj->rewrite_corrupted, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "read-pattern", &obj->has_read_pattern)) {
        visit_type_QuorumReadPattern(v, "read-pattern", &obj->read_pattern, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsQuorum(Visitor *v, const char *name, BlockdevOptionsQuorum **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockdevOptionsQuorum), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockdevOptionsQuorum_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockdevOptionsQuorum(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsRaw_members(Visitor *v, BlockdevOptionsRaw *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_BlockdevOptionsGenericFormat_members(v, (BlockdevOptionsGenericFormat *)obj, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "offset", &obj->has_offset)) {
        visit_type_int(v, "offset", &obj->offset, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "size", &obj->has_size)) {
        visit_type_int(v, "size", &obj->size, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsRaw(Visitor *v, const char *name, BlockdevOptionsRaw **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockdevOptionsRaw), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockdevOptionsRaw_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockdevOptionsRaw(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsRbd_members(Visitor *v, BlockdevOptionsRbd *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "pool", &obj->pool, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "image", &obj->image, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "conf", &obj->has_conf)) {
        visit_type_str(v, "conf", &obj->conf, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "snapshot", &obj->has_snapshot)) {
        visit_type_str(v, "snapshot", &obj->snapshot, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "user", &obj->has_user)) {
        visit_type_str(v, "user", &obj->user, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "server", &obj->has_server)) {
        visit_type_InetSocketAddressBaseList(v, "server", &obj->server, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsRbd(Visitor *v, const char *name, BlockdevOptionsRbd **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockdevOptionsRbd), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockdevOptionsRbd_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockdevOptionsRbd(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsReplication_members(Visitor *v, BlockdevOptionsReplication *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_BlockdevOptionsGenericFormat_members(v, (BlockdevOptionsGenericFormat *)obj, &err);
    if (err) {
        goto out;
    }
    visit_type_ReplicationMode(v, "mode", &obj->mode, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "top-id", &obj->has_top_id)) {
        visit_type_str(v, "top-id", &obj->top_id, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsReplication(Visitor *v, const char *name, BlockdevOptionsReplication **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockdevOptionsReplication), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockdevOptionsReplication_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockdevOptionsReplication(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsSheepdog_members(Visitor *v, BlockdevOptionsSheepdog *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_SocketAddressFlat(v, "server", &obj->server, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "vdi", &obj->vdi, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "snap-id", &obj->has_snap_id)) {
        visit_type_uint32(v, "snap-id", &obj->snap_id, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "tag", &obj->has_tag)) {
        visit_type_str(v, "tag", &obj->tag, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsSheepdog(Visitor *v, const char *name, BlockdevOptionsSheepdog **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockdevOptionsSheepdog), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockdevOptionsSheepdog_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockdevOptionsSheepdog(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsSsh_members(Visitor *v, BlockdevOptionsSsh *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_InetSocketAddress(v, "server", &obj->server, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "path", &obj->path, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "user", &obj->has_user)) {
        visit_type_str(v, "user", &obj->user, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsSsh(Visitor *v, const char *name, BlockdevOptionsSsh **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockdevOptionsSsh), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockdevOptionsSsh_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockdevOptionsSsh(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsVVFAT_members(Visitor *v, BlockdevOptionsVVFAT *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "dir", &obj->dir, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "fat-type", &obj->has_fat_type)) {
        visit_type_int(v, "fat-type", &obj->fat_type, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "floppy", &obj->has_floppy)) {
        visit_type_bool(v, "floppy", &obj->floppy, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "label", &obj->has_label)) {
        visit_type_str(v, "label", &obj->label, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "rw", &obj->has_rw)) {
        visit_type_bool(v, "rw", &obj->rw, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockdevOptionsVVFAT(Visitor *v, const char *name, BlockdevOptionsVVFAT **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockdevOptionsVVFAT), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockdevOptionsVVFAT_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockdevOptionsVVFAT(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockdevRef(Visitor *v, const char *name, BlockdevRef **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_alternate(v, name, (GenericAlternate **)obj, sizeof(**obj),
                          true, &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    switch ((*obj)->type) {
    case QTYPE_QDICT:
        visit_start_struct(v, name, NULL, 0, &err);
        if (err) {
            break;
        }
        visit_type_BlockdevOptions_members(v, &(*obj)->u.definition, &err);
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        break;
    case QTYPE_QSTRING:
        visit_type_str(v, name, &(*obj)->u.reference, &err);
        break;
    case QTYPE_NONE:
        abort();
    default:
        error_setg(&err, QERR_INVALID_PARAMETER_TYPE, name ? name : "null",
                   "BlockdevRef");
    }
out_obj:
    visit_end_alternate(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockdevRef(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockdevRefList(Visitor *v, const char *name, BlockdevRefList **obj, Error **errp)
{
    Error *err = NULL;
    BlockdevRefList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (BlockdevRefList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_BlockdevRef(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockdevRefList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockdevSnapshot_members(Visitor *v, BlockdevSnapshot *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "node", &obj->node, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "overlay", &obj->overlay, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockdevSnapshot(Visitor *v, const char *name, BlockdevSnapshot **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockdevSnapshot), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockdevSnapshot_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockdevSnapshot(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockdevSnapshotInternal_members(Visitor *v, BlockdevSnapshotInternal *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "device", &obj->device, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "name", &obj->name, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockdevSnapshotInternal(Visitor *v, const char *name, BlockdevSnapshotInternal **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockdevSnapshotInternal), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockdevSnapshotInternal_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockdevSnapshotInternal(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_BlockdevSnapshotSync_members(Visitor *v, BlockdevSnapshotSync *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "device", &obj->has_device)) {
        visit_type_str(v, "device", &obj->device, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "node-name", &obj->has_node_name)) {
        visit_type_str(v, "node-name", &obj->node_name, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_str(v, "snapshot-file", &obj->snapshot_file, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "snapshot-node-name", &obj->has_snapshot_node_name)) {
        visit_type_str(v, "snapshot-node-name", &obj->snapshot_node_name, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "format", &obj->has_format)) {
        visit_type_str(v, "format", &obj->format, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "mode", &obj->has_mode)) {
        visit_type_NewImageMode(v, "mode", &obj->mode, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_BlockdevSnapshotSync(Visitor *v, const char *name, BlockdevSnapshotSync **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(BlockdevSnapshotSync), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_BlockdevSnapshotSync_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_BlockdevSnapshotSync(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_COLOMessage(Visitor *v, const char *name, COLOMessage *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, COLOMessage_lookup, errp);
    *obj = value;
}

void visit_type_COLOMode(Visitor *v, const char *name, COLOMode *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, COLOMode_lookup, errp);
    *obj = value;
}

void visit_type_ChardevBackend_members(Visitor *v, ChardevBackend *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_ChardevBackendKind(v, "type", &obj->type, &err);
    if (err) {
        goto out;
    }
    switch (obj->type) {
    case CHARDEV_BACKEND_KIND_FILE:
        visit_type_q_obj_ChardevFile_wrapper_members(v, &obj->u.file, &err);
        break;
    case CHARDEV_BACKEND_KIND_SERIAL:
        visit_type_q_obj_ChardevHostdev_wrapper_members(v, &obj->u.serial, &err);
        break;
    case CHARDEV_BACKEND_KIND_PARALLEL:
        visit_type_q_obj_ChardevHostdev_wrapper_members(v, &obj->u.parallel, &err);
        break;
    case CHARDEV_BACKEND_KIND_PIPE:
        visit_type_q_obj_ChardevHostdev_wrapper_members(v, &obj->u.pipe, &err);
        break;
    case CHARDEV_BACKEND_KIND_SOCKET:
        visit_type_q_obj_ChardevSocket_wrapper_members(v, &obj->u.socket, &err);
        break;
    case CHARDEV_BACKEND_KIND_UDP:
        visit_type_q_obj_ChardevUdp_wrapper_members(v, &obj->u.udp, &err);
        break;
    case CHARDEV_BACKEND_KIND_PTY:
        visit_type_q_obj_ChardevCommon_wrapper_members(v, &obj->u.pty, &err);
        break;
    case CHARDEV_BACKEND_KIND_NULL:
        visit_type_q_obj_ChardevCommon_wrapper_members(v, &obj->u.null, &err);
        break;
    case CHARDEV_BACKEND_KIND_MUX:
        visit_type_q_obj_ChardevMux_wrapper_members(v, &obj->u.mux, &err);
        break;
    case CHARDEV_BACKEND_KIND_MSMOUSE:
        visit_type_q_obj_ChardevCommon_wrapper_members(v, &obj->u.msmouse, &err);
        break;
    case CHARDEV_BACKEND_KIND_WCTABLET:
        visit_type_q_obj_ChardevCommon_wrapper_members(v, &obj->u.wctablet, &err);
        break;
    case CHARDEV_BACKEND_KIND_BRAILLE:
        visit_type_q_obj_ChardevCommon_wrapper_members(v, &obj->u.braille, &err);
        break;
    case CHARDEV_BACKEND_KIND_TESTDEV:
        visit_type_q_obj_ChardevCommon_wrapper_members(v, &obj->u.testdev, &err);
        break;
    case CHARDEV_BACKEND_KIND_STDIO:
        visit_type_q_obj_ChardevStdio_wrapper_members(v, &obj->u.stdio, &err);
        break;
    case CHARDEV_BACKEND_KIND_CONSOLE:
        visit_type_q_obj_ChardevCommon_wrapper_members(v, &obj->u.console, &err);
        break;
    case CHARDEV_BACKEND_KIND_SPICEVMC:
        visit_type_q_obj_ChardevSpiceChannel_wrapper_members(v, &obj->u.spicevmc, &err);
        break;
    case CHARDEV_BACKEND_KIND_SPICEPORT:
        visit_type_q_obj_ChardevSpicePort_wrapper_members(v, &obj->u.spiceport, &err);
        break;
    case CHARDEV_BACKEND_KIND_VC:
        visit_type_q_obj_ChardevVC_wrapper_members(v, &obj->u.vc, &err);
        break;
    case CHARDEV_BACKEND_KIND_RINGBUF:
        visit_type_q_obj_ChardevRingbuf_wrapper_members(v, &obj->u.ringbuf, &err);
        break;
    case CHARDEV_BACKEND_KIND_MEMORY:
        visit_type_q_obj_ChardevRingbuf_wrapper_members(v, &obj->u.memory, &err);
        break;
    default:
        abort();
    }

out:
    error_propagate(errp, err);
}

void visit_type_ChardevBackend(Visitor *v, const char *name, ChardevBackend **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(ChardevBackend), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_ChardevBackend_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_ChardevBackend(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_ChardevBackendInfo_members(Visitor *v, ChardevBackendInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "name", &obj->name, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_ChardevBackendInfo(Visitor *v, const char *name, ChardevBackendInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(ChardevBackendInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_ChardevBackendInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_ChardevBackendInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_ChardevBackendInfoList(Visitor *v, const char *name, ChardevBackendInfoList **obj, Error **errp)
{
    Error *err = NULL;
    ChardevBackendInfoList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (ChardevBackendInfoList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_ChardevBackendInfo(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_ChardevBackendInfoList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_ChardevBackendKind(Visitor *v, const char *name, ChardevBackendKind *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, ChardevBackendKind_lookup, errp);
    *obj = value;
}

void visit_type_ChardevCommon_members(Visitor *v, ChardevCommon *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "logfile", &obj->has_logfile)) {
        visit_type_str(v, "logfile", &obj->logfile, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "logappend", &obj->has_logappend)) {
        visit_type_bool(v, "logappend", &obj->logappend, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_ChardevCommon(Visitor *v, const char *name, ChardevCommon **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(ChardevCommon), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_ChardevCommon_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_ChardevCommon(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_ChardevFile_members(Visitor *v, ChardevFile *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_ChardevCommon_members(v, (ChardevCommon *)obj, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "in", &obj->has_in)) {
        visit_type_str(v, "in", &obj->in, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_str(v, "out", &obj->out, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "append", &obj->has_append)) {
        visit_type_bool(v, "append", &obj->append, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_ChardevFile(Visitor *v, const char *name, ChardevFile **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(ChardevFile), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_ChardevFile_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_ChardevFile(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_ChardevHostdev_members(Visitor *v, ChardevHostdev *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_ChardevCommon_members(v, (ChardevCommon *)obj, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "device", &obj->device, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_ChardevHostdev(Visitor *v, const char *name, ChardevHostdev **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(ChardevHostdev), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_ChardevHostdev_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_ChardevHostdev(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_ChardevInfo_members(Visitor *v, ChardevInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "label", &obj->label, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "filename", &obj->filename, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "frontend-open", &obj->frontend_open, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_ChardevInfo(Visitor *v, const char *name, ChardevInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(ChardevInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_ChardevInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_ChardevInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_ChardevInfoList(Visitor *v, const char *name, ChardevInfoList **obj, Error **errp)
{
    Error *err = NULL;
    ChardevInfoList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (ChardevInfoList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_ChardevInfo(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_ChardevInfoList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_ChardevMux_members(Visitor *v, ChardevMux *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_ChardevCommon_members(v, (ChardevCommon *)obj, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "chardev", &obj->chardev, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_ChardevMux(Visitor *v, const char *name, ChardevMux **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(ChardevMux), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_ChardevMux_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_ChardevMux(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_ChardevReturn_members(Visitor *v, ChardevReturn *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "pty", &obj->has_pty)) {
        visit_type_str(v, "pty", &obj->pty, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_ChardevReturn(Visitor *v, const char *name, ChardevReturn **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(ChardevReturn), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_ChardevReturn_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_ChardevReturn(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_ChardevRingbuf_members(Visitor *v, ChardevRingbuf *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_ChardevCommon_members(v, (ChardevCommon *)obj, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "size", &obj->has_size)) {
        visit_type_int(v, "size", &obj->size, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_ChardevRingbuf(Visitor *v, const char *name, ChardevRingbuf **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(ChardevRingbuf), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_ChardevRingbuf_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_ChardevRingbuf(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_ChardevSocket_members(Visitor *v, ChardevSocket *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_ChardevCommon_members(v, (ChardevCommon *)obj, &err);
    if (err) {
        goto out;
    }
    visit_type_SocketAddress(v, "addr", &obj->addr, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "tls-creds", &obj->has_tls_creds)) {
        visit_type_str(v, "tls-creds", &obj->tls_creds, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "server", &obj->has_server)) {
        visit_type_bool(v, "server", &obj->server, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "wait", &obj->has_wait)) {
        visit_type_bool(v, "wait", &obj->wait, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "nodelay", &obj->has_nodelay)) {
        visit_type_bool(v, "nodelay", &obj->nodelay, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "telnet", &obj->has_telnet)) {
        visit_type_bool(v, "telnet", &obj->telnet, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "reconnect", &obj->has_reconnect)) {
        visit_type_int(v, "reconnect", &obj->reconnect, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_ChardevSocket(Visitor *v, const char *name, ChardevSocket **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(ChardevSocket), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_ChardevSocket_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_ChardevSocket(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_ChardevSpiceChannel_members(Visitor *v, ChardevSpiceChannel *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_ChardevCommon_members(v, (ChardevCommon *)obj, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "type", &obj->type, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_ChardevSpiceChannel(Visitor *v, const char *name, ChardevSpiceChannel **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(ChardevSpiceChannel), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_ChardevSpiceChannel_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_ChardevSpiceChannel(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_ChardevSpicePort_members(Visitor *v, ChardevSpicePort *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_ChardevCommon_members(v, (ChardevCommon *)obj, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "fqdn", &obj->fqdn, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_ChardevSpicePort(Visitor *v, const char *name, ChardevSpicePort **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(ChardevSpicePort), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_ChardevSpicePort_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_ChardevSpicePort(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_ChardevStdio_members(Visitor *v, ChardevStdio *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_ChardevCommon_members(v, (ChardevCommon *)obj, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "signal", &obj->has_signal)) {
        visit_type_bool(v, "signal", &obj->signal, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_ChardevStdio(Visitor *v, const char *name, ChardevStdio **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(ChardevStdio), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_ChardevStdio_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_ChardevStdio(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_ChardevUdp_members(Visitor *v, ChardevUdp *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_ChardevCommon_members(v, (ChardevCommon *)obj, &err);
    if (err) {
        goto out;
    }
    visit_type_SocketAddress(v, "remote", &obj->remote, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "local", &obj->has_local)) {
        visit_type_SocketAddress(v, "local", &obj->local, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_ChardevUdp(Visitor *v, const char *name, ChardevUdp **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(ChardevUdp), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_ChardevUdp_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_ChardevUdp(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_ChardevVC_members(Visitor *v, ChardevVC *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_ChardevCommon_members(v, (ChardevCommon *)obj, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "width", &obj->has_width)) {
        visit_type_int(v, "width", &obj->width, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "height", &obj->has_height)) {
        visit_type_int(v, "height", &obj->height, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "cols", &obj->has_cols)) {
        visit_type_int(v, "cols", &obj->cols, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "rows", &obj->has_rows)) {
        visit_type_int(v, "rows", &obj->rows, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_ChardevVC(Visitor *v, const char *name, ChardevVC **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(ChardevVC), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_ChardevVC_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_ChardevVC(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_CommandInfo_members(Visitor *v, CommandInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "name", &obj->name, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_CommandInfo(Visitor *v, const char *name, CommandInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(CommandInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_CommandInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_CommandInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_CommandInfoList(Visitor *v, const char *name, CommandInfoList **obj, Error **errp)
{
    Error *err = NULL;
    CommandInfoList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (CommandInfoList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_CommandInfo(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_CommandInfoList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_CommandLineOptionInfo_members(Visitor *v, CommandLineOptionInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "option", &obj->option, &err);
    if (err) {
        goto out;
    }
    visit_type_CommandLineParameterInfoList(v, "parameters", &obj->parameters, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_CommandLineOptionInfo(Visitor *v, const char *name, CommandLineOptionInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(CommandLineOptionInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_CommandLineOptionInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_CommandLineOptionInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_CommandLineOptionInfoList(Visitor *v, const char *name, CommandLineOptionInfoList **obj, Error **errp)
{
    Error *err = NULL;
    CommandLineOptionInfoList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (CommandLineOptionInfoList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_CommandLineOptionInfo(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_CommandLineOptionInfoList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_CommandLineParameterInfo_members(Visitor *v, CommandLineParameterInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "name", &obj->name, &err);
    if (err) {
        goto out;
    }
    visit_type_CommandLineParameterType(v, "type", &obj->type, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "help", &obj->has_help)) {
        visit_type_str(v, "help", &obj->help, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "default", &obj->has_q_default)) {
        visit_type_str(v, "default", &obj->q_default, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_CommandLineParameterInfo(Visitor *v, const char *name, CommandLineParameterInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(CommandLineParameterInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_CommandLineParameterInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_CommandLineParameterInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_CommandLineParameterInfoList(Visitor *v, const char *name, CommandLineParameterInfoList **obj, Error **errp)
{
    Error *err = NULL;
    CommandLineParameterInfoList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (CommandLineParameterInfoList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_CommandLineParameterInfo(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_CommandLineParameterInfoList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_CommandLineParameterType(Visitor *v, const char *name, CommandLineParameterType *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, CommandLineParameterType_lookup, errp);
    *obj = value;
}

void visit_type_CpuDefinitionInfo_members(Visitor *v, CpuDefinitionInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "name", &obj->name, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "migration-safe", &obj->has_migration_safe)) {
        visit_type_bool(v, "migration-safe", &obj->migration_safe, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_bool(v, "static", &obj->q_static, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "unavailable-features", &obj->has_unavailable_features)) {
        visit_type_strList(v, "unavailable-features", &obj->unavailable_features, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_str(v, "typename", &obj->q_typename, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_CpuDefinitionInfo(Visitor *v, const char *name, CpuDefinitionInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(CpuDefinitionInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_CpuDefinitionInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_CpuDefinitionInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_CpuDefinitionInfoList(Visitor *v, const char *name, CpuDefinitionInfoList **obj, Error **errp)
{
    Error *err = NULL;
    CpuDefinitionInfoList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (CpuDefinitionInfoList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_CpuDefinitionInfo(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_CpuDefinitionInfoList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_CpuInfo_members(Visitor *v, CpuInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_q_obj_CpuInfo_base_members(v, (q_obj_CpuInfo_base *)obj, &err);
    if (err) {
        goto out;
    }
    switch (obj->arch) {
    case CPU_INFO_ARCH_X86:
        visit_type_CpuInfoX86_members(v, &obj->u.x86, &err);
        break;
    case CPU_INFO_ARCH_SPARC:
        visit_type_CpuInfoSPARC_members(v, &obj->u.q_sparc, &err);
        break;
    case CPU_INFO_ARCH_PPC:
        visit_type_CpuInfoPPC_members(v, &obj->u.ppc, &err);
        break;
    case CPU_INFO_ARCH_MIPS:
        visit_type_CpuInfoMIPS_members(v, &obj->u.q_mips, &err);
        break;
    case CPU_INFO_ARCH_TRICORE:
        visit_type_CpuInfoTricore_members(v, &obj->u.tricore, &err);
        break;
    case CPU_INFO_ARCH_OTHER:
        visit_type_CpuInfoOther_members(v, &obj->u.other, &err);
        break;
    default:
        abort();
    }

out:
    error_propagate(errp, err);
}

void visit_type_CpuInfo(Visitor *v, const char *name, CpuInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(CpuInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_CpuInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_CpuInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_CpuInfoArch(Visitor *v, const char *name, CpuInfoArch *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, CpuInfoArch_lookup, errp);
    *obj = value;
}

void visit_type_CpuInfoList(Visitor *v, const char *name, CpuInfoList **obj, Error **errp)
{
    Error *err = NULL;
    CpuInfoList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (CpuInfoList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_CpuInfo(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_CpuInfoList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_CpuInfoMIPS_members(Visitor *v, CpuInfoMIPS *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, "PC", &obj->PC, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_CpuInfoMIPS(Visitor *v, const char *name, CpuInfoMIPS **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(CpuInfoMIPS), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_CpuInfoMIPS_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_CpuInfoMIPS(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_CpuInfoOther_members(Visitor *v, CpuInfoOther *obj, Error **errp)
{
    Error *err = NULL;

    error_propagate(errp, err);
}

void visit_type_CpuInfoOther(Visitor *v, const char *name, CpuInfoOther **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(CpuInfoOther), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_CpuInfoOther_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_CpuInfoOther(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_CpuInfoPPC_members(Visitor *v, CpuInfoPPC *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, "nip", &obj->nip, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_CpuInfoPPC(Visitor *v, const char *name, CpuInfoPPC **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(CpuInfoPPC), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_CpuInfoPPC_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_CpuInfoPPC(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_CpuInfoSPARC_members(Visitor *v, CpuInfoSPARC *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, "pc", &obj->pc, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "npc", &obj->npc, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_CpuInfoSPARC(Visitor *v, const char *name, CpuInfoSPARC **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(CpuInfoSPARC), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_CpuInfoSPARC_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_CpuInfoSPARC(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_CpuInfoTricore_members(Visitor *v, CpuInfoTricore *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, "PC", &obj->PC, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_CpuInfoTricore(Visitor *v, const char *name, CpuInfoTricore **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(CpuInfoTricore), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_CpuInfoTricore_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_CpuInfoTricore(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_CpuInfoX86_members(Visitor *v, CpuInfoX86 *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, "pc", &obj->pc, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_CpuInfoX86(Visitor *v, const char *name, CpuInfoX86 **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(CpuInfoX86), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_CpuInfoX86_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_CpuInfoX86(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_CpuInstanceProperties_members(Visitor *v, CpuInstanceProperties *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "node-id", &obj->has_node_id)) {
        visit_type_int(v, "node-id", &obj->node_id, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "socket-id", &obj->has_socket_id)) {
        visit_type_int(v, "socket-id", &obj->socket_id, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "core-id", &obj->has_core_id)) {
        visit_type_int(v, "core-id", &obj->core_id, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "thread-id", &obj->has_thread_id)) {
        visit_type_int(v, "thread-id", &obj->thread_id, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_CpuInstanceProperties(Visitor *v, const char *name, CpuInstanceProperties **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(CpuInstanceProperties), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_CpuInstanceProperties_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_CpuInstanceProperties(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_CpuModelBaselineInfo_members(Visitor *v, CpuModelBaselineInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_CpuModelInfo(v, "model", &obj->model, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_CpuModelBaselineInfo(Visitor *v, const char *name, CpuModelBaselineInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(CpuModelBaselineInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_CpuModelBaselineInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_CpuModelBaselineInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_CpuModelCompareInfo_members(Visitor *v, CpuModelCompareInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_CpuModelCompareResult(v, "result", &obj->result, &err);
    if (err) {
        goto out;
    }
    visit_type_strList(v, "responsible-properties", &obj->responsible_properties, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_CpuModelCompareInfo(Visitor *v, const char *name, CpuModelCompareInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(CpuModelCompareInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_CpuModelCompareInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_CpuModelCompareInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_CpuModelCompareResult(Visitor *v, const char *name, CpuModelCompareResult *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, CpuModelCompareResult_lookup, errp);
    *obj = value;
}

void visit_type_CpuModelExpansionInfo_members(Visitor *v, CpuModelExpansionInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_CpuModelInfo(v, "model", &obj->model, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_CpuModelExpansionInfo(Visitor *v, const char *name, CpuModelExpansionInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(CpuModelExpansionInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_CpuModelExpansionInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_CpuModelExpansionInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_CpuModelExpansionType(Visitor *v, const char *name, CpuModelExpansionType *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, CpuModelExpansionType_lookup, errp);
    *obj = value;
}

void visit_type_CpuModelInfo_members(Visitor *v, CpuModelInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "name", &obj->name, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "props", &obj->has_props)) {
        visit_type_any(v, "props", &obj->props, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_CpuModelInfo(Visitor *v, const char *name, CpuModelInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(CpuModelInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_CpuModelInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_CpuModelInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_DataFormat(Visitor *v, const char *name, DataFormat *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, DataFormat_lookup, errp);
    *obj = value;
}

void visit_type_DevicePropertyInfo_members(Visitor *v, DevicePropertyInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "name", &obj->name, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "type", &obj->type, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "description", &obj->has_description)) {
        visit_type_str(v, "description", &obj->description, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_DevicePropertyInfo(Visitor *v, const char *name, DevicePropertyInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(DevicePropertyInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_DevicePropertyInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_DevicePropertyInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_DevicePropertyInfoList(Visitor *v, const char *name, DevicePropertyInfoList **obj, Error **errp)
{
    Error *err = NULL;
    DevicePropertyInfoList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (DevicePropertyInfoList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_DevicePropertyInfo(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_DevicePropertyInfoList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_DirtyBitmapStatus(Visitor *v, const char *name, DirtyBitmapStatus *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, DirtyBitmapStatus_lookup, errp);
    *obj = value;
}

void visit_type_DriveBackup_members(Visitor *v, DriveBackup *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "job-id", &obj->has_job_id)) {
        visit_type_str(v, "job-id", &obj->job_id, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_str(v, "device", &obj->device, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "target", &obj->target, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "format", &obj->has_format)) {
        visit_type_str(v, "format", &obj->format, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_MirrorSyncMode(v, "sync", &obj->sync, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "mode", &obj->has_mode)) {
        visit_type_NewImageMode(v, "mode", &obj->mode, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "speed", &obj->has_speed)) {
        visit_type_int(v, "speed", &obj->speed, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "bitmap", &obj->has_bitmap)) {
        visit_type_str(v, "bitmap", &obj->bitmap, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "compress", &obj->has_compress)) {
        visit_type_bool(v, "compress", &obj->compress, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "on-source-error", &obj->has_on_source_error)) {
        visit_type_BlockdevOnError(v, "on-source-error", &obj->on_source_error, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "on-target-error", &obj->has_on_target_error)) {
        visit_type_BlockdevOnError(v, "on-target-error", &obj->on_target_error, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_DriveBackup(Visitor *v, const char *name, DriveBackup **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(DriveBackup), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_DriveBackup_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_DriveBackup(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_DriveMirror_members(Visitor *v, DriveMirror *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "job-id", &obj->has_job_id)) {
        visit_type_str(v, "job-id", &obj->job_id, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_str(v, "device", &obj->device, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "target", &obj->target, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "format", &obj->has_format)) {
        visit_type_str(v, "format", &obj->format, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "node-name", &obj->has_node_name)) {
        visit_type_str(v, "node-name", &obj->node_name, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "replaces", &obj->has_replaces)) {
        visit_type_str(v, "replaces", &obj->replaces, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_MirrorSyncMode(v, "sync", &obj->sync, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "mode", &obj->has_mode)) {
        visit_type_NewImageMode(v, "mode", &obj->mode, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "speed", &obj->has_speed)) {
        visit_type_int(v, "speed", &obj->speed, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "granularity", &obj->has_granularity)) {
        visit_type_uint32(v, "granularity", &obj->granularity, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "buf-size", &obj->has_buf_size)) {
        visit_type_int(v, "buf-size", &obj->buf_size, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "on-source-error", &obj->has_on_source_error)) {
        visit_type_BlockdevOnError(v, "on-source-error", &obj->on_source_error, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "on-target-error", &obj->has_on_target_error)) {
        visit_type_BlockdevOnError(v, "on-target-error", &obj->on_target_error, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "unmap", &obj->has_unmap)) {
        visit_type_bool(v, "unmap", &obj->unmap, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_DriveMirror(Visitor *v, const char *name, DriveMirror **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(DriveMirror), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_DriveMirror_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_DriveMirror(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_DummyForceArrays_members(Visitor *v, DummyForceArrays *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_X86CPUFeatureWordInfoList(v, "unused", &obj->unused, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_DummyForceArrays(Visitor *v, const char *name, DummyForceArrays **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(DummyForceArrays), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_DummyForceArrays_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_DummyForceArrays(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_DumpGuestMemoryCapability_members(Visitor *v, DumpGuestMemoryCapability *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_DumpGuestMemoryFormatList(v, "formats", &obj->formats, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_DumpGuestMemoryCapability(Visitor *v, const char *name, DumpGuestMemoryCapability **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(DumpGuestMemoryCapability), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_DumpGuestMemoryCapability_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_DumpGuestMemoryCapability(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_DumpGuestMemoryFormat(Visitor *v, const char *name, DumpGuestMemoryFormat *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, DumpGuestMemoryFormat_lookup, errp);
    *obj = value;
}

void visit_type_DumpGuestMemoryFormatList(Visitor *v, const char *name, DumpGuestMemoryFormatList **obj, Error **errp)
{
    Error *err = NULL;
    DumpGuestMemoryFormatList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (DumpGuestMemoryFormatList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_DumpGuestMemoryFormat(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_DumpGuestMemoryFormatList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_DumpQueryResult_members(Visitor *v, DumpQueryResult *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_DumpStatus(v, "status", &obj->status, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "completed", &obj->completed, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "total", &obj->total, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_DumpQueryResult(Visitor *v, const char *name, DumpQueryResult **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(DumpQueryResult), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_DumpQueryResult_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_DumpQueryResult(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_DumpStatus(Visitor *v, const char *name, DumpStatus *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, DumpStatus_lookup, errp);
    *obj = value;
}

void visit_type_EventInfo_members(Visitor *v, EventInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "name", &obj->name, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_EventInfo(Visitor *v, const char *name, EventInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(EventInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_EventInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_EventInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_EventInfoList(Visitor *v, const char *name, EventInfoList **obj, Error **errp)
{
    Error *err = NULL;
    EventInfoList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (EventInfoList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_EventInfo(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_EventInfoList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_FailoverStatus(Visitor *v, const char *name, FailoverStatus *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, FailoverStatus_lookup, errp);
    *obj = value;
}

void visit_type_FdsetFdInfo_members(Visitor *v, FdsetFdInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, "fd", &obj->fd, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "opaque", &obj->has_opaque)) {
        visit_type_str(v, "opaque", &obj->opaque, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_FdsetFdInfo(Visitor *v, const char *name, FdsetFdInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(FdsetFdInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_FdsetFdInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_FdsetFdInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_FdsetFdInfoList(Visitor *v, const char *name, FdsetFdInfoList **obj, Error **errp)
{
    Error *err = NULL;
    FdsetFdInfoList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (FdsetFdInfoList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_FdsetFdInfo(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_FdsetFdInfoList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_FdsetInfo_members(Visitor *v, FdsetInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, "fdset-id", &obj->fdset_id, &err);
    if (err) {
        goto out;
    }
    visit_type_FdsetFdInfoList(v, "fds", &obj->fds, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_FdsetInfo(Visitor *v, const char *name, FdsetInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(FdsetInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_FdsetInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_FdsetInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_FdsetInfoList(Visitor *v, const char *name, FdsetInfoList **obj, Error **errp)
{
    Error *err = NULL;
    FdsetInfoList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (FdsetInfoList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_FdsetInfo(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_FdsetInfoList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_FloppyDriveType(Visitor *v, const char *name, FloppyDriveType *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, FloppyDriveType_lookup, errp);
    *obj = value;
}

void visit_type_GICCapability_members(Visitor *v, GICCapability *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, "version", &obj->version, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "emulated", &obj->emulated, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "kernel", &obj->kernel, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_GICCapability(Visitor *v, const char *name, GICCapability **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(GICCapability), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_GICCapability_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_GICCapability(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_GICCapabilityList(Visitor *v, const char *name, GICCapabilityList **obj, Error **errp)
{
    Error *err = NULL;
    GICCapabilityList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (GICCapabilityList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_GICCapability(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_GICCapabilityList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_GuestPanicAction(Visitor *v, const char *name, GuestPanicAction *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, GuestPanicAction_lookup, errp);
    *obj = value;
}

void visit_type_GuestPanicInformation_members(Visitor *v, GuestPanicInformation *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_q_obj_GuestPanicInformation_base_members(v, (q_obj_GuestPanicInformation_base *)obj, &err);
    if (err) {
        goto out;
    }
    switch (obj->type) {
    case GUEST_PANIC_INFORMATION_TYPE_HYPER_V:
        visit_type_GuestPanicInformationHyperV_members(v, &obj->u.hyper_v, &err);
        break;
    default:
        abort();
    }

out:
    error_propagate(errp, err);
}

void visit_type_GuestPanicInformation(Visitor *v, const char *name, GuestPanicInformation **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(GuestPanicInformation), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_GuestPanicInformation_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_GuestPanicInformation(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_GuestPanicInformationHyperV_members(Visitor *v, GuestPanicInformationHyperV *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_uint64(v, "arg1", &obj->arg1, &err);
    if (err) {
        goto out;
    }
    visit_type_uint64(v, "arg2", &obj->arg2, &err);
    if (err) {
        goto out;
    }
    visit_type_uint64(v, "arg3", &obj->arg3, &err);
    if (err) {
        goto out;
    }
    visit_type_uint64(v, "arg4", &obj->arg4, &err);
    if (err) {
        goto out;
    }
    visit_type_uint64(v, "arg5", &obj->arg5, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_GuestPanicInformationHyperV(Visitor *v, const char *name, GuestPanicInformationHyperV **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(GuestPanicInformationHyperV), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_GuestPanicInformationHyperV_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_GuestPanicInformationHyperV(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_GuestPanicInformationType(Visitor *v, const char *name, GuestPanicInformationType *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, GuestPanicInformationType_lookup, errp);
    *obj = value;
}

void visit_type_GuidInfo_members(Visitor *v, GuidInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "guid", &obj->guid, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_GuidInfo(Visitor *v, const char *name, GuidInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(GuidInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_GuidInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_GuidInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_HostMemPolicy(Visitor *v, const char *name, HostMemPolicy *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, HostMemPolicy_lookup, errp);
    *obj = value;
}

void visit_type_HotpluggableCPU_members(Visitor *v, HotpluggableCPU *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "type", &obj->type, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "vcpus-count", &obj->vcpus_count, &err);
    if (err) {
        goto out;
    }
    visit_type_CpuInstanceProperties(v, "props", &obj->props, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "qom-path", &obj->has_qom_path)) {
        visit_type_str(v, "qom-path", &obj->qom_path, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_HotpluggableCPU(Visitor *v, const char *name, HotpluggableCPU **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(HotpluggableCPU), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_HotpluggableCPU_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_HotpluggableCPU(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_HotpluggableCPUList(Visitor *v, const char *name, HotpluggableCPUList **obj, Error **errp)
{
    Error *err = NULL;
    HotpluggableCPUList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (HotpluggableCPUList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_HotpluggableCPU(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_HotpluggableCPUList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_IOThreadInfo_members(Visitor *v, IOThreadInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "id", &obj->id, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "thread-id", &obj->thread_id, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "poll-max-ns", &obj->poll_max_ns, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "poll-grow", &obj->poll_grow, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "poll-shrink", &obj->poll_shrink, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_IOThreadInfo(Visitor *v, const char *name, IOThreadInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(IOThreadInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_IOThreadInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_IOThreadInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_IOThreadInfoList(Visitor *v, const char *name, IOThreadInfoList **obj, Error **errp)
{
    Error *err = NULL;
    IOThreadInfoList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (IOThreadInfoList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_IOThreadInfo(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_IOThreadInfoList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_ImageCheck_members(Visitor *v, ImageCheck *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "filename", &obj->filename, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "format", &obj->format, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "check-errors", &obj->check_errors, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "image-end-offset", &obj->has_image_end_offset)) {
        visit_type_int(v, "image-end-offset", &obj->image_end_offset, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "corruptions", &obj->has_corruptions)) {
        visit_type_int(v, "corruptions", &obj->corruptions, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "leaks", &obj->has_leaks)) {
        visit_type_int(v, "leaks", &obj->leaks, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "corruptions-fixed", &obj->has_corruptions_fixed)) {
        visit_type_int(v, "corruptions-fixed", &obj->corruptions_fixed, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "leaks-fixed", &obj->has_leaks_fixed)) {
        visit_type_int(v, "leaks-fixed", &obj->leaks_fixed, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "total-clusters", &obj->has_total_clusters)) {
        visit_type_int(v, "total-clusters", &obj->total_clusters, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "allocated-clusters", &obj->has_allocated_clusters)) {
        visit_type_int(v, "allocated-clusters", &obj->allocated_clusters, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "fragmented-clusters", &obj->has_fragmented_clusters)) {
        visit_type_int(v, "fragmented-clusters", &obj->fragmented_clusters, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "compressed-clusters", &obj->has_compressed_clusters)) {
        visit_type_int(v, "compressed-clusters", &obj->compressed_clusters, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_ImageCheck(Visitor *v, const char *name, ImageCheck **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(ImageCheck), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_ImageCheck_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_ImageCheck(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_ImageInfo_members(Visitor *v, ImageInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "filename", &obj->filename, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "format", &obj->format, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "dirty-flag", &obj->has_dirty_flag)) {
        visit_type_bool(v, "dirty-flag", &obj->dirty_flag, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "actual-size", &obj->has_actual_size)) {
        visit_type_int(v, "actual-size", &obj->actual_size, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_int(v, "virtual-size", &obj->virtual_size, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "cluster-size", &obj->has_cluster_size)) {
        visit_type_int(v, "cluster-size", &obj->cluster_size, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "encrypted", &obj->has_encrypted)) {
        visit_type_bool(v, "encrypted", &obj->encrypted, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "compressed", &obj->has_compressed)) {
        visit_type_bool(v, "compressed", &obj->compressed, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "backing-filename", &obj->has_backing_filename)) {
        visit_type_str(v, "backing-filename", &obj->backing_filename, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "full-backing-filename", &obj->has_full_backing_filename)) {
        visit_type_str(v, "full-backing-filename", &obj->full_backing_filename, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "backing-filename-format", &obj->has_backing_filename_format)) {
        visit_type_str(v, "backing-filename-format", &obj->backing_filename_format, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "snapshots", &obj->has_snapshots)) {
        visit_type_SnapshotInfoList(v, "snapshots", &obj->snapshots, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "backing-image", &obj->has_backing_image)) {
        visit_type_ImageInfo(v, "backing-image", &obj->backing_image, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "format-specific", &obj->has_format_specific)) {
        visit_type_ImageInfoSpecific(v, "format-specific", &obj->format_specific, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_ImageInfo(Visitor *v, const char *name, ImageInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(ImageInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_ImageInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_ImageInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_ImageInfoList(Visitor *v, const char *name, ImageInfoList **obj, Error **errp)
{
    Error *err = NULL;
    ImageInfoList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (ImageInfoList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_ImageInfo(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_ImageInfoList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_ImageInfoSpecific_members(Visitor *v, ImageInfoSpecific *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_ImageInfoSpecificKind(v, "type", &obj->type, &err);
    if (err) {
        goto out;
    }
    switch (obj->type) {
    case IMAGE_INFO_SPECIFIC_KIND_QCOW2:
        visit_type_q_obj_ImageInfoSpecificQCow2_wrapper_members(v, &obj->u.qcow2, &err);
        break;
    case IMAGE_INFO_SPECIFIC_KIND_VMDK:
        visit_type_q_obj_ImageInfoSpecificVmdk_wrapper_members(v, &obj->u.vmdk, &err);
        break;
    case IMAGE_INFO_SPECIFIC_KIND_LUKS:
        visit_type_q_obj_QCryptoBlockInfoLUKS_wrapper_members(v, &obj->u.luks, &err);
        break;
    default:
        abort();
    }

out:
    error_propagate(errp, err);
}

void visit_type_ImageInfoSpecific(Visitor *v, const char *name, ImageInfoSpecific **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(ImageInfoSpecific), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_ImageInfoSpecific_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_ImageInfoSpecific(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_ImageInfoSpecificKind(Visitor *v, const char *name, ImageInfoSpecificKind *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, ImageInfoSpecificKind_lookup, errp);
    *obj = value;
}

void visit_type_ImageInfoSpecificQCow2_members(Visitor *v, ImageInfoSpecificQCow2 *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "compat", &obj->compat, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "lazy-refcounts", &obj->has_lazy_refcounts)) {
        visit_type_bool(v, "lazy-refcounts", &obj->lazy_refcounts, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "corrupt", &obj->has_corrupt)) {
        visit_type_bool(v, "corrupt", &obj->corrupt, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_int(v, "refcount-bits", &obj->refcount_bits, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_ImageInfoSpecificQCow2(Visitor *v, const char *name, ImageInfoSpecificQCow2 **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(ImageInfoSpecificQCow2), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_ImageInfoSpecificQCow2_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_ImageInfoSpecificQCow2(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_ImageInfoSpecificVmdk_members(Visitor *v, ImageInfoSpecificVmdk *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "create-type", &obj->create_type, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "cid", &obj->cid, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "parent-cid", &obj->parent_cid, &err);
    if (err) {
        goto out;
    }
    visit_type_ImageInfoList(v, "extents", &obj->extents, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_ImageInfoSpecificVmdk(Visitor *v, const char *name, ImageInfoSpecificVmdk **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(ImageInfoSpecificVmdk), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_ImageInfoSpecificVmdk_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_ImageInfoSpecificVmdk(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_InetSocketAddress_members(Visitor *v, InetSocketAddress *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_InetSocketAddressBase_members(v, (InetSocketAddressBase *)obj, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "numeric", &obj->has_numeric)) {
        visit_type_bool(v, "numeric", &obj->numeric, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "to", &obj->has_to)) {
        visit_type_uint16(v, "to", &obj->to, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "ipv4", &obj->has_ipv4)) {
        visit_type_bool(v, "ipv4", &obj->ipv4, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "ipv6", &obj->has_ipv6)) {
        visit_type_bool(v, "ipv6", &obj->ipv6, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_InetSocketAddress(Visitor *v, const char *name, InetSocketAddress **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(InetSocketAddress), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_InetSocketAddress_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_InetSocketAddress(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_InetSocketAddressBase_members(Visitor *v, InetSocketAddressBase *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "host", &obj->host, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "port", &obj->port, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_InetSocketAddressBase(Visitor *v, const char *name, InetSocketAddressBase **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(InetSocketAddressBase), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_InetSocketAddressBase_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_InetSocketAddressBase(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_InetSocketAddressBaseList(Visitor *v, const char *name, InetSocketAddressBaseList **obj, Error **errp)
{
    Error *err = NULL;
    InetSocketAddressBaseList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (InetSocketAddressBaseList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_InetSocketAddressBase(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_InetSocketAddressBaseList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_InputAxis(Visitor *v, const char *name, InputAxis *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, InputAxis_lookup, errp);
    *obj = value;
}

void visit_type_InputBtnEvent_members(Visitor *v, InputBtnEvent *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_InputButton(v, "button", &obj->button, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "down", &obj->down, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_InputBtnEvent(Visitor *v, const char *name, InputBtnEvent **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(InputBtnEvent), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_InputBtnEvent_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_InputBtnEvent(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_InputButton(Visitor *v, const char *name, InputButton *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, InputButton_lookup, errp);
    *obj = value;
}

void visit_type_InputEvent_members(Visitor *v, InputEvent *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_InputEventKind(v, "type", &obj->type, &err);
    if (err) {
        goto out;
    }
    switch (obj->type) {
    case INPUT_EVENT_KIND_KEY:
        visit_type_q_obj_InputKeyEvent_wrapper_members(v, &obj->u.key, &err);
        break;
    case INPUT_EVENT_KIND_BTN:
        visit_type_q_obj_InputBtnEvent_wrapper_members(v, &obj->u.btn, &err);
        break;
    case INPUT_EVENT_KIND_REL:
        visit_type_q_obj_InputMoveEvent_wrapper_members(v, &obj->u.rel, &err);
        break;
    case INPUT_EVENT_KIND_ABS:
        visit_type_q_obj_InputMoveEvent_wrapper_members(v, &obj->u.abs, &err);
        break;
    default:
        abort();
    }

out:
    error_propagate(errp, err);
}

void visit_type_InputEvent(Visitor *v, const char *name, InputEvent **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(InputEvent), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_InputEvent_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_InputEvent(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_InputEventKind(Visitor *v, const char *name, InputEventKind *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, InputEventKind_lookup, errp);
    *obj = value;
}

void visit_type_InputEventList(Visitor *v, const char *name, InputEventList **obj, Error **errp)
{
    Error *err = NULL;
    InputEventList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (InputEventList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_InputEvent(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_InputEventList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_InputKeyEvent_members(Visitor *v, InputKeyEvent *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_KeyValue(v, "key", &obj->key, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "down", &obj->down, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_InputKeyEvent(Visitor *v, const char *name, InputKeyEvent **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(InputKeyEvent), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_InputKeyEvent_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_InputKeyEvent(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_InputMoveEvent_members(Visitor *v, InputMoveEvent *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_InputAxis(v, "axis", &obj->axis, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "value", &obj->value, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_InputMoveEvent(Visitor *v, const char *name, InputMoveEvent **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(InputMoveEvent), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_InputMoveEvent_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_InputMoveEvent(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_IoOperationType(Visitor *v, const char *name, IoOperationType *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, IoOperationType_lookup, errp);
    *obj = value;
}

void visit_type_IscsiHeaderDigest(Visitor *v, const char *name, IscsiHeaderDigest *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, IscsiHeaderDigest_lookup, errp);
    *obj = value;
}

void visit_type_IscsiTransport(Visitor *v, const char *name, IscsiTransport *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, IscsiTransport_lookup, errp);
    *obj = value;
}

void visit_type_JSONType(Visitor *v, const char *name, JSONType *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, JSONType_lookup, errp);
    *obj = value;
}

void visit_type_KeyValue_members(Visitor *v, KeyValue *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_KeyValueKind(v, "type", &obj->type, &err);
    if (err) {
        goto out;
    }
    switch (obj->type) {
    case KEY_VALUE_KIND_NUMBER:
        visit_type_q_obj_int_wrapper_members(v, &obj->u.number, &err);
        break;
    case KEY_VALUE_KIND_QCODE:
        visit_type_q_obj_QKeyCode_wrapper_members(v, &obj->u.qcode, &err);
        break;
    default:
        abort();
    }

out:
    error_propagate(errp, err);
}

void visit_type_KeyValue(Visitor *v, const char *name, KeyValue **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(KeyValue), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_KeyValue_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_KeyValue(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_KeyValueKind(Visitor *v, const char *name, KeyValueKind *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, KeyValueKind_lookup, errp);
    *obj = value;
}

void visit_type_KeyValueList(Visitor *v, const char *name, KeyValueList **obj, Error **errp)
{
    Error *err = NULL;
    KeyValueList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (KeyValueList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_KeyValue(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_KeyValueList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_KvmInfo_members(Visitor *v, KvmInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_bool(v, "enabled", &obj->enabled, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "present", &obj->present, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_KvmInfo(Visitor *v, const char *name, KvmInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(KvmInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_KvmInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_KvmInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_LostTickPolicy(Visitor *v, const char *name, LostTickPolicy *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, LostTickPolicy_lookup, errp);
    *obj = value;
}

void visit_type_MachineInfo_members(Visitor *v, MachineInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "name", &obj->name, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "alias", &obj->has_alias)) {
        visit_type_str(v, "alias", &obj->alias, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "is-default", &obj->has_is_default)) {
        visit_type_bool(v, "is-default", &obj->is_default, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_int(v, "cpu-max", &obj->cpu_max, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "hotpluggable-cpus", &obj->hotpluggable_cpus, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_MachineInfo(Visitor *v, const char *name, MachineInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(MachineInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_MachineInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_MachineInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_MachineInfoList(Visitor *v, const char *name, MachineInfoList **obj, Error **errp)
{
    Error *err = NULL;
    MachineInfoList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (MachineInfoList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_MachineInfo(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_MachineInfoList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_MapEntry_members(Visitor *v, MapEntry *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, "start", &obj->start, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "length", &obj->length, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "data", &obj->data, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "zero", &obj->zero, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "depth", &obj->depth, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "offset", &obj->has_offset)) {
        visit_type_int(v, "offset", &obj->offset, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "filename", &obj->has_filename)) {
        visit_type_str(v, "filename", &obj->filename, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_MapEntry(Visitor *v, const char *name, MapEntry **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(MapEntry), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_MapEntry_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_MapEntry(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_Memdev_members(Visitor *v, Memdev *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "id", &obj->has_id)) {
        visit_type_str(v, "id", &obj->id, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_size(v, "size", &obj->size, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "merge", &obj->merge, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "dump", &obj->dump, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "prealloc", &obj->prealloc, &err);
    if (err) {
        goto out;
    }
    visit_type_uint16List(v, "host-nodes", &obj->host_nodes, &err);
    if (err) {
        goto out;
    }
    visit_type_HostMemPolicy(v, "policy", &obj->policy, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_Memdev(Visitor *v, const char *name, Memdev **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(Memdev), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_Memdev_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_Memdev(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_MemdevList(Visitor *v, const char *name, MemdevList **obj, Error **errp)
{
    Error *err = NULL;
    MemdevList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (MemdevList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_Memdev(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_MemdevList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_MemoryDeviceInfo_members(Visitor *v, MemoryDeviceInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_MemoryDeviceInfoKind(v, "type", &obj->type, &err);
    if (err) {
        goto out;
    }
    switch (obj->type) {
    case MEMORY_DEVICE_INFO_KIND_DIMM:
        visit_type_q_obj_PCDIMMDeviceInfo_wrapper_members(v, &obj->u.dimm, &err);
        break;
    default:
        abort();
    }

out:
    error_propagate(errp, err);
}

void visit_type_MemoryDeviceInfo(Visitor *v, const char *name, MemoryDeviceInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(MemoryDeviceInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_MemoryDeviceInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_MemoryDeviceInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_MemoryDeviceInfoKind(Visitor *v, const char *name, MemoryDeviceInfoKind *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, MemoryDeviceInfoKind_lookup, errp);
    *obj = value;
}

void visit_type_MemoryDeviceInfoList(Visitor *v, const char *name, MemoryDeviceInfoList **obj, Error **errp)
{
    Error *err = NULL;
    MemoryDeviceInfoList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (MemoryDeviceInfoList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_MemoryDeviceInfo(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_MemoryDeviceInfoList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_MigrationCapability(Visitor *v, const char *name, MigrationCapability *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, MigrationCapability_lookup, errp);
    *obj = value;
}

void visit_type_MigrationCapabilityStatus_members(Visitor *v, MigrationCapabilityStatus *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_MigrationCapability(v, "capability", &obj->capability, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "state", &obj->state, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_MigrationCapabilityStatus(Visitor *v, const char *name, MigrationCapabilityStatus **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(MigrationCapabilityStatus), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_MigrationCapabilityStatus_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_MigrationCapabilityStatus(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_MigrationCapabilityStatusList(Visitor *v, const char *name, MigrationCapabilityStatusList **obj, Error **errp)
{
    Error *err = NULL;
    MigrationCapabilityStatusList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (MigrationCapabilityStatusList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_MigrationCapabilityStatus(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_MigrationCapabilityStatusList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_MigrationInfo_members(Visitor *v, MigrationInfo *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "status", &obj->has_status)) {
        visit_type_MigrationStatus(v, "status", &obj->status, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "ram", &obj->has_ram)) {
        visit_type_MigrationStats(v, "ram", &obj->ram, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "disk", &obj->has_disk)) {
        visit_type_MigrationStats(v, "disk", &obj->disk, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "xbzrle-cache", &obj->has_xbzrle_cache)) {
        visit_type_XBZRLECacheStats(v, "xbzrle-cache", &obj->xbzrle_cache, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "total-time", &obj->has_total_time)) {
        visit_type_int(v, "total-time", &obj->total_time, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "expected-downtime", &obj->has_expected_downtime)) {
        visit_type_int(v, "expected-downtime", &obj->expected_downtime, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "downtime", &obj->has_downtime)) {
        visit_type_int(v, "downtime", &obj->downtime, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "setup-time", &obj->has_setup_time)) {
        visit_type_int(v, "setup-time", &obj->setup_time, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "cpu-throttle-percentage", &obj->has_cpu_throttle_percentage)) {
        visit_type_int(v, "cpu-throttle-percentage", &obj->cpu_throttle_percentage, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "error-desc", &obj->has_error_desc)) {
        visit_type_str(v, "error-desc", &obj->error_desc, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_MigrationInfo(Visitor *v, const char *name, MigrationInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(MigrationInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_MigrationInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_MigrationInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_MigrationParameter(Visitor *v, const char *name, MigrationParameter *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, MigrationParameter_lookup, errp);
    *obj = value;
}

void visit_type_MigrationParameters_members(Visitor *v, MigrationParameters *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "compress-level", &obj->has_compress_level)) {
        visit_type_int(v, "compress-level", &obj->compress_level, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "compress-threads", &obj->has_compress_threads)) {
        visit_type_int(v, "compress-threads", &obj->compress_threads, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "decompress-threads", &obj->has_decompress_threads)) {
        visit_type_int(v, "decompress-threads", &obj->decompress_threads, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "cpu-throttle-initial", &obj->has_cpu_throttle_initial)) {
        visit_type_int(v, "cpu-throttle-initial", &obj->cpu_throttle_initial, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "cpu-throttle-increment", &obj->has_cpu_throttle_increment)) {
        visit_type_int(v, "cpu-throttle-increment", &obj->cpu_throttle_increment, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "tls-creds", &obj->has_tls_creds)) {
        visit_type_str(v, "tls-creds", &obj->tls_creds, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "tls-hostname", &obj->has_tls_hostname)) {
        visit_type_str(v, "tls-hostname", &obj->tls_hostname, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "max-bandwidth", &obj->has_max_bandwidth)) {
        visit_type_int(v, "max-bandwidth", &obj->max_bandwidth, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "downtime-limit", &obj->has_downtime_limit)) {
        visit_type_int(v, "downtime-limit", &obj->downtime_limit, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "x-checkpoint-delay", &obj->has_x_checkpoint_delay)) {
        visit_type_int(v, "x-checkpoint-delay", &obj->x_checkpoint_delay, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_MigrationParameters(Visitor *v, const char *name, MigrationParameters **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(MigrationParameters), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_MigrationParameters_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_MigrationParameters(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_MigrationStats_members(Visitor *v, MigrationStats *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, "transferred", &obj->transferred, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "remaining", &obj->remaining, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "total", &obj->total, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "duplicate", &obj->duplicate, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "skipped", &obj->skipped, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "normal", &obj->normal, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "normal-bytes", &obj->normal_bytes, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "dirty-pages-rate", &obj->dirty_pages_rate, &err);
    if (err) {
        goto out;
    }
    visit_type_number(v, "mbps", &obj->mbps, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "dirty-sync-count", &obj->dirty_sync_count, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "postcopy-requests", &obj->postcopy_requests, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_MigrationStats(Visitor *v, const char *name, MigrationStats **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(MigrationStats), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_MigrationStats_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_MigrationStats(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_MigrationStatus(Visitor *v, const char *name, MigrationStatus *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, MigrationStatus_lookup, errp);
    *obj = value;
}

void visit_type_MirrorSyncMode(Visitor *v, const char *name, MirrorSyncMode *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, MirrorSyncMode_lookup, errp);
    *obj = value;
}

void visit_type_MouseInfo_members(Visitor *v, MouseInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "name", &obj->name, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "index", &obj->index, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "current", &obj->current, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "absolute", &obj->absolute, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_MouseInfo(Visitor *v, const char *name, MouseInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(MouseInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_MouseInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_MouseInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_MouseInfoList(Visitor *v, const char *name, MouseInfoList **obj, Error **errp)
{
    Error *err = NULL;
    MouseInfoList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (MouseInfoList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_MouseInfo(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_MouseInfoList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_NFSServer_members(Visitor *v, NFSServer *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_NFSTransport(v, "type", &obj->type, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "host", &obj->host, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_NFSServer(Visitor *v, const char *name, NFSServer **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(NFSServer), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_NFSServer_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_NFSServer(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_NFSTransport(Visitor *v, const char *name, NFSTransport *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, NFSTransport_lookup, errp);
    *obj = value;
}

void visit_type_NameInfo_members(Visitor *v, NameInfo *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "name", &obj->has_name)) {
        visit_type_str(v, "name", &obj->name, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_NameInfo(Visitor *v, const char *name, NameInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(NameInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_NameInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_NameInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_NetClientDriver(Visitor *v, const char *name, NetClientDriver *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, NetClientDriver_lookup, errp);
    *obj = value;
}

void visit_type_NetFilterDirection(Visitor *v, const char *name, NetFilterDirection *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, NetFilterDirection_lookup, errp);
    *obj = value;
}

void visit_type_NetLegacy_members(Visitor *v, NetLegacy *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "vlan", &obj->has_vlan)) {
        visit_type_int32(v, "vlan", &obj->vlan, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "id", &obj->has_id)) {
        visit_type_str(v, "id", &obj->id, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "name", &obj->has_name)) {
        visit_type_str(v, "name", &obj->name, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_NetLegacyOptions(v, "opts", &obj->opts, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_NetLegacy(Visitor *v, const char *name, NetLegacy **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(NetLegacy), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_NetLegacy_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_NetLegacy(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_NetLegacyNicOptions_members(Visitor *v, NetLegacyNicOptions *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "netdev", &obj->has_netdev)) {
        visit_type_str(v, "netdev", &obj->netdev, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "macaddr", &obj->has_macaddr)) {
        visit_type_str(v, "macaddr", &obj->macaddr, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "model", &obj->has_model)) {
        visit_type_str(v, "model", &obj->model, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "addr", &obj->has_addr)) {
        visit_type_str(v, "addr", &obj->addr, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "vectors", &obj->has_vectors)) {
        visit_type_uint32(v, "vectors", &obj->vectors, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_NetLegacyNicOptions(Visitor *v, const char *name, NetLegacyNicOptions **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(NetLegacyNicOptions), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_NetLegacyNicOptions_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_NetLegacyNicOptions(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_NetLegacyOptions_members(Visitor *v, NetLegacyOptions *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_q_obj_NetLegacyOptions_base_members(v, (q_obj_NetLegacyOptions_base *)obj, &err);
    if (err) {
        goto out;
    }
    switch (obj->type) {
    case NET_LEGACY_OPTIONS_TYPE_NONE:
        visit_type_NetdevNoneOptions_members(v, &obj->u.none, &err);
        break;
    case NET_LEGACY_OPTIONS_TYPE_NIC:
        visit_type_NetLegacyNicOptions_members(v, &obj->u.nic, &err);
        break;
    case NET_LEGACY_OPTIONS_TYPE_USER:
        visit_type_NetdevUserOptions_members(v, &obj->u.user, &err);
        break;
    case NET_LEGACY_OPTIONS_TYPE_TAP:
        visit_type_NetdevTapOptions_members(v, &obj->u.tap, &err);
        break;
    case NET_LEGACY_OPTIONS_TYPE_L2TPV3:
        visit_type_NetdevL2TPv3Options_members(v, &obj->u.l2tpv3, &err);
        break;
    case NET_LEGACY_OPTIONS_TYPE_SOCKET:
        visit_type_NetdevSocketOptions_members(v, &obj->u.socket, &err);
        break;
    case NET_LEGACY_OPTIONS_TYPE_VDE:
        visit_type_NetdevVdeOptions_members(v, &obj->u.vde, &err);
        break;
    case NET_LEGACY_OPTIONS_TYPE_DUMP:
        visit_type_NetdevDumpOptions_members(v, &obj->u.dump, &err);
        break;
    case NET_LEGACY_OPTIONS_TYPE_BRIDGE:
        visit_type_NetdevBridgeOptions_members(v, &obj->u.bridge, &err);
        break;
    case NET_LEGACY_OPTIONS_TYPE_NETMAP:
        visit_type_NetdevNetmapOptions_members(v, &obj->u.netmap, &err);
        break;
    case NET_LEGACY_OPTIONS_TYPE_VHOST_USER:
        visit_type_NetdevVhostUserOptions_members(v, &obj->u.vhost_user, &err);
        break;
    default:
        abort();
    }

out:
    error_propagate(errp, err);
}

void visit_type_NetLegacyOptions(Visitor *v, const char *name, NetLegacyOptions **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(NetLegacyOptions), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_NetLegacyOptions_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_NetLegacyOptions(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_NetLegacyOptionsType(Visitor *v, const char *name, NetLegacyOptionsType *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, NetLegacyOptionsType_lookup, errp);
    *obj = value;
}

void visit_type_Netdev_members(Visitor *v, Netdev *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_q_obj_Netdev_base_members(v, (q_obj_Netdev_base *)obj, &err);
    if (err) {
        goto out;
    }
    switch (obj->type) {
    case NET_CLIENT_DRIVER_NONE:
        visit_type_NetdevNoneOptions_members(v, &obj->u.none, &err);
        break;
    case NET_CLIENT_DRIVER_NIC:
        visit_type_NetLegacyNicOptions_members(v, &obj->u.nic, &err);
        break;
    case NET_CLIENT_DRIVER_USER:
        visit_type_NetdevUserOptions_members(v, &obj->u.user, &err);
        break;
    case NET_CLIENT_DRIVER_TAP:
        visit_type_NetdevTapOptions_members(v, &obj->u.tap, &err);
        break;
    case NET_CLIENT_DRIVER_L2TPV3:
        visit_type_NetdevL2TPv3Options_members(v, &obj->u.l2tpv3, &err);
        break;
    case NET_CLIENT_DRIVER_SOCKET:
        visit_type_NetdevSocketOptions_members(v, &obj->u.socket, &err);
        break;
    case NET_CLIENT_DRIVER_VDE:
        visit_type_NetdevVdeOptions_members(v, &obj->u.vde, &err);
        break;
    case NET_CLIENT_DRIVER_DUMP:
        visit_type_NetdevDumpOptions_members(v, &obj->u.dump, &err);
        break;
    case NET_CLIENT_DRIVER_BRIDGE:
        visit_type_NetdevBridgeOptions_members(v, &obj->u.bridge, &err);
        break;
    case NET_CLIENT_DRIVER_HUBPORT:
        visit_type_NetdevHubPortOptions_members(v, &obj->u.hubport, &err);
        break;
    case NET_CLIENT_DRIVER_NETMAP:
        visit_type_NetdevNetmapOptions_members(v, &obj->u.netmap, &err);
        break;
    case NET_CLIENT_DRIVER_VHOST_USER:
        visit_type_NetdevVhostUserOptions_members(v, &obj->u.vhost_user, &err);
        break;
    default:
        abort();
    }

out:
    error_propagate(errp, err);
}

void visit_type_Netdev(Visitor *v, const char *name, Netdev **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(Netdev), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_Netdev_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_Netdev(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_NetdevBridgeOptions_members(Visitor *v, NetdevBridgeOptions *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "br", &obj->has_br)) {
        visit_type_str(v, "br", &obj->br, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "helper", &obj->has_helper)) {
        visit_type_str(v, "helper", &obj->helper, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_NetdevBridgeOptions(Visitor *v, const char *name, NetdevBridgeOptions **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(NetdevBridgeOptions), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_NetdevBridgeOptions_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_NetdevBridgeOptions(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_NetdevDumpOptions_members(Visitor *v, NetdevDumpOptions *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "len", &obj->has_len)) {
        visit_type_size(v, "len", &obj->len, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "file", &obj->has_file)) {
        visit_type_str(v, "file", &obj->file, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_NetdevDumpOptions(Visitor *v, const char *name, NetdevDumpOptions **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(NetdevDumpOptions), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_NetdevDumpOptions_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_NetdevDumpOptions(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_NetdevHubPortOptions_members(Visitor *v, NetdevHubPortOptions *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int32(v, "hubid", &obj->hubid, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_NetdevHubPortOptions(Visitor *v, const char *name, NetdevHubPortOptions **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(NetdevHubPortOptions), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_NetdevHubPortOptions_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_NetdevHubPortOptions(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_NetdevL2TPv3Options_members(Visitor *v, NetdevL2TPv3Options *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "src", &obj->src, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "dst", &obj->dst, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "srcport", &obj->has_srcport)) {
        visit_type_str(v, "srcport", &obj->srcport, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "dstport", &obj->has_dstport)) {
        visit_type_str(v, "dstport", &obj->dstport, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "ipv6", &obj->has_ipv6)) {
        visit_type_bool(v, "ipv6", &obj->ipv6, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "udp", &obj->has_udp)) {
        visit_type_bool(v, "udp", &obj->udp, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "cookie64", &obj->has_cookie64)) {
        visit_type_bool(v, "cookie64", &obj->cookie64, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "counter", &obj->has_counter)) {
        visit_type_bool(v, "counter", &obj->counter, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "pincounter", &obj->has_pincounter)) {
        visit_type_bool(v, "pincounter", &obj->pincounter, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "txcookie", &obj->has_txcookie)) {
        visit_type_uint64(v, "txcookie", &obj->txcookie, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "rxcookie", &obj->has_rxcookie)) {
        visit_type_uint64(v, "rxcookie", &obj->rxcookie, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_uint32(v, "txsession", &obj->txsession, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "rxsession", &obj->has_rxsession)) {
        visit_type_uint32(v, "rxsession", &obj->rxsession, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "offset", &obj->has_offset)) {
        visit_type_uint32(v, "offset", &obj->offset, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_NetdevL2TPv3Options(Visitor *v, const char *name, NetdevL2TPv3Options **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(NetdevL2TPv3Options), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_NetdevL2TPv3Options_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_NetdevL2TPv3Options(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_NetdevNetmapOptions_members(Visitor *v, NetdevNetmapOptions *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "ifname", &obj->ifname, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "devname", &obj->has_devname)) {
        visit_type_str(v, "devname", &obj->devname, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_NetdevNetmapOptions(Visitor *v, const char *name, NetdevNetmapOptions **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(NetdevNetmapOptions), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_NetdevNetmapOptions_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_NetdevNetmapOptions(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_NetdevNoneOptions_members(Visitor *v, NetdevNoneOptions *obj, Error **errp)
{
    Error *err = NULL;

    error_propagate(errp, err);
}

void visit_type_NetdevNoneOptions(Visitor *v, const char *name, NetdevNoneOptions **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(NetdevNoneOptions), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_NetdevNoneOptions_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_NetdevNoneOptions(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_NetdevSocketOptions_members(Visitor *v, NetdevSocketOptions *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "fd", &obj->has_fd)) {
        visit_type_str(v, "fd", &obj->fd, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "listen", &obj->has_listen)) {
        visit_type_str(v, "listen", &obj->listen, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "connect", &obj->has_connect)) {
        visit_type_str(v, "connect", &obj->connect, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "mcast", &obj->has_mcast)) {
        visit_type_str(v, "mcast", &obj->mcast, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "localaddr", &obj->has_localaddr)) {
        visit_type_str(v, "localaddr", &obj->localaddr, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "udp", &obj->has_udp)) {
        visit_type_str(v, "udp", &obj->udp, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_NetdevSocketOptions(Visitor *v, const char *name, NetdevSocketOptions **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(NetdevSocketOptions), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_NetdevSocketOptions_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_NetdevSocketOptions(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_NetdevTapOptions_members(Visitor *v, NetdevTapOptions *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "ifname", &obj->has_ifname)) {
        visit_type_str(v, "ifname", &obj->ifname, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "fd", &obj->has_fd)) {
        visit_type_str(v, "fd", &obj->fd, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "fds", &obj->has_fds)) {
        visit_type_str(v, "fds", &obj->fds, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "script", &obj->has_script)) {
        visit_type_str(v, "script", &obj->script, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "downscript", &obj->has_downscript)) {
        visit_type_str(v, "downscript", &obj->downscript, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "br", &obj->has_br)) {
        visit_type_str(v, "br", &obj->br, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "helper", &obj->has_helper)) {
        visit_type_str(v, "helper", &obj->helper, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "sndbuf", &obj->has_sndbuf)) {
        visit_type_size(v, "sndbuf", &obj->sndbuf, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "vnet_hdr", &obj->has_vnet_hdr)) {
        visit_type_bool(v, "vnet_hdr", &obj->vnet_hdr, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "vhost", &obj->has_vhost)) {
        visit_type_bool(v, "vhost", &obj->vhost, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "vhostfd", &obj->has_vhostfd)) {
        visit_type_str(v, "vhostfd", &obj->vhostfd, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "vhostfds", &obj->has_vhostfds)) {
        visit_type_str(v, "vhostfds", &obj->vhostfds, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "vhostforce", &obj->has_vhostforce)) {
        visit_type_bool(v, "vhostforce", &obj->vhostforce, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "queues", &obj->has_queues)) {
        visit_type_uint32(v, "queues", &obj->queues, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "poll-us", &obj->has_poll_us)) {
        visit_type_uint32(v, "poll-us", &obj->poll_us, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_NetdevTapOptions(Visitor *v, const char *name, NetdevTapOptions **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(NetdevTapOptions), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_NetdevTapOptions_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_NetdevTapOptions(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_NetdevUserOptions_members(Visitor *v, NetdevUserOptions *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "hostname", &obj->has_hostname)) {
        visit_type_str(v, "hostname", &obj->hostname, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "restrict", &obj->has_q_restrict)) {
        visit_type_bool(v, "restrict", &obj->q_restrict, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "ipv4", &obj->has_ipv4)) {
        visit_type_bool(v, "ipv4", &obj->ipv4, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "ipv6", &obj->has_ipv6)) {
        visit_type_bool(v, "ipv6", &obj->ipv6, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "ip", &obj->has_ip)) {
        visit_type_str(v, "ip", &obj->ip, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "net", &obj->has_net)) {
        visit_type_str(v, "net", &obj->net, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "host", &obj->has_host)) {
        visit_type_str(v, "host", &obj->host, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "tftp", &obj->has_tftp)) {
        visit_type_str(v, "tftp", &obj->tftp, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "bootfile", &obj->has_bootfile)) {
        visit_type_str(v, "bootfile", &obj->bootfile, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "dhcpstart", &obj->has_dhcpstart)) {
        visit_type_str(v, "dhcpstart", &obj->dhcpstart, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "dns", &obj->has_dns)) {
        visit_type_str(v, "dns", &obj->dns, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "dnssearch", &obj->has_dnssearch)) {
        visit_type_StringList(v, "dnssearch", &obj->dnssearch, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "ipv6-prefix", &obj->has_ipv6_prefix)) {
        visit_type_str(v, "ipv6-prefix", &obj->ipv6_prefix, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "ipv6-prefixlen", &obj->has_ipv6_prefixlen)) {
        visit_type_int(v, "ipv6-prefixlen", &obj->ipv6_prefixlen, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "ipv6-host", &obj->has_ipv6_host)) {
        visit_type_str(v, "ipv6-host", &obj->ipv6_host, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "ipv6-dns", &obj->has_ipv6_dns)) {
        visit_type_str(v, "ipv6-dns", &obj->ipv6_dns, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "smb", &obj->has_smb)) {
        visit_type_str(v, "smb", &obj->smb, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "smbserver", &obj->has_smbserver)) {
        visit_type_str(v, "smbserver", &obj->smbserver, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "hostfwd", &obj->has_hostfwd)) {
        visit_type_StringList(v, "hostfwd", &obj->hostfwd, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "guestfwd", &obj->has_guestfwd)) {
        visit_type_StringList(v, "guestfwd", &obj->guestfwd, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_NetdevUserOptions(Visitor *v, const char *name, NetdevUserOptions **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(NetdevUserOptions), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_NetdevUserOptions_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_NetdevUserOptions(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_NetdevVdeOptions_members(Visitor *v, NetdevVdeOptions *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "sock", &obj->has_sock)) {
        visit_type_str(v, "sock", &obj->sock, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "port", &obj->has_port)) {
        visit_type_uint16(v, "port", &obj->port, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "group", &obj->has_group)) {
        visit_type_str(v, "group", &obj->group, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "mode", &obj->has_mode)) {
        visit_type_uint16(v, "mode", &obj->mode, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_NetdevVdeOptions(Visitor *v, const char *name, NetdevVdeOptions **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(NetdevVdeOptions), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_NetdevVdeOptions_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_NetdevVdeOptions(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_NetdevVhostUserOptions_members(Visitor *v, NetdevVhostUserOptions *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "chardev", &obj->chardev, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "vhostforce", &obj->has_vhostforce)) {
        visit_type_bool(v, "vhostforce", &obj->vhostforce, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "queues", &obj->has_queues)) {
        visit_type_int(v, "queues", &obj->queues, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_NetdevVhostUserOptions(Visitor *v, const char *name, NetdevVhostUserOptions **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(NetdevVhostUserOptions), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_NetdevVhostUserOptions_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_NetdevVhostUserOptions(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_NetworkAddressFamily(Visitor *v, const char *name, NetworkAddressFamily *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, NetworkAddressFamily_lookup, errp);
    *obj = value;
}

void visit_type_NewImageMode(Visitor *v, const char *name, NewImageMode *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, NewImageMode_lookup, errp);
    *obj = value;
}

void visit_type_NumaNodeOptions_members(Visitor *v, NumaNodeOptions *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "nodeid", &obj->has_nodeid)) {
        visit_type_uint16(v, "nodeid", &obj->nodeid, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "cpus", &obj->has_cpus)) {
        visit_type_uint16List(v, "cpus", &obj->cpus, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "mem", &obj->has_mem)) {
        visit_type_size(v, "mem", &obj->mem, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "memdev", &obj->has_memdev)) {
        visit_type_str(v, "memdev", &obj->memdev, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_NumaNodeOptions(Visitor *v, const char *name, NumaNodeOptions **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(NumaNodeOptions), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_NumaNodeOptions_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_NumaNodeOptions(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_NumaOptions_members(Visitor *v, NumaOptions *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_q_obj_NumaOptions_base_members(v, (q_obj_NumaOptions_base *)obj, &err);
    if (err) {
        goto out;
    }
    switch (obj->type) {
    case NUMA_OPTIONS_TYPE_NODE:
        visit_type_NumaNodeOptions_members(v, &obj->u.node, &err);
        break;
    default:
        abort();
    }

out:
    error_propagate(errp, err);
}

void visit_type_NumaOptions(Visitor *v, const char *name, NumaOptions **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(NumaOptions), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_NumaOptions_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_NumaOptions(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_NumaOptionsType(Visitor *v, const char *name, NumaOptionsType *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, NumaOptionsType_lookup, errp);
    *obj = value;
}

void visit_type_ObjectPropertyInfo_members(Visitor *v, ObjectPropertyInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "name", &obj->name, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "type", &obj->type, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_ObjectPropertyInfo(Visitor *v, const char *name, ObjectPropertyInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(ObjectPropertyInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_ObjectPropertyInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_ObjectPropertyInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_ObjectPropertyInfoList(Visitor *v, const char *name, ObjectPropertyInfoList **obj, Error **errp)
{
    Error *err = NULL;
    ObjectPropertyInfoList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (ObjectPropertyInfoList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_ObjectPropertyInfo(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_ObjectPropertyInfoList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_ObjectTypeInfo_members(Visitor *v, ObjectTypeInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "name", &obj->name, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_ObjectTypeInfo(Visitor *v, const char *name, ObjectTypeInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(ObjectTypeInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_ObjectTypeInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_ObjectTypeInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_ObjectTypeInfoList(Visitor *v, const char *name, ObjectTypeInfoList **obj, Error **errp)
{
    Error *err = NULL;
    ObjectTypeInfoList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (ObjectTypeInfoList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_ObjectTypeInfo(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_ObjectTypeInfoList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_OnOffAuto(Visitor *v, const char *name, OnOffAuto *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, OnOffAuto_lookup, errp);
    *obj = value;
}

void visit_type_OnOffSplit(Visitor *v, const char *name, OnOffSplit *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, OnOffSplit_lookup, errp);
    *obj = value;
}

void visit_type_PCDIMMDeviceInfo_members(Visitor *v, PCDIMMDeviceInfo *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "id", &obj->has_id)) {
        visit_type_str(v, "id", &obj->id, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_int(v, "addr", &obj->addr, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "size", &obj->size, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "slot", &obj->slot, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "node", &obj->node, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "memdev", &obj->memdev, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "hotplugged", &obj->hotplugged, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "hotpluggable", &obj->hotpluggable, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_PCDIMMDeviceInfo(Visitor *v, const char *name, PCDIMMDeviceInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(PCDIMMDeviceInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_PCDIMMDeviceInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_PCDIMMDeviceInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_PciBridgeInfo_members(Visitor *v, PciBridgeInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_PciBusInfo(v, "bus", &obj->bus, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "devices", &obj->has_devices)) {
        visit_type_PciDeviceInfoList(v, "devices", &obj->devices, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_PciBridgeInfo(Visitor *v, const char *name, PciBridgeInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(PciBridgeInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_PciBridgeInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_PciBridgeInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_PciBusInfo_members(Visitor *v, PciBusInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, "number", &obj->number, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "secondary", &obj->secondary, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "subordinate", &obj->subordinate, &err);
    if (err) {
        goto out;
    }
    visit_type_PciMemoryRange(v, "io_range", &obj->io_range, &err);
    if (err) {
        goto out;
    }
    visit_type_PciMemoryRange(v, "memory_range", &obj->memory_range, &err);
    if (err) {
        goto out;
    }
    visit_type_PciMemoryRange(v, "prefetchable_range", &obj->prefetchable_range, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_PciBusInfo(Visitor *v, const char *name, PciBusInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(PciBusInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_PciBusInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_PciBusInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_PciDeviceClass_members(Visitor *v, PciDeviceClass *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "desc", &obj->has_desc)) {
        visit_type_str(v, "desc", &obj->desc, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_int(v, "class", &obj->q_class, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_PciDeviceClass(Visitor *v, const char *name, PciDeviceClass **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(PciDeviceClass), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_PciDeviceClass_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_PciDeviceClass(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_PciDeviceId_members(Visitor *v, PciDeviceId *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, "device", &obj->device, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "vendor", &obj->vendor, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_PciDeviceId(Visitor *v, const char *name, PciDeviceId **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(PciDeviceId), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_PciDeviceId_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_PciDeviceId(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_PciDeviceInfo_members(Visitor *v, PciDeviceInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, "bus", &obj->bus, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "slot", &obj->slot, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "function", &obj->function, &err);
    if (err) {
        goto out;
    }
    visit_type_PciDeviceClass(v, "class_info", &obj->class_info, &err);
    if (err) {
        goto out;
    }
    visit_type_PciDeviceId(v, "id", &obj->id, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "irq", &obj->has_irq)) {
        visit_type_int(v, "irq", &obj->irq, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_str(v, "qdev_id", &obj->qdev_id, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "pci_bridge", &obj->has_pci_bridge)) {
        visit_type_PciBridgeInfo(v, "pci_bridge", &obj->pci_bridge, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_PciMemoryRegionList(v, "regions", &obj->regions, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_PciDeviceInfo(Visitor *v, const char *name, PciDeviceInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(PciDeviceInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_PciDeviceInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_PciDeviceInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_PciDeviceInfoList(Visitor *v, const char *name, PciDeviceInfoList **obj, Error **errp)
{
    Error *err = NULL;
    PciDeviceInfoList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (PciDeviceInfoList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_PciDeviceInfo(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_PciDeviceInfoList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_PciInfo_members(Visitor *v, PciInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, "bus", &obj->bus, &err);
    if (err) {
        goto out;
    }
    visit_type_PciDeviceInfoList(v, "devices", &obj->devices, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_PciInfo(Visitor *v, const char *name, PciInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(PciInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_PciInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_PciInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_PciInfoList(Visitor *v, const char *name, PciInfoList **obj, Error **errp)
{
    Error *err = NULL;
    PciInfoList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (PciInfoList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_PciInfo(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_PciInfoList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_PciMemoryRange_members(Visitor *v, PciMemoryRange *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, "base", &obj->base, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "limit", &obj->limit, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_PciMemoryRange(Visitor *v, const char *name, PciMemoryRange **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(PciMemoryRange), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_PciMemoryRange_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_PciMemoryRange(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_PciMemoryRegion_members(Visitor *v, PciMemoryRegion *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, "bar", &obj->bar, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "type", &obj->type, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "address", &obj->address, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "size", &obj->size, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "prefetch", &obj->has_prefetch)) {
        visit_type_bool(v, "prefetch", &obj->prefetch, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "mem_type_64", &obj->has_mem_type_64)) {
        visit_type_bool(v, "mem_type_64", &obj->mem_type_64, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_PciMemoryRegion(Visitor *v, const char *name, PciMemoryRegion **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(PciMemoryRegion), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_PciMemoryRegion_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_PciMemoryRegion(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_PciMemoryRegionList(Visitor *v, const char *name, PciMemoryRegionList **obj, Error **errp)
{
    Error *err = NULL;
    PciMemoryRegionList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (PciMemoryRegionList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_PciMemoryRegion(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_PciMemoryRegionList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_PreallocMode(Visitor *v, const char *name, PreallocMode *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, PreallocMode_lookup, errp);
    *obj = value;
}

void visit_type_QCryptoBlockCreateOptions_members(Visitor *v, QCryptoBlockCreateOptions *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_QCryptoBlockOptionsBase_members(v, (QCryptoBlockOptionsBase *)obj, &err);
    if (err) {
        goto out;
    }
    switch (obj->format) {
    case Q_CRYPTO_BLOCK_FORMAT_QCOW:
        visit_type_QCryptoBlockOptionsQCow_members(v, &obj->u.qcow, &err);
        break;
    case Q_CRYPTO_BLOCK_FORMAT_LUKS:
        visit_type_QCryptoBlockCreateOptionsLUKS_members(v, &obj->u.luks, &err);
        break;
    default:
        abort();
    }

out:
    error_propagate(errp, err);
}

void visit_type_QCryptoBlockCreateOptions(Visitor *v, const char *name, QCryptoBlockCreateOptions **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(QCryptoBlockCreateOptions), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_QCryptoBlockCreateOptions_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_QCryptoBlockCreateOptions(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_QCryptoBlockCreateOptionsLUKS_members(Visitor *v, QCryptoBlockCreateOptionsLUKS *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_QCryptoBlockOptionsLUKS_members(v, (QCryptoBlockOptionsLUKS *)obj, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "cipher-alg", &obj->has_cipher_alg)) {
        visit_type_QCryptoCipherAlgorithm(v, "cipher-alg", &obj->cipher_alg, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "cipher-mode", &obj->has_cipher_mode)) {
        visit_type_QCryptoCipherMode(v, "cipher-mode", &obj->cipher_mode, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "ivgen-alg", &obj->has_ivgen_alg)) {
        visit_type_QCryptoIVGenAlgorithm(v, "ivgen-alg", &obj->ivgen_alg, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "ivgen-hash-alg", &obj->has_ivgen_hash_alg)) {
        visit_type_QCryptoHashAlgorithm(v, "ivgen-hash-alg", &obj->ivgen_hash_alg, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "hash-alg", &obj->has_hash_alg)) {
        visit_type_QCryptoHashAlgorithm(v, "hash-alg", &obj->hash_alg, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "iter-time", &obj->has_iter_time)) {
        visit_type_int(v, "iter-time", &obj->iter_time, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_QCryptoBlockCreateOptionsLUKS(Visitor *v, const char *name, QCryptoBlockCreateOptionsLUKS **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(QCryptoBlockCreateOptionsLUKS), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_QCryptoBlockCreateOptionsLUKS_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_QCryptoBlockCreateOptionsLUKS(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_QCryptoBlockFormat(Visitor *v, const char *name, QCryptoBlockFormat *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, QCryptoBlockFormat_lookup, errp);
    *obj = value;
}

void visit_type_QCryptoBlockInfo_members(Visitor *v, QCryptoBlockInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_QCryptoBlockInfoBase_members(v, (QCryptoBlockInfoBase *)obj, &err);
    if (err) {
        goto out;
    }
    switch (obj->format) {
    case Q_CRYPTO_BLOCK_FORMAT_QCOW:
        visit_type_QCryptoBlockInfoQCow_members(v, &obj->u.qcow, &err);
        break;
    case Q_CRYPTO_BLOCK_FORMAT_LUKS:
        visit_type_QCryptoBlockInfoLUKS_members(v, &obj->u.luks, &err);
        break;
    default:
        abort();
    }

out:
    error_propagate(errp, err);
}

void visit_type_QCryptoBlockInfo(Visitor *v, const char *name, QCryptoBlockInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(QCryptoBlockInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_QCryptoBlockInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_QCryptoBlockInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_QCryptoBlockInfoBase_members(Visitor *v, QCryptoBlockInfoBase *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_QCryptoBlockFormat(v, "format", &obj->format, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_QCryptoBlockInfoBase(Visitor *v, const char *name, QCryptoBlockInfoBase **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(QCryptoBlockInfoBase), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_QCryptoBlockInfoBase_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_QCryptoBlockInfoBase(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_QCryptoBlockInfoLUKS_members(Visitor *v, QCryptoBlockInfoLUKS *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_QCryptoCipherAlgorithm(v, "cipher-alg", &obj->cipher_alg, &err);
    if (err) {
        goto out;
    }
    visit_type_QCryptoCipherMode(v, "cipher-mode", &obj->cipher_mode, &err);
    if (err) {
        goto out;
    }
    visit_type_QCryptoIVGenAlgorithm(v, "ivgen-alg", &obj->ivgen_alg, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "ivgen-hash-alg", &obj->has_ivgen_hash_alg)) {
        visit_type_QCryptoHashAlgorithm(v, "ivgen-hash-alg", &obj->ivgen_hash_alg, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_QCryptoHashAlgorithm(v, "hash-alg", &obj->hash_alg, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "payload-offset", &obj->payload_offset, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "master-key-iters", &obj->master_key_iters, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "uuid", &obj->uuid, &err);
    if (err) {
        goto out;
    }
    visit_type_QCryptoBlockInfoLUKSSlotList(v, "slots", &obj->slots, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_QCryptoBlockInfoLUKS(Visitor *v, const char *name, QCryptoBlockInfoLUKS **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(QCryptoBlockInfoLUKS), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_QCryptoBlockInfoLUKS_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_QCryptoBlockInfoLUKS(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_QCryptoBlockInfoLUKSSlot_members(Visitor *v, QCryptoBlockInfoLUKSSlot *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_bool(v, "active", &obj->active, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "iters", &obj->has_iters)) {
        visit_type_int(v, "iters", &obj->iters, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "stripes", &obj->has_stripes)) {
        visit_type_int(v, "stripes", &obj->stripes, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_int(v, "key-offset", &obj->key_offset, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_QCryptoBlockInfoLUKSSlot(Visitor *v, const char *name, QCryptoBlockInfoLUKSSlot **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(QCryptoBlockInfoLUKSSlot), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_QCryptoBlockInfoLUKSSlot_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_QCryptoBlockInfoLUKSSlot(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_QCryptoBlockInfoLUKSSlotList(Visitor *v, const char *name, QCryptoBlockInfoLUKSSlotList **obj, Error **errp)
{
    Error *err = NULL;
    QCryptoBlockInfoLUKSSlotList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (QCryptoBlockInfoLUKSSlotList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_QCryptoBlockInfoLUKSSlot(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_QCryptoBlockInfoLUKSSlotList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_QCryptoBlockInfoQCow_members(Visitor *v, QCryptoBlockInfoQCow *obj, Error **errp)
{
    Error *err = NULL;

    error_propagate(errp, err);
}

void visit_type_QCryptoBlockInfoQCow(Visitor *v, const char *name, QCryptoBlockInfoQCow **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(QCryptoBlockInfoQCow), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_QCryptoBlockInfoQCow_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_QCryptoBlockInfoQCow(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_QCryptoBlockOpenOptions_members(Visitor *v, QCryptoBlockOpenOptions *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_QCryptoBlockOptionsBase_members(v, (QCryptoBlockOptionsBase *)obj, &err);
    if (err) {
        goto out;
    }
    switch (obj->format) {
    case Q_CRYPTO_BLOCK_FORMAT_QCOW:
        visit_type_QCryptoBlockOptionsQCow_members(v, &obj->u.qcow, &err);
        break;
    case Q_CRYPTO_BLOCK_FORMAT_LUKS:
        visit_type_QCryptoBlockOptionsLUKS_members(v, &obj->u.luks, &err);
        break;
    default:
        abort();
    }

out:
    error_propagate(errp, err);
}

void visit_type_QCryptoBlockOpenOptions(Visitor *v, const char *name, QCryptoBlockOpenOptions **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(QCryptoBlockOpenOptions), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_QCryptoBlockOpenOptions_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_QCryptoBlockOpenOptions(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_QCryptoBlockOptionsBase_members(Visitor *v, QCryptoBlockOptionsBase *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_QCryptoBlockFormat(v, "format", &obj->format, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_QCryptoBlockOptionsBase(Visitor *v, const char *name, QCryptoBlockOptionsBase **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(QCryptoBlockOptionsBase), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_QCryptoBlockOptionsBase_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_QCryptoBlockOptionsBase(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_QCryptoBlockOptionsLUKS_members(Visitor *v, QCryptoBlockOptionsLUKS *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "key-secret", &obj->has_key_secret)) {
        visit_type_str(v, "key-secret", &obj->key_secret, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_QCryptoBlockOptionsLUKS(Visitor *v, const char *name, QCryptoBlockOptionsLUKS **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(QCryptoBlockOptionsLUKS), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_QCryptoBlockOptionsLUKS_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_QCryptoBlockOptionsLUKS(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_QCryptoBlockOptionsQCow_members(Visitor *v, QCryptoBlockOptionsQCow *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "key-secret", &obj->has_key_secret)) {
        visit_type_str(v, "key-secret", &obj->key_secret, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_QCryptoBlockOptionsQCow(Visitor *v, const char *name, QCryptoBlockOptionsQCow **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(QCryptoBlockOptionsQCow), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_QCryptoBlockOptionsQCow_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_QCryptoBlockOptionsQCow(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_QCryptoCipherAlgorithm(Visitor *v, const char *name, QCryptoCipherAlgorithm *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, QCryptoCipherAlgorithm_lookup, errp);
    *obj = value;
}

void visit_type_QCryptoCipherMode(Visitor *v, const char *name, QCryptoCipherMode *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, QCryptoCipherMode_lookup, errp);
    *obj = value;
}

void visit_type_QCryptoHashAlgorithm(Visitor *v, const char *name, QCryptoHashAlgorithm *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, QCryptoHashAlgorithm_lookup, errp);
    *obj = value;
}

void visit_type_QCryptoIVGenAlgorithm(Visitor *v, const char *name, QCryptoIVGenAlgorithm *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, QCryptoIVGenAlgorithm_lookup, errp);
    *obj = value;
}

void visit_type_QCryptoSecretFormat(Visitor *v, const char *name, QCryptoSecretFormat *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, QCryptoSecretFormat_lookup, errp);
    *obj = value;
}

void visit_type_QCryptoTLSCredsEndpoint(Visitor *v, const char *name, QCryptoTLSCredsEndpoint *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, QCryptoTLSCredsEndpoint_lookup, errp);
    *obj = value;
}

void visit_type_QKeyCode(Visitor *v, const char *name, QKeyCode *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, QKeyCode_lookup, errp);
    *obj = value;
}

void visit_type_QType(Visitor *v, const char *name, QType *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, QType_lookup, errp);
    *obj = value;
}

void visit_type_QapiErrorClass(Visitor *v, const char *name, QapiErrorClass *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, QapiErrorClass_lookup, errp);
    *obj = value;
}

void visit_type_Qcow2OverlapCheckFlags_members(Visitor *v, Qcow2OverlapCheckFlags *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "template", &obj->has_q_template)) {
        visit_type_Qcow2OverlapCheckMode(v, "template", &obj->q_template, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "main-header", &obj->has_main_header)) {
        visit_type_bool(v, "main-header", &obj->main_header, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "active-l1", &obj->has_active_l1)) {
        visit_type_bool(v, "active-l1", &obj->active_l1, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "active-l2", &obj->has_active_l2)) {
        visit_type_bool(v, "active-l2", &obj->active_l2, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "refcount-table", &obj->has_refcount_table)) {
        visit_type_bool(v, "refcount-table", &obj->refcount_table, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "refcount-block", &obj->has_refcount_block)) {
        visit_type_bool(v, "refcount-block", &obj->refcount_block, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "snapshot-table", &obj->has_snapshot_table)) {
        visit_type_bool(v, "snapshot-table", &obj->snapshot_table, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "inactive-l1", &obj->has_inactive_l1)) {
        visit_type_bool(v, "inactive-l1", &obj->inactive_l1, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "inactive-l2", &obj->has_inactive_l2)) {
        visit_type_bool(v, "inactive-l2", &obj->inactive_l2, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_Qcow2OverlapCheckFlags(Visitor *v, const char *name, Qcow2OverlapCheckFlags **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(Qcow2OverlapCheckFlags), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_Qcow2OverlapCheckFlags_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_Qcow2OverlapCheckFlags(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_Qcow2OverlapCheckMode(Visitor *v, const char *name, Qcow2OverlapCheckMode *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, Qcow2OverlapCheckMode_lookup, errp);
    *obj = value;
}

void visit_type_Qcow2OverlapChecks(Visitor *v, const char *name, Qcow2OverlapChecks **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_alternate(v, name, (GenericAlternate **)obj, sizeof(**obj),
                          true, &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    switch ((*obj)->type) {
    case QTYPE_QDICT:
        visit_start_struct(v, name, NULL, 0, &err);
        if (err) {
            break;
        }
        visit_type_Qcow2OverlapCheckFlags_members(v, &(*obj)->u.flags, &err);
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        break;
    case QTYPE_QSTRING:
        visit_type_Qcow2OverlapCheckMode(v, name, &(*obj)->u.mode, &err);
        break;
    case QTYPE_NONE:
        abort();
    default:
        error_setg(&err, QERR_INVALID_PARAMETER_TYPE, name ? name : "null",
                   "Qcow2OverlapChecks");
    }
out_obj:
    visit_end_alternate(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_Qcow2OverlapChecks(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_QuorumOpType(Visitor *v, const char *name, QuorumOpType *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, QuorumOpType_lookup, errp);
    *obj = value;
}

void visit_type_QuorumReadPattern(Visitor *v, const char *name, QuorumReadPattern *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, QuorumReadPattern_lookup, errp);
    *obj = value;
}

void visit_type_ReplayMode(Visitor *v, const char *name, ReplayMode *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, ReplayMode_lookup, errp);
    *obj = value;
}

void visit_type_ReplicationMode(Visitor *v, const char *name, ReplicationMode *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, ReplicationMode_lookup, errp);
    *obj = value;
}

void visit_type_ReplicationStatus_members(Visitor *v, ReplicationStatus *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_bool(v, "error", &obj->error, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "desc", &obj->has_desc)) {
        visit_type_str(v, "desc", &obj->desc, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_ReplicationStatus(Visitor *v, const char *name, ReplicationStatus **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(ReplicationStatus), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_ReplicationStatus_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_ReplicationStatus(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_RockerOfDpaFlow_members(Visitor *v, RockerOfDpaFlow *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_uint64(v, "cookie", &obj->cookie, &err);
    if (err) {
        goto out;
    }
    visit_type_uint64(v, "hits", &obj->hits, &err);
    if (err) {
        goto out;
    }
    visit_type_RockerOfDpaFlowKey(v, "key", &obj->key, &err);
    if (err) {
        goto out;
    }
    visit_type_RockerOfDpaFlowMask(v, "mask", &obj->mask, &err);
    if (err) {
        goto out;
    }
    visit_type_RockerOfDpaFlowAction(v, "action", &obj->action, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_RockerOfDpaFlow(Visitor *v, const char *name, RockerOfDpaFlow **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(RockerOfDpaFlow), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_RockerOfDpaFlow_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_RockerOfDpaFlow(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_RockerOfDpaFlowAction_members(Visitor *v, RockerOfDpaFlowAction *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "goto-tbl", &obj->has_goto_tbl)) {
        visit_type_uint32(v, "goto-tbl", &obj->goto_tbl, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "group-id", &obj->has_group_id)) {
        visit_type_uint32(v, "group-id", &obj->group_id, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "tunnel-lport", &obj->has_tunnel_lport)) {
        visit_type_uint32(v, "tunnel-lport", &obj->tunnel_lport, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "vlan-id", &obj->has_vlan_id)) {
        visit_type_uint16(v, "vlan-id", &obj->vlan_id, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "new-vlan-id", &obj->has_new_vlan_id)) {
        visit_type_uint16(v, "new-vlan-id", &obj->new_vlan_id, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "out-pport", &obj->has_out_pport)) {
        visit_type_uint32(v, "out-pport", &obj->out_pport, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_RockerOfDpaFlowAction(Visitor *v, const char *name, RockerOfDpaFlowAction **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(RockerOfDpaFlowAction), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_RockerOfDpaFlowAction_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_RockerOfDpaFlowAction(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_RockerOfDpaFlowKey_members(Visitor *v, RockerOfDpaFlowKey *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_uint32(v, "priority", &obj->priority, &err);
    if (err) {
        goto out;
    }
    visit_type_uint32(v, "tbl-id", &obj->tbl_id, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "in-pport", &obj->has_in_pport)) {
        visit_type_uint32(v, "in-pport", &obj->in_pport, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "tunnel-id", &obj->has_tunnel_id)) {
        visit_type_uint32(v, "tunnel-id", &obj->tunnel_id, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "vlan-id", &obj->has_vlan_id)) {
        visit_type_uint16(v, "vlan-id", &obj->vlan_id, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "eth-type", &obj->has_eth_type)) {
        visit_type_uint16(v, "eth-type", &obj->eth_type, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "eth-src", &obj->has_eth_src)) {
        visit_type_str(v, "eth-src", &obj->eth_src, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "eth-dst", &obj->has_eth_dst)) {
        visit_type_str(v, "eth-dst", &obj->eth_dst, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "ip-proto", &obj->has_ip_proto)) {
        visit_type_uint8(v, "ip-proto", &obj->ip_proto, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "ip-tos", &obj->has_ip_tos)) {
        visit_type_uint8(v, "ip-tos", &obj->ip_tos, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "ip-dst", &obj->has_ip_dst)) {
        visit_type_str(v, "ip-dst", &obj->ip_dst, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_RockerOfDpaFlowKey(Visitor *v, const char *name, RockerOfDpaFlowKey **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(RockerOfDpaFlowKey), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_RockerOfDpaFlowKey_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_RockerOfDpaFlowKey(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_RockerOfDpaFlowList(Visitor *v, const char *name, RockerOfDpaFlowList **obj, Error **errp)
{
    Error *err = NULL;
    RockerOfDpaFlowList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (RockerOfDpaFlowList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_RockerOfDpaFlow(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_RockerOfDpaFlowList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_RockerOfDpaFlowMask_members(Visitor *v, RockerOfDpaFlowMask *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "in-pport", &obj->has_in_pport)) {
        visit_type_uint32(v, "in-pport", &obj->in_pport, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "tunnel-id", &obj->has_tunnel_id)) {
        visit_type_uint32(v, "tunnel-id", &obj->tunnel_id, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "vlan-id", &obj->has_vlan_id)) {
        visit_type_uint16(v, "vlan-id", &obj->vlan_id, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "eth-src", &obj->has_eth_src)) {
        visit_type_str(v, "eth-src", &obj->eth_src, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "eth-dst", &obj->has_eth_dst)) {
        visit_type_str(v, "eth-dst", &obj->eth_dst, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "ip-proto", &obj->has_ip_proto)) {
        visit_type_uint8(v, "ip-proto", &obj->ip_proto, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "ip-tos", &obj->has_ip_tos)) {
        visit_type_uint8(v, "ip-tos", &obj->ip_tos, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_RockerOfDpaFlowMask(Visitor *v, const char *name, RockerOfDpaFlowMask **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(RockerOfDpaFlowMask), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_RockerOfDpaFlowMask_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_RockerOfDpaFlowMask(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_RockerOfDpaGroup_members(Visitor *v, RockerOfDpaGroup *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_uint32(v, "id", &obj->id, &err);
    if (err) {
        goto out;
    }
    visit_type_uint8(v, "type", &obj->type, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "vlan-id", &obj->has_vlan_id)) {
        visit_type_uint16(v, "vlan-id", &obj->vlan_id, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "pport", &obj->has_pport)) {
        visit_type_uint32(v, "pport", &obj->pport, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "index", &obj->has_index)) {
        visit_type_uint32(v, "index", &obj->index, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "out-pport", &obj->has_out_pport)) {
        visit_type_uint32(v, "out-pport", &obj->out_pport, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "group-id", &obj->has_group_id)) {
        visit_type_uint32(v, "group-id", &obj->group_id, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "set-vlan-id", &obj->has_set_vlan_id)) {
        visit_type_uint16(v, "set-vlan-id", &obj->set_vlan_id, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "pop-vlan", &obj->has_pop_vlan)) {
        visit_type_uint8(v, "pop-vlan", &obj->pop_vlan, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "group-ids", &obj->has_group_ids)) {
        visit_type_uint32List(v, "group-ids", &obj->group_ids, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "set-eth-src", &obj->has_set_eth_src)) {
        visit_type_str(v, "set-eth-src", &obj->set_eth_src, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "set-eth-dst", &obj->has_set_eth_dst)) {
        visit_type_str(v, "set-eth-dst", &obj->set_eth_dst, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "ttl-check", &obj->has_ttl_check)) {
        visit_type_uint8(v, "ttl-check", &obj->ttl_check, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_RockerOfDpaGroup(Visitor *v, const char *name, RockerOfDpaGroup **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(RockerOfDpaGroup), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_RockerOfDpaGroup_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_RockerOfDpaGroup(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_RockerOfDpaGroupList(Visitor *v, const char *name, RockerOfDpaGroupList **obj, Error **errp)
{
    Error *err = NULL;
    RockerOfDpaGroupList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (RockerOfDpaGroupList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_RockerOfDpaGroup(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_RockerOfDpaGroupList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_RockerPort_members(Visitor *v, RockerPort *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "name", &obj->name, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "enabled", &obj->enabled, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "link-up", &obj->link_up, &err);
    if (err) {
        goto out;
    }
    visit_type_uint32(v, "speed", &obj->speed, &err);
    if (err) {
        goto out;
    }
    visit_type_RockerPortDuplex(v, "duplex", &obj->duplex, &err);
    if (err) {
        goto out;
    }
    visit_type_RockerPortAutoneg(v, "autoneg", &obj->autoneg, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_RockerPort(Visitor *v, const char *name, RockerPort **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(RockerPort), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_RockerPort_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_RockerPort(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_RockerPortAutoneg(Visitor *v, const char *name, RockerPortAutoneg *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, RockerPortAutoneg_lookup, errp);
    *obj = value;
}

void visit_type_RockerPortDuplex(Visitor *v, const char *name, RockerPortDuplex *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, RockerPortDuplex_lookup, errp);
    *obj = value;
}

void visit_type_RockerPortList(Visitor *v, const char *name, RockerPortList **obj, Error **errp)
{
    Error *err = NULL;
    RockerPortList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (RockerPortList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_RockerPort(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_RockerPortList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_RockerSwitch_members(Visitor *v, RockerSwitch *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "name", &obj->name, &err);
    if (err) {
        goto out;
    }
    visit_type_uint64(v, "id", &obj->id, &err);
    if (err) {
        goto out;
    }
    visit_type_uint32(v, "ports", &obj->ports, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_RockerSwitch(Visitor *v, const char *name, RockerSwitch **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(RockerSwitch), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_RockerSwitch_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_RockerSwitch(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_RunState(Visitor *v, const char *name, RunState *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, RunState_lookup, errp);
    *obj = value;
}

void visit_type_RxFilterInfo_members(Visitor *v, RxFilterInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "name", &obj->name, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "promiscuous", &obj->promiscuous, &err);
    if (err) {
        goto out;
    }
    visit_type_RxState(v, "multicast", &obj->multicast, &err);
    if (err) {
        goto out;
    }
    visit_type_RxState(v, "unicast", &obj->unicast, &err);
    if (err) {
        goto out;
    }
    visit_type_RxState(v, "vlan", &obj->vlan, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "broadcast-allowed", &obj->broadcast_allowed, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "multicast-overflow", &obj->multicast_overflow, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "unicast-overflow", &obj->unicast_overflow, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "main-mac", &obj->main_mac, &err);
    if (err) {
        goto out;
    }
    visit_type_intList(v, "vlan-table", &obj->vlan_table, &err);
    if (err) {
        goto out;
    }
    visit_type_strList(v, "unicast-table", &obj->unicast_table, &err);
    if (err) {
        goto out;
    }
    visit_type_strList(v, "multicast-table", &obj->multicast_table, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_RxFilterInfo(Visitor *v, const char *name, RxFilterInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(RxFilterInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_RxFilterInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_RxFilterInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_RxFilterInfoList(Visitor *v, const char *name, RxFilterInfoList **obj, Error **errp)
{
    Error *err = NULL;
    RxFilterInfoList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (RxFilterInfoList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_RxFilterInfo(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_RxFilterInfoList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_RxState(Visitor *v, const char *name, RxState *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, RxState_lookup, errp);
    *obj = value;
}

void visit_type_SchemaInfo_members(Visitor *v, SchemaInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_q_obj_SchemaInfo_base_members(v, (q_obj_SchemaInfo_base *)obj, &err);
    if (err) {
        goto out;
    }
    switch (obj->meta_type) {
    case SCHEMA_META_TYPE_BUILTIN:
        visit_type_SchemaInfoBuiltin_members(v, &obj->u.builtin, &err);
        break;
    case SCHEMA_META_TYPE_ENUM:
        visit_type_SchemaInfoEnum_members(v, &obj->u.q_enum, &err);
        break;
    case SCHEMA_META_TYPE_ARRAY:
        visit_type_SchemaInfoArray_members(v, &obj->u.array, &err);
        break;
    case SCHEMA_META_TYPE_OBJECT:
        visit_type_SchemaInfoObject_members(v, &obj->u.object, &err);
        break;
    case SCHEMA_META_TYPE_ALTERNATE:
        visit_type_SchemaInfoAlternate_members(v, &obj->u.alternate, &err);
        break;
    case SCHEMA_META_TYPE_COMMAND:
        visit_type_SchemaInfoCommand_members(v, &obj->u.command, &err);
        break;
    case SCHEMA_META_TYPE_EVENT:
        visit_type_SchemaInfoEvent_members(v, &obj->u.event, &err);
        break;
    default:
        abort();
    }

out:
    error_propagate(errp, err);
}

void visit_type_SchemaInfo(Visitor *v, const char *name, SchemaInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(SchemaInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_SchemaInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_SchemaInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_SchemaInfoAlternate_members(Visitor *v, SchemaInfoAlternate *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_SchemaInfoAlternateMemberList(v, "members", &obj->members, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_SchemaInfoAlternate(Visitor *v, const char *name, SchemaInfoAlternate **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(SchemaInfoAlternate), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_SchemaInfoAlternate_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_SchemaInfoAlternate(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_SchemaInfoAlternateMember_members(Visitor *v, SchemaInfoAlternateMember *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "type", &obj->type, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_SchemaInfoAlternateMember(Visitor *v, const char *name, SchemaInfoAlternateMember **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(SchemaInfoAlternateMember), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_SchemaInfoAlternateMember_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_SchemaInfoAlternateMember(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_SchemaInfoAlternateMemberList(Visitor *v, const char *name, SchemaInfoAlternateMemberList **obj, Error **errp)
{
    Error *err = NULL;
    SchemaInfoAlternateMemberList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (SchemaInfoAlternateMemberList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_SchemaInfoAlternateMember(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_SchemaInfoAlternateMemberList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_SchemaInfoArray_members(Visitor *v, SchemaInfoArray *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "element-type", &obj->element_type, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_SchemaInfoArray(Visitor *v, const char *name, SchemaInfoArray **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(SchemaInfoArray), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_SchemaInfoArray_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_SchemaInfoArray(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_SchemaInfoBuiltin_members(Visitor *v, SchemaInfoBuiltin *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_JSONType(v, "json-type", &obj->json_type, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_SchemaInfoBuiltin(Visitor *v, const char *name, SchemaInfoBuiltin **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(SchemaInfoBuiltin), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_SchemaInfoBuiltin_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_SchemaInfoBuiltin(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_SchemaInfoCommand_members(Visitor *v, SchemaInfoCommand *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "arg-type", &obj->arg_type, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "ret-type", &obj->ret_type, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_SchemaInfoCommand(Visitor *v, const char *name, SchemaInfoCommand **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(SchemaInfoCommand), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_SchemaInfoCommand_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_SchemaInfoCommand(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_SchemaInfoEnum_members(Visitor *v, SchemaInfoEnum *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_strList(v, "values", &obj->values, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_SchemaInfoEnum(Visitor *v, const char *name, SchemaInfoEnum **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(SchemaInfoEnum), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_SchemaInfoEnum_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_SchemaInfoEnum(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_SchemaInfoEvent_members(Visitor *v, SchemaInfoEvent *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "arg-type", &obj->arg_type, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_SchemaInfoEvent(Visitor *v, const char *name, SchemaInfoEvent **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(SchemaInfoEvent), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_SchemaInfoEvent_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_SchemaInfoEvent(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_SchemaInfoList(Visitor *v, const char *name, SchemaInfoList **obj, Error **errp)
{
    Error *err = NULL;
    SchemaInfoList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (SchemaInfoList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_SchemaInfo(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_SchemaInfoList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_SchemaInfoObject_members(Visitor *v, SchemaInfoObject *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_SchemaInfoObjectMemberList(v, "members", &obj->members, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "tag", &obj->has_tag)) {
        visit_type_str(v, "tag", &obj->tag, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "variants", &obj->has_variants)) {
        visit_type_SchemaInfoObjectVariantList(v, "variants", &obj->variants, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_SchemaInfoObject(Visitor *v, const char *name, SchemaInfoObject **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(SchemaInfoObject), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_SchemaInfoObject_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_SchemaInfoObject(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_SchemaInfoObjectMember_members(Visitor *v, SchemaInfoObjectMember *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "name", &obj->name, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "type", &obj->type, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "default", &obj->has_q_default)) {
        visit_type_any(v, "default", &obj->q_default, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_SchemaInfoObjectMember(Visitor *v, const char *name, SchemaInfoObjectMember **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(SchemaInfoObjectMember), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_SchemaInfoObjectMember_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_SchemaInfoObjectMember(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_SchemaInfoObjectMemberList(Visitor *v, const char *name, SchemaInfoObjectMemberList **obj, Error **errp)
{
    Error *err = NULL;
    SchemaInfoObjectMemberList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (SchemaInfoObjectMemberList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_SchemaInfoObjectMember(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_SchemaInfoObjectMemberList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_SchemaInfoObjectVariant_members(Visitor *v, SchemaInfoObjectVariant *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "case", &obj->q_case, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "type", &obj->type, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_SchemaInfoObjectVariant(Visitor *v, const char *name, SchemaInfoObjectVariant **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(SchemaInfoObjectVariant), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_SchemaInfoObjectVariant_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_SchemaInfoObjectVariant(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_SchemaInfoObjectVariantList(Visitor *v, const char *name, SchemaInfoObjectVariantList **obj, Error **errp)
{
    Error *err = NULL;
    SchemaInfoObjectVariantList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (SchemaInfoObjectVariantList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_SchemaInfoObjectVariant(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_SchemaInfoObjectVariantList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_SchemaMetaType(Visitor *v, const char *name, SchemaMetaType *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, SchemaMetaType_lookup, errp);
    *obj = value;
}

void visit_type_SnapshotInfo_members(Visitor *v, SnapshotInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "id", &obj->id, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "name", &obj->name, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "vm-state-size", &obj->vm_state_size, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "date-sec", &obj->date_sec, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "date-nsec", &obj->date_nsec, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "vm-clock-sec", &obj->vm_clock_sec, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "vm-clock-nsec", &obj->vm_clock_nsec, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_SnapshotInfo(Visitor *v, const char *name, SnapshotInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(SnapshotInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_SnapshotInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_SnapshotInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_SnapshotInfoList(Visitor *v, const char *name, SnapshotInfoList **obj, Error **errp)
{
    Error *err = NULL;
    SnapshotInfoList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (SnapshotInfoList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_SnapshotInfo(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_SnapshotInfoList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_SocketAddress_members(Visitor *v, SocketAddress *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_SocketAddressKind(v, "type", &obj->type, &err);
    if (err) {
        goto out;
    }
    switch (obj->type) {
    case SOCKET_ADDRESS_KIND_INET:
        visit_type_q_obj_InetSocketAddress_wrapper_members(v, &obj->u.inet, &err);
        break;
    case SOCKET_ADDRESS_KIND_UNIX:
        visit_type_q_obj_UnixSocketAddress_wrapper_members(v, &obj->u.q_unix, &err);
        break;
    case SOCKET_ADDRESS_KIND_VSOCK:
        visit_type_q_obj_VsockSocketAddress_wrapper_members(v, &obj->u.vsock, &err);
        break;
    case SOCKET_ADDRESS_KIND_FD:
        visit_type_q_obj_String_wrapper_members(v, &obj->u.fd, &err);
        break;
    default:
        abort();
    }

out:
    error_propagate(errp, err);
}

void visit_type_SocketAddress(Visitor *v, const char *name, SocketAddress **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(SocketAddress), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_SocketAddress_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_SocketAddress(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_SocketAddressFlat_members(Visitor *v, SocketAddressFlat *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_q_obj_SocketAddressFlat_base_members(v, (q_obj_SocketAddressFlat_base *)obj, &err);
    if (err) {
        goto out;
    }
    switch (obj->type) {
    case SOCKET_ADDRESS_FLAT_TYPE_INET:
        visit_type_InetSocketAddress_members(v, &obj->u.inet, &err);
        break;
    case SOCKET_ADDRESS_FLAT_TYPE_UNIX:
        visit_type_UnixSocketAddress_members(v, &obj->u.q_unix, &err);
        break;
    case SOCKET_ADDRESS_FLAT_TYPE_VSOCK:
        visit_type_VsockSocketAddress_members(v, &obj->u.vsock, &err);
        break;
    case SOCKET_ADDRESS_FLAT_TYPE_FD:
        visit_type_String_members(v, &obj->u.fd, &err);
        break;
    default:
        abort();
    }

out:
    error_propagate(errp, err);
}

void visit_type_SocketAddressFlat(Visitor *v, const char *name, SocketAddressFlat **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(SocketAddressFlat), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_SocketAddressFlat_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_SocketAddressFlat(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_SocketAddressFlatList(Visitor *v, const char *name, SocketAddressFlatList **obj, Error **errp)
{
    Error *err = NULL;
    SocketAddressFlatList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (SocketAddressFlatList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_SocketAddressFlat(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_SocketAddressFlatList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_SocketAddressFlatType(Visitor *v, const char *name, SocketAddressFlatType *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, SocketAddressFlatType_lookup, errp);
    *obj = value;
}

void visit_type_SocketAddressKind(Visitor *v, const char *name, SocketAddressKind *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, SocketAddressKind_lookup, errp);
    *obj = value;
}

void visit_type_SpiceBasicInfo_members(Visitor *v, SpiceBasicInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "host", &obj->host, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "port", &obj->port, &err);
    if (err) {
        goto out;
    }
    visit_type_NetworkAddressFamily(v, "family", &obj->family, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_SpiceBasicInfo(Visitor *v, const char *name, SpiceBasicInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(SpiceBasicInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_SpiceBasicInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_SpiceBasicInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_SpiceChannel_members(Visitor *v, SpiceChannel *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_SpiceBasicInfo_members(v, (SpiceBasicInfo *)obj, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "connection-id", &obj->connection_id, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "channel-type", &obj->channel_type, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "channel-id", &obj->channel_id, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "tls", &obj->tls, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_SpiceChannel(Visitor *v, const char *name, SpiceChannel **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(SpiceChannel), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_SpiceChannel_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_SpiceChannel(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_SpiceChannelList(Visitor *v, const char *name, SpiceChannelList **obj, Error **errp)
{
    Error *err = NULL;
    SpiceChannelList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (SpiceChannelList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_SpiceChannel(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_SpiceChannelList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_SpiceInfo_members(Visitor *v, SpiceInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_bool(v, "enabled", &obj->enabled, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "migrated", &obj->migrated, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "host", &obj->has_host)) {
        visit_type_str(v, "host", &obj->host, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "port", &obj->has_port)) {
        visit_type_int(v, "port", &obj->port, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "tls-port", &obj->has_tls_port)) {
        visit_type_int(v, "tls-port", &obj->tls_port, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "auth", &obj->has_auth)) {
        visit_type_str(v, "auth", &obj->auth, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "compiled-version", &obj->has_compiled_version)) {
        visit_type_str(v, "compiled-version", &obj->compiled_version, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_SpiceQueryMouseMode(v, "mouse-mode", &obj->mouse_mode, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "channels", &obj->has_channels)) {
        visit_type_SpiceChannelList(v, "channels", &obj->channels, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_SpiceInfo(Visitor *v, const char *name, SpiceInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(SpiceInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_SpiceInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_SpiceInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_SpiceQueryMouseMode(Visitor *v, const char *name, SpiceQueryMouseMode *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, SpiceQueryMouseMode_lookup, errp);
    *obj = value;
}

void visit_type_SpiceServerInfo_members(Visitor *v, SpiceServerInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_SpiceBasicInfo_members(v, (SpiceBasicInfo *)obj, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "auth", &obj->has_auth)) {
        visit_type_str(v, "auth", &obj->auth, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_SpiceServerInfo(Visitor *v, const char *name, SpiceServerInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(SpiceServerInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_SpiceServerInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_SpiceServerInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_StatusInfo_members(Visitor *v, StatusInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_bool(v, "running", &obj->running, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "singlestep", &obj->singlestep, &err);
    if (err) {
        goto out;
    }
    visit_type_RunState(v, "status", &obj->status, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_StatusInfo(Visitor *v, const char *name, StatusInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(StatusInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_StatusInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_StatusInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_String_members(Visitor *v, String *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "str", &obj->str, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_String(Visitor *v, const char *name, String **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(String), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_String_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_String(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_StringList(Visitor *v, const char *name, StringList **obj, Error **errp)
{
    Error *err = NULL;
    StringList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (StringList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_String(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_StringList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_TPMInfo_members(Visitor *v, TPMInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "id", &obj->id, &err);
    if (err) {
        goto out;
    }
    visit_type_TpmModel(v, "model", &obj->model, &err);
    if (err) {
        goto out;
    }
    visit_type_TpmTypeOptions(v, "options", &obj->options, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_TPMInfo(Visitor *v, const char *name, TPMInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(TPMInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_TPMInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_TPMInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_TPMInfoList(Visitor *v, const char *name, TPMInfoList **obj, Error **errp)
{
    Error *err = NULL;
    TPMInfoList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (TPMInfoList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_TPMInfo(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_TPMInfoList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_TPMPassthroughOptions_members(Visitor *v, TPMPassthroughOptions *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "path", &obj->has_path)) {
        visit_type_str(v, "path", &obj->path, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "cancel-path", &obj->has_cancel_path)) {
        visit_type_str(v, "cancel-path", &obj->cancel_path, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_TPMPassthroughOptions(Visitor *v, const char *name, TPMPassthroughOptions **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(TPMPassthroughOptions), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_TPMPassthroughOptions_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_TPMPassthroughOptions(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_TargetInfo_members(Visitor *v, TargetInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "arch", &obj->arch, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_TargetInfo(Visitor *v, const char *name, TargetInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(TargetInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_TargetInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_TargetInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_TpmModel(Visitor *v, const char *name, TpmModel *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, TpmModel_lookup, errp);
    *obj = value;
}

void visit_type_TpmModelList(Visitor *v, const char *name, TpmModelList **obj, Error **errp)
{
    Error *err = NULL;
    TpmModelList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (TpmModelList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_TpmModel(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_TpmModelList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_TpmType(Visitor *v, const char *name, TpmType *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, TpmType_lookup, errp);
    *obj = value;
}

void visit_type_TpmTypeList(Visitor *v, const char *name, TpmTypeList **obj, Error **errp)
{
    Error *err = NULL;
    TpmTypeList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (TpmTypeList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_TpmType(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_TpmTypeList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_TpmTypeOptions_members(Visitor *v, TpmTypeOptions *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_TpmTypeOptionsKind(v, "type", &obj->type, &err);
    if (err) {
        goto out;
    }
    switch (obj->type) {
    case TPM_TYPE_OPTIONS_KIND_PASSTHROUGH:
        visit_type_q_obj_TPMPassthroughOptions_wrapper_members(v, &obj->u.passthrough, &err);
        break;
    default:
        abort();
    }

out:
    error_propagate(errp, err);
}

void visit_type_TpmTypeOptions(Visitor *v, const char *name, TpmTypeOptions **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(TpmTypeOptions), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_TpmTypeOptions_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_TpmTypeOptions(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_TpmTypeOptionsKind(Visitor *v, const char *name, TpmTypeOptionsKind *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, TpmTypeOptionsKind_lookup, errp);
    *obj = value;
}

void visit_type_TraceEventInfo_members(Visitor *v, TraceEventInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "name", &obj->name, &err);
    if (err) {
        goto out;
    }
    visit_type_TraceEventState(v, "state", &obj->state, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "vcpu", &obj->vcpu, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_TraceEventInfo(Visitor *v, const char *name, TraceEventInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(TraceEventInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_TraceEventInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_TraceEventInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_TraceEventInfoList(Visitor *v, const char *name, TraceEventInfoList **obj, Error **errp)
{
    Error *err = NULL;
    TraceEventInfoList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (TraceEventInfoList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_TraceEventInfo(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_TraceEventInfoList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_TraceEventState(Visitor *v, const char *name, TraceEventState *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, TraceEventState_lookup, errp);
    *obj = value;
}

void visit_type_TransactionAction_members(Visitor *v, TransactionAction *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_TransactionActionKind(v, "type", &obj->type, &err);
    if (err) {
        goto out;
    }
    switch (obj->type) {
    case TRANSACTION_ACTION_KIND_ABORT:
        visit_type_q_obj_Abort_wrapper_members(v, &obj->u.abort, &err);
        break;
    case TRANSACTION_ACTION_KIND_BLOCK_DIRTY_BITMAP_ADD:
        visit_type_q_obj_BlockDirtyBitmapAdd_wrapper_members(v, &obj->u.block_dirty_bitmap_add, &err);
        break;
    case TRANSACTION_ACTION_KIND_BLOCK_DIRTY_BITMAP_CLEAR:
        visit_type_q_obj_BlockDirtyBitmap_wrapper_members(v, &obj->u.block_dirty_bitmap_clear, &err);
        break;
    case TRANSACTION_ACTION_KIND_BLOCKDEV_BACKUP:
        visit_type_q_obj_BlockdevBackup_wrapper_members(v, &obj->u.blockdev_backup, &err);
        break;
    case TRANSACTION_ACTION_KIND_BLOCKDEV_SNAPSHOT:
        visit_type_q_obj_BlockdevSnapshot_wrapper_members(v, &obj->u.blockdev_snapshot, &err);
        break;
    case TRANSACTION_ACTION_KIND_BLOCKDEV_SNAPSHOT_INTERNAL_SYNC:
        visit_type_q_obj_BlockdevSnapshotInternal_wrapper_members(v, &obj->u.blockdev_snapshot_internal_sync, &err);
        break;
    case TRANSACTION_ACTION_KIND_BLOCKDEV_SNAPSHOT_SYNC:
        visit_type_q_obj_BlockdevSnapshotSync_wrapper_members(v, &obj->u.blockdev_snapshot_sync, &err);
        break;
    case TRANSACTION_ACTION_KIND_DRIVE_BACKUP:
        visit_type_q_obj_DriveBackup_wrapper_members(v, &obj->u.drive_backup, &err);
        break;
    default:
        abort();
    }

out:
    error_propagate(errp, err);
}

void visit_type_TransactionAction(Visitor *v, const char *name, TransactionAction **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(TransactionAction), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_TransactionAction_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_TransactionAction(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_TransactionActionKind(Visitor *v, const char *name, TransactionActionKind *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, TransactionActionKind_lookup, errp);
    *obj = value;
}

void visit_type_TransactionActionList(Visitor *v, const char *name, TransactionActionList **obj, Error **errp)
{
    Error *err = NULL;
    TransactionActionList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (TransactionActionList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_TransactionAction(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_TransactionActionList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_TransactionProperties_members(Visitor *v, TransactionProperties *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "completion-mode", &obj->has_completion_mode)) {
        visit_type_ActionCompletionMode(v, "completion-mode", &obj->completion_mode, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_TransactionProperties(Visitor *v, const char *name, TransactionProperties **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(TransactionProperties), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_TransactionProperties_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_TransactionProperties(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_UnixSocketAddress_members(Visitor *v, UnixSocketAddress *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "path", &obj->path, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_UnixSocketAddress(Visitor *v, const char *name, UnixSocketAddress **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(UnixSocketAddress), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_UnixSocketAddress_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_UnixSocketAddress(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_UuidInfo_members(Visitor *v, UuidInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "UUID", &obj->UUID, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_UuidInfo(Visitor *v, const char *name, UuidInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(UuidInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_UuidInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_UuidInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_VersionInfo_members(Visitor *v, VersionInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_VersionTriple(v, "qemu", &obj->qemu, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "package", &obj->package, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_VersionInfo(Visitor *v, const char *name, VersionInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(VersionInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_VersionInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_VersionInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_VersionTriple_members(Visitor *v, VersionTriple *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, "major", &obj->major, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "minor", &obj->minor, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "micro", &obj->micro, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_VersionTriple(Visitor *v, const char *name, VersionTriple **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(VersionTriple), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_VersionTriple_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_VersionTriple(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_VncBasicInfo_members(Visitor *v, VncBasicInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "host", &obj->host, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "service", &obj->service, &err);
    if (err) {
        goto out;
    }
    visit_type_NetworkAddressFamily(v, "family", &obj->family, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "websocket", &obj->websocket, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_VncBasicInfo(Visitor *v, const char *name, VncBasicInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(VncBasicInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_VncBasicInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_VncBasicInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_VncClientInfo_members(Visitor *v, VncClientInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_VncBasicInfo_members(v, (VncBasicInfo *)obj, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "x509_dname", &obj->has_x509_dname)) {
        visit_type_str(v, "x509_dname", &obj->x509_dname, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "sasl_username", &obj->has_sasl_username)) {
        visit_type_str(v, "sasl_username", &obj->sasl_username, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_VncClientInfo(Visitor *v, const char *name, VncClientInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(VncClientInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_VncClientInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_VncClientInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_VncClientInfoList(Visitor *v, const char *name, VncClientInfoList **obj, Error **errp)
{
    Error *err = NULL;
    VncClientInfoList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (VncClientInfoList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_VncClientInfo(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_VncClientInfoList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_VncInfo_members(Visitor *v, VncInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_bool(v, "enabled", &obj->enabled, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "host", &obj->has_host)) {
        visit_type_str(v, "host", &obj->host, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "family", &obj->has_family)) {
        visit_type_NetworkAddressFamily(v, "family", &obj->family, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "service", &obj->has_service)) {
        visit_type_str(v, "service", &obj->service, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "auth", &obj->has_auth)) {
        visit_type_str(v, "auth", &obj->auth, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "clients", &obj->has_clients)) {
        visit_type_VncClientInfoList(v, "clients", &obj->clients, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_VncInfo(Visitor *v, const char *name, VncInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(VncInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_VncInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_VncInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_VncInfo2_members(Visitor *v, VncInfo2 *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "id", &obj->id, &err);
    if (err) {
        goto out;
    }
    visit_type_VncServerInfo2List(v, "server", &obj->server, &err);
    if (err) {
        goto out;
    }
    visit_type_VncClientInfoList(v, "clients", &obj->clients, &err);
    if (err) {
        goto out;
    }
    visit_type_VncPrimaryAuth(v, "auth", &obj->auth, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "vencrypt", &obj->has_vencrypt)) {
        visit_type_VncVencryptSubAuth(v, "vencrypt", &obj->vencrypt, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "display", &obj->has_display)) {
        visit_type_str(v, "display", &obj->display, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_VncInfo2(Visitor *v, const char *name, VncInfo2 **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(VncInfo2), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_VncInfo2_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_VncInfo2(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_VncInfo2List(Visitor *v, const char *name, VncInfo2List **obj, Error **errp)
{
    Error *err = NULL;
    VncInfo2List *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (VncInfo2List *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_VncInfo2(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_VncInfo2List(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_VncPrimaryAuth(Visitor *v, const char *name, VncPrimaryAuth *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, VncPrimaryAuth_lookup, errp);
    *obj = value;
}

void visit_type_VncServerInfo_members(Visitor *v, VncServerInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_VncBasicInfo_members(v, (VncBasicInfo *)obj, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "auth", &obj->has_auth)) {
        visit_type_str(v, "auth", &obj->auth, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_VncServerInfo(Visitor *v, const char *name, VncServerInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(VncServerInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_VncServerInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_VncServerInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_VncServerInfo2_members(Visitor *v, VncServerInfo2 *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_VncBasicInfo_members(v, (VncBasicInfo *)obj, &err);
    if (err) {
        goto out;
    }
    visit_type_VncPrimaryAuth(v, "auth", &obj->auth, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "vencrypt", &obj->has_vencrypt)) {
        visit_type_VncVencryptSubAuth(v, "vencrypt", &obj->vencrypt, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_VncServerInfo2(Visitor *v, const char *name, VncServerInfo2 **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(VncServerInfo2), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_VncServerInfo2_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_VncServerInfo2(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_VncServerInfo2List(Visitor *v, const char *name, VncServerInfo2List **obj, Error **errp)
{
    Error *err = NULL;
    VncServerInfo2List *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (VncServerInfo2List *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_VncServerInfo2(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_VncServerInfo2List(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_VncVencryptSubAuth(Visitor *v, const char *name, VncVencryptSubAuth *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, VncVencryptSubAuth_lookup, errp);
    *obj = value;
}

void visit_type_VsockSocketAddress_members(Visitor *v, VsockSocketAddress *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "cid", &obj->cid, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "port", &obj->port, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_VsockSocketAddress(Visitor *v, const char *name, VsockSocketAddress **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(VsockSocketAddress), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_VsockSocketAddress_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_VsockSocketAddress(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_WatchdogExpirationAction(Visitor *v, const char *name, WatchdogExpirationAction *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, WatchdogExpirationAction_lookup, errp);
    *obj = value;
}

void visit_type_X86CPUFeatureWordInfo_members(Visitor *v, X86CPUFeatureWordInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, "cpuid-input-eax", &obj->cpuid_input_eax, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "cpuid-input-ecx", &obj->has_cpuid_input_ecx)) {
        visit_type_int(v, "cpuid-input-ecx", &obj->cpuid_input_ecx, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_X86CPURegister32(v, "cpuid-register", &obj->cpuid_register, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "features", &obj->features, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_X86CPUFeatureWordInfo(Visitor *v, const char *name, X86CPUFeatureWordInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(X86CPUFeatureWordInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_X86CPUFeatureWordInfo_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_X86CPUFeatureWordInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_X86CPUFeatureWordInfoList(Visitor *v, const char *name, X86CPUFeatureWordInfoList **obj, Error **errp)
{
    Error *err = NULL;
    X86CPUFeatureWordInfoList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (X86CPUFeatureWordInfoList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_X86CPUFeatureWordInfo(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_X86CPUFeatureWordInfoList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_X86CPURegister32(Visitor *v, const char *name, X86CPURegister32 *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, X86CPURegister32_lookup, errp);
    *obj = value;
}

void visit_type_XBZRLECacheStats_members(Visitor *v, XBZRLECacheStats *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, "cache-size", &obj->cache_size, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "bytes", &obj->bytes, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "pages", &obj->pages, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "cache-miss", &obj->cache_miss, &err);
    if (err) {
        goto out;
    }
    visit_type_number(v, "cache-miss-rate", &obj->cache_miss_rate, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "overflow", &obj->overflow, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_XBZRLECacheStats(Visitor *v, const char *name, XBZRLECacheStats **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(XBZRLECacheStats), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_XBZRLECacheStats_members(v, *obj, &err);
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_XBZRLECacheStats(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_anyList(Visitor *v, const char *name, anyList **obj, Error **errp)
{
    Error *err = NULL;
    anyList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (anyList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_any(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_anyList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_boolList(Visitor *v, const char *name, boolList **obj, Error **errp)
{
    Error *err = NULL;
    boolList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (boolList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_bool(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_boolList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_int16List(Visitor *v, const char *name, int16List **obj, Error **errp)
{
    Error *err = NULL;
    int16List *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (int16List *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_int16(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_int16List(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_int32List(Visitor *v, const char *name, int32List **obj, Error **errp)
{
    Error *err = NULL;
    int32List *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (int32List *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_int32(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_int32List(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_int64List(Visitor *v, const char *name, int64List **obj, Error **errp)
{
    Error *err = NULL;
    int64List *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (int64List *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_int64(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_int64List(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_int8List(Visitor *v, const char *name, int8List **obj, Error **errp)
{
    Error *err = NULL;
    int8List *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (int8List *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_int8(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_int8List(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_intList(Visitor *v, const char *name, intList **obj, Error **errp)
{
    Error *err = NULL;
    intList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (intList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_int(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_intList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_numberList(Visitor *v, const char *name, numberList **obj, Error **errp)
{
    Error *err = NULL;
    numberList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (numberList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_number(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_numberList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_q_obj_ACPI_DEVICE_OST_arg_members(Visitor *v, q_obj_ACPI_DEVICE_OST_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_ACPIOSTInfo(v, "info", &obj->info, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_Abort_wrapper_members(Visitor *v, q_obj_Abort_wrapper *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_Abort(v, "data", &obj->data, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_BALLOON_CHANGE_arg_members(Visitor *v, q_obj_BALLOON_CHANGE_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, "actual", &obj->actual, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_BLOCK_IMAGE_CORRUPTED_arg_members(Visitor *v, q_obj_BLOCK_IMAGE_CORRUPTED_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "device", &obj->device, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "node-name", &obj->has_node_name)) {
        visit_type_str(v, "node-name", &obj->node_name, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_str(v, "msg", &obj->msg, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "offset", &obj->has_offset)) {
        visit_type_int(v, "offset", &obj->offset, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "size", &obj->has_size)) {
        visit_type_int(v, "size", &obj->size, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_bool(v, "fatal", &obj->fatal, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_BLOCK_IO_ERROR_arg_members(Visitor *v, q_obj_BLOCK_IO_ERROR_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "device", &obj->device, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "node-name", &obj->node_name, &err);
    if (err) {
        goto out;
    }
    visit_type_IoOperationType(v, "operation", &obj->operation, &err);
    if (err) {
        goto out;
    }
    visit_type_BlockErrorAction(v, "action", &obj->action, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "nospace", &obj->has_nospace)) {
        visit_type_bool(v, "nospace", &obj->nospace, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_str(v, "reason", &obj->reason, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_BLOCK_JOB_CANCELLED_arg_members(Visitor *v, q_obj_BLOCK_JOB_CANCELLED_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_BlockJobType(v, "type", &obj->type, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "device", &obj->device, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "len", &obj->len, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "offset", &obj->offset, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "speed", &obj->speed, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_BLOCK_JOB_COMPLETED_arg_members(Visitor *v, q_obj_BLOCK_JOB_COMPLETED_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_BlockJobType(v, "type", &obj->type, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "device", &obj->device, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "len", &obj->len, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "offset", &obj->offset, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "speed", &obj->speed, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "error", &obj->has_error)) {
        visit_type_str(v, "error", &obj->error, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_BLOCK_JOB_ERROR_arg_members(Visitor *v, q_obj_BLOCK_JOB_ERROR_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "device", &obj->device, &err);
    if (err) {
        goto out;
    }
    visit_type_IoOperationType(v, "operation", &obj->operation, &err);
    if (err) {
        goto out;
    }
    visit_type_BlockErrorAction(v, "action", &obj->action, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_BLOCK_JOB_READY_arg_members(Visitor *v, q_obj_BLOCK_JOB_READY_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_BlockJobType(v, "type", &obj->type, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "device", &obj->device, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "len", &obj->len, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "offset", &obj->offset, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "speed", &obj->speed, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_BLOCK_WRITE_THRESHOLD_arg_members(Visitor *v, q_obj_BLOCK_WRITE_THRESHOLD_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "node-name", &obj->node_name, &err);
    if (err) {
        goto out;
    }
    visit_type_uint64(v, "amount-exceeded", &obj->amount_exceeded, &err);
    if (err) {
        goto out;
    }
    visit_type_uint64(v, "write-threshold", &obj->write_threshold, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_BlockDirtyBitmap_wrapper_members(Visitor *v, q_obj_BlockDirtyBitmap_wrapper *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_BlockDirtyBitmap(v, "data", &obj->data, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_BlockDirtyBitmapAdd_wrapper_members(Visitor *v, q_obj_BlockDirtyBitmapAdd_wrapper *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_BlockDirtyBitmapAdd(v, "data", &obj->data, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_BlockdevBackup_wrapper_members(Visitor *v, q_obj_BlockdevBackup_wrapper *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_BlockdevBackup(v, "data", &obj->data, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_BlockdevOptions_base_members(Visitor *v, q_obj_BlockdevOptions_base *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_BlockdevDriver(v, "driver", &obj->driver, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "node-name", &obj->has_node_name)) {
        visit_type_str(v, "node-name", &obj->node_name, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "discard", &obj->has_discard)) {
        visit_type_BlockdevDiscardOptions(v, "discard", &obj->discard, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "cache", &obj->has_cache)) {
        visit_type_BlockdevCacheOptions(v, "cache", &obj->cache, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "read-only", &obj->has_read_only)) {
        visit_type_bool(v, "read-only", &obj->read_only, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "detect-zeroes", &obj->has_detect_zeroes)) {
        visit_type_BlockdevDetectZeroesOptions(v, "detect-zeroes", &obj->detect_zeroes, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_BlockdevSnapshot_wrapper_members(Visitor *v, q_obj_BlockdevSnapshot_wrapper *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_BlockdevSnapshot(v, "data", &obj->data, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_BlockdevSnapshotInternal_wrapper_members(Visitor *v, q_obj_BlockdevSnapshotInternal_wrapper *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_BlockdevSnapshotInternal(v, "data", &obj->data, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_BlockdevSnapshotSync_wrapper_members(Visitor *v, q_obj_BlockdevSnapshotSync_wrapper *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_BlockdevSnapshotSync(v, "data", &obj->data, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_ChardevCommon_wrapper_members(Visitor *v, q_obj_ChardevCommon_wrapper *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_ChardevCommon(v, "data", &obj->data, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_ChardevFile_wrapper_members(Visitor *v, q_obj_ChardevFile_wrapper *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_ChardevFile(v, "data", &obj->data, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_ChardevHostdev_wrapper_members(Visitor *v, q_obj_ChardevHostdev_wrapper *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_ChardevHostdev(v, "data", &obj->data, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_ChardevMux_wrapper_members(Visitor *v, q_obj_ChardevMux_wrapper *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_ChardevMux(v, "data", &obj->data, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_ChardevRingbuf_wrapper_members(Visitor *v, q_obj_ChardevRingbuf_wrapper *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_ChardevRingbuf(v, "data", &obj->data, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_ChardevSocket_wrapper_members(Visitor *v, q_obj_ChardevSocket_wrapper *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_ChardevSocket(v, "data", &obj->data, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_ChardevSpiceChannel_wrapper_members(Visitor *v, q_obj_ChardevSpiceChannel_wrapper *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_ChardevSpiceChannel(v, "data", &obj->data, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_ChardevSpicePort_wrapper_members(Visitor *v, q_obj_ChardevSpicePort_wrapper *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_ChardevSpicePort(v, "data", &obj->data, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_ChardevStdio_wrapper_members(Visitor *v, q_obj_ChardevStdio_wrapper *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_ChardevStdio(v, "data", &obj->data, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_ChardevUdp_wrapper_members(Visitor *v, q_obj_ChardevUdp_wrapper *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_ChardevUdp(v, "data", &obj->data, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_ChardevVC_wrapper_members(Visitor *v, q_obj_ChardevVC_wrapper *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_ChardevVC(v, "data", &obj->data, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_CpuInfo_base_members(Visitor *v, q_obj_CpuInfo_base *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, "CPU", &obj->CPU, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "current", &obj->current, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "halted", &obj->halted, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "qom_path", &obj->qom_path, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "thread_id", &obj->thread_id, &err);
    if (err) {
        goto out;
    }
    visit_type_CpuInfoArch(v, "arch", &obj->arch, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_DEVICE_DELETED_arg_members(Visitor *v, q_obj_DEVICE_DELETED_arg *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "device", &obj->has_device)) {
        visit_type_str(v, "device", &obj->device, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_str(v, "path", &obj->path, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_DEVICE_TRAY_MOVED_arg_members(Visitor *v, q_obj_DEVICE_TRAY_MOVED_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "device", &obj->device, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "id", &obj->id, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "tray-open", &obj->tray_open, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_DUMP_COMPLETED_arg_members(Visitor *v, q_obj_DUMP_COMPLETED_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_DumpQueryResult(v, "result", &obj->result, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "error", &obj->has_error)) {
        visit_type_str(v, "error", &obj->error, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_DriveBackup_wrapper_members(Visitor *v, q_obj_DriveBackup_wrapper *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_DriveBackup(v, "data", &obj->data, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_GUEST_PANICKED_arg_members(Visitor *v, q_obj_GUEST_PANICKED_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_GuestPanicAction(v, "action", &obj->action, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "info", &obj->has_info)) {
        visit_type_GuestPanicInformation(v, "info", &obj->info, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_GuestPanicInformation_base_members(Visitor *v, q_obj_GuestPanicInformation_base *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_GuestPanicInformationType(v, "type", &obj->type, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_ImageInfoSpecificQCow2_wrapper_members(Visitor *v, q_obj_ImageInfoSpecificQCow2_wrapper *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_ImageInfoSpecificQCow2(v, "data", &obj->data, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_ImageInfoSpecificVmdk_wrapper_members(Visitor *v, q_obj_ImageInfoSpecificVmdk_wrapper *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_ImageInfoSpecificVmdk(v, "data", &obj->data, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_InetSocketAddress_wrapper_members(Visitor *v, q_obj_InetSocketAddress_wrapper *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_InetSocketAddress(v, "data", &obj->data, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_InputBtnEvent_wrapper_members(Visitor *v, q_obj_InputBtnEvent_wrapper *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_InputBtnEvent(v, "data", &obj->data, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_InputKeyEvent_wrapper_members(Visitor *v, q_obj_InputKeyEvent_wrapper *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_InputKeyEvent(v, "data", &obj->data, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_InputMoveEvent_wrapper_members(Visitor *v, q_obj_InputMoveEvent_wrapper *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_InputMoveEvent(v, "data", &obj->data, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_MEM_UNPLUG_ERROR_arg_members(Visitor *v, q_obj_MEM_UNPLUG_ERROR_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "device", &obj->device, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "msg", &obj->msg, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_MIGRATION_arg_members(Visitor *v, q_obj_MIGRATION_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_MigrationStatus(v, "status", &obj->status, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_MIGRATION_PASS_arg_members(Visitor *v, q_obj_MIGRATION_PASS_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, "pass", &obj->pass, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_NIC_RX_FILTER_CHANGED_arg_members(Visitor *v, q_obj_NIC_RX_FILTER_CHANGED_arg *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "name", &obj->has_name)) {
        visit_type_str(v, "name", &obj->name, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_str(v, "path", &obj->path, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_NetLegacyOptions_base_members(Visitor *v, q_obj_NetLegacyOptions_base *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_NetLegacyOptionsType(v, "type", &obj->type, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_Netdev_base_members(Visitor *v, q_obj_Netdev_base *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "id", &obj->id, &err);
    if (err) {
        goto out;
    }
    visit_type_NetClientDriver(v, "type", &obj->type, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_NumaOptions_base_members(Visitor *v, q_obj_NumaOptions_base *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_NumaOptionsType(v, "type", &obj->type, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_PCDIMMDeviceInfo_wrapper_members(Visitor *v, q_obj_PCDIMMDeviceInfo_wrapper *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_PCDIMMDeviceInfo(v, "data", &obj->data, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_QCryptoBlockInfoLUKS_wrapper_members(Visitor *v, q_obj_QCryptoBlockInfoLUKS_wrapper *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_QCryptoBlockInfoLUKS(v, "data", &obj->data, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_QKeyCode_wrapper_members(Visitor *v, q_obj_QKeyCode_wrapper *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_QKeyCode(v, "data", &obj->data, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_QUORUM_FAILURE_arg_members(Visitor *v, q_obj_QUORUM_FAILURE_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "reference", &obj->reference, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "sector-num", &obj->sector_num, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "sectors-count", &obj->sectors_count, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_QUORUM_REPORT_BAD_arg_members(Visitor *v, q_obj_QUORUM_REPORT_BAD_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_QuorumOpType(v, "type", &obj->type, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "error", &obj->has_error)) {
        visit_type_str(v, "error", &obj->error, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_str(v, "node-name", &obj->node_name, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "sector-num", &obj->sector_num, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "sectors-count", &obj->sectors_count, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_RTC_CHANGE_arg_members(Visitor *v, q_obj_RTC_CHANGE_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, "offset", &obj->offset, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_SPICE_CONNECTED_arg_members(Visitor *v, q_obj_SPICE_CONNECTED_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_SpiceBasicInfo(v, "server", &obj->server, &err);
    if (err) {
        goto out;
    }
    visit_type_SpiceBasicInfo(v, "client", &obj->client, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_SPICE_DISCONNECTED_arg_members(Visitor *v, q_obj_SPICE_DISCONNECTED_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_SpiceBasicInfo(v, "server", &obj->server, &err);
    if (err) {
        goto out;
    }
    visit_type_SpiceBasicInfo(v, "client", &obj->client, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_SPICE_INITIALIZED_arg_members(Visitor *v, q_obj_SPICE_INITIALIZED_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_SpiceServerInfo(v, "server", &obj->server, &err);
    if (err) {
        goto out;
    }
    visit_type_SpiceChannel(v, "client", &obj->client, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_SchemaInfo_base_members(Visitor *v, q_obj_SchemaInfo_base *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "name", &obj->name, &err);
    if (err) {
        goto out;
    }
    visit_type_SchemaMetaType(v, "meta-type", &obj->meta_type, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_SocketAddressFlat_base_members(Visitor *v, q_obj_SocketAddressFlat_base *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_SocketAddressFlatType(v, "type", &obj->type, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_String_wrapper_members(Visitor *v, q_obj_String_wrapper *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_String(v, "data", &obj->data, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_TPMPassthroughOptions_wrapper_members(Visitor *v, q_obj_TPMPassthroughOptions_wrapper *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_TPMPassthroughOptions(v, "data", &obj->data, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_UnixSocketAddress_wrapper_members(Visitor *v, q_obj_UnixSocketAddress_wrapper *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_UnixSocketAddress(v, "data", &obj->data, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_VNC_CONNECTED_arg_members(Visitor *v, q_obj_VNC_CONNECTED_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_VncServerInfo(v, "server", &obj->server, &err);
    if (err) {
        goto out;
    }
    visit_type_VncBasicInfo(v, "client", &obj->client, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_VNC_DISCONNECTED_arg_members(Visitor *v, q_obj_VNC_DISCONNECTED_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_VncServerInfo(v, "server", &obj->server, &err);
    if (err) {
        goto out;
    }
    visit_type_VncClientInfo(v, "client", &obj->client, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_VNC_INITIALIZED_arg_members(Visitor *v, q_obj_VNC_INITIALIZED_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_VncServerInfo(v, "server", &obj->server, &err);
    if (err) {
        goto out;
    }
    visit_type_VncClientInfo(v, "client", &obj->client, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_VSERPORT_CHANGE_arg_members(Visitor *v, q_obj_VSERPORT_CHANGE_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "id", &obj->id, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "open", &obj->open, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_VsockSocketAddress_wrapper_members(Visitor *v, q_obj_VsockSocketAddress_wrapper *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_VsockSocketAddress(v, "data", &obj->data, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_WATCHDOG_arg_members(Visitor *v, q_obj_WATCHDOG_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_WatchdogExpirationAction(v, "action", &obj->action, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_add_fd_arg_members(Visitor *v, q_obj_add_fd_arg *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "fdset-id", &obj->has_fdset_id)) {
        visit_type_int(v, "fdset-id", &obj->fdset_id, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "opaque", &obj->has_opaque)) {
        visit_type_str(v, "opaque", &obj->opaque, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_add_client_arg_members(Visitor *v, q_obj_add_client_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "protocol", &obj->protocol, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "fdname", &obj->fdname, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "skipauth", &obj->has_skipauth)) {
        visit_type_bool(v, "skipauth", &obj->skipauth, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "tls", &obj->has_tls)) {
        visit_type_bool(v, "tls", &obj->tls, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_balloon_arg_members(Visitor *v, q_obj_balloon_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, "value", &obj->value, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_block_commit_arg_members(Visitor *v, q_obj_block_commit_arg *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "job-id", &obj->has_job_id)) {
        visit_type_str(v, "job-id", &obj->job_id, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_str(v, "device", &obj->device, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "base", &obj->has_base)) {
        visit_type_str(v, "base", &obj->base, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "top", &obj->has_top)) {
        visit_type_str(v, "top", &obj->top, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "backing-file", &obj->has_backing_file)) {
        visit_type_str(v, "backing-file", &obj->backing_file, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "speed", &obj->has_speed)) {
        visit_type_int(v, "speed", &obj->speed, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "filter-node-name", &obj->has_filter_node_name)) {
        visit_type_str(v, "filter-node-name", &obj->filter_node_name, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_block_job_cancel_arg_members(Visitor *v, q_obj_block_job_cancel_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "device", &obj->device, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "force", &obj->has_force)) {
        visit_type_bool(v, "force", &obj->force, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_block_job_complete_arg_members(Visitor *v, q_obj_block_job_complete_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "device", &obj->device, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_block_job_pause_arg_members(Visitor *v, q_obj_block_job_pause_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "device", &obj->device, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_block_job_resume_arg_members(Visitor *v, q_obj_block_job_resume_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "device", &obj->device, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_block_job_set_speed_arg_members(Visitor *v, q_obj_block_job_set_speed_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "device", &obj->device, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "speed", &obj->speed, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_block_set_write_threshold_arg_members(Visitor *v, q_obj_block_set_write_threshold_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "node-name", &obj->node_name, &err);
    if (err) {
        goto out;
    }
    visit_type_uint64(v, "write-threshold", &obj->write_threshold, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_block_stream_arg_members(Visitor *v, q_obj_block_stream_arg *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "job-id", &obj->has_job_id)) {
        visit_type_str(v, "job-id", &obj->job_id, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_str(v, "device", &obj->device, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "base", &obj->has_base)) {
        visit_type_str(v, "base", &obj->base, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "base-node", &obj->has_base_node)) {
        visit_type_str(v, "base-node", &obj->base_node, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "backing-file", &obj->has_backing_file)) {
        visit_type_str(v, "backing-file", &obj->backing_file, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "speed", &obj->has_speed)) {
        visit_type_int(v, "speed", &obj->speed, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "on-error", &obj->has_on_error)) {
        visit_type_BlockdevOnError(v, "on-error", &obj->on_error, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_block_passwd_arg_members(Visitor *v, q_obj_block_passwd_arg *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "device", &obj->has_device)) {
        visit_type_str(v, "device", &obj->device, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "node-name", &obj->has_node_name)) {
        visit_type_str(v, "node-name", &obj->node_name, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_str(v, "password", &obj->password, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_block_resize_arg_members(Visitor *v, q_obj_block_resize_arg *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "device", &obj->has_device)) {
        visit_type_str(v, "device", &obj->device, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "node-name", &obj->has_node_name)) {
        visit_type_str(v, "node-name", &obj->node_name, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_int(v, "size", &obj->size, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_blockdev_change_medium_arg_members(Visitor *v, q_obj_blockdev_change_medium_arg *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "device", &obj->has_device)) {
        visit_type_str(v, "device", &obj->device, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "id", &obj->has_id)) {
        visit_type_str(v, "id", &obj->id, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_str(v, "filename", &obj->filename, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "format", &obj->has_format)) {
        visit_type_str(v, "format", &obj->format, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "read-only-mode", &obj->has_read_only_mode)) {
        visit_type_BlockdevChangeReadOnlyMode(v, "read-only-mode", &obj->read_only_mode, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_blockdev_close_tray_arg_members(Visitor *v, q_obj_blockdev_close_tray_arg *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "device", &obj->has_device)) {
        visit_type_str(v, "device", &obj->device, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "id", &obj->has_id)) {
        visit_type_str(v, "id", &obj->id, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_blockdev_del_arg_members(Visitor *v, q_obj_blockdev_del_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "node-name", &obj->node_name, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_blockdev_mirror_arg_members(Visitor *v, q_obj_blockdev_mirror_arg *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "job-id", &obj->has_job_id)) {
        visit_type_str(v, "job-id", &obj->job_id, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_str(v, "device", &obj->device, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "target", &obj->target, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "replaces", &obj->has_replaces)) {
        visit_type_str(v, "replaces", &obj->replaces, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_MirrorSyncMode(v, "sync", &obj->sync, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "speed", &obj->has_speed)) {
        visit_type_int(v, "speed", &obj->speed, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "granularity", &obj->has_granularity)) {
        visit_type_uint32(v, "granularity", &obj->granularity, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "buf-size", &obj->has_buf_size)) {
        visit_type_int(v, "buf-size", &obj->buf_size, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "on-source-error", &obj->has_on_source_error)) {
        visit_type_BlockdevOnError(v, "on-source-error", &obj->on_source_error, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "on-target-error", &obj->has_on_target_error)) {
        visit_type_BlockdevOnError(v, "on-target-error", &obj->on_target_error, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "filter-node-name", &obj->has_filter_node_name)) {
        visit_type_str(v, "filter-node-name", &obj->filter_node_name, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_blockdev_open_tray_arg_members(Visitor *v, q_obj_blockdev_open_tray_arg *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "device", &obj->has_device)) {
        visit_type_str(v, "device", &obj->device, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "id", &obj->has_id)) {
        visit_type_str(v, "id", &obj->id, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "force", &obj->has_force)) {
        visit_type_bool(v, "force", &obj->force, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_blockdev_snapshot_delete_internal_sync_arg_members(Visitor *v, q_obj_blockdev_snapshot_delete_internal_sync_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "device", &obj->device, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "id", &obj->has_id)) {
        visit_type_str(v, "id", &obj->id, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "name", &obj->has_name)) {
        visit_type_str(v, "name", &obj->name, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_change_arg_members(Visitor *v, q_obj_change_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "device", &obj->device, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "target", &obj->target, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "arg", &obj->has_arg)) {
        visit_type_str(v, "arg", &obj->arg, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_change_backing_file_arg_members(Visitor *v, q_obj_change_backing_file_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "device", &obj->device, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "image-node-name", &obj->image_node_name, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "backing-file", &obj->backing_file, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_change_vnc_password_arg_members(Visitor *v, q_obj_change_vnc_password_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "password", &obj->password, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_chardev_add_arg_members(Visitor *v, q_obj_chardev_add_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "id", &obj->id, &err);
    if (err) {
        goto out;
    }
    visit_type_ChardevBackend(v, "backend", &obj->backend, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_chardev_remove_arg_members(Visitor *v, q_obj_chardev_remove_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "id", &obj->id, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_client_migrate_info_arg_members(Visitor *v, q_obj_client_migrate_info_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "protocol", &obj->protocol, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "hostname", &obj->hostname, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "port", &obj->has_port)) {
        visit_type_int(v, "port", &obj->port, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "tls-port", &obj->has_tls_port)) {
        visit_type_int(v, "tls-port", &obj->tls_port, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "cert-subject", &obj->has_cert_subject)) {
        visit_type_str(v, "cert-subject", &obj->cert_subject, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_closefd_arg_members(Visitor *v, q_obj_closefd_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "fdname", &obj->fdname, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_cpu_add_arg_members(Visitor *v, q_obj_cpu_add_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, "id", &obj->id, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_cpu_arg_members(Visitor *v, q_obj_cpu_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, "index", &obj->index, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_device_list_properties_arg_members(Visitor *v, q_obj_device_list_properties_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "typename", &obj->q_typename, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_device_add_arg_members(Visitor *v, q_obj_device_add_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "driver", &obj->driver, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "bus", &obj->has_bus)) {
        visit_type_str(v, "bus", &obj->bus, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "id", &obj->has_id)) {
        visit_type_str(v, "id", &obj->id, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_device_del_arg_members(Visitor *v, q_obj_device_del_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "id", &obj->id, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_dump_guest_memory_arg_members(Visitor *v, q_obj_dump_guest_memory_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_bool(v, "paging", &obj->paging, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "protocol", &obj->protocol, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "detach", &obj->has_detach)) {
        visit_type_bool(v, "detach", &obj->detach, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "begin", &obj->has_begin)) {
        visit_type_int(v, "begin", &obj->begin, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "length", &obj->has_length)) {
        visit_type_int(v, "length", &obj->length, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "format", &obj->has_format)) {
        visit_type_DumpGuestMemoryFormat(v, "format", &obj->format, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_dump_skeys_arg_members(Visitor *v, q_obj_dump_skeys_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "filename", &obj->filename, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_eject_arg_members(Visitor *v, q_obj_eject_arg *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "device", &obj->has_device)) {
        visit_type_str(v, "device", &obj->device, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "id", &obj->has_id)) {
        visit_type_str(v, "id", &obj->id, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "force", &obj->has_force)) {
        visit_type_bool(v, "force", &obj->force, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_expire_password_arg_members(Visitor *v, q_obj_expire_password_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "protocol", &obj->protocol, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "time", &obj->time, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_getfd_arg_members(Visitor *v, q_obj_getfd_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "fdname", &obj->fdname, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_human_monitor_command_arg_members(Visitor *v, q_obj_human_monitor_command_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "command-line", &obj->command_line, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "cpu-index", &obj->has_cpu_index)) {
        visit_type_int(v, "cpu-index", &obj->cpu_index, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_input_send_event_arg_members(Visitor *v, q_obj_input_send_event_arg *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "device", &obj->has_device)) {
        visit_type_str(v, "device", &obj->device, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "head", &obj->has_head)) {
        visit_type_int(v, "head", &obj->head, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_InputEventList(v, "events", &obj->events, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_int_wrapper_members(Visitor *v, q_obj_int_wrapper *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, "data", &obj->data, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_memsave_arg_members(Visitor *v, q_obj_memsave_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, "val", &obj->val, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "size", &obj->size, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "filename", &obj->filename, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "cpu-index", &obj->has_cpu_index)) {
        visit_type_int(v, "cpu-index", &obj->cpu_index, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_migrate_arg_members(Visitor *v, q_obj_migrate_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "uri", &obj->uri, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "blk", &obj->has_blk)) {
        visit_type_bool(v, "blk", &obj->blk, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "inc", &obj->has_inc)) {
        visit_type_bool(v, "inc", &obj->inc, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "detach", &obj->has_detach)) {
        visit_type_bool(v, "detach", &obj->detach, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_migrate_incoming_arg_members(Visitor *v, q_obj_migrate_incoming_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "uri", &obj->uri, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_migrate_set_cache_size_arg_members(Visitor *v, q_obj_migrate_set_cache_size_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, "value", &obj->value, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_migrate_set_capabilities_arg_members(Visitor *v, q_obj_migrate_set_capabilities_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_MigrationCapabilityStatusList(v, "capabilities", &obj->capabilities, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_migrate_set_downtime_arg_members(Visitor *v, q_obj_migrate_set_downtime_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_number(v, "value", &obj->value, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_migrate_set_speed_arg_members(Visitor *v, q_obj_migrate_set_speed_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, "value", &obj->value, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_nbd_server_add_arg_members(Visitor *v, q_obj_nbd_server_add_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "device", &obj->device, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "writable", &obj->has_writable)) {
        visit_type_bool(v, "writable", &obj->writable, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_nbd_server_start_arg_members(Visitor *v, q_obj_nbd_server_start_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_SocketAddress(v, "addr", &obj->addr, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "tls-creds", &obj->has_tls_creds)) {
        visit_type_str(v, "tls-creds", &obj->tls_creds, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_netdev_add_arg_members(Visitor *v, q_obj_netdev_add_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "type", &obj->type, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "id", &obj->id, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_netdev_del_arg_members(Visitor *v, q_obj_netdev_del_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "id", &obj->id, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_object_add_arg_members(Visitor *v, q_obj_object_add_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "qom-type", &obj->qom_type, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "id", &obj->id, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "props", &obj->has_props)) {
        visit_type_any(v, "props", &obj->props, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_object_del_arg_members(Visitor *v, q_obj_object_del_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "id", &obj->id, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_pmemsave_arg_members(Visitor *v, q_obj_pmemsave_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, "val", &obj->val, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "size", &obj->size, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "filename", &obj->filename, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_qom_get_arg_members(Visitor *v, q_obj_qom_get_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "path", &obj->path, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "property", &obj->property, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_qom_list_arg_members(Visitor *v, q_obj_qom_list_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "path", &obj->path, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_qom_list_types_arg_members(Visitor *v, q_obj_qom_list_types_arg *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "implements", &obj->has_implements)) {
        visit_type_str(v, "implements", &obj->implements, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "abstract", &obj->has_abstract)) {
        visit_type_bool(v, "abstract", &obj->abstract, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_qom_set_arg_members(Visitor *v, q_obj_qom_set_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "path", &obj->path, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "property", &obj->property, &err);
    if (err) {
        goto out;
    }
    visit_type_any(v, "value", &obj->value, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_query_blockstats_arg_members(Visitor *v, q_obj_query_blockstats_arg *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "query-nodes", &obj->has_query_nodes)) {
        visit_type_bool(v, "query-nodes", &obj->query_nodes, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_query_command_line_options_arg_members(Visitor *v, q_obj_query_command_line_options_arg *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "option", &obj->has_option)) {
        visit_type_str(v, "option", &obj->option, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_query_cpu_model_baseline_arg_members(Visitor *v, q_obj_query_cpu_model_baseline_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_CpuModelInfo(v, "modela", &obj->modela, &err);
    if (err) {
        goto out;
    }
    visit_type_CpuModelInfo(v, "modelb", &obj->modelb, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_query_cpu_model_comparison_arg_members(Visitor *v, q_obj_query_cpu_model_comparison_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_CpuModelInfo(v, "modela", &obj->modela, &err);
    if (err) {
        goto out;
    }
    visit_type_CpuModelInfo(v, "modelb", &obj->modelb, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_query_cpu_model_expansion_arg_members(Visitor *v, q_obj_query_cpu_model_expansion_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_CpuModelExpansionType(v, "type", &obj->type, &err);
    if (err) {
        goto out;
    }
    visit_type_CpuModelInfo(v, "model", &obj->model, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_query_rocker_arg_members(Visitor *v, q_obj_query_rocker_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "name", &obj->name, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_query_rocker_of_dpa_flows_arg_members(Visitor *v, q_obj_query_rocker_of_dpa_flows_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "name", &obj->name, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "tbl-id", &obj->has_tbl_id)) {
        visit_type_uint32(v, "tbl-id", &obj->tbl_id, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_query_rocker_of_dpa_groups_arg_members(Visitor *v, q_obj_query_rocker_of_dpa_groups_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "name", &obj->name, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "type", &obj->has_type)) {
        visit_type_uint8(v, "type", &obj->type, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_query_rocker_ports_arg_members(Visitor *v, q_obj_query_rocker_ports_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "name", &obj->name, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_query_rx_filter_arg_members(Visitor *v, q_obj_query_rx_filter_arg *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "name", &obj->has_name)) {
        visit_type_str(v, "name", &obj->name, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_remove_fd_arg_members(Visitor *v, q_obj_remove_fd_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, "fdset-id", &obj->fdset_id, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "fd", &obj->has_fd)) {
        visit_type_int(v, "fd", &obj->fd, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_ringbuf_read_arg_members(Visitor *v, q_obj_ringbuf_read_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "device", &obj->device, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "size", &obj->size, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "format", &obj->has_format)) {
        visit_type_DataFormat(v, "format", &obj->format, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_ringbuf_write_arg_members(Visitor *v, q_obj_ringbuf_write_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "device", &obj->device, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "data", &obj->data, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "format", &obj->has_format)) {
        visit_type_DataFormat(v, "format", &obj->format, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_screendump_arg_members(Visitor *v, q_obj_screendump_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "filename", &obj->filename, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_send_key_arg_members(Visitor *v, q_obj_send_key_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_KeyValueList(v, "keys", &obj->keys, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "hold-time", &obj->has_hold_time)) {
        visit_type_int(v, "hold-time", &obj->hold_time, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_set_link_arg_members(Visitor *v, q_obj_set_link_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "name", &obj->name, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "up", &obj->up, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_set_password_arg_members(Visitor *v, q_obj_set_password_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "protocol", &obj->protocol, &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, "password", &obj->password, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "connected", &obj->has_connected)) {
        visit_type_str(v, "connected", &obj->connected, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_trace_event_get_state_arg_members(Visitor *v, q_obj_trace_event_get_state_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "name", &obj->name, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "vcpu", &obj->has_vcpu)) {
        visit_type_int(v, "vcpu", &obj->vcpu, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_trace_event_set_state_arg_members(Visitor *v, q_obj_trace_event_set_state_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "name", &obj->name, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "enable", &obj->enable, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "ignore-unavailable", &obj->has_ignore_unavailable)) {
        visit_type_bool(v, "ignore-unavailable", &obj->ignore_unavailable, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "vcpu", &obj->has_vcpu)) {
        visit_type_int(v, "vcpu", &obj->vcpu, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_transaction_arg_members(Visitor *v, q_obj_transaction_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_TransactionActionList(v, "actions", &obj->actions, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "properties", &obj->has_properties)) {
        visit_type_TransactionProperties(v, "properties", &obj->properties, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_x_blockdev_change_arg_members(Visitor *v, q_obj_x_blockdev_change_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "parent", &obj->parent, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "child", &obj->has_child)) {
        visit_type_str(v, "child", &obj->child, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "node", &obj->has_node)) {
        visit_type_str(v, "node", &obj->node, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_x_blockdev_insert_medium_arg_members(Visitor *v, q_obj_x_blockdev_insert_medium_arg *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "device", &obj->has_device)) {
        visit_type_str(v, "device", &obj->device, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "id", &obj->has_id)) {
        visit_type_str(v, "id", &obj->id, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_str(v, "node-name", &obj->node_name, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_x_blockdev_remove_medium_arg_members(Visitor *v, q_obj_x_blockdev_remove_medium_arg *obj, Error **errp)
{
    Error *err = NULL;

    if (visit_optional(v, "device", &obj->has_device)) {
        visit_type_str(v, "device", &obj->device, &err);
        if (err) {
            goto out;
        }
    }
    if (visit_optional(v, "id", &obj->has_id)) {
        visit_type_str(v, "id", &obj->id, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_xen_load_devices_state_arg_members(Visitor *v, q_obj_xen_load_devices_state_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "filename", &obj->filename, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_xen_save_devices_state_arg_members(Visitor *v, q_obj_xen_save_devices_state_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, "filename", &obj->filename, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_xen_set_global_dirty_log_arg_members(Visitor *v, q_obj_xen_set_global_dirty_log_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_bool(v, "enable", &obj->enable, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_q_obj_xen_set_replication_arg_members(Visitor *v, q_obj_xen_set_replication_arg *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_bool(v, "enable", &obj->enable, &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, "primary", &obj->primary, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "failover", &obj->has_failover)) {
        visit_type_bool(v, "failover", &obj->failover, &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_sizeList(Visitor *v, const char *name, sizeList **obj, Error **errp)
{
    Error *err = NULL;
    sizeList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (sizeList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_size(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_sizeList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_strList(Visitor *v, const char *name, strList **obj, Error **errp)
{
    Error *err = NULL;
    strList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (strList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_str(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_strList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_uint16List(Visitor *v, const char *name, uint16List **obj, Error **errp)
{
    Error *err = NULL;
    uint16List *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (uint16List *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_uint16(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_uint16List(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_uint32List(Visitor *v, const char *name, uint32List **obj, Error **errp)
{
    Error *err = NULL;
    uint32List *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (uint32List *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_uint32(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_uint32List(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_uint64List(Visitor *v, const char *name, uint64List **obj, Error **errp)
{
    Error *err = NULL;
    uint64List *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (uint64List *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_uint64(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_uint64List(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_uint8List(Visitor *v, const char *name, uint8List **obj, Error **errp)
{
    Error *err = NULL;
    uint8List *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (uint8List *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_uint8(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_uint8List(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}
