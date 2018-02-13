/* AUTOMATICALLY GENERATED, DO NOT MODIFY */

/*
 * schema-defined QAPI event functions
 *
 * Copyright (c) 2014 Wenchao Xia
 *
 * Authors:
 *  Wenchao Xia   <wenchaoqemu@gmail.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qapi-event.h"
#include "qapi-visit.h"
#include "qapi/qobject-output-visitor.h"
#include "qapi/qmp-event.h"


void qapi_event_send_acpi_device_ost(ACPIOSTInfo *info, Error **errp)
{
    QDict *qmp;
    Error *err = NULL;
    QMPEventFuncEmit emit;
    QObject *obj;
    Visitor *v;
    q_obj_ACPI_DEVICE_OST_arg param = {
        info
    };

    emit = qmp_event_get_func_emit();
    if (!emit) {
        return;
    }

    qmp = qmp_event_build_dict("ACPI_DEVICE_OST");

    v = qobject_output_visitor_new(&obj);

    visit_start_struct(v, "ACPI_DEVICE_OST", NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_ACPI_DEVICE_OST_arg_members(v, &param, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    visit_complete(v, &obj);
    qdict_put_obj(qmp, "data", obj);
    emit(QAPI_EVENT_ACPI_DEVICE_OST, qmp, &err);

out:
    visit_free(v);
    error_propagate(errp, err);
    QDECREF(qmp);
}

void qapi_event_send_balloon_change(int64_t actual, Error **errp)
{
    QDict *qmp;
    Error *err = NULL;
    QMPEventFuncEmit emit;
    QObject *obj;
    Visitor *v;
    q_obj_BALLOON_CHANGE_arg param = {
        actual
    };

    emit = qmp_event_get_func_emit();
    if (!emit) {
        return;
    }

    qmp = qmp_event_build_dict("BALLOON_CHANGE");

    v = qobject_output_visitor_new(&obj);

    visit_start_struct(v, "BALLOON_CHANGE", NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_BALLOON_CHANGE_arg_members(v, &param, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    visit_complete(v, &obj);
    qdict_put_obj(qmp, "data", obj);
    emit(QAPI_EVENT_BALLOON_CHANGE, qmp, &err);

out:
    visit_free(v);
    error_propagate(errp, err);
    QDECREF(qmp);
}

void qapi_event_send_block_image_corrupted(const char *device, bool has_node_name, const char *node_name, const char *msg, bool has_offset, int64_t offset, bool has_size, int64_t size, bool fatal, Error **errp)
{
    QDict *qmp;
    Error *err = NULL;
    QMPEventFuncEmit emit;
    QObject *obj;
    Visitor *v;
    q_obj_BLOCK_IMAGE_CORRUPTED_arg param = {
        (char *)device, has_node_name, (char *)node_name, (char *)msg, has_offset, offset, has_size, size, fatal
    };

    emit = qmp_event_get_func_emit();
    if (!emit) {
        return;
    }

    qmp = qmp_event_build_dict("BLOCK_IMAGE_CORRUPTED");

    v = qobject_output_visitor_new(&obj);

    visit_start_struct(v, "BLOCK_IMAGE_CORRUPTED", NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_BLOCK_IMAGE_CORRUPTED_arg_members(v, &param, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    visit_complete(v, &obj);
    qdict_put_obj(qmp, "data", obj);
    emit(QAPI_EVENT_BLOCK_IMAGE_CORRUPTED, qmp, &err);

out:
    visit_free(v);
    error_propagate(errp, err);
    QDECREF(qmp);
}

void qapi_event_send_block_io_error(const char *device, const char *node_name, IoOperationType operation, BlockErrorAction action, bool has_nospace, bool nospace, const char *reason, Error **errp)
{
    QDict *qmp;
    Error *err = NULL;
    QMPEventFuncEmit emit;
    QObject *obj;
    Visitor *v;
    q_obj_BLOCK_IO_ERROR_arg param = {
        (char *)device, (char *)node_name, operation, action, has_nospace, nospace, (char *)reason
    };

    emit = qmp_event_get_func_emit();
    if (!emit) {
        return;
    }

    qmp = qmp_event_build_dict("BLOCK_IO_ERROR");

    v = qobject_output_visitor_new(&obj);

    visit_start_struct(v, "BLOCK_IO_ERROR", NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_BLOCK_IO_ERROR_arg_members(v, &param, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    visit_complete(v, &obj);
    qdict_put_obj(qmp, "data", obj);
    emit(QAPI_EVENT_BLOCK_IO_ERROR, qmp, &err);

out:
    visit_free(v);
    error_propagate(errp, err);
    QDECREF(qmp);
}

void qapi_event_send_block_job_cancelled(BlockJobType type, const char *device, int64_t len, int64_t offset, int64_t speed, Error **errp)
{
    QDict *qmp;
    Error *err = NULL;
    QMPEventFuncEmit emit;
    QObject *obj;
    Visitor *v;
    q_obj_BLOCK_JOB_CANCELLED_arg param = {
        type, (char *)device, len, offset, speed
    };

    emit = qmp_event_get_func_emit();
    if (!emit) {
        return;
    }

    qmp = qmp_event_build_dict("BLOCK_JOB_CANCELLED");

    v = qobject_output_visitor_new(&obj);

    visit_start_struct(v, "BLOCK_JOB_CANCELLED", NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_BLOCK_JOB_CANCELLED_arg_members(v, &param, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    visit_complete(v, &obj);
    qdict_put_obj(qmp, "data", obj);
    emit(QAPI_EVENT_BLOCK_JOB_CANCELLED, qmp, &err);

out:
    visit_free(v);
    error_propagate(errp, err);
    QDECREF(qmp);
}

void qapi_event_send_block_job_completed(BlockJobType type, const char *device, int64_t len, int64_t offset, int64_t speed, bool has_error, const char *error, Error **errp)
{
    QDict *qmp;
    Error *err = NULL;
    QMPEventFuncEmit emit;
    QObject *obj;
    Visitor *v;
    q_obj_BLOCK_JOB_COMPLETED_arg param = {
        type, (char *)device, len, offset, speed, has_error, (char *)error
    };

    emit = qmp_event_get_func_emit();
    if (!emit) {
        return;
    }

    qmp = qmp_event_build_dict("BLOCK_JOB_COMPLETED");

    v = qobject_output_visitor_new(&obj);

    visit_start_struct(v, "BLOCK_JOB_COMPLETED", NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_BLOCK_JOB_COMPLETED_arg_members(v, &param, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    visit_complete(v, &obj);
    qdict_put_obj(qmp, "data", obj);
    emit(QAPI_EVENT_BLOCK_JOB_COMPLETED, qmp, &err);

out:
    visit_free(v);
    error_propagate(errp, err);
    QDECREF(qmp);
}

void qapi_event_send_block_job_error(const char *device, IoOperationType operation, BlockErrorAction action, Error **errp)
{
    QDict *qmp;
    Error *err = NULL;
    QMPEventFuncEmit emit;
    QObject *obj;
    Visitor *v;
    q_obj_BLOCK_JOB_ERROR_arg param = {
        (char *)device, operation, action
    };

    emit = qmp_event_get_func_emit();
    if (!emit) {
        return;
    }

    qmp = qmp_event_build_dict("BLOCK_JOB_ERROR");

    v = qobject_output_visitor_new(&obj);

    visit_start_struct(v, "BLOCK_JOB_ERROR", NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_BLOCK_JOB_ERROR_arg_members(v, &param, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    visit_complete(v, &obj);
    qdict_put_obj(qmp, "data", obj);
    emit(QAPI_EVENT_BLOCK_JOB_ERROR, qmp, &err);

out:
    visit_free(v);
    error_propagate(errp, err);
    QDECREF(qmp);
}

void qapi_event_send_block_job_ready(BlockJobType type, const char *device, int64_t len, int64_t offset, int64_t speed, Error **errp)
{
    QDict *qmp;
    Error *err = NULL;
    QMPEventFuncEmit emit;
    QObject *obj;
    Visitor *v;
    q_obj_BLOCK_JOB_READY_arg param = {
        type, (char *)device, len, offset, speed
    };

    emit = qmp_event_get_func_emit();
    if (!emit) {
        return;
    }

    qmp = qmp_event_build_dict("BLOCK_JOB_READY");

    v = qobject_output_visitor_new(&obj);

    visit_start_struct(v, "BLOCK_JOB_READY", NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_BLOCK_JOB_READY_arg_members(v, &param, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    visit_complete(v, &obj);
    qdict_put_obj(qmp, "data", obj);
    emit(QAPI_EVENT_BLOCK_JOB_READY, qmp, &err);

out:
    visit_free(v);
    error_propagate(errp, err);
    QDECREF(qmp);
}

void qapi_event_send_block_write_threshold(const char *node_name, uint64_t amount_exceeded, uint64_t write_threshold, Error **errp)
{
    QDict *qmp;
    Error *err = NULL;
    QMPEventFuncEmit emit;
    QObject *obj;
    Visitor *v;
    q_obj_BLOCK_WRITE_THRESHOLD_arg param = {
        (char *)node_name, amount_exceeded, write_threshold
    };

    emit = qmp_event_get_func_emit();
    if (!emit) {
        return;
    }

    qmp = qmp_event_build_dict("BLOCK_WRITE_THRESHOLD");

    v = qobject_output_visitor_new(&obj);

    visit_start_struct(v, "BLOCK_WRITE_THRESHOLD", NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_BLOCK_WRITE_THRESHOLD_arg_members(v, &param, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    visit_complete(v, &obj);
    qdict_put_obj(qmp, "data", obj);
    emit(QAPI_EVENT_BLOCK_WRITE_THRESHOLD, qmp, &err);

out:
    visit_free(v);
    error_propagate(errp, err);
    QDECREF(qmp);
}

void qapi_event_send_device_deleted(bool has_device, const char *device, const char *path, Error **errp)
{
    QDict *qmp;
    Error *err = NULL;
    QMPEventFuncEmit emit;
    QObject *obj;
    Visitor *v;
    q_obj_DEVICE_DELETED_arg param = {
        has_device, (char *)device, (char *)path
    };

    emit = qmp_event_get_func_emit();
    if (!emit) {
        return;
    }

    qmp = qmp_event_build_dict("DEVICE_DELETED");

    v = qobject_output_visitor_new(&obj);

    visit_start_struct(v, "DEVICE_DELETED", NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_DEVICE_DELETED_arg_members(v, &param, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    visit_complete(v, &obj);
    qdict_put_obj(qmp, "data", obj);
    emit(QAPI_EVENT_DEVICE_DELETED, qmp, &err);

out:
    visit_free(v);
    error_propagate(errp, err);
    QDECREF(qmp);
}

void qapi_event_send_device_tray_moved(const char *device, const char *id, bool tray_open, Error **errp)
{
    QDict *qmp;
    Error *err = NULL;
    QMPEventFuncEmit emit;
    QObject *obj;
    Visitor *v;
    q_obj_DEVICE_TRAY_MOVED_arg param = {
        (char *)device, (char *)id, tray_open
    };

    emit = qmp_event_get_func_emit();
    if (!emit) {
        return;
    }

    qmp = qmp_event_build_dict("DEVICE_TRAY_MOVED");

    v = qobject_output_visitor_new(&obj);

    visit_start_struct(v, "DEVICE_TRAY_MOVED", NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_DEVICE_TRAY_MOVED_arg_members(v, &param, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    visit_complete(v, &obj);
    qdict_put_obj(qmp, "data", obj);
    emit(QAPI_EVENT_DEVICE_TRAY_MOVED, qmp, &err);

out:
    visit_free(v);
    error_propagate(errp, err);
    QDECREF(qmp);
}

void qapi_event_send_dump_completed(DumpQueryResult *result, bool has_error, const char *error, Error **errp)
{
    QDict *qmp;
    Error *err = NULL;
    QMPEventFuncEmit emit;
    QObject *obj;
    Visitor *v;
    q_obj_DUMP_COMPLETED_arg param = {
        result, has_error, (char *)error
    };

    emit = qmp_event_get_func_emit();
    if (!emit) {
        return;
    }

    qmp = qmp_event_build_dict("DUMP_COMPLETED");

    v = qobject_output_visitor_new(&obj);

    visit_start_struct(v, "DUMP_COMPLETED", NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_DUMP_COMPLETED_arg_members(v, &param, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    visit_complete(v, &obj);
    qdict_put_obj(qmp, "data", obj);
    emit(QAPI_EVENT_DUMP_COMPLETED, qmp, &err);

out:
    visit_free(v);
    error_propagate(errp, err);
    QDECREF(qmp);
}

void qapi_event_send_guest_panicked(GuestPanicAction action, bool has_info, GuestPanicInformation *info, Error **errp)
{
    QDict *qmp;
    Error *err = NULL;
    QMPEventFuncEmit emit;
    QObject *obj;
    Visitor *v;
    q_obj_GUEST_PANICKED_arg param = {
        action, has_info, info
    };

    emit = qmp_event_get_func_emit();
    if (!emit) {
        return;
    }

    qmp = qmp_event_build_dict("GUEST_PANICKED");

    v = qobject_output_visitor_new(&obj);

    visit_start_struct(v, "GUEST_PANICKED", NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_GUEST_PANICKED_arg_members(v, &param, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    visit_complete(v, &obj);
    qdict_put_obj(qmp, "data", obj);
    emit(QAPI_EVENT_GUEST_PANICKED, qmp, &err);

out:
    visit_free(v);
    error_propagate(errp, err);
    QDECREF(qmp);
}

void qapi_event_send_mem_unplug_error(const char *device, const char *msg, Error **errp)
{
    QDict *qmp;
    Error *err = NULL;
    QMPEventFuncEmit emit;
    QObject *obj;
    Visitor *v;
    q_obj_MEM_UNPLUG_ERROR_arg param = {
        (char *)device, (char *)msg
    };

    emit = qmp_event_get_func_emit();
    if (!emit) {
        return;
    }

    qmp = qmp_event_build_dict("MEM_UNPLUG_ERROR");

    v = qobject_output_visitor_new(&obj);

    visit_start_struct(v, "MEM_UNPLUG_ERROR", NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_MEM_UNPLUG_ERROR_arg_members(v, &param, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    visit_complete(v, &obj);
    qdict_put_obj(qmp, "data", obj);
    emit(QAPI_EVENT_MEM_UNPLUG_ERROR, qmp, &err);

out:
    visit_free(v);
    error_propagate(errp, err);
    QDECREF(qmp);
}

void qapi_event_send_migration(MigrationStatus status, Error **errp)
{
    QDict *qmp;
    Error *err = NULL;
    QMPEventFuncEmit emit;
    QObject *obj;
    Visitor *v;
    q_obj_MIGRATION_arg param = {
        status
    };

    emit = qmp_event_get_func_emit();
    if (!emit) {
        return;
    }

    qmp = qmp_event_build_dict("MIGRATION");

    v = qobject_output_visitor_new(&obj);

    visit_start_struct(v, "MIGRATION", NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_MIGRATION_arg_members(v, &param, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    visit_complete(v, &obj);
    qdict_put_obj(qmp, "data", obj);
    emit(QAPI_EVENT_MIGRATION, qmp, &err);

out:
    visit_free(v);
    error_propagate(errp, err);
    QDECREF(qmp);
}

void qapi_event_send_migration_pass(int64_t pass, Error **errp)
{
    QDict *qmp;
    Error *err = NULL;
    QMPEventFuncEmit emit;
    QObject *obj;
    Visitor *v;
    q_obj_MIGRATION_PASS_arg param = {
        pass
    };

    emit = qmp_event_get_func_emit();
    if (!emit) {
        return;
    }

    qmp = qmp_event_build_dict("MIGRATION_PASS");

    v = qobject_output_visitor_new(&obj);

    visit_start_struct(v, "MIGRATION_PASS", NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_MIGRATION_PASS_arg_members(v, &param, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    visit_complete(v, &obj);
    qdict_put_obj(qmp, "data", obj);
    emit(QAPI_EVENT_MIGRATION_PASS, qmp, &err);

out:
    visit_free(v);
    error_propagate(errp, err);
    QDECREF(qmp);
}

void qapi_event_send_nic_rx_filter_changed(bool has_name, const char *name, const char *path, Error **errp)
{
    QDict *qmp;
    Error *err = NULL;
    QMPEventFuncEmit emit;
    QObject *obj;
    Visitor *v;
    q_obj_NIC_RX_FILTER_CHANGED_arg param = {
        has_name, (char *)name, (char *)path
    };

    emit = qmp_event_get_func_emit();
    if (!emit) {
        return;
    }

    qmp = qmp_event_build_dict("NIC_RX_FILTER_CHANGED");

    v = qobject_output_visitor_new(&obj);

    visit_start_struct(v, "NIC_RX_FILTER_CHANGED", NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_NIC_RX_FILTER_CHANGED_arg_members(v, &param, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    visit_complete(v, &obj);
    qdict_put_obj(qmp, "data", obj);
    emit(QAPI_EVENT_NIC_RX_FILTER_CHANGED, qmp, &err);

out:
    visit_free(v);
    error_propagate(errp, err);
    QDECREF(qmp);
}

void qapi_event_send_powerdown(Error **errp)
{
    QDict *qmp;
    Error *err = NULL;
    QMPEventFuncEmit emit;

    emit = qmp_event_get_func_emit();
    if (!emit) {
        return;
    }

    qmp = qmp_event_build_dict("POWERDOWN");

    emit(QAPI_EVENT_POWERDOWN, qmp, &err);

    error_propagate(errp, err);
    QDECREF(qmp);
}

void qapi_event_send_quorum_failure(const char *reference, int64_t sector_num, int64_t sectors_count, Error **errp)
{
    QDict *qmp;
    Error *err = NULL;
    QMPEventFuncEmit emit;
    QObject *obj;
    Visitor *v;
    q_obj_QUORUM_FAILURE_arg param = {
        (char *)reference, sector_num, sectors_count
    };

    emit = qmp_event_get_func_emit();
    if (!emit) {
        return;
    }

    qmp = qmp_event_build_dict("QUORUM_FAILURE");

    v = qobject_output_visitor_new(&obj);

    visit_start_struct(v, "QUORUM_FAILURE", NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_QUORUM_FAILURE_arg_members(v, &param, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    visit_complete(v, &obj);
    qdict_put_obj(qmp, "data", obj);
    emit(QAPI_EVENT_QUORUM_FAILURE, qmp, &err);

out:
    visit_free(v);
    error_propagate(errp, err);
    QDECREF(qmp);
}

void qapi_event_send_quorum_report_bad(QuorumOpType type, bool has_error, const char *error, const char *node_name, int64_t sector_num, int64_t sectors_count, Error **errp)
{
    QDict *qmp;
    Error *err = NULL;
    QMPEventFuncEmit emit;
    QObject *obj;
    Visitor *v;
    q_obj_QUORUM_REPORT_BAD_arg param = {
        type, has_error, (char *)error, (char *)node_name, sector_num, sectors_count
    };

    emit = qmp_event_get_func_emit();
    if (!emit) {
        return;
    }

    qmp = qmp_event_build_dict("QUORUM_REPORT_BAD");

    v = qobject_output_visitor_new(&obj);

    visit_start_struct(v, "QUORUM_REPORT_BAD", NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_QUORUM_REPORT_BAD_arg_members(v, &param, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    visit_complete(v, &obj);
    qdict_put_obj(qmp, "data", obj);
    emit(QAPI_EVENT_QUORUM_REPORT_BAD, qmp, &err);

out:
    visit_free(v);
    error_propagate(errp, err);
    QDECREF(qmp);
}

void qapi_event_send_reset(Error **errp)
{
    QDict *qmp;
    Error *err = NULL;
    QMPEventFuncEmit emit;

    emit = qmp_event_get_func_emit();
    if (!emit) {
        return;
    }

    qmp = qmp_event_build_dict("RESET");

    emit(QAPI_EVENT_RESET, qmp, &err);

    error_propagate(errp, err);
    QDECREF(qmp);
}

void qapi_event_send_resume(Error **errp)
{
    QDict *qmp;
    Error *err = NULL;
    QMPEventFuncEmit emit;

    emit = qmp_event_get_func_emit();
    if (!emit) {
        return;
    }

    qmp = qmp_event_build_dict("RESUME");

    emit(QAPI_EVENT_RESUME, qmp, &err);

    error_propagate(errp, err);
    QDECREF(qmp);
}

void qapi_event_send_rtc_change(int64_t offset, Error **errp)
{
    QDict *qmp;
    Error *err = NULL;
    QMPEventFuncEmit emit;
    QObject *obj;
    Visitor *v;
    q_obj_RTC_CHANGE_arg param = {
        offset
    };

    emit = qmp_event_get_func_emit();
    if (!emit) {
        return;
    }

    qmp = qmp_event_build_dict("RTC_CHANGE");

    v = qobject_output_visitor_new(&obj);

    visit_start_struct(v, "RTC_CHANGE", NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_RTC_CHANGE_arg_members(v, &param, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    visit_complete(v, &obj);
    qdict_put_obj(qmp, "data", obj);
    emit(QAPI_EVENT_RTC_CHANGE, qmp, &err);

out:
    visit_free(v);
    error_propagate(errp, err);
    QDECREF(qmp);
}

void qapi_event_send_shutdown(Error **errp)
{
    QDict *qmp;
    Error *err = NULL;
    QMPEventFuncEmit emit;

    emit = qmp_event_get_func_emit();
    if (!emit) {
        return;
    }

    qmp = qmp_event_build_dict("SHUTDOWN");

    emit(QAPI_EVENT_SHUTDOWN, qmp, &err);

    error_propagate(errp, err);
    QDECREF(qmp);
}

void qapi_event_send_spice_connected(SpiceBasicInfo *server, SpiceBasicInfo *client, Error **errp)
{
    QDict *qmp;
    Error *err = NULL;
    QMPEventFuncEmit emit;
    QObject *obj;
    Visitor *v;
    q_obj_SPICE_CONNECTED_arg param = {
        server, client
    };

    emit = qmp_event_get_func_emit();
    if (!emit) {
        return;
    }

    qmp = qmp_event_build_dict("SPICE_CONNECTED");

    v = qobject_output_visitor_new(&obj);

    visit_start_struct(v, "SPICE_CONNECTED", NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_SPICE_CONNECTED_arg_members(v, &param, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    visit_complete(v, &obj);
    qdict_put_obj(qmp, "data", obj);
    emit(QAPI_EVENT_SPICE_CONNECTED, qmp, &err);

out:
    visit_free(v);
    error_propagate(errp, err);
    QDECREF(qmp);
}

void qapi_event_send_spice_disconnected(SpiceBasicInfo *server, SpiceBasicInfo *client, Error **errp)
{
    QDict *qmp;
    Error *err = NULL;
    QMPEventFuncEmit emit;
    QObject *obj;
    Visitor *v;
    q_obj_SPICE_DISCONNECTED_arg param = {
        server, client
    };

    emit = qmp_event_get_func_emit();
    if (!emit) {
        return;
    }

    qmp = qmp_event_build_dict("SPICE_DISCONNECTED");

    v = qobject_output_visitor_new(&obj);

    visit_start_struct(v, "SPICE_DISCONNECTED", NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_SPICE_DISCONNECTED_arg_members(v, &param, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    visit_complete(v, &obj);
    qdict_put_obj(qmp, "data", obj);
    emit(QAPI_EVENT_SPICE_DISCONNECTED, qmp, &err);

out:
    visit_free(v);
    error_propagate(errp, err);
    QDECREF(qmp);
}

void qapi_event_send_spice_initialized(SpiceServerInfo *server, SpiceChannel *client, Error **errp)
{
    QDict *qmp;
    Error *err = NULL;
    QMPEventFuncEmit emit;
    QObject *obj;
    Visitor *v;
    q_obj_SPICE_INITIALIZED_arg param = {
        server, client
    };

    emit = qmp_event_get_func_emit();
    if (!emit) {
        return;
    }

    qmp = qmp_event_build_dict("SPICE_INITIALIZED");

    v = qobject_output_visitor_new(&obj);

    visit_start_struct(v, "SPICE_INITIALIZED", NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_SPICE_INITIALIZED_arg_members(v, &param, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    visit_complete(v, &obj);
    qdict_put_obj(qmp, "data", obj);
    emit(QAPI_EVENT_SPICE_INITIALIZED, qmp, &err);

out:
    visit_free(v);
    error_propagate(errp, err);
    QDECREF(qmp);
}

void qapi_event_send_spice_migrate_completed(Error **errp)
{
    QDict *qmp;
    Error *err = NULL;
    QMPEventFuncEmit emit;

    emit = qmp_event_get_func_emit();
    if (!emit) {
        return;
    }

    qmp = qmp_event_build_dict("SPICE_MIGRATE_COMPLETED");

    emit(QAPI_EVENT_SPICE_MIGRATE_COMPLETED, qmp, &err);

    error_propagate(errp, err);
    QDECREF(qmp);
}

void qapi_event_send_stop(Error **errp)
{
    QDict *qmp;
    Error *err = NULL;
    QMPEventFuncEmit emit;

    emit = qmp_event_get_func_emit();
    if (!emit) {
        return;
    }

    qmp = qmp_event_build_dict("STOP");

    emit(QAPI_EVENT_STOP, qmp, &err);

    error_propagate(errp, err);
    QDECREF(qmp);
}

void qapi_event_send_suspend(Error **errp)
{
    QDict *qmp;
    Error *err = NULL;
    QMPEventFuncEmit emit;

    emit = qmp_event_get_func_emit();
    if (!emit) {
        return;
    }

    qmp = qmp_event_build_dict("SUSPEND");

    emit(QAPI_EVENT_SUSPEND, qmp, &err);

    error_propagate(errp, err);
    QDECREF(qmp);
}

void qapi_event_send_suspend_disk(Error **errp)
{
    QDict *qmp;
    Error *err = NULL;
    QMPEventFuncEmit emit;

    emit = qmp_event_get_func_emit();
    if (!emit) {
        return;
    }

    qmp = qmp_event_build_dict("SUSPEND_DISK");

    emit(QAPI_EVENT_SUSPEND_DISK, qmp, &err);

    error_propagate(errp, err);
    QDECREF(qmp);
}

void qapi_event_send_vnc_connected(VncServerInfo *server, VncBasicInfo *client, Error **errp)
{
    QDict *qmp;
    Error *err = NULL;
    QMPEventFuncEmit emit;
    QObject *obj;
    Visitor *v;
    q_obj_VNC_CONNECTED_arg param = {
        server, client
    };

    emit = qmp_event_get_func_emit();
    if (!emit) {
        return;
    }

    qmp = qmp_event_build_dict("VNC_CONNECTED");

    v = qobject_output_visitor_new(&obj);

    visit_start_struct(v, "VNC_CONNECTED", NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_VNC_CONNECTED_arg_members(v, &param, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    visit_complete(v, &obj);
    qdict_put_obj(qmp, "data", obj);
    emit(QAPI_EVENT_VNC_CONNECTED, qmp, &err);

out:
    visit_free(v);
    error_propagate(errp, err);
    QDECREF(qmp);
}

void qapi_event_send_vnc_disconnected(VncServerInfo *server, VncClientInfo *client, Error **errp)
{
    QDict *qmp;
    Error *err = NULL;
    QMPEventFuncEmit emit;
    QObject *obj;
    Visitor *v;
    q_obj_VNC_DISCONNECTED_arg param = {
        server, client
    };

    emit = qmp_event_get_func_emit();
    if (!emit) {
        return;
    }

    qmp = qmp_event_build_dict("VNC_DISCONNECTED");

    v = qobject_output_visitor_new(&obj);

    visit_start_struct(v, "VNC_DISCONNECTED", NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_VNC_DISCONNECTED_arg_members(v, &param, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    visit_complete(v, &obj);
    qdict_put_obj(qmp, "data", obj);
    emit(QAPI_EVENT_VNC_DISCONNECTED, qmp, &err);

out:
    visit_free(v);
    error_propagate(errp, err);
    QDECREF(qmp);
}

void qapi_event_send_vnc_initialized(VncServerInfo *server, VncClientInfo *client, Error **errp)
{
    QDict *qmp;
    Error *err = NULL;
    QMPEventFuncEmit emit;
    QObject *obj;
    Visitor *v;
    q_obj_VNC_INITIALIZED_arg param = {
        server, client
    };

    emit = qmp_event_get_func_emit();
    if (!emit) {
        return;
    }

    qmp = qmp_event_build_dict("VNC_INITIALIZED");

    v = qobject_output_visitor_new(&obj);

    visit_start_struct(v, "VNC_INITIALIZED", NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_VNC_INITIALIZED_arg_members(v, &param, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    visit_complete(v, &obj);
    qdict_put_obj(qmp, "data", obj);
    emit(QAPI_EVENT_VNC_INITIALIZED, qmp, &err);

out:
    visit_free(v);
    error_propagate(errp, err);
    QDECREF(qmp);
}

void qapi_event_send_vserport_change(const char *id, bool open, Error **errp)
{
    QDict *qmp;
    Error *err = NULL;
    QMPEventFuncEmit emit;
    QObject *obj;
    Visitor *v;
    q_obj_VSERPORT_CHANGE_arg param = {
        (char *)id, open
    };

    emit = qmp_event_get_func_emit();
    if (!emit) {
        return;
    }

    qmp = qmp_event_build_dict("VSERPORT_CHANGE");

    v = qobject_output_visitor_new(&obj);

    visit_start_struct(v, "VSERPORT_CHANGE", NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_VSERPORT_CHANGE_arg_members(v, &param, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    visit_complete(v, &obj);
    qdict_put_obj(qmp, "data", obj);
    emit(QAPI_EVENT_VSERPORT_CHANGE, qmp, &err);

out:
    visit_free(v);
    error_propagate(errp, err);
    QDECREF(qmp);
}

void qapi_event_send_wakeup(Error **errp)
{
    QDict *qmp;
    Error *err = NULL;
    QMPEventFuncEmit emit;

    emit = qmp_event_get_func_emit();
    if (!emit) {
        return;
    }

    qmp = qmp_event_build_dict("WAKEUP");

    emit(QAPI_EVENT_WAKEUP, qmp, &err);

    error_propagate(errp, err);
    QDECREF(qmp);
}

void qapi_event_send_watchdog(WatchdogExpirationAction action, Error **errp)
{
    QDict *qmp;
    Error *err = NULL;
    QMPEventFuncEmit emit;
    QObject *obj;
    Visitor *v;
    q_obj_WATCHDOG_arg param = {
        action
    };

    emit = qmp_event_get_func_emit();
    if (!emit) {
        return;
    }

    qmp = qmp_event_build_dict("WATCHDOG");

    v = qobject_output_visitor_new(&obj);

    visit_start_struct(v, "WATCHDOG", NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_WATCHDOG_arg_members(v, &param, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    visit_complete(v, &obj);
    qdict_put_obj(qmp, "data", obj);
    emit(QAPI_EVENT_WATCHDOG, qmp, &err);

out:
    visit_free(v);
    error_propagate(errp, err);
    QDECREF(qmp);
}

const char *const QAPIEvent_lookup[] = {
    [QAPI_EVENT_ACPI_DEVICE_OST] = "ACPI_DEVICE_OST",
    [QAPI_EVENT_BALLOON_CHANGE] = "BALLOON_CHANGE",
    [QAPI_EVENT_BLOCK_IMAGE_CORRUPTED] = "BLOCK_IMAGE_CORRUPTED",
    [QAPI_EVENT_BLOCK_IO_ERROR] = "BLOCK_IO_ERROR",
    [QAPI_EVENT_BLOCK_JOB_CANCELLED] = "BLOCK_JOB_CANCELLED",
    [QAPI_EVENT_BLOCK_JOB_COMPLETED] = "BLOCK_JOB_COMPLETED",
    [QAPI_EVENT_BLOCK_JOB_ERROR] = "BLOCK_JOB_ERROR",
    [QAPI_EVENT_BLOCK_JOB_READY] = "BLOCK_JOB_READY",
    [QAPI_EVENT_BLOCK_WRITE_THRESHOLD] = "BLOCK_WRITE_THRESHOLD",
    [QAPI_EVENT_DEVICE_DELETED] = "DEVICE_DELETED",
    [QAPI_EVENT_DEVICE_TRAY_MOVED] = "DEVICE_TRAY_MOVED",
    [QAPI_EVENT_DUMP_COMPLETED] = "DUMP_COMPLETED",
    [QAPI_EVENT_GUEST_PANICKED] = "GUEST_PANICKED",
    [QAPI_EVENT_MEM_UNPLUG_ERROR] = "MEM_UNPLUG_ERROR",
    [QAPI_EVENT_MIGRATION] = "MIGRATION",
    [QAPI_EVENT_MIGRATION_PASS] = "MIGRATION_PASS",
    [QAPI_EVENT_NIC_RX_FILTER_CHANGED] = "NIC_RX_FILTER_CHANGED",
    [QAPI_EVENT_POWERDOWN] = "POWERDOWN",
    [QAPI_EVENT_QUORUM_FAILURE] = "QUORUM_FAILURE",
    [QAPI_EVENT_QUORUM_REPORT_BAD] = "QUORUM_REPORT_BAD",
    [QAPI_EVENT_RESET] = "RESET",
    [QAPI_EVENT_RESUME] = "RESUME",
    [QAPI_EVENT_RTC_CHANGE] = "RTC_CHANGE",
    [QAPI_EVENT_SHUTDOWN] = "SHUTDOWN",
    [QAPI_EVENT_SPICE_CONNECTED] = "SPICE_CONNECTED",
    [QAPI_EVENT_SPICE_DISCONNECTED] = "SPICE_DISCONNECTED",
    [QAPI_EVENT_SPICE_INITIALIZED] = "SPICE_INITIALIZED",
    [QAPI_EVENT_SPICE_MIGRATE_COMPLETED] = "SPICE_MIGRATE_COMPLETED",
    [QAPI_EVENT_STOP] = "STOP",
    [QAPI_EVENT_SUSPEND] = "SUSPEND",
    [QAPI_EVENT_SUSPEND_DISK] = "SUSPEND_DISK",
    [QAPI_EVENT_VNC_CONNECTED] = "VNC_CONNECTED",
    [QAPI_EVENT_VNC_DISCONNECTED] = "VNC_DISCONNECTED",
    [QAPI_EVENT_VNC_INITIALIZED] = "VNC_INITIALIZED",
    [QAPI_EVENT_VSERPORT_CHANGE] = "VSERPORT_CHANGE",
    [QAPI_EVENT_WAKEUP] = "WAKEUP",
    [QAPI_EVENT_WATCHDOG] = "WATCHDOG",
    [QAPI_EVENT__MAX] = NULL,
};
