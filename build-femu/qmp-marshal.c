/* AUTOMATICALLY GENERATED, DO NOT MODIFY */

/*
 * schema-defined QMP->QAPI command dispatch
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
#include "qemu/module.h"
#include "qapi/qmp/types.h"
#include "qapi/visitor.h"
#include "qapi/qobject-output-visitor.h"
#include "qapi/qobject-input-visitor.h"
#include "qapi/dealloc-visitor.h"
#include "qapi-types.h"
#include "qapi-visit.h"
#include "qmp-commands.h"


static void qmp_marshal_output_AddfdInfo(AddfdInfo *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_AddfdInfo(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_AddfdInfo(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_add_fd(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    AddfdInfo *retval;
    Visitor *v;
    q_obj_add_fd_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_add_fd_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    retval = qmp_add_fd(arg.has_fdset_id, arg.fdset_id, arg.has_opaque, arg.opaque, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_AddfdInfo(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_add_fd_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_add_client(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_add_client_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_add_client_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_add_client(arg.protocol, arg.fdname, arg.has_skipauth, arg.skipauth, arg.has_tls, arg.tls, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_add_client_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_balloon(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_balloon_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_balloon_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_balloon(arg.value, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_balloon_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_block_commit(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_block_commit_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_block_commit_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_block_commit(arg.has_job_id, arg.job_id, arg.device, arg.has_base, arg.base, arg.has_top, arg.top, arg.has_backing_file, arg.backing_file, arg.has_speed, arg.speed, arg.has_filter_node_name, arg.filter_node_name, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_block_commit_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_block_dirty_bitmap_add(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    BlockDirtyBitmapAdd arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_BlockDirtyBitmapAdd_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_block_dirty_bitmap_add(arg.node, arg.name, arg.has_granularity, arg.granularity, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_BlockDirtyBitmapAdd_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_block_dirty_bitmap_clear(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    BlockDirtyBitmap arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_BlockDirtyBitmap_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_block_dirty_bitmap_clear(arg.node, arg.name, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_BlockDirtyBitmap_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_block_dirty_bitmap_remove(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    BlockDirtyBitmap arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_BlockDirtyBitmap_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_block_dirty_bitmap_remove(arg.node, arg.name, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_BlockDirtyBitmap_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_block_job_cancel(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_block_job_cancel_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_block_job_cancel_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_block_job_cancel(arg.device, arg.has_force, arg.force, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_block_job_cancel_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_block_job_complete(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_block_job_complete_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_block_job_complete_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_block_job_complete(arg.device, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_block_job_complete_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_block_job_pause(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_block_job_pause_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_block_job_pause_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_block_job_pause(arg.device, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_block_job_pause_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_block_job_resume(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_block_job_resume_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_block_job_resume_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_block_job_resume(arg.device, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_block_job_resume_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_block_job_set_speed(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_block_job_set_speed_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_block_job_set_speed_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_block_job_set_speed(arg.device, arg.speed, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_block_job_set_speed_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_block_set_write_threshold(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_block_set_write_threshold_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_block_set_write_threshold_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_block_set_write_threshold(arg.node_name, arg.write_threshold, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_block_set_write_threshold_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_block_stream(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_block_stream_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_block_stream_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_block_stream(arg.has_job_id, arg.job_id, arg.device, arg.has_base, arg.base, arg.has_base_node, arg.base_node, arg.has_backing_file, arg.backing_file, arg.has_speed, arg.speed, arg.has_on_error, arg.on_error, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_block_stream_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_block_passwd(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_block_passwd_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_block_passwd_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_block_passwd(arg.has_device, arg.device, arg.has_node_name, arg.node_name, arg.password, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_block_passwd_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_block_resize(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_block_resize_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_block_resize_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_block_resize(arg.has_device, arg.device, arg.has_node_name, arg.node_name, arg.size, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_block_resize_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_block_set_io_throttle(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    BlockIOThrottle arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_BlockIOThrottle_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_block_set_io_throttle(&arg, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_BlockIOThrottle_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_blockdev_add(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    BlockdevOptions arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_BlockdevOptions_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_blockdev_add(&arg, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_BlockdevOptions_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_blockdev_backup(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    BlockdevBackup arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_BlockdevBackup_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_blockdev_backup(&arg, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_BlockdevBackup_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_blockdev_change_medium(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_blockdev_change_medium_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_blockdev_change_medium_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_blockdev_change_medium(arg.has_device, arg.device, arg.has_id, arg.id, arg.filename, arg.has_format, arg.format, arg.has_read_only_mode, arg.read_only_mode, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_blockdev_change_medium_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_blockdev_close_tray(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_blockdev_close_tray_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_blockdev_close_tray_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_blockdev_close_tray(arg.has_device, arg.device, arg.has_id, arg.id, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_blockdev_close_tray_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_blockdev_del(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_blockdev_del_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_blockdev_del_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_blockdev_del(arg.node_name, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_blockdev_del_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_blockdev_mirror(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_blockdev_mirror_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_blockdev_mirror_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_blockdev_mirror(arg.has_job_id, arg.job_id, arg.device, arg.target, arg.has_replaces, arg.replaces, arg.sync, arg.has_speed, arg.speed, arg.has_granularity, arg.granularity, arg.has_buf_size, arg.buf_size, arg.has_on_source_error, arg.on_source_error, arg.has_on_target_error, arg.on_target_error, arg.has_filter_node_name, arg.filter_node_name, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_blockdev_mirror_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_blockdev_open_tray(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_blockdev_open_tray_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_blockdev_open_tray_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_blockdev_open_tray(arg.has_device, arg.device, arg.has_id, arg.id, arg.has_force, arg.force, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_blockdev_open_tray_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_blockdev_snapshot(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    BlockdevSnapshot arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_BlockdevSnapshot_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_blockdev_snapshot(arg.node, arg.overlay, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_BlockdevSnapshot_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

static void qmp_marshal_output_SnapshotInfo(SnapshotInfo *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_SnapshotInfo(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_SnapshotInfo(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_blockdev_snapshot_delete_internal_sync(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    SnapshotInfo *retval;
    Visitor *v;
    q_obj_blockdev_snapshot_delete_internal_sync_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_blockdev_snapshot_delete_internal_sync_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    retval = qmp_blockdev_snapshot_delete_internal_sync(arg.device, arg.has_id, arg.id, arg.has_name, arg.name, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_SnapshotInfo(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_blockdev_snapshot_delete_internal_sync_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_blockdev_snapshot_internal_sync(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    BlockdevSnapshotInternal arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_BlockdevSnapshotInternal_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_blockdev_snapshot_internal_sync(arg.device, arg.name, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_BlockdevSnapshotInternal_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_blockdev_snapshot_sync(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    BlockdevSnapshotSync arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_BlockdevSnapshotSync_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_blockdev_snapshot_sync(arg.has_device, arg.device, arg.has_node_name, arg.node_name, arg.snapshot_file, arg.has_snapshot_node_name, arg.snapshot_node_name, arg.has_format, arg.format, arg.has_mode, arg.mode, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_BlockdevSnapshotSync_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_change(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_change_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_change_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_change(arg.device, arg.target, arg.has_arg, arg.arg, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_change_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_change_backing_file(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_change_backing_file_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_change_backing_file_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_change_backing_file(arg.device, arg.image_node_name, arg.backing_file, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_change_backing_file_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_change_vnc_password(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_change_vnc_password_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_change_vnc_password_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_change_vnc_password(arg.password, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_change_vnc_password_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

static void qmp_marshal_output_ChardevReturn(ChardevReturn *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_ChardevReturn(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_ChardevReturn(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_chardev_add(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    ChardevReturn *retval;
    Visitor *v;
    q_obj_chardev_add_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_chardev_add_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    retval = qmp_chardev_add(arg.id, arg.backend, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_ChardevReturn(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_chardev_add_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_chardev_remove(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_chardev_remove_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_chardev_remove_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_chardev_remove(arg.id, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_chardev_remove_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_client_migrate_info(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_client_migrate_info_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_client_migrate_info_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_client_migrate_info(arg.protocol, arg.hostname, arg.has_port, arg.port, arg.has_tls_port, arg.tls_port, arg.has_cert_subject, arg.cert_subject, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_client_migrate_info_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_closefd(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_closefd_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_closefd_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_closefd(arg.fdname, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_closefd_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_cont(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    qmp_cont(&err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

void qmp_marshal_cpu(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_cpu_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_cpu_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_cpu(arg.index, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_cpu_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_cpu_add(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_cpu_add_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_cpu_add_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_cpu_add(arg.id, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_cpu_add_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

static void qmp_marshal_output_DevicePropertyInfoList(DevicePropertyInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_DevicePropertyInfoList(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_DevicePropertyInfoList(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_device_list_properties(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    DevicePropertyInfoList *retval;
    Visitor *v;
    q_obj_device_list_properties_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_device_list_properties_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    retval = qmp_device_list_properties(arg.q_typename, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_DevicePropertyInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_device_list_properties_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_device_del(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_device_del_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_device_del_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_device_del(arg.id, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_device_del_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_drive_backup(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    DriveBackup arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_DriveBackup_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_drive_backup(&arg, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_DriveBackup_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_drive_mirror(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    DriveMirror arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_DriveMirror_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_drive_mirror(&arg, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_DriveMirror_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_dump_guest_memory(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_dump_guest_memory_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_dump_guest_memory_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_dump_guest_memory(arg.paging, arg.protocol, arg.has_detach, arg.detach, arg.has_begin, arg.begin, arg.has_length, arg.length, arg.has_format, arg.format, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_dump_guest_memory_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_dump_skeys(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_dump_skeys_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_dump_skeys_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_dump_skeys(arg.filename, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_dump_skeys_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_eject(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_eject_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_eject_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_eject(arg.has_device, arg.device, arg.has_id, arg.id, arg.has_force, arg.force, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_eject_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_expire_password(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_expire_password_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_expire_password_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_expire_password(arg.protocol, arg.time, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_expire_password_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_getfd(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_getfd_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_getfd_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_getfd(arg.fdname, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_getfd_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

static void qmp_marshal_output_str(char *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_str(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_str(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_human_monitor_command(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    char *retval;
    Visitor *v;
    q_obj_human_monitor_command_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_human_monitor_command_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    retval = qmp_human_monitor_command(arg.command_line, arg.has_cpu_index, arg.cpu_index, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_str(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_human_monitor_command_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_inject_nmi(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    qmp_inject_nmi(&err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

void qmp_marshal_input_send_event(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_input_send_event_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_input_send_event_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_input_send_event(arg.has_device, arg.device, arg.has_head, arg.head, arg.events, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_input_send_event_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_memsave(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_memsave_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_memsave_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_memsave(arg.val, arg.size, arg.filename, arg.has_cpu_index, arg.cpu_index, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_memsave_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_migrate(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_migrate_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_migrate_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_migrate(arg.uri, arg.has_blk, arg.blk, arg.has_inc, arg.inc, arg.has_detach, arg.detach, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_migrate_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_migrate_incoming(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_migrate_incoming_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_migrate_incoming_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_migrate_incoming(arg.uri, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_migrate_incoming_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_migrate_set_cache_size(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_migrate_set_cache_size_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_migrate_set_cache_size_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_migrate_set_cache_size(arg.value, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_migrate_set_cache_size_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_migrate_set_capabilities(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_migrate_set_capabilities_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_migrate_set_capabilities_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_migrate_set_capabilities(arg.capabilities, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_migrate_set_capabilities_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_migrate_set_parameters(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    MigrationParameters arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_MigrationParameters_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_migrate_set_parameters(&arg, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_MigrationParameters_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_migrate_start_postcopy(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    qmp_migrate_start_postcopy(&err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

void qmp_marshal_migrate_cancel(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    qmp_migrate_cancel(&err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

void qmp_marshal_migrate_set_downtime(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_migrate_set_downtime_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_migrate_set_downtime_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_migrate_set_downtime(arg.value, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_migrate_set_downtime_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_migrate_set_speed(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_migrate_set_speed_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_migrate_set_speed_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_migrate_set_speed(arg.value, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_migrate_set_speed_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_nbd_server_add(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_nbd_server_add_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_nbd_server_add_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_nbd_server_add(arg.device, arg.has_writable, arg.writable, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_nbd_server_add_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_nbd_server_start(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_nbd_server_start_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_nbd_server_start_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_nbd_server_start(arg.addr, arg.has_tls_creds, arg.tls_creds, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_nbd_server_start_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_nbd_server_stop(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    qmp_nbd_server_stop(&err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

void qmp_marshal_netdev_del(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_netdev_del_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_netdev_del_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_netdev_del(arg.id, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_netdev_del_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_object_add(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_object_add_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_object_add_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_object_add(arg.qom_type, arg.id, arg.has_props, arg.props, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_object_add_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_object_del(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_object_del_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_object_del_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_object_del(arg.id, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_object_del_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_pmemsave(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_pmemsave_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_pmemsave_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_pmemsave(arg.val, arg.size, arg.filename, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_pmemsave_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_qmp_capabilities(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    qmp_qmp_capabilities(&err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_any(QObject *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_any(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_any(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_qom_get(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QObject *retval;
    Visitor *v;
    q_obj_qom_get_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_qom_get_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    retval = qmp_qom_get(arg.path, arg.property, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_any(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_qom_get_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

static void qmp_marshal_output_ObjectPropertyInfoList(ObjectPropertyInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_ObjectPropertyInfoList(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_ObjectPropertyInfoList(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_qom_list(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    ObjectPropertyInfoList *retval;
    Visitor *v;
    q_obj_qom_list_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_qom_list_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    retval = qmp_qom_list(arg.path, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_ObjectPropertyInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_qom_list_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

static void qmp_marshal_output_ObjectTypeInfoList(ObjectTypeInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_ObjectTypeInfoList(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_ObjectTypeInfoList(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_qom_list_types(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    ObjectTypeInfoList *retval;
    Visitor *v;
    q_obj_qom_list_types_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_qom_list_types_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    retval = qmp_qom_list_types(arg.has_implements, arg.implements, arg.has_abstract, arg.abstract, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_ObjectTypeInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_qom_list_types_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_qom_set(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_qom_set_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_qom_set_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_qom_set(arg.path, arg.property, arg.value, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_qom_set_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

static void qmp_marshal_output_ACPIOSTInfoList(ACPIOSTInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_ACPIOSTInfoList(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_ACPIOSTInfoList(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_acpi_ospm_status(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    ACPIOSTInfoList *retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_acpi_ospm_status(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_ACPIOSTInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_BalloonInfo(BalloonInfo *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_BalloonInfo(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_BalloonInfo(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_balloon(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    BalloonInfo *retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_balloon(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_BalloonInfo(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_BlockInfoList(BlockInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_BlockInfoList(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_BlockInfoList(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_block(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    BlockInfoList *retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_block(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_BlockInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_BlockJobInfoList(BlockJobInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_BlockJobInfoList(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_BlockJobInfoList(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_block_jobs(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    BlockJobInfoList *retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_block_jobs(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_BlockJobInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_BlockStatsList(BlockStatsList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_BlockStatsList(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_BlockStatsList(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_blockstats(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    BlockStatsList *retval;
    Visitor *v;
    q_obj_query_blockstats_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_query_blockstats_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    retval = qmp_query_blockstats(arg.has_query_nodes, arg.query_nodes, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_BlockStatsList(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_query_blockstats_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

static void qmp_marshal_output_ChardevInfoList(ChardevInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_ChardevInfoList(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_ChardevInfoList(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_chardev(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    ChardevInfoList *retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_chardev(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_ChardevInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_ChardevBackendInfoList(ChardevBackendInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_ChardevBackendInfoList(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_ChardevBackendInfoList(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_chardev_backends(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    ChardevBackendInfoList *retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_chardev_backends(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_ChardevBackendInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_CommandLineOptionInfoList(CommandLineOptionInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_CommandLineOptionInfoList(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_CommandLineOptionInfoList(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_command_line_options(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    CommandLineOptionInfoList *retval;
    Visitor *v;
    q_obj_query_command_line_options_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_query_command_line_options_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    retval = qmp_query_command_line_options(arg.has_option, arg.option, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_CommandLineOptionInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_query_command_line_options_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

static void qmp_marshal_output_CommandInfoList(CommandInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_CommandInfoList(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_CommandInfoList(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_commands(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    CommandInfoList *retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_commands(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_CommandInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_CpuDefinitionInfoList(CpuDefinitionInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_CpuDefinitionInfoList(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_CpuDefinitionInfoList(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_cpu_definitions(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    CpuDefinitionInfoList *retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_cpu_definitions(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_CpuDefinitionInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_CpuModelBaselineInfo(CpuModelBaselineInfo *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_CpuModelBaselineInfo(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_CpuModelBaselineInfo(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_cpu_model_baseline(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    CpuModelBaselineInfo *retval;
    Visitor *v;
    q_obj_query_cpu_model_baseline_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_query_cpu_model_baseline_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    retval = qmp_query_cpu_model_baseline(arg.modela, arg.modelb, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_CpuModelBaselineInfo(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_query_cpu_model_baseline_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

static void qmp_marshal_output_CpuModelCompareInfo(CpuModelCompareInfo *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_CpuModelCompareInfo(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_CpuModelCompareInfo(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_cpu_model_comparison(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    CpuModelCompareInfo *retval;
    Visitor *v;
    q_obj_query_cpu_model_comparison_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_query_cpu_model_comparison_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    retval = qmp_query_cpu_model_comparison(arg.modela, arg.modelb, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_CpuModelCompareInfo(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_query_cpu_model_comparison_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

static void qmp_marshal_output_CpuModelExpansionInfo(CpuModelExpansionInfo *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_CpuModelExpansionInfo(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_CpuModelExpansionInfo(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_cpu_model_expansion(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    CpuModelExpansionInfo *retval;
    Visitor *v;
    q_obj_query_cpu_model_expansion_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_query_cpu_model_expansion_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    retval = qmp_query_cpu_model_expansion(arg.type, arg.model, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_CpuModelExpansionInfo(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_query_cpu_model_expansion_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

static void qmp_marshal_output_CpuInfoList(CpuInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_CpuInfoList(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_CpuInfoList(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_cpus(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    CpuInfoList *retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_cpus(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_CpuInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_DumpQueryResult(DumpQueryResult *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_DumpQueryResult(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_DumpQueryResult(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_dump(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    DumpQueryResult *retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_dump(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_DumpQueryResult(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_DumpGuestMemoryCapability(DumpGuestMemoryCapability *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_DumpGuestMemoryCapability(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_DumpGuestMemoryCapability(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_dump_guest_memory_capability(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    DumpGuestMemoryCapability *retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_dump_guest_memory_capability(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_DumpGuestMemoryCapability(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_EventInfoList(EventInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_EventInfoList(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_EventInfoList(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_events(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    EventInfoList *retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_events(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_EventInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_FdsetInfoList(FdsetInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_FdsetInfoList(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_FdsetInfoList(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_fdsets(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    FdsetInfoList *retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_fdsets(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_FdsetInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_GICCapabilityList(GICCapabilityList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_GICCapabilityList(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_GICCapabilityList(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_gic_capabilities(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    GICCapabilityList *retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_gic_capabilities(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_GICCapabilityList(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_HotpluggableCPUList(HotpluggableCPUList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_HotpluggableCPUList(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_HotpluggableCPUList(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_hotpluggable_cpus(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    HotpluggableCPUList *retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_hotpluggable_cpus(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_HotpluggableCPUList(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_IOThreadInfoList(IOThreadInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_IOThreadInfoList(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_IOThreadInfoList(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_iothreads(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    IOThreadInfoList *retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_iothreads(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_IOThreadInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_KvmInfo(KvmInfo *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_KvmInfo(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_KvmInfo(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_kvm(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    KvmInfo *retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_kvm(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_KvmInfo(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_MachineInfoList(MachineInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_MachineInfoList(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_MachineInfoList(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_machines(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    MachineInfoList *retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_machines(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_MachineInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_MemdevList(MemdevList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_MemdevList(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_MemdevList(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_memdev(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    MemdevList *retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_memdev(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_MemdevList(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_MemoryDeviceInfoList(MemoryDeviceInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_MemoryDeviceInfoList(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_MemoryDeviceInfoList(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_memory_devices(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    MemoryDeviceInfoList *retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_memory_devices(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_MemoryDeviceInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_MouseInfoList(MouseInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_MouseInfoList(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_MouseInfoList(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_mice(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    MouseInfoList *retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_mice(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_MouseInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_MigrationInfo(MigrationInfo *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_MigrationInfo(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_MigrationInfo(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_migrate(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    MigrationInfo *retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_migrate(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_MigrationInfo(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_int(int64_t ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_int(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_int(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_migrate_cache_size(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    int64_t retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_migrate_cache_size(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_int(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_MigrationCapabilityStatusList(MigrationCapabilityStatusList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_MigrationCapabilityStatusList(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_MigrationCapabilityStatusList(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_migrate_capabilities(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    MigrationCapabilityStatusList *retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_migrate_capabilities(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_MigrationCapabilityStatusList(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_MigrationParameters(MigrationParameters *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_MigrationParameters(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_MigrationParameters(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_migrate_parameters(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    MigrationParameters *retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_migrate_parameters(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_MigrationParameters(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_NameInfo(NameInfo *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_NameInfo(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_NameInfo(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_name(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    NameInfo *retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_name(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_NameInfo(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_BlockDeviceInfoList(BlockDeviceInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_BlockDeviceInfoList(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_BlockDeviceInfoList(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_named_block_nodes(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    BlockDeviceInfoList *retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_named_block_nodes(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_BlockDeviceInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_PciInfoList(PciInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_PciInfoList(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_PciInfoList(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_pci(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    PciInfoList *retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_pci(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_PciInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_RockerSwitch(RockerSwitch *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_RockerSwitch(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_RockerSwitch(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_rocker(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    RockerSwitch *retval;
    Visitor *v;
    q_obj_query_rocker_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_query_rocker_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    retval = qmp_query_rocker(arg.name, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_RockerSwitch(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_query_rocker_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

static void qmp_marshal_output_RockerOfDpaFlowList(RockerOfDpaFlowList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_RockerOfDpaFlowList(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_RockerOfDpaFlowList(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_rocker_of_dpa_flows(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    RockerOfDpaFlowList *retval;
    Visitor *v;
    q_obj_query_rocker_of_dpa_flows_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_query_rocker_of_dpa_flows_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    retval = qmp_query_rocker_of_dpa_flows(arg.name, arg.has_tbl_id, arg.tbl_id, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_RockerOfDpaFlowList(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_query_rocker_of_dpa_flows_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

static void qmp_marshal_output_RockerOfDpaGroupList(RockerOfDpaGroupList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_RockerOfDpaGroupList(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_RockerOfDpaGroupList(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_rocker_of_dpa_groups(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    RockerOfDpaGroupList *retval;
    Visitor *v;
    q_obj_query_rocker_of_dpa_groups_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_query_rocker_of_dpa_groups_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    retval = qmp_query_rocker_of_dpa_groups(arg.name, arg.has_type, arg.type, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_RockerOfDpaGroupList(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_query_rocker_of_dpa_groups_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

static void qmp_marshal_output_RockerPortList(RockerPortList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_RockerPortList(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_RockerPortList(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_rocker_ports(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    RockerPortList *retval;
    Visitor *v;
    q_obj_query_rocker_ports_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_query_rocker_ports_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    retval = qmp_query_rocker_ports(arg.name, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_RockerPortList(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_query_rocker_ports_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

static void qmp_marshal_output_RxFilterInfoList(RxFilterInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_RxFilterInfoList(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_RxFilterInfoList(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_rx_filter(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    RxFilterInfoList *retval;
    Visitor *v;
    q_obj_query_rx_filter_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_query_rx_filter_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    retval = qmp_query_rx_filter(arg.has_name, arg.name, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_RxFilterInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_query_rx_filter_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

static void qmp_marshal_output_SpiceInfo(SpiceInfo *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_SpiceInfo(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_SpiceInfo(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_spice(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    SpiceInfo *retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_spice(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_SpiceInfo(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_StatusInfo(StatusInfo *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_StatusInfo(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_StatusInfo(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_status(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    StatusInfo *retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_status(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_StatusInfo(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_TargetInfo(TargetInfo *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_TargetInfo(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_TargetInfo(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_target(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    TargetInfo *retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_target(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_TargetInfo(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_TPMInfoList(TPMInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_TPMInfoList(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_TPMInfoList(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_tpm(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    TPMInfoList *retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_tpm(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_TPMInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_TpmModelList(TpmModelList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_TpmModelList(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_TpmModelList(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_tpm_models(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    TpmModelList *retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_tpm_models(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_TpmModelList(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_TpmTypeList(TpmTypeList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_TpmTypeList(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_TpmTypeList(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_tpm_types(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    TpmTypeList *retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_tpm_types(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_TpmTypeList(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_UuidInfo(UuidInfo *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_UuidInfo(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_UuidInfo(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_uuid(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    UuidInfo *retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_uuid(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_UuidInfo(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_VersionInfo(VersionInfo *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_VersionInfo(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_VersionInfo(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_version(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    VersionInfo *retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_version(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_VersionInfo(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_GuidInfo(GuidInfo *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_GuidInfo(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_GuidInfo(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_vm_generation_id(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    GuidInfo *retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_vm_generation_id(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_GuidInfo(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_VncInfo(VncInfo *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_VncInfo(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_VncInfo(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_vnc(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    VncInfo *retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_vnc(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_VncInfo(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_VncInfo2List(VncInfo2List *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_VncInfo2List(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_VncInfo2List(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_vnc_servers(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    VncInfo2List *retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_vnc_servers(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_VncInfo2List(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_ReplicationStatus(ReplicationStatus *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_ReplicationStatus(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_ReplicationStatus(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_query_xen_replication_status(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    ReplicationStatus *retval;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_xen_replication_status(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_ReplicationStatus(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

void qmp_marshal_quit(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    qmp_quit(&err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

void qmp_marshal_remove_fd(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_remove_fd_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_remove_fd_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_remove_fd(arg.fdset_id, arg.has_fd, arg.fd, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_remove_fd_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_ringbuf_read(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    char *retval;
    Visitor *v;
    q_obj_ringbuf_read_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_ringbuf_read_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    retval = qmp_ringbuf_read(arg.device, arg.size, arg.has_format, arg.format, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_str(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_ringbuf_read_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_ringbuf_write(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_ringbuf_write_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_ringbuf_write_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_ringbuf_write(arg.device, arg.data, arg.has_format, arg.format, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_ringbuf_write_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_rtc_reset_reinjection(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    qmp_rtc_reset_reinjection(&err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

void qmp_marshal_screendump(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_screendump_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_screendump_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_screendump(arg.filename, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_screendump_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_send_key(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_send_key_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_send_key_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_send_key(arg.keys, arg.has_hold_time, arg.hold_time, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_send_key_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_set_link(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_set_link_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_set_link_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_set_link(arg.name, arg.up, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_set_link_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_set_password(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_set_password_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_set_password_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_set_password(arg.protocol, arg.password, arg.has_connected, arg.connected, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_set_password_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_stop(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    qmp_stop(&err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

void qmp_marshal_system_powerdown(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    qmp_system_powerdown(&err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

void qmp_marshal_system_reset(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    qmp_system_reset(&err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

void qmp_marshal_system_wakeup(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    qmp_system_wakeup(&err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

static void qmp_marshal_output_TraceEventInfoList(TraceEventInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_TraceEventInfoList(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_TraceEventInfoList(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_trace_event_get_state(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    TraceEventInfoList *retval;
    Visitor *v;
    q_obj_trace_event_get_state_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_trace_event_get_state_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    retval = qmp_trace_event_get_state(arg.name, arg.has_vcpu, arg.vcpu, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_TraceEventInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_trace_event_get_state_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_trace_event_set_state(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_trace_event_set_state_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_trace_event_set_state_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_trace_event_set_state(arg.name, arg.enable, arg.has_ignore_unavailable, arg.ignore_unavailable, arg.has_vcpu, arg.vcpu, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_trace_event_set_state_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_transaction(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_transaction_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_transaction_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_transaction(arg.actions, arg.has_properties, arg.properties, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_transaction_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_x_blockdev_change(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_x_blockdev_change_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_x_blockdev_change_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_x_blockdev_change(arg.parent, arg.has_child, arg.child, arg.has_node, arg.node, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_x_blockdev_change_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_x_blockdev_insert_medium(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_x_blockdev_insert_medium_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_x_blockdev_insert_medium_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_x_blockdev_insert_medium(arg.has_device, arg.device, arg.has_id, arg.id, arg.node_name, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_x_blockdev_insert_medium_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_x_blockdev_remove_medium(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_x_blockdev_remove_medium_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_x_blockdev_remove_medium_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_x_blockdev_remove_medium(arg.has_device, arg.device, arg.has_id, arg.id, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_x_blockdev_remove_medium_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_x_colo_lost_heartbeat(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    qmp_x_colo_lost_heartbeat(&err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

void qmp_marshal_xen_colo_do_checkpoint(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v = NULL;

    if (args) {
        v = qobject_input_visitor_new(QOBJECT(args));
        visit_start_struct(v, NULL, NULL, 0, &err);
        if (err) {
            goto out;
        }
        
        if (!err) {
            visit_check_struct(v, &err);
        }
        visit_end_struct(v, NULL);
        if (err) {
            goto out;
        }
    }

    qmp_xen_colo_do_checkpoint(&err);

out:
    error_propagate(errp, err);
    visit_free(v);
    if (args) {
        v = qapi_dealloc_visitor_new();
        visit_start_struct(v, NULL, NULL, 0, NULL);
        
        visit_end_struct(v, NULL);
        visit_free(v);
    }
}

void qmp_marshal_xen_load_devices_state(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_xen_load_devices_state_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_xen_load_devices_state_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_xen_load_devices_state(arg.filename, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_xen_load_devices_state_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_xen_save_devices_state(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_xen_save_devices_state_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_xen_save_devices_state_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_xen_save_devices_state(arg.filename, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_xen_save_devices_state_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_xen_set_global_dirty_log(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_xen_set_global_dirty_log_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_xen_set_global_dirty_log_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_xen_set_global_dirty_log(arg.enable, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_xen_set_global_dirty_log_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_xen_set_replication(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_xen_set_replication_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_xen_set_replication_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_xen_set_replication(arg.enable, arg.primary, arg.has_failover, arg.failover, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_xen_set_replication_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_init_marshal(QmpCommandList *cmds)
{
    QTAILQ_INIT(cmds);

    qmp_register_command(cmds, "add-fd",
                         qmp_marshal_add_fd, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "add_client",
                         qmp_marshal_add_client, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "balloon",
                         qmp_marshal_balloon, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "block-commit",
                         qmp_marshal_block_commit, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "block-dirty-bitmap-add",
                         qmp_marshal_block_dirty_bitmap_add, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "block-dirty-bitmap-clear",
                         qmp_marshal_block_dirty_bitmap_clear, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "block-dirty-bitmap-remove",
                         qmp_marshal_block_dirty_bitmap_remove, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "block-job-cancel",
                         qmp_marshal_block_job_cancel, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "block-job-complete",
                         qmp_marshal_block_job_complete, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "block-job-pause",
                         qmp_marshal_block_job_pause, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "block-job-resume",
                         qmp_marshal_block_job_resume, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "block-job-set-speed",
                         qmp_marshal_block_job_set_speed, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "block-set-write-threshold",
                         qmp_marshal_block_set_write_threshold, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "block-stream",
                         qmp_marshal_block_stream, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "block_passwd",
                         qmp_marshal_block_passwd, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "block_resize",
                         qmp_marshal_block_resize, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "block_set_io_throttle",
                         qmp_marshal_block_set_io_throttle, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "blockdev-add",
                         qmp_marshal_blockdev_add, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "blockdev-backup",
                         qmp_marshal_blockdev_backup, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "blockdev-change-medium",
                         qmp_marshal_blockdev_change_medium, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "blockdev-close-tray",
                         qmp_marshal_blockdev_close_tray, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "blockdev-del",
                         qmp_marshal_blockdev_del, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "blockdev-mirror",
                         qmp_marshal_blockdev_mirror, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "blockdev-open-tray",
                         qmp_marshal_blockdev_open_tray, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "blockdev-snapshot",
                         qmp_marshal_blockdev_snapshot, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "blockdev-snapshot-delete-internal-sync",
                         qmp_marshal_blockdev_snapshot_delete_internal_sync, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "blockdev-snapshot-internal-sync",
                         qmp_marshal_blockdev_snapshot_internal_sync, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "blockdev-snapshot-sync",
                         qmp_marshal_blockdev_snapshot_sync, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "change",
                         qmp_marshal_change, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "change-backing-file",
                         qmp_marshal_change_backing_file, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "change-vnc-password",
                         qmp_marshal_change_vnc_password, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "chardev-add",
                         qmp_marshal_chardev_add, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "chardev-remove",
                         qmp_marshal_chardev_remove, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "client_migrate_info",
                         qmp_marshal_client_migrate_info, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "closefd",
                         qmp_marshal_closefd, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "cont",
                         qmp_marshal_cont, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "cpu",
                         qmp_marshal_cpu, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "cpu-add",
                         qmp_marshal_cpu_add, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "device-list-properties",
                         qmp_marshal_device_list_properties, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "device_del",
                         qmp_marshal_device_del, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "drive-backup",
                         qmp_marshal_drive_backup, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "drive-mirror",
                         qmp_marshal_drive_mirror, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "dump-guest-memory",
                         qmp_marshal_dump_guest_memory, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "dump-skeys",
                         qmp_marshal_dump_skeys, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "eject",
                         qmp_marshal_eject, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "expire_password",
                         qmp_marshal_expire_password, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "getfd",
                         qmp_marshal_getfd, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "human-monitor-command",
                         qmp_marshal_human_monitor_command, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "inject-nmi",
                         qmp_marshal_inject_nmi, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "input-send-event",
                         qmp_marshal_input_send_event, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "memsave",
                         qmp_marshal_memsave, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "migrate",
                         qmp_marshal_migrate, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "migrate-incoming",
                         qmp_marshal_migrate_incoming, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "migrate-set-cache-size",
                         qmp_marshal_migrate_set_cache_size, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "migrate-set-capabilities",
                         qmp_marshal_migrate_set_capabilities, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "migrate-set-parameters",
                         qmp_marshal_migrate_set_parameters, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "migrate-start-postcopy",
                         qmp_marshal_migrate_start_postcopy, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "migrate_cancel",
                         qmp_marshal_migrate_cancel, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "migrate_set_downtime",
                         qmp_marshal_migrate_set_downtime, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "migrate_set_speed",
                         qmp_marshal_migrate_set_speed, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "nbd-server-add",
                         qmp_marshal_nbd_server_add, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "nbd-server-start",
                         qmp_marshal_nbd_server_start, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "nbd-server-stop",
                         qmp_marshal_nbd_server_stop, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "netdev_del",
                         qmp_marshal_netdev_del, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "object-add",
                         qmp_marshal_object_add, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "object-del",
                         qmp_marshal_object_del, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "pmemsave",
                         qmp_marshal_pmemsave, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "qmp_capabilities",
                         qmp_marshal_qmp_capabilities, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "qom-get",
                         qmp_marshal_qom_get, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "qom-list",
                         qmp_marshal_qom_list, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "qom-list-types",
                         qmp_marshal_qom_list_types, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "qom-set",
                         qmp_marshal_qom_set, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-acpi-ospm-status",
                         qmp_marshal_query_acpi_ospm_status, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-balloon",
                         qmp_marshal_query_balloon, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-block",
                         qmp_marshal_query_block, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-block-jobs",
                         qmp_marshal_query_block_jobs, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-blockstats",
                         qmp_marshal_query_blockstats, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-chardev",
                         qmp_marshal_query_chardev, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-chardev-backends",
                         qmp_marshal_query_chardev_backends, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-command-line-options",
                         qmp_marshal_query_command_line_options, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-commands",
                         qmp_marshal_query_commands, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-cpu-definitions",
                         qmp_marshal_query_cpu_definitions, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-cpu-model-baseline",
                         qmp_marshal_query_cpu_model_baseline, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-cpu-model-comparison",
                         qmp_marshal_query_cpu_model_comparison, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-cpu-model-expansion",
                         qmp_marshal_query_cpu_model_expansion, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-cpus",
                         qmp_marshal_query_cpus, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-dump",
                         qmp_marshal_query_dump, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-dump-guest-memory-capability",
                         qmp_marshal_query_dump_guest_memory_capability, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-events",
                         qmp_marshal_query_events, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-fdsets",
                         qmp_marshal_query_fdsets, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-gic-capabilities",
                         qmp_marshal_query_gic_capabilities, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-hotpluggable-cpus",
                         qmp_marshal_query_hotpluggable_cpus, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-iothreads",
                         qmp_marshal_query_iothreads, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-kvm",
                         qmp_marshal_query_kvm, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-machines",
                         qmp_marshal_query_machines, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-memdev",
                         qmp_marshal_query_memdev, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-memory-devices",
                         qmp_marshal_query_memory_devices, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-mice",
                         qmp_marshal_query_mice, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-migrate",
                         qmp_marshal_query_migrate, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-migrate-cache-size",
                         qmp_marshal_query_migrate_cache_size, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-migrate-capabilities",
                         qmp_marshal_query_migrate_capabilities, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-migrate-parameters",
                         qmp_marshal_query_migrate_parameters, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-name",
                         qmp_marshal_query_name, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-named-block-nodes",
                         qmp_marshal_query_named_block_nodes, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-pci",
                         qmp_marshal_query_pci, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-rocker",
                         qmp_marshal_query_rocker, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-rocker-of-dpa-flows",
                         qmp_marshal_query_rocker_of_dpa_flows, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-rocker-of-dpa-groups",
                         qmp_marshal_query_rocker_of_dpa_groups, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-rocker-ports",
                         qmp_marshal_query_rocker_ports, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-rx-filter",
                         qmp_marshal_query_rx_filter, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-spice",
                         qmp_marshal_query_spice, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-status",
                         qmp_marshal_query_status, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-target",
                         qmp_marshal_query_target, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-tpm",
                         qmp_marshal_query_tpm, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-tpm-models",
                         qmp_marshal_query_tpm_models, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-tpm-types",
                         qmp_marshal_query_tpm_types, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-uuid",
                         qmp_marshal_query_uuid, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-version",
                         qmp_marshal_query_version, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-vm-generation-id",
                         qmp_marshal_query_vm_generation_id, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-vnc",
                         qmp_marshal_query_vnc, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-vnc-servers",
                         qmp_marshal_query_vnc_servers, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "query-xen-replication-status",
                         qmp_marshal_query_xen_replication_status, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "quit",
                         qmp_marshal_quit, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "remove-fd",
                         qmp_marshal_remove_fd, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "ringbuf-read",
                         qmp_marshal_ringbuf_read, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "ringbuf-write",
                         qmp_marshal_ringbuf_write, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "rtc-reset-reinjection",
                         qmp_marshal_rtc_reset_reinjection, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "screendump",
                         qmp_marshal_screendump, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "send-key",
                         qmp_marshal_send_key, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "set_link",
                         qmp_marshal_set_link, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "set_password",
                         qmp_marshal_set_password, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "stop",
                         qmp_marshal_stop, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "system_powerdown",
                         qmp_marshal_system_powerdown, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "system_reset",
                         qmp_marshal_system_reset, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "system_wakeup",
                         qmp_marshal_system_wakeup, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "trace-event-get-state",
                         qmp_marshal_trace_event_get_state, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "trace-event-set-state",
                         qmp_marshal_trace_event_set_state, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "transaction",
                         qmp_marshal_transaction, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "x-blockdev-change",
                         qmp_marshal_x_blockdev_change, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "x-blockdev-insert-medium",
                         qmp_marshal_x_blockdev_insert_medium, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "x-blockdev-remove-medium",
                         qmp_marshal_x_blockdev_remove_medium, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "x-colo-lost-heartbeat",
                         qmp_marshal_x_colo_lost_heartbeat, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "xen-colo-do-checkpoint",
                         qmp_marshal_xen_colo_do_checkpoint, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "xen-load-devices-state",
                         qmp_marshal_xen_load_devices_state, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "xen-save-devices-state",
                         qmp_marshal_xen_save_devices_state, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "xen-set-global-dirty-log",
                         qmp_marshal_xen_set_global_dirty_log, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "xen-set-replication",
                         qmp_marshal_xen_set_replication, QCO_NO_OPTIONS);
}
