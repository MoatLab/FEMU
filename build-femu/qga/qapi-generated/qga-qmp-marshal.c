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
#include "qga-qapi-types.h"
#include "qga-qapi-visit.h"
#include "qga-qmp-commands.h"


static void qmp_marshal_output_GuestExec(GuestExec *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_GuestExec(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_GuestExec(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_guest_exec(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    GuestExec *retval;
    Visitor *v;
    q_obj_guest_exec_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_guest_exec_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    retval = qmp_guest_exec(arg.path, arg.has_arg, arg.arg, arg.has_env, arg.env, arg.has_input_data, arg.input_data, arg.has_capture_output, arg.capture_output, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_GuestExec(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_guest_exec_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

static void qmp_marshal_output_GuestExecStatus(GuestExecStatus *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_GuestExecStatus(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_GuestExecStatus(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_guest_exec_status(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    GuestExecStatus *retval;
    Visitor *v;
    q_obj_guest_exec_status_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_guest_exec_status_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    retval = qmp_guest_exec_status(arg.pid, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_GuestExecStatus(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_guest_exec_status_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_guest_file_close(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_guest_file_close_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_guest_file_close_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_guest_file_close(arg.handle, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_guest_file_close_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_guest_file_flush(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_guest_file_flush_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_guest_file_flush_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_guest_file_flush(arg.handle, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_guest_file_flush_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
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

void qmp_marshal_guest_file_open(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    int64_t retval;
    Visitor *v;
    q_obj_guest_file_open_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_guest_file_open_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    retval = qmp_guest_file_open(arg.path, arg.has_mode, arg.mode, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_int(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_guest_file_open_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

static void qmp_marshal_output_GuestFileRead(GuestFileRead *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_GuestFileRead(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_GuestFileRead(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_guest_file_read(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    GuestFileRead *retval;
    Visitor *v;
    q_obj_guest_file_read_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_guest_file_read_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    retval = qmp_guest_file_read(arg.handle, arg.has_count, arg.count, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_GuestFileRead(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_guest_file_read_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

static void qmp_marshal_output_GuestFileSeek(GuestFileSeek *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_GuestFileSeek(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_GuestFileSeek(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_guest_file_seek(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    GuestFileSeek *retval;
    Visitor *v;
    q_obj_guest_file_seek_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_guest_file_seek_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    retval = qmp_guest_file_seek(arg.handle, arg.offset, arg.whence, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_GuestFileSeek(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_guest_file_seek_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

static void qmp_marshal_output_GuestFileWrite(GuestFileWrite *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_GuestFileWrite(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_GuestFileWrite(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_guest_file_write(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    GuestFileWrite *retval;
    Visitor *v;
    q_obj_guest_file_write_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_guest_file_write_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    retval = qmp_guest_file_write(arg.handle, arg.buf_b64, arg.has_count, arg.count, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_GuestFileWrite(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_guest_file_write_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_guest_fsfreeze_freeze(QDict *args, QObject **ret, Error **errp)
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

    retval = qmp_guest_fsfreeze_freeze(&err);
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

void qmp_marshal_guest_fsfreeze_freeze_list(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    int64_t retval;
    Visitor *v;
    q_obj_guest_fsfreeze_freeze_list_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_guest_fsfreeze_freeze_list_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    retval = qmp_guest_fsfreeze_freeze_list(arg.has_mountpoints, arg.mountpoints, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_int(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_guest_fsfreeze_freeze_list_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

static void qmp_marshal_output_GuestFsfreezeStatus(GuestFsfreezeStatus ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_GuestFsfreezeStatus(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_GuestFsfreezeStatus(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_guest_fsfreeze_status(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    GuestFsfreezeStatus retval;
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

    retval = qmp_guest_fsfreeze_status(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_GuestFsfreezeStatus(retval, ret, &err);

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

void qmp_marshal_guest_fsfreeze_thaw(QDict *args, QObject **ret, Error **errp)
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

    retval = qmp_guest_fsfreeze_thaw(&err);
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

static void qmp_marshal_output_GuestFilesystemTrimResponse(GuestFilesystemTrimResponse *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_GuestFilesystemTrimResponse(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_GuestFilesystemTrimResponse(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_guest_fstrim(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    GuestFilesystemTrimResponse *retval;
    Visitor *v;
    q_obj_guest_fstrim_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_guest_fstrim_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    retval = qmp_guest_fstrim(arg.has_minimum, arg.minimum, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_GuestFilesystemTrimResponse(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_guest_fstrim_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

static void qmp_marshal_output_GuestFilesystemInfoList(GuestFilesystemInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_GuestFilesystemInfoList(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_GuestFilesystemInfoList(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_guest_get_fsinfo(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    GuestFilesystemInfoList *retval;
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

    retval = qmp_guest_get_fsinfo(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_GuestFilesystemInfoList(retval, ret, &err);

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

static void qmp_marshal_output_GuestMemoryBlockInfo(GuestMemoryBlockInfo *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_GuestMemoryBlockInfo(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_GuestMemoryBlockInfo(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_guest_get_memory_block_info(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    GuestMemoryBlockInfo *retval;
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

    retval = qmp_guest_get_memory_block_info(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_GuestMemoryBlockInfo(retval, ret, &err);

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

static void qmp_marshal_output_GuestMemoryBlockList(GuestMemoryBlockList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_GuestMemoryBlockList(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_GuestMemoryBlockList(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_guest_get_memory_blocks(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    GuestMemoryBlockList *retval;
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

    retval = qmp_guest_get_memory_blocks(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_GuestMemoryBlockList(retval, ret, &err);

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

void qmp_marshal_guest_get_time(QDict *args, QObject **ret, Error **errp)
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

    retval = qmp_guest_get_time(&err);
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

static void qmp_marshal_output_GuestLogicalProcessorList(GuestLogicalProcessorList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_GuestLogicalProcessorList(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_GuestLogicalProcessorList(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_guest_get_vcpus(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    GuestLogicalProcessorList *retval;
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

    retval = qmp_guest_get_vcpus(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_GuestLogicalProcessorList(retval, ret, &err);

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

static void qmp_marshal_output_GuestAgentInfo(GuestAgentInfo *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_GuestAgentInfo(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_GuestAgentInfo(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_guest_info(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    GuestAgentInfo *retval;
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

    retval = qmp_guest_info(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_GuestAgentInfo(retval, ret, &err);

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

static void qmp_marshal_output_GuestNetworkInterfaceList(GuestNetworkInterfaceList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_GuestNetworkInterfaceList(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_GuestNetworkInterfaceList(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_guest_network_get_interfaces(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    GuestNetworkInterfaceList *retval;
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

    retval = qmp_guest_network_get_interfaces(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_GuestNetworkInterfaceList(retval, ret, &err);

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

void qmp_marshal_guest_ping(QDict *args, QObject **ret, Error **errp)
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

    qmp_guest_ping(&err);

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

static void qmp_marshal_output_GuestMemoryBlockResponseList(GuestMemoryBlockResponseList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    visit_type_GuestMemoryBlockResponseList(v, "unused", &ret_in, &err);
    if (!err) {
        visit_complete(v, ret_out);
    }
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_GuestMemoryBlockResponseList(v, "unused", &ret_in, NULL);
    visit_free(v);
}

void qmp_marshal_guest_set_memory_blocks(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    GuestMemoryBlockResponseList *retval;
    Visitor *v;
    q_obj_guest_set_memory_blocks_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_guest_set_memory_blocks_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    retval = qmp_guest_set_memory_blocks(arg.mem_blks, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_GuestMemoryBlockResponseList(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_guest_set_memory_blocks_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_guest_set_time(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_guest_set_time_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_guest_set_time_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_guest_set_time(arg.has_time, arg.time, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_guest_set_time_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_guest_set_user_password(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_guest_set_user_password_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_guest_set_user_password_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_guest_set_user_password(arg.username, arg.password, arg.crypted, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_guest_set_user_password_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_guest_set_vcpus(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    int64_t retval;
    Visitor *v;
    q_obj_guest_set_vcpus_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_guest_set_vcpus_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    retval = qmp_guest_set_vcpus(arg.vcpus, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_int(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_guest_set_vcpus_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_guest_shutdown(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    Visitor *v;
    q_obj_guest_shutdown_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_guest_shutdown_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    qmp_guest_shutdown(arg.has_mode, arg.mode, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_guest_shutdown_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_guest_suspend_disk(QDict *args, QObject **ret, Error **errp)
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

    qmp_guest_suspend_disk(&err);

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

void qmp_marshal_guest_suspend_hybrid(QDict *args, QObject **ret, Error **errp)
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

    qmp_guest_suspend_hybrid(&err);

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

void qmp_marshal_guest_suspend_ram(QDict *args, QObject **ret, Error **errp)
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

    qmp_guest_suspend_ram(&err);

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

void qmp_marshal_guest_sync(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    int64_t retval;
    Visitor *v;
    q_obj_guest_sync_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_guest_sync_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    retval = qmp_guest_sync(arg.id, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_int(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_guest_sync_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qmp_marshal_guest_sync_delimited(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    int64_t retval;
    Visitor *v;
    q_obj_guest_sync_delimited_arg arg = {0};

    v = qobject_input_visitor_new(QOBJECT(args));
    visit_start_struct(v, NULL, NULL, 0, &err);
    if (err) {
        goto out;
    }
    visit_type_q_obj_guest_sync_delimited_arg_members(v, &arg, &err);
    if (!err) {
        visit_check_struct(v, &err);
    }
    visit_end_struct(v, NULL);
    if (err) {
        goto out;
    }

    retval = qmp_guest_sync_delimited(arg.id, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_int(retval, ret, &err);

out:
    error_propagate(errp, err);
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_q_obj_guest_sync_delimited_arg_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

void qga_qmp_init_marshal(QmpCommandList *cmds)
{
    QTAILQ_INIT(cmds);

    qmp_register_command(cmds, "guest-exec",
                         qmp_marshal_guest_exec, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "guest-exec-status",
                         qmp_marshal_guest_exec_status, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "guest-file-close",
                         qmp_marshal_guest_file_close, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "guest-file-flush",
                         qmp_marshal_guest_file_flush, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "guest-file-open",
                         qmp_marshal_guest_file_open, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "guest-file-read",
                         qmp_marshal_guest_file_read, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "guest-file-seek",
                         qmp_marshal_guest_file_seek, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "guest-file-write",
                         qmp_marshal_guest_file_write, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "guest-fsfreeze-freeze",
                         qmp_marshal_guest_fsfreeze_freeze, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "guest-fsfreeze-freeze-list",
                         qmp_marshal_guest_fsfreeze_freeze_list, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "guest-fsfreeze-status",
                         qmp_marshal_guest_fsfreeze_status, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "guest-fsfreeze-thaw",
                         qmp_marshal_guest_fsfreeze_thaw, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "guest-fstrim",
                         qmp_marshal_guest_fstrim, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "guest-get-fsinfo",
                         qmp_marshal_guest_get_fsinfo, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "guest-get-memory-block-info",
                         qmp_marshal_guest_get_memory_block_info, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "guest-get-memory-blocks",
                         qmp_marshal_guest_get_memory_blocks, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "guest-get-time",
                         qmp_marshal_guest_get_time, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "guest-get-vcpus",
                         qmp_marshal_guest_get_vcpus, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "guest-info",
                         qmp_marshal_guest_info, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "guest-network-get-interfaces",
                         qmp_marshal_guest_network_get_interfaces, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "guest-ping",
                         qmp_marshal_guest_ping, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "guest-set-memory-blocks",
                         qmp_marshal_guest_set_memory_blocks, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "guest-set-time",
                         qmp_marshal_guest_set_time, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "guest-set-user-password",
                         qmp_marshal_guest_set_user_password, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "guest-set-vcpus",
                         qmp_marshal_guest_set_vcpus, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "guest-shutdown",
                         qmp_marshal_guest_shutdown, QCO_NO_SUCCESS_RESP);
    qmp_register_command(cmds, "guest-suspend-disk",
                         qmp_marshal_guest_suspend_disk, QCO_NO_SUCCESS_RESP);
    qmp_register_command(cmds, "guest-suspend-hybrid",
                         qmp_marshal_guest_suspend_hybrid, QCO_NO_SUCCESS_RESP);
    qmp_register_command(cmds, "guest-suspend-ram",
                         qmp_marshal_guest_suspend_ram, QCO_NO_SUCCESS_RESP);
    qmp_register_command(cmds, "guest-sync",
                         qmp_marshal_guest_sync, QCO_NO_OPTIONS);
    qmp_register_command(cmds, "guest-sync-delimited",
                         qmp_marshal_guest_sync_delimited, QCO_NO_OPTIONS);
}
