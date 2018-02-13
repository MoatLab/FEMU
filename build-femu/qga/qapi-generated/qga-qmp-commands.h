/* AUTOMATICALLY GENERATED, DO NOT MODIFY */

/*
 * schema-defined QAPI function prototypes
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

#ifndef QGA_QMP_COMMANDS_H
#define QGA_QMP_COMMANDS_H

#include "qga-qapi-types.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/dispatch.h"
#include "qapi/error.h"

void qga_qmp_init_marshal(QmpCommandList *cmds);
GuestExec *qmp_guest_exec(const char *path, bool has_arg, strList *arg, bool has_env, strList *env, bool has_input_data, const char *input_data, bool has_capture_output, bool capture_output, Error **errp);
void qmp_marshal_guest_exec(QDict *args, QObject **ret, Error **errp);
GuestExecStatus *qmp_guest_exec_status(int64_t pid, Error **errp);
void qmp_marshal_guest_exec_status(QDict *args, QObject **ret, Error **errp);
void qmp_guest_file_close(int64_t handle, Error **errp);
void qmp_marshal_guest_file_close(QDict *args, QObject **ret, Error **errp);
void qmp_guest_file_flush(int64_t handle, Error **errp);
void qmp_marshal_guest_file_flush(QDict *args, QObject **ret, Error **errp);
int64_t qmp_guest_file_open(const char *path, bool has_mode, const char *mode, Error **errp);
void qmp_marshal_guest_file_open(QDict *args, QObject **ret, Error **errp);
GuestFileRead *qmp_guest_file_read(int64_t handle, bool has_count, int64_t count, Error **errp);
void qmp_marshal_guest_file_read(QDict *args, QObject **ret, Error **errp);
GuestFileSeek *qmp_guest_file_seek(int64_t handle, int64_t offset, GuestFileWhence *whence, Error **errp);
void qmp_marshal_guest_file_seek(QDict *args, QObject **ret, Error **errp);
GuestFileWrite *qmp_guest_file_write(int64_t handle, const char *buf_b64, bool has_count, int64_t count, Error **errp);
void qmp_marshal_guest_file_write(QDict *args, QObject **ret, Error **errp);
int64_t qmp_guest_fsfreeze_freeze(Error **errp);
void qmp_marshal_guest_fsfreeze_freeze(QDict *args, QObject **ret, Error **errp);
int64_t qmp_guest_fsfreeze_freeze_list(bool has_mountpoints, strList *mountpoints, Error **errp);
void qmp_marshal_guest_fsfreeze_freeze_list(QDict *args, QObject **ret, Error **errp);
GuestFsfreezeStatus qmp_guest_fsfreeze_status(Error **errp);
void qmp_marshal_guest_fsfreeze_status(QDict *args, QObject **ret, Error **errp);
int64_t qmp_guest_fsfreeze_thaw(Error **errp);
void qmp_marshal_guest_fsfreeze_thaw(QDict *args, QObject **ret, Error **errp);
GuestFilesystemTrimResponse *qmp_guest_fstrim(bool has_minimum, int64_t minimum, Error **errp);
void qmp_marshal_guest_fstrim(QDict *args, QObject **ret, Error **errp);
GuestFilesystemInfoList *qmp_guest_get_fsinfo(Error **errp);
void qmp_marshal_guest_get_fsinfo(QDict *args, QObject **ret, Error **errp);
GuestMemoryBlockInfo *qmp_guest_get_memory_block_info(Error **errp);
void qmp_marshal_guest_get_memory_block_info(QDict *args, QObject **ret, Error **errp);
GuestMemoryBlockList *qmp_guest_get_memory_blocks(Error **errp);
void qmp_marshal_guest_get_memory_blocks(QDict *args, QObject **ret, Error **errp);
int64_t qmp_guest_get_time(Error **errp);
void qmp_marshal_guest_get_time(QDict *args, QObject **ret, Error **errp);
GuestLogicalProcessorList *qmp_guest_get_vcpus(Error **errp);
void qmp_marshal_guest_get_vcpus(QDict *args, QObject **ret, Error **errp);
GuestAgentInfo *qmp_guest_info(Error **errp);
void qmp_marshal_guest_info(QDict *args, QObject **ret, Error **errp);
GuestNetworkInterfaceList *qmp_guest_network_get_interfaces(Error **errp);
void qmp_marshal_guest_network_get_interfaces(QDict *args, QObject **ret, Error **errp);
void qmp_guest_ping(Error **errp);
void qmp_marshal_guest_ping(QDict *args, QObject **ret, Error **errp);
GuestMemoryBlockResponseList *qmp_guest_set_memory_blocks(GuestMemoryBlockList *mem_blks, Error **errp);
void qmp_marshal_guest_set_memory_blocks(QDict *args, QObject **ret, Error **errp);
void qmp_guest_set_time(bool has_time, int64_t time, Error **errp);
void qmp_marshal_guest_set_time(QDict *args, QObject **ret, Error **errp);
void qmp_guest_set_user_password(const char *username, const char *password, bool crypted, Error **errp);
void qmp_marshal_guest_set_user_password(QDict *args, QObject **ret, Error **errp);
int64_t qmp_guest_set_vcpus(GuestLogicalProcessorList *vcpus, Error **errp);
void qmp_marshal_guest_set_vcpus(QDict *args, QObject **ret, Error **errp);
void qmp_guest_shutdown(bool has_mode, const char *mode, Error **errp);
void qmp_marshal_guest_shutdown(QDict *args, QObject **ret, Error **errp);
void qmp_guest_suspend_disk(Error **errp);
void qmp_marshal_guest_suspend_disk(QDict *args, QObject **ret, Error **errp);
void qmp_guest_suspend_hybrid(Error **errp);
void qmp_marshal_guest_suspend_hybrid(QDict *args, QObject **ret, Error **errp);
void qmp_guest_suspend_ram(Error **errp);
void qmp_marshal_guest_suspend_ram(QDict *args, QObject **ret, Error **errp);
int64_t qmp_guest_sync(int64_t id, Error **errp);
void qmp_marshal_guest_sync(QDict *args, QObject **ret, Error **errp);
int64_t qmp_guest_sync_delimited(int64_t id, Error **errp);
void qmp_marshal_guest_sync_delimited(QDict *args, QObject **ret, Error **errp);

#endif
