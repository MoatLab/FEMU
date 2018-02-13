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

#ifndef QGA_QAPI_VISIT_H
#define QGA_QAPI_VISIT_H

#include "qapi/visitor.h"
#include "qapi/qmp/qerror.h"
#include "qga-qapi-types.h"


#ifndef QAPI_VISIT_BUILTIN
#define QAPI_VISIT_BUILTIN

void visit_type_QType(Visitor *v, const char *name, QType *obj, Error **errp);
void visit_type_anyList(Visitor *v, const char *name, anyList **obj, Error **errp);
void visit_type_boolList(Visitor *v, const char *name, boolList **obj, Error **errp);
void visit_type_int16List(Visitor *v, const char *name, int16List **obj, Error **errp);
void visit_type_int32List(Visitor *v, const char *name, int32List **obj, Error **errp);
void visit_type_int64List(Visitor *v, const char *name, int64List **obj, Error **errp);
void visit_type_int8List(Visitor *v, const char *name, int8List **obj, Error **errp);
void visit_type_intList(Visitor *v, const char *name, intList **obj, Error **errp);
void visit_type_numberList(Visitor *v, const char *name, numberList **obj, Error **errp);
void visit_type_sizeList(Visitor *v, const char *name, sizeList **obj, Error **errp);
void visit_type_strList(Visitor *v, const char *name, strList **obj, Error **errp);
void visit_type_uint16List(Visitor *v, const char *name, uint16List **obj, Error **errp);
void visit_type_uint32List(Visitor *v, const char *name, uint32List **obj, Error **errp);
void visit_type_uint64List(Visitor *v, const char *name, uint64List **obj, Error **errp);
void visit_type_uint8List(Visitor *v, const char *name, uint8List **obj, Error **errp);

#endif /* QAPI_VISIT_BUILTIN */


void visit_type_GuestAgentCommandInfo_members(Visitor *v, GuestAgentCommandInfo *obj, Error **errp);
void visit_type_GuestAgentCommandInfo(Visitor *v, const char *name, GuestAgentCommandInfo **obj, Error **errp);
void visit_type_GuestAgentCommandInfoList(Visitor *v, const char *name, GuestAgentCommandInfoList **obj, Error **errp);

void visit_type_GuestAgentInfo_members(Visitor *v, GuestAgentInfo *obj, Error **errp);
void visit_type_GuestAgentInfo(Visitor *v, const char *name, GuestAgentInfo **obj, Error **errp);

void visit_type_GuestDiskAddress_members(Visitor *v, GuestDiskAddress *obj, Error **errp);
void visit_type_GuestDiskAddress(Visitor *v, const char *name, GuestDiskAddress **obj, Error **errp);
void visit_type_GuestDiskAddressList(Visitor *v, const char *name, GuestDiskAddressList **obj, Error **errp);
void visit_type_GuestDiskBusType(Visitor *v, const char *name, GuestDiskBusType *obj, Error **errp);

void visit_type_GuestExec_members(Visitor *v, GuestExec *obj, Error **errp);
void visit_type_GuestExec(Visitor *v, const char *name, GuestExec **obj, Error **errp);

void visit_type_GuestExecStatus_members(Visitor *v, GuestExecStatus *obj, Error **errp);
void visit_type_GuestExecStatus(Visitor *v, const char *name, GuestExecStatus **obj, Error **errp);

void visit_type_GuestFileRead_members(Visitor *v, GuestFileRead *obj, Error **errp);
void visit_type_GuestFileRead(Visitor *v, const char *name, GuestFileRead **obj, Error **errp);

void visit_type_GuestFileSeek_members(Visitor *v, GuestFileSeek *obj, Error **errp);
void visit_type_GuestFileSeek(Visitor *v, const char *name, GuestFileSeek **obj, Error **errp);
void visit_type_GuestFileWhence(Visitor *v, const char *name, GuestFileWhence **obj, Error **errp);

void visit_type_GuestFileWrite_members(Visitor *v, GuestFileWrite *obj, Error **errp);
void visit_type_GuestFileWrite(Visitor *v, const char *name, GuestFileWrite **obj, Error **errp);

void visit_type_GuestFilesystemInfo_members(Visitor *v, GuestFilesystemInfo *obj, Error **errp);
void visit_type_GuestFilesystemInfo(Visitor *v, const char *name, GuestFilesystemInfo **obj, Error **errp);
void visit_type_GuestFilesystemInfoList(Visitor *v, const char *name, GuestFilesystemInfoList **obj, Error **errp);

void visit_type_GuestFilesystemTrimResponse_members(Visitor *v, GuestFilesystemTrimResponse *obj, Error **errp);
void visit_type_GuestFilesystemTrimResponse(Visitor *v, const char *name, GuestFilesystemTrimResponse **obj, Error **errp);

void visit_type_GuestFilesystemTrimResult_members(Visitor *v, GuestFilesystemTrimResult *obj, Error **errp);
void visit_type_GuestFilesystemTrimResult(Visitor *v, const char *name, GuestFilesystemTrimResult **obj, Error **errp);
void visit_type_GuestFilesystemTrimResultList(Visitor *v, const char *name, GuestFilesystemTrimResultList **obj, Error **errp);
void visit_type_GuestFsfreezeStatus(Visitor *v, const char *name, GuestFsfreezeStatus *obj, Error **errp);

void visit_type_GuestIpAddress_members(Visitor *v, GuestIpAddress *obj, Error **errp);
void visit_type_GuestIpAddress(Visitor *v, const char *name, GuestIpAddress **obj, Error **errp);
void visit_type_GuestIpAddressList(Visitor *v, const char *name, GuestIpAddressList **obj, Error **errp);
void visit_type_GuestIpAddressType(Visitor *v, const char *name, GuestIpAddressType *obj, Error **errp);

void visit_type_GuestLogicalProcessor_members(Visitor *v, GuestLogicalProcessor *obj, Error **errp);
void visit_type_GuestLogicalProcessor(Visitor *v, const char *name, GuestLogicalProcessor **obj, Error **errp);
void visit_type_GuestLogicalProcessorList(Visitor *v, const char *name, GuestLogicalProcessorList **obj, Error **errp);

void visit_type_GuestMemoryBlock_members(Visitor *v, GuestMemoryBlock *obj, Error **errp);
void visit_type_GuestMemoryBlock(Visitor *v, const char *name, GuestMemoryBlock **obj, Error **errp);

void visit_type_GuestMemoryBlockInfo_members(Visitor *v, GuestMemoryBlockInfo *obj, Error **errp);
void visit_type_GuestMemoryBlockInfo(Visitor *v, const char *name, GuestMemoryBlockInfo **obj, Error **errp);
void visit_type_GuestMemoryBlockList(Visitor *v, const char *name, GuestMemoryBlockList **obj, Error **errp);

void visit_type_GuestMemoryBlockResponse_members(Visitor *v, GuestMemoryBlockResponse *obj, Error **errp);
void visit_type_GuestMemoryBlockResponse(Visitor *v, const char *name, GuestMemoryBlockResponse **obj, Error **errp);
void visit_type_GuestMemoryBlockResponseList(Visitor *v, const char *name, GuestMemoryBlockResponseList **obj, Error **errp);
void visit_type_GuestMemoryBlockResponseType(Visitor *v, const char *name, GuestMemoryBlockResponseType *obj, Error **errp);

void visit_type_GuestNetworkInterface_members(Visitor *v, GuestNetworkInterface *obj, Error **errp);
void visit_type_GuestNetworkInterface(Visitor *v, const char *name, GuestNetworkInterface **obj, Error **errp);
void visit_type_GuestNetworkInterfaceList(Visitor *v, const char *name, GuestNetworkInterfaceList **obj, Error **errp);

void visit_type_GuestPCIAddress_members(Visitor *v, GuestPCIAddress *obj, Error **errp);
void visit_type_GuestPCIAddress(Visitor *v, const char *name, GuestPCIAddress **obj, Error **errp);
void visit_type_QGASeek(Visitor *v, const char *name, QGASeek *obj, Error **errp);

void visit_type_q_obj_guest_exec_arg_members(Visitor *v, q_obj_guest_exec_arg *obj, Error **errp);

void visit_type_q_obj_guest_exec_status_arg_members(Visitor *v, q_obj_guest_exec_status_arg *obj, Error **errp);

void visit_type_q_obj_guest_file_close_arg_members(Visitor *v, q_obj_guest_file_close_arg *obj, Error **errp);

void visit_type_q_obj_guest_file_flush_arg_members(Visitor *v, q_obj_guest_file_flush_arg *obj, Error **errp);

void visit_type_q_obj_guest_file_open_arg_members(Visitor *v, q_obj_guest_file_open_arg *obj, Error **errp);

void visit_type_q_obj_guest_file_read_arg_members(Visitor *v, q_obj_guest_file_read_arg *obj, Error **errp);

void visit_type_q_obj_guest_file_seek_arg_members(Visitor *v, q_obj_guest_file_seek_arg *obj, Error **errp);

void visit_type_q_obj_guest_file_write_arg_members(Visitor *v, q_obj_guest_file_write_arg *obj, Error **errp);

void visit_type_q_obj_guest_fsfreeze_freeze_list_arg_members(Visitor *v, q_obj_guest_fsfreeze_freeze_list_arg *obj, Error **errp);

void visit_type_q_obj_guest_fstrim_arg_members(Visitor *v, q_obj_guest_fstrim_arg *obj, Error **errp);

void visit_type_q_obj_guest_set_memory_blocks_arg_members(Visitor *v, q_obj_guest_set_memory_blocks_arg *obj, Error **errp);

void visit_type_q_obj_guest_set_time_arg_members(Visitor *v, q_obj_guest_set_time_arg *obj, Error **errp);

void visit_type_q_obj_guest_set_user_password_arg_members(Visitor *v, q_obj_guest_set_user_password_arg *obj, Error **errp);

void visit_type_q_obj_guest_set_vcpus_arg_members(Visitor *v, q_obj_guest_set_vcpus_arg *obj, Error **errp);

void visit_type_q_obj_guest_shutdown_arg_members(Visitor *v, q_obj_guest_shutdown_arg *obj, Error **errp);

void visit_type_q_obj_guest_sync_arg_members(Visitor *v, q_obj_guest_sync_arg *obj, Error **errp);

void visit_type_q_obj_guest_sync_delimited_arg_members(Visitor *v, q_obj_guest_sync_delimited_arg *obj, Error **errp);

#endif
