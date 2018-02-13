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

#ifndef TEST_QAPI_VISIT_H
#define TEST_QAPI_VISIT_H

#include "qapi/visitor.h"
#include "qapi/qmp/qerror.h"
#include "test-qapi-types.h"


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

void visit_type_AltIntNum(Visitor *v, const char *name, AltIntNum **obj, Error **errp);
void visit_type_AltNumInt(Visitor *v, const char *name, AltNumInt **obj, Error **errp);
void visit_type_AltNumStr(Visitor *v, const char *name, AltNumStr **obj, Error **errp);
void visit_type_AltStrBool(Visitor *v, const char *name, AltStrBool **obj, Error **errp);
void visit_type_AltStrInt(Visitor *v, const char *name, AltStrInt **obj, Error **errp);
void visit_type_AltStrNum(Visitor *v, const char *name, AltStrNum **obj, Error **errp);

void visit_type_Empty1_members(Visitor *v, Empty1 *obj, Error **errp);
void visit_type_Empty1(Visitor *v, const char *name, Empty1 **obj, Error **errp);

void visit_type_Empty2_members(Visitor *v, Empty2 *obj, Error **errp);
void visit_type_Empty2(Visitor *v, const char *name, Empty2 **obj, Error **errp);
void visit_type_EnumOne(Visitor *v, const char *name, EnumOne *obj, Error **errp);

void visit_type_EventStructOne_members(Visitor *v, EventStructOne *obj, Error **errp);
void visit_type_EventStructOne(Visitor *v, const char *name, EventStructOne **obj, Error **errp);

void visit_type_ForceArrays_members(Visitor *v, ForceArrays *obj, Error **errp);
void visit_type_ForceArrays(Visitor *v, const char *name, ForceArrays **obj, Error **errp);
void visit_type_MyEnum(Visitor *v, const char *name, MyEnum *obj, Error **errp);

void visit_type_NestedEnumsOne_members(Visitor *v, NestedEnumsOne *obj, Error **errp);
void visit_type_NestedEnumsOne(Visitor *v, const char *name, NestedEnumsOne **obj, Error **errp);
void visit_type_QEnumTwo(Visitor *v, const char *name, QEnumTwo *obj, Error **errp);

void visit_type_TestStruct_members(Visitor *v, TestStruct *obj, Error **errp);
void visit_type_TestStruct(Visitor *v, const char *name, TestStruct **obj, Error **errp);
void visit_type_TestStructList(Visitor *v, const char *name, TestStructList **obj, Error **errp);

void visit_type_UserDefA_members(Visitor *v, UserDefA *obj, Error **errp);
void visit_type_UserDefA(Visitor *v, const char *name, UserDefA **obj, Error **errp);
void visit_type_UserDefAlternate(Visitor *v, const char *name, UserDefAlternate **obj, Error **errp);

void visit_type_UserDefB_members(Visitor *v, UserDefB *obj, Error **errp);
void visit_type_UserDefB(Visitor *v, const char *name, UserDefB **obj, Error **errp);

void visit_type_UserDefC_members(Visitor *v, UserDefC *obj, Error **errp);
void visit_type_UserDefC(Visitor *v, const char *name, UserDefC **obj, Error **errp);

void visit_type_UserDefFlatUnion_members(Visitor *v, UserDefFlatUnion *obj, Error **errp);
void visit_type_UserDefFlatUnion(Visitor *v, const char *name, UserDefFlatUnion **obj, Error **errp);

void visit_type_UserDefFlatUnion2_members(Visitor *v, UserDefFlatUnion2 *obj, Error **errp);
void visit_type_UserDefFlatUnion2(Visitor *v, const char *name, UserDefFlatUnion2 **obj, Error **errp);

void visit_type_UserDefNativeListUnion_members(Visitor *v, UserDefNativeListUnion *obj, Error **errp);
void visit_type_UserDefNativeListUnion(Visitor *v, const char *name, UserDefNativeListUnion **obj, Error **errp);
void visit_type_UserDefNativeListUnionKind(Visitor *v, const char *name, UserDefNativeListUnionKind *obj, Error **errp);

void visit_type_UserDefOne_members(Visitor *v, UserDefOne *obj, Error **errp);
void visit_type_UserDefOne(Visitor *v, const char *name, UserDefOne **obj, Error **errp);
void visit_type_UserDefOneList(Visitor *v, const char *name, UserDefOneList **obj, Error **errp);

void visit_type_UserDefOptions_members(Visitor *v, UserDefOptions *obj, Error **errp);
void visit_type_UserDefOptions(Visitor *v, const char *name, UserDefOptions **obj, Error **errp);

void visit_type_UserDefTwo_members(Visitor *v, UserDefTwo *obj, Error **errp);
void visit_type_UserDefTwo(Visitor *v, const char *name, UserDefTwo **obj, Error **errp);

void visit_type_UserDefTwoDict_members(Visitor *v, UserDefTwoDict *obj, Error **errp);
void visit_type_UserDefTwoDict(Visitor *v, const char *name, UserDefTwoDict **obj, Error **errp);

void visit_type_UserDefTwoDictDict_members(Visitor *v, UserDefTwoDictDict *obj, Error **errp);
void visit_type_UserDefTwoDictDict(Visitor *v, const char *name, UserDefTwoDictDict **obj, Error **errp);
void visit_type_UserDefTwoList(Visitor *v, const char *name, UserDefTwoList **obj, Error **errp);

void visit_type_UserDefUnionBase_members(Visitor *v, UserDefUnionBase *obj, Error **errp);
void visit_type_UserDefUnionBase(Visitor *v, const char *name, UserDefUnionBase **obj, Error **errp);

void visit_type_UserDefZero_members(Visitor *v, UserDefZero *obj, Error **errp);
void visit_type_UserDefZero(Visitor *v, const char *name, UserDefZero **obj, Error **errp);

void visit_type_WrapAlternate_members(Visitor *v, WrapAlternate *obj, Error **errp);
void visit_type_WrapAlternate(Visitor *v, const char *name, WrapAlternate **obj, Error **errp);
void visit_type___org_qemu_x_Alt(Visitor *v, const char *name, __org_qemu_x_Alt **obj, Error **errp);

void visit_type___org_qemu_x_Base_members(Visitor *v, __org_qemu_x_Base *obj, Error **errp);
void visit_type___org_qemu_x_Base(Visitor *v, const char *name, __org_qemu_x_Base **obj, Error **errp);
void visit_type___org_qemu_x_Enum(Visitor *v, const char *name, __org_qemu_x_Enum *obj, Error **errp);
void visit_type___org_qemu_x_EnumList(Visitor *v, const char *name, __org_qemu_x_EnumList **obj, Error **errp);

void visit_type___org_qemu_x_Struct_members(Visitor *v, __org_qemu_x_Struct *obj, Error **errp);
void visit_type___org_qemu_x_Struct(Visitor *v, const char *name, __org_qemu_x_Struct **obj, Error **errp);

void visit_type___org_qemu_x_Struct2_members(Visitor *v, __org_qemu_x_Struct2 *obj, Error **errp);
void visit_type___org_qemu_x_Struct2(Visitor *v, const char *name, __org_qemu_x_Struct2 **obj, Error **errp);
void visit_type___org_qemu_x_StructList(Visitor *v, const char *name, __org_qemu_x_StructList **obj, Error **errp);

void visit_type___org_qemu_x_Union1_members(Visitor *v, __org_qemu_x_Union1 *obj, Error **errp);
void visit_type___org_qemu_x_Union1(Visitor *v, const char *name, __org_qemu_x_Union1 **obj, Error **errp);
void visit_type___org_qemu_x_Union1Kind(Visitor *v, const char *name, __org_qemu_x_Union1Kind *obj, Error **errp);
void visit_type___org_qemu_x_Union1List(Visitor *v, const char *name, __org_qemu_x_Union1List **obj, Error **errp);

void visit_type___org_qemu_x_Union2_members(Visitor *v, __org_qemu_x_Union2 *obj, Error **errp);
void visit_type___org_qemu_x_Union2(Visitor *v, const char *name, __org_qemu_x_Union2 **obj, Error **errp);

void visit_type_q_obj_EVENT_C_arg_members(Visitor *v, q_obj_EVENT_C_arg *obj, Error **errp);

void visit_type_q_obj_EVENT_D_arg_members(Visitor *v, q_obj_EVENT_D_arg *obj, Error **errp);

void visit_type_q_obj_UserDefFlatUnion2_base_members(Visitor *v, q_obj_UserDefFlatUnion2_base *obj, Error **errp);

void visit_type_q_obj___org_qemu_x_command_arg_members(Visitor *v, q_obj___org_qemu_x_command_arg *obj, Error **errp);

void visit_type_q_obj_anyList_wrapper_members(Visitor *v, q_obj_anyList_wrapper *obj, Error **errp);

void visit_type_q_obj_boolList_wrapper_members(Visitor *v, q_obj_boolList_wrapper *obj, Error **errp);

void visit_type_q_obj_guest_get_time_arg_members(Visitor *v, q_obj_guest_get_time_arg *obj, Error **errp);

void visit_type_q_obj_guest_sync_arg_members(Visitor *v, q_obj_guest_sync_arg *obj, Error **errp);

void visit_type_q_obj_int16List_wrapper_members(Visitor *v, q_obj_int16List_wrapper *obj, Error **errp);

void visit_type_q_obj_int32List_wrapper_members(Visitor *v, q_obj_int32List_wrapper *obj, Error **errp);

void visit_type_q_obj_int64List_wrapper_members(Visitor *v, q_obj_int64List_wrapper *obj, Error **errp);

void visit_type_q_obj_int8List_wrapper_members(Visitor *v, q_obj_int8List_wrapper *obj, Error **errp);

void visit_type_q_obj_intList_wrapper_members(Visitor *v, q_obj_intList_wrapper *obj, Error **errp);

void visit_type_q_obj_numberList_wrapper_members(Visitor *v, q_obj_numberList_wrapper *obj, Error **errp);

void visit_type_q_obj_sizeList_wrapper_members(Visitor *v, q_obj_sizeList_wrapper *obj, Error **errp);

void visit_type_q_obj_str_wrapper_members(Visitor *v, q_obj_str_wrapper *obj, Error **errp);

void visit_type_q_obj_strList_wrapper_members(Visitor *v, q_obj_strList_wrapper *obj, Error **errp);

void visit_type_q_obj_uint16List_wrapper_members(Visitor *v, q_obj_uint16List_wrapper *obj, Error **errp);

void visit_type_q_obj_uint32List_wrapper_members(Visitor *v, q_obj_uint32List_wrapper *obj, Error **errp);

void visit_type_q_obj_uint64List_wrapper_members(Visitor *v, q_obj_uint64List_wrapper *obj, Error **errp);

void visit_type_q_obj_uint8List_wrapper_members(Visitor *v, q_obj_uint8List_wrapper *obj, Error **errp);

void visit_type_q_obj_user_def_cmd1_arg_members(Visitor *v, q_obj_user_def_cmd1_arg *obj, Error **errp);

void visit_type_q_obj_user_def_cmd2_arg_members(Visitor *v, q_obj_user_def_cmd2_arg *obj, Error **errp);

#endif
