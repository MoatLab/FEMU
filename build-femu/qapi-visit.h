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

#ifndef QAPI_VISIT_H
#define QAPI_VISIT_H

#include "qapi/visitor.h"
#include "qapi/qmp/qerror.h"
#include "qapi-types.h"


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


void visit_type_ACPIOSTInfo_members(Visitor *v, ACPIOSTInfo *obj, Error **errp);
void visit_type_ACPIOSTInfo(Visitor *v, const char *name, ACPIOSTInfo **obj, Error **errp);
void visit_type_ACPIOSTInfoList(Visitor *v, const char *name, ACPIOSTInfoList **obj, Error **errp);
void visit_type_ACPISlotType(Visitor *v, const char *name, ACPISlotType *obj, Error **errp);

void visit_type_Abort_members(Visitor *v, Abort *obj, Error **errp);
void visit_type_Abort(Visitor *v, const char *name, Abort **obj, Error **errp);

void visit_type_AcpiTableOptions_members(Visitor *v, AcpiTableOptions *obj, Error **errp);
void visit_type_AcpiTableOptions(Visitor *v, const char *name, AcpiTableOptions **obj, Error **errp);
void visit_type_ActionCompletionMode(Visitor *v, const char *name, ActionCompletionMode *obj, Error **errp);

void visit_type_AddfdInfo_members(Visitor *v, AddfdInfo *obj, Error **errp);
void visit_type_AddfdInfo(Visitor *v, const char *name, AddfdInfo **obj, Error **errp);

void visit_type_BalloonInfo_members(Visitor *v, BalloonInfo *obj, Error **errp);
void visit_type_BalloonInfo(Visitor *v, const char *name, BalloonInfo **obj, Error **errp);
void visit_type_BiosAtaTranslation(Visitor *v, const char *name, BiosAtaTranslation *obj, Error **errp);
void visit_type_BlkdebugEvent(Visitor *v, const char *name, BlkdebugEvent *obj, Error **errp);

void visit_type_BlkdebugInjectErrorOptions_members(Visitor *v, BlkdebugInjectErrorOptions *obj, Error **errp);
void visit_type_BlkdebugInjectErrorOptions(Visitor *v, const char *name, BlkdebugInjectErrorOptions **obj, Error **errp);
void visit_type_BlkdebugInjectErrorOptionsList(Visitor *v, const char *name, BlkdebugInjectErrorOptionsList **obj, Error **errp);

void visit_type_BlkdebugSetStateOptions_members(Visitor *v, BlkdebugSetStateOptions *obj, Error **errp);
void visit_type_BlkdebugSetStateOptions(Visitor *v, const char *name, BlkdebugSetStateOptions **obj, Error **errp);
void visit_type_BlkdebugSetStateOptionsList(Visitor *v, const char *name, BlkdebugSetStateOptionsList **obj, Error **errp);

void visit_type_BlockDeviceInfo_members(Visitor *v, BlockDeviceInfo *obj, Error **errp);
void visit_type_BlockDeviceInfo(Visitor *v, const char *name, BlockDeviceInfo **obj, Error **errp);
void visit_type_BlockDeviceInfoList(Visitor *v, const char *name, BlockDeviceInfoList **obj, Error **errp);
void visit_type_BlockDeviceIoStatus(Visitor *v, const char *name, BlockDeviceIoStatus *obj, Error **errp);

void visit_type_BlockDeviceMapEntry_members(Visitor *v, BlockDeviceMapEntry *obj, Error **errp);
void visit_type_BlockDeviceMapEntry(Visitor *v, const char *name, BlockDeviceMapEntry **obj, Error **errp);

void visit_type_BlockDeviceStats_members(Visitor *v, BlockDeviceStats *obj, Error **errp);
void visit_type_BlockDeviceStats(Visitor *v, const char *name, BlockDeviceStats **obj, Error **errp);

void visit_type_BlockDeviceTimedStats_members(Visitor *v, BlockDeviceTimedStats *obj, Error **errp);
void visit_type_BlockDeviceTimedStats(Visitor *v, const char *name, BlockDeviceTimedStats **obj, Error **errp);
void visit_type_BlockDeviceTimedStatsList(Visitor *v, const char *name, BlockDeviceTimedStatsList **obj, Error **errp);

void visit_type_BlockDirtyBitmap_members(Visitor *v, BlockDirtyBitmap *obj, Error **errp);
void visit_type_BlockDirtyBitmap(Visitor *v, const char *name, BlockDirtyBitmap **obj, Error **errp);

void visit_type_BlockDirtyBitmapAdd_members(Visitor *v, BlockDirtyBitmapAdd *obj, Error **errp);
void visit_type_BlockDirtyBitmapAdd(Visitor *v, const char *name, BlockDirtyBitmapAdd **obj, Error **errp);

void visit_type_BlockDirtyInfo_members(Visitor *v, BlockDirtyInfo *obj, Error **errp);
void visit_type_BlockDirtyInfo(Visitor *v, const char *name, BlockDirtyInfo **obj, Error **errp);
void visit_type_BlockDirtyInfoList(Visitor *v, const char *name, BlockDirtyInfoList **obj, Error **errp);
void visit_type_BlockErrorAction(Visitor *v, const char *name, BlockErrorAction *obj, Error **errp);

void visit_type_BlockIOThrottle_members(Visitor *v, BlockIOThrottle *obj, Error **errp);
void visit_type_BlockIOThrottle(Visitor *v, const char *name, BlockIOThrottle **obj, Error **errp);

void visit_type_BlockInfo_members(Visitor *v, BlockInfo *obj, Error **errp);
void visit_type_BlockInfo(Visitor *v, const char *name, BlockInfo **obj, Error **errp);
void visit_type_BlockInfoList(Visitor *v, const char *name, BlockInfoList **obj, Error **errp);

void visit_type_BlockJobInfo_members(Visitor *v, BlockJobInfo *obj, Error **errp);
void visit_type_BlockJobInfo(Visitor *v, const char *name, BlockJobInfo **obj, Error **errp);
void visit_type_BlockJobInfoList(Visitor *v, const char *name, BlockJobInfoList **obj, Error **errp);
void visit_type_BlockJobType(Visitor *v, const char *name, BlockJobType *obj, Error **errp);

void visit_type_BlockStats_members(Visitor *v, BlockStats *obj, Error **errp);
void visit_type_BlockStats(Visitor *v, const char *name, BlockStats **obj, Error **errp);
void visit_type_BlockStatsList(Visitor *v, const char *name, BlockStatsList **obj, Error **errp);
void visit_type_BlockdevAioOptions(Visitor *v, const char *name, BlockdevAioOptions *obj, Error **errp);

void visit_type_BlockdevBackup_members(Visitor *v, BlockdevBackup *obj, Error **errp);
void visit_type_BlockdevBackup(Visitor *v, const char *name, BlockdevBackup **obj, Error **errp);

void visit_type_BlockdevCacheInfo_members(Visitor *v, BlockdevCacheInfo *obj, Error **errp);
void visit_type_BlockdevCacheInfo(Visitor *v, const char *name, BlockdevCacheInfo **obj, Error **errp);

void visit_type_BlockdevCacheOptions_members(Visitor *v, BlockdevCacheOptions *obj, Error **errp);
void visit_type_BlockdevCacheOptions(Visitor *v, const char *name, BlockdevCacheOptions **obj, Error **errp);
void visit_type_BlockdevChangeReadOnlyMode(Visitor *v, const char *name, BlockdevChangeReadOnlyMode *obj, Error **errp);
void visit_type_BlockdevDetectZeroesOptions(Visitor *v, const char *name, BlockdevDetectZeroesOptions *obj, Error **errp);
void visit_type_BlockdevDiscardOptions(Visitor *v, const char *name, BlockdevDiscardOptions *obj, Error **errp);
void visit_type_BlockdevDriver(Visitor *v, const char *name, BlockdevDriver *obj, Error **errp);
void visit_type_BlockdevOnError(Visitor *v, const char *name, BlockdevOnError *obj, Error **errp);

void visit_type_BlockdevOptions_members(Visitor *v, BlockdevOptions *obj, Error **errp);
void visit_type_BlockdevOptions(Visitor *v, const char *name, BlockdevOptions **obj, Error **errp);

void visit_type_BlockdevOptionsBlkdebug_members(Visitor *v, BlockdevOptionsBlkdebug *obj, Error **errp);
void visit_type_BlockdevOptionsBlkdebug(Visitor *v, const char *name, BlockdevOptionsBlkdebug **obj, Error **errp);

void visit_type_BlockdevOptionsBlkverify_members(Visitor *v, BlockdevOptionsBlkverify *obj, Error **errp);
void visit_type_BlockdevOptionsBlkverify(Visitor *v, const char *name, BlockdevOptionsBlkverify **obj, Error **errp);

void visit_type_BlockdevOptionsCurlBase_members(Visitor *v, BlockdevOptionsCurlBase *obj, Error **errp);
void visit_type_BlockdevOptionsCurlBase(Visitor *v, const char *name, BlockdevOptionsCurlBase **obj, Error **errp);

void visit_type_BlockdevOptionsCurlFtp_members(Visitor *v, BlockdevOptionsCurlFtp *obj, Error **errp);
void visit_type_BlockdevOptionsCurlFtp(Visitor *v, const char *name, BlockdevOptionsCurlFtp **obj, Error **errp);

void visit_type_BlockdevOptionsCurlFtps_members(Visitor *v, BlockdevOptionsCurlFtps *obj, Error **errp);
void visit_type_BlockdevOptionsCurlFtps(Visitor *v, const char *name, BlockdevOptionsCurlFtps **obj, Error **errp);

void visit_type_BlockdevOptionsCurlHttp_members(Visitor *v, BlockdevOptionsCurlHttp *obj, Error **errp);
void visit_type_BlockdevOptionsCurlHttp(Visitor *v, const char *name, BlockdevOptionsCurlHttp **obj, Error **errp);

void visit_type_BlockdevOptionsCurlHttps_members(Visitor *v, BlockdevOptionsCurlHttps *obj, Error **errp);
void visit_type_BlockdevOptionsCurlHttps(Visitor *v, const char *name, BlockdevOptionsCurlHttps **obj, Error **errp);

void visit_type_BlockdevOptionsFile_members(Visitor *v, BlockdevOptionsFile *obj, Error **errp);
void visit_type_BlockdevOptionsFile(Visitor *v, const char *name, BlockdevOptionsFile **obj, Error **errp);

void visit_type_BlockdevOptionsGenericCOWFormat_members(Visitor *v, BlockdevOptionsGenericCOWFormat *obj, Error **errp);
void visit_type_BlockdevOptionsGenericCOWFormat(Visitor *v, const char *name, BlockdevOptionsGenericCOWFormat **obj, Error **errp);

void visit_type_BlockdevOptionsGenericFormat_members(Visitor *v, BlockdevOptionsGenericFormat *obj, Error **errp);
void visit_type_BlockdevOptionsGenericFormat(Visitor *v, const char *name, BlockdevOptionsGenericFormat **obj, Error **errp);

void visit_type_BlockdevOptionsGluster_members(Visitor *v, BlockdevOptionsGluster *obj, Error **errp);
void visit_type_BlockdevOptionsGluster(Visitor *v, const char *name, BlockdevOptionsGluster **obj, Error **errp);

void visit_type_BlockdevOptionsIscsi_members(Visitor *v, BlockdevOptionsIscsi *obj, Error **errp);
void visit_type_BlockdevOptionsIscsi(Visitor *v, const char *name, BlockdevOptionsIscsi **obj, Error **errp);

void visit_type_BlockdevOptionsLUKS_members(Visitor *v, BlockdevOptionsLUKS *obj, Error **errp);
void visit_type_BlockdevOptionsLUKS(Visitor *v, const char *name, BlockdevOptionsLUKS **obj, Error **errp);

void visit_type_BlockdevOptionsNbd_members(Visitor *v, BlockdevOptionsNbd *obj, Error **errp);
void visit_type_BlockdevOptionsNbd(Visitor *v, const char *name, BlockdevOptionsNbd **obj, Error **errp);

void visit_type_BlockdevOptionsNfs_members(Visitor *v, BlockdevOptionsNfs *obj, Error **errp);
void visit_type_BlockdevOptionsNfs(Visitor *v, const char *name, BlockdevOptionsNfs **obj, Error **errp);

void visit_type_BlockdevOptionsNull_members(Visitor *v, BlockdevOptionsNull *obj, Error **errp);
void visit_type_BlockdevOptionsNull(Visitor *v, const char *name, BlockdevOptionsNull **obj, Error **errp);

void visit_type_BlockdevOptionsQcow2_members(Visitor *v, BlockdevOptionsQcow2 *obj, Error **errp);
void visit_type_BlockdevOptionsQcow2(Visitor *v, const char *name, BlockdevOptionsQcow2 **obj, Error **errp);

void visit_type_BlockdevOptionsQuorum_members(Visitor *v, BlockdevOptionsQuorum *obj, Error **errp);
void visit_type_BlockdevOptionsQuorum(Visitor *v, const char *name, BlockdevOptionsQuorum **obj, Error **errp);

void visit_type_BlockdevOptionsRaw_members(Visitor *v, BlockdevOptionsRaw *obj, Error **errp);
void visit_type_BlockdevOptionsRaw(Visitor *v, const char *name, BlockdevOptionsRaw **obj, Error **errp);

void visit_type_BlockdevOptionsRbd_members(Visitor *v, BlockdevOptionsRbd *obj, Error **errp);
void visit_type_BlockdevOptionsRbd(Visitor *v, const char *name, BlockdevOptionsRbd **obj, Error **errp);

void visit_type_BlockdevOptionsReplication_members(Visitor *v, BlockdevOptionsReplication *obj, Error **errp);
void visit_type_BlockdevOptionsReplication(Visitor *v, const char *name, BlockdevOptionsReplication **obj, Error **errp);

void visit_type_BlockdevOptionsSheepdog_members(Visitor *v, BlockdevOptionsSheepdog *obj, Error **errp);
void visit_type_BlockdevOptionsSheepdog(Visitor *v, const char *name, BlockdevOptionsSheepdog **obj, Error **errp);

void visit_type_BlockdevOptionsSsh_members(Visitor *v, BlockdevOptionsSsh *obj, Error **errp);
void visit_type_BlockdevOptionsSsh(Visitor *v, const char *name, BlockdevOptionsSsh **obj, Error **errp);

void visit_type_BlockdevOptionsVVFAT_members(Visitor *v, BlockdevOptionsVVFAT *obj, Error **errp);
void visit_type_BlockdevOptionsVVFAT(Visitor *v, const char *name, BlockdevOptionsVVFAT **obj, Error **errp);
void visit_type_BlockdevRef(Visitor *v, const char *name, BlockdevRef **obj, Error **errp);
void visit_type_BlockdevRefList(Visitor *v, const char *name, BlockdevRefList **obj, Error **errp);

void visit_type_BlockdevSnapshot_members(Visitor *v, BlockdevSnapshot *obj, Error **errp);
void visit_type_BlockdevSnapshot(Visitor *v, const char *name, BlockdevSnapshot **obj, Error **errp);

void visit_type_BlockdevSnapshotInternal_members(Visitor *v, BlockdevSnapshotInternal *obj, Error **errp);
void visit_type_BlockdevSnapshotInternal(Visitor *v, const char *name, BlockdevSnapshotInternal **obj, Error **errp);

void visit_type_BlockdevSnapshotSync_members(Visitor *v, BlockdevSnapshotSync *obj, Error **errp);
void visit_type_BlockdevSnapshotSync(Visitor *v, const char *name, BlockdevSnapshotSync **obj, Error **errp);
void visit_type_COLOMessage(Visitor *v, const char *name, COLOMessage *obj, Error **errp);
void visit_type_COLOMode(Visitor *v, const char *name, COLOMode *obj, Error **errp);

void visit_type_ChardevBackend_members(Visitor *v, ChardevBackend *obj, Error **errp);
void visit_type_ChardevBackend(Visitor *v, const char *name, ChardevBackend **obj, Error **errp);

void visit_type_ChardevBackendInfo_members(Visitor *v, ChardevBackendInfo *obj, Error **errp);
void visit_type_ChardevBackendInfo(Visitor *v, const char *name, ChardevBackendInfo **obj, Error **errp);
void visit_type_ChardevBackendInfoList(Visitor *v, const char *name, ChardevBackendInfoList **obj, Error **errp);
void visit_type_ChardevBackendKind(Visitor *v, const char *name, ChardevBackendKind *obj, Error **errp);

void visit_type_ChardevCommon_members(Visitor *v, ChardevCommon *obj, Error **errp);
void visit_type_ChardevCommon(Visitor *v, const char *name, ChardevCommon **obj, Error **errp);

void visit_type_ChardevFile_members(Visitor *v, ChardevFile *obj, Error **errp);
void visit_type_ChardevFile(Visitor *v, const char *name, ChardevFile **obj, Error **errp);

void visit_type_ChardevHostdev_members(Visitor *v, ChardevHostdev *obj, Error **errp);
void visit_type_ChardevHostdev(Visitor *v, const char *name, ChardevHostdev **obj, Error **errp);

void visit_type_ChardevInfo_members(Visitor *v, ChardevInfo *obj, Error **errp);
void visit_type_ChardevInfo(Visitor *v, const char *name, ChardevInfo **obj, Error **errp);
void visit_type_ChardevInfoList(Visitor *v, const char *name, ChardevInfoList **obj, Error **errp);

void visit_type_ChardevMux_members(Visitor *v, ChardevMux *obj, Error **errp);
void visit_type_ChardevMux(Visitor *v, const char *name, ChardevMux **obj, Error **errp);

void visit_type_ChardevReturn_members(Visitor *v, ChardevReturn *obj, Error **errp);
void visit_type_ChardevReturn(Visitor *v, const char *name, ChardevReturn **obj, Error **errp);

void visit_type_ChardevRingbuf_members(Visitor *v, ChardevRingbuf *obj, Error **errp);
void visit_type_ChardevRingbuf(Visitor *v, const char *name, ChardevRingbuf **obj, Error **errp);

void visit_type_ChardevSocket_members(Visitor *v, ChardevSocket *obj, Error **errp);
void visit_type_ChardevSocket(Visitor *v, const char *name, ChardevSocket **obj, Error **errp);

void visit_type_ChardevSpiceChannel_members(Visitor *v, ChardevSpiceChannel *obj, Error **errp);
void visit_type_ChardevSpiceChannel(Visitor *v, const char *name, ChardevSpiceChannel **obj, Error **errp);

void visit_type_ChardevSpicePort_members(Visitor *v, ChardevSpicePort *obj, Error **errp);
void visit_type_ChardevSpicePort(Visitor *v, const char *name, ChardevSpicePort **obj, Error **errp);

void visit_type_ChardevStdio_members(Visitor *v, ChardevStdio *obj, Error **errp);
void visit_type_ChardevStdio(Visitor *v, const char *name, ChardevStdio **obj, Error **errp);

void visit_type_ChardevUdp_members(Visitor *v, ChardevUdp *obj, Error **errp);
void visit_type_ChardevUdp(Visitor *v, const char *name, ChardevUdp **obj, Error **errp);

void visit_type_ChardevVC_members(Visitor *v, ChardevVC *obj, Error **errp);
void visit_type_ChardevVC(Visitor *v, const char *name, ChardevVC **obj, Error **errp);

void visit_type_CommandInfo_members(Visitor *v, CommandInfo *obj, Error **errp);
void visit_type_CommandInfo(Visitor *v, const char *name, CommandInfo **obj, Error **errp);
void visit_type_CommandInfoList(Visitor *v, const char *name, CommandInfoList **obj, Error **errp);

void visit_type_CommandLineOptionInfo_members(Visitor *v, CommandLineOptionInfo *obj, Error **errp);
void visit_type_CommandLineOptionInfo(Visitor *v, const char *name, CommandLineOptionInfo **obj, Error **errp);
void visit_type_CommandLineOptionInfoList(Visitor *v, const char *name, CommandLineOptionInfoList **obj, Error **errp);

void visit_type_CommandLineParameterInfo_members(Visitor *v, CommandLineParameterInfo *obj, Error **errp);
void visit_type_CommandLineParameterInfo(Visitor *v, const char *name, CommandLineParameterInfo **obj, Error **errp);
void visit_type_CommandLineParameterInfoList(Visitor *v, const char *name, CommandLineParameterInfoList **obj, Error **errp);
void visit_type_CommandLineParameterType(Visitor *v, const char *name, CommandLineParameterType *obj, Error **errp);

void visit_type_CpuDefinitionInfo_members(Visitor *v, CpuDefinitionInfo *obj, Error **errp);
void visit_type_CpuDefinitionInfo(Visitor *v, const char *name, CpuDefinitionInfo **obj, Error **errp);
void visit_type_CpuDefinitionInfoList(Visitor *v, const char *name, CpuDefinitionInfoList **obj, Error **errp);

void visit_type_CpuInfo_members(Visitor *v, CpuInfo *obj, Error **errp);
void visit_type_CpuInfo(Visitor *v, const char *name, CpuInfo **obj, Error **errp);
void visit_type_CpuInfoArch(Visitor *v, const char *name, CpuInfoArch *obj, Error **errp);
void visit_type_CpuInfoList(Visitor *v, const char *name, CpuInfoList **obj, Error **errp);

void visit_type_CpuInfoMIPS_members(Visitor *v, CpuInfoMIPS *obj, Error **errp);
void visit_type_CpuInfoMIPS(Visitor *v, const char *name, CpuInfoMIPS **obj, Error **errp);

void visit_type_CpuInfoOther_members(Visitor *v, CpuInfoOther *obj, Error **errp);
void visit_type_CpuInfoOther(Visitor *v, const char *name, CpuInfoOther **obj, Error **errp);

void visit_type_CpuInfoPPC_members(Visitor *v, CpuInfoPPC *obj, Error **errp);
void visit_type_CpuInfoPPC(Visitor *v, const char *name, CpuInfoPPC **obj, Error **errp);

void visit_type_CpuInfoSPARC_members(Visitor *v, CpuInfoSPARC *obj, Error **errp);
void visit_type_CpuInfoSPARC(Visitor *v, const char *name, CpuInfoSPARC **obj, Error **errp);

void visit_type_CpuInfoTricore_members(Visitor *v, CpuInfoTricore *obj, Error **errp);
void visit_type_CpuInfoTricore(Visitor *v, const char *name, CpuInfoTricore **obj, Error **errp);

void visit_type_CpuInfoX86_members(Visitor *v, CpuInfoX86 *obj, Error **errp);
void visit_type_CpuInfoX86(Visitor *v, const char *name, CpuInfoX86 **obj, Error **errp);

void visit_type_CpuInstanceProperties_members(Visitor *v, CpuInstanceProperties *obj, Error **errp);
void visit_type_CpuInstanceProperties(Visitor *v, const char *name, CpuInstanceProperties **obj, Error **errp);

void visit_type_CpuModelBaselineInfo_members(Visitor *v, CpuModelBaselineInfo *obj, Error **errp);
void visit_type_CpuModelBaselineInfo(Visitor *v, const char *name, CpuModelBaselineInfo **obj, Error **errp);

void visit_type_CpuModelCompareInfo_members(Visitor *v, CpuModelCompareInfo *obj, Error **errp);
void visit_type_CpuModelCompareInfo(Visitor *v, const char *name, CpuModelCompareInfo **obj, Error **errp);
void visit_type_CpuModelCompareResult(Visitor *v, const char *name, CpuModelCompareResult *obj, Error **errp);

void visit_type_CpuModelExpansionInfo_members(Visitor *v, CpuModelExpansionInfo *obj, Error **errp);
void visit_type_CpuModelExpansionInfo(Visitor *v, const char *name, CpuModelExpansionInfo **obj, Error **errp);
void visit_type_CpuModelExpansionType(Visitor *v, const char *name, CpuModelExpansionType *obj, Error **errp);

void visit_type_CpuModelInfo_members(Visitor *v, CpuModelInfo *obj, Error **errp);
void visit_type_CpuModelInfo(Visitor *v, const char *name, CpuModelInfo **obj, Error **errp);
void visit_type_DataFormat(Visitor *v, const char *name, DataFormat *obj, Error **errp);

void visit_type_DevicePropertyInfo_members(Visitor *v, DevicePropertyInfo *obj, Error **errp);
void visit_type_DevicePropertyInfo(Visitor *v, const char *name, DevicePropertyInfo **obj, Error **errp);
void visit_type_DevicePropertyInfoList(Visitor *v, const char *name, DevicePropertyInfoList **obj, Error **errp);
void visit_type_DirtyBitmapStatus(Visitor *v, const char *name, DirtyBitmapStatus *obj, Error **errp);

void visit_type_DriveBackup_members(Visitor *v, DriveBackup *obj, Error **errp);
void visit_type_DriveBackup(Visitor *v, const char *name, DriveBackup **obj, Error **errp);

void visit_type_DriveMirror_members(Visitor *v, DriveMirror *obj, Error **errp);
void visit_type_DriveMirror(Visitor *v, const char *name, DriveMirror **obj, Error **errp);

void visit_type_DummyForceArrays_members(Visitor *v, DummyForceArrays *obj, Error **errp);
void visit_type_DummyForceArrays(Visitor *v, const char *name, DummyForceArrays **obj, Error **errp);

void visit_type_DumpGuestMemoryCapability_members(Visitor *v, DumpGuestMemoryCapability *obj, Error **errp);
void visit_type_DumpGuestMemoryCapability(Visitor *v, const char *name, DumpGuestMemoryCapability **obj, Error **errp);
void visit_type_DumpGuestMemoryFormat(Visitor *v, const char *name, DumpGuestMemoryFormat *obj, Error **errp);
void visit_type_DumpGuestMemoryFormatList(Visitor *v, const char *name, DumpGuestMemoryFormatList **obj, Error **errp);

void visit_type_DumpQueryResult_members(Visitor *v, DumpQueryResult *obj, Error **errp);
void visit_type_DumpQueryResult(Visitor *v, const char *name, DumpQueryResult **obj, Error **errp);
void visit_type_DumpStatus(Visitor *v, const char *name, DumpStatus *obj, Error **errp);

void visit_type_EventInfo_members(Visitor *v, EventInfo *obj, Error **errp);
void visit_type_EventInfo(Visitor *v, const char *name, EventInfo **obj, Error **errp);
void visit_type_EventInfoList(Visitor *v, const char *name, EventInfoList **obj, Error **errp);
void visit_type_FailoverStatus(Visitor *v, const char *name, FailoverStatus *obj, Error **errp);

void visit_type_FdsetFdInfo_members(Visitor *v, FdsetFdInfo *obj, Error **errp);
void visit_type_FdsetFdInfo(Visitor *v, const char *name, FdsetFdInfo **obj, Error **errp);
void visit_type_FdsetFdInfoList(Visitor *v, const char *name, FdsetFdInfoList **obj, Error **errp);

void visit_type_FdsetInfo_members(Visitor *v, FdsetInfo *obj, Error **errp);
void visit_type_FdsetInfo(Visitor *v, const char *name, FdsetInfo **obj, Error **errp);
void visit_type_FdsetInfoList(Visitor *v, const char *name, FdsetInfoList **obj, Error **errp);
void visit_type_FloppyDriveType(Visitor *v, const char *name, FloppyDriveType *obj, Error **errp);

void visit_type_GICCapability_members(Visitor *v, GICCapability *obj, Error **errp);
void visit_type_GICCapability(Visitor *v, const char *name, GICCapability **obj, Error **errp);
void visit_type_GICCapabilityList(Visitor *v, const char *name, GICCapabilityList **obj, Error **errp);
void visit_type_GuestPanicAction(Visitor *v, const char *name, GuestPanicAction *obj, Error **errp);

void visit_type_GuestPanicInformation_members(Visitor *v, GuestPanicInformation *obj, Error **errp);
void visit_type_GuestPanicInformation(Visitor *v, const char *name, GuestPanicInformation **obj, Error **errp);

void visit_type_GuestPanicInformationHyperV_members(Visitor *v, GuestPanicInformationHyperV *obj, Error **errp);
void visit_type_GuestPanicInformationHyperV(Visitor *v, const char *name, GuestPanicInformationHyperV **obj, Error **errp);
void visit_type_GuestPanicInformationType(Visitor *v, const char *name, GuestPanicInformationType *obj, Error **errp);

void visit_type_GuidInfo_members(Visitor *v, GuidInfo *obj, Error **errp);
void visit_type_GuidInfo(Visitor *v, const char *name, GuidInfo **obj, Error **errp);
void visit_type_HostMemPolicy(Visitor *v, const char *name, HostMemPolicy *obj, Error **errp);

void visit_type_HotpluggableCPU_members(Visitor *v, HotpluggableCPU *obj, Error **errp);
void visit_type_HotpluggableCPU(Visitor *v, const char *name, HotpluggableCPU **obj, Error **errp);
void visit_type_HotpluggableCPUList(Visitor *v, const char *name, HotpluggableCPUList **obj, Error **errp);

void visit_type_IOThreadInfo_members(Visitor *v, IOThreadInfo *obj, Error **errp);
void visit_type_IOThreadInfo(Visitor *v, const char *name, IOThreadInfo **obj, Error **errp);
void visit_type_IOThreadInfoList(Visitor *v, const char *name, IOThreadInfoList **obj, Error **errp);

void visit_type_ImageCheck_members(Visitor *v, ImageCheck *obj, Error **errp);
void visit_type_ImageCheck(Visitor *v, const char *name, ImageCheck **obj, Error **errp);

void visit_type_ImageInfo_members(Visitor *v, ImageInfo *obj, Error **errp);
void visit_type_ImageInfo(Visitor *v, const char *name, ImageInfo **obj, Error **errp);
void visit_type_ImageInfoList(Visitor *v, const char *name, ImageInfoList **obj, Error **errp);

void visit_type_ImageInfoSpecific_members(Visitor *v, ImageInfoSpecific *obj, Error **errp);
void visit_type_ImageInfoSpecific(Visitor *v, const char *name, ImageInfoSpecific **obj, Error **errp);
void visit_type_ImageInfoSpecificKind(Visitor *v, const char *name, ImageInfoSpecificKind *obj, Error **errp);

void visit_type_ImageInfoSpecificQCow2_members(Visitor *v, ImageInfoSpecificQCow2 *obj, Error **errp);
void visit_type_ImageInfoSpecificQCow2(Visitor *v, const char *name, ImageInfoSpecificQCow2 **obj, Error **errp);

void visit_type_ImageInfoSpecificVmdk_members(Visitor *v, ImageInfoSpecificVmdk *obj, Error **errp);
void visit_type_ImageInfoSpecificVmdk(Visitor *v, const char *name, ImageInfoSpecificVmdk **obj, Error **errp);

void visit_type_InetSocketAddress_members(Visitor *v, InetSocketAddress *obj, Error **errp);
void visit_type_InetSocketAddress(Visitor *v, const char *name, InetSocketAddress **obj, Error **errp);

void visit_type_InetSocketAddressBase_members(Visitor *v, InetSocketAddressBase *obj, Error **errp);
void visit_type_InetSocketAddressBase(Visitor *v, const char *name, InetSocketAddressBase **obj, Error **errp);
void visit_type_InetSocketAddressBaseList(Visitor *v, const char *name, InetSocketAddressBaseList **obj, Error **errp);
void visit_type_InputAxis(Visitor *v, const char *name, InputAxis *obj, Error **errp);

void visit_type_InputBtnEvent_members(Visitor *v, InputBtnEvent *obj, Error **errp);
void visit_type_InputBtnEvent(Visitor *v, const char *name, InputBtnEvent **obj, Error **errp);
void visit_type_InputButton(Visitor *v, const char *name, InputButton *obj, Error **errp);

void visit_type_InputEvent_members(Visitor *v, InputEvent *obj, Error **errp);
void visit_type_InputEvent(Visitor *v, const char *name, InputEvent **obj, Error **errp);
void visit_type_InputEventKind(Visitor *v, const char *name, InputEventKind *obj, Error **errp);
void visit_type_InputEventList(Visitor *v, const char *name, InputEventList **obj, Error **errp);

void visit_type_InputKeyEvent_members(Visitor *v, InputKeyEvent *obj, Error **errp);
void visit_type_InputKeyEvent(Visitor *v, const char *name, InputKeyEvent **obj, Error **errp);

void visit_type_InputMoveEvent_members(Visitor *v, InputMoveEvent *obj, Error **errp);
void visit_type_InputMoveEvent(Visitor *v, const char *name, InputMoveEvent **obj, Error **errp);
void visit_type_IoOperationType(Visitor *v, const char *name, IoOperationType *obj, Error **errp);
void visit_type_IscsiHeaderDigest(Visitor *v, const char *name, IscsiHeaderDigest *obj, Error **errp);
void visit_type_IscsiTransport(Visitor *v, const char *name, IscsiTransport *obj, Error **errp);
void visit_type_JSONType(Visitor *v, const char *name, JSONType *obj, Error **errp);

void visit_type_KeyValue_members(Visitor *v, KeyValue *obj, Error **errp);
void visit_type_KeyValue(Visitor *v, const char *name, KeyValue **obj, Error **errp);
void visit_type_KeyValueKind(Visitor *v, const char *name, KeyValueKind *obj, Error **errp);
void visit_type_KeyValueList(Visitor *v, const char *name, KeyValueList **obj, Error **errp);

void visit_type_KvmInfo_members(Visitor *v, KvmInfo *obj, Error **errp);
void visit_type_KvmInfo(Visitor *v, const char *name, KvmInfo **obj, Error **errp);
void visit_type_LostTickPolicy(Visitor *v, const char *name, LostTickPolicy *obj, Error **errp);

void visit_type_MachineInfo_members(Visitor *v, MachineInfo *obj, Error **errp);
void visit_type_MachineInfo(Visitor *v, const char *name, MachineInfo **obj, Error **errp);
void visit_type_MachineInfoList(Visitor *v, const char *name, MachineInfoList **obj, Error **errp);

void visit_type_MapEntry_members(Visitor *v, MapEntry *obj, Error **errp);
void visit_type_MapEntry(Visitor *v, const char *name, MapEntry **obj, Error **errp);

void visit_type_Memdev_members(Visitor *v, Memdev *obj, Error **errp);
void visit_type_Memdev(Visitor *v, const char *name, Memdev **obj, Error **errp);
void visit_type_MemdevList(Visitor *v, const char *name, MemdevList **obj, Error **errp);

void visit_type_MemoryDeviceInfo_members(Visitor *v, MemoryDeviceInfo *obj, Error **errp);
void visit_type_MemoryDeviceInfo(Visitor *v, const char *name, MemoryDeviceInfo **obj, Error **errp);
void visit_type_MemoryDeviceInfoKind(Visitor *v, const char *name, MemoryDeviceInfoKind *obj, Error **errp);
void visit_type_MemoryDeviceInfoList(Visitor *v, const char *name, MemoryDeviceInfoList **obj, Error **errp);
void visit_type_MigrationCapability(Visitor *v, const char *name, MigrationCapability *obj, Error **errp);

void visit_type_MigrationCapabilityStatus_members(Visitor *v, MigrationCapabilityStatus *obj, Error **errp);
void visit_type_MigrationCapabilityStatus(Visitor *v, const char *name, MigrationCapabilityStatus **obj, Error **errp);
void visit_type_MigrationCapabilityStatusList(Visitor *v, const char *name, MigrationCapabilityStatusList **obj, Error **errp);

void visit_type_MigrationInfo_members(Visitor *v, MigrationInfo *obj, Error **errp);
void visit_type_MigrationInfo(Visitor *v, const char *name, MigrationInfo **obj, Error **errp);
void visit_type_MigrationParameter(Visitor *v, const char *name, MigrationParameter *obj, Error **errp);

void visit_type_MigrationParameters_members(Visitor *v, MigrationParameters *obj, Error **errp);
void visit_type_MigrationParameters(Visitor *v, const char *name, MigrationParameters **obj, Error **errp);

void visit_type_MigrationStats_members(Visitor *v, MigrationStats *obj, Error **errp);
void visit_type_MigrationStats(Visitor *v, const char *name, MigrationStats **obj, Error **errp);
void visit_type_MigrationStatus(Visitor *v, const char *name, MigrationStatus *obj, Error **errp);
void visit_type_MirrorSyncMode(Visitor *v, const char *name, MirrorSyncMode *obj, Error **errp);

void visit_type_MouseInfo_members(Visitor *v, MouseInfo *obj, Error **errp);
void visit_type_MouseInfo(Visitor *v, const char *name, MouseInfo **obj, Error **errp);
void visit_type_MouseInfoList(Visitor *v, const char *name, MouseInfoList **obj, Error **errp);

void visit_type_NFSServer_members(Visitor *v, NFSServer *obj, Error **errp);
void visit_type_NFSServer(Visitor *v, const char *name, NFSServer **obj, Error **errp);
void visit_type_NFSTransport(Visitor *v, const char *name, NFSTransport *obj, Error **errp);

void visit_type_NameInfo_members(Visitor *v, NameInfo *obj, Error **errp);
void visit_type_NameInfo(Visitor *v, const char *name, NameInfo **obj, Error **errp);
void visit_type_NetClientDriver(Visitor *v, const char *name, NetClientDriver *obj, Error **errp);
void visit_type_NetFilterDirection(Visitor *v, const char *name, NetFilterDirection *obj, Error **errp);

void visit_type_NetLegacy_members(Visitor *v, NetLegacy *obj, Error **errp);
void visit_type_NetLegacy(Visitor *v, const char *name, NetLegacy **obj, Error **errp);

void visit_type_NetLegacyNicOptions_members(Visitor *v, NetLegacyNicOptions *obj, Error **errp);
void visit_type_NetLegacyNicOptions(Visitor *v, const char *name, NetLegacyNicOptions **obj, Error **errp);

void visit_type_NetLegacyOptions_members(Visitor *v, NetLegacyOptions *obj, Error **errp);
void visit_type_NetLegacyOptions(Visitor *v, const char *name, NetLegacyOptions **obj, Error **errp);
void visit_type_NetLegacyOptionsType(Visitor *v, const char *name, NetLegacyOptionsType *obj, Error **errp);

void visit_type_Netdev_members(Visitor *v, Netdev *obj, Error **errp);
void visit_type_Netdev(Visitor *v, const char *name, Netdev **obj, Error **errp);

void visit_type_NetdevBridgeOptions_members(Visitor *v, NetdevBridgeOptions *obj, Error **errp);
void visit_type_NetdevBridgeOptions(Visitor *v, const char *name, NetdevBridgeOptions **obj, Error **errp);

void visit_type_NetdevDumpOptions_members(Visitor *v, NetdevDumpOptions *obj, Error **errp);
void visit_type_NetdevDumpOptions(Visitor *v, const char *name, NetdevDumpOptions **obj, Error **errp);

void visit_type_NetdevHubPortOptions_members(Visitor *v, NetdevHubPortOptions *obj, Error **errp);
void visit_type_NetdevHubPortOptions(Visitor *v, const char *name, NetdevHubPortOptions **obj, Error **errp);

void visit_type_NetdevL2TPv3Options_members(Visitor *v, NetdevL2TPv3Options *obj, Error **errp);
void visit_type_NetdevL2TPv3Options(Visitor *v, const char *name, NetdevL2TPv3Options **obj, Error **errp);

void visit_type_NetdevNetmapOptions_members(Visitor *v, NetdevNetmapOptions *obj, Error **errp);
void visit_type_NetdevNetmapOptions(Visitor *v, const char *name, NetdevNetmapOptions **obj, Error **errp);

void visit_type_NetdevNoneOptions_members(Visitor *v, NetdevNoneOptions *obj, Error **errp);
void visit_type_NetdevNoneOptions(Visitor *v, const char *name, NetdevNoneOptions **obj, Error **errp);

void visit_type_NetdevSocketOptions_members(Visitor *v, NetdevSocketOptions *obj, Error **errp);
void visit_type_NetdevSocketOptions(Visitor *v, const char *name, NetdevSocketOptions **obj, Error **errp);

void visit_type_NetdevTapOptions_members(Visitor *v, NetdevTapOptions *obj, Error **errp);
void visit_type_NetdevTapOptions(Visitor *v, const char *name, NetdevTapOptions **obj, Error **errp);

void visit_type_NetdevUserOptions_members(Visitor *v, NetdevUserOptions *obj, Error **errp);
void visit_type_NetdevUserOptions(Visitor *v, const char *name, NetdevUserOptions **obj, Error **errp);

void visit_type_NetdevVdeOptions_members(Visitor *v, NetdevVdeOptions *obj, Error **errp);
void visit_type_NetdevVdeOptions(Visitor *v, const char *name, NetdevVdeOptions **obj, Error **errp);

void visit_type_NetdevVhostUserOptions_members(Visitor *v, NetdevVhostUserOptions *obj, Error **errp);
void visit_type_NetdevVhostUserOptions(Visitor *v, const char *name, NetdevVhostUserOptions **obj, Error **errp);
void visit_type_NetworkAddressFamily(Visitor *v, const char *name, NetworkAddressFamily *obj, Error **errp);
void visit_type_NewImageMode(Visitor *v, const char *name, NewImageMode *obj, Error **errp);

void visit_type_NumaNodeOptions_members(Visitor *v, NumaNodeOptions *obj, Error **errp);
void visit_type_NumaNodeOptions(Visitor *v, const char *name, NumaNodeOptions **obj, Error **errp);

void visit_type_NumaOptions_members(Visitor *v, NumaOptions *obj, Error **errp);
void visit_type_NumaOptions(Visitor *v, const char *name, NumaOptions **obj, Error **errp);
void visit_type_NumaOptionsType(Visitor *v, const char *name, NumaOptionsType *obj, Error **errp);

void visit_type_ObjectPropertyInfo_members(Visitor *v, ObjectPropertyInfo *obj, Error **errp);
void visit_type_ObjectPropertyInfo(Visitor *v, const char *name, ObjectPropertyInfo **obj, Error **errp);
void visit_type_ObjectPropertyInfoList(Visitor *v, const char *name, ObjectPropertyInfoList **obj, Error **errp);

void visit_type_ObjectTypeInfo_members(Visitor *v, ObjectTypeInfo *obj, Error **errp);
void visit_type_ObjectTypeInfo(Visitor *v, const char *name, ObjectTypeInfo **obj, Error **errp);
void visit_type_ObjectTypeInfoList(Visitor *v, const char *name, ObjectTypeInfoList **obj, Error **errp);
void visit_type_OnOffAuto(Visitor *v, const char *name, OnOffAuto *obj, Error **errp);
void visit_type_OnOffSplit(Visitor *v, const char *name, OnOffSplit *obj, Error **errp);

void visit_type_PCDIMMDeviceInfo_members(Visitor *v, PCDIMMDeviceInfo *obj, Error **errp);
void visit_type_PCDIMMDeviceInfo(Visitor *v, const char *name, PCDIMMDeviceInfo **obj, Error **errp);

void visit_type_PciBridgeInfo_members(Visitor *v, PciBridgeInfo *obj, Error **errp);
void visit_type_PciBridgeInfo(Visitor *v, const char *name, PciBridgeInfo **obj, Error **errp);

void visit_type_PciBusInfo_members(Visitor *v, PciBusInfo *obj, Error **errp);
void visit_type_PciBusInfo(Visitor *v, const char *name, PciBusInfo **obj, Error **errp);

void visit_type_PciDeviceClass_members(Visitor *v, PciDeviceClass *obj, Error **errp);
void visit_type_PciDeviceClass(Visitor *v, const char *name, PciDeviceClass **obj, Error **errp);

void visit_type_PciDeviceId_members(Visitor *v, PciDeviceId *obj, Error **errp);
void visit_type_PciDeviceId(Visitor *v, const char *name, PciDeviceId **obj, Error **errp);

void visit_type_PciDeviceInfo_members(Visitor *v, PciDeviceInfo *obj, Error **errp);
void visit_type_PciDeviceInfo(Visitor *v, const char *name, PciDeviceInfo **obj, Error **errp);
void visit_type_PciDeviceInfoList(Visitor *v, const char *name, PciDeviceInfoList **obj, Error **errp);

void visit_type_PciInfo_members(Visitor *v, PciInfo *obj, Error **errp);
void visit_type_PciInfo(Visitor *v, const char *name, PciInfo **obj, Error **errp);
void visit_type_PciInfoList(Visitor *v, const char *name, PciInfoList **obj, Error **errp);

void visit_type_PciMemoryRange_members(Visitor *v, PciMemoryRange *obj, Error **errp);
void visit_type_PciMemoryRange(Visitor *v, const char *name, PciMemoryRange **obj, Error **errp);

void visit_type_PciMemoryRegion_members(Visitor *v, PciMemoryRegion *obj, Error **errp);
void visit_type_PciMemoryRegion(Visitor *v, const char *name, PciMemoryRegion **obj, Error **errp);
void visit_type_PciMemoryRegionList(Visitor *v, const char *name, PciMemoryRegionList **obj, Error **errp);
void visit_type_PreallocMode(Visitor *v, const char *name, PreallocMode *obj, Error **errp);

void visit_type_QCryptoBlockCreateOptions_members(Visitor *v, QCryptoBlockCreateOptions *obj, Error **errp);
void visit_type_QCryptoBlockCreateOptions(Visitor *v, const char *name, QCryptoBlockCreateOptions **obj, Error **errp);

void visit_type_QCryptoBlockCreateOptionsLUKS_members(Visitor *v, QCryptoBlockCreateOptionsLUKS *obj, Error **errp);
void visit_type_QCryptoBlockCreateOptionsLUKS(Visitor *v, const char *name, QCryptoBlockCreateOptionsLUKS **obj, Error **errp);
void visit_type_QCryptoBlockFormat(Visitor *v, const char *name, QCryptoBlockFormat *obj, Error **errp);

void visit_type_QCryptoBlockInfo_members(Visitor *v, QCryptoBlockInfo *obj, Error **errp);
void visit_type_QCryptoBlockInfo(Visitor *v, const char *name, QCryptoBlockInfo **obj, Error **errp);

void visit_type_QCryptoBlockInfoBase_members(Visitor *v, QCryptoBlockInfoBase *obj, Error **errp);
void visit_type_QCryptoBlockInfoBase(Visitor *v, const char *name, QCryptoBlockInfoBase **obj, Error **errp);

void visit_type_QCryptoBlockInfoLUKS_members(Visitor *v, QCryptoBlockInfoLUKS *obj, Error **errp);
void visit_type_QCryptoBlockInfoLUKS(Visitor *v, const char *name, QCryptoBlockInfoLUKS **obj, Error **errp);

void visit_type_QCryptoBlockInfoLUKSSlot_members(Visitor *v, QCryptoBlockInfoLUKSSlot *obj, Error **errp);
void visit_type_QCryptoBlockInfoLUKSSlot(Visitor *v, const char *name, QCryptoBlockInfoLUKSSlot **obj, Error **errp);
void visit_type_QCryptoBlockInfoLUKSSlotList(Visitor *v, const char *name, QCryptoBlockInfoLUKSSlotList **obj, Error **errp);

void visit_type_QCryptoBlockInfoQCow_members(Visitor *v, QCryptoBlockInfoQCow *obj, Error **errp);
void visit_type_QCryptoBlockInfoQCow(Visitor *v, const char *name, QCryptoBlockInfoQCow **obj, Error **errp);

void visit_type_QCryptoBlockOpenOptions_members(Visitor *v, QCryptoBlockOpenOptions *obj, Error **errp);
void visit_type_QCryptoBlockOpenOptions(Visitor *v, const char *name, QCryptoBlockOpenOptions **obj, Error **errp);

void visit_type_QCryptoBlockOptionsBase_members(Visitor *v, QCryptoBlockOptionsBase *obj, Error **errp);
void visit_type_QCryptoBlockOptionsBase(Visitor *v, const char *name, QCryptoBlockOptionsBase **obj, Error **errp);

void visit_type_QCryptoBlockOptionsLUKS_members(Visitor *v, QCryptoBlockOptionsLUKS *obj, Error **errp);
void visit_type_QCryptoBlockOptionsLUKS(Visitor *v, const char *name, QCryptoBlockOptionsLUKS **obj, Error **errp);

void visit_type_QCryptoBlockOptionsQCow_members(Visitor *v, QCryptoBlockOptionsQCow *obj, Error **errp);
void visit_type_QCryptoBlockOptionsQCow(Visitor *v, const char *name, QCryptoBlockOptionsQCow **obj, Error **errp);
void visit_type_QCryptoCipherAlgorithm(Visitor *v, const char *name, QCryptoCipherAlgorithm *obj, Error **errp);
void visit_type_QCryptoCipherMode(Visitor *v, const char *name, QCryptoCipherMode *obj, Error **errp);
void visit_type_QCryptoHashAlgorithm(Visitor *v, const char *name, QCryptoHashAlgorithm *obj, Error **errp);
void visit_type_QCryptoIVGenAlgorithm(Visitor *v, const char *name, QCryptoIVGenAlgorithm *obj, Error **errp);
void visit_type_QCryptoSecretFormat(Visitor *v, const char *name, QCryptoSecretFormat *obj, Error **errp);
void visit_type_QCryptoTLSCredsEndpoint(Visitor *v, const char *name, QCryptoTLSCredsEndpoint *obj, Error **errp);
void visit_type_QKeyCode(Visitor *v, const char *name, QKeyCode *obj, Error **errp);
void visit_type_QapiErrorClass(Visitor *v, const char *name, QapiErrorClass *obj, Error **errp);

void visit_type_Qcow2OverlapCheckFlags_members(Visitor *v, Qcow2OverlapCheckFlags *obj, Error **errp);
void visit_type_Qcow2OverlapCheckFlags(Visitor *v, const char *name, Qcow2OverlapCheckFlags **obj, Error **errp);
void visit_type_Qcow2OverlapCheckMode(Visitor *v, const char *name, Qcow2OverlapCheckMode *obj, Error **errp);
void visit_type_Qcow2OverlapChecks(Visitor *v, const char *name, Qcow2OverlapChecks **obj, Error **errp);
void visit_type_QuorumOpType(Visitor *v, const char *name, QuorumOpType *obj, Error **errp);
void visit_type_QuorumReadPattern(Visitor *v, const char *name, QuorumReadPattern *obj, Error **errp);
void visit_type_ReplayMode(Visitor *v, const char *name, ReplayMode *obj, Error **errp);
void visit_type_ReplicationMode(Visitor *v, const char *name, ReplicationMode *obj, Error **errp);

void visit_type_ReplicationStatus_members(Visitor *v, ReplicationStatus *obj, Error **errp);
void visit_type_ReplicationStatus(Visitor *v, const char *name, ReplicationStatus **obj, Error **errp);

void visit_type_RockerOfDpaFlow_members(Visitor *v, RockerOfDpaFlow *obj, Error **errp);
void visit_type_RockerOfDpaFlow(Visitor *v, const char *name, RockerOfDpaFlow **obj, Error **errp);

void visit_type_RockerOfDpaFlowAction_members(Visitor *v, RockerOfDpaFlowAction *obj, Error **errp);
void visit_type_RockerOfDpaFlowAction(Visitor *v, const char *name, RockerOfDpaFlowAction **obj, Error **errp);

void visit_type_RockerOfDpaFlowKey_members(Visitor *v, RockerOfDpaFlowKey *obj, Error **errp);
void visit_type_RockerOfDpaFlowKey(Visitor *v, const char *name, RockerOfDpaFlowKey **obj, Error **errp);
void visit_type_RockerOfDpaFlowList(Visitor *v, const char *name, RockerOfDpaFlowList **obj, Error **errp);

void visit_type_RockerOfDpaFlowMask_members(Visitor *v, RockerOfDpaFlowMask *obj, Error **errp);
void visit_type_RockerOfDpaFlowMask(Visitor *v, const char *name, RockerOfDpaFlowMask **obj, Error **errp);

void visit_type_RockerOfDpaGroup_members(Visitor *v, RockerOfDpaGroup *obj, Error **errp);
void visit_type_RockerOfDpaGroup(Visitor *v, const char *name, RockerOfDpaGroup **obj, Error **errp);
void visit_type_RockerOfDpaGroupList(Visitor *v, const char *name, RockerOfDpaGroupList **obj, Error **errp);

void visit_type_RockerPort_members(Visitor *v, RockerPort *obj, Error **errp);
void visit_type_RockerPort(Visitor *v, const char *name, RockerPort **obj, Error **errp);
void visit_type_RockerPortAutoneg(Visitor *v, const char *name, RockerPortAutoneg *obj, Error **errp);
void visit_type_RockerPortDuplex(Visitor *v, const char *name, RockerPortDuplex *obj, Error **errp);
void visit_type_RockerPortList(Visitor *v, const char *name, RockerPortList **obj, Error **errp);

void visit_type_RockerSwitch_members(Visitor *v, RockerSwitch *obj, Error **errp);
void visit_type_RockerSwitch(Visitor *v, const char *name, RockerSwitch **obj, Error **errp);
void visit_type_RunState(Visitor *v, const char *name, RunState *obj, Error **errp);

void visit_type_RxFilterInfo_members(Visitor *v, RxFilterInfo *obj, Error **errp);
void visit_type_RxFilterInfo(Visitor *v, const char *name, RxFilterInfo **obj, Error **errp);
void visit_type_RxFilterInfoList(Visitor *v, const char *name, RxFilterInfoList **obj, Error **errp);
void visit_type_RxState(Visitor *v, const char *name, RxState *obj, Error **errp);

void visit_type_SchemaInfo_members(Visitor *v, SchemaInfo *obj, Error **errp);
void visit_type_SchemaInfo(Visitor *v, const char *name, SchemaInfo **obj, Error **errp);

void visit_type_SchemaInfoAlternate_members(Visitor *v, SchemaInfoAlternate *obj, Error **errp);
void visit_type_SchemaInfoAlternate(Visitor *v, const char *name, SchemaInfoAlternate **obj, Error **errp);

void visit_type_SchemaInfoAlternateMember_members(Visitor *v, SchemaInfoAlternateMember *obj, Error **errp);
void visit_type_SchemaInfoAlternateMember(Visitor *v, const char *name, SchemaInfoAlternateMember **obj, Error **errp);
void visit_type_SchemaInfoAlternateMemberList(Visitor *v, const char *name, SchemaInfoAlternateMemberList **obj, Error **errp);

void visit_type_SchemaInfoArray_members(Visitor *v, SchemaInfoArray *obj, Error **errp);
void visit_type_SchemaInfoArray(Visitor *v, const char *name, SchemaInfoArray **obj, Error **errp);

void visit_type_SchemaInfoBuiltin_members(Visitor *v, SchemaInfoBuiltin *obj, Error **errp);
void visit_type_SchemaInfoBuiltin(Visitor *v, const char *name, SchemaInfoBuiltin **obj, Error **errp);

void visit_type_SchemaInfoCommand_members(Visitor *v, SchemaInfoCommand *obj, Error **errp);
void visit_type_SchemaInfoCommand(Visitor *v, const char *name, SchemaInfoCommand **obj, Error **errp);

void visit_type_SchemaInfoEnum_members(Visitor *v, SchemaInfoEnum *obj, Error **errp);
void visit_type_SchemaInfoEnum(Visitor *v, const char *name, SchemaInfoEnum **obj, Error **errp);

void visit_type_SchemaInfoEvent_members(Visitor *v, SchemaInfoEvent *obj, Error **errp);
void visit_type_SchemaInfoEvent(Visitor *v, const char *name, SchemaInfoEvent **obj, Error **errp);
void visit_type_SchemaInfoList(Visitor *v, const char *name, SchemaInfoList **obj, Error **errp);

void visit_type_SchemaInfoObject_members(Visitor *v, SchemaInfoObject *obj, Error **errp);
void visit_type_SchemaInfoObject(Visitor *v, const char *name, SchemaInfoObject **obj, Error **errp);

void visit_type_SchemaInfoObjectMember_members(Visitor *v, SchemaInfoObjectMember *obj, Error **errp);
void visit_type_SchemaInfoObjectMember(Visitor *v, const char *name, SchemaInfoObjectMember **obj, Error **errp);
void visit_type_SchemaInfoObjectMemberList(Visitor *v, const char *name, SchemaInfoObjectMemberList **obj, Error **errp);

void visit_type_SchemaInfoObjectVariant_members(Visitor *v, SchemaInfoObjectVariant *obj, Error **errp);
void visit_type_SchemaInfoObjectVariant(Visitor *v, const char *name, SchemaInfoObjectVariant **obj, Error **errp);
void visit_type_SchemaInfoObjectVariantList(Visitor *v, const char *name, SchemaInfoObjectVariantList **obj, Error **errp);
void visit_type_SchemaMetaType(Visitor *v, const char *name, SchemaMetaType *obj, Error **errp);

void visit_type_SnapshotInfo_members(Visitor *v, SnapshotInfo *obj, Error **errp);
void visit_type_SnapshotInfo(Visitor *v, const char *name, SnapshotInfo **obj, Error **errp);
void visit_type_SnapshotInfoList(Visitor *v, const char *name, SnapshotInfoList **obj, Error **errp);

void visit_type_SocketAddress_members(Visitor *v, SocketAddress *obj, Error **errp);
void visit_type_SocketAddress(Visitor *v, const char *name, SocketAddress **obj, Error **errp);

void visit_type_SocketAddressFlat_members(Visitor *v, SocketAddressFlat *obj, Error **errp);
void visit_type_SocketAddressFlat(Visitor *v, const char *name, SocketAddressFlat **obj, Error **errp);
void visit_type_SocketAddressFlatList(Visitor *v, const char *name, SocketAddressFlatList **obj, Error **errp);
void visit_type_SocketAddressFlatType(Visitor *v, const char *name, SocketAddressFlatType *obj, Error **errp);
void visit_type_SocketAddressKind(Visitor *v, const char *name, SocketAddressKind *obj, Error **errp);

void visit_type_SpiceBasicInfo_members(Visitor *v, SpiceBasicInfo *obj, Error **errp);
void visit_type_SpiceBasicInfo(Visitor *v, const char *name, SpiceBasicInfo **obj, Error **errp);

void visit_type_SpiceChannel_members(Visitor *v, SpiceChannel *obj, Error **errp);
void visit_type_SpiceChannel(Visitor *v, const char *name, SpiceChannel **obj, Error **errp);
void visit_type_SpiceChannelList(Visitor *v, const char *name, SpiceChannelList **obj, Error **errp);

void visit_type_SpiceInfo_members(Visitor *v, SpiceInfo *obj, Error **errp);
void visit_type_SpiceInfo(Visitor *v, const char *name, SpiceInfo **obj, Error **errp);
void visit_type_SpiceQueryMouseMode(Visitor *v, const char *name, SpiceQueryMouseMode *obj, Error **errp);

void visit_type_SpiceServerInfo_members(Visitor *v, SpiceServerInfo *obj, Error **errp);
void visit_type_SpiceServerInfo(Visitor *v, const char *name, SpiceServerInfo **obj, Error **errp);

void visit_type_StatusInfo_members(Visitor *v, StatusInfo *obj, Error **errp);
void visit_type_StatusInfo(Visitor *v, const char *name, StatusInfo **obj, Error **errp);

void visit_type_String_members(Visitor *v, String *obj, Error **errp);
void visit_type_String(Visitor *v, const char *name, String **obj, Error **errp);
void visit_type_StringList(Visitor *v, const char *name, StringList **obj, Error **errp);

void visit_type_TPMInfo_members(Visitor *v, TPMInfo *obj, Error **errp);
void visit_type_TPMInfo(Visitor *v, const char *name, TPMInfo **obj, Error **errp);
void visit_type_TPMInfoList(Visitor *v, const char *name, TPMInfoList **obj, Error **errp);

void visit_type_TPMPassthroughOptions_members(Visitor *v, TPMPassthroughOptions *obj, Error **errp);
void visit_type_TPMPassthroughOptions(Visitor *v, const char *name, TPMPassthroughOptions **obj, Error **errp);

void visit_type_TargetInfo_members(Visitor *v, TargetInfo *obj, Error **errp);
void visit_type_TargetInfo(Visitor *v, const char *name, TargetInfo **obj, Error **errp);
void visit_type_TpmModel(Visitor *v, const char *name, TpmModel *obj, Error **errp);
void visit_type_TpmModelList(Visitor *v, const char *name, TpmModelList **obj, Error **errp);
void visit_type_TpmType(Visitor *v, const char *name, TpmType *obj, Error **errp);
void visit_type_TpmTypeList(Visitor *v, const char *name, TpmTypeList **obj, Error **errp);

void visit_type_TpmTypeOptions_members(Visitor *v, TpmTypeOptions *obj, Error **errp);
void visit_type_TpmTypeOptions(Visitor *v, const char *name, TpmTypeOptions **obj, Error **errp);
void visit_type_TpmTypeOptionsKind(Visitor *v, const char *name, TpmTypeOptionsKind *obj, Error **errp);

void visit_type_TraceEventInfo_members(Visitor *v, TraceEventInfo *obj, Error **errp);
void visit_type_TraceEventInfo(Visitor *v, const char *name, TraceEventInfo **obj, Error **errp);
void visit_type_TraceEventInfoList(Visitor *v, const char *name, TraceEventInfoList **obj, Error **errp);
void visit_type_TraceEventState(Visitor *v, const char *name, TraceEventState *obj, Error **errp);

void visit_type_TransactionAction_members(Visitor *v, TransactionAction *obj, Error **errp);
void visit_type_TransactionAction(Visitor *v, const char *name, TransactionAction **obj, Error **errp);
void visit_type_TransactionActionKind(Visitor *v, const char *name, TransactionActionKind *obj, Error **errp);
void visit_type_TransactionActionList(Visitor *v, const char *name, TransactionActionList **obj, Error **errp);

void visit_type_TransactionProperties_members(Visitor *v, TransactionProperties *obj, Error **errp);
void visit_type_TransactionProperties(Visitor *v, const char *name, TransactionProperties **obj, Error **errp);

void visit_type_UnixSocketAddress_members(Visitor *v, UnixSocketAddress *obj, Error **errp);
void visit_type_UnixSocketAddress(Visitor *v, const char *name, UnixSocketAddress **obj, Error **errp);

void visit_type_UuidInfo_members(Visitor *v, UuidInfo *obj, Error **errp);
void visit_type_UuidInfo(Visitor *v, const char *name, UuidInfo **obj, Error **errp);

void visit_type_VersionInfo_members(Visitor *v, VersionInfo *obj, Error **errp);
void visit_type_VersionInfo(Visitor *v, const char *name, VersionInfo **obj, Error **errp);

void visit_type_VersionTriple_members(Visitor *v, VersionTriple *obj, Error **errp);
void visit_type_VersionTriple(Visitor *v, const char *name, VersionTriple **obj, Error **errp);

void visit_type_VncBasicInfo_members(Visitor *v, VncBasicInfo *obj, Error **errp);
void visit_type_VncBasicInfo(Visitor *v, const char *name, VncBasicInfo **obj, Error **errp);

void visit_type_VncClientInfo_members(Visitor *v, VncClientInfo *obj, Error **errp);
void visit_type_VncClientInfo(Visitor *v, const char *name, VncClientInfo **obj, Error **errp);
void visit_type_VncClientInfoList(Visitor *v, const char *name, VncClientInfoList **obj, Error **errp);

void visit_type_VncInfo_members(Visitor *v, VncInfo *obj, Error **errp);
void visit_type_VncInfo(Visitor *v, const char *name, VncInfo **obj, Error **errp);

void visit_type_VncInfo2_members(Visitor *v, VncInfo2 *obj, Error **errp);
void visit_type_VncInfo2(Visitor *v, const char *name, VncInfo2 **obj, Error **errp);
void visit_type_VncInfo2List(Visitor *v, const char *name, VncInfo2List **obj, Error **errp);
void visit_type_VncPrimaryAuth(Visitor *v, const char *name, VncPrimaryAuth *obj, Error **errp);

void visit_type_VncServerInfo_members(Visitor *v, VncServerInfo *obj, Error **errp);
void visit_type_VncServerInfo(Visitor *v, const char *name, VncServerInfo **obj, Error **errp);

void visit_type_VncServerInfo2_members(Visitor *v, VncServerInfo2 *obj, Error **errp);
void visit_type_VncServerInfo2(Visitor *v, const char *name, VncServerInfo2 **obj, Error **errp);
void visit_type_VncServerInfo2List(Visitor *v, const char *name, VncServerInfo2List **obj, Error **errp);
void visit_type_VncVencryptSubAuth(Visitor *v, const char *name, VncVencryptSubAuth *obj, Error **errp);

void visit_type_VsockSocketAddress_members(Visitor *v, VsockSocketAddress *obj, Error **errp);
void visit_type_VsockSocketAddress(Visitor *v, const char *name, VsockSocketAddress **obj, Error **errp);
void visit_type_WatchdogExpirationAction(Visitor *v, const char *name, WatchdogExpirationAction *obj, Error **errp);

void visit_type_X86CPUFeatureWordInfo_members(Visitor *v, X86CPUFeatureWordInfo *obj, Error **errp);
void visit_type_X86CPUFeatureWordInfo(Visitor *v, const char *name, X86CPUFeatureWordInfo **obj, Error **errp);
void visit_type_X86CPUFeatureWordInfoList(Visitor *v, const char *name, X86CPUFeatureWordInfoList **obj, Error **errp);
void visit_type_X86CPURegister32(Visitor *v, const char *name, X86CPURegister32 *obj, Error **errp);

void visit_type_XBZRLECacheStats_members(Visitor *v, XBZRLECacheStats *obj, Error **errp);
void visit_type_XBZRLECacheStats(Visitor *v, const char *name, XBZRLECacheStats **obj, Error **errp);

void visit_type_q_obj_ACPI_DEVICE_OST_arg_members(Visitor *v, q_obj_ACPI_DEVICE_OST_arg *obj, Error **errp);

void visit_type_q_obj_Abort_wrapper_members(Visitor *v, q_obj_Abort_wrapper *obj, Error **errp);

void visit_type_q_obj_BALLOON_CHANGE_arg_members(Visitor *v, q_obj_BALLOON_CHANGE_arg *obj, Error **errp);

void visit_type_q_obj_BLOCK_IMAGE_CORRUPTED_arg_members(Visitor *v, q_obj_BLOCK_IMAGE_CORRUPTED_arg *obj, Error **errp);

void visit_type_q_obj_BLOCK_IO_ERROR_arg_members(Visitor *v, q_obj_BLOCK_IO_ERROR_arg *obj, Error **errp);

void visit_type_q_obj_BLOCK_JOB_CANCELLED_arg_members(Visitor *v, q_obj_BLOCK_JOB_CANCELLED_arg *obj, Error **errp);

void visit_type_q_obj_BLOCK_JOB_COMPLETED_arg_members(Visitor *v, q_obj_BLOCK_JOB_COMPLETED_arg *obj, Error **errp);

void visit_type_q_obj_BLOCK_JOB_ERROR_arg_members(Visitor *v, q_obj_BLOCK_JOB_ERROR_arg *obj, Error **errp);

void visit_type_q_obj_BLOCK_JOB_READY_arg_members(Visitor *v, q_obj_BLOCK_JOB_READY_arg *obj, Error **errp);

void visit_type_q_obj_BLOCK_WRITE_THRESHOLD_arg_members(Visitor *v, q_obj_BLOCK_WRITE_THRESHOLD_arg *obj, Error **errp);

void visit_type_q_obj_BlockDirtyBitmap_wrapper_members(Visitor *v, q_obj_BlockDirtyBitmap_wrapper *obj, Error **errp);

void visit_type_q_obj_BlockDirtyBitmapAdd_wrapper_members(Visitor *v, q_obj_BlockDirtyBitmapAdd_wrapper *obj, Error **errp);

void visit_type_q_obj_BlockdevBackup_wrapper_members(Visitor *v, q_obj_BlockdevBackup_wrapper *obj, Error **errp);

void visit_type_q_obj_BlockdevOptions_base_members(Visitor *v, q_obj_BlockdevOptions_base *obj, Error **errp);

void visit_type_q_obj_BlockdevSnapshot_wrapper_members(Visitor *v, q_obj_BlockdevSnapshot_wrapper *obj, Error **errp);

void visit_type_q_obj_BlockdevSnapshotInternal_wrapper_members(Visitor *v, q_obj_BlockdevSnapshotInternal_wrapper *obj, Error **errp);

void visit_type_q_obj_BlockdevSnapshotSync_wrapper_members(Visitor *v, q_obj_BlockdevSnapshotSync_wrapper *obj, Error **errp);

void visit_type_q_obj_ChardevCommon_wrapper_members(Visitor *v, q_obj_ChardevCommon_wrapper *obj, Error **errp);

void visit_type_q_obj_ChardevFile_wrapper_members(Visitor *v, q_obj_ChardevFile_wrapper *obj, Error **errp);

void visit_type_q_obj_ChardevHostdev_wrapper_members(Visitor *v, q_obj_ChardevHostdev_wrapper *obj, Error **errp);

void visit_type_q_obj_ChardevMux_wrapper_members(Visitor *v, q_obj_ChardevMux_wrapper *obj, Error **errp);

void visit_type_q_obj_ChardevRingbuf_wrapper_members(Visitor *v, q_obj_ChardevRingbuf_wrapper *obj, Error **errp);

void visit_type_q_obj_ChardevSocket_wrapper_members(Visitor *v, q_obj_ChardevSocket_wrapper *obj, Error **errp);

void visit_type_q_obj_ChardevSpiceChannel_wrapper_members(Visitor *v, q_obj_ChardevSpiceChannel_wrapper *obj, Error **errp);

void visit_type_q_obj_ChardevSpicePort_wrapper_members(Visitor *v, q_obj_ChardevSpicePort_wrapper *obj, Error **errp);

void visit_type_q_obj_ChardevStdio_wrapper_members(Visitor *v, q_obj_ChardevStdio_wrapper *obj, Error **errp);

void visit_type_q_obj_ChardevUdp_wrapper_members(Visitor *v, q_obj_ChardevUdp_wrapper *obj, Error **errp);

void visit_type_q_obj_ChardevVC_wrapper_members(Visitor *v, q_obj_ChardevVC_wrapper *obj, Error **errp);

void visit_type_q_obj_CpuInfo_base_members(Visitor *v, q_obj_CpuInfo_base *obj, Error **errp);

void visit_type_q_obj_DEVICE_DELETED_arg_members(Visitor *v, q_obj_DEVICE_DELETED_arg *obj, Error **errp);

void visit_type_q_obj_DEVICE_TRAY_MOVED_arg_members(Visitor *v, q_obj_DEVICE_TRAY_MOVED_arg *obj, Error **errp);

void visit_type_q_obj_DUMP_COMPLETED_arg_members(Visitor *v, q_obj_DUMP_COMPLETED_arg *obj, Error **errp);

void visit_type_q_obj_DriveBackup_wrapper_members(Visitor *v, q_obj_DriveBackup_wrapper *obj, Error **errp);

void visit_type_q_obj_GUEST_PANICKED_arg_members(Visitor *v, q_obj_GUEST_PANICKED_arg *obj, Error **errp);

void visit_type_q_obj_GuestPanicInformation_base_members(Visitor *v, q_obj_GuestPanicInformation_base *obj, Error **errp);

void visit_type_q_obj_ImageInfoSpecificQCow2_wrapper_members(Visitor *v, q_obj_ImageInfoSpecificQCow2_wrapper *obj, Error **errp);

void visit_type_q_obj_ImageInfoSpecificVmdk_wrapper_members(Visitor *v, q_obj_ImageInfoSpecificVmdk_wrapper *obj, Error **errp);

void visit_type_q_obj_InetSocketAddress_wrapper_members(Visitor *v, q_obj_InetSocketAddress_wrapper *obj, Error **errp);

void visit_type_q_obj_InputBtnEvent_wrapper_members(Visitor *v, q_obj_InputBtnEvent_wrapper *obj, Error **errp);

void visit_type_q_obj_InputKeyEvent_wrapper_members(Visitor *v, q_obj_InputKeyEvent_wrapper *obj, Error **errp);

void visit_type_q_obj_InputMoveEvent_wrapper_members(Visitor *v, q_obj_InputMoveEvent_wrapper *obj, Error **errp);

void visit_type_q_obj_MEM_UNPLUG_ERROR_arg_members(Visitor *v, q_obj_MEM_UNPLUG_ERROR_arg *obj, Error **errp);

void visit_type_q_obj_MIGRATION_arg_members(Visitor *v, q_obj_MIGRATION_arg *obj, Error **errp);

void visit_type_q_obj_MIGRATION_PASS_arg_members(Visitor *v, q_obj_MIGRATION_PASS_arg *obj, Error **errp);

void visit_type_q_obj_NIC_RX_FILTER_CHANGED_arg_members(Visitor *v, q_obj_NIC_RX_FILTER_CHANGED_arg *obj, Error **errp);

void visit_type_q_obj_NetLegacyOptions_base_members(Visitor *v, q_obj_NetLegacyOptions_base *obj, Error **errp);

void visit_type_q_obj_Netdev_base_members(Visitor *v, q_obj_Netdev_base *obj, Error **errp);

void visit_type_q_obj_NumaOptions_base_members(Visitor *v, q_obj_NumaOptions_base *obj, Error **errp);

void visit_type_q_obj_PCDIMMDeviceInfo_wrapper_members(Visitor *v, q_obj_PCDIMMDeviceInfo_wrapper *obj, Error **errp);

void visit_type_q_obj_QCryptoBlockInfoLUKS_wrapper_members(Visitor *v, q_obj_QCryptoBlockInfoLUKS_wrapper *obj, Error **errp);

void visit_type_q_obj_QKeyCode_wrapper_members(Visitor *v, q_obj_QKeyCode_wrapper *obj, Error **errp);

void visit_type_q_obj_QUORUM_FAILURE_arg_members(Visitor *v, q_obj_QUORUM_FAILURE_arg *obj, Error **errp);

void visit_type_q_obj_QUORUM_REPORT_BAD_arg_members(Visitor *v, q_obj_QUORUM_REPORT_BAD_arg *obj, Error **errp);

void visit_type_q_obj_RTC_CHANGE_arg_members(Visitor *v, q_obj_RTC_CHANGE_arg *obj, Error **errp);

void visit_type_q_obj_SPICE_CONNECTED_arg_members(Visitor *v, q_obj_SPICE_CONNECTED_arg *obj, Error **errp);

void visit_type_q_obj_SPICE_DISCONNECTED_arg_members(Visitor *v, q_obj_SPICE_DISCONNECTED_arg *obj, Error **errp);

void visit_type_q_obj_SPICE_INITIALIZED_arg_members(Visitor *v, q_obj_SPICE_INITIALIZED_arg *obj, Error **errp);

void visit_type_q_obj_SchemaInfo_base_members(Visitor *v, q_obj_SchemaInfo_base *obj, Error **errp);

void visit_type_q_obj_SocketAddressFlat_base_members(Visitor *v, q_obj_SocketAddressFlat_base *obj, Error **errp);

void visit_type_q_obj_String_wrapper_members(Visitor *v, q_obj_String_wrapper *obj, Error **errp);

void visit_type_q_obj_TPMPassthroughOptions_wrapper_members(Visitor *v, q_obj_TPMPassthroughOptions_wrapper *obj, Error **errp);

void visit_type_q_obj_UnixSocketAddress_wrapper_members(Visitor *v, q_obj_UnixSocketAddress_wrapper *obj, Error **errp);

void visit_type_q_obj_VNC_CONNECTED_arg_members(Visitor *v, q_obj_VNC_CONNECTED_arg *obj, Error **errp);

void visit_type_q_obj_VNC_DISCONNECTED_arg_members(Visitor *v, q_obj_VNC_DISCONNECTED_arg *obj, Error **errp);

void visit_type_q_obj_VNC_INITIALIZED_arg_members(Visitor *v, q_obj_VNC_INITIALIZED_arg *obj, Error **errp);

void visit_type_q_obj_VSERPORT_CHANGE_arg_members(Visitor *v, q_obj_VSERPORT_CHANGE_arg *obj, Error **errp);

void visit_type_q_obj_VsockSocketAddress_wrapper_members(Visitor *v, q_obj_VsockSocketAddress_wrapper *obj, Error **errp);

void visit_type_q_obj_WATCHDOG_arg_members(Visitor *v, q_obj_WATCHDOG_arg *obj, Error **errp);

void visit_type_q_obj_add_fd_arg_members(Visitor *v, q_obj_add_fd_arg *obj, Error **errp);

void visit_type_q_obj_add_client_arg_members(Visitor *v, q_obj_add_client_arg *obj, Error **errp);

void visit_type_q_obj_balloon_arg_members(Visitor *v, q_obj_balloon_arg *obj, Error **errp);

void visit_type_q_obj_block_commit_arg_members(Visitor *v, q_obj_block_commit_arg *obj, Error **errp);

void visit_type_q_obj_block_job_cancel_arg_members(Visitor *v, q_obj_block_job_cancel_arg *obj, Error **errp);

void visit_type_q_obj_block_job_complete_arg_members(Visitor *v, q_obj_block_job_complete_arg *obj, Error **errp);

void visit_type_q_obj_block_job_pause_arg_members(Visitor *v, q_obj_block_job_pause_arg *obj, Error **errp);

void visit_type_q_obj_block_job_resume_arg_members(Visitor *v, q_obj_block_job_resume_arg *obj, Error **errp);

void visit_type_q_obj_block_job_set_speed_arg_members(Visitor *v, q_obj_block_job_set_speed_arg *obj, Error **errp);

void visit_type_q_obj_block_set_write_threshold_arg_members(Visitor *v, q_obj_block_set_write_threshold_arg *obj, Error **errp);

void visit_type_q_obj_block_stream_arg_members(Visitor *v, q_obj_block_stream_arg *obj, Error **errp);

void visit_type_q_obj_block_passwd_arg_members(Visitor *v, q_obj_block_passwd_arg *obj, Error **errp);

void visit_type_q_obj_block_resize_arg_members(Visitor *v, q_obj_block_resize_arg *obj, Error **errp);

void visit_type_q_obj_blockdev_change_medium_arg_members(Visitor *v, q_obj_blockdev_change_medium_arg *obj, Error **errp);

void visit_type_q_obj_blockdev_close_tray_arg_members(Visitor *v, q_obj_blockdev_close_tray_arg *obj, Error **errp);

void visit_type_q_obj_blockdev_del_arg_members(Visitor *v, q_obj_blockdev_del_arg *obj, Error **errp);

void visit_type_q_obj_blockdev_mirror_arg_members(Visitor *v, q_obj_blockdev_mirror_arg *obj, Error **errp);

void visit_type_q_obj_blockdev_open_tray_arg_members(Visitor *v, q_obj_blockdev_open_tray_arg *obj, Error **errp);

void visit_type_q_obj_blockdev_snapshot_delete_internal_sync_arg_members(Visitor *v, q_obj_blockdev_snapshot_delete_internal_sync_arg *obj, Error **errp);

void visit_type_q_obj_change_arg_members(Visitor *v, q_obj_change_arg *obj, Error **errp);

void visit_type_q_obj_change_backing_file_arg_members(Visitor *v, q_obj_change_backing_file_arg *obj, Error **errp);

void visit_type_q_obj_change_vnc_password_arg_members(Visitor *v, q_obj_change_vnc_password_arg *obj, Error **errp);

void visit_type_q_obj_chardev_add_arg_members(Visitor *v, q_obj_chardev_add_arg *obj, Error **errp);

void visit_type_q_obj_chardev_remove_arg_members(Visitor *v, q_obj_chardev_remove_arg *obj, Error **errp);

void visit_type_q_obj_client_migrate_info_arg_members(Visitor *v, q_obj_client_migrate_info_arg *obj, Error **errp);

void visit_type_q_obj_closefd_arg_members(Visitor *v, q_obj_closefd_arg *obj, Error **errp);

void visit_type_q_obj_cpu_add_arg_members(Visitor *v, q_obj_cpu_add_arg *obj, Error **errp);

void visit_type_q_obj_cpu_arg_members(Visitor *v, q_obj_cpu_arg *obj, Error **errp);

void visit_type_q_obj_device_list_properties_arg_members(Visitor *v, q_obj_device_list_properties_arg *obj, Error **errp);

void visit_type_q_obj_device_add_arg_members(Visitor *v, q_obj_device_add_arg *obj, Error **errp);

void visit_type_q_obj_device_del_arg_members(Visitor *v, q_obj_device_del_arg *obj, Error **errp);

void visit_type_q_obj_dump_guest_memory_arg_members(Visitor *v, q_obj_dump_guest_memory_arg *obj, Error **errp);

void visit_type_q_obj_dump_skeys_arg_members(Visitor *v, q_obj_dump_skeys_arg *obj, Error **errp);

void visit_type_q_obj_eject_arg_members(Visitor *v, q_obj_eject_arg *obj, Error **errp);

void visit_type_q_obj_expire_password_arg_members(Visitor *v, q_obj_expire_password_arg *obj, Error **errp);

void visit_type_q_obj_getfd_arg_members(Visitor *v, q_obj_getfd_arg *obj, Error **errp);

void visit_type_q_obj_human_monitor_command_arg_members(Visitor *v, q_obj_human_monitor_command_arg *obj, Error **errp);

void visit_type_q_obj_input_send_event_arg_members(Visitor *v, q_obj_input_send_event_arg *obj, Error **errp);

void visit_type_q_obj_int_wrapper_members(Visitor *v, q_obj_int_wrapper *obj, Error **errp);

void visit_type_q_obj_memsave_arg_members(Visitor *v, q_obj_memsave_arg *obj, Error **errp);

void visit_type_q_obj_migrate_arg_members(Visitor *v, q_obj_migrate_arg *obj, Error **errp);

void visit_type_q_obj_migrate_incoming_arg_members(Visitor *v, q_obj_migrate_incoming_arg *obj, Error **errp);

void visit_type_q_obj_migrate_set_cache_size_arg_members(Visitor *v, q_obj_migrate_set_cache_size_arg *obj, Error **errp);

void visit_type_q_obj_migrate_set_capabilities_arg_members(Visitor *v, q_obj_migrate_set_capabilities_arg *obj, Error **errp);

void visit_type_q_obj_migrate_set_downtime_arg_members(Visitor *v, q_obj_migrate_set_downtime_arg *obj, Error **errp);

void visit_type_q_obj_migrate_set_speed_arg_members(Visitor *v, q_obj_migrate_set_speed_arg *obj, Error **errp);

void visit_type_q_obj_nbd_server_add_arg_members(Visitor *v, q_obj_nbd_server_add_arg *obj, Error **errp);

void visit_type_q_obj_nbd_server_start_arg_members(Visitor *v, q_obj_nbd_server_start_arg *obj, Error **errp);

void visit_type_q_obj_netdev_add_arg_members(Visitor *v, q_obj_netdev_add_arg *obj, Error **errp);

void visit_type_q_obj_netdev_del_arg_members(Visitor *v, q_obj_netdev_del_arg *obj, Error **errp);

void visit_type_q_obj_object_add_arg_members(Visitor *v, q_obj_object_add_arg *obj, Error **errp);

void visit_type_q_obj_object_del_arg_members(Visitor *v, q_obj_object_del_arg *obj, Error **errp);

void visit_type_q_obj_pmemsave_arg_members(Visitor *v, q_obj_pmemsave_arg *obj, Error **errp);

void visit_type_q_obj_qom_get_arg_members(Visitor *v, q_obj_qom_get_arg *obj, Error **errp);

void visit_type_q_obj_qom_list_arg_members(Visitor *v, q_obj_qom_list_arg *obj, Error **errp);

void visit_type_q_obj_qom_list_types_arg_members(Visitor *v, q_obj_qom_list_types_arg *obj, Error **errp);

void visit_type_q_obj_qom_set_arg_members(Visitor *v, q_obj_qom_set_arg *obj, Error **errp);

void visit_type_q_obj_query_blockstats_arg_members(Visitor *v, q_obj_query_blockstats_arg *obj, Error **errp);

void visit_type_q_obj_query_command_line_options_arg_members(Visitor *v, q_obj_query_command_line_options_arg *obj, Error **errp);

void visit_type_q_obj_query_cpu_model_baseline_arg_members(Visitor *v, q_obj_query_cpu_model_baseline_arg *obj, Error **errp);

void visit_type_q_obj_query_cpu_model_comparison_arg_members(Visitor *v, q_obj_query_cpu_model_comparison_arg *obj, Error **errp);

void visit_type_q_obj_query_cpu_model_expansion_arg_members(Visitor *v, q_obj_query_cpu_model_expansion_arg *obj, Error **errp);

void visit_type_q_obj_query_rocker_arg_members(Visitor *v, q_obj_query_rocker_arg *obj, Error **errp);

void visit_type_q_obj_query_rocker_of_dpa_flows_arg_members(Visitor *v, q_obj_query_rocker_of_dpa_flows_arg *obj, Error **errp);

void visit_type_q_obj_query_rocker_of_dpa_groups_arg_members(Visitor *v, q_obj_query_rocker_of_dpa_groups_arg *obj, Error **errp);

void visit_type_q_obj_query_rocker_ports_arg_members(Visitor *v, q_obj_query_rocker_ports_arg *obj, Error **errp);

void visit_type_q_obj_query_rx_filter_arg_members(Visitor *v, q_obj_query_rx_filter_arg *obj, Error **errp);

void visit_type_q_obj_remove_fd_arg_members(Visitor *v, q_obj_remove_fd_arg *obj, Error **errp);

void visit_type_q_obj_ringbuf_read_arg_members(Visitor *v, q_obj_ringbuf_read_arg *obj, Error **errp);

void visit_type_q_obj_ringbuf_write_arg_members(Visitor *v, q_obj_ringbuf_write_arg *obj, Error **errp);

void visit_type_q_obj_screendump_arg_members(Visitor *v, q_obj_screendump_arg *obj, Error **errp);

void visit_type_q_obj_send_key_arg_members(Visitor *v, q_obj_send_key_arg *obj, Error **errp);

void visit_type_q_obj_set_link_arg_members(Visitor *v, q_obj_set_link_arg *obj, Error **errp);

void visit_type_q_obj_set_password_arg_members(Visitor *v, q_obj_set_password_arg *obj, Error **errp);

void visit_type_q_obj_trace_event_get_state_arg_members(Visitor *v, q_obj_trace_event_get_state_arg *obj, Error **errp);

void visit_type_q_obj_trace_event_set_state_arg_members(Visitor *v, q_obj_trace_event_set_state_arg *obj, Error **errp);

void visit_type_q_obj_transaction_arg_members(Visitor *v, q_obj_transaction_arg *obj, Error **errp);

void visit_type_q_obj_x_blockdev_change_arg_members(Visitor *v, q_obj_x_blockdev_change_arg *obj, Error **errp);

void visit_type_q_obj_x_blockdev_insert_medium_arg_members(Visitor *v, q_obj_x_blockdev_insert_medium_arg *obj, Error **errp);

void visit_type_q_obj_x_blockdev_remove_medium_arg_members(Visitor *v, q_obj_x_blockdev_remove_medium_arg *obj, Error **errp);

void visit_type_q_obj_xen_load_devices_state_arg_members(Visitor *v, q_obj_xen_load_devices_state_arg *obj, Error **errp);

void visit_type_q_obj_xen_save_devices_state_arg_members(Visitor *v, q_obj_xen_save_devices_state_arg *obj, Error **errp);

void visit_type_q_obj_xen_set_global_dirty_log_arg_members(Visitor *v, q_obj_xen_set_global_dirty_log_arg *obj, Error **errp);

void visit_type_q_obj_xen_set_replication_arg_members(Visitor *v, q_obj_xen_set_replication_arg *obj, Error **errp);

#endif
