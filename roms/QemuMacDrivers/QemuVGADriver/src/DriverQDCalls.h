#ifndef _DRIVER_QD_CALLS_H__
#define _DRIVER_QD_CALLS_H__

// ###ÊCONTROL ROUTINES ###

OSStatus	GraphicsCoreSetMode(VDPageInfo *pageInfo);
OSStatus	GraphicsCoreSetEntries(VDSetEntryRecord *entryRecord);
OSStatus	GraphicsCoreSetGamma(VDGammaRecord *gammaRec);
OSStatus	GraphicsCoreGrayPage(VDPageInfo *pageInfo);
OSStatus	GraphicsCoreSetGray(VDGrayRecord *grayRecord);
OSStatus	GraphicsCoreSetInterrupt(VDFlagRecord *flagRecord);
OSStatus	GraphicsCoreDirectSetEntries(VDSetEntryRecord *entryRecord);
OSStatus	GraphicsCoreSwitchMode(VDSwitchInfoRec *switchInfo);
OSStatus	GraphicsCoreSetSync(VDSyncInfoRec *syncInfo);
OSStatus	GraphicsCoreSetPreferredConfiguration(VDSwitchInfoRec *switchInfo);
OSStatus	GraphicsCoreSetHardwareCursor(VDSetHardwareCursorRec *setHwCursRec);
OSStatus	GraphicsCoreDrawHardwareCursor(VDDrawHardwareCursorRec *drawHwCursRec);
OSStatus	GraphicsCoreSetPowerState(VDPowerStateRec * powerStateRec);

// ### STATUS ROUTINES ###

OSStatus	GraphicsCoreGetMode(VDPageInfo *pageInfo);
OSStatus	GraphicsCoreGetEntries(VDSetEntryRecord *entryRecord);
OSStatus	GraphicsCoreGetPages(VDPageInfo *pageInfo);
OSStatus	GraphicsCoreGetBaseAddress(VDPageInfo *pageInfo);
OSStatus	GraphicsCoreGetGray(VDGrayRecord *grayRecord);
OSStatus	GraphicsCoreGetInterrupt(VDFlagRecord *flagRecord);
OSStatus	GraphicsCoreGetGamma(VDGammaRecord *gammaRecord);
OSStatus	GraphicsCoreGetCurrentMode(VDSwitchInfoRec *switchInfo);
OSStatus	GraphicsCoreGetSync(VDSyncInfoRec *syncInfo);
OSStatus	GraphicsCoreGetConnection(VDDisplayConnectInfoRec *connectInfo);
OSStatus	GraphicsCoreGetModeTiming(VDTimingInfoRec *timingInfo);
OSStatus	GraphicsCoreGetPreferredConfiguration(VDSwitchInfoRec *switchInfo);
OSStatus	GraphicsCoreGetNextResolution(VDResolutionInfoRec *resInfo);
OSStatus	GraphicsCoreGetVideoParams(VDVideoParametersInfoRec *videoParams);
OSStatus	GraphicsCoreGetGammaInfoList(VDGetGammaListRec *gammaList);
OSStatus	GraphicsCoreRetrieveGammaTable(VDRetrieveGammaRec *gammaRec);
OSStatus	GraphicsCoreSupportsHardwareCursor(VDSupportsHardwareCursorRec *hwCursRec);
OSStatus	GraphicsCoreGetHardwareCursorDrawState(VDHardwareCursorDrawStateRec *hwCursDStateRec);
OSStatus	GraphicsCoreGetPowerState(VDPowerStateRec * powerStateRec);

#endif /* DRIVER_QD_CALLS */
