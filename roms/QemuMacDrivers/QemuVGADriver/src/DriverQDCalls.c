#include "VideoDriverPrivate.h"
#include "VideoDriverPrototypes.h"
#include "DriverQDCalls.h"
#include "QemuVga.h"

#define MAX_DEPTH_MODE	kDepthMode3

static UInt8 DepthToDepthMode(UInt8 depth)
{
	switch (depth) {
	case 8:
		return kDepthMode1;
	case 15:
	case 16:
		return kDepthMode2;
	case 24:
	case 32:
		return kDepthMode3;
	default:
		return kDepthMode1;
	}
}

static UInt8 DepthModeToDepth(UInt8 mode)
{
	switch (mode) {
	case kDepthMode1:
		return 8;
	case kDepthMode2:
		return 15;
	case kDepthMode3:
		return 32;
	default:
		return 8;
	}
}

/************************ Color Table Stuff ****************************/

static OSStatus
GraphicsCoreDoSetEntries(VDSetEntryRecord *entryRecord, Boolean directDevice, UInt32 start, UInt32 stop, Boolean useValue)
{
	UInt32 i;
	
	CHECK_OPEN( controlErr );
	if (GLOBAL.depth != 8)
		return controlErr;
	if (NULL == entryRecord->csTable)
		return controlErr;
	
	/* Note that stop value is included in the range */
	for(i=start;i<=stop;i++) {
		UInt32	colorIndex = useValue ? entryRecord->csTable[i].value : i;
		QemuVga_SetColorEntry(colorIndex, &entryRecord->csTable[i].rgb);
	}
	
	return noErr;
}

OSStatus
GraphicsCoreSetEntries(VDSetEntryRecord *entryRecord)
{
	Boolean useValue	= (entryRecord->csStart < 0);
	UInt32	start		= useValue ? 0UL : (UInt32)entryRecord->csStart;
	UInt32	stop		= start + entryRecord->csCount;

	Trace(GraphicsCoreSetEntries);

	return GraphicsCoreDoSetEntries(entryRecord, false, start, stop, useValue);
}
						
OSStatus
GraphicsCoreDirectSetEntries(VDSetEntryRecord *entryRecord)
{
	Boolean useValue	= (entryRecord->csStart < 0);
	UInt32	start		= useValue ? 0 : entryRecord->csStart;
	UInt32	stop		= start + entryRecord->csCount;

	Trace(GraphicsCoreDirectSetEntries);
	
	return GraphicsCoreDoSetEntries(entryRecord, true, start, stop, useValue);
}

OSStatus
GraphicsCoreGetEntries(VDSetEntryRecord *entryRecord)
{
	Boolean useValue	= (entryRecord->csStart < 0);
	UInt32	start		= useValue ? 0UL : (UInt32)entryRecord->csStart;
	UInt32	stop		= start + entryRecord->csCount;
	UInt32	i;
	
	Trace(GraphicsCoreGetEntries);

	if (GLOBAL.depth != 8)
		return controlErr;
	for(i=start;i<=stop;i++) {
		UInt32	colorIndex = useValue ? entryRecord->csTable[i].value : i;
		QemuVga_GetColorEntry(colorIndex, &entryRecord->csTable[i].rgb);
	}

	return noErr;
}

/************************ Gamma ****************************/

OSStatus
GraphicsCoreSetGamma(VDGammaRecord *gammaRec)
{
	CHECK_OPEN( controlErr );
		
	return noErr;
}

OSStatus
GraphicsCoreGetGammaInfoList(VDGetGammaListRec *gammaList)
{
	Trace(GraphicsCoreGammaInfoList);

	return statusErr;
}

OSStatus
GraphicsCoreRetrieveGammaTable(VDRetrieveGammaRec *gammaRec)
{
	Trace(GraphicsCoreRetrieveGammaTable);

	return statusErr;
}

OSStatus
GraphicsCoreGetGamma(VDGammaRecord *gammaRecord)
{
	CHECK_OPEN( statusErr );
		
	Trace(GraphicsCoreGetGamma);

	gammaRecord->csGTable = NULL;

	return noErr;
}


/************************ Gray pages ****************************/
			
OSStatus
GraphicsCoreGrayPage(VDPageInfo *pageInfo)
{
	UInt32 pageCount;

	CHECK_OPEN( controlErr );
		
	Trace(GraphicsCoreGrayPage);

	QemuVga_GetModePages(GLOBAL.curMode, GLOBAL.depth, NULL, &pageCount);
	if (pageInfo->csPage >= pageCount)
		return paramErr;
	
	/* XXX Make it gray ! */
	return noErr;
}
			
OSStatus
GraphicsCoreSetGray(VDGrayRecord *grayRecord)
{
	CHECK_OPEN( controlErr );
	
	Trace(GraphicsCoreSetGray);

	GLOBAL.qdLuminanceMapping	= grayRecord->csMode;
	return noErr;
}


OSStatus
GraphicsCoreGetPages(VDPageInfo *pageInfo)
{
	UInt32 pageCount, depth;

	CHECK_OPEN( statusErr );

	Trace(GraphicsCoreGetPages);

	depth = DepthModeToDepth(pageInfo->csMode);
	QemuVga_GetModePages(GLOBAL.curMode, depth, NULL, &pageCount);
	pageInfo->csPage = pageCount;

	return noErr;
}

			
OSStatus
GraphicsCoreGetGray(VDGrayRecord *grayRecord)
{
	CHECK_OPEN( statusErr );
		
	Trace(GraphicsCoreGetGray);
		
	grayRecord->csMode = (GLOBAL.qdLuminanceMapping);
	
	return noErr;
}

/************************ Hardware Cursor ****************************/

OSStatus
GraphicsCoreSupportsHardwareCursor(VDSupportsHardwareCursorRec *hwCursRec)
{
	CHECK_OPEN( statusErr );
		
	Trace(GraphicsCoreSupportsHardwareCursor);

	hwCursRec->csReserved1 = 0;
	hwCursRec->csReserved2 = 0;

	hwCursRec->csSupportsHardwareCursor = false;

	return noErr;
}

OSStatus
GraphicsCoreSetHardwareCursor(VDSetHardwareCursorRec *setHwCursRec)
{
	Trace(GraphicsCoreSetHardwareCursor);

	return controlErr;
}

OSStatus
GraphicsCoreDrawHardwareCursor(VDDrawHardwareCursorRec *drawHwCursRec)
{
	Trace(GraphicsCoreDrawHardwareCursor);

	return controlErr;
}

OSStatus
GraphicsCoreGetHardwareCursorDrawState(VDHardwareCursorDrawStateRec *hwCursDStateRec)
{
	Trace(GraphicsCoreGetHardwareCursorDrawState);

	return statusErr;
}

/************************ Misc ****************************/

OSStatus
GraphicsCoreSetInterrupt(VDFlagRecord *flagRecord)
{
	CHECK_OPEN( controlErr );

	Trace(GraphicsCoreSetInterrupt);

	if (!flagRecord->csMode)
	    QemuVga_EnableInterrupts();
	else
	    QemuVga_DisableInterrupts();

	return noErr;
}

OSStatus
GraphicsCoreGetInterrupt(VDFlagRecord *flagRecord)
{
	Trace(GraphicsCoreGetInterrupt);

	CHECK_OPEN( statusErr );
		
	flagRecord->csMode = !GLOBAL.qdInterruptsEnable;
	return noErr;
}

OSStatus
GraphicsCoreSetSync(VDSyncInfoRec *syncInfo)
{
	UInt8 sync, mask;

	Trace(GraphicsCoreSetSync);

	CHECK_OPEN( controlErr );

	sync = syncInfo->csMode;
	mask = syncInfo->csFlags;	

	/* Unblank shortcut */
	if (sync == 0 && mask == 0) {
		sync = 0;
		mask = kDPMSSyncMask;
	}
	/* Blank shortcut */
	if (sync == 0xff && mask == 0xff) {
		sync = 0x7;
		mask = kDPMSSyncMask;
	}
	
	lprintf("SetSync req: sync=%x mask=%x\n", sync, mask);
	
	/* Only care about the DPMS mode */
	if ((mask & kDPMSSyncMask) == 0)
		return noErr;
	
	/* If any sync is disabled, blank */
	if (sync & kDPMSSyncMask)
		QemuVga_Blank(true);
	else
		QemuVga_Blank(false);

	return noErr;
}

OSStatus
GraphicsCoreGetSync(VDSyncInfoRec *syncInfo)
{
	Trace(GraphicsCoreGetSync);

	if (syncInfo->csMode == 0xff) {
		/* Return HW caps */
		syncInfo->csMode = (1 << kDisableHorizontalSyncBit) |
						   (1 << kDisableVerticalSyncBit) |
						   (1 << kDisableCompositeSyncBit) |
						   (1 << kNoSeparateSyncControlBit);
	} else if (syncInfo->csMode == 0x00){
		syncInfo->csMode = GLOBAL.blanked ? kDPMSSyncMask : 0;
	} else
		return statusErr;

	syncInfo->csFlags = 0;

	return noErr;
}

OSStatus
GraphicsCoreSetPowerState(VDPowerStateRec *powerStateRec)
{
	Trace(GraphicsCoreSetPowerState);

	return paramErr;
}

OSStatus
GraphicsCoreGetPowerState(VDPowerStateRec *powerStateRec)
{
	Trace(GraphicsCoreGetPowerState);

	return paramErr;
}
		
OSStatus
GraphicsCoreSetPreferredConfiguration(VDSwitchInfoRec *switchInfo)
{
	Trace(GraphicsCoreSetPreferredConfiguration);

	CHECK_OPEN( controlErr );
	
	return noErr;
}


OSStatus
GraphicsCoreGetPreferredConfiguration(VDSwitchInfoRec *switchInfo)
{
	Trace(GraphicsCoreGetPreferredConfiguration);

	CHECK_OPEN( statusErr );
	
	switchInfo->csMode 	 	= DepthToDepthMode(GLOBAL.bootDepth);
	switchInfo->csData		= GLOBAL.bootMode + 1; /* Modes are 1 based */
	switchInfo->csPage		= 0;
	switchInfo->csBaseAddr	= FB_START;

	return noErr;
}

// €***************** Misc status calls *********************/

OSStatus
GraphicsCoreGetBaseAddress(VDPageInfo *pageInfo)
{
	UInt32 pageCount, pageSize;

	Trace(GraphicsCoreGetBaseAddress);

	CHECK_OPEN( statusErr );

	QemuVga_GetModePages(GLOBAL.curMode, GLOBAL.depth, &pageSize, &pageCount);
	if (pageInfo->csPage >= pageCount)
		return paramErr;
		
	pageInfo->csBaseAddr = FB_START + pageInfo->csPage * pageSize;

	return noErr;
}
			
OSStatus
GraphicsCoreGetConnection(VDDisplayConnectInfoRec *connectInfo)
{
	Trace(GraphicsCoreGetConnection);

	CHECK_OPEN( statusErr );
		
	connectInfo->csDisplayType			= kVGAConnect;
	connectInfo->csConnectTaggedType	= 0;
	connectInfo->csConnectTaggedData	= 0;

	connectInfo->csConnectFlags		=
		(1 << kTaggingInfoNonStandard) | (1 << kUncertainConnection);
		
	connectInfo->csDisplayComponent		= 0;
	
	return noErr;
}

OSStatus
GraphicsCoreGetMode(VDPageInfo *pageInfo)
{
	Trace(GraphicsCoreGetMode);

	CHECK_OPEN( statusErr );
	
	pageInfo->csMode		= DepthToDepthMode(GLOBAL.depth);
	pageInfo->csPage		= GLOBAL.curPage;
	pageInfo->csBaseAddr	= GLOBAL.curBaseAddress;

	return noErr;
}

OSStatus
GraphicsCoreGetCurrentMode(VDSwitchInfoRec *switchInfo)
{
	Trace(GraphicsCoreGetCurrentMode);

	CHECK_OPEN( statusErr );
	
	//lprintf("GetCurrentMode\n");
	switchInfo->csMode		= DepthToDepthMode(GLOBAL.depth);
	switchInfo->csData		= GLOBAL.curMode + 1;
	switchInfo->csPage		= GLOBAL.curPage;
	switchInfo->csBaseAddr	= GLOBAL.curBaseAddress;

	return noErr;
}

/********************** Video mode *****************************/
						
OSStatus
GraphicsCoreGetModeTiming(VDTimingInfoRec *timingInfo)
{
	Trace(GraphicsCoreGetModeTiming);

	CHECK_OPEN( statusErr );

	if (timingInfo->csTimingMode < 1 || timingInfo->csTimingMode > GLOBAL.numModes )
		return paramErr;
	
	timingInfo->csTimingFlags	=
		(1 << kModeValid) | (1 << kModeDefault) | (1 <<kModeSafe);

	timingInfo->csTimingFormat	= kDeclROMtables;
	timingInfo->csTimingData	= timingVESA_640x480_60hz;

	return noErr;
}


OSStatus
GraphicsCoreSetMode(VDPageInfo *pageInfo)
{
	UInt32 newDepth, newPage, pageCount;

	Trace(GraphicsCoreSetMode);

	CHECK_OPEN(controlErr);

	newDepth = DepthModeToDepth(pageInfo->csMode);
	newPage = pageInfo->csPage;
	QemuVga_GetModePages(GLOBAL.curMode, newDepth, NULL, &pageCount);

	lprintf("Requested depth=%d page=%d\n", newDepth, newPage);
	if (pageInfo->csPage >= pageCount)
		return paramErr;
	
	if (newDepth != GLOBAL.depth || newPage != GLOBAL.curPage)
		QemuVga_SetMode(GLOBAL.curMode, newDepth, newPage);
	
	pageInfo->csBaseAddr = GLOBAL.curBaseAddress;
	lprintf("Returning BA: %lx\n", pageInfo->csBaseAddr);

	return noErr;
}			


OSStatus
GraphicsCoreSwitchMode(VDSwitchInfoRec *switchInfo)
{
	UInt32 newMode, newDepth, newPage, pageCount;

	Trace(GraphicsCoreSwitchMode);

	CHECK_OPEN(controlErr);
	
	newMode = switchInfo->csData - 1;
	newDepth = DepthModeToDepth(switchInfo->csMode);
	newPage = switchInfo->csPage;
	QemuVga_GetModePages(GLOBAL.curMode, newDepth, NULL, &pageCount);

	if (newPage >= pageCount)
		return paramErr;

	if (newMode != GLOBAL.curMode || newDepth != GLOBAL.depth ||
	    newPage != GLOBAL.curPage) {
		if (QemuVga_SetMode(newMode, newDepth, newPage))
			return controlErr;
	}
	switchInfo->csBaseAddr = GLOBAL.curBaseAddress;

	return noErr;
}

OSStatus
GraphicsCoreGetNextResolution(VDResolutionInfoRec *resInfo)
{
	UInt32 width, height;
	int id = resInfo->csPreviousDisplayModeID;

	Trace(GraphicsCoreGetNextResolution);

	CHECK_OPEN(statusErr);

	if (id == kDisplayModeIDFindFirstResolution)
		id = 0;
	else if (id == kDisplayModeIDCurrent)
		id = GLOBAL.curMode;
	id++;
	
	if (id == GLOBAL.numModes + 1) {
		resInfo->csDisplayModeID = kDisplayModeIDNoMoreResolutions;
		return noErr;
	}
	if (id < 1 || id > GLOBAL.numModes)
		return paramErr;
	
	if (QemuVga_GetModeInfo(id - 1, &width, &height))
		return paramErr;

	resInfo->csDisplayModeID	= id;
	resInfo->csHorizontalPixels	= width;
	resInfo->csVerticalLines	= height;
	resInfo->csRefreshRate		= 60;
	resInfo->csMaxDepthMode		= MAX_DEPTH_MODE; /* XXX Calculate if it fits ! */

	return noErr;
}

// Looks quite a bit hard-coded, isn't it ?
OSStatus
GraphicsCoreGetVideoParams(VDVideoParametersInfoRec *videoParams)
{
	UInt32 width, height, depth, rowBytes, pageCount;
	OSStatus err = noErr;
	
	Trace(GraphicsCoreGetVideoParams);

	CHECK_OPEN(statusErr);
 		
	if (videoParams->csDisplayModeID < 1 || videoParams->csDisplayModeID > GLOBAL.numModes)
		return paramErr;
	if (videoParams->csDepthMode > MAX_DEPTH_MODE)
		return paramErr;
	if (QemuVga_GetModeInfo(videoParams->csDisplayModeID - 1, &width, &height))
		return paramErr;
	
	depth = DepthModeToDepth(videoParams->csDepthMode);
	QemuVga_GetModePages(videoParams->csDisplayModeID - 1, depth, NULL, &pageCount);
	videoParams->csPageCount = pageCount;
	lprintf("Video Params says %d pages\n", pageCount);
	
	rowBytes = width * ((depth + 7) / 8);
	(videoParams->csVPBlockPtr)->vpBaseOffset 		= 0;			// For us, it's always 0
	(videoParams->csVPBlockPtr)->vpBounds.top 		= 0;			// Always 0
	(videoParams->csVPBlockPtr)->vpBounds.left 		= 0;			// Always 0
	(videoParams->csVPBlockPtr)->vpVersion 			= 0;			// Always 0
	(videoParams->csVPBlockPtr)->vpPackType 		= 0;			// Always 0
	(videoParams->csVPBlockPtr)->vpPackSize 		= 0;			// Always 0
	(videoParams->csVPBlockPtr)->vpHRes 			= 0x00480000;	// Hard coded to 72 dpi
	(videoParams->csVPBlockPtr)->vpVRes 			= 0x00480000;	// Hard coded to 72 dpi
	(videoParams->csVPBlockPtr)->vpPlaneBytes 		= 0;			// Always 0
	(videoParams->csVPBlockPtr)->vpBounds.bottom	= height;
	(videoParams->csVPBlockPtr)->vpBounds.right		= width;
	(videoParams->csVPBlockPtr)->vpRowBytes			= rowBytes;

	switch (depth) {
	case 8:
		videoParams->csDeviceType 						= clutType;
		(videoParams->csVPBlockPtr)->vpPixelType 		= 0;
		(videoParams->csVPBlockPtr)->vpPixelSize 		= 8;
		(videoParams->csVPBlockPtr)->vpCmpCount 		= 1;
		(videoParams->csVPBlockPtr)->vpCmpSize 			= 8;
		(videoParams->csVPBlockPtr)->vpPlaneBytes 		= 0;
		break;
	case 15:
	case 16:
		videoParams->csDeviceType 						= directType;
		(videoParams->csVPBlockPtr)->vpPixelType 		= 16;
		(videoParams->csVPBlockPtr)->vpPixelSize 		= 16;
		(videoParams->csVPBlockPtr)->vpCmpCount 		= 3;
		(videoParams->csVPBlockPtr)->vpCmpSize 			= 5;
		(videoParams->csVPBlockPtr)->vpPlaneBytes 		= 0;
		break;
	case 32:
		videoParams->csDeviceType 						= directType;
		(videoParams->csVPBlockPtr)->vpPixelType 		= 16;
		(videoParams->csVPBlockPtr)->vpPixelSize 		= 32;
		(videoParams->csVPBlockPtr)->vpCmpCount 		= 3;
		(videoParams->csVPBlockPtr)->vpCmpSize 			= 8;
		(videoParams->csVPBlockPtr)->vpPlaneBytes 		= 0;
		break;
	default:
		err = paramErr;
		break;
	}

	return err;
}
