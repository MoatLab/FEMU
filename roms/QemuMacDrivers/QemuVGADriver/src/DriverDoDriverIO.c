/* Simple PCI video driver for use with Mac-On-Linux emulator
 *
 * Basically, this driver forward Apple video driver calls to
 * the emulator via a fake HW (and later, a "sc" based API).
*/

#include "VideoDriverPrivate.h"
#include "VideoDriverPrototypes.h"
#include "DriverQDCalls.h"
#include "QemuVga.h"

DriverDescription TheDriverDescription = {
	/*
	 * Signature info
	 */
	kTheDescriptionSignature,		/* OSType driverDescSignature */
	kInitialDriverDescriptor,		/* DriverDescVersion driverDescVersion */
	QEMU_PCI_VIDEO_NAME,
	0x01, 0x01,
	0, 0,
	/*
	 * DriverOSRuntime driverOSRuntimeInfo
	 */
	0					/* RuntimeOptions driverRuntime */
	| (0 * kDriverIsLoadedUponDiscovery)	/* Loader runtime options */
	| (1 * kDriverIsOpenedUponLoad)		/* Opened when loaded */
	| (1 * kDriverIsUnderExpertControl)	/* I/O expert handles loads/opens */
	| (0 * kDriverIsConcurrent)		/* concurrent */
	| (0 * kDriverQueuesIOPB),		/* Internally queued */
	QEMU_PCI_VIDEO_PNAME,			/* Str31 driverName (OpenDriver param) */
	0, 0, 0, 0, 0, 0, 0, 0,			/* UInt32 driverDescReserved[8] */
	/*
	 * DriverOSService Information. This section contains a vector count followed by
	 * a vector of structures, each defining a driver service.
	 */
	1,					/* ServiceCount nServices */
	/*
	 * DriverServiceInfo service[0]
	 */
	kServiceCategoryNdrvDriver,		/* OSType serviceCategory */
	kNdrvTypeIsVideo,				/* OSType serviceType */
	1, 0, 0, 0
};

/*
 * All driver-global information is in a structure defined in NCRDriverPrivate.
 * Note that "modern" drivers do not have access to their dce. In native Power PC
 * environments, the global world is created by the Code Fragment Manager (hmm,
 * perhaps it is created by CFMInitialize).
 */
DriverGlobal	gDriverGlobal;

/*
 * DoDriverIO
 *
 * In the new driver environment, DoDriverIO performs all driver
 * functions. It is called with the following parameters:
 *	IOCommandID		A unique reference for this driver request. In
 *				the emulated environment, this will be the ParamBlkPtr
 *				passed in from the Device Manager.
 *
 *	IOCommandContents	A union structure that contains information for the
 *				specific request. For the emulated environment, this
 *				will contain the following:
 *		Initialize	Driver RefNum and the name registry id for this driver.
 *		Finalize	Driver RefNum and the name registry id for this driver. 
 *		Others		The ParamBlkPtr
 *
 *	IOCommandCode		A switch value that specifies the required function.
 *
 *	IOCommandKind		A bit-mask indicating Synchronous, Asynchronous, and Immediate
 *
 * For Synchronous and Immediate commands, DoDriverIO returns the final status to
 * the Device Manager. For Asynchronous commands, DoDriverIO may return kIOBusyStatus.
 * If it returns busy status, the driver promises to call IOCommandIsComplete when
 * the transaction has completed.
 */
OSStatus
DoDriverIO( AddressSpaceID addressSpaceID, IOCommandID ioCommandID, IOCommandContents ioCommandContents,
	    IOCommandCode ioCommandCode, IOCommandKind ioCommandKind )
{
	OSStatus status;

	/*
	 * Note: Initialize, Open, KillIO, Close, and Finalize are either synchronous
	 * or immediate. Read, Write, Control, and Status may be immediate,
	 * synchronous, or asynchronous.
	 */

	lprintf("DoDriverIO cmdCode=%d\n", ioCommandCode);

	switch( ioCommandCode ) {
	case kInitializeCommand:			/* Always immediate */
		status = DriverInitializeCmd(addressSpaceID, ioCommandContents.initialInfo);
		CheckStatus(status, "Initialize failed");
		break;
	case kFinalizeCommand:				/* Always immediate */
		status = DriverFinalizeCmd(ioCommandContents.finalInfo);
		break;
	case kSupersededCommand:
		status = DriverSupersededCmd(ioCommandContents.supersededInfo, FALSE);
		break;
	case kReplaceCommand:				/* replace an old driver */
		status = DriverReplaceCmd(addressSpaceID, ioCommandContents.replaceInfo);
		break;
	case kOpenCommand:				/* Always immediate */
		status = DriverOpenCmd(addressSpaceID, ioCommandContents.pb);
		break;
	case kCloseCommand:				/* Always immediate */
		status = DriverCloseCmd(ioCommandContents.pb);
		break;
	case kControlCommand:
		/* lprintf("kControlCommand\n"); */				
		status = DriverControlCmd( addressSpaceID, ioCommandID, ioCommandKind,
					   (CntrlParam*)ioCommandContents.pb );
		break;
	case kStatusCommand:
		status = DriverStatusCmd( ioCommandID, ioCommandKind, 
					  (CntrlParam *)ioCommandContents.pb );
		break;
	case kReadCommand:
		status = DriverReadCmd(	addressSpaceID, ioCommandID, ioCommandKind,
					ioCommandContents.pb );
		break;
	case kWriteCommand:
		status = DriverWriteCmd( addressSpaceID, ioCommandID, ioCommandKind,
					 ioCommandContents.pb);
		break;
	case kKillIOCommand:				/* Always immediate */
		status = DriverKillIOCmd(ioCommandContents.pb);
		break;
	default:
		status = paramErr;
		break;
	}
	lprintf("Completing with status=%d (kind: %x)\n", status, ioCommandKind);

	/*
	 * Force a valid result for immediate commands -- they must return a valid
	 * status to the Driver Manager: returning kIOBusyStatus would be a bug..
	 * Non-immediate commands return a status from the lower-level routine. If the
	 * status is kIOBusyStatus, we just return -- an asynchronous I/O completion
	 * routine will eventually complete the request. If it's some other status, the
	 * lower-level routine has completed a non-immediate task, so we call
	 * IOCommandIsComplete and return its (presumably noErr) status.
	 */
	if( (ioCommandKind & kImmediateIOCommandKind) != 0 ) {
		;	/* Immediate commands return the operation status */
	}
	else if (status == ioInProgress) {
		/*
		 * An asynchronous operation is in progress. The driver handler promises
		 * to call IOCommandIsComplete when the operation concludes.
		 */
		status = noErr;
	} else {
		/*
		 * Normal command that completed synchronously. Dequeue the user's
		 * parameter block.
		 */
		status = (OSStatus)IOCommandIsComplete(ioCommandID, (OSErr)status);
	}
	return status;
}

/*
 * DriverInitializeCmd
 *
 * The New Driver Manager calls this when the driver is first opened.
 */
OSStatus
DriverInitializeCmd( AddressSpaceID addressSpaceID, DriverInitInfoPtr driverInitInfoPtr )
{
	OSStatus status;
		
	Trace(DriverInitializeCmd);

	lprintf("** First call:\n");
	lprintf("   DoDriverIO       @ %p\n", DoDriverIO);
	lprintf("   DriverStatusCmd  @ %p\n", DriverStatusCmd);
	lprintf("   DriverControlCmd @ %p\n", DriverControlCmd);
	
	GLOBAL.refNum = driverInitInfoPtr->refNum;
	GLOBAL.openCount = 0;
	GLOBAL.inInterrupt = false;
	GLOBAL.hasTimer = false;
	
	RegistryEntryIDInit( &GLOBAL.deviceEntry );
	status = RegistryEntryIDCopy( &driverInitInfoPtr->deviceEntry, &GLOBAL.deviceEntry );
	if( status != noErr )
		return status;

	GLOBAL.isOpen = false;
	GLOBAL.qdInterruptsEnable = false;
	GLOBAL.qdVBLInterrupt = NULL;

	GLOBAL.boardFBAddress = GetDeviceBARAddress(&GLOBAL.deviceEntry,
												QEMU_PCI_VIDEO_BASE_REG,
												&GLOBAL.boardFBMappedSize,
												NULL);
	if (GLOBAL.boardFBAddress == NULL) {
		status = paramErr;
		goto bail;
	}
	lprintf("boardFBAddress %08lX boardFBMappedSize %08lX\n", 
			GLOBAL.boardFBAddress, GLOBAL.boardFBMappedSize);

	GLOBAL.boardRegAddress = GetDeviceBARAddress(&GLOBAL.deviceEntry,
												 QEMU_PCI_VIDEO_MMIO_REG,
												 &GLOBAL.boardRegMappedSize,
												 NULL);
	if (GLOBAL.boardRegAddress == NULL) {
		status = paramErr;
		goto bail;
	}
	lprintf("boardRegAddress %08lX boardRegMappedSize %08lX\n", 
			GLOBAL.boardRegAddress, GLOBAL.boardRegMappedSize);


	lprintf("Enabling memory space..\n");
	status = EnablePCIMemorySpace(&GLOBAL.deviceEntry);
	if (status != noErr) {
		lprintf("EnablePCIMemorySpace returned %d\n", status);
		goto bail;
	}

	status = QemuVga_Init();
	if (status != noErr)
		goto bail;
	
bail:
	DBG(lprintf("Driver init result: %d\n", status));
	
	return status;
}

/*
 * DriverReplaceCmd
 *
 * We are replacing an existing driver -- or are completing an initialization sequence.
 * Retrieve any state information from the Name Registry (we have none), install
 * our interrupt handlers, and activate the device.
 *
 * We don't use the calledFromInitialize parameter, but it's here so that a driver can
 * distinguish between initialization (fetch only the NVRAM parameter) and replacement
 * (fetch state information that may be left-over from the previous incantation).
 */
OSStatus
DriverReplaceCmd( AddressSpaceID addressSpaceID, DriverReplaceInfoPtr driverReplaceInfoPtr )
{
	OSStatus status;
	
	Trace(DriverReplaceCmd);

	GLOBAL.refNum = driverReplaceInfoPtr->refNum;
	GLOBAL.deviceEntry = driverReplaceInfoPtr->deviceEntry;

	status = DriverInitializeCmd(addressSpaceID, driverReplaceInfoPtr);

	return status;
}

/*
 * DriverFinalizeCmd
 *
 * Process a DoDriverIO finalize command.
 */
OSStatus
DriverFinalizeCmd( DriverFinalInfoPtr driverFinalInfoPtr )
{
	Trace(DriverFinializeCmd);
	(void) DriverSupersededCmd((DriverSupersededInfoPtr) driverFinalInfoPtr, TRUE);
	return noErr;
}

/*
 * DriverSupersededCmd
 *
 * We are shutting down, or being replaced by a later driver. Wait for all I/O to
 * complete and store volatile state in the Name Registry whree it will be retrieved
 * by our replacement.
 */
OSStatus
DriverSupersededCmd( DriverSupersededInfoPtr driverSupersededInfoPtr, Boolean calledFromFinalize )
{
	Trace(DriverSupersededCmd);

	/*
	 * This duplicates DriverKillIOCmd, the correct algorithm would wait for
	 * concurrent I/O to complete. Hmm, what about "infinite wait" I/O, such
	 * as would be posted by a modem server or socket listener? Note that
	 * this section needs to be extended to handle all pending requests.
	 *
	 * It's safe to call CompleteThisRequest, as that routine uses an atomic
	 * operation that allows it to be called when no request is pending without
	 * any possible problems. Since it's a secondary interrupt handler, we
	 * need to call it through the Driver Services Library.
	 *
	 * Warning: GLOBAL.perRequestDataPtr will be NULL if initialization fails
	 * and the Driver Manager tries to terminate us. When we permit concurrent
	 * requests, this will loop on all per-request records.
	 */
	 
	QemuVga_Exit();

	RegistryEntryIDDispose( &GLOBAL.deviceEntry );
	
	return noErr;
}

/*
 * DriverControlCmd
 *
 * Process a PBControl command.
 */
OSStatus
DriverControlCmd( AddressSpaceID addressSpaceID, IOCommandID ioCommandID,
		  IOCommandKind ioCommandKind, CntrlParam *pb )
{
	OSStatus status;
	void *genericPtr;
	
	/* The 'csParam' field of the 'CntrlParam' stucture is defined as 'short csParam[11]'.  This is
	 * meant for 'operation defined parameters.' For the graphics driver, only the first 4 bytes are
	 * used.  They are used as a pointer to another structure.
	 * To help code readability, the pointer will be extracted as a generic 'void *' and then cast as
	 * appropriate.
	 */

	genericPtr = (void *) *((UInt32 *) &(pb->csParam[0]));

	Trace(DriverControlCmd);
	
	switch( pb->csCode ) {
	case cscReset:			// Old obsolete call..return a 'controlErr'
		return controlErr;
		break;
			
	case cscKillIO:			// Old obsolete call..do nothing
		return noErr;

	case cscSetMode:
		status = GraphicsCoreSetMode((VDPageInfo *) genericPtr);
		break;
			
	case cscSetEntries:
		status = GraphicsCoreSetEntries((VDSetEntryRecord *) genericPtr);
		// if ((status == noErr)&&(GLOBAL.qdDeskServiceCreated)&&(ioCommandKind == kSynchronousIOCommandKind))
		// VSLWaitOnInterruptService(GLOBAL.qdVBLInterrupt, 1000);
		break;
			
	case cscSetGamma:
		status = GraphicsCoreSetGamma((VDGammaRecord *) genericPtr);
		break;
			
	case cscGrayPage:
		status = GraphicsCoreGrayPage((VDPageInfo *) genericPtr);
		break;
			
	case cscSetGray:
		status = GraphicsCoreSetGray((VDGrayRecord *) genericPtr);
		break;
			
	case cscSetInterrupt:
		status = GraphicsCoreSetInterrupt((VDFlagRecord *) genericPtr);
		break;
			
	case cscDirectSetEntries:
		status = GraphicsCoreDirectSetEntries((VDSetEntryRecord *) genericPtr);
		break;
			
	case cscSetDefaultMode:
		return controlErr;
		
	case cscSwitchMode:
		status = GraphicsCoreSwitchMode((VDSwitchInfoRec *) genericPtr);
		break;
		
	case cscSetSync:
		status = GraphicsCoreSetSync((VDSyncInfoRec *) genericPtr);
		break;
		
	case cscSavePreferredConfiguration:
		status = GraphicsCoreSetPreferredConfiguration((VDSwitchInfoRec *) genericPtr);
		break;
		
	case cscSetHardwareCursor:
		status = GraphicsCoreSetHardwareCursor((VDSetHardwareCursorRec *) genericPtr);
		break;
		
	case cscDrawHardwareCursor:
		status = GraphicsCoreDrawHardwareCursor((VDDrawHardwareCursorRec *) genericPtr);
		break;
	case cscSetPowerState:
		status = GraphicsCoreSetPowerState((VDPowerStateRec *) genericPtr);
		break;	
	default:
		break;
	}
	if (status)
		status = paramErr;

	return status;
}

/*
 * DriverStatusCmd
 *
 * Process a PBStatus command. We support the driver gestalt call and our private
 * debugging commands.
 */
OSStatus
DriverStatusCmd( IOCommandID ioCommandID, IOCommandKind ioCommandKind, CntrlParam *pb )
{
	OSStatus status;
	void *genericPtr;

	/* The 'csParam' field of the 'CntrlParam' stucture is defined as 'short csParam[11]'.  This is
	 * meant for 'operation defined parameters.' For the graphics driver, only the first 4 bytes are
	 * used.  They are used as a pointer to another structure.
	 * To help code readability, the pointer will be extracted as a generic 'void *' and then cast as
	 * appropriate.
	 */

	genericPtr = (void *) *((UInt32 *) &(pb->csParam[0]));

	Trace(DriverStatusCmd);
	lprintf("csCode=%d\n", pb->csCode);
	switch( pb->csCode ) {
	case cscGetMode:
		status = GraphicsCoreGetMode((VDPageInfo *) genericPtr);
		break;
		
	case cscGetEntries:
		status = GraphicsCoreGetEntries((VDSetEntryRecord *) genericPtr);
		break;
		
	case cscGetPages:
		status = GraphicsCoreGetPages((VDPageInfo *) genericPtr);
		break;
		
	case cscGetBaseAddr:
		status = GraphicsCoreGetBaseAddress((VDPageInfo *) genericPtr);
		break;
		
	case cscGetGray:
		status = GraphicsCoreGetGray((VDGrayRecord *) genericPtr);
		break;
		
	case cscGetInterrupt:
		status = GraphicsCoreGetInterrupt((VDFlagRecord *) genericPtr);
		break;
		
	case cscGetGamma:
		status = GraphicsCoreGetGamma((VDGammaRecord *) genericPtr);
		break;
		
	case cscGetDefaultMode:
		status = statusErr;
		break;
		
	case cscGetCurMode:
		status = GraphicsCoreGetCurrentMode((VDSwitchInfoRec *) genericPtr);
		break;
		
	case cscGetSync:
		status = GraphicsCoreGetSync((VDSyncInfoRec *) genericPtr);
		break;
		
	case cscGetConnection:
		status = GraphicsCoreGetConnection((VDDisplayConnectInfoRec *) genericPtr);
		break;
		
	case cscGetModeTiming:
		status = GraphicsCoreGetModeTiming((VDTimingInfoRec *) genericPtr);
		break;
		
	case cscGetPreferredConfiguration:
		status = GraphicsCoreGetPreferredConfiguration((VDSwitchInfoRec *) genericPtr);
		break;
		
	case cscGetNextResolution:
		status = GraphicsCoreGetNextResolution((VDResolutionInfoRec *) genericPtr);
		break;
		
	case cscGetVideoParameters:
		status = GraphicsCoreGetVideoParams((VDVideoParametersInfoRec *) genericPtr);
		break;
		
	case cscGetGammaInfoList:
		status = GraphicsCoreGetGammaInfoList((VDGetGammaListRec *) genericPtr);
		break;
		
	case cscRetrieveGammaTable:
		status = GraphicsCoreRetrieveGammaTable((VDRetrieveGammaRec *) genericPtr);
		break;
		
	case cscSupportsHardwareCursor:
		status = GraphicsCoreSupportsHardwareCursor((VDSupportsHardwareCursorRec *) genericPtr);
		break;
		
	case cscGetHardwareCursorDrawState:
		status = GraphicsCoreGetHardwareCursorDrawState((VDHardwareCursorDrawStateRec *) genericPtr);
		break;
		
	case kDriverGestaltCode:
		status = DriverGestaltHandler(pb);
		break;
		
	case cscGetPowerState:
		status = GraphicsCoreGetPowerState((VDPowerStateRec *) genericPtr);
		break;
	case cscGetClutBehavior:
		*(VDClutBehaviorPtr)genericPtr = kSetClutAtSetEntries;
		status = noErr;
		break;
	default:
		return statusErr;
	}
	if (status)
		status = paramErr;

	return status;
}

/*
 * DriverKillIOCmd stops all I/O for this chip. It's a big hammer, use it wisely.
 * This will need revision when we support concurrent I/O as we must stop all
 * pending requests.
 */
OSStatus
DriverKillIOCmd( ParmBlkPtr pb )
{
#define REQUEST	(GLOBAL.perRequestData)

	Trace(DriverKillIOCmd);
	return noErr;
#undef REQUEST
}

/*
 * DriverReadCmd
 *
 * The caller passes the data buffer and buffer length in the IOParam record and
 * a pointer to a SCSI NCRSCSIParam in the ioMisc field.
 */
OSStatus
DriverReadCmd( AddressSpaceID addressSpaceID, IOCommandID ioCommandID,
	       IOCommandKind ioCommandKind, ParmBlkPtr pb )
{
	Trace(DriverReadCmd);
	return paramErr;
}


/*
 * DriverWriteCmd
 *
 * The caller passes the data buffer and buffer length in the IOParam record and
 * a pointer to a SCSI NCRSCSIParam in the ioMisc field.
 */
OSStatus
DriverWriteCmd( AddressSpaceID addressSpaceID, IOCommandID ioCommandID,
		IOCommandKind ioCommandKind, ParmBlkPtr pb )
{
	Trace(DriverWriteCmd);
	return paramErr;
}

/*
 * DriverCloseCmd does nothing..
 */
OSStatus
DriverCloseCmd(	ParmBlkPtr pb )
{
	Trace(DriverCloseCmd);
	
	if( !GLOBAL.openCount )
		return notOpenErr;
		
	GLOBAL.openCount--;

	if (!GLOBAL.openCount)
		QemuVga_Close();

	return noErr;
}

/*
 * DriverOpenCmd does nothing: remember that many applications will open a device, but
 * never close it..
 */
OSStatus
DriverOpenCmd( AddressSpaceID addressSpaceID, ParmBlkPtr pb )
{
	Trace(DriverOpenCmd);
	
	GLOBAL.openCount++;
	if (GLOBAL.openCount == 1)
		QemuVga_Open();

	return noErr;
}


