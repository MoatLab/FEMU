#ifndef __VideoDriverPrototypes_H__
#define __VideoDriverPrototypes_H__

#include <PCI.h>
#include "logger.h"

/*
 * The Driver Manager calls DoDriverIO to perform I/O.
 */

OSStatus
DoDriverIO(	AddressSpaceID			addressSpaceID,
		IOCommandID			ioCommandID,
		IOCommandContents		ioCommandContents,
		IOCommandCode			ioCommandCode,
		IOCommandKind			ioCommandKind);

#include "MacDriverUtils.h"

/*
 * Prototypes for the specific driver handlers. These do real work.
 */
OSStatus
DriverInitializeCmd(	AddressSpaceID			addressSpaceID,
			DriverInitInfoPtr		driverInitInfoPtr);

OSStatus
DriverFinalizeCmd(	DriverFinalInfoPtr		driverFinalInfoPtr);

OSStatus
DriverSupersededCmd(	DriverSupersededInfoPtr		driverSupersededInfoPtr,
			Boolean				calledFromFinalize);
			
OSStatus
DriverReplaceCmd(	AddressSpaceID			addressSpaceID,
			DriverReplaceInfoPtr		driverReplaceInfoPtr);
			
OSStatus
DriverOpenCmd(		AddressSpaceID			addressSpaceID,
			ParmBlkPtr			pb);
			
OSStatus
DriverCloseCmd(		ParmBlkPtr			pb);

OSStatus
DriverControlCmd(	AddressSpaceID			addressSpaceID,
			IOCommandID			ioCommandID,
			IOCommandKind			ioCommandKind,
			CntrlParam			*pb);
			
OSStatus
DriverStatusCmd(	IOCommandID			ioCommandID,
			IOCommandKind			ioCommandKind,
			CntrlParam			*pb);
			
OSStatus
DriverKillIOCmd(	ParmBlkPtr			pb);

OSStatus
DriverReadCmd(
			AddressSpaceID			addressSpaceID,
			IOCommandID			ioCommandID,
			IOCommandKind			ioCommandKind,
			ParmBlkPtr			pb);
			
OSStatus
DriverWriteCmd(		AddressSpaceID			addressSpaceID,
			IOCommandID			ioCommandID,
			IOCommandKind			ioCommandKind,
			ParmBlkPtr			pb);

/*	.___________________________________________________________________________________.
  	| Driver Gestalt handler -- called from the PBStatus handler.						|
	.___________________________________________________________________________________.
 */
OSStatus
DriverGestaltHandler(	CntrlParam*			pb);


/*	.___________________________________________________________________________________.
  	| Utitlity function to clear a block of memory.										|
	.___________________________________________________________________________________.
 */
#ifndef CLEAR
#define CLEAR(what)	BlockZero((char*)&what, sizeof what)
#endif

/*
 * This uses the ANSI-C string concatenate and "stringize" operations.
 */
#define Trace(what)	lprintf("Trace: %s\n", #what)

#if 0
static void
CheckStatus(	OSStatus	value,
		char*		message)
{}
#endif

#endif