#include "VideoDriverPrivate.h"
#include "VideoDriverPrototypes.h"

/*
 * Called on PBStatus, csCode = 43
 */
OSStatus
DriverGestaltHandler( CntrlParam *pb )
{
#define PB (*((DriverGestaltParam *) pb))
#define OPTIONS	(TheDriverDescription.driverOSRuntimeInfo)

	OSStatus status;
	Trace(DriverGestaltHandler);

	PB.driverGestaltResponse = 0;
	status = noErr;

	lprintf("DriverGestalt, selector=%c%c%c%c\n",
		PB.driverGestaltSelector >> 24,
		(PB.driverGestaltSelector >> 16) & 0xff,
		(PB.driverGestaltSelector >>  8) & 0xff,
		(PB.driverGestaltSelector      ) & 0xff);	
	switch( PB.driverGestaltSelector ) {
	case kdgSync:
		PB.driverGestaltResponse = FALSE;	/* We handle asynchronous I/O */
		break;
	case kdgVersion:
		PB.driverGestaltResponse = 
			*((UInt32 *) &TheDriverDescription.driverType.version);
		break;
	case kdgDeviceType:
		PB.driverGestaltResponse = 'QEMU';
		break;
	case kdgInterface:
		PB.driverGestaltResponse = 'pci ';
		break;
	case kdgSupportsSwitching:			/* Support Power up/down switching? */
		PB.driverGestaltResponse = FALSE;	/* Not supported yet */
		break;
	case kdgSupportsPowerCtl:			/* TRUE if in high-power mode */
		PB.driverGestaltResponse = FALSE;	/* Power-switching is not supported */
		break;
	default:
		status = statusErr;			
		break;
	}
	return status;
#undef PB
}
