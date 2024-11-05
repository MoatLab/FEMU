#include "VideoDriverPrivate.h"
#include "VideoDriverPrototypes.h"
#include "DriverQDCalls.h"
#include "QemuVga.h"
#include <Timer.h>

/*
static struct _vMode defaultVModes[] =  {
	{ 640, 480 },
	{ 800, 600 },
	{ 1024, 768 },
	{ 1280, 1024 },
	{ 1600, 1200 },
	{ 1920, 1080 },
	{ 1920, 1200 },
	{ 0, 0 }
};
*/
static void VgaWriteB(UInt16 port, UInt8 val)
{
	UInt8 *ptr;
	
	ptr = (UInt8 *)((UInt32)GLOBAL.boardRegAddress + port + 0x400 - 0x3c0);
	*ptr = val;
	SynchronizeIO();
}

static UInt8 VgaReadB(UInt16 port)
{
	UInt8 *ptr, val;
	
	ptr = (UInt8 *)((UInt32)GLOBAL.boardRegAddress + port + 0x400 - 0x3c0);
	val = *ptr;
	SynchronizeIO();
	return val;
}

static void DispiWriteW(UInt16 reg, UInt16 val)
{
	UInt16 *ptr;
	
	ptr = (UInt16 *)((UInt32)GLOBAL.boardRegAddress + (reg << 1) + 0x500);
	*ptr = EndianSwap16Bit(val);
	SynchronizeIO();
}

static UInt16 DispiReadW(UInt16 reg)
{
	UInt16 *ptr, val;
	
	ptr = (UInt16 *)((UInt32)GLOBAL.boardRegAddress + (reg << 1) + 0x500);
	val = EndianSwap16Bit(*ptr);
	SynchronizeIO();
	return val;
}

static void ExtWriteL(UInt16 reg, UInt32 val)
{
	UInt32 *ptr;
	
	ptr = (UInt32 *)((UInt32)GLOBAL.boardRegAddress + (reg << 2) + 0x600);
	*ptr = EndianSwap32Bit(val);
	SynchronizeIO();
}

static UInt32 ExtReadL(UInt32 reg)
{
	UInt32 *ptr, val;
	
	ptr = (UInt32 *)((UInt32)GLOBAL.boardRegAddress + (reg << 2) + 0x600);
	val = EndianSwap32Bit(*ptr);
	SynchronizeIO();
	return val;
}

static OSStatus VBLTimerProc(void *p1, void *p2);

#ifndef USE_DSL_TIMER
static TMTask gLegacyTimer;

static pascal void legacyTimerCB(TMTaskPtr *inTask)
{
	VBLTimerProc(NULL, NULL);
}

static const RoutineDescriptor	gLegacyTimerDesc	= BUILD_ROUTINE_DESCRIPTOR(uppTimerProcInfo, legacyTimerCB);
static const TimerUPP			gLegacyTimerProc	= (TimerUPP) &gLegacyTimerDesc;
static int gTimerInstalled;

static OSStatus ScheduleVBLTimer(void)
{
	if (!gTimerInstalled) {
		BlockZero(&gLegacyTimer, sizeof(gLegacyTimer));
		gLegacyTimer.tmAddr = gLegacyTimerProc;
		gLegacyTimer.qLink = (QElemPtr)'eada';
		InsXTime((QElemPtr)&gLegacyTimer);
		gTimerInstalled = true;
	}
	PrimeTime((QElemPtr)&gLegacyTimer, TIMER_DURATION);
	return noErr;
}

#else

static OSStatus ScheduleVBLTimer(void)
{
	AbsoluteTime target = AddDurationToAbsolute(TIMER_DURATION, UpTime());
	return SetInterruptTimer(&target, VBLTimerProc, NULL, &GLOBAL.VBLTimerID);
}

#endif

static OSStatus VBLTimerProc(void *p1, void *p2)
{
	static UInt32 VBcnt;

	GLOBAL.inInterrupt = 1;

	/* This can be called before the service is ready */
	if (GLOBAL.qdVBLInterrupt && GLOBAL.qdInterruptsEnable)
		VSLDoInterruptService(GLOBAL.qdVBLInterrupt);
	
	/* Reschedule */
	ScheduleVBLTimer();

	GLOBAL.inInterrupt = 0;
}

#ifdef USE_PCI_IRQ
static InterruptMemberNumber PCIInterruptHandler(InterruptSetMember ISTmember,
												 void *refCon, UInt32 theIntCount)
{
	UInt32 reg;
	
	reg = ExtReadL(2);
	if (!(reg & 1))
		return kIsrIsNotComplete;
	if (GLOBAL.qdVBLInterrupt && GLOBAL.qdInterruptsEnable)
		VSLDoInterruptService(GLOBAL.qdVBLInterrupt);
	ExtWriteL(2, 3);
	return kIsrIsComplete;
}
#endif


OSStatus QemuVga_Init(void)
{
	UInt16 id, i;
	UInt32 mem, width, height, depth;
	Boolean modeFound = false;
	struct vMode *v;

	lprintf("First MMIO read...\n");
	id = DispiReadW(VBE_DISPI_INDEX_ID);
	mem = DispiReadW(VBE_DISPI_INDEX_VIDEO_MEMORY_64K);
	mem <<= 16;
	lprintf("DISPI_ID=%04x VMEM=%d Mb\n", id, mem >> 20);
	if ((id & 0xfff0) != VBE_DISPI_ID0) {
		lprintf("Unsupported ID !\n");
		return controlErr;
	}
	if (mem > GLOBAL.boardFBMappedSize)
		mem = GLOBAL.boardFBMappedSize;
	GLOBAL.vramSize = mem;
	
	// XXX Add endian control regs

	width = DispiReadW(VBE_DISPI_INDEX_XRES);
	height = DispiReadW(VBE_DISPI_INDEX_YRES);
	depth = DispiReadW(VBE_DISPI_INDEX_BPP);
	lprintf("Current setting: %dx%dx%d\n", width, height, depth);

	GLOBAL.depth = GLOBAL.bootDepth = depth;
	GLOBAL.numModes = QemuVga_ReadEdidModes();
	lprintf("Number of modes: %d\n", GLOBAL.numModes);

	for (i = 0, v = vModes; v != NULL; v = v->next, i++) {
		if (width == v->mode->width && height == v->mode->height) {
		    modeFound = true;
			break;
		}
	}

	if (!modeFound) {
		lprintf("Not found in list ! using default.\n");
		i = 0;
	} else {
	    lprintf("Using mode: %d\n", i);
	}
	GLOBAL.bootMode = i;

	QemuVga_SetMode(GLOBAL.bootMode, depth, 0);

#ifdef USE_PCI_IRQ
	if (SetupPCIInterrupt(&GLOBAL.deviceEntry, &GLOBAL.irqInfo,
					   	  PCIInterruptHandler, NULL) == noErr)
		GLOBAL.hasPCIInterrupt = true;
	else
#else
	GLOBAL.hasPCIInterrupt = false;
#endif
	return noErr;
}

OSStatus QemuVga_Open(void)
{
	lprintf("QemuVga v1.00\n");

	GLOBAL.isOpen = true;

	if (GLOBAL.hasPCIInterrupt) {
		QemuVga_EnableInterrupts();
		lprintf("VBL registered using PCI interrupts\n");	
	} else {
		/* Schedule the timer now if timers are supported. They aren't on OS X
		 * in which case we must not create the VSL service, otherwise OS X will expect
		 * a VBL and fail to update the cursor when not getting one.
	 	*/
		lprintf("Testing using timer to simulate VBL..\n");	
		GLOBAL.hasTimer = (ScheduleVBLTimer() == noErr);
		GLOBAL.qdInterruptsEnable = GLOBAL.hasTimer;

		if (GLOBAL.hasTimer)
			lprintf("Using timer to simulate VBL.\n");	
		else
			lprintf("No timer service (OS X ?), VBL not registered.\n");	

	}

	/* Create VBL if we have a PCI interrupt or timer works */
	if (GLOBAL.hasPCIInterrupt || GLOBAL.hasTimer)
		VSLNewInterruptService(&GLOBAL.deviceEntry, kVBLInterruptServiceType, &GLOBAL.qdVBLInterrupt);
	
	return noErr;
}

OSStatus QemuVga_Close(void)
{
	lprintf("Closing Driver...\n");

	GLOBAL.isOpen = false;
	
	QemuVga_DisableInterrupts();
	if (GLOBAL.qdVBLInterrupt)
		VSLDisposeInterruptService( GLOBAL.qdVBLInterrupt );
	GLOBAL.qdVBLInterrupt = NULL;

	return noErr;
}

OSStatus QemuVga_Exit(void)
{
	QemuVga_Close();

	return noErr;
}

void QemuVga_EnableInterrupts(void)
{
	GLOBAL.qdInterruptsEnable = true;
	if (GLOBAL.hasTimer)
		ScheduleVBLTimer();
	else if (GLOBAL.hasPCIInterrupt) {
		GLOBAL.irqInfo.enableFunction(GLOBAL.irqInfo.interruptSetMember, GLOBAL.irqInfo.refCon);
		ExtWriteL(2, 3);
	}
}

void QemuVga_DisableInterrupts(void)
{
	AbsoluteTime remaining;

	GLOBAL.qdInterruptsEnable = false;
	if (GLOBAL.hasTimer)
		CancelTimer(GLOBAL.VBLTimerID, &remaining);
	else if (GLOBAL.hasPCIInterrupt) {
		ExtWriteL(2, 1);
		GLOBAL.irqInfo.disableFunction(GLOBAL.irqInfo.interruptSetMember, GLOBAL.irqInfo.refCon);
	}
}

OSStatus QemuVga_SetColorEntry(UInt32 index, RGBColor *color)
{
	//lprintf("SetColorEntry %d, %x %x %x\n", index, color->red, color->green, color->blue);
	VgaWriteB(0x3c8, index);
	VgaWriteB(0x3c9, color->red >> 8);
	VgaWriteB(0x3c9, color->green >> 8);
	VgaWriteB(0x3c9, color->blue >> 8);
	return noErr;
}

OSStatus QemuVga_GetColorEntry(UInt32 index, RGBColor *color)
{
	UInt32 r,g,b;
	
	VgaWriteB(0x3c7, index);
	r = VgaReadB(0x3c9);
	g = VgaReadB(0x3c9);
	b = VgaReadB(0x3c9);
	color->red = (r << 8) | r;
	color->green = (g << 8) | g;
	color->blue = (b << 8) | b;

	return noErr;
}

OSStatus QemuVga_GetModeInfo(UInt32 index, UInt32 *width, UInt32 *height)
{
	if (index >= GLOBAL.numModes)
		return paramErr;
	if (width)
		*width = getVMode(index)->width;
	if (height)
		*height = getVMode(index)->height;
	return noErr;
}

OSStatus QemuVga_GetModePages(UInt32 index, UInt32 depth,
							  UInt32 *pageSize, UInt32 *pageCount)
{
	UInt32 width, height, pBytes;

	if (index >= GLOBAL.numModes)
		return paramErr;
	width = getVMode(index)->width;
	height = getVMode(index)->height;
	pBytes = width * ((depth + 7) / 8) * height;
	if (pageSize)
		*pageSize = pBytes;
	if (pageCount) {
		if (pBytes <= (GLOBAL.boardFBMappedSize / 2))
			*pageCount = 2;
		else
			*pageCount = 1;
	}
	return noErr;
}

OSStatus QemuVga_SetMode(UInt32 mode, UInt32 depth, UInt32 page)
{
	UInt32 width, height;
	UInt32 pageSize, numPages;

	if (mode >= GLOBAL.numModes)
		return paramErr;
	
	width = getVMode(mode)->width;
	height = getVMode(mode)->height;
	QemuVga_GetModePages(mode, depth, &pageSize, &numPages);
	lprintf("Set Mode: %dx%dx%d has %d pages\n", width, height, depth, numPages);
	if (page >= numPages)
		return paramErr;

	DispiWriteW(VBE_DISPI_INDEX_ENABLE,      0);
	DispiWriteW(VBE_DISPI_INDEX_BPP,         depth);
	DispiWriteW(VBE_DISPI_INDEX_XRES,        width);
	DispiWriteW(VBE_DISPI_INDEX_YRES,        height);
	DispiWriteW(VBE_DISPI_INDEX_BANK,        0);
	DispiWriteW(VBE_DISPI_INDEX_VIRT_WIDTH,  width);
	DispiWriteW(VBE_DISPI_INDEX_VIRT_HEIGHT, height * numPages);
	DispiWriteW(VBE_DISPI_INDEX_X_OFFSET,    0);
	DispiWriteW(VBE_DISPI_INDEX_Y_OFFSET,    height * page);
	DispiWriteW(VBE_DISPI_INDEX_ENABLE,      VBE_DISPI_ENABLED | VBE_DISPI_LFB_ENABLED | VBE_DISPI_8BIT_DAC);	
	GLOBAL.curMode = mode;
	GLOBAL.depth = depth;
	GLOBAL.curPage = page;
	GLOBAL.curBaseAddress = FB_START + page * pageSize;
	
	return noErr;
}

OSStatus QemuVga_Blank(Boolean blank)
{
	/* We use the AR Index VGA register which is a flip flop
	 * so we need to ensure we write twice. We use a non-existing
	 * index so that the second write is dropped.
	 */
	if (blank) {
		VgaWriteB(0x3c0, 0x1f);
		VgaWriteB(0x3c0, 0x1f);
	} else {
		VgaWriteB(0x3c0, 0x3f);
		VgaWriteB(0x3c0, 0x3f);
	}
	GLOBAL.blanked = blank;
}
