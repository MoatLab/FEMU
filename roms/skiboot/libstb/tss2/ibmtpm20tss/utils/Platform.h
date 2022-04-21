/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: Platform.h 1257 2018-06-27 20:52:08Z kgoldman $		*/
/*										*/
/*  Licenses and Notices							*/
/*										*/
/*  1. Copyright Licenses:							*/
/*										*/
/*  - Trusted Computing Group (TCG) grants to the user of the source code in	*/
/*    this specification (the "Source Code") a worldwide, irrevocable, 		*/
/*    nonexclusive, royalty free, copyright license to reproduce, create 	*/
/*    derivative works, distribute, display and perform the Source Code and	*/
/*    derivative works thereof, and to grant others the rights granted herein.	*/
/*										*/
/*  - The TCG grants to the user of the other parts of the specification 	*/
/*    (other than the Source Code) the rights to reproduce, distribute, 	*/
/*    display, and perform the specification solely for the purpose of 		*/
/*    developing products based on such documents.				*/
/*										*/
/*  2. Source Code Distribution Conditions:					*/
/*										*/
/*  - Redistributions of Source Code must retain the above copyright licenses, 	*/
/*    this list of conditions and the following disclaimers.			*/
/*										*/
/*  - Redistributions in binary form must reproduce the above copyright 	*/
/*    licenses, this list of conditions	and the following disclaimers in the 	*/
/*    documentation and/or other materials provided with the distribution.	*/
/*										*/
/*  3. Disclaimers:								*/
/*										*/
/*  - THE COPYRIGHT LICENSES SET FORTH ABOVE DO NOT REPRESENT ANY FORM OF	*/
/*  LICENSE OR WAIVER, EXPRESS OR IMPLIED, BY ESTOPPEL OR OTHERWISE, WITH	*/
/*  RESPECT TO PATENT RIGHTS HELD BY TCG MEMBERS (OR OTHER THIRD PARTIES)	*/
/*  THAT MAY BE NECESSARY TO IMPLEMENT THIS SPECIFICATION OR OTHERWISE.		*/
/*  Contact TCG Administration (admin@trustedcomputinggroup.org) for 		*/
/*  information on specification licensing rights available through TCG 	*/
/*  membership agreements.							*/
/*										*/
/*  - THIS SPECIFICATION IS PROVIDED "AS IS" WITH NO EXPRESS OR IMPLIED 	*/
/*    WARRANTIES WHATSOEVER, INCLUDING ANY WARRANTY OF MERCHANTABILITY OR 	*/
/*    FITNESS FOR A PARTICULAR PURPOSE, ACCURACY, COMPLETENESS, OR 		*/
/*    NONINFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS, OR ANY WARRANTY 		*/
/*    OTHERWISE ARISING OUT OF ANY PROPOSAL, SPECIFICATION OR SAMPLE.		*/
/*										*/
/*  - Without limitation, TCG and its members and licensors disclaim all 	*/
/*    liability, including liability for infringement of any proprietary 	*/
/*    rights, relating to use of information in this specification and to the	*/
/*    implementation of this specification, and TCG disclaims all liability for	*/
/*    cost of procurement of substitute goods or services, lost profits, loss 	*/
/*    of use, loss of data or any incidental, consequential, direct, indirect, 	*/
/*    or special damages, whether under contract, tort, warranty or otherwise, 	*/
/*    arising in any way out of use or reliance upon this specification or any 	*/
/*    information herein.							*/
/*										*/
/*  (c) Copyright IBM Corp. and others, 2012-2015				*/
/*										*/
/********************************************************************************/

/* rev 122 */

// C.8	Platform.h

#ifndef    PLATFORM_H
#define    PLATFORM_H

// C.8.1.	Includes and Defines

#include <ibmtss/BaseTypes.h>
#include "stdint.h"
#include "TpmError.h"
#include <ibmtss/TpmBuildSwitches.h>

// C.8.2.	Power Functions
// C.8.2.1.	_plat__Signal_PowerOn
// Signal power on This signal is simulate by a RPC call

LIB_EXPORT int
_plat__Signal_PowerOn(void);

// C.8.2.2.	_plat__Signal_Reset
// Signal reset This signal is simulate by a RPC call

LIB_EXPORT int
_plat__Signal_Reset(void);

// C.8.2.3.	_plat__WasPowerLost()
// Indicates if the power was lost before a _TPM__Init().

LIB_EXPORT BOOL
_plat__WasPowerLost(BOOL clear);

// C.8.2.4.	_plat__Signal_PowerOff()
// Signal power off This signal is simulate by a RPC call

LIB_EXPORT void
_plat__Signal_PowerOff(void);

// C.8.3.	Physical Presence Functions
// C.8.3.1.	_plat__PhysicalPresenceAsserted()
// Check if physical presence is signaled
// Return Value	Meaning
// TRUE	if physical presence is signaled
// FALSE	if physical presence is not signaled

LIB_EXPORT BOOL
_plat__PhysicalPresenceAsserted(void);

// C.8.3.2.	_plat__Signal_PhysicalPresenceOn
// Signal physical presence on This signal is simulate by a RPC call

LIB_EXPORT void
_plat__Signal_PhysicalPresenceOn(void);

// C.8.3.3.	_plat__Signal_PhysicalPresenceOff()
// Signal physical presence off This signal is simulate by a RPC call

LIB_EXPORT void
_plat__Signal_PhysicalPresenceOff(void);

// C.8.4.	Command Canceling Functions
// C.8.4.1.	_plat__IsCanceled()
// Check if the cancel flag is set
// Return Value	Meaning
// TRUE	if cancel flag is set
// FALSE	if cancel flag is not set

LIB_EXPORT BOOL
_plat__IsCanceled(void);

// C.8.4.2.	_plat__SetCancel()
// Set cancel flag.

LIB_EXPORT void
_plat__SetCancel(void);

// C.8.4.3.	_plat__ClearCancel()
// Clear cancel flag

LIB_EXPORT void
_plat__ClearCancel( void);

// C.8.5.	NV memory functions
// C.8.5.1.	_plat__NvErrors()

// This function is used by the simulator to set the error flags in the NV subsystem to simulate an
// error in the NV loading process

LIB_EXPORT void
_plat__NvErrors(
		BOOL        recoverable,
		BOOL        unrecoverable
		);

// C.8.5.2.	_plat__NVEnable()

// Enable platform NV memory NV memory is automatically enabled at power on event.  This function is
// mostly for TPM_Manufacture() to access NV memory without a power on event

// Return Value	Meaning
// 0	if success
// non-0	if fail

LIB_EXPORT int
_plat__NVEnable(
		void    *platParameter              // IN: platform specific parameters
		);

// C.8.5.3.	_plat__NVDisable()

// Disable platform NV memory NV memory is automatically disabled at power off event.  This function
// is mostly for TPM_Manufacture() to disable NV memory without a power off event

LIB_EXPORT void
_plat__NVDisable(void);

// C.8.5.4.	_plat__IsNvAvailable()
// Check if NV is available
// Return Value	Meaning
// 0	NV is available
// 1	NV is not available due to write failure
// 2	NV is not available due to rate limit

LIB_EXPORT int
_plat__IsNvAvailable(void);

// C.8.5.5.	_plat__NvCommit()
// Update NV chip
// Return Value	Meaning
// 0	NV write success
// non-0	NV write fail

LIB_EXPORT int
_plat__NvCommit(void);

// C.8.5.6.	_plat__NvMemoryRead()
// Read a chunk of NV memory

LIB_EXPORT void
_plat__NvMemoryRead(
		    unsigned int        startOffset,         // IN: read start
		    unsigned int        size,                // IN: size of bytes to read
		    void                *data                // OUT: data buffer
		    );

// C.8.5.7.	_plat__NvIsDifferent()

// This function checks to see if the NV is different from the test value. This is so that NV will
// not be written if it has not changed.

// Return Value	Meaning
// TRUE	the NV location is different from the test value
// FALSE	the NV location is the same as the test value

LIB_EXPORT BOOL
_plat__NvIsDifferent(
		     unsigned int         startOffset,         // IN: read start
		     unsigned int         size,                // IN: size of bytes to compare
		     void                *data                 // IN: data buffer
		     );

// C.8.5.8.	_plat__NvMemoryWrite()

// Write a chunk of NV memory

LIB_EXPORT void
_plat__NvMemoryWrite(
		     unsigned int        startOffset,         // IN: read start
		     unsigned int        size,                // IN: size of bytes to read
		     void                *data                // OUT: data buffer
		     );

// C.8.5.9.	_plat__NvMemoryClear()

// Function is used to set a range of NV memory bytes to an implementation-dependent value. The
// value represents the errase state of the memory.

LIB_EXPORT void
_plat__NvMemoryClear(
		     unsigned int     start,         // IN: clear start
		     unsigned int     size           // IN: number of bytes to be clear
		     );

// C.8.5.10.	_plat__NvMemoryMove()

// Move a chunk of NV memory from source to destination This function should ensure that if there
// overlap, the original data is copied before it is written

LIB_EXPORT void
_plat__NvMemoryMove(
		    unsigned int        sourceOffset,         // IN: source offset
		    unsigned int        destOffset,           // IN: destination offset
		    unsigned int        size                  // IN: size of data being moved
		    );

// C.8.5.11.	_plat__SetNvAvail()

// Set the current NV state to available.  This function is for testing purposes only.  It is not
// part of the platform NV logic

LIB_EXPORT void
_plat__SetNvAvail(void);

// C.8.5.12.	_plat__ClearNvAvail()

// Set the current NV state to unavailable.  This function is for testing purposes only.  It is not
// part of the platform NV logic

LIB_EXPORT void
_plat__ClearNvAvail(void);

// C.8.6.	Locality Functions
// C.8.6.1.	_plat__LocalityGet()
// Get the most recent command locality in locality value form

LIB_EXPORT unsigned char
_plat__LocalityGet(void);

// C.8.6.2.	_plat__LocalitySet()
// Set the most recent command locality in locality value form

LIB_EXPORT void
_plat__LocalitySet(
		   unsigned char   locality
		   );

// C.8.7.	Clock Constants and Functions
// Assume that the nominal divisor is 30000

#define     CLOCK_NOMINAL           30000

// A 1% change in rate is 300 counts

#define     CLOCK_ADJUST_COARSE     300

// A .1 change in rate is 30 counts

#define     CLOCK_ADJUST_MEDIUM     30

// A minimum change in rate is 1 count

#define     CLOCK_ADJUST_FINE       1

// The clock tolerance is +/-15% (4500 counts) Allow some guard band (16.7%)

#define     CLOCK_ADJUST_LIMIT      5000

// C.8.7.1.	_plat__ClockReset()

// This function sets the current clock time as initial time.  This function is called at a power on
// event to reset the clock

LIB_EXPORT void
_plat__ClockReset(void);

// C.8.7.2.	_plat__ClockTimeFromStart()

// Function returns the compensated time from the start of the command when
// _plat__ClockTimeFromStart() was called.

LIB_EXPORT unsigned long long
_plat__ClockTimeFromStart(void);

// C.8.7.3.	_plat__ClockTimeElapsed()

// Get the time elapsed from current to the last time the _plat__ClockTimeElapsed() is called.  For
// the first _plat__ClockTimeElapsed() call after a power on event, this call report the elapsed
// time from power on to the current call

LIB_EXPORT unsigned long long
_plat__ClockTimeElapsed(void);

// C.8.7.4.	_plat__ClockAdjustRate()
// Adjust the clock rate

LIB_EXPORT void
_plat__ClockAdjustRate(
		       int         adjust              // IN: the adjust number.  It could be
		       // positive or negative
		       );

// C.8.8.	Single Function Files
// C.8.8.1.	_plat__GetEntropy()

// This function is used to get available hardware entropy. In a hardware implementation of this
// function, there would be no call to the system to get entropy. If the caller does not ask for any
// entropy, then this is a startup indication and firstValue should be reset.

//     Return Value	Meaning
//     < 0	hardware failure of the entropy generator, this is sticky
//       >= 0	the returned amount of entropy (bytes)

LIB_EXPORT int32_t
_plat__GetEntropy(
		  unsigned char       *entropy,           // output buffer
		  uint32_t             amount             // amount requested
		  );

#endif
