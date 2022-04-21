/********************************************************************************/
/*										*/
/*			    Transmit and Receive Utility			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2015 - 2020.					*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

/* This file contains the interface that is not platform or interface specific
 */

#include <string.h>
#include <stdio.h>

#include "tssproperties.h"
#ifndef TPM_NOSOCKET
#include "tsssocket.h"
#endif
#include <ibmtss/tsserror.h>
#include <ibmtss/tssprint.h>

#include "tssdev.h"
#include <ibmtss/tsstransmit.h>

extern int tssVverbose;
extern int tssVerbose;

/* local prototypes */

/* TSS_TransmitPlatform() transmits an administrative out of band command to the TPM through the
   platform port.

   Supported by the simulator, not the TPM device.
*/

TPM_RC TSS_TransmitPlatform(TSS_CONTEXT *tssContext, uint32_t command, const char *message)
{
    TPM_RC rc = 0;

#ifndef TPM_NOSOCKET
    if ((strcmp(tssContext->tssInterfaceType, "socsim") == 0)) {
	rc = TSS_Socket_TransmitPlatform(tssContext, command, message);
    }
    else
#else
    command = command;
    message = message;
#endif
    if ((strcmp(tssContext->tssInterfaceType, "dev") == 0)) {
	if (tssVerbose) printf("TSS_TransmitPlatform: device %s unsupported\n",
			       tssContext->tssInterfaceType);
	rc = TSS_RC_INSUPPORTED_INTERFACE;	
    }
    else {
	if (tssVerbose) printf("TSS_TransmitPlatform: device %s unsupported\n",
			       tssContext->tssInterfaceType);
	rc = TSS_RC_INSUPPORTED_INTERFACE;	
    }
    return rc;
}

/* TSS_TransmitCommand() transmits an administrative in band command to the TPM through the
   command port.

   Supported by the simulator, not the TPM device.
*/

TPM_RC TSS_TransmitCommand(TSS_CONTEXT *tssContext, uint32_t command, const char *message)
{
    TPM_RC rc = 0;

#ifndef TPM_NOSOCKET
    if ((strcmp(tssContext->tssInterfaceType, "socsim") == 0)) {
	rc = TSS_Socket_TransmitCommand(tssContext, command, message);
    }
    else
#else
    command = command;
    message = message;
#endif
    if ((strcmp(tssContext->tssInterfaceType, "dev") == 0)) {
	if (tssVerbose) printf("TSS_TransmitCommand: device %s unsupported\n",
			       tssContext->tssInterfaceType);
	rc = TSS_RC_INSUPPORTED_INTERFACE;	
    }
    else {
	if (tssVerbose) printf("TSS_TransmitCommand: device %s unsupported\n",
			       tssContext->tssInterfaceType);
	rc = TSS_RC_INSUPPORTED_INTERFACE;	
    }
    return rc;
}

/* TSS_Transmit() transmits a TPM command packet and receives a response using the command port.
   The command type is hard coded to TPM_SEND_COMMAND.

*/

TPM_RC TSS_Transmit(TSS_CONTEXT *tssContext,
		    uint8_t *responseBuffer, uint32_t *read,
		    const uint8_t *commandBuffer, uint32_t written,
		    const char *message)
{
    TPM_RC rc = 0;

#ifndef TPM_NOSOCKET
    if ((strcmp(tssContext->tssInterfaceType, "socsim") == 0)) {
	rc = TSS_Socket_Transmit(tssContext,
				 responseBuffer, read,
				 commandBuffer, written,
				 message);
    }
    else
#endif
    if (strcmp(tssContext->tssInterfaceType, "dev") == 0) {
	rc = TSS_Dev_Transmit(tssContext,
			      responseBuffer, read,
			      commandBuffer, written,
			      message);
    }
    else {
	if (tssVerbose) printf("TSS_Transmit: device %s unsupported\n",
			       tssContext->tssInterfaceType);
	rc = TSS_RC_INSUPPORTED_INTERFACE;	
    }
    return rc;
}

/* TSS_Close() closes the connection to the TPM */

TPM_RC TSS_Close(TSS_CONTEXT *tssContext)
{
    TPM_RC rc = 0;

    /* only close if there was an open */
    if (!tssContext->tssFirstTransmit) {
#ifndef TPM_NOSOCKET
	if ((strcmp(tssContext->tssInterfaceType, "socsim") == 0)) {
	    rc = TSS_Socket_Close(tssContext);
	}
	else
#endif
        if (strcmp(tssContext->tssInterfaceType, "dev") == 0) {
	    rc = TSS_Dev_Close(tssContext);
	}
	else {
	    if (tssVerbose) printf("TSS_Transmit: device %s unsupported\n",
				   tssContext->tssInterfaceType);
	    rc = TSS_RC_INSUPPORTED_INTERFACE;	
	}
	tssContext->tssFirstTransmit = TRUE;
    }
    return rc;
}
