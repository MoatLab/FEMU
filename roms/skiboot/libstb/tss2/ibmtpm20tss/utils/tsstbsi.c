/********************************************************************************/
/*										*/
/*	Windows 10 Device Transmit and Receive Utilities			*/
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

#ifdef TPM_WINDOWS_TBSI

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#include <winsock2.h>
#include <windows.h>
#include <winerror.h>
#include <specstrings.h>
#include <tbs.h>

#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tssprint.h>
#include <ibmtss/tsserror.h>
#include <ibmtss/Unmarshal_fp.h>
#include "tssproperties.h"

/* local prototypes */

static uint32_t TSS_Tbsi_Open(TBS_CONTEXT_PARAMS2 *contextParams,
			      TBS_HCONTEXT *hContext);
static uint32_t TSS_Tbsi_SubmitCommand(TBS_HCONTEXT hContext,
				       uint8_t *responseBuffer, uint32_t *read,
				       const uint8_t *commandBuffer, uint32_t written,
				       const char *message);
static void TSS_Tbsi_GetTBSError(const char *prefix,
				 TBS_RESULT rc);


/* global configuration */

extern int tssVverbose;
extern int tssVerbose;

/* TSS_Dev_Transmit() transmits the command and receives the response. 'responseBuffer' must be at
   least MAX_RESPONSE_SIZE bytes.

   Can return device transmit and receive packet errors, but normally returns the TPM response code.
*/

TPM_RC TSS_Dev_Transmit(TSS_CONTEXT *tssContext,
			 uint8_t *responseBuffer, uint32_t *read,
			 const uint8_t *commandBuffer, uint32_t written,
			 const char *message)
{
    TPM_RC rc = 0;
    TBS_CONTEXT_PARAMS2 contextParams;

    if (rc == 0) {
	contextParams.version = TBS_CONTEXT_VERSION_TWO;
	if (!tssContext->tpm12Command) {	/* TPM 2.0 command */
	    contextParams.includeTpm12 = 0;
	    contextParams.includeTpm20 = 1;
	}
	else {					/* TPM 1.2 command */
	    contextParams.includeTpm12 = 1;
	    contextParams.includeTpm20 = 0;
	}
    }
    *read = MAX_RESPONSE_SIZE;
    /* open on first transmit */
    if (tssContext->tssFirstTransmit) {	
	if (rc == 0) {
	    rc = TSS_Tbsi_Open(&contextParams, &tssContext->hContext);
	}
	if (rc == 0) {
	    tssContext->tssFirstTransmit = FALSE;
	}
    }
    /* send the command to the device.  Error if the device send fails. */
    if (rc == 0) {
	rc = TSS_Tbsi_SubmitCommand(tssContext->hContext,
				    responseBuffer, read,
				    commandBuffer, written,
				    message);
    }
    return rc;
}

/* TSS_Tbsi_Open() opens the TPM device */

static uint32_t TSS_Tbsi_Open(TBS_CONTEXT_PARAMS2 *contextParams,
			      TBS_HCONTEXT *hContext)
{
    uint32_t rc = 0;

    if (rc == 0) {
	/* cast is safe because caller sets the version member for the subclass */
	rc = Tbsi_Context_Create((TBS_CONTEXT_PARAMS *)contextParams, hContext);
	if (tssVverbose) printf("TSS_Tbsi_Open: Tbsi_Context_Create rc %08x\n", rc);
	if (rc != 0) {
	    if (tssVerbose) TSS_Tbsi_GetTBSError("TSS_Tbsi_Open: Error Tbsi_Context_Create ", rc);
	    rc = TSS_RC_NO_CONNECTION;
	}
    }
    return rc;
}

/* TSS_Tbsi_Submit_Command sends the command to the TPM and receives the response.

   If the submit succeeds, returns TPM packet error code.
*/

static uint32_t TSS_Tbsi_SubmitCommand(TBS_HCONTEXT hContext,
				       uint8_t *responseBuffer, uint32_t *read,
				       const uint8_t *commandBuffer, uint32_t written,
				       const char *message)
{
    uint32_t 	rc = 0;
    TPM_RC 	responseCode;

    if (message != NULL) {
	if (tssVverbose) printf("TSS_Tbsi_SubmitCommand: %s\n", message);
    }
    if (rc == 0) {
	if (tssVverbose) TSS_PrintAll("TSS_Tbsi_SubmitCommand: Command",
				      commandBuffer, written);
    }
    if (rc == 0) {
	rc = Tbsip_Submit_Command(hContext,
				  TBS_COMMAND_LOCALITY_ZERO,
				  TBS_COMMAND_PRIORITY_NORMAL,
				  commandBuffer,
				  written,
				  responseBuffer,
				  read);
	if (rc != 0) {
	    TSS_Tbsi_GetTBSError("Tbsip_Submit_Command", rc);
	    rc = TSS_RC_BAD_CONNECTION;

	}
    }
    if (rc == 0) {
	if (tssVverbose) TSS_PrintAll("TSS_Tbsi_SubmitCommand: Response",
				      responseBuffer, *read);
    }
    /* read the TPM return code from the packet */
    if (rc == 0) {
	uint8_t		*bufferPtr;
	uint32_t	size;

	bufferPtr = responseBuffer + sizeof(TPM_ST) + sizeof(uint32_t);		/* skip to responseCode */
	size = sizeof(TPM_RC);		/* dummy for call */
	rc = TSS_UINT32_Unmarshalu(&responseCode, &bufferPtr, &size);
    }
    if (rc == 0) {
	rc = responseCode;
    }
    return rc;
}

TPM_RC TSS_Dev_Close(TSS_CONTEXT *tssContext)
{
    TPM_RC rc = 0;
    if (tssVverbose) printf("TSS_Dev_Close: Closing connection\n");
    rc = Tbsip_Context_Close(tssContext->hContext);
    return rc;
}

static void TSS_Tbsi_GetTBSError(const char *prefix,
				 TBS_RESULT rc)
{
    const char *error_string;
		     
    switch (rc) {

	/* error codes from the TBS html docs */
      case TBS_SUCCESS:
	error_string = "The function succeeded.";
	break;
      case TBS_E_INTERNAL_ERROR:
	error_string = "An internal software error occurred.";
	break;
      case TBS_E_BAD_PARAMETER:
	error_string = "One or more parameter values are not valid.";
	break;
      case TBS_E_INVALID_OUTPUT_POINTER:
	error_string = "A specified output pointer is bad.";
	break;
      case TBS_E_INVALID_CONTEXT:
	error_string = "The specified context handle does not refer to a valid context.";
	break;
      case TBS_E_INSUFFICIENT_BUFFER:
	error_string = "The specified output buffer is too small.";
	break;
      case TBS_E_IOERROR:
	error_string = "An error occurred while communicating with the TPM.";
	break;
      case TBS_E_INVALID_CONTEXT_PARAM:
	error_string = "A context parameter that is not valid was passed when attempting to create a "
		       "TBS context.";
	break;
      case TBS_E_SERVICE_NOT_RUNNING:
	error_string = "The TBS service is not running and could not be started.";
	break;
      case TBS_E_TOO_MANY_TBS_CONTEXTS:
	error_string = "A new context could not be created because there are too many open contexts.";
	break;
      case TBS_E_TOO_MANY_RESOURCES:
	error_string = "A new virtual resource could not be created because there are too many open "
		       "virtual resources.";
	break;
      case TBS_E_SERVICE_START_PENDING:
	error_string = "The TBS service has been started but is not yet running.";
	break;
      case TBS_E_PPI_NOT_SUPPORTED:
	error_string = "The physical presence interface is not supported.";
	break;
      case TBS_E_COMMAND_CANCELED:
	error_string = "The command was canceled.";
	break;
      case TBS_E_BUFFER_TOO_LARGE:
	error_string = "The input or output buffer is too large.";
	break;
      case TBS_E_TPM_NOT_FOUND:
	error_string = "A compatible Trusted Platform Module (TPM) Security Device cannot be found "
		       "on this computer.";
	break;
      case TBS_E_SERVICE_DISABLED:
	error_string = "The TBS service has been disabled.";
	break;
      case TBS_E_NO_EVENT_LOG:
	error_string = "The TBS event log is not available.";
	break;
      case TBS_E_ACCESS_DENIED:
	error_string = "The caller does not have the appropriate rights to perform the requested operation.";
	break;
      case TBS_E_PROVISIONING_NOT_ALLOWED:
	error_string = "The TPM provisioning action is not allowed by the specified flags.";
	break;
      case TBS_E_PPI_FUNCTION_UNSUPPORTED:
	error_string = "The Physical Presence Interface of this firmware does not support the "
		       "requested method.";
	break;
      case TBS_E_OWNERAUTH_NOT_FOUND:
	error_string = "The requested TPM OwnerAuth value was not found.";
	break;

	/* a few error codes from WinError.h */
      case TPM_E_COMMAND_BLOCKED:
	error_string = "The command was blocked.";
	break;

      default:
	error_string = "unknown error type\n";
	break;

    }
    printf("%s %s\n", prefix, error_string);
    return;
}

#endif	/* TPM_WINDOWS_TBSI */
