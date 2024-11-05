/********************************************************************************/
/*										*/
/*		Skiboot Transmit and Receive Utilities				*/
/*										*/
/* (c) Copyright IBM Corporation 2020.						*/
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

#include <string.h>

#include <ibmtss/tssresponsecode.h>
#include <ibmtss/Implementation.h>
#include <ibmtss/tsserror.h>
#include <ibmtss/tssprint.h>
#include <tssproperties.h>

#include <tssdev.h>
#include <tpm_chip.h>

/* global configuration */

extern int tssVerbose;
extern int tssVverbose;

/*
 * TSS_Dev_Transmit() transmits the command and receives the response in
 * skiboot.
 * Can return device transmit and receive packet errors, but normally returns
 * the TPM response code.
*/
TPM_RC TSS_Dev_Transmit(TSS_CONTEXT *tssContext,
			    uint8_t *responseBuffer, uint32_t *length,
			    const uint8_t *commandBuffer, uint32_t written,
			    const char *message)
{
	TPM_RC rc = 0;
	size_t responseSize;

	/* skiboot driver's transmit function expects a size_t value as buffer
	 * length instead of uint32_t used in this function header, so this
	 * variable exists just for type compatibility.
	 */
	size_t buffer_length;

	if (message != NULL) {
		if (tssVverbose) printf("TSS_Skiboot_Transmit: %s\n", message);
	}
	if ((rc == 0) && tssVverbose) {
			TSS_PrintAll("TSS_Skiboot_Transmit: Command ",
				     commandBuffer, written);
	}

	/* we don't need to open a device as it is done in user space but we
	 * need to be sure a device and the driver are available for use.
	 */
	if (rc == 0) {
		if (tssContext->tssFirstTransmit) {
			tssContext->tpm_device = tpm_get_device();
			if (tssContext->tpm_device == NULL) {
				if (tssVerbose)
					printf("TSS_Skiboot_Transmit: TPM device not set\n");
				rc = TSS_RC_NO_CONNECTION;
			}
			if (rc == 0) {
		        	tssContext->tpm_driver = tpm_get_driver();
				if (tssContext->tpm_driver == NULL) {
					if (tssVerbose)
						printf("TSS_Skiboot_Transmit: TPM driver not set\n");
					rc = TSS_RC_NO_CONNECTION;
				}
			}
		}
	}

	if (rc == 0 ) {
		tssContext->tssFirstTransmit = FALSE;
	}

	/*
	 * Let's issue compilation issue if eventually MAX_COMMAND_SIZE becomes
	 * potentially greater than MAX_RESPONSE_SIZE
	 */
#if MAX_COMMAND_SIZE > MAX_RESPONSE_SIZE
#error "MAX_COMMAND_SIZE cannot be greater than MAX_RESPONSE_SIZE. Potential overflow on the buffer for Command and Response"
#endif
	if (rc == 0) {
		if (written > MAX_RESPONSE_SIZE) {
			if (tssVerbose)
				printf("TSS_Skiboot_Transmit: Response Overflow. TPM wrote %u bytes, Max response size is %u ",
				       written, MAX_RESPONSE_SIZE);
			rc = TSS_RC_BAD_CONNECTION;
		}
	}

	/*
	 * the buffer used to send the command will be overwritten and store the
	 * response data after TPM execution. So here we copy the contents of
	 * commandBuffer to responseBuffer, using the latter to perform the
	 * operation and storing the response and keeping the former safe.
	 */
	if (rc == 0) {
		/*
		 * skiboot driver checks for overflow, so we need to share the
		 * max response size to length. In the response length will
		 * contain the length of the response buffer.
	 	 */
		buffer_length = MAX_RESPONSE_SIZE;

		memcpy(responseBuffer, commandBuffer, written);
		rc = tssContext->tpm_driver->transmit(tssContext->tpm_device,
					      responseBuffer, written, &buffer_length);
		/* now that we have buffer length set we save it to length so it
		 * can be used by the callers
		 */
		*length = buffer_length;

		if (rc != 0) {
			if (tssVerbose)
				printf("TSS_Skiboot_Transmit: receive error %u\n", rc);
			rc = TSS_RC_BAD_CONNECTION;
		}
	}

	if (rc == 0) {
		if (tssVverbose)
			TSS_PrintAll("TSS_Skiboot_Transmit: Response", responseBuffer, *length);

    		/* verify that there is at least a tag, responseSize, and responseCode */
		if (*length < (sizeof(TPM_ST) + (2 * sizeof(uint32_t)))) {
			if (tssVerbose)
				printf("TSS_Skiboot_Transmit: received %u bytes < header\n", *length);
			rc = TSS_RC_MALFORMED_RESPONSE;
		}
	}

	/*
	 * length and the response size in the response body should match. Check
	 * it here.
	 */
	if (rc == 0) {
		responseSize = ntohl(*(uint32_t *)(responseBuffer + sizeof(TPM_ST)));
		if (responseSize != *length) {
			if (tssVerbose)
				printf("TSS_Skiboot_Transmit: Bytes read (%u) and Buffer responseSize field (%lu) don't match\n",
				       *length, responseSize);
		    rc = TSS_RC_MALFORMED_RESPONSE;
		}
	}

	/*
	 * Now we need to get the actual return code from the response buffer
	 * and deliver it to the upper layers
	 */
	if (rc == 0)
		rc = ntohl(*(uint32_t *)(responseBuffer + sizeof(TPM_ST) + sizeof(uint32_t)));

	if (tssVverbose)
		printf("TSS_Skiboot_Transmit: Response Code: %08x", rc);

	return rc;
}

TPM_RC TSS_Dev_Close(TSS_CONTEXT *tssContext)
{
	tssContext = tssContext;
	return 0;
}
