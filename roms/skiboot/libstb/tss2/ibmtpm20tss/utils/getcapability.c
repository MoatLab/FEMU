/********************************************************************************/
/*										*/
/*			    Get Capability	 				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2015 - 2019.					*/
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

/* 

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>

static void printUsage(TPM_CAP capability);
static TPM_RC printResponse(TPMS_CAPABILITY_DATA *capabilityData, uint32_t property);

extern int tssUtilsVerbose;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    		/* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    TPM_CAP			capability = TPM_CAP_LAST + 1;	/* invalid */
    uint32_t			property = 0;			/* default, start at first one */
    uint32_t			propertyCount = 64;		/* default, return 64 values */
    GetCapability_In 		in;
    GetCapability_Out		out;
    TPMI_SH_AUTH_SESSION    	sessionHandle0 = TPM_RH_NULL;
    unsigned int		sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle1 = TPM_RH_NULL;
    unsigned int		sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle2 = TPM_RH_NULL;
    unsigned int		sessionAttributes2 = 0;

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
    tssUtilsVerbose = FALSE;
    
    /* command line argument defaults */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-cap") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &capability);
	    }
	    else {
		printf("Missing parameter for -cap\n");
		printUsage(capability);
	    }
	    
	}
	else if (strcmp(argv[i],"-pr") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &property);
	    }
	    else {
		printf("Missing parameter for -pr\n");
		printUsage(capability);
	    }
	    
	}
	else if (strcmp(argv[i],"-pc") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%u", &propertyCount);
	    }
	    else {
		printf("Missing parameter for -pc\n");
		printUsage(capability);
	    }
	    
	}
	else if (strcmp(argv[i],"-se0") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionHandle0);
	    }
	    else {
		printf("Missing parameter for -se0\n");
		printUsage(capability);
	    }
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionAttributes0);
		if (sessionAttributes0 > 0xff) {
		    printf("Out of range session attributes for -se0\n");
		    printUsage(capability);
		}
	    }
	    else {
		printf("Missing parameter for -se0\n");
		printUsage(capability);
	    }
	}
	else if (strcmp(argv[i],"-se1") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionHandle1);
	    }
	    else {
		printf("Missing parameter for -se1\n");
		printUsage(capability);
	    }
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionAttributes1);
		if (sessionAttributes1 > 0xff) {
		    printf("Out of range session attributes for -se1\n");
		    printUsage(capability);
		}
	    }
	    else {
		printf("Missing parameter for -se1\n");
		printUsage(capability);
	    }
	}
	else if (strcmp(argv[i],"-se2") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionHandle2);
	    }
	    else {
		printf("Missing parameter for -se2\n");
		printUsage(capability);
	    }
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionAttributes2);
		if (sessionAttributes2 > 0xff) {
		    printf("Out of range session attributes for -se2\n");
		    printUsage(capability);
		}
	    }
	    else {
		printf("Missing parameter for -se2\n");
		printUsage(capability);
	    }
	}
	else if (strcmp(argv[i],"-h") == 0) {
	    printUsage(capability);
	}
	else if (strcmp(argv[i],"-v") == 0) {
	    tssUtilsVerbose = TRUE;
	    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "2");
	}
	else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    printUsage(capability);
	}
    }
    if (capability > TPM_CAP_LAST) {
	printf("Missing or illegal parameter -cap\n");
	printUsage(capability);
    }
    if (rc == 0) {
	in.capability = capability;
	in.property = property;
	in.propertyCount = propertyCount;
    }
    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out, 
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_GetCapability,
			 sessionHandle0, NULL, sessionAttributes0,
			 sessionHandle1, NULL, sessionAttributes1,
			 sessionHandle2, NULL, sessionAttributes2,
			 TPM_RH_NULL, NULL, 0);
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    if (rc == 0) {
	if (out.moreData > 0) {
	    printf("moreData: %u\n", out.moreData);
	}
	rc = printResponse(&out.capabilityData, property);
    }
    if (rc == 0) {
	if (tssUtilsVerbose) printf("getcapability: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("getcapability: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

typedef void (* USAGE_FUNCTION)(void);
typedef TPM_RC (* RESPONSE_FUNCTION)(TPMS_CAPABILITY_DATA *out, uint32_t property);

typedef struct {
    TPM_CAP capability;
    USAGE_FUNCTION usageFunction;
    RESPONSE_FUNCTION responseFunction;
} CAPABILITY_TABLE;

static void usageCapability(void);
static void usageAlgs(void);
static void usageHandles(void);
static void usageCommands(void);
static void usagePpCommands(void);
static void usageAuditCommands(void);
static void usagePcrs(void);
static void usageTpmProperties(void);
static void usagePcrProperties(void);
static void usageEccCurves(void);
static void usageAuthPolicies(void);

static TPM_RC responseCapability(TPMS_CAPABILITY_DATA *capabilityData, uint32_t property);
static TPM_RC responseAlgs(TPMS_CAPABILITY_DATA *capabilityData, uint32_t property);
static TPM_RC responseHandles(TPMS_CAPABILITY_DATA *capabilityData, uint32_t property);
static TPM_RC responseCommands(TPMS_CAPABILITY_DATA *capabilityData, uint32_t property);
static TPM_RC responsePpCommands(TPMS_CAPABILITY_DATA *capabilityData, uint32_t property);
static TPM_RC responseAuditCommands(TPMS_CAPABILITY_DATA *capabilityData, uint32_t property);
static TPM_RC responsePcrs(TPMS_CAPABILITY_DATA *capabilityData, uint32_t property);
static TPM_RC responseTpmProperties(TPMS_CAPABILITY_DATA *capabilityData, uint32_t property);
static TPM_RC responsePcrProperties(TPMS_CAPABILITY_DATA *capabilityData, uint32_t property);
static TPM_RC responseEccCurves(TPMS_CAPABILITY_DATA *capabilityData, uint32_t property);
static TPM_RC responseAuthPolicies(TPMS_CAPABILITY_DATA *capabilityData, uint32_t property);

static const CAPABILITY_TABLE capabilityTable [] = {
    {TPM_CAP_LAST + 1, usageCapability, responseCapability}, 
    {TPM_CAP_ALGS, usageAlgs, responseAlgs} ,                 
    {TPM_CAP_HANDLES, usageHandles, responseHandles} ,             
    {TPM_CAP_COMMANDS, usageCommands, responseCommands} ,            
    {TPM_CAP_PP_COMMANDS, usagePpCommands, responsePpCommands} ,         
    {TPM_CAP_AUDIT_COMMANDS, usageAuditCommands, responseAuditCommands},      
    {TPM_CAP_PCRS, usagePcrs, responsePcrs} ,                
    {TPM_CAP_TPM_PROPERTIES, usageTpmProperties, responseTpmProperties},      
    {TPM_CAP_PCR_PROPERTIES, usagePcrProperties, responsePcrProperties},      
    {TPM_CAP_ECC_CURVES, usageEccCurves, responseEccCurves},          
    {TPM_CAP_AUTH_POLICIES, usageAuthPolicies, responseAuthPolicies}          
};

static TPM_RC printResponse(TPMS_CAPABILITY_DATA *capabilityData, uint32_t property)
{
    TPM_RC	rc = 0;
    size_t 	i;

    /* call the response function in the capability table */
    for (i = 0 ; i < (sizeof(capabilityTable) / sizeof(CAPABILITY_TABLE)) ; i++) {
	if (capabilityTable[i].capability == capabilityData->capability) {
	    rc = capabilityTable[i].responseFunction(capabilityData, property);
	}
    }
    return rc;
}

static TPM_RC responseCapability(TPMS_CAPABILITY_DATA *capabilityData, uint32_t property)
{
    TPM_RC			rc = 0;
    property = property;
    printf("Cannot parse illegal response capability %08x\n", capabilityData->capability);
    rc = TPM_RC_VALUE;
    return rc;
}

static TPM_RC responseAlgs(TPMS_CAPABILITY_DATA *capabilityData, uint32_t property)
{
    TPM_RC	rc = 0;
    uint32_t	count;
    TPML_ALG_PROPERTY *algorithms = (TPML_ALG_PROPERTY *)&(capabilityData->data);
    property = property;

    printf("%u algorithms \n", algorithms->count);
    for (count = 0 ; count < algorithms->count ; count++) {
	TPMS_ALG_PROPERTY *algProperties = &(algorithms->algProperties[count]);
	TSS_TPM_ALG_ID_Print("", algProperties->alg, 2);
	TSS_TPM_TPMA_ALGORITHM_Print(algProperties->algProperties, 4);
    }
    return rc;
}

static TPM_RC responseHandles(TPMS_CAPABILITY_DATA *capabilityData, uint32_t property)
{
    TPM_RC	rc = 0;
    uint32_t	count;
    TPML_HANDLE	*handles = (TPML_HANDLE *)&(capabilityData->data);
    property = property;

    printf("%u handles\n", handles->count);
    for (count = 0 ; count < handles->count ; count++) {
	printf("\t%08x\n", handles->handle[count]);
    }
    return rc;
}

static TPM_RC responseCommands(TPMS_CAPABILITY_DATA *capabilityData, uint32_t property)
{
    TPM_RC	rc = 0;
    uint32_t	count;
    TPML_CCA	*command = (TPML_CCA *)&(capabilityData->data);
    property = property;

    printf("%u commands\n", command->count);
    for (count = 0 ; count < command->count ; count++) {
	printf("\tcommand Attributes %08x\n", command->commandAttributes[count].val);
    }
    return rc;
}

static TPM_RC responsePpCommands(TPMS_CAPABILITY_DATA *capabilityData, uint32_t property)
{
    TPM_RC	rc = 0;
    uint32_t	count;
    TPML_CC	*command = (TPML_CC *)&(capabilityData->data);
    property = property;

    printf("%u commands\n", command->count);
    for (count = 0 ; count < command->count ; count++) {
	printf("\tPP command %08x\n", command->commandCodes[count]);
    }
    return rc;
}

static TPM_RC responseAuditCommands(TPMS_CAPABILITY_DATA *capabilityData, uint32_t property)
{
    TPM_RC	rc = 0;
    uint32_t	count;
    TPML_CC	*command = (TPML_CC *)&(capabilityData->data);
    property = property;

    printf("%u commands\n", command->count);
    for (count = 0 ; count < command->count ; count++) {
	printf("\tAudit command %08x\n", command->commandCodes[count]);
    }
    return rc;
}

static TPM_RC responsePcrs(TPMS_CAPABILITY_DATA *capabilityData, uint32_t property)
{
    TPM_RC	rc = 0;
    uint32_t	count;
    TPML_PCR_SELECTION *pcrSelection = (TPML_PCR_SELECTION *)&(capabilityData->data);
    property = property;

    printf("%u PCR selections\n", pcrSelection->count);
    for (count = 0 ; count < pcrSelection->count ; count++) {
	TSS_TPMS_PCR_SELECTION_Print(&pcrSelection->pcrSelections[count], 2);
    }
    return rc;
}

typedef struct {
    TPM_PT pt;
    const char *ptText;
} PT_TABLE;

static PT_TABLE ptTable [] = {
    {(PT_FIXED + 0),"TPM_PT_FAMILY_INDICATOR - a 4-octet character string containing the TPM Family value (TPM_SPEC_FAMILY)"},
    {(PT_FIXED + 1), "TPM_PT_LEVEL - the level of the specification"},
    {(PT_FIXED + 2), "TPM_PT_REVISION - the specification Revision times 100"},
    {(PT_FIXED + 3), "TPM_PT_DAY_OF_YEAR - the specification day of year using TCG calendar"},
    {(PT_FIXED + 4), "TPM_PT_YEAR - the specification year using the CE"},
    {(PT_FIXED + 5), "TPM_PT_MANUFACTURER - the vendor ID unique to each TPM manufacturer "},
    {(PT_FIXED + 6), "TPM_PT_VENDOR_STRING_1 - the first four characters of the vendor ID string"},
    {(PT_FIXED + 7), "TPM_PT_VENDOR_STRING_2 - the second four characters of the vendor ID string "},
    {(PT_FIXED + 8), "TPM_PT_VENDOR_STRING_3 - the third four characters of the vendor ID string "},
    {(PT_FIXED + 9), "TPM_PT_VENDOR_STRING_4 - the fourth four characters of the vendor ID sting "},
    {(PT_FIXED + 10), "TPM_PT_VENDOR_TPM_TYPE - vendor-defined value indicating the TPM model "},
    {(PT_FIXED + 11), "TPM_PT_FIRMWARE_VERSION_1 - the most-significant 32 bits of a TPM vendor-specific value indicating the version number of the firmware"},
    {(PT_FIXED + 12), "TPM_PT_FIRMWARE_VERSION_2 - the least-significant 32 bits of a TPM vendor-specific value indicating the version number of the firmware"},
    {(PT_FIXED + 13), "TPM_PT_INPUT_BUFFER - the maximum size of a parameter (typically, a TPM2B_MAX_BUFFER)"},
    {(PT_FIXED + 14), "TPM_PT_HR_TRANSIENT_MIN - the minimum number of transient objects that can be held in TPM RAM"},
    {(PT_FIXED + 15), "TPM_PT_HR_PERSISTENT_MIN - the minimum number of persistent objects that can be held in TPM NV memory"},
    {(PT_FIXED + 16), "TPM_PT_HR_LOADED_MIN - the minimum number of authorization sessions that can be held in TPM RAM"},
    {(PT_FIXED + 17), "TPM_PT_ACTIVE_SESSIONS_MAX - the number of authorization sessions that may be active at a time"},
    {(PT_FIXED + 18), "TPM_PT_PCR_COUNT - the number of PCR implemented"},
    {(PT_FIXED + 19), "TPM_PT_PCR_SELECT_MIN - the minimum number of octets in a TPMS_PCR_SELECT.sizeOfSelect"},
    {(PT_FIXED + 20), "TPM_PT_CONTEXT_GAP_MAX - the maximum allowed difference (unsigned) between the contextID values of two saved session contexts"},
    {(PT_FIXED + 22), "TPM_PT_NV_COUNTERS_MAX - the maximum number of NV Indexes that are allowed to have the TPMA_NV_COUNTER attribute SET"},
    {(PT_FIXED + 23), "TPM_PT_NV_INDEX_MAX - the maximum size of an NV Index data area"},
    {(PT_FIXED + 24), "TPM_PT_MEMORY - a TPMA_MEMORY indicating the memory management method for the TPM"},
    {(PT_FIXED + 25), "TPM_PT_CLOCK_UPDATE - interval, in milliseconds, between updates to the copy of TPMS_CLOCK_INFO.clock in NV"},
    {(PT_FIXED + 26), "TPM_PT_CONTEXT_HASH - the algorithm used for the integrity HMAC on saved contexts and for hashing the fuData of TPM2_FirmwareRead()"},
    {(PT_FIXED + 27), "TPM_PT_CONTEXT_SYM - TPM_ALG_ID, the algorithm used for encryption of saved contexts"},
    {(PT_FIXED + 28), "TPM_PT_CONTEXT_SYM_SIZE - TPM_KEY_BITS, the size of the key used for encryption of saved contexts"},
    {(PT_FIXED + 29), "TPM_PT_ORDERLY_COUNT - the modulus - 1 of the count for NV update of an orderly counter"},
    {(PT_FIXED + 30), "TPM_PT_MAX_COMMAND_SIZE - the maximum value for commandSize in a command"},
    {(PT_FIXED + 31), "TPM_PT_MAX_RESPONSE_SIZE - the maximum value for responseSize in a response"},
    {(PT_FIXED + 32), "TPM_PT_MAX_DIGEST - the maximum size of a digest that can be produced by the TPM"},
    {(PT_FIXED + 33), "TPM_PT_MAX_OBJECT_CONTEXT - the maximum size of an object context that will be returned by TPM2_ContextSave"},
    {(PT_FIXED + 34), "TPM_PT_MAX_SESSION_CONTEXT - the maximum size of a session context that will be returned by TPM2_ContextSave"},
    {(PT_FIXED + 35), "TPM_PT_PS_FAMILY_INDICATOR - platform-specific family (a TPM_PS value)(see Table 24)"},
    {(PT_FIXED + 36), "TPM_PT_PS_LEVEL - the level of the platform-specific specification"},
    {(PT_FIXED + 37), "TPM_PT_PS_REVISION - the specification Revision times 100 for the platform-specific specification"},
    {(PT_FIXED + 38), "TPM_PT_PS_DAY_OF_YEAR - the platform-specific specification day of year using TCG calendar"},
    {(PT_FIXED + 39), "TPM_PT_PS_YEAR - the platform-specific specification year using the CE"},
    {(PT_FIXED + 40), "TPM_PT_SPLIT_MAX - the number of split signing operations supported by the TPM"},
    {(PT_FIXED + 41), "TPM_PT_TOTAL_COMMANDS - total number of commands implemented in the TPM"},
    {(PT_FIXED + 42), "TPM_PT_LIBRARY_COMMANDS - number of commands from the TPM library that are implemented"},
    {(PT_FIXED + 43), "TPM_PT_VENDOR_COMMANDS - number of vendor commands that are implemented"},
    {(PT_FIXED + 44), "TPM_PT_NV_BUFFER_MAX - the maximum data size in one NV write command"},
    {(PT_FIXED + 45) ,"TPM_PT_MODES - a TPMA_MODES value, indicating that the TPM is designed for these modes"},
    {(PT_FIXED + 46) ,"TPM_PT_MAX_CAP_BUFFER - the maximum size of a TPMS_CAPABILITY_DATA structure returned in TPM2_GetCapability"},
    {(PT_VAR + 0), "TPM_PT_PERMANENT - TPMA_PERMANENT "},
    {(PT_VAR + 1), "TPM_PT_STARTUP_CLEAR - TPMA_STARTUP_CLEAR "},
    {(PT_VAR + 2), "TPM_PT_HR_NV_INDEX - the number of NV Indexes currently defined "},
    {(PT_VAR + 3), "TPM_PT_HR_LOADED - the number of authorization sessions currently loaded into TPM RAM"},
    {(PT_VAR + 4), "TPM_PT_HR_LOADED_AVAIL - the number of additional authorization sessions, of any type, that could be loaded into TPM RAM"},
    {(PT_VAR + 5), "TPM_PT_HR_ACTIVE - the number of active authorization sessions currently being tracked by the TPM"},
    {(PT_VAR + 6), "TPM_PT_HR_ACTIVE_AVAIL - the number of additional authorization sessions, of any type, that could be created"},
    {(PT_VAR + 7), "TPM_PT_HR_TRANSIENT_AVAIL - estimate of the number of additional transient objects that could be loaded into TPM RAM"},
    {(PT_VAR + 8), "TPM_PT_HR_PERSISTENT - the number of persistent objects currently loaded into TPM NV memory"},
    {(PT_VAR + 9), "TPM_PT_HR_PERSISTENT_AVAIL - the number of additional persistent objects that could be loaded into NV memory"},
    {(PT_VAR + 10), "TPM_PT_NV_COUNTERS - the number of defined NV Indexes that have NV TPMA_NV_COUNTER attribute SET"},
    {(PT_VAR + 11), "TPM_PT_NV_COUNTERS_AVAIL - the number of additional NV Indexes that can be defined with their TPMA_NV_COUNTER and TPMA_NV_ORDERLY attribute SET"},
    {(PT_VAR + 12), "TPM_PT_ALGORITHM_SET - code that limits the algorithms that may be used with the TPM"},
    {(PT_VAR + 13), "TPM_PT_LOADED_CURVES - the number of loaded ECC curves "},
    {(PT_VAR + 14), "TPM_PT_LOCKOUT_COUNTER - the current value of the lockout counter (failedTries) "},
    {(PT_VAR + 15), "TPM_PT_MAX_AUTH_FAIL - the number of authorization failures before DA lockout is invoked"},
    {(PT_VAR + 16), "TPM_PT_LOCKOUT_INTERVAL - the number of seconds before the value reported by TPM_PT_LOCKOUT_COUNTER is decremented"},
    {(PT_VAR + 17), "TPM_PT_LOCKOUT_RECOVERY - the number of seconds after a lockoutAuth failure before use of lockoutAuth may be attempted again"},
    {(PT_VAR + 18), "TPM_PT_NV_WRITE_RECOVERY - number of milliseconds before the TPM will accept another command that will modify NV"},
    {(PT_VAR + 19), "TPM_PT_AUDIT_COUNTER_0 - the high-order 32 bits of the command audit counter "},
    {(PT_VAR + 20), "TPM_PT_AUDIT_COUNTER_1 - the low-order 32 bits of the command audit counter"},
};

static char get8(uint32_t value32, size_t offset);
static uint16_t get16(uint32_t value32, size_t offset);

/* get8() gets a char from a uint32_t at offset */

static char get8(uint32_t value32, size_t offset)
{
    char value8 = (uint8_t)((value32 >> ((3 - offset) * 8)) & 0xff);
    return value8;
}

/* get16() gets a uint16_t from a uint32_t at offset */

static uint16_t get16(uint32_t value32, size_t offset)
{
    uint16_t value16 = (uint16_t)((value32 >> ((1 - offset) * 16)) & 0xffff);
    return value16;
}

static TPM_RC responseTpmProperties(TPMS_CAPABILITY_DATA *capabilityData, uint32_t property)
{
    TPM_RC		rc = 0;
    uint32_t		count;
    TPML_TAGGED_TPM_PROPERTY *tpmProperties = (TPML_TAGGED_TPM_PROPERTY *)&(capabilityData->data);
    property = property;

    printf("%u properties\n", tpmProperties->count);
    for (count = 0 ; count < tpmProperties->count ; count++) {
	TPMS_TAGGED_PROPERTY *tpmProperty = &(tpmProperties->tpmProperty[count]);
	const char *ptText = NULL;
	size_t i;
	for  (i = 0 ; i < (sizeof(ptTable) / sizeof(PT_TABLE)) ; i++) {
	    if (tpmProperty->property == ptTable[i].pt) {
		ptText = ptTable[i].ptText;
		break;
	    }
	}
	if (ptText == NULL) {
	    ptText = "PT unknown";
	}
	printf("TPM_PT %08x value %08x %s\n", tpmProperty->property, tpmProperty->value, ptText);
	switch (tpmProperty->property) {
	    char c;
	  case TPM_PT_FAMILY_INDICATOR:
	    printf("\tTPM ");
	    for (i = 0 ; i < sizeof(uint32_t) ; i++) {
		c = get8(tpmProperty->value, i);
		printf("%c", c);
	    }
	    printf("\n");
	    break;
	  case TPM_PT_REVISION:
	    printf("\trev %u\n", tpmProperty->value);
	    break;
	  case TPM_PT_DAY_OF_YEAR:
	  case TPM_PT_YEAR:
	  case TPM_PT_INPUT_BUFFER:
	  case TPM_PT_ACTIVE_SESSIONS_MAX:
	  case TPM_PT_PCR_COUNT:
	  case TPM_PT_NV_INDEX_MAX:
	  case TPM_PT_CLOCK_UPDATE:
	  case TPM_PT_CONTEXT_SYM_SIZE:
	  case TPM_PT_MAX_COMMAND_SIZE:
	  case TPM_PT_MAX_RESPONSE_SIZE:
	  case TPM_PT_MAX_DIGEST:
	  case TPM_PT_MAX_OBJECT_CONTEXT:
	  case TPM_PT_MAX_SESSION_CONTEXT:
	  case TPM_PT_PS_DAY_OF_YEAR:
	  case TPM_PT_PS_YEAR:
	  case TPM_PT_SPLIT_MAX:
	  case TPM_PT_TOTAL_COMMANDS:
	  case TPM_PT_LIBRARY_COMMANDS:
	  case TPM_PT_VENDOR_COMMANDS:
	  case TPM_PT_NV_BUFFER_MAX:
	  case TPM_PT_MAX_CAP_BUFFER:
	    
	  case TPM_PT_HR_ACTIVE_AVAIL:
	  case TPM_PT_HR_PERSISTENT_AVAIL:
	  case TPM_PT_NV_COUNTERS_AVAIL:
 	    printf("\t%u\n", tpmProperty->value);
	    break;
	  case TPM_PT_MANUFACTURER:
	  case TPM_PT_VENDOR_STRING_1:
	  case TPM_PT_VENDOR_STRING_2:
	  case TPM_PT_VENDOR_STRING_3:
	  case TPM_PT_VENDOR_STRING_4:
	    printf("\t");
	    for (i = 0 ; i < sizeof(uint32_t) ; i++) {
		c = get8(tpmProperty->value, i);
		printf("%c", c);
	    }
	    printf("\n");
	    break;
	  case TPM_PT_FIRMWARE_VERSION_1:
	  case TPM_PT_FIRMWARE_VERSION_2:
	    printf("\t%u.%u\n", get16(tpmProperty->value, 0), get16(tpmProperty->value, 1));
	    break;
	  case TPM_PT_PS_REVISION:
	    printf("\t%u.%u.%u.%u\n",
		   get8(tpmProperty->value, 0), get8(tpmProperty->value, 1),
		   get8(tpmProperty->value, 2), get8(tpmProperty->value, 3));
	    break;
	  case TPM_PT_CONTEXT_HASH:
	  case TPM_PT_CONTEXT_SYM:
	    TSS_TPM_ALG_ID_Print("algorithm", tpmProperty->value, 4);
	    break;
	  case TPM_PT_MEMORY:
	      {
		  TPMA_MEMORY tmp;
		  tmp.val = tpmProperty->value;
		  TSS_TPMA_MEMORY_Print(tmp, 4);
	      }
	      break;
	  case TPM_PT_MODES :
	      {
		  TPMA_MODES tmp;
		  tmp.val = tpmProperty->value;
		  TSS_TPMA_MODES_Print(tmp, 4);
	      }
	      break;
	  case TPM_PT_PERMANENT:
	      {
		  TPMA_PERMANENT tmp;
		  tmp.val = tpmProperty->value;
		  TSS_TPMA_PERMANENT_Print(tmp, 4);
	      }
	      break;
	  case TPM_PT_STARTUP_CLEAR:
	      {
		  TPMA_STARTUP_CLEAR tmp;
		  tmp.val = tpmProperty->value;
		  TSS_TPMA_STARTUP_CLEAR_Print(tmp, 4);
	      }
	      break; 
	}
    }
    return rc;
}

typedef struct {
    TPM_PT_PCR ptPcr;
    const char *ptPcrText;
} PT_PCR_TABLE;

static PT_PCR_TABLE ptPcrTable [] = {
    {TPM_PT_PCR_SAVE, "TPM_PT_PCR_SAVE - PCR is saved and restored by TPM_SU_STATE"},
    {TPM_PT_PCR_EXTEND_L0, "TPM_PT_PCR_EXTEND_L0 - PCR may be extended from locality 0"},
    {TPM_PT_PCR_RESET_L0, "TPM_PT_PCR_RESET_L0 - PCR may be reset by TPM2_PCR_Reset() from locality 0"},
    {TPM_PT_PCR_EXTEND_L1, "TPM_PT_PCR_EXTEND_L1 - PCR may be extended from locality 1"},
    {TPM_PT_PCR_RESET_L1, "TPM_PT_PCR_RESET_L1 - PCR may be reset by TPM2_PCR_Reset() from locality 1"},
    {TPM_PT_PCR_EXTEND_L2, "TPM_PT_PCR_EXTEND_L2 - PCR may be extended from locality 2"},
    {TPM_PT_PCR_RESET_L2, "TPM_PT_PCR_RESET_L2 - PCR may be reset by TPM2_PCR_Reset() from locality 2"},
    {TPM_PT_PCR_EXTEND_L3, "TPM_PT_PCR_EXTEND_L3 - PCR may be extended from locality 3"},
    {TPM_PT_PCR_RESET_L3, "TPM_PT_PCR_RESET_L3 - PCR may be reset by TPM2_PCR_Reset() from locality 3"},
    {TPM_PT_PCR_EXTEND_L4, "TPM_PT_PCR_EXTEND_L4 - PCR may be extended from locality 4"},
    {TPM_PT_PCR_RESET_L4, "TPM_PT_PCR_RESET_L4 - PCR may be reset by TPM2_PCR_Reset() from locality 4"},
    {TPM_PT_PCR_NO_INCREMENT, "TPM_PT_PCR_NO_INCREMENT - modifications to this PCR (reset or Extend) will not increment the pcrUpdateCounter"},
    {TPM_PT_PCR_RESET_L4, "TPM_PT_PCR_RESET_L4 - PCR may be reset by TPM2_PCR_Reset() from locality 4"},
    {TPM_PT_PCR_DRTM_RESET, "TPM_PT_PCR_DRTM_RESET - PCR is reset by a DRTM event"},
    {TPM_PT_PCR_POLICY, "TPM_PT_PCR_POLICY - PCR is controlled by policy"},
    {TPM_PT_PCR_AUTH, "TPM_PT_PCR_AUTH - PCR is controlled by an authorization value"}
};

static TPM_RC responsePcrProperties(TPMS_CAPABILITY_DATA *capabilityData, uint32_t property)
{
    TPM_RC		rc = 0;
    uint32_t		count;
    TPML_TAGGED_PCR_PROPERTY *pcrProperties = (TPML_TAGGED_PCR_PROPERTY *)&(capabilityData->data);
    property = property; 

    printf("%u properties\n", pcrProperties->count);
    for (count = 0 ; count < pcrProperties->count ; count++) {
	

	TPMS_TAGGED_PCR_SELECT *pcrProperty = &(pcrProperties->pcrProperty[count]);
	const char *ptPcrText = NULL;
	size_t i;
	for  (i = 0 ; i < (sizeof(ptPcrTable) / sizeof(PT_PCR_TABLE)) ; i++) {
	    if (pcrProperty->tag == ptPcrTable[i].ptPcr) {	/* the property identifier */
		ptPcrText = ptPcrTable[i].ptPcrText;
		break;
	    }
	}
	if (ptPcrText == NULL) {
	    ptPcrText = "PT unknown";
	}
	printf("TPM_PT_PCR %08x %s\n", pcrProperty->tag, ptPcrText);
	for (i = 0 ; i < pcrProperty->sizeofSelect ; i++) {	/* the size in octets of the
								   pcrSelect array */
	    printf("PCR %u-%u  \tpcrSelect\t%02x\n",
		   (unsigned int)i*8, (unsigned int)(i*8) + 7,
		   pcrProperty->pcrSelect[i]); 
	}
    }
    return rc;
}

static TPM_RC responseEccCurves(TPMS_CAPABILITY_DATA *capabilityData, uint32_t property)
{
    TPM_RC	rc = 0;
    uint32_t	count;
    TPML_ECC_CURVE *eccCurves = (TPML_ECC_CURVE *)&(capabilityData->data);
    TPM_ECC_CURVE curve;
    property = property;

    printf("%u curves\n", eccCurves->count);
    for (count = 0 ; count < eccCurves->count ; count++) {
	curve = eccCurves->eccCurves[count];
	TSS_TPM_ECC_CURVE_Print("", curve, 4);
    }
    return rc;
}

static TPM_RC responseAuthPolicies(TPMS_CAPABILITY_DATA *capabilityData, uint32_t property)
{
    TPM_RC	rc = 0;
    uint32_t	count;
    TPML_TAGGED_POLICY *authPolicies = (TPML_TAGGED_POLICY *)&(capabilityData->data);
    property = property;

    printf("%u authPolicies\n", authPolicies->count);
    for (count = 0 ; count < authPolicies->count ; count++) {
	TSS_TPMS_TAGGED_POLICY_Print(&authPolicies->policies[count], 4);
    }
    return rc;
}

static void printUsage(TPM_CAP capability)
{
    size_t i;
    
    printf("\n");
    printf("getcapability\n");
    printf("\n");
    printf("Runs TPM2_GetCapability\n");
    printf("\n");
    printf("\t-cap\tcapability\n");
    printf("\t-pr\tproperty (defaults to 0)\n");
    printf("\t-pc\tpropertyCount (defaults to 64)\n");
    printf("\n");
    printf("\t-se[0-2] session handle / attributes (default NULL)\n");
    printf("\t\t01\tcontinue\n");
    printf("\t\t80\tcommand audit\n");
    printf("\n");
   
    /* call the usage function in the capability table */
    for (i = 0 ; i < (sizeof(capabilityTable) / sizeof(CAPABILITY_TABLE)) ; i++) {
	if (capabilityTable[i].capability == capability) {
	    capabilityTable[i].usageFunction();
	    exit(1);
	}
    }
    printf("unknown -cap %08x\n", capability);
    usageCapability();
    exit(1);
}

static void usageCapability(void)
{
    printf("\t-cap\tvalues\n"
	   "\n"
	   "\t\tTPM_CAP_ALGS                0\n"
	   "\t\tTPM_CAP_HANDLES             1\n"
	   "\t\tTPM_CAP_COMMANDS            2\n"
	   "\t\tTPM_CAP_PP_COMMANDS         3\n"
	   "\t\tTPM_CAP_AUDIT_COMMANDS      4\n"
	   "\t\tTPM_CAP_PCRS                5\n"
	   "\t\tTPM_CAP_TPM_PROPERTIES      6\n"
	   "\t\tTPM_CAP_PCR_PROPERTIES      7\n"
	   "\t\tTPM_CAP_ECC_CURVES          8\n"
	   "\t\tTPM_CAP_AUTH_POLICIES       9\n"
	   );
    return;
}

static void usageAlgs(void)
{
    printf("TPM_CAP_ALGS -pr not used\n");
    return;
}

static void usageHandles(void)
{
    printf("TPM_CAP_HANDLES -pr values\n"
	   "\n"
	   "TPM_HT_PCR                  00000000\n"
	   "TPM_HT_NV_INDEX             01000000\n"
	   "TPM_HT_LOADED_SESSION       02000000\n"
	   "TPM_HT_SAVED_SESSION        03000000\n"
	   "TPM_HT_PERMANENT            40000000\n"
	   "TPM_HT_TRANSIENT            80000000\n"
	   "TPM_HT_PERSISTENT           81000000\n"
	   );
    return;
}

static void usageCommands(void)
{
    printf("TPM_CAP_COMMANDS -pr is first command\n");
    return;
}

;
static void usagePpCommands(void)
{
    printf("TPM_CAP_PP_COMMANDS -pr is first command\n");
    return;
}

static void usageAuditCommands(void)
{
    printf("TPM_CAP_AUDIT_COMMANDS -pr is first command\n");
    return;
}

static void usagePcrs(void)
{
    printf("TPM_CAP_PCRS -pr is not used\n");
    return;
}

static void usageTpmProperties(void)
{
    printf("TPM_CAP_TPM_PROPERTIES -pr is first property\n");
    printf("\tPT_FIXED starts at %08x\n", PT_FIXED);	
    printf("\tPT_VAR starts at %08x\n", PT_VAR);	
    return;
}

static void usagePcrProperties(void)
{
    printf("TPM_CAP_PCR_PROPERTIES -pr is the first property\n");
    return;
}

static void usageEccCurves(void)
{
    printf("TPM_CAP_ECC_CURVES -pr is the first curve\n");
    return;
}

static void usageAuthPolicies(void)
{
    printf("TPM_CAP_AUTH_POLICIES -pr is the first handle in range 40000000\n");
    return;
}
