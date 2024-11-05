/********************************************************************************/
/*										*/
/*			    TSS Configuration Properties			*/
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

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <ibmtss/tss.h>
#include <ibmtss/tsstransmit.h>
#ifndef TPM_TSS_NOCRYPTO
#include <ibmtss/tsscrypto.h>
#endif
#include <ibmtss/tssprint.h>

#include "tssproperties.h"

/* For systems where there are no environment variables, GETENV returns NULL.  This simulates the
   situation when an environment variable is not set, causing the compiled in default to be used. */
#ifndef TPM_TSS_NOENV
#define GETENV(x) getenv(x)
#else
#define GETENV(x) NULL
#endif

/* local prototypes */

static TPM_RC TSS_SetTraceLevel(const char *value);
static TPM_RC TSS_SetDataDirectory(TSS_CONTEXT *tssContext, const char *value);
static TPM_RC TSS_SetCommandPort(TSS_CONTEXT *tssContext, const char *value);
static TPM_RC TSS_SetPlatformPort(TSS_CONTEXT *tssContext, const char *value);
static TPM_RC TSS_SetServerName(TSS_CONTEXT *tssContext, const char *value);
static TPM_RC TSS_SetServerType(TSS_CONTEXT *tssContext, const char *value);
static TPM_RC TSS_SetInterfaceType(TSS_CONTEXT *tssContext, const char *value);
static TPM_RC TSS_SetDevice(TSS_CONTEXT *tssContext, const char *value);
static TPM_RC TSS_SetEncryptSessions(TSS_CONTEXT *tssContext, const char *value);

/* globals for the library */

/* tracing is global to avoid passing the context into every function call */
int tssVerbose = TRUE;		/* initial value so TSS_Properties_Init errors emit message */
int tssVverbose = FALSE;

/* This is a total hack to ensure that the global verbose flags are only set once.  It's used by the
   two entry points to the TSS, TSS_Create() and TSS_SetProperty() */

int tssFirstCall = TRUE;

/* defaults for global settings */

#ifndef TPM_TRACE_LEVEL_DEFAULT 	
#define TPM_TRACE_LEVEL_DEFAULT 	"0"
#endif

#ifndef TPM_COMMAND_PORT_DEFAULT
#define TPM_COMMAND_PORT_DEFAULT 	"2321"		/* default for MS simulator */
#endif

#ifndef TPM_PLATFORM_PORT_DEFAULT
#define TPM_PLATFORM_PORT_DEFAULT 	"2322"		/* default for MS simulator */
#endif

#ifndef TPM_SERVER_NAME_DEFAULT
#define TPM_SERVER_NAME_DEFAULT		"localhost"	/* default to local machine */
#endif

#ifndef TPM_SERVER_TYPE_DEFAULT
#define TPM_SERVER_TYPE_DEFAULT		"mssim"		/* default to MS simulator format */
#endif

#ifndef TPM_DATA_DIR_DEFAULT
#define TPM_DATA_DIR_DEFAULT		"."		/* default to current working directory */
#endif

#ifndef TPM_INTERFACE_TYPE_DEFAULT
#ifndef TPM_NOSOCKET
#define TPM_INTERFACE_TYPE_DEFAULT	"socsim"	/* default to MS simulator interface */
#else
#define TPM_INTERFACE_TYPE_DEFAULT	"dev"		/* if no sockets, default to device driver */
#endif
#endif

#ifndef TPM_DEVICE_DEFAULT
#ifdef TPM_POSIX
#define TPM_DEVICE_DEFAULT		"/dev/tpm0"	/* default to Linux device driver */
#endif
#ifdef TPM_WINDOWS
#define TPM_DEVICE_DEFAULT		"tddl.dll"	/* default to Windows TPM interface dll */
#endif
#endif

#ifndef TPM_ENCRYPT_SESSIONS_DEFAULT
#define TPM_ENCRYPT_SESSIONS_DEFAULT	"1"
#endif

/* TSS_GlobalProperties_Init() sets the global verbose trace flags at the first entry points to the
   TSS */

TPM_RC TSS_GlobalProperties_Init(void)
{
    TPM_RC		rc = 0;
    const char 		*value;

    /* trace level is global, tssContext can be null */
    if (rc == 0) {
	value = GETENV("TPM_TRACE_LEVEL");
	rc = TSS_SetTraceLevel(value);
    }
    return rc;
}


/* TSS_Properties_Init() sets the initial TSS_CONTEXT properties based on either the environment
   variables (if set) or the defaults (if not).
*/

TPM_RC TSS_Properties_Init(TSS_CONTEXT *tssContext)
{
    TPM_RC		rc = 0;
    const char 		*value;

    if (rc == 0) {
	tssContext->tssAuthContext = NULL;
	tssContext->tssFirstTransmit = TRUE;	/* connection not opened */
	tssContext->tpm12Command = FALSE;
#ifdef TPM_WINDOWS
	tssContext->sock_fd = INVALID_SOCKET;
#endif
#ifdef TPM_POSIX
#ifndef TPM_NOSOCKET
	tssContext->sock_fd = -1;
#endif 	/* TPM_NOSOCKET */
	tssContext->dev_fd = -1;
#endif	/* TPM_POSIX */

#ifdef TPM_SKIBOOT
	tssContext->tpm_driver = NULL;
	tssContext->tpm_device = NULL;
#endif /* TPM_SKIBOOT */
	
#ifndef TPM_TSS_NOCRYPTO
#ifndef TPM_TSS_NOFILE
	tssContext->tssSessionEncKey = NULL;
	tssContext->tssSessionDecKey = NULL;
#endif
#endif
    }
    /* for a minimal TSS with no file support */
#ifdef TPM_TSS_NOFILE
    {
	size_t i;
	for (i = 0 ; i < (sizeof(tssContext->sessions) / sizeof(TSS_SESSIONS)) ; i++) {
	    tssContext->sessions[i].sessionHandle = TPM_RH_NULL;
	    tssContext->sessions[i].sessionData = NULL;
	    tssContext->sessions[i].sessionDataLength = 0;
	}
	for (i = 0 ; i < (sizeof(tssContext->objectPublic) / sizeof(TSS_OBJECT_PUBLIC)) ; i++) {
	    tssContext->objectPublic[i].objectHandle = TPM_RH_NULL;
	}
	for (i = 0 ; i < (sizeof(tssContext->nvPublic) / sizeof(TSS_NVPUBLIC)) ; i++) {
	    tssContext->nvPublic[i].nvIndex = TPM_RH_NULL;
	}
    }
#endif
    /* data directory */
    if (rc == 0) {
	value = GETENV("TPM_DATA_DIR");
	rc = TSS_SetDataDirectory(tssContext, value);
    }
    /* flag whether session state should be encrypted */
    if (rc == 0) {
	value = GETENV("TPM_ENCRYPT_SESSIONS");
	rc = TSS_SetEncryptSessions(tssContext, value);
    }
    /* TPM socket command port */
    if (rc == 0) {
	value = GETENV("TPM_COMMAND_PORT");
	rc = TSS_SetCommandPort(tssContext, value);
    }
    /* TPM simulator socket platform port */
    if (rc == 0) {
	value = GETENV("TPM_PLATFORM_PORT");
	rc = TSS_SetPlatformPort(tssContext, value);
    }
    /* TPM socket host name */
    if (rc == 0) {
	value = GETENV("TPM_SERVER_NAME");
	rc = TSS_SetServerName(tssContext, value);
    }
    /* TPM socket server type */
    if (rc == 0) {
	value = GETENV("TPM_SERVER_TYPE");
	rc = TSS_SetServerType(tssContext, value);
    }
    /* TPM interface type */
    if (rc == 0) {
	value = GETENV("TPM_INTERFACE_TYPE");
	rc = TSS_SetInterfaceType(tssContext, value);
    }
    /* TPM device within the interface type */
    if (rc == 0) {
	value = GETENV("TPM_DEVICE");
	rc = TSS_SetDevice(tssContext, value);
    }
    return rc;
}

/* TSS_SetProperty() sets the property to the value.

   The format of the property and value the same as that of the environment variable.

   A NULL value sets the property to the default.
*/

TPM_RC TSS_SetProperty(TSS_CONTEXT *tssContext,
		       int property,
		       const char *value)
{
    TPM_RC		rc = 0;

    /* at the first call to the TSS, initialize global variables */
    if (tssFirstCall) {
#ifndef TPM_TSS_NOCRYPTO
	/* crypto module initializations */
	if (rc == 0) {
	    rc = TSS_Crypto_Init();
	}
#endif
	if (rc == 0) {
	    rc = TSS_GlobalProperties_Init();
	}
	tssFirstCall = FALSE;
    }
    if (rc == 0) {
	switch (property) {
	  case TPM_TRACE_LEVEL:
	    rc = TSS_SetTraceLevel(value);
	    break;
	  case TPM_DATA_DIR:
	    rc = TSS_SetDataDirectory(tssContext, value);
	    break;
	  case TPM_COMMAND_PORT:	
	    rc = TSS_SetCommandPort(tssContext, value);
	    break;
	  case TPM_PLATFORM_PORT:	
	    rc = TSS_SetPlatformPort(tssContext, value);
	    break;
	  case TPM_SERVER_NAME:		
	    rc = TSS_SetServerName(tssContext, value);
	    break;
	  case TPM_SERVER_TYPE:		
	    rc = TSS_SetServerType(tssContext, value);
	    break;
	  case TPM_INTERFACE_TYPE:
	    rc = TSS_SetInterfaceType(tssContext, value);
	    break;
	  case TPM_DEVICE:
	    rc = TSS_SetDevice(tssContext, value);
	    break;
	  case TPM_ENCRYPT_SESSIONS:
	    rc = TSS_SetEncryptSessions(tssContext, value);
	    break;
	  default:
	    rc = TSS_RC_BAD_PROPERTY;
	}
    }
    return rc;
}

/* TSS_SetTraceLevel() sets the trace level.

   0:	no printing
   1:	error printing
   2:	trace printing
*/

static TPM_RC TSS_SetTraceLevel(const char *value)
{
    TPM_RC		rc = 0;
    int			irc = 0;
    int 		level;

    if (rc == 0) {
	if (value == NULL) {
	    value = TPM_TRACE_LEVEL_DEFAULT;
	}
    }
#if !defined(__ULTRAVISOR__) && !defined(TPM_SKIBOOT)
    if (rc == 0) {
	irc = sscanf(value, "%u", &level);
	if (irc != 1) {
	    if (tssVerbose) printf("TSS_SetTraceLevel: Error, value invalid\n");
	    rc = TSS_RC_BAD_PROPERTY_VALUE;
	}
    }
    /* disable tracing within the ultravisor and skiboot, which doesn't implement sscanf() anyway */
#else
    irc = irc;
    level = 0;
#endif
    if (rc == 0) {
	switch (level) {
	  case 0:
	    tssVerbose = FALSE;
	    tssVverbose = FALSE;
	    break;
	  case 1:
	    tssVerbose = TRUE;
	    tssVverbose = FALSE;
	    break;
	  default:
	    tssVerbose = TRUE;
	    tssVverbose = TRUE;
	    break;
	}
    }
    return rc;
}

static TPM_RC TSS_SetDataDirectory(TSS_CONTEXT *tssContext, const char *value)
{
    TPM_RC		rc = 0;

    if (rc == 0) {
	if (value == NULL) {
	    value = TPM_DATA_DIR_DEFAULT;
	}
    }
    if (rc == 0) {
	tssContext->tssDataDirectory = value;
	/* appended to this is 17 characters /cccnnnnnnnn.bin[nul], add a bit of margin for future
	   prefixes */
	if (strlen(value) > (TPM_DATA_DIR_PATH_LENGTH - 24)) {
	    if (tssVerbose) printf("TSS_SetDataDirectory: Error, value too long\n");
	    rc = TSS_RC_BAD_PROPERTY_VALUE;
	}
    }
    return rc;
}

static TPM_RC TSS_SetCommandPort(TSS_CONTEXT *tssContext, const char *value)
{
    TPM_RC		rc = 0;
    int			irc = 0;

    /* close an open connection before changing property */
    if (rc == 0) {
	rc = TSS_Close(tssContext);
    }
    if (rc == 0) {
	if (value == NULL) {
	    value = TPM_COMMAND_PORT_DEFAULT;
	}
    }
#ifndef TPM_NOSOCKET
    if (rc == 0) {
	irc = sscanf(value, "%hu", &tssContext->tssCommandPort);
	if (irc != 1) {
	    if (tssVerbose) printf("TSS_SetCommandPort: Error, value invalid\n");
	    rc = TSS_RC_BAD_PROPERTY_VALUE;
	}
    }
#else
    tssContext->tssCommandPort = 0;
    irc = irc;
#endif /* TPM_NOSOCKET */
    return rc;
}

static TPM_RC TSS_SetPlatformPort(TSS_CONTEXT *tssContext, const char *value)
{
    TPM_RC		rc = 0;
    int			irc = 0;

    /* close an open connection before changing property */
    if (rc == 0) {
	rc = TSS_Close(tssContext);
    }
    if (rc == 0) {
	if (value == NULL) {
	    value = TPM_PLATFORM_PORT_DEFAULT;
	}
    }
#ifndef TPM_NOSOCKET
   if (rc == 0) {
	irc = sscanf(value, "%hu", &tssContext->tssPlatformPort);
	if (irc != 1) {
	    if (tssVerbose) printf("TSS_SetPlatformPort: Error, , value invalid\n");
	    rc = TSS_RC_BAD_PROPERTY_VALUE;
	}
    }
#else
   tssContext->tssPlatformPort = 0;
    irc = irc;
#endif /* TPM_NOSOCKET */
    return rc;
}

static TPM_RC TSS_SetServerName(TSS_CONTEXT *tssContext, const char *value)
{
    TPM_RC		rc = 0;

    /* close an open connection before changing property */
    if (rc == 0) {
	rc = TSS_Close(tssContext);
    }
    if (rc == 0) {
	if (value == NULL) {
	    value = TPM_SERVER_NAME_DEFAULT;
	}
    }
    if (rc == 0) {
	tssContext->tssServerName = value;
    }
    return rc;
}

static TPM_RC TSS_SetServerType(TSS_CONTEXT *tssContext, const char *value)
{
    TPM_RC		rc = 0;

    /* close an open connection before changing property */
    if (rc == 0) {
	rc = TSS_Close(tssContext);
    }
    if (rc == 0) {
	if (value == NULL) {
	    value = TPM_SERVER_TYPE_DEFAULT;
	}
    }
    if (rc == 0) {
	tssContext->tssServerType = value;
    }
    return rc;
}

static TPM_RC TSS_SetInterfaceType(TSS_CONTEXT *tssContext, const char *value)
{
    TPM_RC		rc = 0;

    /* close an open connection before changing property */
    if (rc == 0) {
	rc = TSS_Close(tssContext);
    }
    if (rc == 0) {
	if (value == NULL) {
	    value = TPM_INTERFACE_TYPE_DEFAULT;
	}
    }
    if (rc == 0) {
	tssContext->tssInterfaceType = value;
    }
    return rc;
}

static TPM_RC TSS_SetDevice(TSS_CONTEXT *tssContext, const char *value)
{
    TPM_RC		rc = 0;

    /* close an open connection before changing property */
    if (rc == 0) {
	rc = TSS_Close(tssContext);
    }
    if (rc == 0) {
	if (value == NULL) {
	    value = TPM_DEVICE_DEFAULT;
	}
    }
    if (rc == 0) {
	tssContext->tssDevice = value;
    }
    return rc;
}

static TPM_RC TSS_SetEncryptSessions(TSS_CONTEXT *tssContext, const char *value)
{
    TPM_RC		rc = 0;
    int			irc = 0;

    if (rc == 0) {
	if (value == NULL) {
	    value = TPM_ENCRYPT_SESSIONS_DEFAULT;
	}
    }
#ifndef TPM_TSS_NOFILE
   if (rc == 0) {
	irc = sscanf(value, "%u", &tssContext->tssEncryptSessions);
	if (irc != 1) {
	    if (tssVerbose) printf("TSS_SetEncryptSessions: Error, value invalid\n");
	    rc = TSS_RC_BAD_PROPERTY_VALUE;
	}
    }
#else
   tssContext->tssEncryptSessions = TRUE;
   irc = irc;
#endif /* TPM_TSS_NOFILE */
   return rc;
}
