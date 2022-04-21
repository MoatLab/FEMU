// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2016 IBM Corp. */

#ifndef __STB_STATUS_CODES_H
#define __STB_STATUS_CODES_H

/*  general return codes */
#define STB_ERROR		-1
#define STB_ARG_ERROR		-2
#define STB_DRIVER_ERROR	-3

/* secure boot */
#define STB_SECURE_MODE_DISABLED	 100
#define STB_VERIFY_FAILED  		-100

/* trusted boot */
#define STB_TRUSTED_MODE_DISABLED	 200
#define STB_MEASURE_FAILED		-200

/* TPM */
#define STB_NO_TPM_INITIALIZED	 300
#define STB_TPM_OVERFLOW	-300
#define STB_TPM_TIMEOUT	-301

#endif /* __STB_STATUS_CODES_H */
