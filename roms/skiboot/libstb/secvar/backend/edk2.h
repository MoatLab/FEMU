/* Copyright (c) 2006 - 2015, Intel Corporation. All rights reserved. This
 * program and the accompanying materials are licensed and made available
 * under the terms and conditions of the 2-Clause BSD License which
 * accompanies this distribution.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * This file is derived from the following files referred from edk2-staging[1] repo
 * of tianocore
 *
 * MdePkg/Include/Guid/GlobalVariable.h
 * MdePkg/Include/Guid/WinCertificate.h
 * MdePkg/Include/Uefi/UefiMultiPhase.h
 * MdePkg/Include/Uefi/UefiBaseType.h
 * MdePkg/Include/Guid/ImageAuthentication.h
 *
 * [1] https://github.com/tianocore/edk2-staging
 *
 * Copyright 2020 IBM Corp.
 */

#ifndef __EDK2_H__
#define __EDK2_H__

#include <compiler.h>
#include <ccan/short_types/short_types.h>

#define UUID_SIZE 16

typedef struct {
        u8 b[UUID_SIZE];
} uuid_t;

#define EFI_GLOBAL_VARIABLE_GUID (uuid_t){{0x61, 0xDF, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11, 0xaa, \
			 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}}

#define EFI_IMAGE_SECURITY_DATABASE_GUID (uuid_t){{0xcb, 0xb2, 0x19, 0xd7, 0x3a, 0x3d, 0x96, 0x45, \
					   0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f}}

#define SECVAR_ATTRIBUTES	39

///
/// This identifies a signature based on an X.509 certificate. If the signature is an X.509
/// certificate then verification of the signature of an image should validate the public
/// key certificate in the image using certificate path verification, up to this X.509
/// certificate as a trusted root.  The SignatureHeader size shall always be 0. The
/// SignatureSize may vary but shall always be 16 (size of the SignatureOwner component) +
/// the size of the certificate itself.
/// Note: This means that each certificate will normally be in a separate EFI_SIGNATURE_LIST.
///

static const uuid_t EFI_CERT_TYPE_PKCS7_GUID = {{0x9d, 0xd2, 0xaf, 0x4a, 0xdf, 0x68, 0xee, 0x49, 0x8a, 0xa9, 0x34, 0x7d, 0x37, 0x56, 0x65, 0xa7}};

static const uuid_t EFI_CERT_X509_GUID = {{ 0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a, 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72 }};

static const uuid_t EFI_CERT_SHA1_GUID = {{ 0x12, 0xa5, 0x6c, 0x82, 0x10, 0xcf, 0xc9, 0x4a, 0xb1, 0x87, 0xbe, 0x01, 0x49, 0x66, 0x31, 0xbd }};

static const uuid_t EFI_CERT_SHA224_GUID = {{ 0x33, 0x52, 0x6e, 0x0b, 0x5c, 0xa6, 0xc9, 0x44, 0x94, 0x07, 0xd9, 0xab, 0x83, 0xbf, 0xc8, 0xbd }};

static const uuid_t EFI_CERT_SHA256_GUID = {{ 0x26, 0x16, 0xc4, 0xc1, 0x4c, 0x50, 0x92, 0x40, 0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28 }};

static const uuid_t EFI_CERT_SHA384_GUID = {{ 0x07, 0x53, 0x3e, 0xff, 0xd0, 0x9f, 0xc9, 0x48, 0x85, 0xf1, 0x8a, 0xd5, 0x6c, 0x70, 0x1e, 0x01 }};

static const uuid_t EFI_CERT_SHA512_GUID = {{ 0xae, 0x0f, 0x3e, 0x09, 0xc4, 0xa6, 0x50, 0x4f, 0x9f, 0x1b, 0xd4, 0x1e, 0x2b, 0x89, 0xc1, 0x9a }};

static const uuid_t EFI_CERT_RSA2048_GUID = {{ 0xe8, 0x66, 0x57, 0x3c, 0x9c, 0x26, 0x34, 0x4e, 0xaa, 0x14, 0xed, 0x77, 0x6e, 0x85, 0xb3, 0xb6 }};

#define EFI_VARIABLE_NON_VOLATILE				0x00000001
#define EFI_VARIABLE_BOOTSERVICE_ACCESS				0x00000002
#define EFI_VARIABLE_RUNTIME_ACCESS				0x00000004

/*
 * Attributes of Authenticated Variable
 */
#define EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS	0x00000020
#define EFI_VARIABLE_APPEND_WRITE				0x00000040
/*
 * NOTE: EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS is deprecated and should be
 * considered reserved.
 */
#define EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS			0x00000010

/*
 * win_certificate.w_certificate_type
 */
#define WIN_CERT_TYPE_PKCS_SIGNED_DATA	0x0002

#define SECURE_BOOT_MODE_ENABLE           1
#define SECURE_BOOT_MODE_DISABLE          0
///
/// Depricated value definition for SetupMode variable
///
#define SETUP_MODE                        1
#define USER_MODE                         0

/*
 * EFI Time Abstraction:
 *   Year:       1900 - 9999
 *   Month:      1 - 12
 *   Day:        1 - 31
 *   Hour:       0 - 23
 *   Minute:     0 - 59
 *   Second:     0 - 59
 *   Nanosecond: 0 - 999,999,999
 *   TimeZone:   -1440 to 1440 or 2047
 */
struct efi_time {
	le16 year;
	u8 month;
	u8 day;
	u8 hour;
	u8 minute;
	u8 second;
	u8 pad1;
	le32 nanosecond;
	le16 timezone;
	u8 daylight;
	u8 pad2;
};
//***********************************************************************
// Signature Database
//***********************************************************************
///
/// The format of a signature database.
///

typedef struct __packed {
  ///
  /// An identifier which identifies the agent which added the signature to the list.
  ///
  uuid_t SignatureOwner;
  ///
  /// The format of the signature is defined by the SignatureType.
  ///
  unsigned char SignatureData[0];
} EFI_SIGNATURE_DATA;

typedef struct __packed {
  ///
  /// Type of the signature. GUID signature types are defined in below.
  ///
  uuid_t SignatureType;
  ///
  /// Total size of the signature list, including this header.
  ///
  leint32_t	SignatureListSize;
  ///
  /// Size of the signature header which precedes the array of signatures.
  ///
  leint32_t	SignatureHeaderSize;
  ///
  /// Size of each signature.
  ///
  leint32_t	SignatureSize;
  ///
  /// Header before the array of signatures. The format of this header is specified
  /// by the SignatureType.
  /// UINT8           SignatureHeader[SignatureHeaderSize];
  ///
  /// An array of signatures. Each signature is SignatureSize bytes in length.
  /// EFI_SIGNATURE_DATA Signatures[][SignatureSize];
  ///
} EFI_SIGNATURE_LIST;


/*
 * The win_certificate structure is part of the PE/COFF specification.
 */
struct win_certificate {
	/*
	 * The length of the entire certificate, including the length of the
	 * header, in bytes.
	 */
	le32  dw_length;
	/*
	 * The revision level of the WIN_CERTIFICATE structure. The current
	 * revision level is 0x0200.
	 */
	le16  w_revision;
	/*
	 * The certificate type. See WIN_CERT_TYPE_xxx for the UEFI certificate
	 * types. The UEFI specification reserves the range of certificate type
	 * values from 0x0EF0 to 0x0EFF.
	 */
	le16  w_certificate_type;
	/*
	 * The following is the actual certificate. The format of
	 * the certificate depends on wCertificateType.
	 */
	/// UINT8 bCertificate[ANYSIZE_ARRAY];
} __packed;

/*
 * Certificate which encapsulates a GUID-specific digital signature
 */
struct win_certificate_uefi_guid {
	/*
	 * This is the standard win_certificate header, where w_certificate_type
	 * is set to WIN_CERT_TYPE_EFI_GUID.
	 */
	struct win_certificate hdr;
	/*
	 * This is the unique id which determines the format of the cert_data.
	 */
	uuid_t cert_type;
	/*
	 * The following is the certificate data. The format of the data is
	 * determined by the @cert_type. If @cert_type is
	 * EFI_CERT_TYPE_RSA2048_SHA256_GUID, the @cert_data will be
	 * EFI_CERT_BLOCK_RSA_2048_SHA256 structure.
	 */
	u8 cert_data[];
} __packed;

/*
 * When the attribute EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS is set,
 * then the Data buffer shall begin with an instance of a complete (and
 * serialized) EFI_VARIABLE_AUTHENTICATION_2 descriptor. The descriptor shall be
 * followed by the new variable value and DataSize shall reflect the combined
 * size of the descriptor and the new variable value. The authentication
 * descriptor is not part of the variable data and is not returned by subsequent
 * calls to GetVariable().
 */
struct efi_variable_authentication_2 {
	/*
	 * For the TimeStamp value, components Pad1, Nanosecond, TimeZone, Daylight and
	 * Pad2 shall be set to 0. This means that the time shall always be expressed in GMT.
	 */
	struct efi_time timestamp;
	/*
	 * Only a CertType of  EFI_CERT_TYPE_PKCS7_GUID is accepted.
	 */
	struct win_certificate_uefi_guid auth_info;
} __packed;

#endif
