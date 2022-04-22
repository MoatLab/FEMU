/** @file
  PBKDF2 Key Derivation Function Wrapper Implementation over OpenSSL.

Copyright (c) 2016, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "InternalCryptLib.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>

/**
  Derives a key from a password using a salt and iteration count, based on PKCS#5 v2.0
  password based encryption key derivation function PBKDF2, as specified in RFC 2898.

  If Password or Salt or OutKey is NULL, then return FALSE.
  If the hash algorithm could not be determined, then return FALSE.

  @param[in]  PasswordLength  Length of input password in bytes.
  @param[in]  Password        Pointer to the array for the password.
  @param[in]  SaltLength      Size of the Salt in bytes.
  @param[in]  Salt            Pointer to the Salt.
  @param[in]  IterationCount  Number of iterations to perform. Its value should be
                              greater than or equal to 1.
  @param[in]  DigestSize      Size of the message digest to be used (eg. SHA256_DIGEST_SIZE).
                              NOTE: DigestSize will be used to determine the hash algorithm.
                                    Only SHA1_DIGEST_SIZE or SHA256_DIGEST_SIZE is supported.
  @param[in]  KeyLength       Size of the derived key buffer in bytes.
  @param[out] OutKey          Pointer to the output derived key buffer.

  @retval  TRUE   A key was derived successfully.
  @retval  FALSE  One of the pointers was NULL or one of the sizes was too large.
  @retval  FALSE  The hash algorithm could not be determined from the digest size.
  @retval  FALSE  The key derivation operation failed.

**/
BOOLEAN
EFIAPI
Pkcs5HashPassword (
  IN  UINTN        PasswordLength,
  IN  CONST CHAR8  *Password,
  IN  UINTN        SaltLength,
  IN  CONST UINT8  *Salt,
  IN  UINTN        IterationCount,
  IN  UINTN        DigestSize,
  IN  UINTN        KeyLength,
  OUT UINT8        *OutKey
  )
{
  CONST EVP_MD  *HashAlg;

  HashAlg = NULL;

  //
  // Parameter Checking.
  //
  if ((Password == NULL) || (Salt == NULL) || (OutKey == NULL)) {
    return FALSE;
  }

  if ((PasswordLength == 0) || (PasswordLength > INT_MAX) ||
      (SaltLength == 0) || (SaltLength > INT_MAX) ||
      (KeyLength == 0) || (KeyLength > INT_MAX) ||
      (IterationCount < 1) || (IterationCount > INT_MAX))
  {
    return FALSE;
  }

  //
  // Make sure the digest algorithm is supported.
  //
  switch (DigestSize) {
    case SHA1_DIGEST_SIZE:
      HashAlg = EVP_sha1 ();
      break;
    case SHA256_DIGEST_SIZE:
      HashAlg = EVP_sha256 ();
      break;
    default:
      return FALSE;
      break;
  }

  //
  // Perform password-based key derivation routines.
  //
  return (BOOLEAN)PKCS5_PBKDF2_HMAC (
                    (const char *)Password,
                    (int)PasswordLength,
                    (const unsigned char *)Salt,
                    (int)SaltLength,
                    (int)IterationCount,
                    HashAlg,
                    (int)KeyLength,
                    (unsigned char *)OutKey
                    );
}
