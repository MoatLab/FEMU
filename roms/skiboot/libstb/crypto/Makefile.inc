# SPDX-License-Identifier: Apache-2.0
# Copyright 2012-2019 IBM Corp

CRYPTO_DIR = $(LIBSTB_DIR)/crypto
MBEDTLS_DIR = $(CRYPTO_DIR)/mbedtls/library

SUBDIRS += $(CRYPTO_DIR) $(MBEDTLS_DIR)

# Source file list borrowed from mbedtls/library/Makefile
# Can probably trim disabled files for slightly less noise
MBED_CRYPTO_SRCS  = aes.c aesni.c arc4.c
MBED_CRYPTO_SRCS += aria.c asn1parse.c asn1write.c
MBED_CRYPTO_SRCS += base64.c bignum.c blowfish.c
MBED_CRYPTO_SRCS += camellia.c ccm.c chacha20.c
MBED_CRYPTO_SRCS += chachapoly.c cipher.c cipher_wrap.c
MBED_CRYPTO_SRCS += cmac.c ctr_drbg.c des.c
MBED_CRYPTO_SRCS += dhm.c ecdh.c ecdsa.c
MBED_CRYPTO_SRCS += ecjpake.c ecp.c
MBED_CRYPTO_SRCS += ecp_curves.c entropy.c entropy_poll.c
MBED_CRYPTO_SRCS += error.c gcm.c havege.c
MBED_CRYPTO_SRCS += hkdf.c
MBED_CRYPTO_SRCS += hmac_drbg.c md.c md2.c
MBED_CRYPTO_SRCS += md4.c md5.c md_wrap.c
MBED_CRYPTO_SRCS += memory_buffer_alloc.c nist_kw.c
MBED_CRYPTO_SRCS += oid.c padlock.c pem.c
MBED_CRYPTO_SRCS += pk.c pk_wrap.c pkcs12.c
MBED_CRYPTO_SRCS += pkcs5.c pkparse.c pkwrite.c
MBED_CRYPTO_SRCS += platform.c platform_util.c poly1305.c
MBED_CRYPTO_SRCS += ripemd160.c rsa_internal.c rsa.c
MBED_CRYPTO_SRCS += sha1.c sha256.c sha512.c
MBED_CRYPTO_SRCS += threading.c timing.c version.c
MBED_CRYPTO_SRCS += version_features.c xtea.c

MBED_X509_SRCS  = certs.c pkcs11.c x509.c
MBED_X509_SRCS += x509_create.c x509_crl.c x509_crt.c
MBED_X509_SRCS += x509_csr.c x509write_crt.c x509write_csr.c

CFLAGS_$(MBEDTLS_DIR)/  = -I$(SRC)/$(LIBSTB_DIR)/crypto -DMBEDTLS_CONFIG_FILE='<mbedtls-config.h>'
CFLAGS_$(MBEDTLS_DIR)/ += -Wno-unused-function -Wno-suggest-attribute=const

MBEDTLS_SRCS = $(addprefix mbedtls/library/,$(MBED_CRYPTO_SRCS) $(MBED_X509_SRCS))

MBEDTLS_OBJS = $(MBEDTLS_SRCS:%.c=%.o)

include $(SRC)/$(CRYPTO_DIR)/pkcs7/Makefile.inc

CRYPTO = $(CRYPTO_DIR)/built-in.a

$(CRYPTO): $(MBEDTLS_OBJS:%=$(CRYPTO_DIR)/%) $(PKCS7)
