/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * FEMU HPKE (RFC 9180) for the TCG MEK-MPA emulation: one suite,
 * DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and ChaCha20-Poly1305, plus
 * Ed25519 for the certificate signature. The code is for emulation only:
 * it is not constant time and has no side-channel review.
 */

#ifndef FEMU_HPKE_H
#define FEMU_HPKE_H

#define FEMU_X25519_LEN     32
#define FEMU_ED25519_SIG    64
#define FEMU_AEAD_KEY       32
#define FEMU_AEAD_NONCE     12
#define FEMU_AEAD_TAG       16
#define FEMU_HKDF_LEN       32

#define FEMU_HPKE_KEM       0x0020
#define FEMU_HPKE_KDF       0x0001
#define FEMU_HPKE_AEAD      0x0003

/* X25519 (RFC 7748): @out = @k times the point with u-coordinate @u */
void femu_x25519(uint8_t out[32], const uint8_t k[32], const uint8_t u[32]);
void femu_x25519_base(uint8_t out[32], const uint8_t k[32]);

/* Ed25519 (RFC 8032) with a 32-byte secret seed */
void femu_ed25519_pub(uint8_t pk[32], const uint8_t seed[32]);
void femu_ed25519_sign(uint8_t sig[64], const uint8_t *m, size_t n,
                       const uint8_t seed[32]);
bool femu_ed25519_verify(const uint8_t sig[64], const uint8_t *m, size_t n,
                         const uint8_t pk[32]);

/* HKDF-SHA256 (RFC 5869) */
void femu_hkdf_extract(uint8_t prk[32], const uint8_t *salt, size_t sl,
                       const uint8_t *ikm, size_t il);
void femu_hkdf_expand(uint8_t *okm, size_t l, const uint8_t prk[32],
                      const uint8_t *info, size_t il);

/* ChaCha20-Poly1305 (RFC 8439); @ct holds @n + 16 bytes */
void femu_aead_seal(uint8_t *ct, const uint8_t key[32],
                    const uint8_t nonce[12], const uint8_t *aad, size_t al,
                    const uint8_t *pt, size_t n);
/* @ctl includes the tag; false (and @pt zeroed) when the tag is wrong */
bool femu_aead_open(uint8_t *pt, const uint8_t key[32],
                    const uint8_t nonce[12], const uint8_t *aad, size_t al,
                    const uint8_t *ct, size_t ctl);

typedef struct FemuHpkeCtx {
    uint8_t key[FEMU_AEAD_KEY];
    uint8_t base_nonce[FEMU_AEAD_NONCE];
    uint64_t seq;
} FemuHpkeCtx;

/* DeriveKeyPair (RFC 9180 7.1.3) */
void femu_hpke_derive_keypair(uint8_t sk[32], uint8_t pk[32],
                              const uint8_t *ikm, size_t il);
/* Decap; false for an all-zero DH result (RFC 9180 7.1.4) */
bool femu_hpke_decap(uint8_t ss[32], const uint8_t enc[32],
                     const uint8_t skr[32]);
/* SetupBaseS with a given ephemeral key, and SetupBaseR */
bool femu_hpke_setup_s(FemuHpkeCtx *c, uint8_t enc[32],
                       const uint8_t ske[32], const uint8_t pkr[32],
                       const uint8_t *info, size_t il);
bool femu_hpke_setup_r(FemuHpkeCtx *c, const uint8_t enc[32],
                       const uint8_t skr[32], const uint8_t *info, size_t il);
/* Seal and Open with the next sequence number; false when it runs out */
bool femu_hpke_seal(FemuHpkeCtx *c, uint8_t *ct, const uint8_t *aad,
                    size_t al, const uint8_t *pt, size_t n);
bool femu_hpke_open(FemuHpkeCtx *c, uint8_t *pt, const uint8_t *aad,
                    size_t al, const uint8_t *ct, size_t ctl);
void femu_hpke_wipe(FemuHpkeCtx *c);

#endif
