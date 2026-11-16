/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * FEMU HPKE for the TCG MEK-MPA emulation (see femu-hpke.h).
 *
 * The field, X25519, Ed25519 and Poly1305 code follows the public domain
 * TweetNaCl layout: an element of GF(2^255 - 19) is 16 limbs of 16 bits.
 * Hashes and HMAC come from glib.
 *
 *   HPKE Open:  enc --X25519(skR)--> dh --HKDF--> shared secret
 *               shared secret + info --HKDF--> key, base_nonce
 *               ChaCha20-Poly1305(key, base_nonce ^ seq) --> plaintext
 */

#include "qemu/osdep.h"
#include "qemu/bswap.h"
#include "femu-hpke.h"

typedef int64_t gf[16];

/* a wipe the compiler keeps: key material must not outlive its use */
static void hpke_wipe(void *p, size_t n)
{
    volatile uint8_t *q = p;    /* keeps the stores to dead memory */

    while (n--) {
        *q++ = 0;
    }
}

static const gf gf0;
static const gf gf1 = { 1 };
static const gf c121665 = { 0xDB41, 1 };
static const gf ed_d = {
    0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
    0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203,
};
static const gf ed_d2 = {
    0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
    0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406,
};
static const gf ed_x = {
    0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
    0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169,
};
static const gf ed_y = {
    0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
    0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
};
static const gf ed_i = {
    0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
    0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83,
};

/* ---- GF(2^255 - 19) ---- */

static void fset(gf r, const gf a)
{
    memcpy(r, a, sizeof(gf));
}

static void fcarry(gf o)
{
    int64_t c;
    int i;

    for (i = 0; i < 16; i++) {
        o[i] += 1LL << 16;
        c = o[i] >> 16;
        if (i < 15) {
            o[i + 1] += c - 1;
        } else {
            o[0] += 38 * (c - 1);
        }
        o[i] -= c * 65536;
    }
}

/* swap @p and @q when @b is 1 */
static void fsel(gf p, gf q, int b)
{
    int64_t c = ~(int64_t)(b - 1);
    int64_t t;
    int i;

    for (i = 0; i < 16; i++) {
        t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void fpack(uint8_t o[32], const gf n)
{
    gf m;
    gf t;
    int b;
    int i;
    int j;

    fset(t, n);
    fcarry(t);
    fcarry(t);
    fcarry(t);
    for (j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        fsel(t, m, 1 - b);
    }
    for (i = 0; i < 16; i++) {
        o[2 * i] = t[i] & 0xff;
        o[2 * i + 1] = t[i] >> 8;
    }
}

static void funpack(gf o, const uint8_t n[32])
{
    int i;

    for (i = 0; i < 16; i++) {
        o[i] = n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
    }
    o[15] &= 0x7fff;
}

static bool fneq(const gf a, const gf b)
{
    uint8_t c[32];
    uint8_t d[32];

    fpack(c, a);
    fpack(d, b);
    return memcmp(c, d, 32) != 0;
}

static int fpar(const gf a)
{
    uint8_t d[32];

    fpack(d, a);
    return d[0] & 1;
}

static void fadd(gf o, const gf a, const gf b)
{
    int i;

    for (i = 0; i < 16; i++) {
        o[i] = a[i] + b[i];
    }
}

static void fsub(gf o, const gf a, const gf b)
{
    int i;

    for (i = 0; i < 16; i++) {
        o[i] = a[i] - b[i];
    }
}

static void fmul(gf o, const gf a, const gf b)
{
    int64_t t[31] = { 0 };
    int i;
    int j;

    for (i = 0; i < 16; i++) {
        for (j = 0; j < 16; j++) {
            t[i + j] += a[i] * b[j];
        }
    }
    for (i = 0; i < 15; i++) {
        t[i] += 38 * t[i + 16];
    }
    for (i = 0; i < 16; i++) {
        o[i] = t[i];
    }
    fcarry(o);
    fcarry(o);
}

static void fsq(gf o, const gf a)
{
    fmul(o, a, a);
}

static void finv(gf o, const gf in)
{
    gf c;
    int a;

    fset(c, in);
    for (a = 253; a >= 0; a--) {
        fsq(c, c);
        if (a != 2 && a != 4) {
            fmul(c, c, in);
        }
    }
    fset(o, c);
}

static void fpow2523(gf o, const gf in)
{
    gf c;
    int a;

    fset(c, in);
    for (a = 250; a >= 0; a--) {
        fsq(c, c);
        if (a != 1) {
            fmul(c, c, in);
        }
    }
    fset(o, c);
}

/* ---- X25519 ---- */

void femu_x25519(uint8_t out[32], const uint8_t k[32], const uint8_t u[32])
{
    uint8_t z[32];
    gf x;
    gf a;
    gf b;
    gf c;
    gf d;
    gf e;
    gf f;
    int r;
    int i;

    memcpy(z, k, 32);
    z[31] = (z[31] & 127) | 64;
    z[0] &= 248;
    funpack(x, u);
    fset(b, x);
    fset(a, gf1);
    fset(c, gf0);
    fset(d, gf1);
    for (i = 254; i >= 0; i--) {
        r = (z[i >> 3] >> (i & 7)) & 1;
        fsel(a, b, r);
        fsel(c, d, r);
        fadd(e, a, c);
        fsub(a, a, c);
        fadd(c, b, d);
        fsub(b, b, d);
        fsq(d, e);
        fsq(f, a);
        fmul(a, c, a);
        fmul(c, b, e);
        fadd(e, a, c);
        fsub(a, a, c);
        fsq(b, a);
        fsub(c, d, f);
        fmul(a, c, c121665);
        fadd(a, a, d);
        fmul(c, c, a);
        fmul(a, d, f);
        fmul(d, b, x);
        fsq(b, e);
        fsel(a, b, r);
        fsel(c, d, r);
    }
    finv(c, c);
    fmul(a, a, c);
    fpack(out, a);
    hpke_wipe(z, sizeof(z));
}

void femu_x25519_base(uint8_t out[32], const uint8_t k[32])
{
    static const uint8_t nine[32] = { 9 };

    femu_x25519(out, k, nine);
}

/* ---- SHA-512 and Ed25519 ---- */

static void sha512_3(uint8_t out[64], const uint8_t *a, size_t al,
                     const uint8_t *b, size_t bl, const uint8_t *c, size_t cl)
{
    GChecksum *h = g_checksum_new(G_CHECKSUM_SHA512);
    gsize len = 64;

    g_checksum_update(h, a, al);
    if (bl) {
        g_checksum_update(h, b, bl);
    }
    if (cl) {
        g_checksum_update(h, c, cl);
    }
    g_checksum_get_digest(h, out, &len);
    g_checksum_free(h);
}

static void edadd(gf p[4], gf q[4])
{
    gf a;
    gf b;
    gf c;
    gf d;
    gf t;
    gf e;
    gf f;
    gf g;
    gf h;

    fsub(a, p[1], p[0]);
    fsub(t, q[1], q[0]);
    fmul(a, a, t);
    fadd(b, p[0], p[1]);
    fadd(t, q[0], q[1]);
    fmul(b, b, t);
    fmul(c, p[3], q[3]);
    fmul(c, c, ed_d2);
    fmul(d, p[2], q[2]);
    fadd(d, d, d);
    fsub(e, b, a);
    fsub(f, d, c);
    fadd(g, d, c);
    fadd(h, b, a);
    fmul(p[0], e, f);
    fmul(p[1], h, g);
    fmul(p[2], g, f);
    fmul(p[3], e, h);
}

static void edswap(gf p[4], gf q[4], int b)
{
    int i;

    for (i = 0; i < 4; i++) {
        fsel(p[i], q[i], b);
    }
}

static void edpack(uint8_t r[32], gf p[4])
{
    gf tx;
    gf ty;
    gf zi;

    finv(zi, p[2]);
    fmul(tx, p[0], zi);
    fmul(ty, p[1], zi);
    fpack(r, ty);
    r[31] ^= fpar(tx) << 7;
}

static void edmul(gf p[4], gf q[4], const uint8_t s[32])
{
    int b;
    int i;

    fset(p[0], gf0);
    fset(p[1], gf1);
    fset(p[2], gf1);
    fset(p[3], gf0);
    for (i = 255; i >= 0; i--) {
        b = (s[i / 8] >> (i & 7)) & 1;
        edswap(p, q, b);
        edadd(q, p);
        edadd(p, p);
        edswap(p, q, b);
    }
}

static void edbase(gf p[4], const uint8_t s[32])
{
    gf q[4];

    fset(q[0], ed_x);
    fset(q[1], ed_y);
    fset(q[2], gf1);
    fmul(q[3], ed_x, ed_y);
    edmul(p, q, s);
}

/* the group order L, little endian */
static const int64_t ed_l[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
};

/* @r = @x mod L, @x being 64 limbs of one byte each */
static void modl(uint8_t r[32], int64_t x[64])
{
    int64_t carry;
    int i;
    int j;

    for (i = 63; i >= 32; i--) {
        carry = 0;
        for (j = i - 32; j < i - 12; j++) {
            x[j] += carry - 16 * x[i] * ed_l[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry * 256;
        }
        x[j] += carry;
        x[i] = 0;
    }
    carry = 0;
    for (j = 0; j < 32; j++) {
        x[j] += carry - (x[31] >> 4) * ed_l[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    for (j = 0; j < 32; j++) {
        x[j] -= carry * ed_l[j];
    }
    for (i = 0; i < 32; i++) {
        x[i + 1] += x[i] >> 8;
        r[i] = x[i] & 255;
    }
}

static void reduce64(uint8_t r[32], const uint8_t h[64])
{
    int64_t x[64];
    int i;

    for (i = 0; i < 64; i++) {
        x[i] = h[i];
    }
    modl(r, x);
}

static void ed_expand(uint8_t d[64], const uint8_t seed[32])
{
    sha512_3(d, seed, 32, NULL, 0, NULL, 0);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;
}

void femu_ed25519_pub(uint8_t pk[32], const uint8_t seed[32])
{
    uint8_t d[64];
    gf p[4];

    ed_expand(d, seed);
    edbase(p, d);
    edpack(pk, p);
    hpke_wipe(d, sizeof(d));
}

void femu_ed25519_sign(uint8_t sig[64], const uint8_t *m, size_t n,
                       const uint8_t seed[32])
{
    uint8_t d[64];
    uint8_t h[64];
    uint8_t r[32];
    uint8_t k[32];
    uint8_t pk[32];
    int64_t x[64] = { 0 };
    gf p[4];
    int i;
    int j;

    ed_expand(d, seed);
    edbase(p, d);
    edpack(pk, p);
    sha512_3(h, d + 32, 32, m, n, NULL, 0);
    reduce64(r, h);
    edbase(p, r);
    edpack(sig, p);
    sha512_3(h, sig, 32, pk, 32, m, n);
    reduce64(k, h);
    for (i = 0; i < 32; i++) {
        x[i] = r[i];
    }
    for (i = 0; i < 32; i++) {
        for (j = 0; j < 32; j++) {
            x[i + j] += (int64_t)k[i] * d[j];
        }
    }
    modl(sig + 32, x);
    hpke_wipe(d, sizeof(d));
    hpke_wipe(r, sizeof(r));
}

/* false for a y of 2^255 - 19 or more (RFC 8032 5.1.3, step 1) */
static bool ed_canonical(const uint8_t p[32])
{
    int i;

    if ((p[31] & 0x7f) != 0x7f) {
        return true;
    }
    for (i = 30; i > 0; i--) {
        if (p[i] != 0xff) {
            return true;
        }
    }
    return p[0] < 0xed;
}

/* the point -@p, false when @p is no point */
static bool edunpackneg(gf r[4], const uint8_t p[32])
{
    gf t;
    gf chk;
    gf num;
    gf den;
    gf den2;
    gf den4;
    gf den6;

    if (!ed_canonical(p)) {
        return false;
    }
    fset(r[2], gf1);
    funpack(r[1], p);
    fsq(num, r[1]);
    fmul(den, num, ed_d);
    fsub(num, num, r[2]);
    fadd(den, r[2], den);
    fsq(den2, den);
    fsq(den4, den2);
    fmul(den6, den4, den2);
    fmul(t, den6, num);
    fmul(t, t, den);
    fpow2523(t, t);
    fmul(t, t, num);
    fmul(t, t, den);
    fmul(t, t, den);
    fmul(r[0], t, den);
    fsq(chk, r[0]);
    fmul(chk, chk, den);
    if (fneq(chk, num)) {
        fmul(r[0], r[0], ed_i);
    }
    fsq(chk, r[0]);
    fmul(chk, chk, den);
    if (fneq(chk, num)) {
        return false;
    }
    if (fpar(r[0]) == (p[31] >> 7)) {
        fsub(r[0], gf0, r[0]);
    }
    fmul(r[3], r[0], r[1]);
    return true;
}

/* S < L (RFC 8032 5.1.7) */
static bool scalar_ok(const uint8_t s[32])
{
    int i;

    for (i = 31; i >= 0; i--) {
        if (s[i] != ed_l[i]) {
            return s[i] < ed_l[i];
        }
    }
    return false;
}

bool femu_ed25519_verify(const uint8_t sig[64], const uint8_t *m, size_t n,
                         const uint8_t pk[32])
{
    uint8_t h[64];
    uint8_t k[32];
    uint8_t t[32];
    gf p[4];
    gf q[4];

    if (!scalar_ok(sig + 32) || !edunpackneg(q, pk)) {
        return false;
    }
    sha512_3(h, sig, 32, pk, 32, m, n);
    reduce64(k, h);
    edmul(p, q, k);
    edbase(q, sig + 32);
    edadd(p, q);
    edpack(t, p);
    return !memcmp(t, sig, 32);
}

/* ---- HKDF-SHA256 ---- */

static void hmac256(uint8_t out[32], const uint8_t *key, size_t kl,
                    const uint8_t *d, size_t dl)
{
    static const uint8_t none;
    GHmac *h = g_hmac_new(G_CHECKSUM_SHA256, kl ? key : &none, kl);
    gsize len = 32;

    g_hmac_update(h, d, dl);
    g_hmac_get_digest(h, out, &len);
    g_hmac_unref(h);
}

void femu_hkdf_extract(uint8_t prk[32], const uint8_t *salt, size_t sl,
                       const uint8_t *ikm, size_t il)
{
    hmac256(prk, salt, sl, ikm, il);
}

void femu_hkdf_expand(uint8_t *okm, size_t l, const uint8_t prk[32],
                      const uint8_t *info, size_t il)
{
    g_autofree uint8_t *buf = g_malloc(32 + il + 1);
    uint8_t t[32];
    size_t done = 0;
    size_t tl = 0;
    uint8_t i = 1;

    g_assert(l <= 255 * 32);
    while (done < l) {
        size_t n = MIN(32, l - done);

        memcpy(buf, t, tl);
        memcpy(buf + tl, info, il);
        buf[tl + il] = i++;
        hmac256(t, prk, 32, buf, tl + il + 1);
        memcpy(okm + done, t, n);
        done += n;
        tl = 32;
    }
    hpke_wipe(t, sizeof(t));
}

/* ---- ChaCha20-Poly1305 ---- */

#define ROTL32(v, n)    (((v) << (n)) | ((v) >> (32 - (n))))
#define QR(a, b, c, d)                                  \
    do {                                                \
        a += b; d ^= a; d = ROTL32(d, 16);              \
        c += d; b ^= c; b = ROTL32(b, 12);              \
        a += b; d ^= a; d = ROTL32(d, 8);               \
        c += d; b ^= c; b = ROTL32(b, 7);               \
    } while (0)

static void chacha_block(uint8_t out[64], const uint8_t key[32],
                         uint32_t ctr, const uint8_t nonce[12])
{
    uint32_t s[16];
    uint32_t x[16];
    int i;

    s[0] = 0x61707865;
    s[1] = 0x3320646e;
    s[2] = 0x79622d32;
    s[3] = 0x6b206574;
    for (i = 0; i < 8; i++) {
        s[4 + i] = ldl_le_p(key + 4 * i);
    }
    s[12] = ctr;
    for (i = 0; i < 3; i++) {
        s[13 + i] = ldl_le_p(nonce + 4 * i);
    }
    memcpy(x, s, sizeof(x));
    for (i = 0; i < 10; i++) {
        QR(x[0], x[4], x[8], x[12]);
        QR(x[1], x[5], x[9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8], x[13]);
        QR(x[3], x[4], x[9], x[14]);
    }
    for (i = 0; i < 16; i++) {
        stl_le_p(out + 4 * i, x[i] + s[i]);
    }
    hpke_wipe(s, sizeof(s));
    hpke_wipe(x, sizeof(x));
}

/* XOR @n bytes with the key stream from block 1 */
static void chacha_xor(uint8_t *o, const uint8_t *in, size_t n,
                       const uint8_t key[32], const uint8_t nonce[12])
{
    uint8_t ks[64];
    uint32_t ctr = 1;
    size_t i;

    for (i = 0; i < n; i++) {
        if (i % 64 == 0) {
            chacha_block(ks, key, ctr++, nonce);
        }
        o[i] = in[i] ^ ks[i % 64];
    }
    hpke_wipe(ks, sizeof(ks));
}

static void p1305_add(uint32_t h[17], const uint32_t c[17])
{
    uint32_t u = 0;
    int j;

    for (j = 0; j < 17; j++) {
        u += h[j] + c[j];
        h[j] = u & 255;
        u >>= 8;
    }
}

static void poly1305(uint8_t out[16], const uint8_t *m, size_t n,
                     const uint8_t k[32])
{
    static const uint32_t minusp[17] = {
        5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252,
    };
    uint32_t x[17];
    uint32_t r[17] = { 0 };
    uint32_t h[17] = { 0 };
    uint32_t c[17];
    uint32_t g[17];
    uint32_t s;
    uint32_t u;
    size_t j;
    int i;

    for (i = 0; i < 16; i++) {
        r[i] = k[i];
    }
    r[3] &= 15;
    r[4] &= 252;
    r[7] &= 15;
    r[8] &= 252;
    r[11] &= 15;
    r[12] &= 252;
    r[15] &= 15;
    while (n > 0) {
        memset(c, 0, sizeof(c));
        for (j = 0; j < 16 && j < n; j++) {
            c[j] = m[j];
        }
        c[j] = 1;
        m += j;
        n -= j;
        p1305_add(h, c);
        for (i = 0; i < 17; i++) {
            int jj;

            x[i] = 0;
            for (jj = 0; jj < 17; jj++) {
                x[i] += h[jj] * (jj <= i ? r[i - jj] : 320 * r[i + 17 - jj]);
            }
        }
        memcpy(h, x, sizeof(h));
        u = 0;
        for (i = 0; i < 16; i++) {
            u += h[i];
            h[i] = u & 255;
            u >>= 8;
        }
        u += h[16];
        h[16] = u & 3;
        u = 5 * (u >> 2);
        for (i = 0; i < 16; i++) {
            u += h[i];
            h[i] = u & 255;
            u >>= 8;
        }
        u += h[16];
        h[16] = u;
    }
    memcpy(g, h, sizeof(g));
    p1305_add(h, minusp);
    s = -(h[16] >> 7);
    for (i = 0; i < 17; i++) {
        h[i] ^= s & (g[i] ^ h[i]);
    }
    for (i = 0; i < 16; i++) {
        c[i] = k[i + 16];
    }
    c[16] = 0;
    p1305_add(h, c);
    for (i = 0; i < 16; i++) {
        out[i] = h[i];
    }
}

/* the RFC 8439 2.8 tag over @aad and the cipher text @ct */
static void aead_tag(uint8_t tag[16], const uint8_t key[32],
                     const uint8_t nonce[12], const uint8_t *aad, size_t al,
                     const uint8_t *ct, size_t n)
{
    size_t pa = ROUND_UP(al, 16);
    size_t pc = ROUND_UP(n, 16);
    g_autofree uint8_t *mac = g_malloc0(pa + pc + 16);
    uint8_t otk[64];

    chacha_block(otk, key, 0, nonce);
    if (al) {
        memcpy(mac, aad, al);
    }
    if (n) {
        memcpy(mac + pa, ct, n);
    }
    stq_le_p(mac + pa + pc, al);
    stq_le_p(mac + pa + pc + 8, n);
    poly1305(tag, mac, pa + pc + 16, otk);
    hpke_wipe(otk, sizeof(otk));
}

void femu_aead_seal(uint8_t *ct, const uint8_t key[32],
                    const uint8_t nonce[12], const uint8_t *aad, size_t al,
                    const uint8_t *pt, size_t n)
{
    chacha_xor(ct, pt, n, key, nonce);
    aead_tag(ct + n, key, nonce, aad, al, ct, n);
}

bool femu_aead_open(uint8_t *pt, const uint8_t key[32],
                    const uint8_t nonce[12], const uint8_t *aad, size_t al,
                    const uint8_t *ct, size_t ctl)
{
    uint8_t tag[16];
    uint8_t d = 0;
    size_t n;
    int i;

    if (ctl < FEMU_AEAD_TAG) {
        return false;
    }
    n = ctl - FEMU_AEAD_TAG;
    aead_tag(tag, key, nonce, aad, al, ct, n);
    for (i = 0; i < 16; i++) {
        d |= tag[i] ^ ct[n + i];
    }
    if (d) {
        memset(pt, 0, n);
        return false;
    }
    chacha_xor(pt, ct, n, key, nonce);
    return true;
}

/* ---- HPKE (RFC 9180), mode_base ---- */

static const uint8_t suite_kem[5] = { 'K', 'E', 'M', 0x00, 0x20 };
static const uint8_t suite_hpke[10] = {
    'H', 'P', 'K', 'E', 0x00, 0x20, 0x00, 0x01, 0x00, 0x03,
};

static void lextract(uint8_t prk[32], const uint8_t *suite, size_t sl,
                     const uint8_t *salt, size_t saltl, const char *label,
                     const uint8_t *ikm, size_t il)
{
    size_t ll = strlen(label);
    g_autofree uint8_t *b = g_malloc(7 + sl + ll + il + 1);

    memcpy(b, "HPKE-v1", 7);
    memcpy(b + 7, suite, sl);
    memcpy(b + 7 + sl, label, ll);
    if (il) {
        memcpy(b + 7 + sl + ll, ikm, il);
    }
    femu_hkdf_extract(prk, salt, saltl, b, 7 + sl + ll + il);
    hpke_wipe(b, 7 + sl + ll + il);
}

static void lexpand(uint8_t *out, size_t l, const uint8_t prk[32],
                    const uint8_t *suite, size_t sl, const char *label,
                    const uint8_t *info, size_t il)
{
    size_t ll = strlen(label);
    g_autofree uint8_t *b = g_malloc(2 + 7 + sl + ll + il + 1);

    stw_be_p(b, l);
    memcpy(b + 2, "HPKE-v1", 7);
    memcpy(b + 9, suite, sl);
    memcpy(b + 9 + sl, label, ll);
    if (il) {
        memcpy(b + 9 + sl + ll, info, il);
    }
    femu_hkdf_expand(out, l, prk, b, 9 + sl + ll + il);
}

void femu_hpke_derive_keypair(uint8_t sk[32], uint8_t pk[32],
                              const uint8_t *ikm, size_t il)
{
    uint8_t prk[32];

    lextract(prk, suite_kem, 5, NULL, 0, "dkp_prk", ikm, il);
    lexpand(sk, 32, prk, suite_kem, 5, "sk", NULL, 0);
    femu_x25519_base(pk, sk);
    hpke_wipe(prk, sizeof(prk));
}

static bool all_zero(const uint8_t *p, size_t n)
{
    uint8_t d = 0;
    size_t i;

    for (i = 0; i < n; i++) {
        d |= p[i];
    }
    return !d;
}

static void kem_secret(uint8_t ss[32], const uint8_t dh[32],
                       const uint8_t enc[32], const uint8_t pkr[32])
{
    uint8_t ctx[64];
    uint8_t prk[32];

    memcpy(ctx, enc, 32);
    memcpy(ctx + 32, pkr, 32);
    lextract(prk, suite_kem, 5, NULL, 0, "eae_prk", dh, 32);
    lexpand(ss, 32, prk, suite_kem, 5, "shared_secret", ctx, 64);
    hpke_wipe(prk, sizeof(prk));
}

bool femu_hpke_decap(uint8_t ss[32], const uint8_t enc[32],
                     const uint8_t skr[32])
{
    uint8_t dh[32];
    uint8_t pkr[32];

    femu_x25519(dh, skr, enc);
    if (all_zero(dh, 32)) {
        return false;
    }
    femu_x25519_base(pkr, skr);
    kem_secret(ss, dh, enc, pkr);
    hpke_wipe(dh, sizeof(dh));
    return true;
}

static void key_schedule(FemuHpkeCtx *c, const uint8_t ss[32],
                         const uint8_t *info, size_t il)
{
    uint8_t ctx[65];
    uint8_t secret[32];

    ctx[0] = 0x00;
    lextract(ctx + 1, suite_hpke, 10, NULL, 0, "psk_id_hash", NULL, 0);
    lextract(ctx + 33, suite_hpke, 10, NULL, 0, "info_hash", info, il);
    lextract(secret, suite_hpke, 10, ss, 32, "secret", NULL, 0);
    lexpand(c->key, 32, secret, suite_hpke, 10, "key", ctx, 65);
    lexpand(c->base_nonce, 12, secret, suite_hpke, 10, "base_nonce", ctx, 65);
    c->seq = 0;
    hpke_wipe(secret, sizeof(secret));
}

bool femu_hpke_setup_s(FemuHpkeCtx *c, uint8_t enc[32],
                       const uint8_t ske[32], const uint8_t pkr[32],
                       const uint8_t *info, size_t il)
{
    uint8_t dh[32];
    uint8_t ss[32];

    femu_x25519(dh, ske, pkr);
    if (all_zero(dh, 32)) {
        return false;
    }
    femu_x25519_base(enc, ske);
    kem_secret(ss, dh, enc, pkr);
    key_schedule(c, ss, info, il);
    hpke_wipe(dh, sizeof(dh));
    hpke_wipe(ss, sizeof(ss));
    return true;
}

bool femu_hpke_setup_r(FemuHpkeCtx *c, const uint8_t enc[32],
                       const uint8_t skr[32], const uint8_t *info, size_t il)
{
    uint8_t ss[32];

    if (!femu_hpke_decap(ss, enc, skr)) {
        return false;
    }
    key_schedule(c, ss, info, il);
    hpke_wipe(ss, sizeof(ss));
    return true;
}

static void seq_nonce(const FemuHpkeCtx *c, uint8_t n[12])
{
    int i;

    memcpy(n, c->base_nonce, 12);
    for (i = 0; i < 8; i++) {
        n[11 - i] ^= c->seq >> (8 * i);
    }
}

/* false once the sequence number would wrap (RFC 9180 5.2) */
bool femu_hpke_seal(FemuHpkeCtx *c, uint8_t *ct, const uint8_t *aad,
                    size_t al, const uint8_t *pt, size_t n)
{
    uint8_t nonce[12];

    if (c->seq == UINT64_MAX) {
        return false;
    }
    seq_nonce(c, nonce);
    femu_aead_seal(ct, c->key, nonce, aad, al, pt, n);
    c->seq++;
    return true;
}

bool femu_hpke_open(FemuHpkeCtx *c, uint8_t *pt, const uint8_t *aad,
                    size_t al, const uint8_t *ct, size_t ctl)
{
    uint8_t nonce[12];

    if (c->seq == UINT64_MAX) {
        return false;
    }
    seq_nonce(c, nonce);
    if (!femu_aead_open(pt, c->key, nonce, aad, al, ct, ctl)) {
        return false;
    }
    c->seq++;
    return true;
}

void femu_hpke_wipe(FemuHpkeCtx *c)
{
    hpke_wipe(c, sizeof(*c));
}
