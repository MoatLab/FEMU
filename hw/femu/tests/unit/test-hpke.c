/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Unit test of hw/femu/femu-hpke.c against the RFC test vectors:
 * RFC 7748 (X25519), RFC 8032 (Ed25519), RFC 5869 (HKDF-SHA256),
 * RFC 8439 (ChaCha20-Poly1305) and RFC 9180 A.2.1 (HPKE base mode with
 * DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305).
 */

#include "qemu/osdep.h"
#include "hw/femu/femu-hpke.h"

/* parse @hex into @out; returns the byte count */
static size_t unhex(uint8_t *out, const char *hex)
{
    size_t n = strlen(hex) / 2;
    size_t i;

    g_assert_cmpuint(strlen(hex) % 2, ==, 0);
    for (i = 0; i < n; i++) {
        unsigned v;

        g_assert_cmpint(sscanf(hex + 2 * i, "%2x", &v), ==, 1);
        out[i] = v;
    }
    return n;
}

static void check_hex(const uint8_t *got, size_t n, const char *hex)
{
    g_autofree uint8_t *want = g_malloc(strlen(hex) / 2 + 1);

    g_assert_cmpuint(unhex(want, hex), ==, n);
    g_assert_cmpmem(got, n, want, n);
}

static void test_x25519(void)
{
    uint8_t k[32];
    uint8_t u[32];
    uint8_t o[32];
    uint8_t a[32];
    uint8_t b[32];
    uint8_t pa[32];
    uint8_t pb[32];
    uint8_t zero[32] = { 0 };

    /* RFC 7748 5.2 */
    unhex(k, "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    unhex(u, "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    femu_x25519(o, k, u);
    check_hex(o, 32,
              "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
    unhex(k, "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
    unhex(u, "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
    femu_x25519(o, k, u);
    check_hex(o, 32,
              "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
    /* RFC 7748 6.1 */
    unhex(a, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    unhex(b, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    femu_x25519_base(pa, a);
    check_hex(pa, 32,
              "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    femu_x25519_base(pb, b);
    check_hex(pb, 32,
              "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    femu_x25519(o, a, pb);
    check_hex(o, 32,
              "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    femu_x25519(o, b, pa);
    check_hex(o, 32,
              "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    /* a small-order point gives the all-zero result */
    femu_x25519(o, a, zero);
    g_assert_cmpmem(o, 32, zero, 32);
}

static const struct {
    const char *sk;
    const char *pk;
    const char *msg;
    const char *sig;
} ed_vec[] = {
    /* RFC 8032 7.1, TEST 1 to TEST 3 */
    { "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
      "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b" },
    { "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
      "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
      "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
      "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00" },
    { "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
      "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
      "af82",
      "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
      "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a" },
};

/* @s += L, little endian; S < L < 2^253, so no carry leaves byte 31 */
static void add_l(uint8_t s[32])
{
    static const uint8_t l[32] = {
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        [31] = 0x10,
    };
    unsigned c = 0;
    int i;

    for (i = 0; i < 32; i++) {
        c += s[i] + l[i];
        s[i] = c;
        c >>= 8;
    }
}

static void test_ed25519(void)
{
    size_t v;

    for (v = 0; v < ARRAY_SIZE(ed_vec); v++) {
        uint8_t sk[32];
        uint8_t pk[32];
        uint8_t m[8];
        uint8_t sig[64];
        size_t n;

        unhex(sk, ed_vec[v].sk);
        n = unhex(m, ed_vec[v].msg);
        femu_ed25519_pub(pk, sk);
        check_hex(pk, 32, ed_vec[v].pk);
        femu_ed25519_sign(sig, m, n, sk);
        check_hex(sig, 64, ed_vec[v].sig);
        g_assert_true(femu_ed25519_verify(sig, m, n, pk));
        /* a changed message, R or S fails */
        m[0] ^= 1;
        g_assert_false(femu_ed25519_verify(sig, m, n ? n : 1, pk));
        m[0] ^= 1;
        sig[3] ^= 0x10;
        g_assert_false(femu_ed25519_verify(sig, m, n, pk));
        sig[3] ^= 0x10;
        sig[40] ^= 0x01;
        g_assert_false(femu_ed25519_verify(sig, m, n, pk));
        sig[40] ^= 0x01;
        /* S + L gives the same point but is not canonical (RFC 8032 5.1.7) */
        add_l(sig + 32);
        g_assert_false(femu_ed25519_verify(sig, m, n, pk));
    }
}

/* y = p + 1 with R = identity and S = 0: a y of p or more is refused */
static void test_ed25519_canonical(void)
{
    uint8_t pk[32];
    uint8_t sig[64] = { 1 };

    memset(pk, 0xff, sizeof(pk));
    pk[0] = 0xee;
    pk[31] = 0x7f;
    g_assert_false(femu_ed25519_verify(sig, (const uint8_t *)"abc", 3, pk));
}

static void test_hkdf(void)
{
    uint8_t ikm[22];
    uint8_t salt[13];
    uint8_t info[10];
    uint8_t prk[32];
    uint8_t okm[42];

    /* RFC 5869 A.1 */
    memset(ikm, 0x0b, sizeof(ikm));
    unhex(salt, "000102030405060708090a0b0c");
    unhex(info, "f0f1f2f3f4f5f6f7f8f9");
    femu_hkdf_extract(prk, salt, sizeof(salt), ikm, sizeof(ikm));
    check_hex(prk, 32,
              "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    femu_hkdf_expand(okm, sizeof(okm), prk, info, sizeof(info));
    check_hex(okm, 42,
              "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
              "34007208d5b887185865");
}

static const char rfc8439_pt[] =
    "Ladies and Gentlemen of the class of '99: If I could offer you only "
    "one tip for the future, sunscreen would be it.";

static void test_aead(void)
{
    uint8_t key[32];
    uint8_t nonce[12];
    uint8_t aad[12];
    size_t n = strlen(rfc8439_pt);
    uint8_t ct[200];
    uint8_t pt[200];

    /* RFC 8439 2.8.2 */
    unhex(key, "808182838485868788898a8b8c8d8e8f"
               "909192939495969798999a9b9c9d9e9f");
    unhex(nonce, "070000004041424344454647");
    unhex(aad, "50515253c0c1c2c3c4c5c6c7");
    femu_aead_seal(ct, key, nonce, aad, sizeof(aad),
                   (const uint8_t *)rfc8439_pt, n);
    check_hex(ct, n,
              "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
              "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
              "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
              "3ff4def08e4b7a9de576d26586cec64b6116");
    check_hex(ct + n, 16, "1ae10b594f09e26a7e902ecbd0600691");
    g_assert_true(femu_aead_open(pt, key, nonce, aad, sizeof(aad), ct,
                                 n + 16));
    g_assert_cmpmem(pt, n, rfc8439_pt, n);
    /* a changed tag, cipher text or AAD fails and clears the output */
    ct[n + 15] ^= 1;
    g_assert_false(femu_aead_open(pt, key, nonce, aad, sizeof(aad), ct,
                                  n + 16));
    g_assert_cmpuint(pt[0], ==, 0);
    ct[n + 15] ^= 1;
    ct[5] ^= 0x80;
    g_assert_false(femu_aead_open(pt, key, nonce, aad, sizeof(aad), ct,
                                  n + 16));
    ct[5] ^= 0x80;
    aad[0] ^= 1;
    g_assert_false(femu_aead_open(pt, key, nonce, aad, sizeof(aad), ct,
                                  n + 16));
    g_assert_false(femu_aead_open(pt, key, nonce, aad, sizeof(aad), ct, 15));
}

static void test_hpke(void)
{
    static const char *const ct_hex[] = {
        "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db"
        "21993c62ce81883d2dd1b51a28",
        "6b53c051e4199c518de79594e1c4ab18b96f081549d45ce015be002090bb119e"
        "85285337cc95ba5f59992dc98c",
    };
    uint8_t info[20];
    uint8_t ikm[32];
    uint8_t ske[32];
    uint8_t pke[32];
    uint8_t skr[32];
    uint8_t pkr[32];
    uint8_t enc[32];
    uint8_t ss[32];
    uint8_t pt[29];
    uint8_t aad[8];
    uint8_t ct[64];
    uint8_t got[64];
    uint8_t zero[32] = { 0 };
    FemuHpkeCtx s;
    FemuHpkeCtx r;
    FemuHpkeCtx w;
    int i;

    /* RFC 9180 A.2.1 */
    unhex(info, "4f6465206f6e2061204772656369616e2055726e");
    unhex(ikm, "909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b");
    femu_hpke_derive_keypair(ske, pke, ikm, 32);
    check_hex(ske, 32,
              "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600");
    check_hex(pke, 32,
              "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a");
    unhex(ikm, "1ac01f181fdf9f352797655161c58b75c656a6cc2716dcb66372da835542e1df");
    femu_hpke_derive_keypair(skr, pkr, ikm, 32);
    check_hex(skr, 32,
              "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb");
    check_hex(pkr, 32,
              "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a");
    g_assert_true(femu_hpke_setup_s(&s, enc, ske, pkr, info, sizeof(info)));
    check_hex(enc, 32,
              "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a");
    g_assert_true(femu_hpke_decap(ss, enc, skr));
    check_hex(ss, 32,
              "0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7");
    g_assert_true(femu_hpke_setup_r(&r, enc, skr, info, sizeof(info)));
    check_hex(r.key, 32,
              "ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91");
    check_hex(r.base_nonce, 12, "5c4d98150661b848853b547f");
    unhex(pt, "4265617574792069732074727574682c20747275746820626561757479");
    for (i = 0; i < 2; i++) {
        size_t al = unhex(aad, i ? "436f756e742d31" : "436f756e742d30");

        femu_hpke_seal(&s, ct, aad, al, pt, sizeof(pt));
        check_hex(ct, sizeof(pt) + 16, ct_hex[i]);
        g_assert_true(femu_hpke_open(&r, got, aad, al, ct, sizeof(pt) + 16));
        g_assert_cmpmem(got, sizeof(pt), pt, sizeof(pt));
    }
    /* sequence 2 opens only at sequence 2: a replay of sequence 1 fails */
    g_assert_false(femu_hpke_open(&r, got, aad, 7, ct, sizeof(pt) + 16));
    g_assert_cmpuint(r.seq, ==, 2);
    /* another info gives another context */
    info[0] ^= 1;
    g_assert_true(femu_hpke_setup_r(&w, enc, skr, info, sizeof(info)));
    g_assert_cmpint(memcmp(w.key, r.key, 32), !=, 0);
    femu_hpke_wipe(&w);
    /* the all-zero encapsulation is refused */
    g_assert_false(femu_hpke_setup_r(&w, zero, skr, info, sizeof(info)));
    g_assert_false(femu_hpke_setup_s(&w, enc, ske, zero, info, sizeof(info)));
    /* the last sequence number is never used (RFC 9180 5.2) */
    s.seq = UINT64_MAX;
    r.seq = UINT64_MAX;
    g_assert_false(femu_hpke_seal(&s, ct, aad, 7, pt, sizeof(pt)));
    g_assert_false(femu_hpke_open(&r, got, aad, 7, ct, sizeof(pt) + 16));
    g_assert_cmpuint(s.seq, ==, UINT64_MAX);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/femu/hpke/x25519", test_x25519);
    g_test_add_func("/femu/hpke/ed25519", test_ed25519);
    g_test_add_func("/femu/hpke/ed25519-canonical", test_ed25519_canonical);
    g_test_add_func("/femu/hpke/hkdf", test_hkdf);
    g_test_add_func("/femu/hpke/aead", test_aead);
    g_test_add_func("/femu/hpke/hpke", test_hpke);
    return g_test_run();
}
