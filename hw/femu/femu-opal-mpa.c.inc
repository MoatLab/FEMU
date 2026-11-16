/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * FEMU TCG Opal TPer: MEK Multiparty Authorization (TCG MEK-MPA 1.00) on
 * the Locking SP. femu-opal-locking.c.inc includes this file at its end.
 *
 *   host: HPKE Seal(Certificate1 key, info = method UID || AC UID, ak)
 *   TPer: Open --> ak --> unseal the AC secret --> AccessEnabled
 *         K_AES Active list + AccessEnabled --> range locks, MEK present
 *
 * Every rule reads and writes the working image o->sp. The committed
 * image changes only at commit, and the I/O view reads only that image.
 * FEMU stores no user data under a key: a new MEK is a new key number.
 */

#include "femu-hpke.h"

#define MPA_AK          32      /* the plaintext access key */

static void mpa_wipe(void *p, size_t n)
{
    volatile uint8_t *q = p;    /* keeps the stores to dead memory */

    while (n--) {
        *q++ = 0;
    }
}

static void mpa_put64(uint8_t *p, uint64_t v)
{
    put32(p, v >> 32);
    put32(p + 4, v);
}

static bool mpa_rand(FemuOpal *o, uint8_t *b, size_t n)
{
    size_t i;

    if (o->cfg.rand) {
        return o->cfg.rand(o->cfg.opaque, b, n);
    }
    for (i = 0; i < n; i++) {
        b[i] = g_random_int();
    }
    return true;
}

/* the 0-based AC index of an AccessCondition row, or -1 */
static int mpa_ac(const FemuOpal *o, uint64_t uid)
{
    if (!o->cfg.mpa || uid < UID_AC(1) ||
        uid > UID_AC(FEMU_OPAL_MPA_ACS)) {
        return -1;
    }
    return uid - UID_AC(1);
}

/* Certificate1 (KEM) or Certificate2 (identity): 1 or 2, else 0 */
static int mpa_cert(const FemuOpal *o, uint64_t uid)
{
    if (!o->cfg.mpa) {
        return 0;
    }
    return uid == UID_CERT(1) ? 1 : uid == UID_CERT(2) ? 2 : 0;
}

static int mpa_certdata(const FemuOpal *o, uint64_t uid)
{
    if (!o->cfg.mpa) {
        return 0;
    }
    return uid == UID_CERTDATA(1) ? 1 : uid == UID_CERTDATA(2) ? 2 : 0;
}

/* ---- a DER writer for the two certificates ---- */

typedef struct MpaDer {
    uint8_t b[FEMU_OPAL_MPA_CERT_MAX];
    size_t n;
    bool over;
} MpaDer;

static void der_put(MpaDer *d, const void *p, size_t n)
{
    if (d->n + n > sizeof(d->b)) {
        d->over = true;
        return;
    }
    memcpy(d->b + d->n, p, n);
    d->n += n;
}

/* put a tag and a length in front of the bytes from @start to the end */
static void der_wrap(MpaDer *d, size_t start, uint8_t tag)
{
    size_t len = d->n - start;
    uint8_t h[4] = { tag };
    size_t hl;

    if (len < 0x80) {
        h[1] = len;
        hl = 2;
    } else if (len < 0x100) {
        h[1] = 0x81;
        h[2] = len;
        hl = 3;
    } else {
        h[1] = 0x82;
        h[2] = len >> 8;
        h[3] = len;
        hl = 4;
    }
    if (d->over || d->n + hl > sizeof(d->b)) {
        d->over = true;
        return;
    }
    memmove(d->b + start + hl, d->b + start, len);
    memcpy(d->b + start, h, hl);
    d->n += hl;
}

static void der_tlv(MpaDer *d, uint8_t tag, const void *p, size_t n)
{
    size_t s = d->n;

    der_put(d, p, n);
    der_wrap(d, s, tag);
}

/* Name: one RDN with a CommonName */
static void der_name(MpaDer *d, const char *cn)
{
    static const uint8_t oid_cn[] = { 0x55, 0x04, 0x03 };
    size_t s = d->n;

    der_tlv(d, 0x06, oid_cn, sizeof(oid_cn));
    der_tlv(d, 0x0C, cn, strlen(cn));
    der_wrap(d, s, 0x30);
    der_wrap(d, s, 0x31);
    der_wrap(d, s, 0x30);
}

/*
 * An X.509 v3 certificate signed with the identity key. @kem: the X25519
 * KEM key of Certificate1, with keyUsage keyEncipherment and keyAgreement
 * and the HPKEIdentifiers extension (MPA 4.2.2.1.3). Else the identity
 * certificate itself: Ed25519, a CA with keyCertSign, self signed.
 */
static bool mpa_cert_build(FemuOpal *o, bool kem, const uint8_t pk[32],
                           uint8_t *out, uint16_t *len)
{
    static const uint8_t v3[] = { 0xA0, 0x03, 0x02, 0x01, 0x02 };
    static const uint8_t alg_ed[] = { 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65,
                                      0x70 };
    static const uint8_t alg_x[] = { 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65,
                                     0x6E };
    static const uint8_t ku_kem[] = {
        0x30, 0x0E, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x01, 0x01, 0xFF,
        0x04, 0x04, 0x03, 0x02, 0x03, 0x28,
    };
    static const uint8_t ku_id[] = {
        0x30, 0x0E, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x01, 0x01, 0xFF,
        0x04, 0x04, 0x03, 0x02, 0x02, 0x04,
    };
    static const uint8_t bc_ca[] = {
        0x30, 0x0F, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF,
        0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xFF,
    };
    /* 2.23.133.21.1.1: HPKEIdentifiers { 0x0020, 0x0001, 0x0003 } */
    static const uint8_t hpke_ids[] = {
        0x30, 0x15, 0x06, 0x06, 0x67, 0x81, 0x05, 0x15, 0x01, 0x01,
        0x04, 0x0B, 0x30, 0x09, 0x02, 0x01, 0x20, 0x02, 0x01, 0x01,
        0x02, 0x01, 0x03,
    };
    g_autofree MpaDer *d = g_new0(MpaDer, 1);
    g_autofree char *id_cn = g_strdup_printf("FEMU MPA Identity %s",
                                             o->cfg.serial);
    g_autofree char *kem_cn = g_strdup_printf("FEMU MPA KEM %s",
                                              o->cfg.serial);
    GChecksum *h = g_checksum_new(G_CHECKSUM_SHA256);
    uint8_t dig[32];
    gsize dl = sizeof(dig);
    uint8_t serial[8];
    uint8_t sig[64];
    uint8_t z = 0;
    size_t s;
    size_t t;

    g_checksum_update(h, (const guchar *)o->cfg.serial,
                      strlen(o->cfg.serial));
    g_checksum_get_digest(h, dig, &dl);
    g_checksum_free(h);
    /* device unique: the serial hash, then a counter; positive, minimal */
    serial[0] = (dig[0] & 0x3F) | 0x40;
    memcpy(serial + 1, dig + 1, 3);
    put32(serial + 4, ++o->cert_serial);

    der_put(d, v3, sizeof(v3));
    der_tlv(d, 0x02, serial, sizeof(serial));
    der_put(d, alg_ed, sizeof(alg_ed));
    der_name(d, id_cn);
    s = d->n;
    der_tlv(d, 0x17, "250101000000Z", 13);
    der_tlv(d, 0x18, "99991231235959Z", 15);
    der_wrap(d, s, 0x30);
    der_name(d, kem ? kem_cn : id_cn);
    s = d->n;
    der_put(d, kem ? alg_x : alg_ed, sizeof(alg_x));
    t = d->n;
    der_put(d, &z, 1);
    der_put(d, pk, 32);
    der_wrap(d, t, 0x03);
    der_wrap(d, s, 0x30);
    s = d->n;
    if (kem) {
        der_put(d, ku_kem, sizeof(ku_kem));
        der_put(d, hpke_ids, sizeof(hpke_ids));
    } else {
        der_put(d, bc_ca, sizeof(bc_ca));
        der_put(d, ku_id, sizeof(ku_id));
    }
    der_wrap(d, s, 0x30);
    der_wrap(d, s, 0xA3);
    der_wrap(d, 0, 0x30);
    if (d->over) {
        return false;
    }
    femu_ed25519_sign(sig, d->b, d->n, o->id_seed);
    der_put(d, alg_ed, sizeof(alg_ed));
    t = d->n;
    der_put(d, &z, 1);
    der_put(d, sig, sizeof(sig));
    der_wrap(d, t, 0x03);
    der_wrap(d, 0, 0x30);
    if (d->over) {
        return false;
    }
    memcpy(out, d->b, d->n);
    *len = d->n;
    return true;
}

/*
 * A new KEM key pair and Certificate1 in the working image. A method
 * (@keep) changes nothing when it fails. A power cycle destroys the old
 * key first, so a failure leaves no KEM key: the methods that need it
 * give FAIL until a later call succeeds (design 11.5).
 */
static bool mpa_new_kem(FemuOpal *o, bool keep)
{
    FemuOpalSp *sp = &o->sp;
    uint8_t cert[FEMU_OPAL_MPA_CERT_MAX];
    uint8_t ikm[32];
    uint8_t sk[32];
    uint8_t pk[32];
    uint16_t len = 0;
    bool ok;

    if (!keep) {
        mpa_wipe(sp->kem_sk, sizeof(sp->kem_sk));
        sp->kem_ok = false;
        sp->cert1_len = 0;
    }
    ok = o->id_ok && mpa_rand(o, ikm, sizeof(ikm));
    if (ok) {
        femu_hpke_derive_keypair(sk, pk, ikm, sizeof(ikm));
        ok = mpa_cert_build(o, true, pk, cert, &len);
    }
    if (ok) {
        memcpy(sp->kem_sk, sk, sizeof(sk));
        memcpy(sp->kem_pk, pk, sizeof(pk));
        memcpy(sp->cert1, cert, len);
        sp->cert1_len = len;
        sp->kem_ok = true;
    }
    mpa_wipe(ikm, sizeof(ikm));
    mpa_wipe(sk, sizeof(sk));
    return ok;
}

/* the device secrets, made once at init; they live with the object */
static void mpa_init(FemuOpal *o)
{
    if (!o->cfg.mpa) {
        return;
    }
    o->id_ok = mpa_rand(o, o->dev_root, sizeof(o->dev_root)) &&
               mpa_rand(o, o->id_seed, sizeof(o->id_seed));
    if (o->id_ok) {
        femu_ed25519_pub(o->id_pk, o->id_seed);
        o->id_ok = mpa_cert_build(o, false, o->id_pk, o->cert2,
                                  &o->cert2_len);
    }
}

/* the AccessCondition rows as they leave the factory (MPA Table 15) */
static void mpa_factory(FemuOpal *o)
{
    int x;

    mpa_wipe(o->sp.ac, sizeof(o->sp.ac));
    for (x = 0; x < FEMU_OPAL_MPA_ACS; x++) {
        o->sp.ac[x].dor = 1u << FEMU_OPAL_RESET_POWER;
    }
    if (o->cfg.mpa) {
        mpa_new_kem(o, false);
    }
}

/* ---- the lists of a K_AES row ---- */

static int mpa_list_len(const uint8_t *l)
{
    int i;

    for (i = 0; i < FEMU_OPAL_MPA_PER_KEY && l[i]; i++) {
        ;
    }
    return i;
}

static bool mpa_list_has(const uint8_t *l, int ac)
{
    int i;

    for (i = 0; i < FEMU_OPAL_MPA_PER_KEY && l[i]; i++) {
        if (l[i] == ac) {
            return true;
        }
    }
    return false;
}

static void enc_ac_list(FemuOpalEnc *e, const uint8_t *l)
{
    int i;

    femu_opal_enc_ctrl(e, TOK_SL);
    for (i = 0; i < FEMU_OPAL_MPA_PER_KEY && l[i]; i++) {
        femu_opal_enc_uid(e, UID_AC(l[i]));
    }
    femu_opal_enc_ctrl(e, TOK_EL);
}

/*
 * A list of AC references into @l: SL uid... EL. Adds to what @l holds
 * and drops a repeat. False for a bad UID or more than the per-key limit.
 */
static bool val_ac_list(const FemuOpal *o, const FemuOpalTok *v, int vn,
                        uint8_t *l)
{
    int i;

    if (vn < 2 || !tok_is(&v[0], TOK_SL) || !tok_is(&v[vn - 1], TOK_EL)) {
        return false;
    }
    for (i = 1; i < vn - 1; i++) {
        uint64_t uid;
        int x;
        int k;

        if (!tok_uid(&v[i], &uid)) {
            return false;
        }
        x = mpa_ac(o, uid);
        if (x < 0) {
            return false;
        }
        if (mpa_list_has(l, x + 1)) {
            continue;
        }
        k = mpa_list_len(l);
        if (k == FEMU_OPAL_MPA_PER_KEY) {
            return false;
        }
        l[k] = x + 1;
    }
    return true;
}

/* does a disabled AC sit in the Active list of range @r of @sp? */
static bool mpa_blocked(const FemuOpalSp *sp, int r)
{
    const uint8_t *l = sp->range[r].active;
    int i;

    for (i = 0; i < FEMU_OPAL_MPA_PER_KEY && l[i]; i++) {
        if (!sp->ac[l[i] - 1].enabled) {
            return true;
        }
    }
    return false;
}

/*
 * AC @x goes disabled, by DisableAccess or by a reset in its policy: every
 * range that names it in Active gets ReadLocked and WriteLocked set, and
 * they stay set until an unlock Set (MPA 4.1.1.5.3, 4.2.2.3).
 */
static void mpa_disable(FemuOpal *o, int x)
{
    FemuOpalAc *ac = &o->sp.ac[x];
    int r;

    ac->enabled = false;
    mpa_wipe(ac->secret, sizeof(ac->secret));
    for (r = 0; r <= FEMU_OPAL_RANGES; r++) {
        if (mpa_list_has(o->sp.range[r].active, x + 1)) {
            o->sp.range[r].rl = true;
            o->sp.range[r].wl = true;
        }
    }
}

/*
 * A TCG reset of @type (MPA 4.2.1.1.5). A power cycle disables every AC
 * and gets a new KEM key; a programmatic reset disables the ACs with type
 * 3 in DisableAccessOnReset. Runs after the abort of an open transaction.
 */
static void mpa_reset(FemuOpal *o, int type)
{
    int x;

    if (!o->cfg.mpa) {
        return;
    }
    for (x = 0; x < FEMU_OPAL_MPA_ACS; x++) {
        FemuOpalAc *ac = &o->sp.ac[x];

        if (type == FEMU_OPAL_RESET_POWER || (ac->dor & (1u << type))) {
            if (ac->enabled) {
                mpa_disable(o, x);
            }
            mpa_wipe(ac->secret, sizeof(ac->secret));
        }
    }
    if (type == FEMU_OPAL_RESET_POWER) {
        mpa_new_kem(o, false);
    }
}

/* ---- the AC seal ---- */

static void mpa_seal_key(const FemuOpal *o, int x, const uint8_t *ak,
                         uint8_t k[32])
{
    uint8_t info[11 + 8];
    uint8_t prk[32];

    memcpy(info, "femu-mpa-ac", 11);
    mpa_put64(info + 11, UID_AC(x + 1));
    femu_hkdf_extract(prk, o->dev_root, sizeof(o->dev_root), ak, MPA_AK);
    femu_hkdf_expand(k, 32, prk, info, sizeof(info));
    mpa_wipe(prk, sizeof(prk));
}

/* the AC secret under @ak; false when @ak is not the access key */
static bool mpa_unseal(const FemuOpal *o, int x, const uint8_t *ak,
                       uint8_t s[32])
{
    const uint8_t *seal = o->sp.ac[x].seal;
    uint8_t aad[8];
    uint8_t k[32];
    bool ok;

    mpa_put64(aad, UID_AC(x + 1));
    mpa_seal_key(o, x, ak, k);
    ok = femu_aead_open(s, k, seal, aad, sizeof(aad), seal + FEMU_AEAD_NONCE,
                        FEMU_OPAL_MPA_SEAL - FEMU_AEAD_NONCE);
    mpa_wipe(k, sizeof(k));
    return ok;
}

/* seal @s under @ak with a new nonce; false (no change) on a failure */
static bool mpa_seal(FemuOpal *o, int x, const uint8_t *ak,
                     const uint8_t s[32])
{
    uint8_t *seal = o->sp.ac[x].seal;
    uint8_t nonce[FEMU_AEAD_NONCE];
    uint8_t aad[8];
    uint8_t k[32];

    if (!mpa_rand(o, nonce, sizeof(nonce))) {
        return false;
    }
    mpa_put64(aad, UID_AC(x + 1));
    mpa_seal_key(o, x, ak, k);
    memcpy(seal, nonce, sizeof(nonce));
    femu_aead_seal(seal + FEMU_AEAD_NONCE, k, nonce, aad, sizeof(aad), s, 32);
    mpa_wipe(k, sizeof(k));
    return true;
}

/* ---- tables ---- */

/* the ACL of an MPA object, or 0 (MPA Table 12) */
static int mpa_acl(const FemuOpal *o, uint64_t obj, uint64_t m, int *ace)
{
    int x = mpa_ac(o, obj);
    int r;

    if (!o->cfg.mpa) {
        return 0;
    }
    if (m == UID_M_NEXT && (obj == UID_T_AC || obj == UID_T_CERTS)) {
        ace[0] = ACE_ANYBODY;
        return 1;
    }
    if (x >= 0) {
        if (m == UID_M_GET) {
            ace[0] = ACE_ANYBODY;
            return 1;
        }
        if (m == UID_M_SET) {
            ace[0] = ACE_MPA_DOR + x;
            ace[1] = ACE_ADMINS_SET_CN;
            return 2;
        }
        if (m > UID_M_MPA(0) && m <= UID_M_MPA(5)) {
            ace[0] = ACE_MPA_METHOD +
                     (m - UID_M_MPA(1)) * FEMU_OPAL_MPA_ACS + x;
            return 1;
        }
        return 0;
    }
    if (mpa_cert(o, obj)) {
        if (m == UID_M_GET) {
            ace[0] = ACE_ANYBODY;
            return 1;
        }
        if (m == UID_M_GENKEY) {
            ace[0] = ACE_ADMIN;
            return 1;
        }
        return 0;
    }
    if (mpa_certdata(o, obj) && m == UID_M_GET) {
        ace[0] = ACE_ANYBODY;
        return 1;
    }
    r = lsp_key_row(obj);
    if (r >= 0 && m == UID_M_SET) {
        ace[0] = ACE_MPA_PENDING + r;
        return 1;
    }
    return 0;
}

static int mpa_maxcol(const FemuOpal *o, uint64_t uid)
{
    if (mpa_ac(o, uid) >= 0) {
        return 5;
    }
    if (mpa_cert(o, uid) || (o->cfg.mpa && lsp_key_row(uid) >= 0)) {
        return 6;
    }
    return -1;
}

/* one column of an MPA object: 1 done, 0 no value, -1 not an MPA object */
static int mpa_col(FemuOpal *o, uint64_t uid, uint32_t col, FemuOpalEnc *e)
{
    const FemuOpalSp *sp = &o->sp;
    int x = mpa_ac(o, uid);
    int c = mpa_cert(o, uid);
    int r;

    if (x >= 0) {
        const FemuOpalAc *ac = &sp->ac[x];

        switch (col) {
        case 1:
            enc_name(e, "AccessCondition%d", x + 1);
            return 1;
        case 2:
            femu_opal_enc_bytes(e, ac->cn.v, ac->cn.len);
            return 1;
        case 3:
            femu_opal_enc_uint(e, ac->enabled);
            return 1;
        case 4:
            enc_resets(e, ac->dor);
            return 1;
        case 5:
            femu_opal_enc_uid(e, UID_CERT(1));
            return 1;
        }
        return 0;
    }
    if (c) {
        switch (col) {
        case 1:
            enc_name(e, "Certificate%d", c);
            return 1;
        case 2:
            femu_opal_enc_bytes(e, "", 0);
            return 1;
        case 3:
            femu_opal_enc_uid(e, UID_CERTDATA(c));
            return 1;
        case 4:
            femu_opal_enc_uint(e, c == 1 ? sp->cert1_len : o->cert2_len);
            return 1;
        case 5:
            femu_opal_enc_uint(e, c == 1);
            return 1;
        case 6:
            femu_opal_enc_uid(e, c == 1 ? UID_CERT(2) : 0);
            return 1;
        }
        return 0;
    }
    r = lsp_key_row(uid);
    if (o->cfg.mpa && r >= 0 && (col == 5 || col == 6)) {
        enc_ac_list(e, col == 5 ? sp->range[r].active : sp->range[r].pending);
        return 1;
    }
    return -1;
}

/* Set of an MPA column into @next: 1 done, 0 bad value, -1 not MPA */
static int mpa_apply(const FemuOpal *o, FemuOpalSp *next, uint64_t uid,
                     uint32_t col, const FemuOpalTok *v, int vn)
{
    int x = mpa_ac(o, uid);
    int r = lsp_key_row(uid);

    if (x >= 0) {
        if (col == 2) {
            return val_name(v, vn, &next->ac[x].cn);
        }
        return col == 4 && val_resets(v, vn, &next->ac[x].dor);
    }
    if (o->cfg.mpa && r >= 0) {
        uint8_t l[FEMU_OPAL_MPA_PER_KEY] = { 0 };

        if (col != 6 || !val_ac_list(o, v, vn, l)) {
            return 0;
        }
        memcpy(next->range[r].pending, l, sizeof(l));
        return 1;
    }
    return -1;
}

/*
 * The Locking row rules of MPA 4.2.2.2.1.1 for a Set that makes @next
 * from the working image: a bound range keeps both LockEnabled columns,
 * and unlocks only while every Active AC is enabled.
 */
static uint8_t mpa_set_check(const FemuOpal *o, const FemuOpalSp *next)
{
    int r;

    if (!o->cfg.mpa) {
        return FEMU_OPAL_ST_SUCCESS;
    }
    for (r = 0; r <= FEMU_OPAL_RANGES; r++) {
        const FemuOpalRange *a = &o->sp.range[r];
        const FemuOpalRange *b = &next->range[r];

        if (!mpa_list_len(a->active)) {
            continue;
        }
        if ((a->rle && !b->rle) || (a->wle && !b->wle)) {
            return FEMU_OPAL_ST_FAIL;
        }
        if (((a->rl && !b->rl) || (a->wl && !b->wl)) &&
            mpa_blocked(&o->sp, r)) {
            return FEMU_OPAL_ST_NOT_AUTHORIZED;
        }
    }
    return FEMU_OPAL_ST_SUCCESS;
}

/*
 * GenKey on K_AES row @k with an optional AdditionalAccessConditions list
 * (MPA 4.1.2.5). Active becomes Pending plus that list and the old MEK
 * goes. The new MEK exists only while every AC in the list is enabled,
 * and the I/O view checks exactly that (mpa_blocked), so a deferred MEK
 * needs no state of its own.
 */
static uint8_t mpa_genkey_kaes(FemuOpal *o, int k, const FemuOpalTok *t,
                               int n)
{
    FemuOpalRange *g = &o->sp.range[k];
    uint8_t l[FEMU_OPAL_MPA_PER_KEY];

    memcpy(l, g->pending, sizeof(l));
    if (n) {
        int ve;

        if (n < 4 || !tok_is(&t[0], TOK_SN) ||
            t[1].type != FEMU_OPAL_TOK_UINT ||
            t[1].val != NAME_ADDITIONAL_AC) {
            return FEMU_OPAL_ST_INVALID_PARAMETER;
        }
        ve = value_end(t, n, 2);
        if (ve != n - 1 || !tok_is(&t[ve], TOK_EN) ||
            !val_ac_list(o, &t[2], ve - 2, l)) {
            return FEMU_OPAL_ST_INVALID_PARAMETER;
        }
    }
    if (mpa_list_len(l) && (!g->rle || !g->wle)) {
        return FEMU_OPAL_ST_FAIL;
    }
    memcpy(g->active, l, sizeof(l));
    g->key = o->next_key++;
    return FEMU_OPAL_ST_SUCCESS;
}

/* GenKey on Certificate1: a new KEM key pair and certificate */
static uint8_t mpa_genkey_cert(FemuOpal *o, int c, int n)
{
    if (n || c != 1) {
        return FEMU_OPAL_ST_INVALID_PARAMETER;
    }
    return mpa_new_kem(o, true) ? FEMU_OPAL_ST_SUCCESS : FEMU_OPAL_ST_FAIL;
}

/* bytes of CertificateData @c; past the certificate they read as zeros */
static void mpa_cert_read(const FemuOpal *o, int c, uint64_t off,
                          uint8_t *buf, uint32_t len)
{
    const uint8_t *src = c == 1 ? o->sp.cert1 : o->cert2;
    uint32_t have = c == 1 ? o->sp.cert1_len : o->cert2_len;

    memset(buf, 0, len);
    if (off < have) {
        memcpy(buf, src + off, MIN(len, have - off));
    }
}

/* ---- the five methods (MPA 4.1.1) ---- */

static bool tok_bytes(const FemuOpalTok *t, uint32_t len)
{
    return t->type == FEMU_OPAL_TOK_BYTES && t->len == len;
}

/* the receiver context of a method on AC @x: info = method UID || AC UID */
static uint8_t mpa_setup(const FemuOpal *o, uint64_t m, int x,
                         const FemuOpalTok *enc, FemuHpkeCtx *c)
{
    uint8_t info[16];

    if (!o->sp.kem_ok) {
        return FEMU_OPAL_ST_FAIL;
    }
    if (!tok_bytes(enc, FEMU_X25519_LEN)) {
        return FEMU_OPAL_ST_INVALID_PARAMETER;
    }
    mpa_put64(info, m);
    mpa_put64(info + 8, UID_AC(x + 1));
    if (!femu_hpke_setup_r(c, enc->p, o->sp.kem_sk, info, sizeof(info))) {
        return FEMU_OPAL_ST_INVALID_PARAMETER;
    }
    return FEMU_OPAL_ST_SUCCESS;
}

/* Open the next 48-byte access key on @c */
static bool mpa_open(FemuHpkeCtx *c, const FemuOpalTok *ct, uint8_t *ak)
{
    return tok_bytes(ct, FEMU_OPAL_MPA_AK_LEN) &&
           femu_hpke_open(c, ak, NULL, 0, ct->p, ct->len);
}

/* is AC @x named in any Active or Pending list of the working image? */
static bool mpa_bound(const FemuOpal *o, int x)
{
    int r;

    for (r = 0; r <= FEMU_OPAL_RANGES; r++) {
        if (mpa_list_has(o->sp.range[r].active, x + 1) ||
            mpa_list_has(o->sp.range[r].pending, x + 1)) {
            return true;
        }
    }
    return false;
}

static uint8_t mpa_do(FemuOpal *o, uint64_t m, int x, const FemuOpalTok *t,
                      int n, FemuOpalReply *r)
{
    FemuOpalAc *ac = &o->sp.ac[x];
    uint8_t ak[2][MPA_AK];
    uint8_t s[32];
    uint8_t st;
    FemuHpkeCtx c = { 0 };

    switch (m) {
    case UID_M_MPA(1):                  /* InitializeAccessCondition */
        if (n != 2) {
            return FEMU_OPAL_ST_INVALID_PARAMETER;
        }
        st = mpa_setup(o, m, x, &t[0], &c);
        if (st) {
            break;
        }
        if (!mpa_open(&c, &t[1], ak[0]) || mpa_bound(o, x)) {
            st = FEMU_OPAL_ST_INVALID_PARAMETER;
        } else if (ac->enabled) {
            st = FEMU_OPAL_ST_FAIL;
        } else if (!mpa_rand(o, s, sizeof(s)) || !mpa_seal(o, x, ak[0], s)) {
            st = FEMU_OPAL_ST_FAIL;
        } else {
            ac->initialized = true;
        }
        break;
    case UID_M_MPA(2):                  /* TestAccessKey */
        if (n != 3 || !tok_bytes(&t[2], 32)) {
            return FEMU_OPAL_ST_INVALID_PARAMETER;
        }
        st = mpa_setup(o, m, x, &t[0], &c);
        if (st) {
            break;
        }
        if (!mpa_open(&c, &t[1], ak[0])) {
            st = FEMU_OPAL_ST_INVALID_PARAMETER;
        } else if (!ac->initialized || !mpa_unseal(o, x, ak[0], s)) {
            st = FEMU_OPAL_ST_FAIL;
        } else {
            GChecksum *h = g_checksum_new(G_CHECKSUM_SHA384);
            uint8_t uid[8];
            uint8_t d[48];
            gsize dl = sizeof(d);

            mpa_put64(uid, UID_AC(x + 1));
            g_checksum_update(h, uid, sizeof(uid));
            g_checksum_update(h, ak[0], MPA_AK);
            g_checksum_update(h, t[2].p, 32);
            g_checksum_get_digest(h, d, &dl);
            g_checksum_free(h);
            femu_opal_enc_ctrl(&r->e, TOK_SL);
            femu_opal_enc_bytes(&r->e, d, sizeof(d));
            femu_opal_enc_ctrl(&r->e, TOK_EL);
        }
        break;
    case UID_M_MPA(3):                  /* ChangeAccessKey */
        if (n != 3) {
            return FEMU_OPAL_ST_INVALID_PARAMETER;
        }
        st = mpa_setup(o, m, x, &t[0], &c);
        if (st) {
            break;
        }
        if (!mpa_open(&c, &t[1], ak[0])) {
            st = FEMU_OPAL_ST_INVALID_PARAMETER;
        } else if (!ac->initialized || !mpa_unseal(o, x, ak[0], s)) {
            st = FEMU_OPAL_ST_FAIL;
        } else if (!mpa_open(&c, &t[2], ak[1])) {
            st = FEMU_OPAL_ST_INVALID_PARAMETER;
        } else if (!mpa_seal(o, x, ak[1], s)) {
            st = FEMU_OPAL_ST_FAIL;
        }
        break;
    case UID_M_MPA(4):                  /* EnableAccess */
        if (n != 2) {
            return FEMU_OPAL_ST_INVALID_PARAMETER;
        }
        st = mpa_setup(o, m, x, &t[0], &c);
        if (st) {
            break;
        }
        if (!mpa_open(&c, &t[1], ak[0]) || !ac->initialized) {
            st = FEMU_OPAL_ST_INVALID_PARAMETER;
        } else if (!mpa_unseal(o, x, ak[0], s)) {
            st = FEMU_OPAL_ST_FAIL;
        } else {
            ac->enabled = true;
            memcpy(ac->secret, s, sizeof(s));
        }
        break;
    default:                            /* DisableAccess */
        if (n) {
            return FEMU_OPAL_ST_INVALID_PARAMETER;
        }
        mpa_disable(o, x);
        st = FEMU_OPAL_ST_SUCCESS;
        break;
    }
    femu_hpke_wipe(&c);
    mpa_wipe(ak, sizeof(ak));
    mpa_wipe(s, sizeof(s));
    return st;
}

/* a method of MEK-MPA Table 10 on @obj; false when it is not one */
static bool mpa_method(FemuOpal *o, uint64_t obj, uint64_t m,
                       const FemuOpalTok *t, int n, FemuOpalReply *r)
{
    int x;

    if (!o->cfg.mpa || m <= UID_M_MPA(0) || m > UID_M_MPA(5)) {
        return false;
    }
    x = mpa_ac(o, obj);
    /* TestAccessKey changes nothing, so a read session may call it */
    if (x < 0 || !lsp_allowed(o, obj, m) ||
        (m != UID_M_MPA(2) && !o->s.write)) {
        r->status = FEMU_OPAL_ST_NOT_AUTHORIZED;
        return true;
    }
    r->status = mpa_do(o, m, x, t, n, r);
    if (!r->status && m != UID_M_MPA(2)) {
        femu_opal_enc_ctrl(&r->e, TOK_SL);
        femu_opal_enc_ctrl(&r->e, TOK_EL);
    }
    return true;
}

/* Level 0 feature 040Ch (MPA 5.2.1, Table 7): 12 bytes */
static uint8_t *mpa_level0(const FemuOpal *o, uint8_t *p)
{
    if (!o->cfg.mpa) {
        return p;
    }
    put16(p, 0x040C);
    p[2] = 0x10;
    p[3] = 0x08;
    put16(p + 4, FEMU_OPAL_MPA_ACS);
    put16(p + 6, FEMU_OPAL_MPA_PER_KEY);
    p[8] = FEMU_OPAL_MPA_AK_LEN;
    return p + 12;
}
