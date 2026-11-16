/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * FEMU TCG Opal TPer: transport, Level 0 discovery and the Session
 * Manager (TCG Storage Architecture Core 2.01, Opal SSC 2.30, SIIS 1.20).
 *
 * Every method finishes inside Security Send. Its response waits in one
 * buffer for the ComID until a Security Receive large enough takes it.
 */

#include "qemu/osdep.h"
#include "femu-opal.h"

enum {
    TOK_SL = 0xF0, TOK_EL = 0xF1, TOK_SN = 0xF2, TOK_EN = 0xF3,
    TOK_CALL = 0xF8, TOK_EOD = 0xF9, TOK_EOS = 0xFA,
    TOK_ST = 0xFB, TOK_ET = 0xFC, TOK_EMPTY = 0xFF,
};

/* Locking SP helpers in femu-opal-locking.c.inc */
static void lsp_factory_tables(FemuOpal *o, bool keep_global);
static void lsp_bytes_clear(FemuOpal *o);
static void lsp_undo_finish(FemuOpal *o, bool rollback);
static int lsp_rows(const FemuOpal *o, uint64_t table, uint64_t *rows);
static uint8_t *mpa_level0(const FemuOpal *o, uint8_t *p);
static void mpa_reset(FemuOpal *o, int type);
static bool mpa_new_kem(FemuOpal *o, bool keep);
static void mpa_init(FemuOpal *o);
struct FemuOpalReply;
static bool mpa_method(FemuOpal *o, uint64_t obj, uint64_t m,
                       const FemuOpalTok *t, int n, struct FemuOpalReply *r);
static void mpa_wipe(void *p, size_t n);

/* frame header sizes (Core 3.2.3, Tables 17, 18 and 20) */
#define COMPKT_HDR      20
#define PKT_HDR         24
#define SUBPKT_HDR      12
#define FRAME_HDR       (COMPKT_HDR + PKT_HDR + SUBPKT_HDR)

/* HANDLE_COMID_REQUEST codes (Core 3.3.4.7) */
#define MGMT_VERIFY_COMID 1
#define MGMT_STACK_RESET  2

/* what femu_opal_consume() takes away after a Receive */
enum { CONSUME_NONE, CONSUME_RESP, CONSUME_MGMT };

/* host property minimums (Opal Table 17) */
static const FemuOpalHostProps host_min = {
    .max_compacket = 2048,
    .max_packet = 2028,
    .max_ind_token = 1992,
    .max_packets = 1,
    .max_subpackets = 1,
    .max_methods = 1,
};

static void put16(uint8_t *p, uint16_t v)
{
    p[0] = v >> 8;
    p[1] = v;
}

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = v >> 24;
    p[1] = v >> 16;
    p[2] = v >> 8;
    p[3] = v;
}

static uint16_t get16(const uint8_t *p)
{
    return (p[0] << 8) | p[1];
}

static uint32_t get32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

static uint64_t get_be(const uint8_t *p, uint32_t n)
{
    uint64_t v = 0;

    while (n--) {
        v = (v << 8) | *p++;
    }
    return v;
}

static void femu_opal_stack_reset(FemuOpal *o)
{
    o->ready = false;
    o->resp_len = 0;
    o->host = host_min;
}

/*
 * The Locking SP as it leaves the factory. Every key is new except the
 * Global key when @keep_global is true; a new key erases its LBAs.
 */
static void femu_opal_factory_lsp(FemuOpal *o, bool keep_global)
{
    int i;

    for (i = FEMU_OPAL_AU_LSP_ADMIN1; i < FEMU_OPAL_AU_COUNT; i++) {
        memset(&o->sp.au[i], 0, sizeof(o->sp.au[i]));
        o->tries[i] = 0;
    }
    o->sp.au[FEMU_OPAL_AU_LSP_ADMIN1].enabled = true;
    o->sp.lsp_life = FEMU_OPAL_LIFE_INACTIVE;
    lsp_factory_tables(o, keep_global);
    lsp_bytes_clear(o);
}

/*
 * The whole TPer as it leaves the factory. User data survives only when
 * the Locking SP was never active (Opal 5.1.2).
 */
static void femu_opal_factory(FemuOpal *o)
{
    bool active = o->sp.lsp_life == FEMU_OPAL_LIFE_MANUFACTURED;
    uint64_t global_key = o->sp.range[0].key;

    memset(&o->sp, 0, sizeof(o->sp));
    o->sp.range[0].key = global_key;
    memset(o->tries, 0, sizeof(o->tries));
    o->sp.au[FEMU_OPAL_AU_ANYBODY].enabled = true;
    o->sp.au[FEMU_OPAL_AU_SID].enabled = true;
    o->sp.au[FEMU_OPAL_AU_SID].pin = o->cfg.msid;
    o->sp.au[FEMU_OPAL_AU_PSID].enabled = true;
    o->sp.au[FEMU_OPAL_AU_PSID].pin = o->cfg.psid;
    femu_opal_factory_lsp(o, !active);
}

void femu_opal_init(FemuOpal *o, const FemuOpalCfg *cfg)
{
    memset(o, 0, sizeof(*o));
    o->cfg = *cfg;
    o->next_tsn = 0x1000;
    o->next_key = 1;
    femu_opal_stack_reset(o);
    mpa_init(o);
    femu_opal_factory(o);
}

/*
 * Token decoder (Core 3.2.2.3; Opal 3.3.4.1.1 needs every atom form with
 * B = 0 or 1 and S = 0). Empty atoms are dropped. Returns the token count,
 * or -1 for a streaming protocol violation.
 */
int femu_opal_decode(const uint8_t *p, uint32_t len, FemuOpalTok *toks,
                     int max)
{
    uint32_t i = 0;
    int n = 0;

    while (i < len) {
        uint8_t b = p[i];
        uint32_t hdr;
        uint32_t dlen;
        bool bytes;
        bool sign;

        if (b == TOK_EMPTY) {
            i++;
            continue;
        }
        if (n == max) {
            return -1;
        }
        if (b < 0x80) {
            /* tiny atom: 0 S dddddd */
            if (b & 0x40) {
                return -1;
            }
            toks[n].type = FEMU_OPAL_TOK_UINT;
            toks[n++].val = b & 0x3f;
            i++;
            continue;
        }
        if (b < 0xC0) {
            bytes = b & 0x20;
            sign = b & 0x10;
            dlen = b & 0x0f;
            hdr = 1;
        } else if (b < 0xE0) {
            if (i + 2 > len) {
                return -1;
            }
            bytes = b & 0x10;
            sign = b & 0x08;
            dlen = ((b & 0x07) << 8) | p[i + 1];
            hdr = 2;
        } else if (b < 0xE4) {
            if (i + 4 > len) {
                return -1;
            }
            bytes = b & 0x02;
            sign = b & 0x01;
            dlen = (p[i + 1] << 16) | (p[i + 2] << 8) | p[i + 3];
            hdr = 4;
        } else if ((b >= TOK_SL && b <= TOK_EN) ||
                   (b >= TOK_CALL && b <= TOK_ET)) {
            toks[n].type = FEMU_OPAL_TOK_CTRL;
            toks[n++].val = b;
            i++;
            continue;
        } else {
            return -1;
        }
        if (sign || dlen > len - i - hdr) {
            return -1;
        }
        /* only the short byte atom A0 may be empty (Core Tables 8 to 13) */
        if (!dlen && (!bytes || hdr != 1)) {
            return -1;
        }
        if (bytes) {
            toks[n].type = FEMU_OPAL_TOK_BYTES;
            toks[n].p = p + i + hdr;
            toks[n].len = dlen;
        } else {
            uint32_t k;

            /* leading zero bytes are legal; a value above 64 bits is not */
            for (k = 0; k + 8 < dlen; k++) {
                if (p[i + hdr + k]) {
                    return -1;
                }
            }
            toks[n].type = FEMU_OPAL_TOK_UINT;
            toks[n].val = get_be(p + i + hdr + k, dlen - k);
        }
        n++;
        i += hdr + dlen;
    }
    return n;
}

static void enc_raw(FemuOpalEnc *e, const void *p, uint32_t len)
{
    if (e->overflow || len > e->cap - e->len) {
        e->overflow = true;
        return;
    }
    memcpy(e->buf + e->len, p, len);
    e->len += len;
}

void femu_opal_enc_ctrl(FemuOpalEnc *e, uint8_t tok)
{
    enc_raw(e, &tok, 1);
}

/* the shortest atom for @v (Core 3.2.2.3.1) */
void femu_opal_enc_uint(FemuOpalEnc *e, uint64_t v)
{
    uint8_t b[9];
    int n = 0;
    int i;

    if (v < 64) {
        femu_opal_enc_ctrl(e, v);
        return;
    }
    for (i = 7; i >= 0; i--) {
        if (n || (v >> (i * 8)) & 0xff) {
            b[1 + n++] = v >> (i * 8);
        }
    }
    b[0] = 0x80 | n;
    enc_raw(e, b, 1 + n);
}

void femu_opal_enc_bytes(FemuOpalEnc *e, const void *p, uint32_t len)
{
    uint8_t h[4];

    /* a long atom holds a 24-bit length */
    if (len > 0xffffff) {
        e->overflow = true;
        return;
    }
    if (len < 16) {
        h[0] = 0xA0 | len;
        enc_raw(e, h, 1);
    } else if (len < 2048) {
        h[0] = 0xD0 | (len >> 8);
        h[1] = len;
        enc_raw(e, h, 2);
    } else {
        h[0] = 0xE2;
        h[1] = len >> 16;
        h[2] = len >> 8;
        h[3] = len;
        enc_raw(e, h, 4);
    }
    enc_raw(e, p, len);
}

void femu_opal_enc_uid(FemuOpalEnc *e, uint64_t uid)
{
    uint8_t b[8];

    put32(b, uid >> 32);
    put32(b + 4, uid);
    femu_opal_enc_bytes(e, b, 8);
}

static void enc_named_uint(FemuOpalEnc *e, const char *name, uint64_t v)
{
    femu_opal_enc_ctrl(e, TOK_SN);
    femu_opal_enc_bytes(e, name, strlen(name));
    femu_opal_enc_uint(e, v);
    femu_opal_enc_ctrl(e, TOK_EN);
}

static bool pin_eq(const FemuOpalPin *a, const FemuOpalPin *b)
{
    return a->len == b->len && !memcmp(a->v, b->v, a->len);
}

/*
 * The committed tables. Effects outside a session (Level 0, Block SID,
 * TPER_RESET) wait for the commit of a transaction (Core 3.3.7.3).
 */
static const FemuOpalSp *committed(const FemuOpal *o)
{
    return o->s.open && o->s.txn ? &o->s.txn_sp : &o->sp;
}

/* the Locking feature bits of Level 0 (Opal 3.1.1.3) */
static uint8_t level0_locking(const FemuOpal *o)
{
    const FemuOpalSp *sp = committed(o);
    uint8_t b = 0x01 | 0x08;            /* Supported, Media Encryption */
    int r;

    if (sp->lsp_life != FEMU_OPAL_LIFE_MANUFACTURED) {
        return b;
    }
    b |= 0x02;
    for (r = 0; r <= FEMU_OPAL_RANGES; r++) {
        if ((sp->range[r].rle && sp->range[r].rl) ||
            (sp->range[r].wle && sp->range[r].wl)) {
            b |= 0x04;
        }
    }
    /* MBR Done is 0 while MBR Enabled is 0 (Core 3.3.6.5.6) */
    if (sp->mbr_enable) {
        b |= 0x10 | (sp->mbr_done ? 0x20 : 0);
    }
    return b;
}

/*
 * Level 0 discovery (Opal 3.1.1): header, then descriptors in increasing
 * feature code order.
 */
uint32_t femu_opal_level0(const FemuOpal *o, uint8_t *buf, uint32_t cap)
{
    uint8_t d[256];
    uint8_t *p = d + 48;

    memset(d, 0, sizeof(d));
    put32(d + 4, 1);                    /* data structure revision */

    /* TPer 0001h: Sync, Streaming */
    put16(p, 0x0001);
    p[2] = 0x10;
    p[3] = 0x0c;
    p[4] = 0x11;
    p += 16;

    /* Locking 0002h */
    put16(p, 0x0002);
    p[2] = 0x30;
    p[3] = 0x0c;
    p[4] = level0_locking(o);
    p += 16;

    /* Geometry Reporting 0003h: no alignment requirement */
    put16(p, 0x0003);
    p[2] = 0x10;
    p[3] = 0x1c;
    put32(p + 12, o->cfg.lba_size);
    p[23] = 1;                          /* AlignmentGranularity */
    p += 32;

    /* SIIS 0005h (SIIS 3.6): revision 1.20 */
    put16(p, 0x0005);
    p[2] = 0x10;
    p[3] = 0x0c;
    p[4] = 0x20;
    p += 16;

    /* Opal SSC V2 0203h: version 2, SSC minor version 3 (2.30) */
    put16(p, 0x0203);
    p[2] = 0x23;
    p[3] = 0x10;
    put16(p + 4, FEMU_OPAL_COMID);
    put16(p + 6, 1);
    put16(p + 9, o->cfg.admins);
    put16(p + 11, o->cfg.users);
    p += 20;

    /* Block SID Authentication 0402h (Block SID 3.1): no Freeze */
    put16(p, 0x0402);
    p[2] = 0x20;
    p[3] = 0x0c;
    p[4] = (pin_eq(&committed(o)->au[FEMU_OPAL_AU_SID].pin,
                   &o->cfg.msid) ? 0 : 1) |
           (o->sid_blocked ? 2 : 0);
    p[5] = o->sid_block_hw;
    p += 16;

    /* Supported Data Removal Mechanism 0404h: set once erase exists */
    put16(p, 0x0404);
    p[2] = 0x20;
    p[3] = 0x20;
    p[6] = o->cfg.crypto_erase ? 0x04 : 0;
    p += 36;

    p = mpa_level0(o, p);

    put32(d, (p - d) - 4);
    memcpy(buf, d, MIN(cap, (uint32_t)(p - d)));
    return p - d;
}

/* frame @slen payload bytes (already at o->resp + FRAME_HDR) */
static void femu_opal_frame(FemuOpal *o, uint32_t tsn, uint32_t hsn,
                            uint32_t slen)
{
    uint32_t pad = -slen & 3;
    uint32_t plen = SUBPKT_HDR + slen + pad;
    uint8_t *r = o->resp;

    memset(r, 0, FRAME_HDR);
    memset(r + FRAME_HDR + slen, 0, pad);
    put16(r + 4, FEMU_OPAL_COMID);
    put32(r + 16, PKT_HDR + plen);
    put32(r + COMPKT_HDR, tsn);
    put32(r + COMPKT_HDR + 4, hsn);
    put32(r + COMPKT_HDR + 20, plen);
    put32(r + COMPKT_HDR + PKT_HDR + 8, slen);
    o->resp_len = COMPKT_HDR + PKT_HDR + plen;
    o->ready = true;
}

static bool tok_is(const FemuOpalTok *t, uint8_t ctrl)
{
    return t->type == FEMU_OPAL_TOK_CTRL && t->val == ctrl;
}

static bool tok_uid(const FemuOpalTok *t, uint64_t *uid)
{
    if (t->type != FEMU_OPAL_TOK_BYTES || t->len != 8) {
        return false;
    }
    *uid = get_be(t->p, 8);
    return true;
}

static bool tok_name(const FemuOpalTok *t, const char *name)
{
    return t->type == FEMU_OPAL_TOK_BYTES && t->len == strlen(name) &&
           !memcmp(t->p, name, t->len);
}

/* the HostProperties name @t names, or NULL */
static uint32_t *host_field(FemuOpalHostProps *h, const FemuOpalTok *t,
                            uint32_t *min)
{
    static const struct {
        const char *name;
        size_t off;
    } names[] = {
        { "MaxComPacketSize", offsetof(FemuOpalHostProps, max_compacket) },
        { "MaxPacketSize", offsetof(FemuOpalHostProps, max_packet) },
        { "MaxIndTokenSize", offsetof(FemuOpalHostProps, max_ind_token) },
        { "MaxPackets", offsetof(FemuOpalHostProps, max_packets) },
        { "MaxSubpackets", offsetof(FemuOpalHostProps, max_subpackets) },
        { "MaxMethods", offsetof(FemuOpalHostProps, max_methods) },
    };
    int i;

    for (i = 0; i < ARRAY_SIZE(names); i++) {
        if (tok_name(t, names[i].name)) {
            *min = *(const uint32_t *)((const uint8_t *)&host_min +
                                       names[i].off);
            return (uint32_t *)((uint8_t *)h + names[i].off);
        }
    }
    return NULL;
}

/*
 * The optional HostProperties parameter: SN 0 SL {SN name uint EN}* EL EN.
 * @t holds the @n tokens between the parameter list's SL and EL. Unknown
 * names are ignored; a value below the minimum is raised (Core 5.2.2.4).
 * Returns false for a malformed list.
 */
static bool host_props(const FemuOpalTok *t, int n, FemuOpalHostProps *h,
                       bool *given)
{
    int i;

    *given = n > 0;
    if (!n) {
        return true;
    }
    if (n < 5 || !tok_is(&t[0], TOK_SN) || t[1].type != FEMU_OPAL_TOK_UINT ||
        t[1].val != 0 || !tok_is(&t[2], TOK_SL)) {
        return false;
    }
    for (i = 3; i + 3 < n && tok_is(&t[i], TOK_SN); i += 4) {
        uint32_t min;
        uint32_t *f;

        if (t[i + 1].type != FEMU_OPAL_TOK_BYTES ||
            t[i + 2].type != FEMU_OPAL_TOK_UINT ||
            !tok_is(&t[i + 3], TOK_EN)) {
            return false;
        }
        f = host_field(h, &t[i + 1], &min);
        if (f) {
            *f = MAX(min, MIN(t[i + 2].val, UINT32_MAX));
        }
    }
    return i + 2 == n && tok_is(&t[i], TOK_EL) && tok_is(&t[i + 1], TOK_EN);
}

/* start a Session Manager reply: CALL SMUID method SL */
static void sm_reply_start(FemuOpalEnc *e, FemuOpal *o, uint64_t method)
{
    *e = (FemuOpalEnc){
        .buf = o->resp + FRAME_HDR,
        .cap = FEMU_OPAL_BUF - FRAME_HDR,
    };
    femu_opal_enc_ctrl(e, TOK_CALL);
    femu_opal_enc_uid(e, FEMU_OPAL_UID_SMUID);
    femu_opal_enc_uid(e, method);
    femu_opal_enc_ctrl(e, TOK_SL);
}

/* end it: EL EOD SL status 0 0 EL, then frame it */
static void sm_reply_end(FemuOpalEnc *e, FemuOpal *o, uint8_t status)
{
    femu_opal_enc_ctrl(e, TOK_EL);
    femu_opal_enc_ctrl(e, TOK_EOD);
    femu_opal_enc_ctrl(e, TOK_SL);
    femu_opal_enc_uint(e, status);
    femu_opal_enc_uint(e, 0);
    femu_opal_enc_uint(e, 0);
    femu_opal_enc_ctrl(e, TOK_EL);
    if (!e->overflow) {
        femu_opal_frame(o, 0, 0, e->len);
    }
}

/*
 * Properties (Core 5.2.2.4): take the HostProperties, then report the TPer
 * properties (Opal Table 17) and, when the host sent some, the host values
 * in use. A nonzero host status aborts the method (Core 3.2.4.2).
 */
static void femu_opal_properties(FemuOpal *o, const FemuOpalTok *t, int n,
                                 uint8_t host_status)
{
    FemuOpalHostProps h = o->host;
    FemuOpalEnc e;
    bool given;

    sm_reply_start(&e, o, FEMU_OPAL_UID_PROPERTIES);
    if (host_status) {
        sm_reply_end(&e, o, host_status);
        return;
    }
    if (!host_props(t, n, &h, &given)) {
        sm_reply_end(&e, o, FEMU_OPAL_ST_INVALID_PARAMETER);
        return;
    }
    o->host = h;
    femu_opal_enc_ctrl(&e, TOK_SL);
    enc_named_uint(&e, "MaxComPacketSize", FEMU_OPAL_BUF);
    enc_named_uint(&e, "MaxResponseComPacketSize", FEMU_OPAL_BUF);
    enc_named_uint(&e, "MaxPacketSize", FEMU_OPAL_BUF - COMPKT_HDR);
    enc_named_uint(&e, "MaxIndTokenSize", FEMU_OPAL_BUF - FRAME_HDR);
    enc_named_uint(&e, "MaxPackets", 1);
    enc_named_uint(&e, "MaxSubpackets", 1);
    enc_named_uint(&e, "MaxMethods", 1);
    enc_named_uint(&e, "MaxSessions", 1);
    enc_named_uint(&e, "MaxAuthentications", 2);
    enc_named_uint(&e, "MaxTransactionLimit", 1);
    /* 0: no session timeout */
    enc_named_uint(&e, "DefSessionTimeout", 0);
    femu_opal_enc_ctrl(&e, TOK_EL);
    if (given) {
        femu_opal_enc_ctrl(&e, TOK_SN);
        femu_opal_enc_uint(&e, 0);
        femu_opal_enc_ctrl(&e, TOK_SL);
        enc_named_uint(&e, "MaxComPacketSize", o->host.max_compacket);
        enc_named_uint(&e, "MaxPacketSize", o->host.max_packet);
        enc_named_uint(&e, "MaxIndTokenSize", o->host.max_ind_token);
        enc_named_uint(&e, "MaxPackets", o->host.max_packets);
        enc_named_uint(&e, "MaxSubpackets", o->host.max_subpackets);
        enc_named_uint(&e, "MaxMethods", o->host.max_methods);
        femu_opal_enc_ctrl(&e, TOK_EL);
        femu_opal_enc_ctrl(&e, TOK_EN);
    }
    sm_reply_end(&e, o, FEMU_OPAL_ST_SUCCESS);
}

/* method UIDs (Core Table 241, Opal Tables 21 and 37) */
#define UID_M_NEXT          0x0000000600000008ull
#define UID_M_GETACL        0x000000060000000Dull
#define UID_M_GET           0x0000000600000016ull
#define UID_M_SET           0x0000000600000017ull
#define UID_M_AUTHENTICATE  0x000000060000001Cull
#define UID_M_REVERT        0x0000000600000202ull
#define UID_M_ACTIVATE      0x0000000600000203ull
#define UID_M_RANDOM        0x0000000600000601ull
#define UID_M_STARTSESSION  0x000000000000FF02ull
#define UID_M_SYNCSESSION   0x000000000000FF03ull

/* objects */
#define UID_THISSP          0x0000000000000001ull
#define UID_SP_ADMIN        0x0000020500000001ull
#define UID_SP_LOCKING      0x0000020500000002ull
#define UID_TPERINFO        0x0000020100030001ull
#define UID_SPINFO          0x0000000200000001ull
#define UID_T_SPINFO        0x0000000200000000ull
#define UID_T_AUTHORITY     0x0000000900000000ull
#define UID_T_CPIN          0x0000000B00000000ull
#define UID_T_SP            0x0000020500000000ull
#define UID_T_ACCESSCONTROL 0x0000000700000000ull
#define UID_AU_ANYBODY      0x0000000900000001ull
#define UID_AU_ADMINS       0x0000000900000002ull
#define UID_AU_MAKERS       0x0000000900000003ull
#define UID_AU_SID          0x0000000900000006ull
#define UID_AU_ASP_ADMIN1   0x0000000900000201ull
#define UID_AU_PSID         0x000000090001FF01ull
#define UID_AU_LSP_ADMIN(i) (0x0000000900010001ull + (i))
#define UID_AU_USERS        0x0000000900030000ull
#define UID_AU_USER(i)      (0x0000000900030001ull + (i))
#define UID_CPIN_SID        0x0000000B00000001ull
#define UID_CPIN_MSID       0x0000000B00008402ull
#define UID_CPIN_ASP_ADMIN1 0x0000000B00000201ull
#define UID_CPIN_PSID       0x0000000B0001FF01ull

/* ACEs the Admin SP ACL names (Opal Table 23, PSID Table 6) */
#define UID_ACE_ANYBODY     0x0000000800000001ull
#define UID_ACE_SET_ENABLED 0x0000000800030001ull
#define UID_ACE_SP_SID      0x0000000800030002ull
#define UID_ACE_TPERINFO_PRE 0x0000000800030003ull
#define UID_ACE_SID_NOPIN   0x0000000800008C02ull
#define UID_ACE_SID_SET_PIN 0x0000000800008C03ull
#define UID_ACE_MSID_GET    0x0000000800008C04ull
#define UID_ACE_ADMINS_SET_PIN 0x000000080003A001ull
#define UID_ACE_SP_PSID     0x00000008000100E0ull
#define UID_ACE_CPIN_PSID_NOPIN 0x00000008000100E1ull

/* the authority @uid names in the Admin SP or the Locking SP, or -1 */
static int femu_opal_auth_index(bool locking, uint64_t uid)
{
    if (uid == UID_AU_ANYBODY) {
        return FEMU_OPAL_AU_ANYBODY;
    }
    if (!locking) {
        switch (uid) {
        case UID_AU_SID:
            return FEMU_OPAL_AU_SID;
        case UID_AU_PSID:
            return FEMU_OPAL_AU_PSID;
        case UID_AU_ASP_ADMIN1:
            return FEMU_OPAL_AU_ASP_ADMIN1;
        }
        return -1;
    }
    if (uid >= UID_AU_LSP_ADMIN(0) && uid <= UID_AU_LSP_ADMIN(3)) {
        return FEMU_OPAL_AU_LSP_ADMIN1 + (uid - UID_AU_LSP_ADMIN(0));
    }
    if (uid >= UID_AU_USER(0) && uid <= UID_AU_USER(7)) {
        return FEMU_OPAL_AU_LSP_USER1 + (uid - UID_AU_USER(0));
    }
    return -1;
}

static bool femu_opal_auth_class(bool locking, uint64_t uid)
{
    return uid == UID_AU_ADMINS || (!locking && uid == UID_AU_MAKERS) ||
           (locking && uid == UID_AU_USERS);
}

/*
 * Check @proof for authority @a. Wrong PINs count in Tries when TryLimit
 * is not 0; a good PIN clears Tries. A SID that Block SID blocks fails
 * without a count (Block SID 4.2.2).
 */
static uint8_t femu_opal_check_pin(FemuOpal *o, int a, const FemuOpalTok *proof)
{
    FemuOpalAuth *au = &o->sp.au[a];

    if (a == FEMU_OPAL_AU_ANYBODY) {
        return FEMU_OPAL_ST_SUCCESS;
    }
    if (!au->enabled) {
        return FEMU_OPAL_ST_NOT_AUTHORIZED;
    }
    if (a == FEMU_OPAL_AU_SID && o->sid_blocked) {
        return FEMU_OPAL_ST_NOT_AUTHORIZED;
    }
    if (au->try_limit && o->tries[a] >= au->try_limit) {
        return FEMU_OPAL_ST_LOCKED_OUT;
    }
    if (proof && proof->len == au->pin.len &&
        !memcmp(proof->p, au->pin.v, au->pin.len)) {
        o->tries[a] = 0;
        return FEMU_OPAL_ST_SUCCESS;
    }
    if (au->try_limit) {
        o->tries[a]++;
    }
    return FEMU_OPAL_ST_NOT_AUTHORIZED;
}

static bool sess_has(const FemuOpal *o, int a)
{
    return o->s.auth & (1u << a);
}

static bool asp_admins(const FemuOpal *o)
{
    return sess_has(o, FEMU_OPAL_AU_ASP_ADMIN1);
}

/*
 * A named parameter SN <name> <value> EN at t[i], with a uint name and a
 * one-token value. Returns the value and sets *name, or returns NULL.
 */
static const FemuOpalTok *named(const FemuOpalTok *t, int n, int i,
                                uint64_t *name)
{
    if (i + 3 < n && tok_is(&t[i], TOK_SN) &&
        t[i + 1].type == FEMU_OPAL_TOK_UINT && tok_is(&t[i + 3], TOK_EN)) {
        *name = t[i + 1].val;
        return &t[i + 2];
    }
    return NULL;
}

/* SyncSession, or a failed StartSession (Core 5.2.3.2) */
/* SyncSession, also the reply to a failed StartSession (Core 5.2.3.2) */
static void femu_opal_sync(FemuOpal *o, uint32_t hsn, uint32_t tsn,
                           uint8_t status)
{
    FemuOpalEnc e;

    sm_reply_start(&e, o, UID_M_SYNCSESSION);
    femu_opal_enc_uint(&e, hsn);
    femu_opal_enc_uint(&e, tsn);
    sm_reply_end(&e, o, status);
}

/*
 * StartSession[HostSessionID, SPID, Write, HostChallenge = 0,
 * HostSigningAuthority = 3, SessionTimeout = 5] (Opal 4.1.1.2). @t holds
 * the @n parameter tokens.
 */
static void femu_opal_start_session(FemuOpal *o, const FemuOpalTok *t, int n)
{
    const FemuOpalTok *challenge = NULL;
    uint64_t sp;
    uint64_t auid = UID_AU_ANYBODY;
    bool locking;
    uint8_t st;
    int a;
    int i;

    if (n < 3 || t[0].type != FEMU_OPAL_TOK_UINT || !tok_uid(&t[1], &sp) ||
        t[2].type != FEMU_OPAL_TOK_UINT || t[2].val > 1) {
        femu_opal_sync(o, 0, 0, FEMU_OPAL_ST_INVALID_PARAMETER);
        return;
    }
    for (i = 3; i < n; i += 4) {
        uint64_t name = ~0ull;
        const FemuOpalTok *v = named(t, n, i, &name);
        bool ok = false;

        if (v && name == 0 && v->type == FEMU_OPAL_TOK_BYTES) {
            challenge = v;
            ok = true;
        } else if (v && name == 3) {
            ok = tok_uid(v, &auid);
        } else if (v && name == 5) {
            ok = v->type == FEMU_OPAL_TOK_UINT;     /* no timeout is kept */
        }
        if (!ok) {
            femu_opal_sync(o, t[0].val, 0, FEMU_OPAL_ST_INVALID_PARAMETER);
            return;
        }
    }
    if (o->s.open) {
        femu_opal_sync(o, t[0].val, 0, FEMU_OPAL_ST_NO_SESSIONS);
        return;
    }
    if (sp != UID_SP_ADMIN && sp != UID_SP_LOCKING) {
        femu_opal_sync(o, t[0].val, 0, FEMU_OPAL_ST_INVALID_PARAMETER);
        return;
    }
    locking = sp == UID_SP_LOCKING;
    /* no session to a Manufactured-Inactive SP (Opal 5.2.2.1) */
    if (locking && o->sp.lsp_life != FEMU_OPAL_LIFE_MANUFACTURED) {
        femu_opal_sync(o, t[0].val, 0, FEMU_OPAL_ST_FAIL);
        return;
    }
    a = femu_opal_auth_index(locking, auid);
    if (a < 0 || femu_opal_auth_class(locking, auid)) {
        femu_opal_sync(o, t[0].val, 0, FEMU_OPAL_ST_INVALID_PARAMETER);
        return;
    }
    st = femu_opal_check_pin(o, a, challenge);
    if (st) {
        femu_opal_sync(o, t[0].val, 0, st);
        return;
    }
    memset(&o->s, 0, sizeof(o->s));
    o->s.open = true;
    o->s.locking = locking;
    o->s.write = t[2].val;
    o->s.hsn = t[0].val;
    o->s.tsn = o->next_tsn++;
    if (o->next_tsn < 0x1000) {
        o->next_tsn = 0x1000;
    }
    o->s.auth = 1u << FEMU_OPAL_AU_ANYBODY | 1u << a;
    femu_opal_sync(o, o->s.hsn, o->s.tsn, FEMU_OPAL_ST_SUCCESS);
}

static void femu_opal_close(FemuOpal *o)
{
    if (o->s.open && o->s.txn) {
        o->sp = o->s.txn_sp;
        lsp_undo_finish(o, true);
    }
    memset(&o->s, 0, sizeof(o->s));
}

/* the C_PIN row of the Admin SP for @uid, as an authority index, or -1 */
static int asp_cpin(uint64_t uid)
{
    switch (uid) {
    case UID_CPIN_SID:
        return FEMU_OPAL_AU_SID;
    case UID_CPIN_ASP_ADMIN1:
        return FEMU_OPAL_AU_ASP_ADMIN1;
    case UID_CPIN_PSID:
        return FEMU_OPAL_AU_PSID;
    }
    return -1;
}

/* the response body for an in-session method */
typedef struct FemuOpalReply {
    FemuOpalEnc e;
    uint8_t status;
} FemuOpalReply;

#include "femu-opal-locking.c.inc"

/*
 * One column of an Admin SP object for Get. Returns false when the object
 * has no such column. Columns a session may read are checked by the
 * caller with asp_get_cols().
 */
static bool asp_col(FemuOpal *o, uint64_t uid, uint32_t col, FemuOpalEnc *e)
{
    int a = asp_cpin(uid);

    if (uid == UID_CPIN_MSID) {
        a = -2;
    }
    if (a != -1) {
        const FemuOpalPin *pin = a == -2 ? &o->cfg.msid : &o->sp.au[a].pin;

        switch (col) {
        case 0:
            femu_opal_enc_uid(e, uid);
            return true;
        case 3:
            femu_opal_enc_bytes(e, pin->v, pin->len);
            return true;
        case 4:
            femu_opal_enc_uid(e, 0);            /* CharSet: NULL */
            return true;
        case 5:
            femu_opal_enc_uint(e, a < 0 ? 0 : o->sp.au[a].try_limit);
            return true;
        case 6:
            femu_opal_enc_uint(e, a < 0 ? 0 : o->tries[a]);
            return true;
        case 7:
            femu_opal_enc_uint(e, 0);           /* Persistence: False */
            return true;
        }
        return false;
    }
    a = femu_opal_auth_index(false, uid);
    if (a >= 0 || uid == UID_AU_ADMINS || uid == UID_AU_MAKERS) {
        bool cls = a < 0;

        static const char *const nm[] = {
            [FEMU_OPAL_AU_ANYBODY] = "Anybody",
            [FEMU_OPAL_AU_SID] = "SID",
            [FEMU_OPAL_AU_PSID] = "PSID",
            [FEMU_OPAL_AU_ASP_ADMIN1] = "Admin1",
        };
        static const uint64_t cred[] = {
            [FEMU_OPAL_AU_SID] = UID_CPIN_SID,
            [FEMU_OPAL_AU_PSID] = UID_CPIN_PSID,
            [FEMU_OPAL_AU_ASP_ADMIN1] = UID_CPIN_ASP_ADMIN1,
        };
        const char *name = cls ? (uid == UID_AU_ADMINS ? "Admins" : "Makers")
                               : nm[a];

        switch (col) {
        case 0:
            femu_opal_enc_uid(e, uid);
            return true;
        case 1:
            femu_opal_enc_bytes(e, name, strlen(name));
            return true;
        case 4:                                 /* Class */
            femu_opal_enc_uid(e, a == FEMU_OPAL_AU_ASP_ADMIN1 ?
                              UID_AU_ADMINS : 0);
            return true;
        case 10:                                /* Credential */
            femu_opal_enc_uid(e, cls ? 0 : cred[a]);
            return true;
        case 3:                                 /* IsClass */
            femu_opal_enc_uint(e, cls);
            return true;
        case 5:                                 /* Enabled */
            femu_opal_enc_uint(e, cls ? 1 : o->sp.au[a].enabled);
            return true;
        case 9:                                 /* Operation: Password */
            femu_opal_enc_uint(e, cls || a == FEMU_OPAL_AU_ANYBODY ? 0 : 1);
            return true;
        }
        return false;
    }
    if (uid == UID_SP_ADMIN || uid == UID_SP_LOCKING) {
        switch (col) {
        case 0:
            femu_opal_enc_uid(e, uid);
            return true;
        case 6:                                 /* LifeCycleState */
            femu_opal_enc_uint(e, uid == UID_SP_ADMIN ?
                               FEMU_OPAL_LIFE_MANUFACTURED : o->sp.lsp_life);
            return true;
        case 7:                                 /* Frozen */
            femu_opal_enc_uint(e, 0);
            return true;
        }
        return false;
    }
    if (uid == UID_SPINFO) {
        switch (col) {
        case 0:
            femu_opal_enc_uid(e, uid);
            return true;
        case 1:
            femu_opal_enc_uid(e, UID_SP_ADMIN);
            return true;
        case 2:
            femu_opal_enc_bytes(e, "Admin", 5);
            return true;
        case 3:                                 /* Size */
        case 4:                                 /* SizeInUse */
        case 5:                                 /* SPSessionTimeout */
            femu_opal_enc_uint(e, 0);
            return true;
        case 6:                                 /* Enabled */
            femu_opal_enc_uint(e, 1);
            return true;
        }
        return false;
    }
    if (uid == UID_TPERINFO) {
        switch (col) {
        case 0:
            femu_opal_enc_uid(e, uid);
            return true;
        case 5:                                 /* ProtocolVersion */
            femu_opal_enc_uint(e, 1);
            return true;
        case 7:                                 /* SSC */
            femu_opal_enc_ctrl(e, TOK_SL);
            femu_opal_enc_bytes(e, "Opal", 4);
            femu_opal_enc_ctrl(e, TOK_EL);
            return true;
        case 8:
            femu_opal_enc_uint(e, o->sp.pre);
            return true;
        }
        return false;
    }
    return false;
}

/*
 * The columns of @uid this session may read (Opal Table 22), as a mask.
 * C_PIN_SID and C_PIN_Admin1 hide the PIN; C_PIN_MSID shows UID and PIN;
 * C_PIN_PSID shows no PIN (PSID 4.2.3).
 */
static uint32_t asp_get_cols(FemuOpal *o, uint64_t uid)
{
    const uint32_t nopin = 1u << 0 | 1u << 4 | 1u << 5 | 1u << 6 | 1u << 7;

    switch (uid) {
    case UID_CPIN_MSID:
        return 1u << 0 | 1u << 3;
    case UID_CPIN_SID:
    case UID_CPIN_ASP_ADMIN1:
        return asp_admins(o) || sess_has(o, FEMU_OPAL_AU_SID) ? nopin : 0;
    case UID_CPIN_PSID:
        return nopin;
    default:
        return ~0u;
    }
}

/* the last column of an Admin SP object (Core and Opal table schemas), or -1 */
static int asp_maxcol(uint64_t uid)
{
    if (asp_cpin(uid) >= 0 || uid == UID_CPIN_MSID) {
        return 7;
    }
    if (femu_opal_auth_index(false, uid) >= 0 || uid == UID_AU_ADMINS ||
        uid == UID_AU_MAKERS) {
        return 18;
    }
    if (uid == UID_SP_ADMIN || uid == UID_SP_LOCKING) {
        return 7;
    }
    if (uid == UID_SPINFO) {
        return 6;
    }
    if (uid == UID_TPERINFO) {
        return 8;
    }
    return -1;
}

static bool asp_object(uint64_t uid)
{
    return asp_maxcol(uid) >= 0;
}

/*
 * Get[Cellblock] (Core 5.3.3.6): SL {SN 3 start EN} {SN 4 end EN} EL. The
 * reply lists the readable columns in the range, in order. No readable
 * column at all: NOT_AUTHORIZED.
 */
static void femu_opal_get(FemuOpal *o, uint64_t uid, const FemuOpalTok *t,
                          int n, FemuOpalReply *r)
{
    uint64_t start = 0;
    uint64_t end;
    uint32_t cols;
    uint32_t c;
    bool have_end = false;
    int i;

    if (o->s.locking || !asp_object(uid) || n < 2 ||
        !tok_is(&t[0], TOK_SL) || !tok_is(&t[n - 1], TOK_EL)) {
        r->status = o->s.locking || asp_object(uid) ?
                    FEMU_OPAL_ST_INVALID_PARAMETER :
                    FEMU_OPAL_ST_NOT_AUTHORIZED;
        return;
    }
    for (i = 1; i < n - 1; i += 4) {
        uint64_t name = ~0ull;
        const FemuOpalTok *v = named(t, n - 1, i, &name);

        if (!v || v->type != FEMU_OPAL_TOK_UINT || (name != 3 && name != 4)) {
            r->status = FEMU_OPAL_ST_INVALID_PARAMETER;
            return;
        }
        if (name == 3) {
            start = v->val;
        } else {
            end = v->val;
            have_end = true;
        }
    }
    if (!have_end) {
        end = asp_maxcol(uid);
    }
    /* a Cellblock outside the table fails (Core 5.3.3.6.3) */
    if (start > end || end > asp_maxcol(uid)) {
        r->status = FEMU_OPAL_ST_INVALID_PARAMETER;
        return;
    }
    cols = asp_get_cols(o, uid);
    if (!cols) {
        r->status = FEMU_OPAL_ST_NOT_AUTHORIZED;
        return;
    }
    femu_opal_enc_ctrl(&r->e, TOK_SL);
    femu_opal_enc_ctrl(&r->e, TOK_SL);
    for (c = start; c <= end; c++) {
        uint32_t mark = r->e.len;

        if (!(cols & (1u << c))) {
            continue;
        }
        femu_opal_enc_ctrl(&r->e, TOK_SN);
        femu_opal_enc_uint(&r->e, c);
        if (!asp_col(o, uid, c, &r->e)) {
            r->e.len = mark;
            continue;
        }
        femu_opal_enc_ctrl(&r->e, TOK_EN);
    }
    femu_opal_enc_ctrl(&r->e, TOK_EL);
    femu_opal_enc_ctrl(&r->e, TOK_EL);
}

/*
 * Set[Where = 0, Values = 1] on an Admin SP object (Core 5.3.3.7). Every
 * column is checked before any changes, so a refusal writes nothing.
 */
/*
 * Set[Where = 0, Values = 1] on an Admin SP object (Core 5.3.3.7). Every
 * column is checked before any change, so a refusal writes nothing. No
 * Values: success with no change. A column twice: INVALID_PARAMETER.
 */
static void femu_opal_set_into(FemuOpal *o, FemuOpalSp *next, uint64_t uid,
                               const FemuOpalTok *t, int n, FemuOpalReply *r)
{
    int a = asp_cpin(uid);
    int au = femu_opal_auth_index(false, uid);
    uint32_t seen = 0;
    bool denied = false;
    int i;

    if (o->s.locking || !asp_object(uid)) {
        r->status = FEMU_OPAL_ST_NOT_AUTHORIZED;
        return;
    }
    if (n && (n < 5 || !tok_is(&t[0], TOK_SN) ||
              t[1].type != FEMU_OPAL_TOK_UINT || t[1].val != 1 ||
              !tok_is(&t[2], TOK_SL) ||
              !tok_is(&t[n - 2], TOK_EL) || !tok_is(&t[n - 1], TOK_EN))) {
        r->status = FEMU_OPAL_ST_INVALID_PARAMETER;
        return;
    }
    if (!o->s.write) {
        r->status = FEMU_OPAL_ST_NOT_AUTHORIZED;
        return;
    }
    for (i = 3; i < n - 2; i += 4) {
        const FemuOpalTok *col = &t[i + 1];
        const FemuOpalTok *v = &t[i + 2];

        if (i + 3 >= n - 1 || !tok_is(&t[i], TOK_SN) ||
            !tok_is(&t[i + 3], TOK_EN) || col->type != FEMU_OPAL_TOK_UINT ||
            col->val > asp_maxcol(uid) || (seen & (1u << col->val))) {
            r->status = FEMU_OPAL_ST_INVALID_PARAMETER;
            return;
        }
        seen |= 1u << col->val;
        if (a == FEMU_OPAL_AU_SID && col->val == 3) {
            /* ACE_C_PIN_SID_Set_PIN */
            denied |= !sess_has(o, FEMU_OPAL_AU_SID);
        } else if (a == FEMU_OPAL_AU_ASP_ADMIN1 && col->val == 3) {
            /* ACE_C_PIN_Admins_Set_PIN */
            denied |= !asp_admins(o) && !sess_has(o, FEMU_OPAL_AU_SID);
        } else if (au == FEMU_OPAL_AU_ASP_ADMIN1 && col->val == 5) {
            /* ACE_Set_Enabled */
            denied |= !sess_has(o, FEMU_OPAL_AU_SID);
            if (v->type != FEMU_OPAL_TOK_UINT || v->val > 1) {
                r->status = FEMU_OPAL_ST_INVALID_PARAMETER;
                return;
            }
            next->au[au].enabled = v->val;
            continue;
        } else if (uid == UID_TPERINFO && col->val == 8) {
            /* ACE_TPerInfo_Set_ProgrammaticResetEnable */
            denied |= !sess_has(o, FEMU_OPAL_AU_SID);
            if (v->type != FEMU_OPAL_TOK_UINT || v->val > 1) {
                r->status = FEMU_OPAL_ST_INVALID_PARAMETER;
                return;
            }
            next->pre = v->val;
            continue;
        } else {
            denied = true;
            continue;
        }
        /* a PIN of at most 32 bytes (Core 5.1.3.63) */
        if (v->type != FEMU_OPAL_TOK_BYTES || v->len > FEMU_OPAL_PIN_MAX) {
            r->status = FEMU_OPAL_ST_INVALID_PARAMETER;
            return;
        }
        next->au[a].pin.len = v->len;
        memcpy(next->au[a].pin.v, v->p, v->len);
    }
    if (denied) {
        r->status = FEMU_OPAL_ST_NOT_AUTHORIZED;
        return;
    }
    o->sp = *next;
    femu_opal_enc_ctrl(&r->e, TOK_SL);
    femu_opal_enc_ctrl(&r->e, TOK_EL);
}

/* the copy holds AC secrets, so it is wiped on every path */
static void femu_opal_set(FemuOpal *o, uint64_t uid, const FemuOpalTok *t,
                          int n, FemuOpalReply *r)
{
    g_autofree FemuOpalSp *next = g_memdup2(&o->sp, sizeof(o->sp));

    femu_opal_set_into(o, next, uid, t, n, r);
    mpa_wipe(next, sizeof(*next));
}

/* Authenticate[Authority, Proof = 0] (Core 5.3.4.1.14.1): result True/False */
static void femu_opal_authenticate(FemuOpal *o, const FemuOpalTok *t, int n,
                                   FemuOpalReply *r)
{
    const FemuOpalTok *proof = NULL;
    uint64_t name = ~0ull;
    uint64_t auid;
    int a;

    if (n == 5) {
        proof = named(t, n, 1, &name);
    }
    if ((n != 1 && n != 5) || !tok_uid(&t[0], &auid) ||
        (n == 5 && (!proof || name != 0 ||
                    proof->type != FEMU_OPAL_TOK_BYTES))) {
        r->status = FEMU_OPAL_ST_INVALID_PARAMETER;
        return;
    }
    a = femu_opal_auth_index(o->s.locking, auid);
    if (a < 0 || femu_opal_auth_class(o->s.locking, auid)) {
        r->status = FEMU_OPAL_ST_INVALID_PARAMETER;
        return;
    }
    femu_opal_enc_ctrl(&r->e, TOK_SL);
    /* MaxAuthentications is 2, and Anybody counts (Core 5.3.4.1.14) */
    if (!sess_has(o, a) && __builtin_popcount(o->s.auth) >= 2) {
        femu_opal_enc_uint(&r->e, 0);
    } else if (femu_opal_check_pin(o, a, proof) == FEMU_OPAL_ST_SUCCESS) {
        o->s.auth |= 1u << a;
        femu_opal_enc_uint(&r->e, 1);
    } else {
        femu_opal_enc_uint(&r->e, 0);
    }
    femu_opal_enc_ctrl(&r->e, TOK_EL);
}

/* Random[Count] (Opal 4.2.9.1): at most 32 bytes */
static void femu_opal_random(FemuOpal *o, const FemuOpalTok *t, int n,
                             FemuOpalReply *r)
{
    uint8_t b[32];
    uint32_t i;

    if (n != 1 || t[0].type != FEMU_OPAL_TOK_UINT || t[0].val > 32) {
        r->status = FEMU_OPAL_ST_INVALID_PARAMETER;
        return;
    }
    for (i = 0; i < t[0].val; i++) {
        b[i] = g_random_int();
    }
    femu_opal_enc_ctrl(&r->e, TOK_SL);
    femu_opal_enc_bytes(&r->e, b, t[0].val);
    femu_opal_enc_ctrl(&r->e, TOK_EL);
}

/*
 * Next[Where = 0, Count = 1] on the Authority, C_PIN or SP table of the
 * Admin SP (Core 5.3.3.8): the row UIDs after Where.
 */
static void femu_opal_next(FemuOpal *o, uint64_t table, const FemuOpalTok *t,
                           int n, FemuOpalReply *r)
{
    static const uint64_t au[] = {
        UID_AU_ANYBODY, UID_AU_ADMINS, UID_AU_MAKERS, UID_AU_SID,
        UID_AU_ASP_ADMIN1, UID_AU_PSID,
    };
    static const uint64_t cpin[] = {
        UID_CPIN_SID, UID_CPIN_ASP_ADMIN1, UID_CPIN_MSID, UID_CPIN_PSID,
    };
    static const uint64_t sp[] = { UID_SP_ADMIN, UID_SP_LOCKING };
    static const uint64_t spinfo[] = { UID_SPINFO };
    uint64_t lrows[FEMU_OPAL_ACE_MAX];
    const uint64_t *rows;
    uint64_t where = 0;
    uint64_t count = ~0ull;
    int nrows;
    int i;
    int k = 0;

    if (o->s.locking) {
        rows = lrows;
        nrows = lsp_rows(o, table, lrows);
        if (!nrows) {
            r->status = FEMU_OPAL_ST_NOT_AUTHORIZED;
            return;
        }
    } else {
        switch (table) {
        case UID_T_AUTHORITY:
            rows = au;
            nrows = ARRAY_SIZE(au);
            break;
        case UID_T_CPIN:
            rows = cpin;
            nrows = ARRAY_SIZE(cpin);
            break;
        case UID_T_SP:
            rows = sp;
            nrows = ARRAY_SIZE(sp);
            break;
        case UID_T_SPINFO:
            rows = spinfo;
            nrows = ARRAY_SIZE(spinfo);
            break;
        default:
            r->status = FEMU_OPAL_ST_NOT_AUTHORIZED;
            return;
        }
    }
    for (i = 0; i < n; i += 4) {
        uint64_t name = ~0ull;
        const FemuOpalTok *v = named(t, n, i, &name);
        bool ok = false;

        if (v && name == 0) {
            ok = tok_uid(v, &where);
        } else if (v && name == 1 && v->type == FEMU_OPAL_TOK_UINT) {
            count = v->val;
            ok = true;
        }
        if (!ok) {
            r->status = FEMU_OPAL_ST_INVALID_PARAMETER;
            return;
        }
    }
    if (where) {
        for (k = 0; k < nrows && rows[k] != where; k++) {
            ;
        }
        if (k == nrows) {
            r->status = FEMU_OPAL_ST_INVALID_PARAMETER;
            return;
        }
        k++;
    }
    femu_opal_enc_ctrl(&r->e, TOK_SL);
    femu_opal_enc_ctrl(&r->e, TOK_SL);
    for (; k < nrows && count; k++, count--) {
        femu_opal_enc_uid(&r->e, rows[k]);
    }
    femu_opal_enc_ctrl(&r->e, TOK_EL);
    femu_opal_enc_ctrl(&r->e, TOK_EL);
}

/* GetACL[InvokingID, MethodID] on AccessControl (Core 5.3.3.13) */
/*
 * GetACL[InvokingID, MethodID] on AccessControl (Core 5.3.3.13). An
 * association that does not exist: NOT_AUTHORIZED (Core 5.1.5.2). The
 * ACEs match what the methods check.
 */
static void femu_opal_getacl(FemuOpal *o, const FemuOpalTok *t, int n,
                             FemuOpalReply *r)
{
    uint64_t obj;
    uint64_t m;
    uint64_t ace[2];
    int k = 0;
    int i;

    if (o->s.locking || n != 2 || !tok_uid(&t[0], &obj) ||
        !tok_uid(&t[1], &m)) {
        r->status = FEMU_OPAL_ST_INVALID_PARAMETER;
        return;
    }
    if (m == UID_M_GET && asp_object(obj)) {
        if (obj == UID_CPIN_SID || obj == UID_CPIN_ASP_ADMIN1) {
            ace[k++] = UID_ACE_SID_NOPIN;
        } else if (obj == UID_CPIN_MSID) {
            ace[k++] = UID_ACE_MSID_GET;
        } else if (obj == UID_CPIN_PSID) {
            ace[k++] = UID_ACE_CPIN_PSID_NOPIN;
        } else {
            ace[k++] = UID_ACE_ANYBODY;
        }
    } else if (m == UID_M_SET && obj == UID_CPIN_SID) {
        ace[k++] = UID_ACE_SID_SET_PIN;
    } else if (m == UID_M_SET && obj == UID_CPIN_ASP_ADMIN1) {
        ace[k++] = UID_ACE_ADMINS_SET_PIN;
    } else if (m == UID_M_SET && obj == UID_AU_ASP_ADMIN1) {
        ace[k++] = UID_ACE_SET_ENABLED;
    } else if (m == UID_M_SET && obj == UID_TPERINFO) {
        ace[k++] = UID_ACE_TPERINFO_PRE;
    } else if (m == UID_M_ACTIVATE && obj == UID_SP_LOCKING) {
        ace[k++] = UID_ACE_SP_SID;
    } else if (m == UID_M_REVERT && obj == UID_SP_ADMIN) {
        ace[k++] = UID_ACE_SP_SID;
        ace[k++] = UID_ACE_SP_PSID;
    } else if (m == UID_M_REVERT && obj == UID_SP_LOCKING) {
        ace[k++] = UID_ACE_SP_SID;
    } else if ((m == UID_M_AUTHENTICATE || m == UID_M_RANDOM) &&
               obj == UID_THISSP) {
        ace[k++] = UID_ACE_ANYBODY;
    } else if (m == UID_M_NEXT &&
               (obj == UID_T_AUTHORITY || obj == UID_T_CPIN ||
                obj == UID_T_SP || obj == UID_T_SPINFO)) {
        ace[k++] = UID_ACE_ANYBODY;
    } else {
        r->status = FEMU_OPAL_ST_NOT_AUTHORIZED;
        return;
    }
    femu_opal_enc_ctrl(&r->e, TOK_SL);
    femu_opal_enc_ctrl(&r->e, TOK_SL);
    for (i = 0; i < k; i++) {
        femu_opal_enc_uid(&r->e, ace[i]);
    }
    femu_opal_enc_ctrl(&r->e, TOK_EL);
    femu_opal_enc_ctrl(&r->e, TOK_EL);
}

/*
 * Activate on the Locking SP object (Opal 5.1.1): Manufactured-Inactive
 * becomes Manufactured, and C_PIN_Admin1 of the Locking SP takes the SID
 * PIN. Any other state: success with no change.
 */
static void femu_opal_activate(FemuOpal *o, uint64_t uid, int n,
                               FemuOpalReply *r)
{
    if (o->s.locking || uid != UID_SP_LOCKING) {
        r->status = FEMU_OPAL_ST_NOT_AUTHORIZED;
        return;
    }
    if (!sess_has(o, FEMU_OPAL_AU_SID) || !o->s.write) {
        r->status = FEMU_OPAL_ST_NOT_AUTHORIZED;
        return;
    }
    if (n || o->s.txn) {
        r->status = n ? FEMU_OPAL_ST_INVALID_PARAMETER : FEMU_OPAL_ST_FAIL;
        return;
    }
    /* each Activate replaces the ephemeral KEM key (MPA 4.1.2.1) */
    if (o->cfg.mpa && !mpa_new_kem(o, true)) {
        r->status = FEMU_OPAL_ST_FAIL;
        return;
    }
    if (o->sp.lsp_life == FEMU_OPAL_LIFE_INACTIVE) {
        o->sp.lsp_life = FEMU_OPAL_LIFE_MANUFACTURED;
        o->sp.au[FEMU_OPAL_AU_LSP_ADMIN1].pin = o->sp.au[FEMU_OPAL_AU_SID].pin;
    }
    femu_opal_enc_ctrl(&r->e, TOK_SL);
    femu_opal_enc_ctrl(&r->e, TOK_EL);
}

/*
 * Revert (Opal 5.1.2). On the Admin SP object, by SID or PSID: the whole
 * TPer goes back to the factory state, C_PIN_SID becomes MSID, and the
 * session ends after the status. On the Locking SP object, by SID: only
 * the Locking SP does. Returns true when the session must end.
 */
static bool femu_opal_revert(FemuOpal *o, uint64_t uid, int n,
                             FemuOpalReply *r)
{
    bool sid = sess_has(o, FEMU_OPAL_AU_SID);

    if (o->s.locking || (uid != UID_SP_ADMIN && uid != UID_SP_LOCKING)) {
        r->status = FEMU_OPAL_ST_NOT_AUTHORIZED;
        return false;
    }
    if (!o->s.write ||
        !(sid || (uid == UID_SP_ADMIN && sess_has(o, FEMU_OPAL_AU_PSID)))) {
        r->status = FEMU_OPAL_ST_NOT_AUTHORIZED;
        return false;
    }
    if (n || o->s.txn) {
        r->status = n ? FEMU_OPAL_ST_INVALID_PARAMETER : FEMU_OPAL_ST_FAIL;
        return false;
    }
    femu_opal_enc_ctrl(&r->e, TOK_SL);
    femu_opal_enc_ctrl(&r->e, TOK_EL);
    if (uid == UID_SP_LOCKING) {
        femu_opal_factory_lsp(o, o->sp.lsp_life != FEMU_OPAL_LIFE_MANUFACTURED);
        return false;
    }
    femu_opal_factory(o);
    /* Revert of the Admin SP is a Block SID clear event */
    o->sid_blocked = false;
    o->sid_block_hw = false;
    return true;
}

/*
 * One method in a session: CALL object method SL params EL EOD SL s 0 0 EL.
 * Returns true when the session ends after the reply.
 */
/* what a method does to its session */
enum { METHOD_DONE, METHOD_END, METHOD_ABORT };

static bool session_ctrl(const FemuOpalTok *t)
{
    return tok_is(t, TOK_CALL) || tok_is(t, TOK_EOD) || tok_is(t, TOK_EOS) ||
           tok_is(t, TOK_ST) || tok_is(t, TOK_ET);
}

/*
 * One method in a session: CALL object method SL params EL EOD SL s 0 0 EL,
 * exactly @n tokens. A malformed status list, or a session or transaction
 * token in the parameters, aborts the session (Core 3.2.2.4.2, 3.3.7.3).
 */
static int femu_opal_method(FemuOpal *o, const FemuOpalTok *t, int n,
                            FemuOpalReply *r)
{
    uint64_t obj;
    uint64_t m;
    int end;
    int depth = 0;
    int k;

    if (n < 5 || !tok_is(&t[0], TOK_CALL) || !tok_uid(&t[1], &obj) ||
        !tok_uid(&t[2], &m) || !tok_is(&t[3], TOK_SL)) {
        return METHOD_ABORT;
    }
    for (end = 3; end < n; end++) {
        if (tok_is(&t[end], TOK_SL)) {
            depth++;
        } else if (tok_is(&t[end], TOK_EL) && --depth == 0) {
            break;
        }
    }
    if (end + 7 != n || !tok_is(&t[end + 1], TOK_EOD) ||
        !tok_is(&t[end + 2], TOK_SL) ||
        t[end + 3].type != FEMU_OPAL_TOK_UINT ||
        t[end + 4].type != FEMU_OPAL_TOK_UINT ||
        t[end + 5].type != FEMU_OPAL_TOK_UINT ||
        !tok_is(&t[end + 6], TOK_EL)) {
        return METHOD_ABORT;
    }
    for (k = 4; k < end; k++) {
        if (session_ctrl(&t[k])) {
            return METHOD_ABORT;
        }
    }
    if (t[end + 3].val) {
        r->status = MIN(t[end + 3].val, 0xff);
        return METHOD_DONE;
    }
    t += 4;
    n = end - 4;
    if (o->s.locking) {
        switch (m) {
        case UID_M_GET:
            lsp_get(o, obj, t, n, r);
            return METHOD_DONE;
        case UID_M_SET:
            lsp_set(o, obj, t, n, r);
            return METHOD_DONE;
        case UID_M_GETACL:
            if (obj != UID_T_ACCESSCONTROL) {
                r->status = FEMU_OPAL_ST_NOT_AUTHORIZED;
            } else {
                lsp_getacl(o, t, n, r);
            }
            return METHOD_DONE;
        case UID_M_GENKEY:
            lsp_genkey(o, obj, t, n, r);
            return METHOD_DONE;
        case UID_M_REVERTSP:
            if (obj != UID_THISSP) {
                r->status = FEMU_OPAL_ST_NOT_AUTHORIZED;
                return METHOD_DONE;
            }
            return lsp_revertsp(o, t, n, r) ? METHOD_END : METHOD_DONE;
        default:
            if (mpa_method(o, obj, m, t, n, r)) {
                return METHOD_DONE;
            }
        }
    }
    switch (m) {
    case UID_M_GET:
        femu_opal_get(o, obj, t, n, r);
        break;
    case UID_M_SET:
        femu_opal_set(o, obj, t, n, r);
        break;
    case UID_M_NEXT:
        femu_opal_next(o, obj, t, n, r);
        break;
    case UID_M_GETACL:
        if (obj != UID_T_ACCESSCONTROL) {
            r->status = FEMU_OPAL_ST_NOT_AUTHORIZED;
            break;
        }
        femu_opal_getacl(o, t, n, r);
        break;
    case UID_M_AUTHENTICATE:
    case UID_M_RANDOM:
        if (obj != UID_THISSP) {
            r->status = FEMU_OPAL_ST_NOT_AUTHORIZED;
        } else if (m == UID_M_AUTHENTICATE) {
            femu_opal_authenticate(o, t, n, r);
        } else {
            femu_opal_random(o, t, n, r);
        }
        break;
    case UID_M_ACTIVATE:
        femu_opal_activate(o, obj, n, r);
        break;
    case UID_M_REVERT:
        return femu_opal_revert(o, obj, n, r) ? METHOD_END : METHOD_DONE;
    default:
        /* Enterprise Erase, Reactivate and the like: not in Opal */
        r->status = FEMU_OPAL_ST_NOT_AUTHORIZED;
        break;
    }
    return METHOD_DONE;
}

/* finish an in-session reply: [results] EOD SL status 0 0 EL */
static void reply_status(FemuOpalReply *r, uint32_t mark)
{
    if (r->status) {
        /* a failed method: an empty result list */
        r->e.len = mark;
        r->e.overflow = false;
        femu_opal_enc_ctrl(&r->e, TOK_SL);
        femu_opal_enc_ctrl(&r->e, TOK_EL);
    }
    femu_opal_enc_ctrl(&r->e, TOK_EOD);
    femu_opal_enc_ctrl(&r->e, TOK_SL);
    femu_opal_enc_uint(&r->e, r->status);
    femu_opal_enc_uint(&r->e, 0);
    femu_opal_enc_uint(&r->e, 0);
    femu_opal_enc_ctrl(&r->e, TOK_EL);
}

/*
 * A Packet of the open session: [ST s] [method] [ET s], or EOS. Bad
 * transaction nesting aborts the session with no reply (Core
 * 3.2.2.3.3.4). The reply mirrors the transaction tokens.
 */
/*
 * A Packet of the open session: [ST s] [method] [ET s] [EOS], every token
 * used. Anything else, a second ST or a bad method aborts the session with
 * no reply (Core 3.2.2.3.3.3 and 3.2.2.3.3.4). The reply mirrors the
 * transaction tokens.
 */
static void femu_opal_session_packet(FemuOpal *o, const FemuOpalTok *t, int n)
{
    FemuOpalReply r = {
        .e = { .buf = o->resp + FRAME_HDR, .cap = FEMU_OPAL_BUF - FRAME_HDR },
    };
    uint32_t hsn = o->s.hsn;
    uint32_t tsn = o->s.tsn;
    FemuOpalSp before;
    int rc = METHOD_DONE;
    int i = 0;

    if (tok_is(&t[0], TOK_ST)) {
        if (o->s.txn || n < 2 || t[1].type != FEMU_OPAL_TOK_UINT) {
            goto abort;
        }
        o->s.txn = true;
        o->s.txn_sp = o->sp;
        o->s.txn_auth = o->s.auth;
        femu_opal_enc_ctrl(&r.e, TOK_ST);
        femu_opal_enc_uint(&r.e, 0);
        i = 2;
    }
    if (i < n && tok_is(&t[i], TOK_CALL)) {
        uint32_t mark = r.e.len;
        int k;

        /* the method ends at its status list: EOD SL s 0 0 EL */
        for (k = i; k < n && !tok_is(&t[k], TOK_EOD); k++) {
            ;
        }
        if (k + 6 > n) {
            goto abort;
        }
        before = o->sp;
        rc = femu_opal_method(o, t + i, k + 6 - i, &r);
        if (rc == METHOD_ABORT) {
            mpa_wipe(&before, sizeof(before));
            goto abort;
        }
        if (!o->s.txn) {
            femu_opal_effects(o, &before);
        }
        mpa_wipe(&before, sizeof(before));
        reply_status(&r, mark);
        i = k + 6;
    }
    if (rc == METHOD_DONE && i < n && tok_is(&t[i], TOK_ET)) {
        uint8_t st = 0;

        if (!o->s.txn || i + 1 >= n || t[i + 1].type != FEMU_OPAL_TOK_UINT) {
            goto abort;
        }
        if (t[i + 1].val) {
            /* abort: tables and authentication back, Tries kept */
            o->sp = o->s.txn_sp;
            o->s.auth = o->s.txn_auth;
            st = 1;
        } else {
            femu_opal_effects(o, &o->s.txn_sp);
        }
        lsp_undo_finish(o, st);
        o->s.txn = false;
        mpa_wipe(&o->s.txn_sp, sizeof(o->s.txn_sp));
        femu_opal_enc_ctrl(&r.e, TOK_ET);
        femu_opal_enc_uint(&r.e, st);
        i += 2;
    }
    if (i < n && tok_is(&t[i], TOK_EOS)) {
        femu_opal_enc_ctrl(&r.e, TOK_EOS);
        rc = METHOD_END;
        i++;
    }
    if (i != n || r.e.overflow) {
        goto abort;
    }
    if (rc == METHOD_END) {
        /* an open transaction aborts with the session */
        femu_opal_close(o);
    }
    femu_opal_frame(o, tsn, hsn, r.e.len);
    return;
abort:
    femu_opal_close(o);
}

/* Block SID Authentication (Block SID 4.2) on ComID 0005h */
/*
 * Block SID Authentication (Block SID 4.2) on ComID 0005h. SID is blocked
 * only while its committed PIN is MSID; the Hardware Reset choice is kept
 * for Level 0 in both cases.
 */
static FemuOpalIf femu_opal_block_sid(FemuOpal *o, const uint8_t *buf,
                                      uint32_t len)
{
    bool freeze = len > 1 && (buf[1] & 1);

    if (freeze || o->sid_blocked) {
        return FEMU_OPAL_IF_INVALID;
    }
    if (pin_eq(&committed(o)->au[FEMU_OPAL_AU_SID].pin, &o->cfg.msid)) {
        o->sid_blocked = true;
    }
    o->sid_block_hw = buf[0] & 1;
    return FEMU_OPAL_IF_GOOD;
}

/*
 * TPER_RESET (Opal 3.2.3): a Programmatic reset when
 * ProgrammaticResetEnable is True. It ends the session, resets the stack
 * and applies LockOnReset and DoneOnReset of type 3.
 */
static FemuOpalIf femu_opal_tper_reset(FemuOpal *o)
{
    if (!committed(o)->pre) {
        return FEMU_OPAL_IF_INVALID;
    }
    femu_opal_close(o);
    femu_opal_stack_reset(o);
    o->mgmt_req = 0;
    lsp_reset(o, FEMU_OPAL_RESET_PROG);
    mpa_reset(o, FEMU_OPAL_RESET_PROG);
    return FEMU_OPAL_IF_GOOD;
}

/*
 * A TCG Hardware Reset (SIIS Table 20: a PCIe warm reset). The session and
 * the host properties end; Block SID clears only when it asked for it.
 * Tries stays (Core 5.3.2.12.8). No range takes reset type 1, so nothing
 * locks.
 */
void femu_opal_hw_reset(FemuOpal *o)
{
    femu_opal_close(o);
    femu_opal_stack_reset(o);
    o->mgmt_req = 0;
    if (o->sid_block_hw) {
        o->sid_blocked = false;
        o->sid_block_hw = false;
    }
}

void femu_opal_power_cycle(FemuOpal *o)
{
    femu_opal_close(o);
    femu_opal_stack_reset(o);
    o->mgmt_req = 0;
    /* Persistence is False for every C_PIN row */
    memset(o->tries, 0, sizeof(o->tries));
    o->sid_blocked = false;
    o->sid_block_hw = false;
    lsp_reset(o, FEMU_OPAL_RESET_POWER);
    mpa_reset(o, FEMU_OPAL_RESET_POWER);
}

/*
 * A cryptographic erase: every range gets a new key. An open transaction
 * keeps its pending GenKey, so its commit still erases that range, and a
 * range it did not touch commits without an erase.
 */
void femu_opal_rekey(FemuOpal *o)
{
    bool txn = o->s.open && o->s.txn;
    int r;

    for (r = 0; r <= FEMU_OPAL_RANGES; r++) {
        uint64_t *was = &o->s.txn_sp.range[r].key;
        uint64_t *key = &o->sp.range[r].key;

        if (txn && *was != *key) {
            *was = o->next_key++;
            *key = o->next_key++;
            continue;
        }
        *key = o->next_key++;
        if (txn) {
            *was = *key;
        }
    }
}

uint64_t femu_opal_key(const FemuOpal *o, int range)
{
    return committed(o)->range[range].key;
}

/*
 * A Session Manager call: CALL SMUID method SL params EL EOD SL s 0 0 EL.
 * The control session ignores unknown methods with no response (Core
 * 3.3.7.1.3). A known method with a bad status list gets
 * INVALID_PARAMETER.
 */
static void femu_opal_session_manager(FemuOpal *o, const FemuOpalTok *t,
                                      int n)
{
    uint64_t inv;
    uint64_t method;
    uint8_t status = FEMU_OPAL_ST_INVALID_PARAMETER;
    bool ok;
    int end;
    int depth = 0;

    if (n < 5 || !tok_is(&t[0], TOK_CALL) || !tok_uid(&t[1], &inv) ||
        !tok_uid(&t[2], &method) || !tok_is(&t[3], TOK_SL) ||
        inv != FEMU_OPAL_UID_SMUID ||
        (method != FEMU_OPAL_UID_PROPERTIES &&
         method != UID_M_STARTSESSION)) {
        return;
    }
    /* the EL that closes the parameter list */
    for (end = 3; end < n; end++) {
        if (tok_is(&t[end], TOK_SL)) {
            depth++;
        } else if (tok_is(&t[end], TOK_EL) && --depth == 0) {
            break;
        }
    }
    ok = end + 6 < n && tok_is(&t[end + 1], TOK_EOD) &&
         tok_is(&t[end + 2], TOK_SL) &&
         t[end + 3].type == FEMU_OPAL_TOK_UINT &&
         t[end + 4].type == FEMU_OPAL_TOK_UINT &&
         t[end + 5].type == FEMU_OPAL_TOK_UINT &&
         tok_is(&t[end + 6], TOK_EL);
    if (ok) {
        status = t[end + 3].val ? MIN(t[end + 3].val, 0xff) : 0;
    }
    if (method == UID_M_STARTSESSION) {
        if (!ok || status) {
            femu_opal_sync(o, 0, 0, status);
        } else {
            femu_opal_start_session(o, t + 4, end - 4);
        }
        return;
    }
    femu_opal_properties(o, t + 4, ok ? end - 4 : 0, status);
}

/*
 * One ComPacket with one Packet and one Subpacket (Opal 3.3.4.1.2). A bad
 * header, nonzero pad, a second Subpacket or a streaming error drops the
 * payload, and the ComID stays idle. Packets after the first are ignored.
 * TSN and HSN 0 go to the Session Manager; a Packet that names no open
 * session is dropped.
 */
static void femu_opal_compacket(FemuOpal *o, const uint8_t *buf, uint32_t len)
{
    FemuOpalTok *toks = o->toks;
    const uint8_t *pkt = buf + COMPKT_HDR;
    const uint8_t *sub = pkt + PKT_HDR;
    uint32_t cplen;
    uint32_t plen;
    uint32_t slen;
    uint32_t pad;
    uint32_t tsn;
    uint32_t hsn;
    uint32_t k;
    int n;

    if (len < FRAME_HDR || get16(buf + 4) != FEMU_OPAL_COMID ||
        get16(buf + 6)) {
        return;
    }
    cplen = get32(buf + 16);
    if (cplen < PKT_HDR + SUBPKT_HDR || cplen > len - COMPKT_HDR) {
        return;
    }
    plen = get32(pkt + 20);
    if (plen < SUBPKT_HDR || plen > cplen - PKT_HDR) {
        return;
    }
    slen = get32(sub + 8);
    pad = -slen & 3;
    if (get16(sub + 6) || slen > plen - SUBPKT_HDR ||
        plen - SUBPKT_HDR - slen != pad) {
        return;
    }
    for (k = 0; k < pad; k++) {
        if (sub[SUBPKT_HDR + slen + k]) {
            return;
        }
    }
    tsn = get32(pkt);
    hsn = get32(pkt + 4);
    n = femu_opal_decode(sub + SUBPKT_HDR, slen, toks, FEMU_OPAL_MAX_TOKS);
    if (n <= 0) {
        /* an invalid token aborts the session it names (Core 3.2.2.4.1) */
        if (n < 0 && o->s.open && tsn == o->s.tsn && hsn == o->s.hsn) {
            femu_opal_close(o);
        }
        return;
    }
    if (!tsn && !hsn) {
        femu_opal_session_manager(o, toks, n);
    } else if (o->s.open && tsn == o->s.tsn && hsn == o->s.hsn) {
        femu_opal_session_packet(o, toks, n);
    }
}

FemuOpalIf femu_opal_send_check(FemuOpal *o, uint8_t secp, uint16_t spsp,
                                uint32_t len)
{
    switch (secp) {
    case FEMU_OPAL_SECP_TCG:
        if (spsp == FEMU_OPAL_COMID_L0) {
            return FEMU_OPAL_IF_GOOD;
        }
        if (spsp != FEMU_OPAL_COMID || len > FEMU_OPAL_BUF) {
            return FEMU_OPAL_IF_INVALID;
        }
        return o->ready ? FEMU_OPAL_IF_SEQUENCE : FEMU_OPAL_IF_GOOD;
    case FEMU_OPAL_SECP_COMID:
        if (spsp == FEMU_OPAL_COMID_TPER_RESET) {
            /* a nonzero length (Opal Table 13) */
            return committed(o)->pre && len ? FEMU_OPAL_IF_GOOD :
                                              FEMU_OPAL_IF_INVALID;
        }
        if (spsp == FEMU_OPAL_COMID_BLOCK_SID) {
            return len ? FEMU_OPAL_IF_GOOD : FEMU_OPAL_IF_INVALID;
        }
        if (spsp != FEMU_OPAL_COMID) {
            return FEMU_OPAL_IF_INVALID;
        }
        if (len < 8) {
            /* a bad request leaves "No Response Available" */
            o->mgmt_req = 0;
            return FEMU_OPAL_IF_INVALID;
        }
        return FEMU_OPAL_IF_GOOD;
    default:
        return FEMU_OPAL_IF_INVALID;
    }
}

FemuOpalIf femu_opal_send(FemuOpal *o, uint8_t secp, uint16_t spsp,
                          const uint8_t *buf, uint32_t len)
{
    FemuOpalIf r = femu_opal_send_check(o, secp, spsp, len);
    uint32_t code;
    uint32_t ext;

    if (r) {
        return r;
    }
    if (secp == FEMU_OPAL_SECP_TCG) {
        /* a Level 0 send is discarded (Core 3.3.6.1) */
        if (spsp == FEMU_OPAL_COMID) {
            femu_opal_compacket(o, buf, len);
        }
        return FEMU_OPAL_IF_GOOD;
    }
    if (spsp == FEMU_OPAL_COMID_TPER_RESET) {
        return femu_opal_tper_reset(o);
    }
    if (spsp == FEMU_OPAL_COMID_BLOCK_SID) {
        return femu_opal_block_sid(o, buf, len);
    }
    ext = get32(buf);
    code = get32(buf + 4);
    o->mgmt_req = 0;
    switch (code) {
    case MGMT_VERIFY_COMID:
        /* any ComID: the response says if it is valid */
        o->mgmt_req = code;
        o->mgmt_ext = ext;
        return FEMU_OPAL_IF_GOOD;
    case MGMT_STACK_RESET:
        if (ext != (uint32_t)FEMU_OPAL_COMID << 16) {
            return FEMU_OPAL_IF_INVALID;
        }
        /* it aborts the session and its transaction (Core 3.3.4.7.5) */
        femu_opal_close(o);
        femu_opal_stack_reset(o);
        o->mgmt_req = code;
        return FEMU_OPAL_IF_GOOD;
    default:
        return FEMU_OPAL_IF_INVALID;
    }
}

/*
 * GET_COMID_RESPONSE (Core 3.3.4.7.2 to 3.3.4.7.5). A VERIFY_COMID_VALID
 * answer stays for every later Receive; a STACK_RESET answer goes once
 * the host has read all of it. Before any request: all zero.
 */
static void femu_opal_mgmt_resp(FemuOpal *o, uint8_t *buf, uint32_t al)
{
    uint8_t r[46] = { 0 };
    uint32_t n = 12;

    if (o->mgmt_req == MGMT_STACK_RESET) {
        put32(r, (uint32_t)FEMU_OPAL_COMID << 16);
        put32(r + 4, MGMT_STACK_RESET);
        put16(r + 10, 4);
        n = 16;                         /* result 0: success */
        if (al >= n) {
            o->consume = CONSUME_MGMT;
        }
    } else if (o->mgmt_req == MGMT_VERIFY_COMID) {
        put32(r, o->mgmt_ext);
        put32(r + 4, MGMT_VERIFY_COMID);
        put16(r + 10, 0x22);
        /* Issued: no session holds it yet; Invalid for any other; no clock */
        put32(r + 12, o->mgmt_ext == (uint32_t)FEMU_OPAL_COMID << 16 ?
                      FEMU_OPAL_COMID_ISSUED : 0);
        n = 46;
    }
    memcpy(buf, r, MIN(al, n));
}

FemuOpalIf femu_opal_recv(FemuOpal *o, uint8_t secp, uint16_t spsp,
                          uint8_t *buf, uint32_t al)
{
    uint8_t h[COMPKT_HDR] = { 0 };

    o->consume = CONSUME_NONE;
    switch (secp) {
    case FEMU_OPAL_SECP_INFO:
        if (spsp == 0) {
            /* supported protocol list: 00h 01h 02h */
            uint8_t l[11] = { [7] = 3, [8] = 0x00, [9] = 0x01, [10] = 0x02 };

            memcpy(buf, l, MIN(al, sizeof(l)));
            return FEMU_OPAL_IF_GOOD;
        }
        /* no certificate: a zero length (SPSP 0001h) */
        return spsp == 1 ? FEMU_OPAL_IF_GOOD : FEMU_OPAL_IF_INVALID;
    case FEMU_OPAL_SECP_TCG:
        if (spsp == FEMU_OPAL_COMID_L0) {
            femu_opal_level0(o, buf, al);
            return FEMU_OPAL_IF_GOOD;
        }
        if (spsp != FEMU_OPAL_COMID) {
            return FEMU_OPAL_IF_INVALID;
        }
        if (o->ready && al >= o->resp_len) {
            memcpy(buf, o->resp, o->resp_len);
            o->consume = CONSUME_RESP;
            return FEMU_OPAL_IF_GOOD;
        }
        /* idle, or too small: Length 0 and what a full Receive needs */
        put16(h + 4, FEMU_OPAL_COMID);
        if (o->ready) {
            put32(h + 8, o->resp_len);
            put32(h + 12, o->resp_len);
        }
        memcpy(buf, h, MIN(al, sizeof(h)));
        return FEMU_OPAL_IF_GOOD;
    case FEMU_OPAL_SECP_COMID:
        if (spsp != FEMU_OPAL_COMID) {
            return FEMU_OPAL_IF_INVALID;
        }
        femu_opal_mgmt_resp(o, buf, al);
        return FEMU_OPAL_IF_GOOD;
    default:
        return FEMU_OPAL_IF_INVALID;
    }
}

void femu_opal_consume(FemuOpal *o)
{
    if (o->consume == CONSUME_MGMT) {
        o->mgmt_req = 0;
    } else if (o->consume == CONSUME_RESP) {
        o->ready = false;
        o->resp_len = 0;
    }
    o->consume = CONSUME_NONE;
}
